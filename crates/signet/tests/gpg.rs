// SPDX-License-Identifier: GPL-3.0-or-later
use signet_vault::{Credentials, Vault};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeroize::Zeroizing;
struct Harness {
    dir: TempDir,
    generation: PathBuf,
    client: PathBuf,
    daemon: Option<Child>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(child) = &mut self.daemon {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = Command::new("gpgconf")
            .arg("--homedir")
            .arg(&self.generation)
            .args(["--kill", "gpg-agent"])
            .status();
    }
}
fn execute(command: &mut Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}
fn success(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let generation = dir.path().join("gen");
        let client = dir.path().join("gnupg");
        for path in [&generation, &client] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            dir,
            generation,
            client,
            daemon: None,
        }
    }
    fn env(&self, command: &mut Command) {
        for (name, path) in [
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_RUNTIME_DIR", "runtime"),
        ] {
            command.env(name, self.dir.path().join(path));
        }
        command
            .env("GNUPGHOME", &self.client)
            .env("RUST_LOG", "signet=debug");
    }
    fn cli(&self, action: &str) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_signet"));
        self.env(&mut command);
        command.arg(action).output().unwrap()
    }
    fn gpg(&self, args: &[&str], input: &[u8]) -> Output {
        let mut command = Command::new("gpg");
        self.env(&mut command);
        command
            .arg("--homedir")
            .arg(&self.client)
            .args(["--batch", "--yes"])
            .args(args);
        execute(&mut command, input)
    }
    fn generator(&self, args: &[&str], input: &[u8]) -> Vec<u8> {
        let mut command = Command::new("gpg");
        command
            .arg("--homedir")
            .arg(&self.generation)
            .args([
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
            ])
            .args(args);
        success(execute(&mut command, input))
    }
    fn start(&mut self, secret: &[u8], public: &[u8]) {
        let credentials = Credentials {
            password: Some(Zeroizing::new("test master password".into())),
            keyfile: None,
        };
        let path = self.dir.path().join("vault.kdbx");
        let mut vault = Vault::create(&path, credentials).unwrap();
        vault.database.config.kdf_config = keepass::config::KdfConfig::Aes { rounds: 10 };
        vault.import(secret, &mut |_| None).unwrap();
        vault.save().unwrap();
        let pinentry = self.dir.path().join("pinentry");
        let script = format!(
            "#!/bin/sh\nprintf 'OK fake pinentry\\n'\nwhile IFS= read -r line; do\n case \"$line\" in\n SETDESC*) printf '%s\\n' \"$line\" >> '{}' ;;\n GETPIN) printf 'D test master password\\n' ;;\n CONFIRM) if test -e '{}'; then printf 'ERR 83886179 Cancelled\\n'; continue; fi ;;\n esac\n printf 'OK\\n'\ndone\n",
            self.dir.path().join("prompts").display(),
            self.dir.path().join("deny").display()
        );
        fs::write(&pinentry, script).unwrap();
        fs::set_permissions(&pinentry, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(self.dir.path().join("config/signet")).unwrap();
        fs::write(
            self.dir.path().join("config/signet/config.toml"),
            format!(
                "vault = {:?}\ngnupg_home = {:?}\npinentry = {:?}\n",
                path.to_str().unwrap(),
                self.client.to_str().unwrap(),
                pinentry.to_str().unwrap()
            ),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_signet"));
        self.env(&mut command);
        let log = fs::File::create(self.dir.path().join("daemon.log")).unwrap();
        self.daemon = Some(
            command
                .arg("agent")
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let start = Instant::now();
        while !self.dir.path().join("runtime/signet/control").exists() {
            if self.daemon.as_mut().unwrap().try_wait().unwrap().is_some()
                || start.elapsed() > Duration::from_secs(10)
            {
                panic!(
                    "agent failed: {}",
                    fs::read_to_string(self.dir.path().join("daemon.log")).unwrap()
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
        success(self.cli("unlock"));
        success(self.gpg(&["--import"], public));
    }
}
#[test]
fn real_gpg_sign_encrypt_deny_lock_and_export() {
    let mut h = Harness::new();
    for (uid, algorithm, subkey) in [
        ("RSA Test <rsa@example.org>", "rsa3072", "rsa3072"),
        ("Ed Test <ed@example.org>", "ed25519", "cv25519"),
        ("P256 Test <p256@example.org>", "nistp256", "nistp256"),
        ("P384 Test <p384@example.org>", "nistp384", "nistp384"),
    ] {
        h.generator(&["--quick-generate-key", uid, algorithm, "sign", "0"], b"");
        let listing =
            String::from_utf8(h.generator(&["--with-colons", "--list-keys", uid], b"")).unwrap();
        let fingerprint = listing
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .unwrap()
            .split(':')
            .nth(9)
            .unwrap();
        h.generator(&["--quick-add-key", fingerprint, subkey, "encr", "0"], b"");
    }
    let secret = h.generator(&["--export-secret-keys"], b"");
    let public = h.generator(&["--export"], b"");
    h.start(&secret, &public);
    let listing = String::from_utf8(success(h.gpg(
        &["--with-colons", "--with-keygrip", "--list-secret-keys"],
        b"",
    )))
    .unwrap();
    assert_eq!(listing.lines().filter(|l| l.starts_with("sec:")).count(), 4);
    assert!(
        listing
            .lines()
            .filter(|l| l.starts_with("sec:") || l.starts_with("ssb:"))
            .all(|l| l.split(':').nth(14) == Some("+")),
        "{listing}"
    );
    let generation =
        String::from_utf8(h.generator(&["--with-colons", "--with-keygrip", "--list-keys"], b""))
            .unwrap();
    let expected = generation
        .lines()
        .filter(|l| l.starts_with("grp:"))
        .map(|l| l.split(':').nth(9).unwrap().to_string())
        .collect::<Vec<_>>();
    let cache = fs::read_to_string(h.dir.path().join("state/signet/keygrips")).unwrap();
    for grip in expected {
        assert!(cache.contains(&grip), "grip {grip} missing");
    }
    let message = b"A message signed and encrypted through Signet.\n";
    for recipient in [
        "rsa@example.org",
        "ed@example.org",
        "p256@example.org",
        "p384@example.org",
    ] {
        for action in ["--sign", "--detach-sign", "--clearsign"] {
            let signed = success(h.gpg(&["--local-user", recipient, action], message));
            let path = h.dir.path().join("signature");
            fs::write(&path, signed).unwrap();
            if action == "--detach-sign" {
                let data = h.dir.path().join("message");
                fs::write(&data, message).unwrap();
                success(h.gpg(
                    &["--verify", path.to_str().unwrap(), data.to_str().unwrap()],
                    b"",
                ));
            } else {
                success(h.gpg(&["--verify", path.to_str().unwrap()], b""));
            }
        }
        let encrypted = success(h.gpg(
            &[
                "--trust-model",
                "always",
                "--recipient",
                recipient,
                "--encrypt",
            ],
            message,
        ));
        assert_eq!(success(h.gpg(&["--decrypt"], &encrypted)), message);
    }
    let prompts = fs::read_to_string(h.dir.path().join("prompts")).unwrap();
    assert!(prompts.contains("Allow sign?"));
    assert!(prompts.contains("Allow decrypt?"));
    assert!(prompts.contains("Fingerprint:"));
    assert!(prompts.contains("gpg"));
    assert!(prompts.contains("not verified identities"));
    fs::write(h.dir.path().join("deny"), b"").unwrap();
    assert!(
        !h.gpg(
            &["--local-user", "ed@example.org", "--detach-sign"],
            message
        )
        .status
        .success()
    );
    let encrypted = success(h.gpg(
        &[
            "--trust-model",
            "always",
            "--recipient",
            "ed@example.org",
            "--encrypt",
        ],
        message,
    ));
    assert!(!h.gpg(&["--decrypt"], &encrypted).status.success());
    fs::remove_file(h.dir.path().join("deny")).unwrap();
    success(h.cli("lock"));
    let count = fs::read_to_string(h.dir.path().join("prompts"))
        .unwrap()
        .lines()
        .count();
    success(h.gpg(&["--list-secret-keys"], b""));
    assert_eq!(
        fs::read_to_string(h.dir.path().join("prompts"))
            .unwrap()
            .lines()
            .count(),
        count
    );
    assert!(!h.gpg(&["--export-secret-keys"], b"").status.success());
    success(h.gpg(
        &["--local-user", "ed@example.org", "--detach-sign"],
        message,
    ));
}

fn connect(h: &Harness, args: &[&str]) -> Output {
    let mut command = Command::new("gpg-connect-agent");
    h.env(&mut command);
    command.args(["--no-autostart"]).args(args).arg("/bye");
    execute(&mut command, b"")
}

#[test]
fn confirmation_ignores_client_environment() {
    let mut h = Harness::new();
    h.generator(
        &[
            "--quick-gen-key",
            "Prompt <prompt@example.org>",
            "ed25519",
            "sign",
            "never",
        ],
        b"",
    );
    let secret = h.generator(&["--export-secret-keys"], b"");
    let public = h.generator(&["--export"], b"");
    h.start(&secret, &public);
    let info = connect(&h, &["KEYINFO --list"]);
    let text = String::from_utf8_lossy(&info.stdout);
    let grip = text.split_whitespace().nth(2).unwrap();
    let log = h.dir.path().join("trusted-prompt");
    fs::write(h.dir.path().join("pinentry"), format!("#!/bin/sh\nprintf 'ENV DISPLAY=%s DBUS=%s\\n' \"$DISPLAY\" \"$DBUS_SESSION_BUS_ADDRESS\" >> '{log}'\nprintf 'OK\\n'\nwhile IFS= read -r line; do printf '%s\\n' \"$line\" >> '{log}'; printf 'OK\\n'; done\n",log=log.display())).unwrap();
    success(connect(
        &h,
        &[
            "OPTION putenv=DISPLAY=:99",
            "OPTION putenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/attacker-bus",
            "OPTION ttyname=/dev/pts/77",
            "SETKEYDESC UniqueRequestDescription",
            &format!("SIGKEY {grip}"),
            &format!("SETHASH 8 {}", "00".repeat(32)),
            "PKSIGN",
            &format!("SETHASH 8 {}", "00".repeat(32)),
            "PKSIGN",
        ],
    ));
    let prompts = fs::read_to_string(log).unwrap();
    let routing = prompts
        .lines()
        .filter(|line| line.starts_with("ENV ") || line.starts_with("OPTION "))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!routing.contains(":99"), "{routing}");
    assert!(!routing.contains("attacker-bus"), "{routing}");
    assert!(!routing.contains("/dev/pts/77"), "{routing}");
}
