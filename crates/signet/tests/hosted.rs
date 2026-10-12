// SPDX-License-Identifier: GPL-3.0-or-later
//! Exercises the API used by the desktop app in an isolated subprocess.
use anyhow::Result;
use sequoia_openpgp::parse::Parse;
use signet::{
    agent::Agent,
    config, manage,
    prompt::{ApprovalRequest, Options, Prompter},
};
use signet_vault::{Credentials, Vault};
use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;
struct TestPrompter;
impl Prompter for TestPrompter {
    fn password(&self, _: &config::Config, _: &Options) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new("test".into()))
    }
    fn approve(&self, _: &config::Config, _: &ApprovalRequest) -> Result<()> {
        anyhow::bail!("denied")
    }
}
#[test]
fn hosted_agent_and_file_setup() {
    if std::env::var_os("SIGNET_HOSTED_TEST").is_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "hosted_agent_and_file_setup", "--nocapture"])
            .env("SIGNET_HOSTED_TEST", "1")
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .env("XDG_RUNTIME_DIR", dir.path().join("run"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let config = manage::new_config(None, None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.kdbx");
    let creds = Credentials {
        password: Some(Zeroizing::new("test".into())),
        keyfile: None,
    };
    let mut vault = Vault::create(&source, creds.clone()).unwrap();
    use sequoia_openpgp::{cert::CertBuilder, serialize::Serialize};
    let (cert, _) = CertBuilder::new()
        .add_userid("Test <test@example.org>")
        .add_signing_subkey()
        .generate()
        .unwrap();
    let mut fixture = Vec::new();
    cert.as_tsk().armored().serialize(&mut fixture).unwrap();
    vault.import(&fixture, &mut |_| None).unwrap();
    vault.save().unwrap();
    let original = std::fs::read(&source).unwrap();
    assert!(
        manage::initialize_from_file(&config, &source, Zeroizing::new("wrong".into())).is_err()
    );
    assert!(!config.vault.exists());
    assert!(!config::config_path().exists());
    // A failed configuration write must leave both setup paths retryable.
    let config_parent = config::config_path().parent().unwrap().to_owned();
    std::fs::create_dir_all(config_parent.parent().unwrap()).unwrap();
    std::fs::write(&config_parent, b"blocks config directory").unwrap();
    assert!(manage::initialize(&config, Zeroizing::new("test".into())).is_err());
    assert!(!config.vault.exists());
    assert!(manage::initialize_from_file(&config, &source, Zeroizing::new("test".into())).is_err());
    assert!(!config.vault.exists());
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_file(config_parent).unwrap();
    manage::initialize_from_file(&config, &source, Zeroizing::new("test".into())).unwrap();
    assert_eq!(std::fs::read(&source).unwrap(), original);
    assert_eq!(std::fs::read(&config.vault).unwrap(), original);
    assert!(manage::initialize_from_file(&config, &source, Zeroizing::new("test".into())).is_err());
    let agent = Agent::start(config.clone(), Arc::new(TestPrompter)).unwrap();
    let handle = agent.handle();
    let stop: Arc<AtomicBool> = agent.stop_flag();
    let serving = std::thread::spawn(move || agent.serve().unwrap());
    assert!(Agent::start(config, Arc::new(TestPrompter)).is_err());
    assert!(handle.status().unwrap().locked);
    handle.unlock().unwrap();
    let keys = handle.keys().unwrap();
    assert!(!keys.is_empty());
    let fp = keys[0].fingerprint.clone();
    assert!(
        handle
            .export_public(&fp)
            .unwrap()
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    );
    handle.setup_gnupg().unwrap();
    // Secret export needs the master password and protects the result.
    assert!(handle.export_secret(&fp, "wrong", "export pass").is_err());
    assert!(handle.export_secret(&fp, "test", "").is_err());
    let armor = handle.export_secret(&fp, "test", "export pass").unwrap();
    let exported = sequoia_openpgp::Cert::from_bytes(armor.as_bytes()).unwrap();
    assert!(exported.keys().secret().count() >= 2);
    assert_eq!(exported.keys().unencrypted_secret().count(), 0);
    let unlocked =
        signet_vault::unlock_cert(exported, &mut || Some(Zeroizing::new("export pass".into())))
            .unwrap();
    assert!(unlocked.keys().unencrypted_secret().count() >= 2);
    let gnupg = tempfile::tempdir().unwrap();
    let import = |args: &[&str]| {
        let mut child = Command::new("gpg")
            .arg("--homedir")
            .arg(gnupg.path())
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "export pass",
            ])
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(armor.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let output = import(&["--import"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = import(&["--with-colons", "--list-secret-keys"]);
    assert!(String::from_utf8_lossy(&output.stdout).contains(&fp));
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(gnupg.path())
        .args(["--kill", "all"])
        .status();
    // Subkey changes need the master password and reach GnuPG, including
    // deletions, which importing alone would not apply.
    let gnupg_subkeys = || {
        let output = Command::new("gpg")
            .arg("--homedir")
            .arg(&handle.config().unwrap().gnupg_home)
            .args(["--batch", "--with-colons", "--list-keys", &fp])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.starts_with("fpr:"))
            .map(|line| line.split(':').nth(9).unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    use signet_vault::edit::{Algorithm, KeyEdit, Usage};
    let add = KeyEdit::AddSubkey {
        algorithm: Algorithm::Cv25519,
        usage: Usage {
            encrypt: true,
            ..Usage::default()
        },
        expires: None,
    };
    assert!(handle.edit_key(&fp, "wrong", &add).is_err());
    let before = handle.key_parts(&fp).unwrap();
    handle.edit_key(&fp, "test", &add).unwrap();
    let after = handle.key_parts(&fp).unwrap();
    assert_eq!(after.len(), before.len() + 1);
    let added = after
        .iter()
        .find(|part| !before.contains(part))
        .unwrap()
        .fingerprint
        .clone();
    assert!(gnupg_subkeys().contains(&added));
    handle
        .edit_key(
            &fp,
            "test",
            &KeyEdit::DeleteSubkey {
                key: added.parse().unwrap(),
            },
        )
        .unwrap();
    assert_eq!(handle.key_parts(&fp).unwrap(), before);
    let listed = gnupg_subkeys();
    assert!(
        !listed.contains(&added),
        "GnuPG still lists the deleted subkey"
    );
    assert_eq!(listed.len(), before.len());
    handle.lock().unwrap();
    assert!(handle.status().unwrap().locked);
    handle.unlock().unwrap();
    handle.remove(&fp).unwrap();
    assert!(handle.keys().unwrap().is_empty());
    // An empty vault still gets a GnuPG home; gpg itself rejects empty input.
    handle.setup_gnupg().unwrap();
    assert!(!Vault::open(&source, creds).unwrap().keys().is_empty());
    stop.store(true, Ordering::Relaxed);
    serving.join().unwrap();
}

#[test]
fn malformed_remote_leaves_sync_usable() {
    if std::env::var_os("SIGNET_MALFORMED_REMOTE_TEST").is_none() {
        let dir = tempfile::tempdir().unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "malformed_remote_leaves_sync_usable",
                "--nocapture",
            ])
            .env("SIGNET_MALFORMED_REMOTE_TEST", "1")
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .env("XDG_STATE_HOME", dir.path().join("state"))
            .env("XDG_RUNTIME_DIR", dir.path().join("run"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = manage::new_config(None, None).unwrap();
    config.webdav = Some(config::WebDav {
        url: format!("http://{}/vault.kdbx", listener.local_addr().unwrap())
            .parse()
            .unwrap(),
        username: None,
        password_command: None,
        sync_interval: "0s".into(),
    });
    manage::initialize(&config, Zeroizing::new("test".into())).unwrap();
    let original = std::fs::read(&config.vault).unwrap();
    // A KDBX 4 header whose compression field is empty, served to every sync.
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 8192];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream
                .write_all(&[
                    0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 4, 0, 3, 0, 0, 0, 0,
                ])
                .unwrap();
        }
    });
    let agent = Agent::start(config.clone(), Arc::new(TestPrompter)).unwrap();
    let handle = agent.handle();
    handle.unlock().unwrap();
    for _ in 0..2 {
        let error = format!("{:#}", handle.sync().unwrap_err());
        assert!(error.contains("remote vault is corrupt"), "{error}");
    }
    server.join().unwrap();
    assert_eq!(std::fs::read(&config.vault).unwrap(), original);
}
