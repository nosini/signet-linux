// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    assuan,
    config::{self, Config},
    crypto,
    keygrip::Keygrip,
    prompt::{self, Options},
};
use anyhow::{Context, Result, bail};
use sequoia_openpgp::{crypto::KeyPair, types::HashAlgorithm};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use signet_vault::{SecretState, Vault};
use std::{
    collections::HashMap,
    fs,
    io::{BufReader, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
const SOURCE: u32 = 5 << 24;
const CANCEL: u32 = SOURCE + 99;
const UNSUPPORTED: u32 = SOURCE + 60;
const NO_KEY: u32 = SOURCE + 17;
#[derive(Clone, Serialize, Deserialize)]
struct CachedKey {
    grip: String,
    fingerprint: String,
    title: String,
    public: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct KeyCache {
    vault: PathBuf,
    keyfile: Option<PathBuf>,
    keys: Vec<CachedKey>,
}
fn build_cache(vault: &Vault) -> Vec<CachedKey> {
    let mut cache = Vec::new();
    for entry in vault
        .keys()
        .into_iter()
        .filter(|e| e.secret == SecretState::Usable)
    {
        for key in entry.cert.keys().secret() {
            let public = key.key().clone().parts_into_public();
            if let Ok(grip) = Keygrip::of(public.mpis())
                && let Ok(sexp) = crypto::public(&public)
            {
                cache.push(CachedKey {
                    grip: grip.to_string(),
                    fingerprint: entry.fingerprint.to_hex(),
                    title: entry.title.clone(),
                    public: sexp,
                });
            }
        }
    }
    cache.sort_by(|a, b| a.grip.cmp(&b.grip));
    cache.dedup_by(|a, b| a.grip == b.grip);
    cache
}
fn write_cache(config: &Config, cache: &[CachedKey]) -> Result<()> {
    config::private_write(
        &config::state_dir().join("keygrips"),
        &serde_json::to_vec(&KeyCache {
            vault: config.vault.clone(),
            keyfile: config.keyfile.clone(),
            keys: cache.to_vec(),
        })?,
    )
}
fn read_cache(config: &Config) -> Vec<CachedKey> {
    fs::read(config::state_dir().join("keygrips"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<KeyCache>(&bytes).ok())
        .filter(|cache| cache.vault == config.vault && cache.keyfile == config.keyfile)
        .map(|cache| cache.keys)
        .unwrap_or_default()
}
pub fn update_index(vault: &Vault, config: &Config) -> Result<()> {
    write_cache(config, &build_cache(vault))
}
struct State {
    config: Config,
    vault: Option<Vault>,
    cache: Vec<CachedKey>,
    used: Instant,
    synced: Instant,
    last_sync: Option<String>,
    approvals: HashMap<(String, String, Vec<PathBuf>), Instant>,
    socket: PathBuf,
    version: String,
    stopping: Arc<AtomicBool>,
}
impl State {
    fn lock(&mut self) {
        self.vault = None;
        self.approvals.clear();
    }
    fn refresh(&mut self) -> Result<()> {
        let Some(vault) = &self.vault else {
            return Ok(());
        };
        let cache = build_cache(vault);
        write_cache(&self.config, &cache)?;
        self.cache = cache;
        Ok(())
    }
    fn unlock(&mut self, options: &Options) -> Result<()> {
        if self.vault.is_some() {
            self.used = Instant::now();
            return Ok(());
        }
        let no_password = self.config.credentials(None);
        let vault = if self.config.keyfile.is_some() {
            Vault::open(&self.config.vault, no_password).ok()
        } else {
            None
        };
        self.vault = Some(match vault {
            Some(vault) => vault,
            None => Vault::open(
                &self.config.vault,
                self.config
                    .credentials(Some(prompt::password(&self.config.pinentry, options)?)),
            )?,
        });
        self.used = Instant::now();
        self.refresh()?;
        if self.config.webdav.is_some()
            && let Err(error) = self.sync()
        {
            tracing::warn!(%error,"sync failed while unlocking; using local vault");
        }
        Ok(())
    }
    fn sync(&mut self) -> Result<()> {
        let result = (|| {
            let cfg = self
                .config
                .webdav_config()?
                .context("WebDAV is not configured")?;
            let vault = self.vault.as_ref().context("vault is locked")?;
            let credentials = vault.credentials().clone();
            let outcome = signet_vault::sync::sync(
                vault.path(),
                &config::state_dir().join("sync.json"),
                &cfg,
                &credentials,
            )?;
            self.vault = Some(Vault::open(&self.config.vault, credentials)?);
            self.refresh()?;
            Ok(outcome)
        })();
        self.synced = Instant::now();
        self.last_sync = Some(match &result {
            Ok(outcome) => format!("{outcome:?}"),
            Err(error) => format!("{error:#}"),
        });
        result.map(|_| ())
    }
    fn pair(
        &mut self,
        grip: &str,
        options: &Options,
        caller: &prompt::Caller,
        operation: &str,
        description: &str,
    ) -> Result<KeyPair> {
        self.unlock(options)?;
        let key = self
            .cache
            .iter()
            .find(|key| key.grip == grip)
            .cloned()
            .context("secret key unavailable")?;
        let approval = (
            grip.to_owned(),
            operation.to_owned(),
            caller.executables.clone(),
        );
        let remember = self.config.remember_duration()?;
        if self
            .approvals
            .get(&approval)
            .is_none_or(|when| when.elapsed() >= remember)
        {
            prompt::approve(
                &self.config.pinentry,
                options,
                operation,
                &key.title,
                &key.fingerprint,
                caller,
                description,
            )?;
            if !remember.is_zero() {
                self.approvals.insert(approval, Instant::now());
            }
        }
        self.used = Instant::now();
        for entry in self.vault.as_ref().context("vault locked")?.keys() {
            if entry.secret != SecretState::Usable {
                continue;
            }
            for key in entry.cert.keys().secret() {
                if Keygrip::of(key.key().mpis()).is_ok_and(|k| k.to_string() == grip) {
                    return key.key().clone().into_keypair();
                }
            }
        }
        bail!("secret key unavailable")
    }
}
pub fn prepare_home(config: &Config) -> Result<PathBuf> {
    config::private_dir(&config.gnupg_home)?;
    let conf = config.gnupg_home.join("gpg.conf");
    if !conf.exists() {
        config::private_write(
            &conf,
            b"# Signet owns this home's agent socket.\nno-autostart\n",
        )?;
    }
    let output = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&config.gnupg_home)
        .args(["--list-dirs", "agent-socket"])
        .output()?;
    if !output.status.success() {
        bail!("gpgconf could not resolve the agent socket");
    }
    let path = assuan::decode(
        output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout),
        false,
    )?;
    use std::os::unix::ffi::OsStringExt;
    let socket = PathBuf::from(std::ffi::OsString::from_vec(path));
    let runtime = PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() }));
    if runtime.is_dir() && socket.parent() == Some(config.gnupg_home.as_path()) {
        bail!(
            "GnuPG fell back to a home socket; create the runtime gnupg directory before starting Signet"
        );
    }
    Ok(socket)
}
struct Socket {
    listener: UnixListener,
    path: PathBuf,
}
impl Socket {
    fn bind(path: &Path) -> Result<Self> {
        config::private_dir(path.parent().context("socket has no parent")?)?;
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket() {
                bail!("{} exists and is not a socket", path.display());
            }
            match UnixStream::connect(path) {
                Ok(_) => bail!(
                    "another agent is listening on {}; stop it before starting Signet",
                    path.display()
                ),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path)?
                }
                Err(error) => return Err(error.into()),
            }
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.to_owned(),
        })
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
fn same_uid(uid: u32) -> bool {
    uid == unsafe { libc::geteuid() }
}
fn peer(stream: &UnixStream) -> Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut _,
            &mut len,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if !same_uid(credentials.uid) {
        bail!("connection from another uid denied");
    }
    Ok(credentials.pid as u32)
}
pub fn run(config: Config) -> Result<()> {
    let socket = prepare_home(&config)?;
    let agent_socket = Socket::bind(&socket)?;
    let control_socket = Socket::bind(&config::control_path())?;
    let output = Command::new("gpgconf").arg("--version").output()?;
    let version = String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or("2.2.40")
        .to_owned();
    let cache = read_cache(&config);
    let stop = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(State {
        config,
        vault: None,
        cache,
        used: Instant::now(),
        synced: Instant::now(),
        last_sync: None,
        approvals: HashMap::new(),
        socket,
        version,
        stopping: stop.clone(),
    }));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stop.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, stop.clone())?;
    tracing::info!(socket = %agent_socket.path.display(),"Signet agent listening");
    while !stop.load(Ordering::Relaxed) {
        for (socket, control) in [(&agent_socket, true), (&control_socket, false)] {
            match socket.listener.accept() {
                Ok((stream, _)) => {
                    let state = state.clone();
                    thread::spawn(move || {
                        let result = if control {
                            serve(stream, state)
                        } else {
                            serve_control(stream, state)
                        };
                        if let Err(error) = result {
                            tracing::debug!(%error,"connection closed");
                        }
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
        if let Ok(mut state) = state.try_lock() {
            if state.vault.is_some() && state.used.elapsed() >= state.config.lock_duration()? {
                state.lock();
            }
            if state.vault.is_some()
                && let Some(webdav) = &state.config.webdav
            {
                let interval = humantime::parse_duration(&webdav.sync_interval)?;
                if !interval.is_zero()
                    && state.synced.elapsed() >= interval
                    && let Err(error) = state.sync()
                {
                    tracing::warn!(%error,"periodic sync failed");
                }
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    state
        .lock()
        .map_err(|_| anyhow::anyhow!("agent state poisoned"))?
        .lock();
    Ok(())
}
#[derive(Default)]
struct Session {
    key: String,
    description: String,
    hash: Option<(HashAlgorithm, Vec<u8>)>,
    options: Options,
}
fn serve(mut stream: UnixStream, state: Arc<Mutex<State>>) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    let pid = peer(&stream)?;
    let caller = prompt::caller(pid);
    let mut reader = BufReader::new(stream.try_clone()?);
    writeln!(
        stream,
        "OK Pleased to meet you, process {}",
        std::process::id()
    )?;
    stream.flush()?;
    let mut session = Session::default();
    while let Some(line) = assuan::line(&mut reader)? {
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let line = std::str::from_utf8(&line)?;
        let (command, args) = line.split_once(' ').unwrap_or((line, ""));
        if command == "BYE" {
            writeln!(stream, "OK closing connection")?;
            break;
        }
        let result = handle(
            command,
            args,
            &mut session,
            &caller,
            &mut reader,
            &mut stream,
            &state,
        );
        match result {
            Ok(()) => writeln!(stream, "OK")?,
            Err(error) => {
                writeln!(stream, "ERR {} {}", error.code, error.message)?;
            }
        }
        stream.flush()?;
    }
    Ok(())
}
struct ProtocolError {
    code: u32,
    message: &'static str,
}
impl From<anyhow::Error> for ProtocolError {
    fn from(_: anyhow::Error) -> Self {
        Self {
            code: CANCEL,
            message: "Operation denied or failed",
        }
    }
}
impl From<std::io::Error> for ProtocolError {
    fn from(_: std::io::Error) -> Self {
        Self {
            code: SOURCE + 1,
            message: "I/O error",
        }
    }
}
fn unsupported() -> ProtocolError {
    ProtocolError {
        code: UNSUPPORTED,
        message: "Not supported by Signet",
    }
}
fn no_key() -> ProtocolError {
    ProtocolError {
        code: NO_KEY,
        message: "No secret key",
    }
}
fn handle(
    command: &str,
    args: &str,
    session: &mut Session,
    caller: &prompt::Caller,
    reader: &mut impl std::io::BufRead,
    writer: &mut impl Write,
    shared: &Arc<Mutex<State>>,
) -> std::result::Result<(), ProtocolError> {
    let ciphertext = if command == "PKDECRYPT" {
        Some(assuan::inquire(reader, writer)?)
    } else {
        None
    };
    let mut state = shared.lock().map_err(|_| unsupported())?;
    match command {
        "RESET" => {
            session.key.clear();
            session.description.clear();
            session.hash = None;
        }
        "NOP" => {}
        "OPTION" => {
            let (name, value) = args.split_once('=').unwrap_or((args, ""));
            if name == "putenv" {
                if let Some((name, value)) = value.split_once('=')
                    && [
                        "DISPLAY",
                        "WAYLAND_DISPLAY",
                        "DBUS_SESSION_BUS_ADDRESS",
                        "XAUTHORITY",
                        "PINENTRY_USER_DATA",
                    ]
                    .contains(&name)
                {
                    session.options.insert(name.into(), value.into());
                }
            } else {
                session.options.insert(name.into(), value.into());
            }
        }

        "GETINFO" => {
            let words = args.split_whitespace().collect::<Vec<_>>();
            let value = match words.as_slice() {
                ["version"] => state.version.clone(),
                ["pid"] => std::process::id().to_string(),
                ["socket_name"] => state.socket.display().to_string(),
                ["ssh_socket_name"] => String::new(),
                ["s2k_count"] => "65536".into(),
                ["s2k_time"] => "100".into(),
                ["std_env_names"] => {
                    "GPG_TTY:TERM:DISPLAY:XAUTHORITY:WAYLAND_DISPLAY:DBUS_SESSION_BUS_ADDRESS:"
                        .into()
                }
                ["cmd_has_option", "PKDECRYPT", "kem"] => String::new(),
                ["cmd_has_option", ..] => return Err(unsupported()),
                _ => return Err(unsupported()),
            };
            assuan::data(writer, value.as_bytes())?;
        }
        "GETEVENTCOUNTER" => writeln!(writer, "S EVENTCOUNTER 0 0 0")?,
        "HAVEKEY" => {
            if args.starts_with("--list") {
                let mut bytes = Vec::new();
                for key in &state.cache {
                    if let Ok(grip) = hex::decode(&key.grip) {
                        bytes.extend(grip);
                    }
                }
                assuan::data(writer, &bytes)?;
            } else if !args.split_whitespace().any(|grip| {
                state
                    .cache
                    .iter()
                    .any(|key| key.grip.eq_ignore_ascii_case(grip))
            }) {
                return Err(no_key());
            }
        }
        "KEYINFO" => {
            let data = args.split_whitespace().any(|a| a == "--data");
            let list = args.split_whitespace().any(|a| a == "--list");
            let grip = args
                .split_whitespace()
                .find(|a| !a.starts_with("--"))
                .unwrap_or("");
            let keys = state
                .cache
                .iter()
                .filter(|key| list || key.grip.eq_ignore_ascii_case(grip))
                .collect::<Vec<_>>();
            if keys.is_empty() && !list {
                return Err(no_key());
            }
            for key in keys {
                let line = format!("{} D - - - P - - -", key.grip);
                if data {
                    assuan::data(writer, format!("{line}\n").as_bytes())?;
                } else {
                    writeln!(writer, "S KEYINFO {line}")?;
                }
            }
        }
        "SIGKEY" | "SETKEY" => {
            if args.len() != 40 || hex::decode(args).is_err() {
                return Err(no_key());
            }
            session.key = args.to_ascii_uppercase();
        }
        "SETKEYDESC" => {
            session.description =
                String::from_utf8_lossy(&assuan::decode(args.as_bytes(), true)?).to_string()
        }
        "SETHASH" => {
            let mut words = args.split_whitespace();
            let algorithm = words.next().ok_or_else(unsupported)?;
            let algorithm = if let Some(name) = algorithm.strip_prefix("--hash=") {
                match name.to_ascii_lowercase().as_str() {
                    "sha1" => HashAlgorithm::SHA1,
                    "sha224" => HashAlgorithm::SHA224,
                    "sha256" => HashAlgorithm::SHA256,
                    "sha384" => HashAlgorithm::SHA384,
                    "sha512" => HashAlgorithm::SHA512,
                    _ => return Err(unsupported()),
                }
            } else {
                HashAlgorithm::from(algorithm.parse::<u8>().map_err(|_| unsupported())?)
            };
            let digest =
                hex::decode(words.next().ok_or_else(unsupported)?).map_err(|_| unsupported())?;
            if algorithm.digest_size().map_err(|_| unsupported())? != digest.len() {
                return Err(unsupported());
            }
            session.hash = Some((algorithm, digest));
        }
        "READKEY" => {
            let grip = args
                .split_whitespace()
                .find(|a| !a.starts_with("--"))
                .unwrap_or("");
            let key = state
                .cache
                .iter()
                .find(|key| key.grip.eq_ignore_ascii_case(grip))
                .ok_or_else(no_key)?;
            assuan::data(writer, &key.public)?;
        }
        "PKSIGN" => {
            let (algorithm, digest) = session.hash.take().ok_or_else(unsupported)?;
            let mut pair = state.pair(
                &session.key,
                &session.options,
                caller,
                "sign",
                &session.description,
            )?;
            let signature = crypto::sign(&mut pair, algorithm, &digest)?;
            assuan::data(writer, &signature)?;
        }
        "PKDECRYPT" => {
            let kem = !args.is_empty();
            if kem && args != "--kem=PGP" {
                return Err(unsupported());
            }
            let ciphertext = ciphertext.ok_or_else(unsupported)?;
            let mut pair = state.pair(
                &session.key,
                &session.options,
                caller,
                "decrypt",
                &session.description,
            )?;
            let decrypted = crypto::decrypt(&mut pair, &ciphertext, kem)?;
            if matches!(
                pair.public().mpis(),
                sequoia_openpgp::crypto::mpi::PublicKey::RSA { .. }
            ) {
                writeln!(writer, "S PADDING 0")?;
            }
            assuan::data(writer, &decrypted)?;
        }
        "RELOADAGENT" => {
            state.lock();
            let updated = Config::read()?;
            if updated.gnupg_home != state.config.gnupg_home {
                return Err(anyhow::anyhow!("restart Signet after changing gnupg_home").into());
            }
            state.config = updated;
            state.cache = read_cache(&state.config);
        }
        "KILLAGENT" => {
            state.lock();
            state.stopping.store(true, Ordering::Relaxed);
        }
        _ => return Err(unsupported()),
    }
    Ok(())
}
fn serve_control(mut stream: UnixStream, shared: Arc<Mutex<State>>) -> Result<()> {
    peer(&stream)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut bytes = Vec::new();
    use std::io::{BufRead, Read};
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    reader.by_ref().take(4097).read_until(b'\n', &mut bytes)?;
    if bytes.len() > 4096 {
        bail!("control request too large");
    }
    let request: Value = serde_json::from_slice(&bytes)?;
    let mut state = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
    let command = request
        .get("command")
        .and_then(Value::as_str)
        .context("missing command")?;
    let result: Result<Value> = (|| match command {
        "status" => Ok(
            json!({"locked":state.vault.is_none(),"key_count":state.cache.iter().map(|k| &k.fingerprint).collect::<std::collections::HashSet<_>>().len(),"last_sync":state.last_sync,"socket":state.socket,"gnupg_home":state.config.gnupg_home}),
        ),
        "keys" => Ok(if let Some(vault) = &state.vault {
            json!(vault.keys().into_iter().map(|key| json!({"fingerprint": key.fingerprint.to_hex(), "title": prompt::sanitize(&key.title), "secret": format!("{:?}", key.secret), "user_ids": key.cert.userids().map(|id| prompt::sanitize(&String::from_utf8_lossy(id.userid().value()))).collect::<Vec<_>>()})).collect::<Vec<_>>())
        } else {
            serde_json::to_value(&state.cache)?
        }),
        "lock" => {
            state.lock();
            Ok(json!({"locked":true}))
        }
        "unlock" => {
            state.unlock(&Options::new())?;
            Ok(json!({"locked":false}))
        }
        "sync" => {
            state.unlock(&Options::new())?;
            state.sync()?;
            Ok(json!({"sync":state.last_sync}))
        }
        "reload" => {
            let updated = Config::read()?;
            if updated.gnupg_home != state.config.gnupg_home {
                bail!("restart Signet after changing gnupg_home");
            }
            if updated.vault != state.config.vault || updated.keyfile != state.config.keyfile {
                state.lock();
            }
            state.config = updated;
            if let Some(vault) = &state.vault {
                let credentials = vault.credentials().clone();
                state.vault = Some(Vault::open(&state.config.vault, credentials)?);
                state.refresh()?;
            } else {
                state.cache = read_cache(&state.config);
            }
            state.approvals.clear();
            Ok(json!({"reloaded":true}))
        }
        _ => bail!("unknown control command"),
    })();
    let response = match result {
        Ok(value) => json!({"ok":true,"result":value}),
        Err(error) => json!({"ok":false,"error":format!("{error:#}")}),
    };
    serde_json::to_writer(&mut stream, &response)?;
    writeln!(stream)?;
    Ok(())
}
pub fn control(command: &str) -> Result<Value> {
    let mut stream =
        UnixStream::connect(config::control_path()).context("Signet agent is not running")?;
    serde_json::to_writer(&mut stream, &json!({"command":command}))?;
    writeln!(stream)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    let response: Value = serde_json::from_reader(stream)?;
    if response["ok"] != true {
        bail!("{}", response["error"].as_str().unwrap_or("control error"));
    }
    Ok(response["result"].clone())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn other_uid_is_rejected() {
        let uid = unsafe { libc::geteuid() };
        assert!(same_uid(uid));
        assert!(!same_uid(uid.wrapping_add(1)));
    }
}
