// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    assuan,
    config::{self, Config},
    crypto,
    keygrip::Keygrip,
    prompt::{self, ApprovalRequest, Options, Prompter},
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
const SOURCE: u32 = 4 << 24;
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
        for key in entry.cert.keys().unencrypted_secret() {
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
    approvals: HashMap<(String, String, Vec<PathBuf>, Option<String>), Instant>,
    socket: PathBuf,
    version: String,
    stopping: Arc<AtomicBool>,
    generation: u64,
    prompting: Arc<Mutex<()>>,
    syncing: Arc<Mutex<()>>,
    prompter: Arc<dyn Prompter>,
}
impl State {
    fn lock(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.vault = None;
        self.approvals.clear();
    }
}

fn unlock_shared(shared: &Arc<Mutex<State>>, options: &Options) -> Result<()> {
    let (config, epoch, prompting, prompter) = {
        let mut state = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
        if state.vault.is_some() {
            state.used = Instant::now();
            return Ok(());
        }
        (
            state.config.clone(),
            state.generation,
            state.prompting.clone(),
            state.prompter.clone(),
        )
    };
    let guard = prompting
        .lock()
        .map_err(|_| anyhow::anyhow!("prompt state poisoned"))?;
    {
        let state = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
        if state.generation != epoch {
            bail!("vault state changed");
        }
        if state.vault.is_some() {
            return Ok(());
        }
    }
    let vault = if config.keyfile.is_some() {
        Vault::open(&config.vault, config.credentials(None)).ok()
    } else {
        None
    };
    let vault = match vault {
        Some(vault) => vault,
        None => Vault::open(
            &config.vault,
            config.credentials(Some(prompter.password(&config, options)?)),
        )?,
    };
    let cache = build_cache(&vault);
    write_cache(&config, &cache)?;
    {
        let mut state = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
        if state.generation != epoch {
            bail!("vault was locked while unlocking");
        }
        state.vault = Some(vault);
        state.cache = cache;
        state.used = Instant::now();
    }
    drop(guard);
    if config.webdav.is_some()
        && let Err(error) = sync_shared(shared)
    {
        tracing::warn!(%error, "sync failed while unlocking; using local vault");
    }
    Ok(())
}

fn sync_shared(shared: &Arc<Mutex<State>>) -> Result<()> {
    let (config, credentials, epoch, syncing) = {
        let state = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
        (
            state.config.clone(),
            state
                .vault
                .as_ref()
                .context("vault is locked")?
                .credentials()
                .clone(),
            state.generation,
            state.syncing.clone(),
        )
    };
    let _guard = syncing
        .try_lock()
        .map_err(|_| anyhow::anyhow!("sync already running"))?;
    let result = (|| -> Result<_> {
        let cfg = config
            .webdav_config()?
            .context("WebDAV is not configured")?;
        let outcome = signet_vault::sync::sync(
            &config.vault,
            &config::state_dir().join("sync.json"),
            &cfg,
            &credentials,
        )?;
        let vault = Vault::open(&config.vault, credentials)?;
        let cache = build_cache(&vault);
        write_cache(&config, &cache)?;
        Ok((outcome, vault, cache))
    })();
    let mut state = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
    // Lock/reload cancels publication; completed encrypted file writes remain valid.
    if state.generation != epoch {
        bail!("vault state changed during sync");
    }
    state.synced = Instant::now();
    state.last_sync = Some(match &result {
        Ok((outcome, _, _)) => format!("{outcome:?}"),
        Err(error) => format!("{error:#}"),
    });
    let (_, vault, cache) = result?;
    state.vault = Some(vault);
    state.cache = cache;
    state.approvals.clear();
    Ok(())
}

fn reload_shared(shared: &Arc<Mutex<State>>) -> Result<()> {
    let updated = Config::read()?;
    let (credentials, epoch) = {
        let mut state = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
        if updated.gnupg_home != state.config.gnupg_home {
            bail!("restart Signet after changing gnupg_home");
        }
        let credentials =
            if updated.vault == state.config.vault && updated.keyfile == state.config.keyfile {
                state
                    .vault
                    .as_ref()
                    .map(|vault| vault.credentials().clone())
            } else {
                None
            };
        state.lock();
        state.config = updated.clone();
        (credentials, state.generation)
    };
    let (vault, cache) = if let Some(credentials) = credentials {
        let _guard = signet_vault::lock(&updated.vault)?;
        let vault = Vault::open(&updated.vault, credentials)?;
        let cache = build_cache(&vault);
        write_cache(&updated, &cache)?;
        (Some(vault), cache)
    } else {
        (None, read_cache(&updated))
    };
    let mut state = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
    if state.generation != epoch {
        bail!("vault state changed during reload");
    }
    state.vault = vault;
    state.cache = cache;
    Ok(())
}

fn pair_shared(
    shared: &Arc<Mutex<State>>,
    grip: &str,
    options: &Options,
    caller: &prompt::Caller,
    operation: &str,
    description: &str,
) -> Result<KeyPair> {
    {
        let state = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
        if !state.cache.iter().any(|key| key.grip == grip) {
            bail!("secret key unavailable");
        }
    }
    unlock_shared(shared, options)?;
    let approval = (
        grip.to_owned(),
        operation.to_owned(),
        caller.executables.clone(),
        caller.app_id.clone(),
    );
    let (config, key, epoch, prompting, prompter) = {
        let state = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
        let key = state
            .cache
            .iter()
            .find(|key| key.grip == grip)
            .cloned()
            .context("secret key unavailable")?;
        (
            state.config.clone(),
            key,
            state.generation,
            state.prompting.clone(),
            state.prompter.clone(),
        )
    };
    let _guard = prompting
        .lock()
        .map_err(|_| anyhow::anyhow!("prompt state poisoned"))?;
    let remembered = {
        let state = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
        if state.generation != epoch || state.vault.is_none() {
            bail!("vault was locked before approval");
        }
        caller.identified()
            && state
                .approvals
                .get(&approval)
                .is_some_and(|when| when.elapsed() < config.remember_duration().unwrap_or_default())
    };
    if !remembered && config.approval.asks(operation) {
        // Confirmation is authorization: client options never reach the prompt.
        let _ = options;
        prompter.approve(
            &config,
            &ApprovalRequest {
                operation,
                title: &key.title,
                fingerprint: &key.fingerprint,
                caller,
                description,
            },
        )?;
    }
    let mut state = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
    if state.generation != epoch {
        bail!("vault was locked during approval");
    }
    let pair = state
        .vault
        .as_ref()
        .context("vault locked")?
        .keys()
        .into_iter()
        .filter(|entry| entry.secret == SecretState::Usable)
        .find_map(|entry| {
            entry
                .cert
                .keys()
                .unencrypted_secret()
                .find(|key| Keygrip::of(key.key().mpis()).is_ok_and(|k| k.to_string() == grip))
                .map(|key| key.key().clone().into_keypair())
        })
        .context("secret key unavailable")??;
    if caller.identified() && !config.remember_duration()?.is_zero() {
        state.approvals.insert(approval, Instant::now());
    }
    state.used = Instant::now();
    Ok(pair)
}
pub fn prepare_home(config: &Config) -> Result<PathBuf> {
    let standard = config.uses_standard_gnupg_home();
    if standard {
        crate::manage::check_standard_gnupg_home_access()?;
    }
    config::private_dir(&config.gnupg_home)?;
    let conf = config.gnupg_home.join("gpg.conf");
    if !standard && !conf.exists() {
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
/// Asks GnuPG's own agent to exit and binds its socket once it has.
fn take_over_socket(config: &Config, path: &Path) -> Result<Socket> {
    let _ = Command::new("gpgconf")
        .arg("--homedir")
        .arg(&config.gnupg_home)
        .args(["--kill", "gpg-agent"])
        .status();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match Socket::bind(path) {
            Ok(socket) => return Ok(socket),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
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
/// A bound agent. [`Agent::serve`] answers clients until stopped; a
/// [`Handle`] gives the hosting process access to the same state.
pub struct Agent {
    agent_socket: Socket,
    control_socket: Socket,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
}
impl Agent {
    /// Binds the GnuPG and control sockets. Fails if another agent is running.
    pub fn start(config: Config, prompter: Arc<dyn Prompter>) -> Result<Self> {
        let socket = prepare_home(&config)?;
        let agent_socket = match Socket::bind(&socket) {
            Ok(socket) => socket,
            // Serving the standard home replaces GnuPG's own agent.
            Err(_) if config.uses_standard_gnupg_home() => {
                take_over_socket(&config, &socket).map_err(|error| {
                    error.context(format!(
                        "GnuPG's own agent keeps the standard socket. Systemd may be holding it; stop that on the host with:\n{}",
                        crate::manage::STOP_GNUPG_AGENT
                    ))
                })?
            }
            Err(error) => return Err(error),
        };
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
            generation: 0,
            prompting: Arc::new(Mutex::new(())),
            syncing: Arc::new(Mutex::new(())),
            prompter,
        }));
        Ok(Self {
            agent_socket,
            control_socket,
            state,
            stop,
        })
    }
    pub fn handle(&self) -> Handle {
        Handle {
            shared: self.state.clone(),
        }
    }
    /// Setting this flag makes [`Agent::serve`] lock the vault and return.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }
    pub fn serve(self) -> Result<()> {
        let Self {
            agent_socket,
            control_socket,
            state,
            stop,
        } = self;
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
                    Err(error) => tracing::warn!(%error, "accept failed; retrying"),
                }
            }
            let mut schedule_sync = false;
            if let Ok(mut state) = state.try_lock() {
                if state.vault.is_some() && state.used.elapsed() >= state.config.lock_duration()? {
                    state.lock();
                }
                if state.vault.is_some()
                    && let Some(webdav) = &state.config.webdav
                {
                    let interval = humantime::parse_duration(&webdav.sync_interval)?;
                    if !interval.is_zero() && state.synced.elapsed() >= interval {
                        state.synced = Instant::now();
                        schedule_sync = true;
                    }
                }
            }
            if schedule_sync {
                let shared = state.clone();
                thread::spawn(move || {
                    if let Err(error) = sync_shared(&shared) {
                        tracing::warn!(%error, "periodic sync failed");
                    }
                });
            }
            thread::sleep(Duration::from_millis(25));
        }
        state
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))?
            .lock();
        Ok(())
    }
}
/// Runs the agent until SIGTERM or SIGINT.
pub fn run(config: Config, prompter: Arc<dyn Prompter>) -> Result<()> {
    let agent = Agent::start(config, prompter)?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, agent.stop_flag())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, agent.stop_flag())?;
    agent.serve()
}
/// Agent state as seen by the hosting process.
#[derive(Clone, Debug)]
pub struct Status {
    pub locked: bool,
    pub key_count: usize,
    pub last_sync: Option<String>,
    pub socket: PathBuf,
    pub gnupg_home: PathBuf,
    pub webdav: bool,
}
/// A key as listed by the agent. While locked only the keygrip index is
/// available, so `user_ids` is empty and `secret` is unknown.
#[derive(Clone, Debug)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub title: String,
    pub user_ids: Vec<String>,
    pub secret: Option<SecretState>,
}
impl KeyInfo {
    fn from_entry(entry: &signet_vault::KeyEntry) -> Self {
        Self {
            fingerprint: entry.fingerprint.to_hex(),
            title: prompt::sanitize(&entry.title),
            user_ids: entry
                .cert
                .userids()
                .map(|id| prompt::sanitize(&String::from_utf8_lossy(id.userid().value())))
                .collect(),
            secret: Some(entry.secret),
        }
    }
}
/// In-process access to a running agent. Methods block while prompting,
/// syncing or writing the vault, so call them off the UI thread.
#[derive(Clone)]
pub struct Handle {
    shared: Arc<Mutex<State>>,
}
impl Handle {
    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.shared
            .lock()
            .map_err(|_| anyhow::anyhow!("agent state poisoned"))
    }
    pub fn status(&self) -> Result<Status> {
        let state = self.state()?;
        Ok(Status {
            locked: state.vault.is_none(),
            key_count: state
                .cache
                .iter()
                .map(|k| &k.fingerprint)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            last_sync: state.last_sync.clone(),
            socket: state.socket.clone(),
            gnupg_home: state.config.gnupg_home.clone(),
            webdav: state.config.webdav.is_some(),
        })
    }
    pub fn config(&self) -> Result<Config> {
        Ok(self.state()?.config.clone())
    }
    pub fn lock(&self) -> Result<()> {
        self.state()?.lock();
        Ok(())
    }
    /// Unlocks through the agent's prompter.
    pub fn unlock(&self) -> Result<()> {
        unlock_shared(&self.shared, &Options::new())
    }
    pub fn sync(&self) -> Result<()> {
        unlock_shared(&self.shared, &Options::new())?;
        sync_shared(&self.shared)
    }
    /// Rereads the configuration file, keeping the vault unlocked when its
    /// location and key file are unchanged.
    pub fn reload(&self) -> Result<()> {
        reload_shared(&self.shared)
    }
    pub fn keys(&self) -> Result<Vec<KeyInfo>> {
        let state = self.state()?;
        Ok(if let Some(vault) = &state.vault {
            vault.keys().iter().map(KeyInfo::from_entry).collect()
        } else {
            let mut keys: Vec<KeyInfo> = Vec::new();
            for key in &state.cache {
                if !keys.iter().any(|k| k.fingerprint == key.fingerprint) {
                    keys.push(KeyInfo {
                        fingerprint: key.fingerprint.clone(),
                        title: prompt::sanitize(&key.title),
                        user_ids: Vec::new(),
                        secret: None,
                    });
                }
            }
            keys
        })
    }
    /// Unlocks, applies `change` to a fresh copy of the vault and saves it
    /// unless the file changed meanwhile, then republishes the result.
    fn modify<T>(&self, change: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
        unlock_shared(&self.shared, &Options::new())?;
        let (config, credentials, epoch) = {
            let state = self.state()?;
            (
                state.config.clone(),
                state
                    .vault
                    .as_ref()
                    .context("vault is locked")?
                    .credentials()
                    .clone(),
                state.generation,
            )
        };
        let mut vault = Vault::open(&config.vault, credentials)?;
        let result = change(&mut vault)?;
        {
            let _guard = signet_vault::lock(&config.vault)?;
            let state = self.state()?;
            if state.generation != epoch {
                bail!("vault was locked or reloaded during the change");
            }
            vault.save_locked()?;
            update_index(&vault, &config)?;
        }
        reload_shared(&self.shared)?;
        if config.webdav.is_some() {
            let shared = self.shared.clone();
            thread::spawn(move || {
                if let Err(error) = sync_shared(&shared) {
                    tracing::warn!(%error, "sync after a vault change failed");
                }
            });
        }
        Ok(result)
    }
    /// Imports OpenPGP keys. `passphrase` is asked for protected secret keys.
    pub fn import(
        &self,
        data: &[u8],
        passphrase: &mut dyn FnMut(
            &signet_vault::ImportPrompt,
        ) -> Option<zeroize::Zeroizing<String>>,
    ) -> Result<Vec<KeyInfo>> {
        self.modify(|vault| {
            Ok(vault
                .import(data, passphrase)?
                .iter()
                .map(KeyInfo::from_entry)
                .collect())
        })
    }
    pub fn remove(&self, fingerprint: &str) -> Result<()> {
        let fingerprint = fingerprint.parse()?;
        self.modify(|vault| Ok(vault.remove(&fingerprint)?))
    }
    /// The armored public certificate. Secret keys are never exported.
    pub fn export_public(&self, fingerprint: &str) -> Result<String> {
        let fingerprint = fingerprint.parse::<sequoia_openpgp::Fingerprint>()?;
        unlock_shared(&self.shared, &Options::new())?;
        let state = self.state()?;
        let key = state
            .vault
            .as_ref()
            .context("vault is locked")?
            .keys()
            .into_iter()
            .find(|key| key.fingerprint == fingerprint)
            .context("key not found")?;
        Ok(signet_vault::public_armor(&key.cert)?)
    }
    /// The secret key, protected with `passphrase`. The master password is
    /// required again so an unlocked, unattended session can't export it.
    /// Agent clients can never request this.
    pub fn export_secret(
        &self,
        fingerprint: &str,
        master_password: &str,
        passphrase: &str,
    ) -> Result<zeroize::Zeroizing<String>> {
        let fingerprint = fingerprint.parse::<sequoia_openpgp::Fingerprint>()?;
        if passphrase.is_empty() {
            bail!("choose a passphrase to protect the exported key");
        }
        unlock_shared(&self.shared, &Options::new())?;
        let cert = {
            let state = self.state()?;
            let vault = state.vault.as_ref().context("vault is locked")?;
            check_master_password(vault, master_password)?;
            vault
                .keys()
                .into_iter()
                .find(|key| key.fingerprint == fingerprint)
                .context("key not found")?
                .cert
        };
        Ok(signet_vault::protected_secret_armor(
            &cert,
            &passphrase.into(),
        )?)
    }
    /// The primary key and subkeys of a stored key.
    pub fn key_parts(&self, fingerprint: &str) -> Result<Vec<signet_vault::edit::KeyPart>> {
        let fingerprint = fingerprint.parse::<sequoia_openpgp::Fingerprint>()?;
        unlock_shared(&self.shared, &Options::new())?;
        let state = self.state()?;
        let key = state
            .vault
            .as_ref()
            .context("vault is locked")?
            .keys()
            .into_iter()
            .find(|key| key.fingerprint == fingerprint)
            .context("key not found")?;
        Ok(signet_vault::edit::describe(&key.cert))
    }
    /// Changes a stored key's subkeys and updates GnuPG. Like secret export,
    /// this needs the master password again. Agent clients can't request it.
    pub fn edit_key(
        &self,
        fingerprint: &str,
        master_password: &str,
        edit: &signet_vault::edit::KeyEdit,
    ) -> Result<()> {
        let fingerprint = fingerprint.parse::<sequoia_openpgp::Fingerprint>()?;
        unlock_shared(&self.shared, &Options::new())?;
        check_master_password(
            self.state()?.vault.as_ref().context("vault is locked")?,
            master_password,
        )?;
        self.modify(|vault| Ok(vault.edit(&fingerprint, edit)?))?;
        self.setup_gnupg().map_err(|error| {
            anyhow::anyhow!(
                "The key was changed, but GnuPG setup failed: {error:#}. Use Set Up GnuPG to retry."
            )
        })?;
        Ok(())
    }
    /// Imports the vault's certificates and owner trust into the dedicated
    /// GnuPG home.
    pub fn setup_gnupg(&self) -> Result<PathBuf> {
        unlock_shared(&self.shared, &Options::new())?;
        let (config, keys) = {
            let state = self.state()?;
            (
                state.config.clone(),
                state.vault.as_ref().context("vault is locked")?.keys(),
            )
        };
        crate::manage::setup_gnupg(&config, &keys)
    }
}
fn check_master_password(vault: &Vault, master_password: &str) -> Result<()> {
    let expected = vault
        .credentials()
        .password
        .as_deref()
        .map_or("", |p| p.as_str());
    if sequoia_openpgp::crypto::mem::secure_cmp(expected.as_bytes(), master_password.as_bytes())
        != std::cmp::Ordering::Equal
    {
        bail!("the master password is incorrect");
    }
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
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
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
    if command == "PKSIGN" || command == "PKDECRYPT" {
        let description = std::mem::take(&mut session.description);
        if !shared
            .lock()
            .map_err(|_| unsupported())?
            .cache
            .iter()
            .any(|key| key.grip == session.key)
        {
            return Err(no_key());
        }
        if command == "PKSIGN" {
            let (algorithm, digest) = session.hash.take().ok_or_else(unsupported)?;
            let mut pair = pair_shared(
                shared,
                &session.key,
                &session.options,
                caller,
                "sign",
                &description,
            )?;
            let signature = crypto::sign(&mut pair, algorithm, &digest)?;
            assuan::data(writer, &signature)?;
        } else {
            let kem = !args.is_empty();
            if kem && args != "--kem=PGP" {
                return Err(unsupported());
            }
            let ciphertext = assuan::inquire(reader, writer)?;
            let mut pair = pair_shared(
                shared,
                &session.key,
                &session.options,
                caller,
                "decrypt",
                &description,
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
        return Ok(());
    }
    if command == "RELOADAGENT" || command == "KILLAGENT" {
        let updated = if command == "RELOADAGENT" {
            Some(Config::read()?)
        } else {
            None
        };
        let cache = updated.as_ref().map(read_cache);
        let mut state = shared.lock().map_err(|_| unsupported())?;
        state.lock();
        if let Some(updated) = updated {
            if updated.gnupg_home != state.config.gnupg_home {
                return Err(anyhow::anyhow!("restart Signet after changing gnupg_home").into());
            }
            state.config = updated;
            state.cache = cache.unwrap_or_default();
        } else {
            state.stopping.store(true, Ordering::Relaxed);
        }
        return Ok(());
    }
    struct PublicState {
        cache: Vec<CachedKey>,
        socket: PathBuf,
        version: String,
    }
    let state = {
        let state = shared.lock().map_err(|_| unsupported())?;
        PublicState {
            cache: state.cache.clone(),
            socket: state.socket.clone(),
            version: state.version.clone(),
        }
    };
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
    let command = request
        .get("command")
        .and_then(Value::as_str)
        .context("missing command")?;
    let blocking: Option<Result<Value>> = match command {
        "reload" => Some(reload_shared(&shared).map(|_| json!({"reloaded":true}))),
        "unlock" => Some(unlock_shared(&shared, &Options::new()).map(|_| json!({"locked":false}))),
        "sync" => Some(
            unlock_shared(&shared, &Options::new())
                .and_then(|_| sync_shared(&shared))
                .map(|_| json!({"sync":"completed"})),
        ),
        _ => None,
    };
    let mut state = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("agent state poisoned"))?;
    let result: Result<Value> = if let Some(result) = blocking {
        result
    } else {
        (|| match command {
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
            _ => bail!("unknown control command"),
        })()
    };
    drop(state);
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
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
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
