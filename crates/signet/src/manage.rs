// SPDX-License-Identifier: GPL-3.0-or-later
//! Setup steps shared by the command line and the app.
use crate::{
    agent,
    config::{self, Config},
};
use anyhow::{Context, Result, bail};
use signet_vault::{KeyEntry, SecretState, Vault};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

/// The configuration a new setup would write, for a vault at `vault` (the
/// default location when `None`) and an optional key file.
pub fn new_config(vault: Option<&Path>, keyfile: Option<&Path>) -> Result<Config> {
    if config::config_path().exists() {
        bail!(
            "Signet is already configured at {}",
            config::config_path().display()
        );
    }
    let mut config = Config::default();
    if let Some(vault) = vault {
        let parent = vault
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        config.vault = fs::canonicalize(parent)?
            .join(vault.file_name().context("vault path must name a file")?);
    }
    config.keyfile = keyfile.map(fs::canonicalize).transpose()?;
    Ok(config)
}

/// Opens the configured vault, or creates it when the file doesn't exist,
/// and writes the configuration. An empty password means key file only.
/// Returns whether an existing vault was opened.
pub fn initialize(config: &Config, password: Zeroizing<String>) -> Result<bool> {
    if config::config_path().exists() {
        bail!(
            "Signet is already configured at {}",
            config::config_path().display()
        );
    }
    let credentials = credentials(config, password)?;
    let existing = config.vault.exists();
    if existing {
        let vault = Vault::open(&config.vault, credentials)?;
        agent::update_index(&vault, config)?;
        config.write()?;
    } else {
        let parent = config.vault.parent().context("vault has no parent")?;
        config::private_dir(parent)?;
        let staging = tempfile::tempdir_in(parent)?;
        let path = staging.path().join("vault.kdbx");
        let vault = Vault::create(&path, credentials)?;
        publish_new_vault(config, &path, &vault)?;
    }
    Ok(existing)
}

fn credentials(config: &Config, password: Zeroizing<String>) -> Result<signet_vault::Credentials> {
    if password.is_empty() && config.keyfile.is_none() {
        bail!("master password cannot be empty without a keyfile");
    }
    Ok(config.credentials(if password.is_empty() {
        None
    } else {
        Some(password)
    }))
}

fn ensure_new(config: &Config) -> Result<()> {
    if config::config_path().exists() {
        bail!(
            "Signet is already configured at {}",
            config::config_path().display()
        );
    }
    if config.vault.exists() {
        bail!("a vault already exists at {}", config.vault.display());
    }
    Ok(())
}

/// Copies an existing vault file to the configured location after checking
/// that the credentials open it, then writes the configuration. The source
/// file is left unchanged.
pub fn initialize_from_file(
    config: &Config,
    source: &Path,
    password: Zeroizing<String>,
) -> Result<()> {
    ensure_new(config)?;
    let credentials = credentials(config, password)?;
    store_new_vault(config, &fs::read(source)?, credentials)
}

/// Downloads the vault from WebDAV, stores it at the configured location
/// and writes the configuration with these WebDAV settings.
pub fn initialize_from_webdav(
    config: &mut Config,
    url: url::Url,
    user: Option<String>,
    webdav_password: Option<Zeroizing<String>>,
    password: Zeroizing<String>,
) -> Result<()> {
    ensure_new(config)?;
    let credentials = credentials(config, password)?;
    let bytes = signet_vault::sync::download(
        &signet_vault::sync::WebDavConfig {
            url: url.clone(),
            username: user.clone(),
            password: webdav_password.clone(),
        },
        &credentials,
    )?;
    configure_webdav(config, url, user, webdav_password)?;
    store_new_vault(config, &bytes, credentials)
}

// Validate the exact bytes we will install, then publish without replacing
// an existing vault. Failed setup can be retried without deleting files.
fn store_new_vault(
    config: &Config,
    bytes: &[u8],
    credentials: signet_vault::Credentials,
) -> Result<()> {
    let parent = config.vault.parent().context("vault has no parent")?;
    config::private_dir(parent)?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    let vault = Vault::open(staged.path(), credentials)?;
    publish_new_vault(config, staged.path(), &vault)
}

fn publish_new_vault(config: &Config, staged: &Path, vault: &Vault) -> Result<()> {
    // Both files are on the same filesystem. Linking publishes atomically
    // and refuses to overwrite a vault created by a concurrent setup.
    fs::hard_link(staged, &config.vault)?;
    let result = (|| {
        fs::File::open(config.vault.parent().context("vault has no parent")?)?.sync_all()?;
        agent::update_index(vault, config)?;
        config.write()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&config.vault);
    }
    result
}

fn gpg(config: &Config, args: &[&str], input: &[u8]) -> Result<()> {
    let mut child = Command::new("gpg")
        .arg("--homedir")
        .arg(&config.gnupg_home)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().context("gpg stdin")?;
    // Write from another thread so a full stderr pipe can't block both sides.
    let output = std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(input));
        let output = child.wait_with_output();
        let written = writer.join().expect("gpg stdin writer panicked");
        let output = output?;
        if output.status.success() {
            written?;
        }
        anyhow::Ok(output)
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("gpg {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

/// Prepares the dedicated GnuPG home and imports the public certificates
/// and owner trust of `keys`. Returns the agent socket path.
pub fn setup_gnupg(config: &Config, keys: &[KeyEntry]) -> Result<PathBuf> {
    let socket = agent::prepare_home(config)?;
    let mut trust = String::new();
    let mut public = Vec::new();
    for key in keys {
        public.extend(signet_vault::public_armor(&key.cert)?.as_bytes());
        if key.secret != SecretState::None {
            trust.push_str(&format!("{}:6:\n", key.fingerprint.to_hex()));
        }
    }
    // gpg rejects empty input, and an empty vault has nothing to import.
    if !public.is_empty() {
        gpg(config, &["--batch", "--import"], &public)?;
    }
    if !trust.is_empty() {
        gpg(
            config,
            &["--batch", "--import-ownertrust"],
            trust.as_bytes(),
        )?;
    }
    Ok(socket)
}

/// Commands that keep systemd from holding the standard home's socket for
/// GnuPG's own agent.
pub const STOP_GNUPG_AGENT: &str = "systemctl --user mask --now gpg-agent.socket gpg-agent-extra.socket gpg-agent-browser.socket gpg-agent-ssh.socket\ngpgconf --kill gpg-agent";
/// Commands that let GnuPG start its own agent again.
pub const START_GNUPG_AGENT: &str = "systemctl --user unmask gpg-agent.socket gpg-agent-extra.socket gpg-agent-browser.socket gpg-agent-ssh.socket\nsystemctl --user start gpg-agent.socket";
/// Fails with the needed host command when Signet's Flatpak can't write
/// the standard GnuPG home.
pub fn check_standard_gnupg_home_access() -> Result<()> {
    if !crate::flatpak::can_write_standard_gnupg_home() {
        bail!(
            "Signet's Flatpak needs access to ~/.gnupg to serve it. Run this on the host, then try again:\nflatpak override --user --filesystem=~/.gnupg {}",
            std::env::var("FLATPAK_ID").unwrap_or_else(|_| "eu.nosini.Signet".into())
        );
    }
    Ok(())
}

/// The shell command that points GnuPG at Signet's home.
pub fn gnupghome_export(config: &Config) -> String {
    if config.uses_standard_gnupg_home() {
        return "unset GNUPGHOME".into();
    }
    format!(
        "export GNUPGHOME='{}'",
        config
            .gnupg_home
            .display()
            .to_string()
            .replace('\'', "'\\''")
    )
}

/// Sets the WebDAV address and user. A password is stored in the Secret
/// Service; `None` leaves a stored password unchanged.
pub fn set_webdav(
    config: &mut Config,
    url: url::Url,
    user: Option<String>,
    password: Option<Zeroizing<String>>,
) -> Result<()> {
    configure_webdav(config, url, user, password)?;
    config.write()
}

fn configure_webdav(
    config: &mut Config,
    url: url::Url,
    user: Option<String>,
    password: Option<Zeroizing<String>>,
) -> Result<()> {
    signet_vault::sync::WebDavConfig {
        url: url.clone(),
        username: user.clone(),
        password: None,
    }
    .validate()?;
    if let (Some(user), Some(password)) = (&user, &password) {
        config::webdav_entry(&url, user)?
            .set_password(password)
            .context("cannot save password in Secret Service; set webdav.password_command in config.toml instead")?;
    }
    let mut webdav = config.webdav.take().unwrap_or(config::WebDav {
        url: url.clone(),
        username: None,
        password_command: None,
        sync_interval: "10m".into(),
    });
    webdav.url = url;
    webdav.username = user;
    config.webdav = Some(webdav);
    Ok(())
}

/// Removes the WebDAV settings and the stored password.
pub fn clear_webdav(config: &mut Config) -> Result<()> {
    if let Some(webdav) = &config.webdav
        && let Some(user) = &webdav.username
    {
        let _ = config::webdav_entry(&webdav.url, user)?.delete_credential();
    }
    config.webdav = None;
    config.write()
}
