// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use signet_vault::{Credentials, sync::WebDavConfig};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub vault: PathBuf,
    pub keyfile: Option<PathBuf>,
    pub gnupg_home: PathBuf,
    pub pinentry: String,
    pub lock_after_idle: String,
    pub approval: Approval,
    pub webdav: Option<WebDav>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Approval {
    pub remember: String,
    /// Ask before signing.
    pub sign: bool,
    /// Ask before decrypting.
    pub decrypt: bool,
}
impl Default for Approval {
    fn default() -> Self {
        Self {
            remember: "0s".into(),
            sign: true,
            decrypt: true,
        }
    }
}
impl Approval {
    /// Whether `operation` needs confirmation. Unknown operations always do.
    pub fn asks(&self, operation: &str) -> bool {
        match operation {
            "sign" => self.sign,
            "decrypt" => self.decrypt,
            _ => true,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDav {
    pub url: url::Url,
    pub username: Option<String>,
    pub password_command: Option<String>,
    #[serde(default = "sync_interval")]
    pub sync_interval: String,
}
fn sync_interval() -> String {
    "10m".into()
}
pub fn home() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
pub fn xdg(name: &str, default: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(default))
}
/// GnuPG's default home. Serving it lets programs reach Signet without
/// setting `GNUPGHOME`.
pub fn standard_gnupg_home() -> PathBuf {
    home().join(".gnupg")
}
/// Signet's own GnuPG home, used unless the standard one is chosen.
pub fn dedicated_gnupg_home() -> PathBuf {
    xdg("XDG_DATA_HOME", ".local/share").join("signet/gnupg")
}
pub fn config_path() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config").join("signet/config.toml")
}
pub fn state_dir() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state").join("signet")
}
pub fn control_path() -> PathBuf {
    env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| xdg("XDG_DATA_HOME", ".local/share"))
        .join("signet/control")
}
fn expand(path: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~") {
        home().join(rest)
    } else {
        path.to_owned()
    }
}
impl Default for Config {
    fn default() -> Self {
        let data = xdg("XDG_DATA_HOME", ".local/share").join("signet");
        Self {
            vault: data.join("vault.kdbx"),
            keyfile: None,
            gnupg_home: dedicated_gnupg_home(),
            pinentry: "pinentry".into(),
            lock_after_idle: "15m".into(),
            approval: Approval::default(),
            webdav: None,
        }
    }
}
impl Config {
    pub fn read() -> Result<Self> {
        let path = config_path();
        let mut config: Self = toml::from_str(
            &fs::read_to_string(&path)
                .with_context(|| format!("read {} (run signet init first)", path.display()))?,
        )?;
        config.vault = expand(&config.vault);
        config.gnupg_home = expand(&config.gnupg_home);
        config.keyfile = config.keyfile.map(|p| expand(&p));
        config.lock_duration()?;
        config.remember_duration()?;
        if !config.vault.is_absolute()
            || !config.gnupg_home.is_absolute()
            || config.keyfile.as_ref().is_some_and(|p| !p.is_absolute())
        {
            bail!("vault, keyfile and gnupg_home must be absolute paths");
        }
        if let Some(webdav) = &config.webdav {
            humantime::parse_duration(&webdav.sync_interval)?;
            WebDavConfig {
                url: webdav.url.clone(),
                username: webdav.username.clone(),
                password: None,
            }
            .validate()?;
        }
        Ok(config)
    }
    pub fn write(&self) -> Result<()> {
        let updated: toml_edit::DocumentMut = toml::to_string_pretty(self)?.parse()?;
        let mut document: toml_edit::DocumentMut = if config_path().exists() {
            fs::read_to_string(config_path())?.parse()?
        } else {
            toml_edit::DocumentMut::new()
        };
        merge_config(document.as_table_mut(), updated.as_table());
        private_write(&config_path(), document.to_string().as_bytes())
    }
    pub fn uses_standard_gnupg_home(&self) -> bool {
        self.gnupg_home == standard_gnupg_home()
    }
    pub fn lock_duration(&self) -> Result<Duration> {
        Ok(humantime::parse_duration(&self.lock_after_idle)?)
    }
    pub fn remember_duration(&self) -> Result<Duration> {
        Ok(humantime::parse_duration(&self.approval.remember)?)
    }
    pub fn credentials(&self, password: Option<Zeroizing<String>>) -> Credentials {
        Credentials {
            password,
            keyfile: self.keyfile.clone(),
        }
    }
    pub fn webdav_config(&self) -> Result<Option<WebDavConfig>> {
        let Some(webdav) = &self.webdav else {
            return Ok(None);
        };
        let password = if let Some(command) = &webdav.password_command {
            let output = Command::new("sh")
                .args(["-c", command])
                .output()
                .context("run WebDAV password_command")?;
            let bytes = Zeroizing::new(output.stdout);
            if !output.status.success() {
                bail!("WebDAV password_command failed");
            }
            Some(Zeroizing::new(
                std::str::from_utf8(&bytes)?
                    .lines()
                    .next()
                    .unwrap_or("")
                    .into(),
            ))
        } else if let Some(username) = &webdav.username {
            Some(Zeroizing::new(webdav_entry(&webdav.url, username)?.get_password().context("WebDAV password unavailable from Secret Service; configure password_command instead")?))
        } else {
            None
        };
        Ok(Some(WebDavConfig {
            url: webdav.url.clone(),
            username: webdav.username.clone(),
            password,
        }))
    }
}
fn merge_config(old: &mut toml_edit::Table, new: &toml_edit::Table) {
    old.retain(|name, _| new.contains_key(name));
    for (name, item) in new.iter() {
        if let Some(existing) = old.get_mut(name) {
            if let (Some(table), Some(updated)) = (existing.as_table_mut(), item.as_table()) {
                merge_config(table, updated);
            } else {
                let mut replacement = item.clone();
                if let (Some(value), Some(previous)) =
                    (replacement.as_value_mut(), existing.as_value())
                {
                    *value.decor_mut() = previous.decor().clone();
                }
                *existing = replacement;
            }
        } else {
            old.insert(name, item.clone());
        }
    }
}

pub fn webdav_entry(url: &url::Url, user: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(&format!("signet-webdav:{url}"), user)
        .context("Secret Service unavailable; configure password_command instead")
}
pub fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub fn private_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("file has no parent")?;
    private_dir(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approvals_default_to_asking() {
        let approval: Approval = toml::from_str("remember = '0s'").unwrap();
        assert!(approval.asks("sign") && approval.asks("decrypt"));
        let approval: Approval = toml::from_str("sign = false").unwrap();
        assert!(!approval.asks("sign"));
        assert!(approval.asks("decrypt"));
        assert!(approval.asks("export"));
    }
    #[test]
    fn updates_preserve_webdav_options_and_comments() {
        let mut old: toml_edit::DocumentMut = "# Vault settings\nvault = 'vault.kdbx' # private storage\n[webdav]\n# Use the credential helper\nurl = 'https://old.example/vault' # server\npassword_command = 'secret-tool lookup service signet'\nsync_interval = '17m'\n".parse().unwrap();
        let new: toml_edit::DocumentMut = "vault = 'vault.kdbx'\n[webdav]\nurl = 'https://new.example/vault'\npassword_command = 'secret-tool lookup service signet'\nsync_interval = '17m'\n".parse().unwrap();
        merge_config(old.as_table_mut(), new.as_table());
        let written = old.to_string();
        for comment in [
            "# Vault settings",
            "# private storage",
            "# Use the credential helper",
            "# server",
        ] {
            assert!(written.contains(comment), "{written}");
        }
        assert_eq!(old["webdav"]["sync_interval"].as_str(), Some("17m"));
        assert_eq!(
            old["webdav"]["url"].as_str(),
            Some("https://new.example/vault")
        );
    }
}
