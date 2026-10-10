// SPDX-License-Identifier: GPL-3.0-or-later
mod agent;
mod assuan;
mod config;
mod crypto;
mod keygrip;
mod prompt;
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use config::Config;
use signet_vault::Vault;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;
#[derive(Parser)]
#[command(
    version,
    about = "OpenPGP keys in KeePass, with approval for every use"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Agent,
    Init {
        #[arg(long)]
        vault: Option<PathBuf>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
    },
    Import {
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    List,
    Remove {
        fingerprint: String,
    },
    /// Export the public certificate. Secret-key export is refused by the agent.
    Export {
        fingerprint: String,
    },
    SetupGnupg,
    Status,
    Lock,
    Unlock,
    Sync,
    Webdav {
        #[command(subcommand)]
        command: Webdav,
    },
}
#[derive(Subcommand)]
enum Webdav {
    Set {
        url: url::Url,
        #[arg(long)]
        user: Option<String>,
    },
    Clear,
}
fn password(prompt: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}
fn open(config: &Config) -> Result<Vault> {
    if config.keyfile.is_some()
        && let Ok(vault) = Vault::open(&config.vault, config.credentials(None))
    {
        return Ok(vault);
    }
    Vault::open(
        &config.vault,
        config.credentials(Some(password("Vault master password: ")?)),
    )
    .map_err(Into::into)
}
fn notify() {
    if agent::control("reload").is_ok()
        && Config::read()
            .ok()
            .is_some_and(|config| config.webdav.is_some())
    {
        let _ = agent::control("sync");
    }
}
fn gpg(config: &Config, args: &[&str], input: &[u8]) -> Result<()> {
    let mut child = Command::new("gpg")
        .arg("--homedir")
        .arg(&config.gnupg_home)
        .args(args)
        .stdin(Stdio::piped())
        .spawn()?;
    child.stdin.take().context("gpg stdin")?.write_all(input)?;
    if !child.wait()?.success() {
        bail!("gpg {} failed", args.join(" "));
    }
    Ok(())
}
fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();
    let command = Cli::parse().command;
    if let Action::Init { vault, keyfile } = command {
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
                .unwrap_or_else(|| std::path::Path::new("."));
            fs::create_dir_all(parent)?;
            config.vault = fs::canonicalize(parent)?
                .join(vault.file_name().context("vault path must name a file")?);
        }
        config.keyfile = keyfile.map(fs::canonicalize).transpose()?;
        let existing = config.vault.exists();
        let first = password(if existing {
            "Vault master password (empty for keyfile only): "
        } else {
            "New master password (empty for keyfile only): "
        })?;
        if first.is_empty() && config.keyfile.is_none() {
            bail!("master password cannot be empty without a keyfile");
        }
        if !existing {
            let second = password("Repeat master password: ")?;
            if *first != *second {
                bail!("passwords do not match");
            }
        }
        let credentials = config.credentials(if first.is_empty() { None } else { Some(first) });
        let vault = if existing {
            Vault::open(&config.vault, credentials)?
        } else {
            Vault::create(&config.vault, credentials)?
        };
        agent::update_index(&vault, &config)?;
        config.write()?;
        println!(
            "{} {}",
            if existing { "Connected to" } else { "Created" },
            config.vault.display()
        );
        return Ok(());
    }
    if let Action::Status | Action::Lock | Action::Unlock | Action::Sync = command {
        let name = match command {
            Action::Status => "status",
            Action::Lock => "lock",
            Action::Unlock => "unlock",
            _ => "sync",
        };
        println!("{}", serde_json::to_string_pretty(&agent::control(name)?)?);
        return Ok(());
    }
    let mut config = Config::read()?;
    match command {
        Action::Agent => {
            if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            agent::run(config)
        }
        Action::Import { files } => {
            let _lock = signet_vault::lock(&config.vault)?;
            let mut vault = open(&config)?;
            for file in files {
                let bytes = Zeroizing::new(fs::read(file)?);
                for key in vault.import(&bytes, &mut |prompt| {
                    password(&format!(
                        "Passphrase for {} (attempt {}): ",
                        prompt.fingerprint, prompt.attempt
                    ))
                    .ok()
                })? {
                    println!("{} {}", key.fingerprint, prompt::sanitize(&key.title));
                }
            }
            vault.save_locked()?;
            agent::update_index(&vault, &config)?;
            drop(_lock);
            notify();
            Ok(())
        }
        Action::List => {
            for key in open(&config)?.keys() {
                println!(
                    "{} {:?} {}",
                    key.fingerprint,
                    key.secret,
                    prompt::sanitize(&key.title)
                );
            }
            Ok(())
        }
        Action::Remove { fingerprint } => {
            let _lock = signet_vault::lock(&config.vault)?;
            let mut vault = open(&config)?;
            vault.remove(&fingerprint.parse()?)?;
            vault.save_locked()?;
            agent::update_index(&vault, &config)?;
            drop(_lock);
            notify();
            Ok(())
        }
        Action::Export { fingerprint } => {
            let fingerprint = fingerprint.parse::<sequoia_openpgp::Fingerprint>()?;
            let key = open(&config)?
                .keys()
                .into_iter()
                .find(|key| key.fingerprint == fingerprint)
                .context("key not found")?;
            io::stdout().write_all(signet_vault::public_armor(&key.cert)?.as_bytes())?;
            Ok(())
        }
        Action::SetupGnupg => {
            let socket = agent::prepare_home(&config)?;
            let vault = open(&config)?;
            let mut trust = String::new();
            let mut public = Vec::new();
            for key in vault.keys() {
                public.extend(signet_vault::public_armor(&key.cert)?.as_bytes());
                if key.secret != signet_vault::SecretState::None {
                    trust.push_str(&format!("{}:6:\n", key.fingerprint.to_hex()));
                }
            }
            gpg(&config, &["--batch", "--import"], &public)?;
            gpg(
                &config,
                &["--batch", "--import-ownertrust"],
                trust.as_bytes(),
            )?;
            println!(
                "export GNUPGHOME='{}'",
                config
                    .gnupg_home
                    .display()
                    .to_string()
                    .replace('\'', "'\\''")
            );
            println!("Agent socket: {}", socket.display());
            Ok(())
        }
        Action::Webdav {
            command: Webdav::Set { url, user },
        } => {
            let check = signet_vault::sync::WebDavConfig {
                url: url.clone(),
                username: user.clone(),
                password: None,
            };
            check.validate()?;
            if let Some(user) = &user {
                let password = password("WebDAV password: ")?;
                config::webdav_entry(&url,user)?.set_password(&password).context("cannot save password in Secret Service; set webdav.password_command in config.toml instead")?;
            }
            config.webdav = Some(config::WebDav {
                url,
                username: user,
                password_command: None,
                sync_interval: "10m".into(),
            });
            config.write()?;
            let _ = agent::control("reload");
            Ok(())
        }
        Action::Webdav {
            command: Webdav::Clear,
        } => {
            if let Some(webdav) = &config.webdav
                && let Some(user) = &webdav.username
            {
                let _ = config::webdav_entry(&webdav.url, user)?.delete_credential();
            }
            config.webdav = None;
            config.write()?;
            let _ = agent::control("reload");
            Ok(())
        }
        _ => unreachable!(),
    }
}
