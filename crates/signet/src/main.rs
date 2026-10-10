// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use signet::{agent, config::Config, manage, prompt};
use signet_vault::Vault;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
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
fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(io::stderr)
        .init();
    let command = Cli::parse().command;
    if let Action::Init { vault, keyfile } = command {
        let config = manage::new_config(vault.as_deref(), keyfile.as_deref())?;
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
        manage::initialize(&config, first)?;
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
            agent::run(config, Arc::new(prompt::PinentryPrompter))
        }
        Action::Import { files } => {
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
            let guard = signet_vault::lock(&config.vault)?;
            vault.save_locked()?;
            agent::update_index(&vault, &config)?;
            drop(guard);
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
            let mut vault = open(&config)?;
            vault.remove(&fingerprint.parse()?)?;
            let guard = signet_vault::lock(&config.vault)?;
            vault.save_locked()?;
            agent::update_index(&vault, &config)?;
            drop(guard);
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
            let vault = open(&config)?;
            let socket = manage::setup_gnupg(&config, &vault.keys())?;
            println!("{}", manage::gnupghome_export(&config));
            println!("Agent socket: {}", socket.display());
            Ok(())
        }
        Action::Webdav {
            command: Webdav::Set { url, user },
        } => {
            signet_vault::sync::WebDavConfig {
                url: url.clone(),
                username: user.clone(),
                password: None,
            }
            .validate()?;
            let password = if user.is_some() {
                Some(password("WebDAV password: ")?)
            } else {
                None
            };
            manage::set_webdav(&mut config, url, user, password)?;
            let _ = agent::control("reload");
            Ok(())
        }
        Action::Webdav {
            command: Webdav::Clear,
        } => {
            manage::clear_webdav(&mut config)?;
            let _ = agent::control("reload");
            Ok(())
        }
        _ => unreachable!(),
    }
}
