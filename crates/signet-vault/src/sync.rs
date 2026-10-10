// SPDX-License-Identifier: GPL-3.0-or-later
//! Conditional WebDAV sync of an encrypted working copy.
use crate::{Credentials, VaultError, atomic_write, lock, merge};
use base64::{Engine, engine::general_purpose::STANDARD};
use keepass::{Database, db::DatabaseOpenError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io, path::Path, time::Duration};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

pub struct WebDavConfig {
    pub url: Url,
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
}
impl WebDavConfig {
    pub fn validate(&self) -> Result<(), SyncError> {
        let local = matches!(
            self.url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if self.url.scheme() != "https" && !(self.url.scheme() == "http" && local) {
            return Err(SyncError::InvalidUrl);
        }
        if !self.url.username().is_empty()
            || self.url.password().is_some()
            || self.url.fragment().is_some()
        {
            return Err(SyncError::InvalidUrl);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SyncOutcome {
    UpToDate,
    Pulled,
    Pushed,
    Merged,
    CreatedRemote,
}
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("WebDAV requires HTTPS (HTTP is allowed only on localhost)")]
    InvalidUrl,
    #[error("WebDAV authentication failed (HTTP {0})")]
    Auth(u16),
    #[error("remote vault not found")]
    NotFound,
    #[error("WebDAV request failed: {0}")]
    Network(#[from] ureq::Error),
    #[error("unexpected WebDAV response: HTTP {0}")]
    Http(u16),
    #[error("three conditional uploads failed; retry sync later")]
    Conflict,
    #[error("remote vault needs different credentials")]
    RemoteCredentials,
    #[error("remote vault is corrupt: {0}")]
    CorruptRemote(String),
    #[error("sync state is invalid: {0}")]
    State(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Merge(#[from] merge::MergeError),
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    url: String,
    username: Option<String>,
    etag: Option<String>,
    remote_hash: String,
    local_hash: String,
}
pub(crate) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn remote_database(bytes: &[u8], creds: &Credentials) -> Result<Database, SyncError> {
    Database::parse(bytes, creds.database_key()?).map_err(|error| match error {
        DatabaseOpenError::Key(_) => SyncError::RemoteCredentials,
        error => SyncError::CorruptRemote(error.to_string()),
    })
}
fn etag(response: &ureq::http::Response<ureq::Body>) -> Option<String> {
    response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}
fn check_status(status: u16) -> Result<(), SyncError> {
    match status {
        401 | 403 => Err(SyncError::Auth(status)),
        404 => Err(SyncError::NotFound),
        200..=299 => Ok(()),
        _ => Err(SyncError::Http(status)),
    }
}
/// Holds the vault's flock for the complete download/merge/upload transaction.
pub fn sync(
    local: &Path,
    state_path: &Path,
    cfg: &WebDavConfig,
    creds: &Credentials,
) -> Result<SyncOutcome, SyncError> {
    cfg.validate()?;
    let _guard = lock(local)?;
    let mut state = match fs::read(state_path) {
        Ok(bytes) => serde_json::from_slice::<State>(&bytes)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => State::default(),
        Err(error) => return Err(error.into()),
    };
    if state.url != cfg.url.as_str() || state.username != cfg.username {
        state = State::default();
    }
    let initial = fs::read(local)?;
    let local_hash = hash(&initial);
    let local_changed = local_hash != state.local_hash;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let authorization = cfg.username.as_ref().map(|user| {
        Zeroizing::new(format!(
            "Basic {}",
            STANDARD.encode(format!(
                "{user}:{}",
                cfg.password.as_ref().map(|p| p.as_str()).unwrap_or("")
            ))
        ))
    });
    for attempt in 0..3 {
        let mut get = agent.get(cfg.url.as_str());
        if let Some(auth) = &authorization {
            get = get.header("Authorization", auth.as_str());
        }
        if attempt == 0
            && let Some(tag) = &state.etag
        {
            get = get.header("If-None-Match", tag);
        }
        let mut response = get.call()?;
        let status = response.status().as_u16();
        let missing = status == 404;
        let mut tag = etag(&response);
        let (remote, remote_hash, remote_changed) = match status {
            304 if !state.remote_hash.is_empty() => {
                tag = tag.or(state.etag.clone());
                (None, state.remote_hash.clone(), false)
            }
            404 => (None, String::new(), false),
            200 => {
                let bytes = response
                    .body_mut()
                    .with_config()
                    .limit(256 * 1024 * 1024)
                    .read_to_vec()?;
                // Authenticate even an unchanged downloaded body before accepting it.
                remote_database(&bytes, creds)?;
                let digest = hash(&bytes);
                let changed = digest != state.remote_hash;
                (Some(bytes), digest, changed)
            }
            _ => {
                check_status(status)?;
                return Err(SyncError::Http(status));
            }
        };
        let (candidate, outcome, upload) = if missing {
            // The local file must be a valid database even for an initial upload.
            Database::parse(&initial, creds.database_key()?).map_err(VaultError::from)?;
            (initial.clone(), SyncOutcome::CreatedRemote, true)
        } else if !local_changed && !remote_changed {
            (initial.clone(), SyncOutcome::UpToDate, false)
        } else if !local_changed {
            (
                remote.ok_or(SyncError::Http(status))?,
                SyncOutcome::Pulled,
                false,
            )
        } else if !remote_changed || remote_hash == local_hash {
            (
                initial.clone(),
                if remote_hash == local_hash {
                    SyncOutcome::UpToDate
                } else {
                    SyncOutcome::Pushed
                },
                remote_hash != local_hash,
            )
        } else {
            let mut database =
                Database::parse(&initial, creds.database_key()?).map_err(VaultError::from)?;
            let other = remote_database(remote.as_deref().ok_or(SyncError::Http(status))?, creds)?;
            merge::merge(&mut database, &other)?;
            let mut bytes = Vec::new();
            database
                .save(&mut bytes, creds.database_key()?)
                .map_err(VaultError::from)?;
            (bytes, SyncOutcome::Merged, true)
        };
        let digest = hash(&candidate);
        if upload {
            let mut put = agent
                .put(cfg.url.as_str())
                .header("Content-Type", "application/octet-stream");
            if let Some(auth) = &authorization {
                put = put.header("Authorization", auth.as_str());
            }
            if missing {
                put = put.header("If-None-Match", "*");
            } else if let Some(tag) = &tag {
                put = put.header("If-Match", tag);
            }
            let response = put.send(candidate.as_slice())?;
            let status = response.status().as_u16();
            if status == 412 {
                continue;
            }
            check_status(status)?;
            // A PUT without an ETag invalidates the old tag. Compare hashes next time.
            tag = etag(&response);
        }
        if candidate != initial {
            backup(local, &initial)?;
            atomic_write(local, &candidate)?;
        }
        state = State {
            url: cfg.url.to_string(),
            username: cfg.username.clone(),
            etag: tag,
            remote_hash: digest.clone(),
            local_hash: digest,
        };
        atomic_write(state_path, &serde_json::to_vec(&state)?)?;
        return Ok(outcome);
    }
    Err(SyncError::Conflict)
}
fn backup(local: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = local
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("backups");
    fs::create_dir_all(&dir)?;
    let stem = local.file_stem().unwrap_or_default().to_string_lossy();
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ");
    atomic_write(&dir.join(format!("{stem}-{stamp}.kdbx")), bytes)?;
    let prefix = format!("{stem}-");
    let mut files = fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_ok_and(|t| t.is_file())
                && e.file_name().to_string_lossy().starts_with(&prefix)
                && e.path().extension().is_some_and(|x| x == "kdbx")
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|e| e.file_name());
    let excess = files.len().saturating_sub(5);
    for file in files.into_iter().take(excess) {
        fs::remove_file(file.path())?;
    }
    Ok(())
}
