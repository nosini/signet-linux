// SPDX-License-Identifier: GPL-3.0-or-later
//! OpenPGP key storage in a KeePass database.
mod legacy_secret;
pub mod merge;
pub mod sync;

use keepass::{
    Database, DatabaseKey,
    config::KdfConfig,
    db::{EntryId, EntryRef, Times},
};
use sequoia_openpgp::{
    Cert, Fingerprint, Packet, cert::CertParser, cert::amalgamation::key::PrimaryKey,
    crypto::Password, parse::Parse, serialize::Serialize,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const PRIVATE_KEY: &str = "gpg_privateKeyArmored";
pub const PUBLIC_KEY: &str = "gpg_publicKeyArmored";
pub const FINGERPRINT: &str = "gpg_fingerprint";

#[derive(Clone, Default)]
pub struct Credentials {
    pub password: Option<Zeroizing<String>>,
    pub keyfile: Option<PathBuf>,
}
impl Credentials {
    pub fn database_key(&self) -> Result<DatabaseKey, VaultError> {
        if self.password.is_none() && self.keyfile.is_none() {
            return Err(VaultError::MissingCredentials);
        }
        let mut key = DatabaseKey::new();
        if let Some(password) = &self.password {
            key = key.with_password(password);
        }
        if let Some(path) = &self.keyfile {
            key = key.with_keyfile(&mut File::open(path)?)?;
        }
        Ok(key)
    }
}

#[derive(Error, Debug)]
pub enum VaultError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Open(#[from] keepass::db::DatabaseOpenError),
    #[error(transparent)]
    Save(#[from] keepass::db::DatabaseSaveError),
    #[error("OpenPGP error: {0}")]
    OpenPgp(String),
    #[error("a master password or key file is required")]
    MissingCredentials,
    #[error("key import cancelled")]
    Cancelled,
    #[error("key not found: {0}")]
    NotFound(Fingerprint),
    #[error("vault already exists")]
    Exists,
    #[error("invalid database structure: {0}")]
    Structure(#[from] keepass::db::signet_merge::MergeError),
    #[error("vault changed on disk; reload before saving")]
    Changed,
}
fn pgp_error(error: impl std::fmt::Display) -> VaultError {
    VaultError::OpenPgp(error.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretState {
    None,
    Usable,
    Locked,
}
#[derive(Clone, Debug)]
pub struct KeyEntry {
    pub uuid: Uuid,
    pub title: String,
    pub fingerprint: Fingerprint,
    pub cert: Cert,
    pub secret: SecretState,
}
#[derive(Debug)]
pub struct ImportPrompt {
    pub fingerprint: Fingerprint,
    pub user_id: String,
    pub attempt: usize,
}

/// Exclusive process lock for an entire read/modify/write or sync operation.
pub struct LockGuard {
    file: File,
}
impl Drop for LockGuard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
pub fn lock(path: &Path) -> Result<LockGuard, VaultError> {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(PathBuf::from(name))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(LockGuard { file })
}

pub struct Vault {
    pub database: Database,
    path: PathBuf,
    credentials: Credentials,
    original_hash: Option<String>,
}
impl Vault {
    pub fn create(path: &Path, credentials: Credentials) -> Result<Self, VaultError> {
        credentials.database_key()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _guard = lock(path)?;
        if path.exists() {
            return Err(VaultError::Exists);
        }
        let mut database = Database::new();
        database.config.kdf_config = KdfConfig::Argon2id {
            iterations: 3,
            memory: 64 * 1024 * 1024,
            parallelism: 2,
            version: argon2::Version::Version13,
        };
        database.root_mut().name = "Signet".into();
        database.meta.database_name = Some("Signet".into());
        database.meta.generator = Some("Signet".into());
        let mut vault = Self {
            database,
            path: path.into(),
            credentials,
            original_hash: None,
        };
        vault.save_locked()?;
        Ok(vault)
    }
    pub fn open(path: &Path, credentials: Credentials) -> Result<Self, VaultError> {
        let bytes = fs::read(path)?;
        let database = Database::parse(&bytes, credentials.database_key()?)?;
        Ok(Self {
            database,
            path: path.into(),
            credentials,
            original_hash: Some(sync::hash(&bytes)),
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }
    pub fn keys(&self) -> Vec<KeyEntry> {
        self.database
            .iter_all_entries()
            .filter(|entry| !in_recycle_bin(entry))
            .filter_map(|entry| match read_key(&entry) {
                Ok(key) => key,
                Err(_) => {
                    tracing::warn!(uuid = %entry.id().uuid(), "invalid key entry");
                    None
                }
            })
            .collect()
    }
    pub fn import(
        &mut self,
        data: &[u8],
        passphrase: &mut dyn FnMut(&ImportPrompt) -> Option<Zeroizing<String>>,
    ) -> Result<Vec<KeyEntry>, VaultError> {
        // Parse and unlock the complete input before changing the database.
        let mut certificates = Vec::new();
        for cert in CertParser::from_bytes(data).map_err(pgp_error)? {
            let cert = cert.map_err(pgp_error)?;
            let user_id = cert
                .userids()
                .next()
                .map(|u| u.userid().to_string())
                .unwrap_or_default();
            let fingerprint = cert.fingerprint();
            let mut attempt = 0;
            let cert = unlock_cert(cert, &mut || {
                attempt += 1;
                passphrase(&ImportPrompt {
                    fingerprint: fingerprint.clone(),
                    user_id: user_id.clone(),
                    attempt,
                })
            });
            certificates.push(cert?);
        }
        if certificates.is_empty() {
            return Err(pgp_error("no OpenPGP certificates in input"));
        }
        let original = self.database.clone();
        let result = (|| {
            let mut imported = Vec::new();
            for cert in certificates {
                let fingerprint = cert.fingerprint();
                let existing = self
                    .keys()
                    .into_iter()
                    .find(|key| key.fingerprint == fingerprint);
                let cert = if let Some(key) = &existing {
                    key.cert
                        .clone()
                        .merge_public_and_secret(cert)
                        .map_err(pgp_error)?
                } else {
                    cert
                };
                let public = public_armor(&cert)?;
                let private = if cert.is_tsk() {
                    Some(secret_armor(&cert)?)
                } else {
                    None
                };
                let id = if let Some(key) = existing {
                    EntryId::from_uuid(key.uuid)
                } else {
                    let mut root = self.database.root_mut();
                    let mut entry = root.add_entry();
                    entry.set_unprotected(
                        "Title",
                        cert.userids()
                            .next()
                            .map(|u| u.userid().to_string())
                            .unwrap_or_else(|| fingerprint.to_hex()),
                    );
                    entry.id()
                };
                {
                    let mut entry = self
                        .database
                        .entry_mut(id)
                        .ok_or_else(|| pgp_error("entry disappeared"))?;
                    let mut tracked = entry.track_changes();
                    tracked.set_unprotected(PUBLIC_KEY, public);
                    tracked.set_unprotected(FINGERPRINT, fingerprint.to_hex());
                    if let Some(private) = private {
                        tracked.set_protected(PRIVATE_KEY, private.to_string());
                    }
                }
                imported.push(
                    read_key(
                        &self
                            .database
                            .entry(id)
                            .ok_or_else(|| pgp_error("entry disappeared"))?,
                    )?
                    .ok_or_else(|| pgp_error("invalid imported key"))?,
                );
            }
            keepass::db::signet_merge::rebuild_references(&mut self.database)?;
            Ok(imported)
        })();
        if result.is_err() {
            self.database = original;
        }
        result
    }
    pub fn remove(&mut self, fingerprint: &Fingerprint) -> Result<(), VaultError> {
        keepass::db::signet_merge::rebuild_references(&mut self.database)?;
        let key = self
            .keys()
            .into_iter()
            .find(|key| &key.fingerprint == fingerprint)
            .ok_or_else(|| VaultError::NotFound(fingerprint.clone()))?;
        let recycle = if self.database.meta.recyclebin_enabled == Some(true) {
            match self.database.recycle_bin() {
                Some(bin) => Some(bin.id()),
                None => {
                    let id = {
                        let mut root = self.database.root_mut();
                        let mut bin = root.add_group();
                        bin.name = "Recycle Bin".into();
                        bin.id()
                    };
                    self.database.meta.recyclebin_uuid = Some(id.uuid());
                    self.database.meta.recyclebin_changed = Some(Times::now());
                    Some(id)
                }
            }
        } else {
            None
        };
        if let Some(mut entry) = self.database.entry_mut(EntryId::from_uuid(key.uuid)) {
            let mut tracked = entry.track_changes();
            if let Some(bin) = recycle {
                tracked.move_to(bin).map_err(pgp_error)?;
            } else {
                tracked.remove();
            }
        }
        Ok(())
    }
    /// Saves under an exclusive lock; rejects stale in-memory snapshots.
    pub fn save(&mut self) -> Result<(), VaultError> {
        let _guard = lock(&self.path)?;
        self.save_locked()
    }
    /// Caller must hold `lock(path)` across the read/modify/write operation.
    pub fn save_locked(&mut self) -> Result<(), VaultError> {
        let current = match fs::read(&self.path) {
            Ok(data) => Some(sync::hash(&data)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if current != self.original_hash {
            return Err(VaultError::Changed);
        }
        let mut bytes = Vec::new();
        self.database
            .save(&mut bytes, self.credentials.database_key()?)?;
        atomic_write(&self.path, &bytes)?;
        self.original_hash = Some(sync::hash(&bytes));
        Ok(())
    }
}
fn in_recycle_bin(entry: &EntryRef<'_>) -> bool {
    let database = entry.database();
    let Some(bin) = database.meta.recyclebin_uuid else {
        return false;
    };
    let mut parent = Some(entry.parent().id());
    while let Some(id) = parent {
        if id.uuid() == bin {
            return true;
        }
        parent = database.group(id).and_then(|g| g.parent().map(|p| p.id()));
    }
    false
}
fn read_key(entry: &EntryRef<'_>) -> Result<Option<KeyEntry>, VaultError> {
    let private = entry.get(PRIVATE_KEY).filter(|s| !s.is_empty());
    let public = entry.get(PUBLIC_KEY).filter(|s| !s.is_empty());
    let Some(armored) = private.or(public) else {
        return Ok(None);
    };
    let mut cert = Cert::from_bytes(armored.as_bytes()).map_err(pgp_error)?;
    let secret = if cert.is_tsk() {
        let mut attempts = 0;
        let max_attempts = cert.keys().secret().count();
        match unlock_cert(cert.clone(), &mut || {
            attempts += 1;
            if attempts <= max_attempts {
                entry.get_password().map(|s| Zeroizing::new(s.to_string()))
            } else {
                None
            }
        }) {
            Ok(unlocked) => {
                cert = unlocked;
                if cert.keys().unencrypted_secret().next().is_some() {
                    SecretState::Usable
                } else {
                    SecretState::Locked
                }
            }
            Err(_) => SecretState::Locked,
        }
    } else {
        SecretState::None
    };
    Ok(Some(KeyEntry {
        uuid: entry.id().uuid(),
        title: entry.get_title().unwrap_or("").into(),
        fingerprint: cert.fingerprint(),
        cert,
        secret,
    }))
}
// GnuPG offline-primary/card stubs carry no usable encrypted secret material.
fn secret_stub(material: &sequoia_openpgp::packet::key::SecretKeyMaterial) -> bool {
    matches!(material, sequoia_openpgp::packet::key::SecretKeyMaterial::Encrypted(encrypted)
        if matches!(encrypted.s2k(), sequoia_openpgp::crypto::S2K::Private { tag: 101, .. })
           && encrypted.algo() == sequoia_openpgp::types::SymmetricAlgorithm::Unencrypted)
}
pub fn unlock_cert(
    cert: Cert,
    prompt: &mut dyn FnMut() -> Option<Zeroizing<String>>,
) -> Result<Cert, VaultError> {
    let mut replacements = Vec::new();
    let mut cached_passphrase: Option<Zeroizing<String>> = None;
    for key in cert.keys().secret() {
        if secret_stub(key.key().secret()) {
            continue;
        }
        let mut unlocked = key.key().clone();
        if unlocked.secret().is_encrypted()
            && let Some(password) = &cached_passphrase
            && let Ok(key) =
                legacy_secret::decrypt(unlocked.clone(), &Password::from(password.as_str()))
        {
            unlocked = key;
        }
        if unlocked.secret().is_encrypted() {
            for attempt in 0..3 {
                let password = prompt().ok_or(VaultError::Cancelled)?;
                match legacy_secret::decrypt(unlocked.clone(), &Password::from(password.as_str())) {
                    Ok(k) => {
                        unlocked = k;
                        cached_passphrase = Some(password);
                        break;
                    }
                    Err(error) if attempt == 2 => {
                        // Keep the cause: a wrong passphrase and an
                        // unsupported key look alike otherwise.
                        return Err(pgp_error(format_args!(
                            "{:#}",
                            error.context(
                                "cannot unlock secret key after three attempts; check its passphrase and OpenPGP format",
                            )
                        )));
                    }
                    Err(_) => {}
                }
            }
        }
        replacements.push(if key.primary() {
            Packet::SecretKey(unlocked.role_into_primary())
        } else {
            Packet::SecretSubkey(unlocked.role_into_subordinate())
        });
    }
    cert.insert_packets(replacements)
        .map(|(cert, _)| cert)
        .map_err(pgp_error)
}
pub fn public_armor(cert: &Cert) -> Result<String, VaultError> {
    let mut buffer = Vec::new();
    cert.armored().serialize(&mut buffer).map_err(pgp_error)?;
    String::from_utf8(buffer).map_err(pgp_error)
}
/// The armored secret key with every unprotected secret encrypted under
/// `passphrase`, for backups and other OpenPGP software.
pub fn protected_secret_armor(
    cert: &Cert,
    passphrase: &Password,
) -> Result<Zeroizing<String>, VaultError> {
    let mut replacements = Vec::new();
    for key in cert.keys().unencrypted_secret() {
        let protected = key
            .key()
            .clone()
            .encrypt_secret(passphrase)
            .map_err(pgp_error)?;
        replacements.push(if key.primary() {
            Packet::SecretKey(protected.role_into_primary())
        } else {
            Packet::SecretSubkey(protected.role_into_subordinate())
        });
    }
    if replacements.is_empty() {
        return Err(pgp_error("the key has no usable secret to export"));
    }
    let (protected, _) = cert
        .clone()
        .insert_packets(replacements)
        .map_err(pgp_error)?;
    secret_armor(&protected)
}
fn secret_armor(cert: &Cert) -> Result<Zeroizing<String>, VaultError> {
    let mut buffer = Zeroizing::new(Vec::new());
    cert.as_tsk()
        .armored()
        .serialize(&mut *buffer)
        .map_err(pgp_error)?;
    String::from_utf8(buffer.to_vec())
        .map(Zeroizing::new)
        .map_err(pgp_error)
}
pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()
}
