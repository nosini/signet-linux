// SPDX-License-Identifier: GPL-3.0-or-later
//! Subkey changes, signed with the stored key's primary key.
use crate::{VaultError, pgp_error};
use sequoia_openpgp::{
    Cert, Fingerprint, Packet,
    cert::{SubkeyRevocationBuilder, amalgamation::key::PrimaryKey},
    crypto::{KeyPair, mpi},
    packet::{
        Key, Signature,
        key::{Key4, KeyParts, PublicParts, SecretParts, SubordinateRole, UnspecifiedRole},
        signature::SignatureBuilder,
    },
    policy::StandardPolicy,
    types::{Curve, HashAlgorithm, KeyFlags, ReasonForRevocation, SignatureType},
};
use std::time::SystemTime;

/// Algorithms offered for new subkeys. GnuPG reads all of them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Ed25519,
    Cv25519,
    Rsa3072,
    Rsa4096,
}
impl Algorithm {
    pub const ALL: [Algorithm; 4] = [
        Algorithm::Ed25519,
        Algorithm::Cv25519,
        Algorithm::Rsa3072,
        Algorithm::Rsa4096,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::Cv25519 => "Cv25519",
            Algorithm::Rsa3072 => "RSA 3072",
            Algorithm::Rsa4096 => "RSA 4096",
        }
    }
    pub fn can_sign(self) -> bool {
        self != Algorithm::Cv25519
    }
    pub fn can_encrypt(self) -> bool {
        self != Algorithm::Ed25519
    }
}

/// What a key may be used for. Certification stays with the primary key.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    pub sign: bool,
    pub encrypt: bool,
    pub authenticate: bool,
}
impl Usage {
    fn flags(self) -> KeyFlags {
        let mut flags = KeyFlags::empty();
        if self.sign {
            flags = flags.set_signing();
        }
        if self.encrypt {
            flags = flags.set_transport_encryption().set_storage_encryption();
        }
        if self.authenticate {
            flags = flags.set_authentication();
        }
        flags
    }
    fn from_flags(flags: &KeyFlags) -> Self {
        Self {
            sign: flags.for_signing(),
            encrypt: flags.for_transport_encryption() || flags.for_storage_encryption(),
            authenticate: flags.for_authentication(),
        }
    }
    fn is_empty(self) -> bool {
        !(self.sign || self.encrypt || self.authenticate)
    }
    /// Signing and authentication sign with the subkey, so its binding
    /// needs the subkey's own signature too.
    fn signs(self) -> bool {
        self.sign || self.authenticate
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationReason {
    Retired,
    Superseded,
    Compromised,
    Unspecified,
}
impl RevocationReason {
    fn code(self) -> ReasonForRevocation {
        match self {
            RevocationReason::Retired => ReasonForRevocation::KeyRetired,
            RevocationReason::Superseded => ReasonForRevocation::KeySuperseded,
            RevocationReason::Compromised => ReasonForRevocation::KeyCompromised,
            RevocationReason::Unspecified => ReasonForRevocation::Unspecified,
        }
    }
}

#[derive(Clone, Debug)]
pub enum KeyEdit {
    /// Generates a new subkey.
    AddSubkey {
        algorithm: Algorithm,
        usage: Usage,
        expires: Option<SystemTime>,
    },
    /// Sets the primary key's or a subkey's expiry; `None` never expires.
    SetExpiry {
        key: Fingerprint,
        expires: Option<SystemTime>,
    },
    RevokeSubkey {
        key: Fingerprint,
        reason: RevocationReason,
        message: String,
    },
    /// Removes a subkey and its secret from the certificate.
    DeleteSubkey { key: Fingerprint },
    /// Binds a key from another stored certificate as a subkey. The key
    /// packet is kept as is, so its creation time and fingerprint stay the
    /// same and messages encrypted to it can still be decrypted.
    AttachSubkey { key: Fingerprint, usage: Usage },
}

/// One key of a certificate, as shown to the user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPart {
    pub fingerprint: String,
    pub primary: bool,
    pub algorithm: String,
    pub usage: Usage,
    pub certify: bool,
    pub created: SystemTime,
    pub expires: Option<SystemTime>,
    pub revoked: bool,
    pub secret: bool,
}

/// The primary key and subkeys of `cert`. Uses the newest self-signature
/// even where the standard policy rejects it, so old keys still show.
pub fn describe(cert: &Cert) -> Vec<KeyPart> {
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).ok();
    cert.keys()
        .map(|ka| {
            let key = ka.key();
            let fingerprint = key.fingerprint();
            let checked = valid
                .as_ref()
                .and_then(|valid| valid.keys().key_handle(fingerprint.clone()).next());
            let (flags, expires) = match &checked {
                // Sequoia lets a subkey inherit the primary key's direct
                // signature; show the subkey's own binding, as GnuPG does.
                Some(checked) if !ka.primary() => (
                    checked.binding_signature().key_flags(),
                    checked
                        .binding_signature()
                        .key_validity_period()
                        .filter(|period| !period.is_zero())
                        .map(|period| key.creation_time() + period),
                ),
                Some(checked) => (checked.key_flags(), checked.key_expiration_time()),
                None => {
                    let signature = ka.self_signatures().next().or_else(|| {
                        ka.primary()
                            .then(|| cert.userids().flat_map(|u| u.self_signatures()).next())
                            .flatten()
                    });
                    (
                        signature.and_then(|s| s.key_flags()),
                        signature
                            .and_then(|s| s.key_validity_period())
                            .filter(|period| !period.is_zero())
                            .map(|period| key.creation_time() + period),
                    )
                }
            };
            let flags = flags.unwrap_or_else(KeyFlags::empty);
            KeyPart {
                fingerprint: fingerprint.to_hex(),
                primary: ka.primary(),
                algorithm: algorithm_name(key.mpis(), key.pk_algo()),
                usage: Usage::from_flags(&flags),
                certify: flags.for_certification(),
                created: key.creation_time(),
                expires,
                revoked: ka.self_revocations().next().is_some(),
                secret: key.has_unencrypted_secret(),
            }
        })
        .collect()
}

fn algorithm_name(
    mpis: &mpi::PublicKey,
    algo: sequoia_openpgp::types::PublicKeyAlgorithm,
) -> String {
    let curve = |curve: &Curve| match curve {
        Curve::Ed25519 => "Ed25519".into(),
        Curve::Cv25519 => "Cv25519".into(),
        other => other.to_string(),
    };
    match mpis {
        mpi::PublicKey::RSA { n, .. } => format!("RSA {}", n.bits()),
        mpi::PublicKey::EdDSA { curve: c, .. }
        | mpi::PublicKey::ECDSA { curve: c, .. }
        | mpi::PublicKey::ECDH { curve: c, .. } => curve(c),
        _ => algo.to_string(),
    }
}

/// Applies `edit` to `cert`, whose primary secret must be unlocked.
/// `find_key` returns the unlocked key with a fingerprint from another
/// stored certificate, for [`KeyEdit::AttachSubkey`].
pub fn apply(
    cert: Cert,
    edit: &KeyEdit,
    find_key: impl Fn(&Fingerprint) -> Option<Key<SecretParts, UnspecifiedRole>>,
) -> Result<Cert, VaultError> {
    let mut primary = primary_signer(&cert)?;
    let packets: Vec<Packet> = match edit {
        KeyEdit::AddSubkey {
            algorithm,
            usage,
            expires,
        } => {
            check_usage(*usage, algorithm.can_sign(), algorithm.can_encrypt())?;
            let now = SystemTime::now();
            let mut key = generate(*algorithm)?;
            key.set_creation_time(now).map_err(pgp_error)?;
            let binding = bind(&cert, &mut primary, &key, *usage, *expires, now)?;
            vec![key.into(), binding.into()]
        }
        KeyEdit::SetExpiry { key, expires } => {
            if let Some(expires) = expires
                && *expires <= SystemTime::now()
            {
                return Err(pgp_error("choose an expiry date in the future"));
            }
            if *key == cert.fingerprint() {
                cert.set_expiration_time(&StandardPolicy::new(), None, &mut primary, *expires)
                    .map_err(pgp_error)?
                    .into_iter()
                    .map(Packet::from)
                    .collect()
            } else {
                let subkey = subkey(&cert, key)?;
                let usage = describe(&cert)
                    .into_iter()
                    .find(|part| part.fingerprint == key.to_hex())
                    .map(|part| part.usage)
                    .unwrap_or_default();
                let binding = bind(
                    &cert,
                    &mut primary,
                    &subkey,
                    usage,
                    *expires,
                    SystemTime::now(),
                )?;
                vec![binding.into()]
            }
        }
        KeyEdit::RevokeSubkey {
            key,
            reason,
            message,
        } => {
            let subkey = cert
                .keys()
                .subkeys()
                .find(|ka| ka.key().fingerprint() == *key)
                .ok_or_else(|| VaultError::NotFound(key.clone()))?;
            let revocation = SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(reason.code(), message.as_bytes())
                .and_then(|builder| builder.build(&mut primary, &cert, subkey.key(), None))
                .map_err(pgp_error)?;
            vec![revocation.into()]
        }
        KeyEdit::DeleteSubkey { key } => {
            if !cert
                .keys()
                .subkeys()
                .any(|ka| ka.key().fingerprint() == *key)
            {
                return Err(VaultError::NotFound(key.clone()));
            }
            return Ok(cert.retain_subkeys(|ka| ka.key().fingerprint() != *key));
        }
        KeyEdit::AttachSubkey { key, usage } => {
            if cert.keys().any(|ka| ka.key().fingerprint() == *key) {
                return Err(pgp_error("this key is already part of the certificate"));
            }
            let source = find_key(key).ok_or_else(|| {
                pgp_error("the key to attach must be in the vault with its secret")
            })?;
            if source.version() != cert.primary_key().key().version() {
                return Err(pgp_error(
                    "the key to attach has a different OpenPGP key version",
                ));
            }
            let algo = source.pk_algo();
            check_usage(*usage, algo.for_signing(), algo.for_encryption())?;
            let source = source.role_into_subordinate();
            let binding = bind(
                &cert,
                &mut primary,
                &source,
                *usage,
                None,
                SystemTime::now(),
            )?;
            vec![source.into(), binding.into()]
        }
    };
    cert.insert_packets(packets)
        .map(|(cert, _)| cert)
        .map_err(pgp_error)
}

fn primary_signer(cert: &Cert) -> Result<KeyPair, VaultError> {
    let key = cert.primary_key().key();
    if !key.has_unencrypted_secret() {
        return Err(pgp_error(
            "the primary key's secret is not in the vault, so this key can't be changed",
        ));
    }
    key.clone()
        .parts_into_secret()
        .and_then(|key| key.into_keypair())
        .map_err(pgp_error)
}

fn subkey(
    cert: &Cert,
    fingerprint: &Fingerprint,
) -> Result<Key<PublicParts, SubordinateRole>, VaultError> {
    cert.keys()
        .subkeys()
        .find(|ka| ka.key().fingerprint() == *fingerprint)
        .map(|ka| ka.key().clone())
        .ok_or_else(|| VaultError::NotFound(fingerprint.clone()))
}

fn check_usage(usage: Usage, can_sign: bool, can_encrypt: bool) -> Result<(), VaultError> {
    if usage.is_empty() {
        return Err(pgp_error("choose what the subkey may be used for"));
    }
    if usage.signs() && !can_sign {
        return Err(pgp_error("this algorithm can't sign or authenticate"));
    }
    if usage.encrypt && !can_encrypt {
        return Err(pgp_error("this algorithm can't encrypt"));
    }
    Ok(())
}

fn generate(algorithm: Algorithm) -> Result<Key<SecretParts, SubordinateRole>, VaultError> {
    let key: Key4<SecretParts, SubordinateRole> = match algorithm {
        Algorithm::Ed25519 => Key4::generate_ecc(true, Curve::Ed25519),
        Algorithm::Cv25519 => Key4::generate_ecc(false, Curve::Cv25519),
        Algorithm::Rsa3072 => Key4::generate_rsa(3072),
        Algorithm::Rsa4096 => Key4::generate_rsa(4096),
    }
    .map_err(pgp_error)?;
    Ok(key.into())
}

/// A subkey binding signature made at `now`. Subkeys that sign carry a
/// back signature, as GnuPG requires.
fn bind<P: KeyParts>(
    cert: &Cert,
    primary: &mut KeyPair,
    subkey: &Key<P, SubordinateRole>,
    usage: Usage,
    expires: Option<SystemTime>,
    now: SystemTime,
) -> Result<Signature, VaultError> {
    let mut builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_signature_creation_time(now)
        .and_then(|b| b.set_key_flags(usage.flags()))
        .and_then(|b| b.set_key_expiration_time(subkey, expires))
        .map_err(pgp_error)?;
    if usage.signs() {
        if !subkey.has_unencrypted_secret() {
            return Err(pgp_error(
                "the subkey's secret is not in the vault, so it can't be bound for signing",
            ));
        }
        let mut signer = subkey
            .clone()
            .parts_into_secret()
            .and_then(|key| key.into_keypair())
            .map_err(pgp_error)?;
        let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
            .set_signature_creation_time(now)
            .map(|b| b.set_hash_algo(HashAlgorithm::SHA512))
            .and_then(|b| b.sign_primary_key_binding(&mut signer, cert.primary_key().key(), subkey))
            .map_err(pgp_error)?;
        builder = builder.set_embedded_signature(backsig).map_err(pgp_error)?;
    }
    subkey.bind(primary, cert, builder).map_err(pgp_error)
}
