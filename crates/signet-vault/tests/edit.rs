// SPDX-License-Identifier: GPL-3.0-or-later
use keepass::{config::KdfConfig, db::EntryId};
use sequoia_openpgp::{
    Cert, Fingerprint, Packet,
    cert::CertBuilder,
    cert::amalgamation::{ValidAmalgamation, key::PrimaryKey},
    parse::Parse,
    policy::StandardPolicy,
    serialize::Serialize,
    types::RevocationStatus,
};
use signet_vault::{
    Credentials, PRIVATE_KEY, SecretState, Vault, VaultError,
    edit::{Algorithm, KeyEdit, RevocationReason, Usage, apply, describe},
};
use std::time::{Duration, SystemTime};
use tempfile::tempdir;
use zeroize::Zeroizing;

fn credentials() -> Credentials {
    Credentials {
        password: Some(Zeroizing::new("test password".into())),
        keyfile: None,
    }
}
fn armored(cert: &Cert) -> Vec<u8> {
    let mut bytes = Vec::new();
    cert.as_tsk().armored().serialize(&mut bytes).unwrap();
    bytes
}
fn cert(name: &str) -> Cert {
    CertBuilder::new()
        .set_validity_period(None)
        .add_userid(name)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .unwrap()
        .0
}
fn vault(dir: &std::path::Path, certs: &[&Cert]) -> Vault {
    let path = dir.join("vault.kdbx");
    let mut vault = Vault::create(&path, credentials()).unwrap();
    vault.database.config.kdf_config = KdfConfig::Aes { rounds: 10 };
    for cert in certs {
        vault.import(&armored(cert), &mut |_| None).unwrap();
    }
    vault.save().unwrap();
    vault
}
/// The fingerprint of the subkey with exactly `usage`.
fn with_usage(cert: &Cert, usage: Usage) -> Fingerprint {
    describe(cert)
        .into_iter()
        .find(|part| !part.primary && part.usage == usage)
        .unwrap()
        .fingerprint
        .parse()
        .unwrap()
}
fn stored(vault: &Vault, fingerprint: &Fingerprint) -> Cert {
    vault
        .keys()
        .into_iter()
        .find(|key| &key.fingerprint == fingerprint)
        .unwrap()
        .cert
}
const ENCRYPT: Usage = Usage {
    sign: false,
    encrypt: true,
    authenticate: false,
};
const SIGN: Usage = Usage {
    sign: true,
    encrypt: false,
    authenticate: false,
};

#[test]
fn new_subkeys_are_bound_for_their_usage_and_saved() {
    let dir = tempdir().unwrap();
    let alice = cert("Alice <alice@example.org>");
    let mut vault = vault(dir.path(), &[&alice]);
    let expires = SystemTime::now() + Duration::from_secs(365 * 86400);
    for (algorithm, usage) in [
        (Algorithm::Ed25519, SIGN),
        (
            Algorithm::Ed25519,
            Usage {
                authenticate: true,
                ..Usage::default()
            },
        ),
        (Algorithm::Cv25519, ENCRYPT),
        (
            Algorithm::Rsa3072,
            Usage {
                sign: true,
                encrypt: true,
                authenticate: false,
            },
        ),
    ] {
        vault
            .edit(
                &alice.fingerprint(),
                &KeyEdit::AddSubkey {
                    algorithm,
                    usage,
                    expires: Some(expires),
                },
            )
            .unwrap();
    }
    vault.save().unwrap();
    let reopened = Vault::open(vault.path(), credentials()).unwrap();
    let cert = stored(&reopened, &alice.fingerprint());
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).unwrap();
    // All new subkeys are valid under the standard policy, which checks the
    // back signatures of signing and authentication subkeys.
    assert_eq!(valid.keys().subkeys().count(), 6);
    let original: Vec<String> = describe(&alice)
        .into_iter()
        .map(|p| p.fingerprint)
        .collect();
    let mut new: Vec<_> = describe(&cert)
        .into_iter()
        .filter(|part| !original.contains(&part.fingerprint))
        .collect();
    new.sort_by_key(|part| (part.algorithm.clone(), part.usage.authenticate));
    assert_eq!(
        new.iter().map(|p| p.algorithm.as_str()).collect::<Vec<_>>(),
        ["Cv25519", "Ed25519", "Ed25519", "RSA 3072"]
    );
    assert_eq!(new[0].usage, ENCRYPT);
    assert_eq!(new[1].usage, SIGN);
    assert!(new[2].usage.authenticate && !new[2].usage.sign);
    assert!(new[3].usage.sign && new[3].usage.encrypt);
    for part in &new {
        assert!(part.secret && !part.revoked && !part.primary);
        let lifetime = part.expires.unwrap().duration_since(expires);
        assert!(lifetime.map_or(true, |d| d < Duration::from_secs(2)));
    }
    assert_eq!(
        reopened.keys()[0].secret,
        SecretState::Usable,
        "new secrets are stored and readable"
    );
}

#[test]
fn usage_must_suit_the_algorithm() {
    let dir = tempdir().unwrap();
    let alice = cert("Alice <alice@example.org>");
    let mut vault = vault(dir.path(), &[&alice]);
    for (algorithm, usage) in [
        (Algorithm::Ed25519, ENCRYPT),
        (Algorithm::Cv25519, SIGN),
        (Algorithm::Rsa3072, Usage::default()),
    ] {
        assert!(matches!(
            vault.edit(
                &alice.fingerprint(),
                &KeyEdit::AddSubkey {
                    algorithm,
                    usage,
                    expires: None,
                },
            ),
            Err(VaultError::OpenPgp(_))
        ));
    }
    assert_eq!(stored(&vault, &alice.fingerprint()).keys().count(), 3);
}

#[test]
fn expiry_revocation_and_deletion() {
    let dir = tempdir().unwrap();
    let alice = cert("Alice <alice@example.org>");
    let mut vault = vault(dir.path(), &[&alice]);
    let fingerprint = alice.fingerprint();
    let signing = with_usage(&alice, SIGN);
    let encryption = with_usage(&alice, ENCRYPT);
    let later = SystemTime::now() + Duration::from_secs(30 * 86400);
    for key in [&fingerprint, &signing] {
        vault
            .edit(
                &fingerprint,
                &KeyEdit::SetExpiry {
                    key: key.clone(),
                    expires: Some(later),
                },
            )
            .unwrap();
    }
    let cert = stored(&vault, &fingerprint);
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).unwrap();
    let in_two_months = SystemTime::now() + Duration::from_secs(60 * 86400);
    assert!(valid.primary_key().alive().is_ok());
    assert!(
        cert.with_policy(&policy, in_two_months)
            .unwrap()
            .primary_key()
            .alive()
            .is_err()
    );
    let part = |fingerprint: &Fingerprint| {
        describe(&cert)
            .into_iter()
            .find(|part| part.fingerprint == fingerprint.to_hex())
            .unwrap()
    };
    assert!(part(&fingerprint).expires.is_some() && part(&signing).expires.is_some());
    assert_eq!(part(&signing).usage, SIGN, "a new binding keeps the usage");
    assert!(part(&encryption).expires.is_none());
    // Back to never expiring.
    vault
        .edit(
            &fingerprint,
            &KeyEdit::SetExpiry {
                key: signing.clone(),
                expires: None,
            },
        )
        .unwrap();
    assert!(
        describe(&stored(&vault, &fingerprint))
            .iter()
            .any(|part| part.fingerprint == signing.to_hex() && part.expires.is_none())
    );
    assert!(
        vault
            .edit(
                &fingerprint,
                &KeyEdit::SetExpiry {
                    key: signing.clone(),
                    expires: Some(SystemTime::now() - Duration::from_secs(60)),
                },
            )
            .is_err()
    );

    vault
        .edit(
            &fingerprint,
            &KeyEdit::RevokeSubkey {
                key: encryption.clone(),
                reason: RevocationReason::Superseded,
                message: "replaced".into(),
            },
        )
        .unwrap();
    let cert = stored(&vault, &fingerprint);
    let revoked = cert
        .with_policy(&policy, None)
        .unwrap()
        .keys()
        .key_handle(encryption.clone())
        .next()
        .unwrap();
    assert!(matches!(
        revoked.revocation_status(),
        RevocationStatus::Revoked(_)
    ));
    assert!(
        describe(&cert)
            .iter()
            .any(|part| part.fingerprint == encryption.to_hex() && part.revoked)
    );

    vault
        .edit(
            &fingerprint,
            &KeyEdit::DeleteSubkey {
                key: signing.clone(),
            },
        )
        .unwrap();
    let cert = stored(&vault, &fingerprint);
    assert!(cert.keys().all(|ka| ka.key().fingerprint() != signing));
    assert!(matches!(
        vault.edit(&fingerprint, &KeyEdit::DeleteSubkey { key: signing }),
        Err(VaultError::NotFound(_))
    ));
    // The primary key is not a subkey.
    assert!(
        vault
            .edit(
                &fingerprint,
                &KeyEdit::DeleteSubkey {
                    key: fingerprint.clone(),
                },
            )
            .is_err()
    );
}

#[test]
fn attached_subkey_keeps_its_fingerprint_and_secret_after_removing_the_old_key() {
    let dir = tempdir().unwrap();
    let old = cert("Old <old@example.org>");
    let new = CertBuilder::new()
        .add_userid("New <new@example.org>")
        .generate()
        .unwrap()
        .0;
    let mut vault = vault(dir.path(), &[&old, &new]);
    let old_signing = with_usage(&old, SIGN);
    let old_encryption = with_usage(&old, ENCRYPT);
    vault
        .edit(
            &new.fingerprint(),
            &KeyEdit::AttachSubkey {
                key: old_encryption.clone(),
                usage: ENCRYPT,
            },
        )
        .unwrap();
    vault
        .edit(
            &new.fingerprint(),
            &KeyEdit::AttachSubkey {
                key: old_signing.clone(),
                usage: SIGN,
            },
        )
        .unwrap();
    assert!(
        vault
            .edit(
                &new.fingerprint(),
                &KeyEdit::AttachSubkey {
                    key: old_signing.clone(),
                    usage: SIGN,
                },
            )
            .is_err(),
        "a key is attached only once"
    );
    vault.remove(&old.fingerprint()).unwrap();
    vault.save().unwrap();
    let reopened = Vault::open(vault.path(), credentials()).unwrap();
    assert_eq!(reopened.keys().len(), 1);
    let cert = stored(&reopened, &new.fingerprint());
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).unwrap();
    for (fingerprint, usage) in [(&old_encryption, ENCRYPT), (&old_signing, SIGN)] {
        let attached = valid.keys().key_handle(fingerprint.clone()).next().unwrap();
        let original = old.keys().key_handle(fingerprint.clone()).next().unwrap();
        assert_eq!(
            attached.key().creation_time(),
            original.key().creation_time()
        );
        assert_eq!(
            attached.key().clone().parts_into_secret().unwrap().secret(),
            original.key().clone().parts_into_secret().unwrap().secret()
        );
        assert_eq!(
            attached.key_flags().unwrap().for_signing(),
            usage.sign,
            "binding carries the chosen usage"
        );
    }
    assert!(matches!(
        vault.edit(
            &new.fingerprint(),
            &KeyEdit::AttachSubkey {
                key: "0123456789ABCDEF0123456789ABCDEF01234567".parse().unwrap(),
                usage: ENCRYPT,
            },
        ),
        Err(VaultError::OpenPgp(_))
    ));
}

#[test]
fn entry_password_protection_is_kept() {
    let dir = tempdir().unwrap();
    let alice = cert("Alice <alice@example.org>");
    let mut vault = vault(dir.path(), &[]);
    let protected = {
        let packets = alice
            .keys()
            .secret()
            .map(|key| {
                let encrypted = key.key().clone().encrypt_secret(&"entry".into()).unwrap();
                if key.primary() {
                    Packet::SecretKey(encrypted.role_into_primary())
                } else {
                    Packet::SecretSubkey(encrypted.role_into_subordinate())
                }
            })
            .collect::<Vec<_>>();
        alice.clone().insert_packets(packets).unwrap().0
    };
    let id = {
        let mut root = vault.database.root_mut();
        let mut entry = root.add_entry();
        entry.set_protected(PRIVATE_KEY, String::from_utf8(armored(&protected)).unwrap());
        entry.set_protected("Password", "entry");
        entry.id()
    };
    assert_eq!(vault.keys()[0].secret, SecretState::Usable);
    vault
        .edit(
            &alice.fingerprint(),
            &KeyEdit::AddSubkey {
                algorithm: Algorithm::Cv25519,
                usage: ENCRYPT,
                expires: None,
            },
        )
        .unwrap();
    let saved = Cert::from_bytes(
        vault
            .database
            .entry(EntryId::from_uuid(id.uuid()))
            .unwrap()
            .get(PRIVATE_KEY)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(saved.keys().secret().count(), 4);
    assert!(
        saved
            .keys()
            .secret()
            .all(|k| k.key().secret().is_encrypted())
    );
    assert_eq!(vault.keys()[0].secret, SecretState::Usable);
}

#[test]
fn keys_without_a_primary_secret_are_not_changed() {
    let dir = tempdir().unwrap();
    let alice = cert("Alice <alice@example.org>");
    let public = alice.clone().strip_secret_key_material();
    let mut vault = vault(dir.path(), &[&public]);
    assert!(
        vault
            .edit(
                &alice.fingerprint(),
                &KeyEdit::AddSubkey {
                    algorithm: Algorithm::Cv25519,
                    usage: ENCRYPT,
                    expires: None,
                },
            )
            .is_err()
    );
}

#[test]
fn back_to_back_edits_take_effect() {
    let mut cert = cert("Alice <alice@example.org>");
    let signing = with_usage(&cert, SIGN);
    let later = SystemTime::now() + Duration::from_secs(30 * 86400);
    for expires in [Some(later), None, Some(later)] {
        let edit = KeyEdit::SetExpiry {
            key: signing.clone(),
            expires,
        };
        cert = apply(cert, &edit, |_| None).unwrap();
        let part = describe(&cert)
            .into_iter()
            .find(|part| part.fingerprint == signing.to_hex())
            .unwrap();
        assert_eq!(part.expires.is_some(), expires.is_some());
    }
    // Bindings from the same second tie, and the winner is arbitrary.
    let subkey = cert.keys().subkeys().key_handle(signing).next().unwrap();
    let mut times: Vec<_> = subkey
        .self_signatures()
        .map(|s| s.signature_creation_time().unwrap())
        .collect();
    times.dedup();
    assert_eq!(times.len(), 4, "{times:?}");
}
