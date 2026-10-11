// SPDX-License-Identifier: GPL-3.0-or-later
use keepass::{
    Database, DatabaseKey,
    config::KdfConfig,
    db::{CustomDataItem, CustomDataValue, Times, Value},
};
use sequoia_openpgp::{
    Cert, Packet, cert::CertBuilder, cert::amalgamation::key::PrimaryKey, parse::Parse,
    serialize::Serialize,
};
use signet_vault::{
    Credentials, FINGERPRINT, PRIVATE_KEY, PUBLIC_KEY, SecretState, Vault, VaultError,
};
use tempfile::tempdir;
use zeroize::Zeroizing;
fn credentials() -> Credentials {
    Credentials {
        password: Some(Zeroizing::new("test password".into())),
        keyfile: None,
    }
}
fn fast(db: &mut Database) {
    db.config.kdf_config = KdfConfig::Aes { rounds: 10 };
}
fn cert() -> Cert {
    CertBuilder::new()
        .add_userid("Alice <alice@example.org>")
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()
        .unwrap()
        .0
}
fn armored(cert: &Cert) -> Vec<u8> {
    let mut bytes = Vec::new();
    cert.as_tsk().armored().serialize(&mut bytes).unwrap();
    bytes
}

fn protect(cert: Cert, password: &str) -> Cert {
    let packets = cert
        .keys()
        .secret()
        .map(|key| {
            let protected = key.key().clone().encrypt_secret(&password.into()).unwrap();
            if key.primary() {
                Packet::SecretKey(protected.role_into_primary())
            } else {
                Packet::SecretSubkey(protected.role_into_subordinate())
            }
        })
        .collect::<Vec<_>>();
    cert.insert_packets(packets).unwrap().0
}

#[test]
fn gnupg_fixed_width_ed25519_secret_import() {
    let cert = Cert::from_bytes(include_bytes!("fixtures/gpg-ed25519-protected.asc")).unwrap();
    let mut attempts = 0;
    let unlocked = signet_vault::unlock_cert(cert.clone(), &mut || {
        attempts += 1;
        Some(Zeroizing::new(
            if attempts == 1 {
                "wrong"
            } else {
                "import-test"
            }
            .into(),
        ))
    })
    .unwrap();
    assert_eq!(attempts, 2);
    assert!(
        unlocked
            .keys()
            .secret()
            .all(|k| !k.key().secret().is_encrypted())
    );
    // Confirm that normalization preserves the secret corresponding to the public key.
    let mut signer = unlocked
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let signature = sequoia_openpgp::packet::signature::SignatureBuilder::new(
        sequoia_openpgp::types::SignatureType::Binary,
    )
    .sign_message(&mut signer, b"legacy secret import")
    .unwrap();
    signature
        .verify_message(unlocked.primary_key().key(), b"legacy secret import")
        .unwrap();
    attempts = 0;
    let error = signet_vault::unlock_cert(cert, &mut || {
        attempts += 1;
        Some(Zeroizing::new("wrong".into()))
    })
    .unwrap_err()
    .to_string();
    assert_eq!(attempts, 3);
    // The cause tells a wrong passphrase apart from an unsupported key.
    assert!(error.to_lowercase().contains("password"), "{error}");
}

#[test]
fn wrong_passphrase_is_reported_for_every_key_type() {
    use sequoia_openpgp::cert::CipherSuite;
    for suite in [CipherSuite::RSA2k, CipherSuite::P256, CipherSuite::Cv25519] {
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(suite)
            .add_userid("Test <test@example.org>")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .set_password(Some("right".into()))
            .generate()
            .unwrap();
        let error =
            signet_vault::unlock_cert(cert.clone(), &mut || Some(Zeroizing::new("wrong".into())))
                .unwrap_err()
                .to_string();
        assert!(
            error.to_lowercase().contains("password"),
            "{suite:?}: {error}"
        );
        signet_vault::unlock_cert(cert, &mut || Some(Zeroizing::new("right".into()))).unwrap();
    }
}

#[test]
fn gnupg_padded_unprotected_ed25519_import() {
    for fixture in [
        &include_bytes!("fixtures/gpg-ed25519-unprotected-primary.asc")[..],
        &include_bytes!("fixtures/gpg-ed25519-unprotected-subkey.asc")[..],
    ] {
        let dir = tempdir().unwrap();
        let mut vault = Vault::create(&dir.path().join("vault.kdbx"), credentials()).unwrap();
        fast(&mut vault.database);
        let imported = vault.import(fixture, &mut |_| None).unwrap();
        assert_eq!(imported.len(), 1);
        let cert = &imported[0].cert;
        // A dropped subkey would not fail the import, so count the secrets.
        assert_eq!(cert.keys().unencrypted_secret().count(), 3);
        for key in cert.keys().unencrypted_secret() {
            if key.key().pk_algo() != sequoia_openpgp::types::PublicKeyAlgorithm::EdDSA {
                continue;
            }
            let mut signer = key.key().clone().into_keypair().unwrap();
            let signature = sequoia_openpgp::packet::signature::SignatureBuilder::new(
                sequoia_openpgp::types::SignatureType::Binary,
            )
            .sign_message(&mut signer, b"padded secret import")
            .unwrap();
            signature
                .verify_message(key.key(), b"padded secret import")
                .unwrap();
        }
    }
}

#[test]
fn gnupg_fixed_width_cv25519_secret_import() {
    use sequoia_openpgp::{
        crypto::SessionKey,
        packet::{key, pkesk::PKESK3},
        types::SymmetricAlgorithm,
    };
    let cert = Cert::from_bytes(include_bytes!("fixtures/gpg-25519-protected.asc")).unwrap();
    let mut prompts = 0;
    let unlocked = signet_vault::unlock_cert(cert.clone(), &mut || {
        prompts += 1;
        Some(Zeroizing::new("import-test".into()))
    })
    .unwrap();
    assert_eq!(prompts, 1, "both keys should reuse the import passphrase");
    let subkey = unlocked.keys().secret().nth(1).unwrap();
    let session_key = SessionKey::new(32).unwrap();
    let packet =
        PKESK3::for_recipient(SymmetricAlgorithm::AES256, &session_key, subkey.key()).unwrap();
    let mut decryptor = subkey.key().clone().into_keypair().unwrap();
    let (algorithm, recovered) = packet
        .decrypt(&mut decryptor, Some(SymmetricAlgorithm::AES256))
        .unwrap();
    assert_eq!(algorithm, SymmetricAlgorithm::AES256);
    assert_eq!(session_key, recovered);

    // Correct passphrases must not bypass a corrupted checksum in the fallback.
    let subkey = cert.keys().secret().nth(1).unwrap().key().clone();
    let key::SecretKeyMaterial::Encrypted(encrypted) = subkey.secret() else {
        panic!("encrypted fixture")
    };
    let mut ciphertext = encrypted.ciphertext().unwrap().to_vec();
    *ciphertext.last_mut().unwrap() ^= 1;
    let damaged = key::Encrypted::new(
        encrypted.s2k().clone(),
        encrypted.algo(),
        encrypted.checksum(),
        ciphertext.into_boxed_slice(),
    );
    let subkey = subkey
        .add_secret(key::SecretKeyMaterial::Encrypted(damaged))
        .0;
    let damaged = cert
        .insert_packets([Packet::SecretSubkey(subkey.role_into_subordinate())])
        .unwrap()
        .0;
    assert!(
        signet_vault::unlock_cert(damaged, &mut || Some(Zeroizing::new("import-test".into())))
            .is_err()
    );
}

#[test]
fn import_history_protection_delete_and_stale_save() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut vault = Vault::create(&path, credentials()).unwrap();
    fast(&mut vault.database);
    vault.save().unwrap();
    let certificate = cert();
    let imported = vault
        .import(&armored(&certificate), &mut |_| {
            panic!("unencrypted key prompted")
        })
        .unwrap();
    assert_eq!(imported[0].secret, SecretState::Usable);
    let id = keepass::db::EntryId::from_uuid(imported[0].uuid);
    {
        let mut entry = vault.database.entry_mut(id).unwrap();
        entry.set_unprotected("unknown", "retained");
        entry.tags.push("my tag".into());
        entry.add_attachment("data", Value::protected(vec![1, 2, 3]));
    }
    vault.save().unwrap();
    let stale = Vault::open(&path, credentials()).unwrap();
    vault.import(&armored(&certificate), &mut |_| None).unwrap();
    vault.save().unwrap();
    let entry = vault.database.entry(id).unwrap();
    assert!(entry.fields[PRIVATE_KEY].is_protected());
    assert!(!entry.fields[PUBLIC_KEY].is_protected());
    assert_eq!(
        entry.get(FINGERPRINT),
        Some(certificate.fingerprint().to_hex().as_str())
    );
    assert_eq!(entry.get("unknown"), Some("retained"));
    assert_eq!(entry.tags, ["my tag"]);
    assert!(!entry.history.as_ref().unwrap().get_entries().is_empty());
    assert_eq!(
        entry.attachment_by_name("data").unwrap().data.get(),
        &[1, 2, 3]
    );
    let mut stale = stale;
    assert!(matches!(stale.save(), Err(VaultError::Changed)));
    vault.database.meta.recyclebin_enabled = Some(true);
    vault.remove(&certificate.fingerprint()).unwrap();
    assert!(vault.keys().is_empty());
    assert!(vault.database.recycle_bin().is_some());
    vault.save().unwrap();
    assert!(Vault::open(&path, credentials()).unwrap().keys().is_empty());
}

#[test]
fn malformed_entries_are_skipped_and_protected_keys_are_tolerated() {
    let dir = tempdir().unwrap();
    let mut vault = Vault::create(&dir.path().join("vault.kdbx"), credentials()).unwrap();
    fast(&mut vault.database);
    let certificate = cert();
    let protected = protect(certificate.clone(), "private password");
    {
        let mut root = vault.database.root_mut();
        let mut entry = root.add_entry();
        entry.set_protected(PRIVATE_KEY, String::from_utf8(armored(&protected)).unwrap());
        entry.set_protected("Password", "wrong password");
        root.add_entry()
            .set_unprotected(PUBLIC_KEY, "invalid certificate");
    }
    let keys = vault.keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].secret, SecretState::Locked);
    let id = keepass::db::EntryId::from_uuid(keys[0].uuid);
    vault
        .database
        .entry_mut(id)
        .unwrap()
        .set_protected("Password", "private password");
    assert_eq!(vault.keys()[0].secret, SecretState::Usable);
    let mut calls = 0;
    vault
        .import(&armored(&protected), &mut |prompt| {
            assert_eq!(prompt.fingerprint, certificate.fingerprint());
            calls += 1;
            Some(Zeroizing::new(
                if calls == 1 {
                    "wrong"
                } else {
                    "private password"
                }
                .into(),
            ))
        })
        .unwrap();
    assert_eq!(calls, 2, "the successful passphrase is reused for subkeys");
    let saved = vault.database.entry(id).unwrap();
    let parsed = Cert::from_bytes(saved.get(PRIVATE_KEY).unwrap().as_bytes()).unwrap();
    assert!(
        parsed
            .keys()
            .secret()
            .all(|key| !key.key().secret().is_encrypted())
    );
}

#[test]
fn invalid_multi_certificate_import_is_transactional() {
    let dir = tempdir().unwrap();
    let mut vault = Vault::create(&dir.path().join("vault.kdbx"), credentials()).unwrap();
    let before = vault.database.clone();
    let protected = protect(cert(), "secret");
    let mut data = armored(&cert());
    data.extend(armored(&protected));
    assert!(matches!(
        vault.import(&data, &mut |_| None),
        Err(VaultError::Cancelled)
    ));
    assert_eq!(vault.database, before);
}

#[test]
fn deleting_without_recycle_bin_records_tombstone() {
    let dir = tempdir().unwrap();
    let mut vault = Vault::create(&dir.path().join("vault.kdbx"), credentials()).unwrap();
    let certificate = cert();
    let key = vault
        .import(&armored(&certificate), &mut |_| None)
        .unwrap()
        .remove(0);
    vault.database.meta.recyclebin_enabled = Some(false);
    vault.remove(&certificate.fingerprint()).unwrap();
    assert!(vault.keys().is_empty());
    assert!(vault.database.deleted_objects[&key.uuid].is_some());
}

#[test]
fn rich_database_round_trip() {
    let mut db = Database::new();
    fast(&mut db);
    let time = Times::now();
    let custom = CustomDataItem {
        value: Some(CustomDataValue::String("plugin value".into())),
        last_modification_time: Some(time),
    };
    db.meta.custom_data.insert("plugin".into(), custom.clone());
    db.meta.settings_changed = Some(time);
    db.meta.recyclebin_enabled = Some(true);
    db.meta.database_description = Some("Description".into());
    db.meta.history_max_items = Some(50);
    let bin = {
        let mut root = db.root_mut();
        let mut group = root.add_group();
        group.name = "Recycle Bin".into();
        group.id()
    };
    db.meta.recyclebin_uuid = Some(bin.uuid());
    db.meta.recyclebin_changed = Some(time);
    let id = {
        let mut root = db.root_mut();
        let mut group = root.add_group();
        group.name = "Other passwords".into();
        group
            .custom_data
            .insert("group plugin".into(), custom.clone());
        let mut entry = group.add_entry();
        entry.set_unprotected("Title", "Personal password");
        entry.set_protected("Password", "secret");
        entry.set_unprotected("custom field", "custom value");
        entry.tags.push("tag".into());
        entry.custom_data.insert("entry plugin".into(), custom);
        let mut icon = entry.set_icon_custom_new(vec![137, 80, 78, 71]);
        icon.name = Some("custom icon".into());
        icon.last_modification_time = Some(time);
        entry.add_attachment("attachment.dat", Value::protected(vec![1, 2, 3, 4]));
        entry
            .track_changes()
            .set_unprotected("custom field", "edited value");
        entry.id()
    };
    db.deleted_objects.insert(uuid::Uuid::new_v4(), Some(time));
    let mut bytes = Vec::new();
    db.save(&mut bytes, DatabaseKey::new().with_password("password"))
        .unwrap();
    if let Some(directory) = std::env::var_os("SIGNET_FIXTURE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("keepass.kdbx"),
            &bytes,
        )
        .unwrap();
    }
    let mut reopened =
        Database::parse(&bytes, DatabaseKey::new().with_password("password")).unwrap();
    keepass::db::signet_merge::rebuild_references(&mut db).unwrap();
    keepass::db::signet_merge::rebuild_references(&mut reopened).unwrap();
    assert_eq!(
        reopened.entry(id).unwrap().get("custom field"),
        Some("edited value")
    );
    assert_eq!(reopened, db, "the codec must preserve all modelled data");
}

#[test]
fn android_database_round_trip() {
    let bytes = include_bytes!("fixtures/kotpass.kdbx");
    let database = Database::parse(bytes, DatabaseKey::new().with_password("password")).unwrap();
    let entry = database
        .iter_all_entries()
        .find(|entry| entry.get("Title") == Some("unrelated"))
        .unwrap();
    assert_eq!(entry.get("Extra"), Some("secret"));
    assert!(entry.fields["Extra"].is_protected());
    assert_eq!(entry.tags, ["tag"]);
    assert_eq!(
        entry
            .attachment_by_name("attachment.txt")
            .unwrap()
            .data
            .get(),
        b"attachment"
    );
    assert_eq!(entry.history.as_ref().unwrap().get_entries().len(), 1);
    assert_eq!(
        database
            .iter_all_custom_icons()
            .next()
            .unwrap()
            .name
            .as_deref(),
        Some("Icon")
    );
    assert_eq!(database.deleted_objects.len(), 1);
    let mut encoded = Vec::new();
    database
        .save(&mut encoded, DatabaseKey::new().with_password("password"))
        .unwrap();
    let reopened = Database::parse(&encoded, DatabaseKey::new().with_password("password")).unwrap();
    assert_eq!(database, reopened);
}

#[test]
fn malformed_history_uuid_returns_error() {
    let bytes = include_bytes!("fixtures/invalid-history.kdbx");
    let error = Database::parse(bytes, DatabaseKey::new().with_password("password")).unwrap_err();
    assert!(error.to_string().contains("History UUID"));
}

#[test]
fn public_armor_has_only_base64_between_the_markers() {
    let certificate = cert();
    let armor = signet_vault::public_armor(&certificate).unwrap();
    let mut lines = armor.lines();
    assert_eq!(lines.next(), Some("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    // Importers like Stalwart decode every character after the BEGIN line
    // as base64, so there must be no headers.
    let body: Vec<&str> = lines
        .take_while(|line| !line.starts_with("-----END"))
        .filter(|line| !line.is_empty())
        .collect();
    assert!(body.iter().all(|line| {
        line.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    }));
    assert!(!armor.contains("Comment:"));
    let parsed = Cert::from_bytes(armor.as_bytes()).unwrap();
    assert_eq!(parsed, certificate.strip_secret_key_material());
}
