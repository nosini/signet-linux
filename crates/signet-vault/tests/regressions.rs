// SPDX-License-Identifier: GPL-3.0-or-later
use keepass::{Database, DatabaseKey};
use signet_vault::merge::merge;
fn time(n: i64) -> chrono::NaiveDateTime {
    chrono::DateTime::from_timestamp(n, 0).unwrap().naive_utc()
}
#[test]
fn concurrent_group_moves_remain_valid() {
    let mut base = Database::new();
    let a = base.root_mut().add_group().id();
    let b = base.root_mut().add_group().id();
    for g in [a, b] {
        base.group_mut(g).unwrap().times.location_changed = Some(time(1));
        base.group_mut(g).unwrap().times.last_modification = Some(time(1));
    }
    let mut local = base.clone();
    let mut remote = base.clone();
    local.group_mut(a).unwrap().move_to(b).unwrap();
    local.group_mut(a).unwrap().times.location_changed = Some(time(10));
    remote.group_mut(b).unwrap().move_to(a).unwrap();
    remote.group_mut(b).unwrap().times.location_changed = Some(time(20));
    let original_local = local.clone();
    let result = merge(&mut local, &remote);
    println!("cross-move merge: {:?}", result.as_ref().err());
    assert!(result.is_ok());
    let mut reverse = remote.clone();
    merge(&mut reverse, &original_local).unwrap();
    for id in [a, b] {
        assert_eq!(
            local.group(id).unwrap().parent().map(|g| g.id()),
            reverse.group(id).unwrap().parent().map(|g| g.id())
        );
    }
    merge(&mut local, &reverse).unwrap();
    assert_eq!(local.root().groups().count(), 1);
}
#[test]
fn history_stays_oldest_first() {
    let mut db = Database::new();
    let id = {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "1");
        e.times.last_modification = Some(time(1));
        e.id()
    };
    for (n, title) in [(2, "2"), (3, "3")] {
        let mut e = db.entry_mut(id).unwrap();
        let mut t = e.track_changes();
        t.set_unprotected("Title", title);
        drop(t);
        db.entry_mut(id).unwrap().times.last_modification = Some(time(n));
    }
    let order = |db: &Database| {
        db.entry(id)
            .unwrap()
            .history
            .as_ref()
            .unwrap()
            .get_entries()
            .iter()
            .map(|e| e.get_title().unwrap_or("").to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(order(&db), vec!["1", "2"]);
    let mut remote = db.clone();
    remote.entry_mut(id).unwrap().set_unprotected("Title", "r");
    remote.entry_mut(id).unwrap().times.last_modification = Some(time(9));
    merge(&mut db, &remote).unwrap();
    assert_eq!(order(&db), vec!["1", "2", "3"]);
}
#[test]
fn kdbx3_header_hash_is_validated_and_writes_upgrade() {
    let bytes = include_bytes!("fixtures/kdbx3.kdbx");
    let database = Database::parse(bytes, DatabaseKey::new().with_password("password")).unwrap();
    // Insert a harmless comment before END: decryption still works, but the header hash must fail.
    let mut changed = bytes.to_vec();
    let mut offset = 12;
    while changed[offset] != 0 {
        let len = u16::from_le_bytes([changed[offset + 1], changed[offset + 2]]) as usize;
        offset += len + 3;
    }
    changed.splice(offset..offset, [1, 1, 0, b'x']);
    let error =
        Database::parse(&changed, DatabaseKey::new().with_password("password")).unwrap_err();
    assert!(error.to_string().contains("header hash"), "{error}");
    let mut out = Vec::new();
    database
        .save(&mut out, DatabaseKey::new().with_password("password"))
        .unwrap();
    let reopened = Database::parse(&out, DatabaseKey::new().with_password("password")).unwrap();
    assert!(matches!(
        reopened.config.version,
        keepass::config::DatabaseVersion::KDB4(_)
    ));
}

#[test]
fn missing_group_times_keep_the_same_topology_across_merge_directions() {
    let password = || DatabaseKey::new().with_password("password");
    let local = Database::parse(include_bytes!("fixtures/absent-local.kdbx"), password()).unwrap();
    let remote =
        Database::parse(include_bytes!("fixtures/absent-remote.kdbx"), password()).unwrap();
    let mut forward = local.clone();
    let mut reverse = remote.clone();
    merge(&mut forward, &remote).unwrap();
    merge(&mut reverse, &local).unwrap();
    let root_child = |db: &Database| db.root().groups().next().unwrap().id();
    assert_eq!(root_child(&forward), root_child(&reverse));
    assert_eq!(
        root_child(&forward).uuid().to_string(),
        "00000000-0000-0000-0000-000000000001"
    );
    merge(&mut forward, &remote).unwrap();
    assert_eq!(root_child(&forward), root_child(&reverse));
    let root = forward.root();
    let a = root.groups().next().unwrap();
    assert_eq!(a.times.location_changed, Some(time(10)));
    assert_eq!(
        a.groups().next().unwrap().times.location_changed,
        Some(time(20))
    );
}

fn test_key() -> DatabaseKey {
    DatabaseKey::new().with_password("test")
}
fn save(db: &Database) -> Vec<u8> {
    let mut bytes = Vec::new();
    db.save(&mut bytes, test_key()).unwrap();
    bytes
}
/// Builds an encrypted KDBX 3.1 file around `xml`. The key is derived with one
/// AES-KDF round; `rounds` only changes the header, for files that must fail first.
fn kdbx3(xml: &[u8], rounds: u64) -> Vec<u8> {
    use openssl::symm::{Cipher, Crypter, Mode, encrypt};
    use sha2::{Digest, Sha256};
    let mut file = vec![0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, 3, 0];
    let mut field = |tag: u8, data: &[u8]| {
        file.push(tag);
        file.extend((data.len() as u16).to_le_bytes());
        file.extend(data);
    };
    let aes = [
        0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a,
        0xff,
    ];
    field(2, &aes);
    field(3, &0u32.to_le_bytes());
    field(4, &[1; 32]);
    field(5, &[2; 32]);
    field(6, &rounds.to_le_bytes());
    field(7, &[3; 16]);
    field(8, &[4; 32]);
    field(9, &[5; 32]);
    field(10, &0u32.to_le_bytes());
    field(0, &[13, 10, 13, 10]);
    let composite = Sha256::digest(Sha256::digest(b"test"));
    let mut aes_kdf = Crypter::new(Cipher::aes_256_ecb(), Mode::Encrypt, &[2; 32], None).unwrap();
    aes_kdf.pad(false);
    let mut transformed = [0; 48];
    let n = aes_kdf.update(&composite, &mut transformed).unwrap();
    let n = n + aes_kdf.finalize(&mut transformed[n..]).unwrap();
    let transformed = &transformed[..n];
    let mut master = vec![1; 32];
    master.extend_from_slice(&Sha256::digest(transformed));
    let master = Sha256::digest(&master);
    let mut payload = vec![5; 32];
    payload.extend(0u32.to_le_bytes());
    payload.extend_from_slice(&Sha256::digest(xml));
    payload.extend((xml.len() as u32).to_le_bytes());
    payload.extend(xml);
    payload.extend(1u32.to_le_bytes());
    payload.extend([0; 32]);
    payload.extend(0u32.to_le_bytes());
    file.extend(encrypt(Cipher::aes_256_cbc(), &master, Some(&[3; 16]), &payload).unwrap());
    file
}
fn attachment(db: &Database, entry: keepass::db::EntryId, name: &str) -> Option<Vec<u8>> {
    let entry = db.entry(entry)?;
    Some(entry.attachment_by_name(name)?.data.get().clone())
}
fn historical_attachment(
    db: &Database,
    entry: keepass::db::EntryId,
    name: &str,
) -> Option<Vec<u8>> {
    let entry = db.entry(entry)?;
    let old = entry.historical(0)?;
    Some(old.attachment_by_name(name)?.data.get().clone())
}

#[test]
fn kdbx3_binaries_keep_their_declared_ids() {
    // IDs are out of order and have gaps; the history refers to one of them as well.
    let xml = br#"<KeePassFile><Meta><Binaries><Binary ID="5" Compressed="False">BQ==</Binary><Binary ID="2" Compressed="False">Ag==</Binary></Binaries></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name><Entry><UUID>AQAAAAAAAAAAAAAAAAAAAA==</UUID><Binary><Key>two</Key><Value Ref="2"/></Binary><Binary><Key>five</Key><Value Ref="5"/></Binary><History><Entry><UUID>AQAAAAAAAAAAAAAAAAAAAA==</UUID><Binary><Key>old</Key><Value Ref="5"/></Binary></Entry></History></Entry></Group></Root></KeePassFile>"#;
    let db = Database::parse(&kdbx3(xml, 1), test_key()).unwrap();
    let id = db.root().entries().next().unwrap().id();
    let check = |db: &Database| {
        assert_eq!(attachment(db, id, "two").unwrap(), [2]);
        assert_eq!(attachment(db, id, "five").unwrap(), [5]);
        assert_eq!(historical_attachment(db, id, "old").unwrap(), [5]);
    };
    check(&db);
    // Saving writes KDBX 4, whose binaries are numbered by position.
    check(&Database::parse(&save(&db), test_key()).unwrap());
}

#[test]
fn kdbx3_duplicate_binary_ids_are_rejected() {
    let xml = br#"<KeePassFile><Meta><Binaries><Binary ID="0" Compressed="False">AQ==</Binary><Binary ID="0" Compressed="False">Ag==</Binary></Binaries></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name></Group></Root></KeePassFile>"#;
    let error = Database::parse(&kdbx3(xml, 1), test_key()).unwrap_err();
    assert!(
        error.to_string().contains("Duplicate binary ID 0"),
        "{error}"
    );
}

#[test]
fn deleting_an_entry_keeps_other_attachments() {
    let mut db = Database::new();
    db.config.kdf_config = keepass::config::KdfConfig::Aes { rounds: 10 };
    let a = db.root_mut().add_entry().id();
    let b = db.root_mut().add_entry().id();
    let value = |byte| keepass::db::Value::unprotected(vec![byte]);
    db.entry_mut(a).unwrap().add_attachment("first", value(1));
    db.entry_mut(b).unwrap().add_attachment("second", value(2));
    db.entry_mut(b)
        .unwrap()
        .track_changes()
        .set_unprotected("Title", "edited");
    let mut db = Database::parse(&save(&db), test_key()).unwrap();
    // Removing the entry frees attachment 0 and leaves a gap before attachment 1.
    db.entry_mut(a).unwrap().remove();
    let reopened = Database::parse(&save(&db), test_key()).unwrap();
    assert_eq!(attachment(&reopened, b, "second").unwrap(), [2]);
    assert_eq!(historical_attachment(&reopened, b, "second").unwrap(), [2]);
}

#[test]
fn malformed_headers_are_errors() {
    let version = |major: u8| {
        vec![
            0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 1, 0, major, 0,
        ]
    };
    // KDBX 4 compression flags without a value.
    let mut empty_compression = version(4);
    empty_compression.extend([3, 0, 0, 0, 0]);
    // KDBX 4 KDF parameters with an empty 64-bit value.
    let mut short_kdf_value = version(4);
    let dictionary = [0, 1, 0x05, 1, 0, 0, 0, b'R', 0, 0, 0, 0, 0];
    short_kdf_value.extend([11, dictionary.len() as u8, 0, 0, 0]);
    short_kdf_value.extend(dictionary);
    // KDBX 3 transform rounds with two bytes.
    let mut short_rounds = version(3);
    short_rounds.extend([6, 2, 0, 1, 0]);
    for bytes in [empty_compression, short_kdf_value, short_rounds] {
        let result = std::panic::catch_unwind(|| Database::parse(&bytes, test_key()));
        assert!(result.expect("parser panicked").is_err());
    }
}

/// Parses on another thread so that an unbounded KDF fails the test instead of hanging it.
fn parse_within(
    bytes: Vec<u8>,
    seconds: u64,
) -> Result<Database, keepass::error::DatabaseOpenError> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(Database::parse(&bytes, test_key()));
    });
    rx.recv_timeout(std::time::Duration::from_secs(seconds))
        .expect("key derivation was not bounded")
}

#[test]
fn excessive_kdf_costs_are_rejected() {
    let xml = br#"<KeePassFile><Meta></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name></Group></Root></KeePassFile>"#;
    let error = parse_within(kdbx3(xml, u64::MAX), 10).unwrap_err();
    assert!(error.to_string().contains("exceed"), "{error}");

    for bytes in [
        argon2_file(u64::MAX, 1, 1),
        argon2_file(1 << 20, 1, u64::MAX),
    ] {
        let error = parse_within(bytes, 10).unwrap_err();
        assert!(error.to_string().contains("exceed"), "{error}");
    }
}

/// A KDBX 4 file whose Argon2 parameters were changed after saving. The header's
/// SHA-256 is updated because it is checked before key derivation; the header HMAC
/// needs the key, so the file fails with "Incorrect key" once derivation is done.
fn argon2_file(memory: u64, lanes: u32, iterations: u64) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut db = Database::new();
    db.config.kdf_config = keepass::config::KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    };
    let mut bytes = save(&db);
    let mut set = |tag: &[u8], value: &[u8]| {
        let at = bytes.windows(tag.len()).position(|w| w == tag).unwrap() + tag.len();
        bytes[at..at + value.len()].copy_from_slice(value);
    };
    set(&[0x05, 1, 0, 0, 0, b'M', 8, 0, 0, 0], &memory.to_le_bytes());
    set(
        &[0x05, 1, 0, 0, 0, b'I', 8, 0, 0, 0],
        &iterations.to_le_bytes(),
    );
    set(&[0x04, 1, 0, 0, 0, b'P', 4, 0, 0, 0], &lanes.to_le_bytes());
    let mut end = 12;
    while bytes[end] != 0 {
        end += 5 + u32::from_le_bytes(bytes[end + 1..end + 5].try_into().unwrap()) as usize;
    }
    end += 5 + u32::from_le_bytes(bytes[end + 1..end + 5].try_into().unwrap()) as usize;
    let hash = Sha256::digest(&bytes[..end]);
    bytes[end..end + 32].copy_from_slice(&hash);
    bytes
}

#[test]
fn small_argon2_lanes_do_not_start_a_thread_per_pass() {
    // Linux assigns thread IDs in order, so the distance between a thread started
    // before parsing and one started after counts the threads started in between.
    let tid = || {
        std::thread::spawn(|| i64::from(unsafe { libc::gettid() }))
            .join()
            .unwrap()
    };
    let pid_max: i64 = std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // 16 KiB in two lanes over 10,000 passes: parallel mode starts 80,000 threads.
    let bytes = argon2_file(16 * 1024, 2, 10_000);
    let before = tid();
    let error = Database::parse(&bytes, test_key()).unwrap_err();
    let started = (tid() - before).rem_euclid(pid_max);
    assert!(error.to_string().contains("Incorrect key"), "{error}");
    assert!(started < 10_000, "{started} threads started");
}
