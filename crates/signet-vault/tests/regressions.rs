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
