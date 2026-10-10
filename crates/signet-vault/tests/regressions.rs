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
