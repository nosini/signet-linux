// SPDX-License-Identifier: GPL-3.0-or-later
use keepass::{Database, DatabaseKey};
use signet_vault::merge::merge;
fn time(n: i64) -> chrono::NaiveDateTime {
    chrono::DateTime::from_timestamp(n, 0).unwrap().naive_utc()
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
