// SPDX-License-Identifier: GPL-3.0-or-later
use keepass::{
    Database, DatabaseKey,
    db::{EntryId, Value},
};
use signet_vault::merge::merge;
fn time(n: i64) -> chrono::NaiveDateTime {
    chrono::DateTime::from_timestamp(n, 0).unwrap().naive_utc()
}
fn entry(db: &mut Database, title: &str, n: i64) -> EntryId {
    let mut root = db.root_mut();
    let mut entry = root.add_entry();
    entry.set_unprotected("Title", title);
    entry.times.last_modification = Some(time(n));
    entry.times.location_changed = Some(time(n));
    entry.id()
}
fn modify(db: &mut Database, id: EntryId, title: &str, n: i64) {
    let mut entry = db.entry_mut(id).unwrap();
    entry.set_unprotected("Title", title);
    entry.times.last_modification = Some(time(n));
}
#[test]
fn additions_and_edits_keep_both_histories() {
    let mut local = Database::new();
    let id = entry(&mut local, "original", 1);
    let mut remote = local.clone();
    let local_id = entry(&mut local, "local", 2);
    let remote_id = entry(&mut remote, "remote", 3);
    modify(&mut local, id, "local edit", 5);
    modify(&mut remote, id, "remote edit", 6);
    merge(&mut local, &remote).unwrap();
    assert_eq!(local.entry(id).unwrap().get_title(), Some("remote edit"));
    assert!(local.entry(local_id).is_some());
    assert!(local.entry(remote_id).is_some());
    assert_eq!(
        local
            .entry(id)
            .unwrap()
            .history
            .as_ref()
            .unwrap()
            .get_entries()
            .len(),
        1
    );
    merge(&mut local, &remote).unwrap();
    assert_eq!(
        local
            .entry(id)
            .unwrap()
            .history
            .as_ref()
            .unwrap()
            .get_entries()
            .len(),
        1
    );
}
#[test]
fn deletion_vs_edit_in_both_orders() {
    for reverse in [false, true] {
        for delete_time in [2, 4] {
            let mut edit = Database::new();
            let id = entry(&mut edit, "original", 1);
            let mut delete = edit.clone();
            modify(&mut edit, id, "edited", 3);
            delete.entry_mut(id).unwrap().remove();
            delete
                .deleted_objects
                .insert(id.uuid(), Some(time(delete_time)));
            let (mut left, right) = if reverse {
                (delete, edit)
            } else {
                (edit, delete)
            };
            merge(&mut left, &right).unwrap();
            assert_eq!(left.entry(id).is_some(), delete_time < 3);
            assert_eq!(left.deleted_objects[&id.uuid()], Some(time(delete_time)));
        }
    }
}
#[test]
fn move_is_independent_of_contents() {
    let mut local = Database::new();
    let id = entry(&mut local, "original", 1);
    let group = {
        let mut root = local.root_mut();
        let mut g = root.add_group();
        g.name = "Destination".into();
        g.id()
    };
    let mut remote = local.clone();
    modify(&mut local, id, "new contents", 10);
    {
        let mut e = remote.entry_mut(id).unwrap();
        e.move_to(group).unwrap();
        e.times.location_changed = Some(time(100));
    }
    merge(&mut local, &remote).unwrap();
    assert_eq!(local.entry(id).unwrap().get_title(), Some("new contents"));
    assert_eq!(local.entry(id).unwrap().parent().id(), group);
}
#[test]
fn attachments_in_losing_version_and_remote_only_entry_survive() {
    let mut local = Database::new();
    let id = entry(&mut local, "original", 1);
    local
        .entry_mut(id)
        .unwrap()
        .add_attachment("data", Value::protected(vec![1]));
    let mut remote = local.clone();
    {
        let mut e = remote.entry_mut(id).unwrap();
        e.add_attachment("data", Value::protected(vec![2]));
        e.times.last_modification = Some(time(2));
    }
    let new_id = entry(&mut remote, "remote only", 3);
    remote
        .entry_mut(new_id)
        .unwrap()
        .add_attachment("other", Value::unprotected(vec![3]));
    merge(&mut local, &remote).unwrap();
    assert_eq!(
        local
            .entry(id)
            .unwrap()
            .attachment_by_name("data")
            .unwrap()
            .data
            .get(),
        &[2]
    );
    assert_eq!(
        local
            .entry(id)
            .unwrap()
            .historical(0)
            .unwrap()
            .attachment_by_name("data")
            .unwrap()
            .data
            .get(),
        &[1]
    );
    assert_eq!(
        local
            .entry(new_id)
            .unwrap()
            .attachment_by_name("other")
            .unwrap()
            .data
            .get(),
        &[3]
    );
    local.config.kdf_config = keepass::config::KdfConfig::Aes { rounds: 10 };
    let mut bytes = Vec::new();
    local
        .save(&mut bytes, DatabaseKey::new().with_password("test"))
        .unwrap();
    let loaded = Database::parse(&bytes, DatabaseKey::new().with_password("test")).unwrap();
    assert_eq!(
        loaded
            .entry(id)
            .unwrap()
            .historical(0)
            .unwrap()
            .attachment_by_name("data")
            .unwrap()
            .data
            .get(),
        &[1]
    );
}
#[test]
fn latest_settings_and_group_content_win_and_tombstones_combine() {
    let mut local = Database::new();
    let mut remote = local.clone();
    local.meta.settings_changed = Some(time(1));
    remote.meta.settings_changed = Some(time(2));
    remote.meta.history_max_items = Some(12);
    remote.root_mut().name = "Renamed".into();
    remote.root_mut().times.last_modification = Some(time(9999999999));
    let uuid = uuid::Uuid::new_v4();
    local.deleted_objects.insert(uuid, Some(time(1)));
    remote.deleted_objects.insert(uuid, Some(time(2)));
    merge(&mut local, &remote).unwrap();
    assert_eq!(local.meta.history_max_items, Some(12));
    assert_eq!(local.root().name, "Renamed");
    assert_eq!(local.deleted_objects[&uuid], Some(time(2)));
}
#[test]
fn same_timestamp_divergent_entries_preserve_losing_version() {
    let mut local = Database::new();
    let id = entry(&mut local, "one", 1);
    let mut remote = local.clone();
    modify(&mut remote, id, "two", 1);
    merge(&mut local, &remote).unwrap();
    assert_eq!(local.entry(id).unwrap().get_title(), Some("one"));
    assert_eq!(
        local.entry(id).unwrap().historical(0).unwrap().get_title(),
        Some("two")
    );
}
#[test]
fn unrelated_databases_fail_without_mutation() {
    let mut local = Database::new();
    let snapshot = local.clone();
    assert!(merge(&mut local, &Database::new()).is_err());
    assert_eq!(local, snapshot);
}

#[test]
fn newer_child_survives_parent_deletion() {
    let mut local = Database::new();
    let parent = local.root_mut().add_group().id();
    local.group_mut(parent).unwrap().times.last_modification = Some(time(1));
    let child = local.group_mut(parent).unwrap().add_entry().id();
    local.entry_mut(child).unwrap().times.last_modification = Some(time(3));
    let mut remote = local.clone();
    remote.entry_mut(child).unwrap().times.last_modification = Some(time(1));
    remote.group_mut(parent).unwrap().remove();
    remote.deleted_objects.insert(parent.uuid(), Some(time(2)));
    remote.deleted_objects.insert(child.uuid(), Some(time(2)));
    merge(&mut local, &remote).unwrap();
    assert_eq!(local.entry(child).unwrap().parent().id(), local.root().id());
}
