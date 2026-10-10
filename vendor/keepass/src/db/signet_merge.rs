// SPDX-License-Identifier: GPL-3.0-or-later
//! Signet's UUID merge, including binary references and both entry histories.
use crate::{
    db::{AttachmentId, Entry, GroupId, History, Icon},
    Database,
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Conditions that prevent a safe merge.
#[derive(Debug, Error)]
pub enum MergeError {
    #[error("cannot merge databases with different root UUIDs")]
    /// The inputs are not versions of the same database.
    DifferentRoots,
    #[error("merged group structure contains a cycle or missing parent")]
    /// Merged references are missing or cyclic.
    InvalidStructure,
}

/// Transactional merge: failure leaves `local` unchanged.
pub fn merge(local: &mut Database, remote: &Database) -> Result<(), MergeError> {
    if local.root != remote.root {
        return Err(MergeError::DifferentRoots);
    }
    let mut out = local.clone();
    let mut remote = remote.clone();
    let mut binary_ids = HashMap::new();
    for (&old_id, attachment) in &remote.attachments {
        let id = out
            .attachments
            .iter()
            .find(|(_, a)| a.data == attachment.data)
            .map(|(&id, _)| id)
            .unwrap_or_else(|| AttachmentId::next_free(&out));
        binary_ids.insert(old_id, id);
        if let std::collections::hash_map::Entry::Vacant(slot) = out.attachments.entry(id) {
            let mut copy = attachment.clone();
            copy.id = id;
            copy.entries.clear();
            slot.insert(copy);
        }
    }
    for entry in remote.entries.values_mut() {
        remap_binaries(entry, &binary_ids);
    }
    for (&id, icon) in &remote.custom_icons {
        if out
            .custom_icons
            .get(&id)
            .is_none_or(|old| old.last_modification_time < icon.last_modification_time)
        {
            out.custom_icons.insert(id, icon.clone());
        }
    }
    for (&id, &time) in &remote.deleted_objects {
        out.deleted_objects
            .entry(id)
            .and_modify(|old| *old = (*old).max(time))
            .or_insert(time);
    }
    let local_groups = local.groups.keys().copied().collect::<HashSet<_>>();
    let remote_groups = remote.groups.keys().copied().collect::<HashSet<_>>();
    for id in local_groups.union(&remote_groups) {
        let left = local.groups.get(id);
        let right = remote.groups.get(id);
        let (winner, parent, moved) = match (left, right) {
            (Some(a), Some(b)) => {
                let winner = if b.times.last_modification > a.times.last_modification {
                    b
                } else {
                    a
                };
                let location = if b.times.location_changed > a.times.location_changed {
                    b
                } else {
                    a
                };
                (winner, location.parent, location.times.location_changed)
            }
            (Some(a), None)
                if remote
                    .deleted_objects
                    .get(&id.uuid())
                    .is_some_and(|&t| t >= a.times.last_modification) =>
            {
                out.groups.remove(id);
                continue;
            }
            (None, Some(b))
                if local
                    .deleted_objects
                    .get(&id.uuid())
                    .is_some_and(|&t| t >= b.times.last_modification) =>
            {
                continue;
            }
            (Some(a), None) => (a, a.parent, a.times.location_changed),
            (None, Some(b)) => (b, b.parent, b.times.location_changed),
            _ => unreachable!(),
        };
        if *id != local.root
            && out
                .deleted_objects
                .get(&id.uuid())
                .is_some_and(|&t| t >= winner.times.last_modification)
        {
            out.groups.remove(id);
            continue;
        }
        let mut group = winner.clone();
        group.parent = parent;
        group.times.location_changed = moved;
        group.groups.clear();
        group.entries.clear();
        out.groups.insert(*id, group);
    }
    let local_entries = local.entries.keys().copied().collect::<HashSet<_>>();
    let remote_entries = remote.entries.keys().copied().collect::<HashSet<_>>();
    for id in local_entries.union(&remote_entries) {
        let left = local.entries.get(id);
        let right = remote.entries.get(id);
        let entry = match (left, right) {
            (Some(a), Some(b)) => {
                let (winner, loser) = if b.times.last_modification > a.times.last_modification {
                    (b, a)
                } else {
                    (a, b)
                };
                let location = if b.times.location_changed > a.times.location_changed {
                    b
                } else {
                    a
                };
                let mut entry = winner.clone();
                let mut history = Vec::new();
                for item in a
                    .history
                    .iter()
                    .flat_map(|h| &h.entries)
                    .chain(b.history.iter().flat_map(|h| &h.entries))
                {
                    add_history(&mut history, item.clone());
                }
                let mut current = winner.clone();
                current.history = None;
                let mut previous = loser.clone();
                previous.history = None;
                if current != previous {
                    add_history(&mut history, previous);
                }
                history.sort_by_key(|e| e.times.last_modification);
                entry.history = Some(History { entries: history });
                entry.parent = location.parent;
                entry.previous_parent_group = location.previous_parent_group;
                entry.times.location_changed = location.times.location_changed;
                entry
            }
            (Some(a), None)
                if remote
                    .deleted_objects
                    .get(&id.uuid())
                    .is_some_and(|&t| t >= a.times.last_modification) =>
            {
                out.entries.remove(id);
                continue;
            }
            (None, Some(b))
                if local
                    .deleted_objects
                    .get(&id.uuid())
                    .is_some_and(|&t| t >= b.times.last_modification) =>
            {
                continue;
            }
            (Some(a), None) => a.clone(),
            (None, Some(b)) => b.clone(),
            _ => unreachable!(),
        };
        if out
            .deleted_objects
            .get(&id.uuid())
            .is_some_and(|&t| t >= entry.times.last_modification)
        {
            out.entries.remove(id);
            continue;
        }
        out.entries.insert(*id, entry);
    }
    if remote.meta.settings_changed > local.meta.settings_changed {
        out.meta = remote.meta.clone();
        out.config = remote.config.clone();
    }
    let mut custom = local.meta.custom_data.clone();
    for (name, item) in &remote.meta.custom_data {
        if custom.get(name).is_none_or(|old| {
            item.last_modification_time > old.last_modification_time
                || (item.last_modification_time == old.last_modification_time
                    && remote.meta.settings_changed > local.meta.settings_changed)
        }) {
            custom.insert(name.clone(), item.clone());
        }
    }
    out.meta.custom_data = custom;
    // Concurrent edits may keep children of a group deleted on the other side.
    // Reparent these children to the nearest surviving original ancestor.
    let parents = out
        .groups
        .iter()
        .filter(|(id, _)| **id != out.root)
        .map(|(id, group)| {
            Ok((
                *id,
                surviving_parent(
                    group.parent.ok_or(MergeError::InvalidStructure)?,
                    &out,
                    local,
                    &remote,
                )?,
            ))
        })
        .collect::<Result<Vec<_>, MergeError>>()?;
    for (id, parent) in parents {
        out.groups
            .get_mut(&id)
            .ok_or(MergeError::InvalidStructure)?
            .parent = Some(parent);
    }
    let parents = out
        .entries
        .iter()
        .map(|(id, entry)| Ok((*id, surviving_parent(entry.parent, &out, local, &remote)?)))
        .collect::<Result<Vec<_>, MergeError>>()?;
    for (id, parent) in parents {
        out.entries
            .get_mut(&id)
            .ok_or(MergeError::InvalidStructure)?
            .parent = parent;
    }
    // Independent valid moves can form a cycle. Keep the newest moves and break
    // the oldest edge (UUID breaks ties) by returning that group to the root.
    let mut ids: Vec<_> = out.groups.keys().copied().collect();
    ids.sort_by_key(|id| id.uuid());
    for id in ids {
        let mut chain = Vec::new();
        let mut next = Some(id);
        while let Some(group) = next {
            if let Some(start) = chain.iter().position(|&old| old == group) {
                let break_id = *chain[start..]
                    .iter()
                    .min_by_key(|id| (out.groups[id].times.location_changed, id.uuid()))
                    .ok_or(MergeError::InvalidStructure)?;
                out.groups
                    .get_mut(&break_id)
                    .ok_or(MergeError::InvalidStructure)?
                    .parent = Some(out.root);
                break;
            }
            chain.push(group);
            next = out
                .groups
                .get(&group)
                .ok_or(MergeError::InvalidStructure)?
                .parent;
        }
    }
    rebuild_references(&mut out)?;
    *local = out;
    Ok(())
}
fn surviving_parent(
    mut parent: GroupId,
    out: &Database,
    local: &Database,
    remote: &Database,
) -> Result<GroupId, MergeError> {
    let mut seen = HashSet::new();
    while !out.groups.contains_key(&parent) {
        if !seen.insert(parent) {
            return Err(MergeError::InvalidStructure);
        }
        parent = local
            .groups
            .get(&parent)
            .or_else(|| remote.groups.get(&parent))
            .and_then(|group| group.parent)
            .ok_or(MergeError::InvalidStructure)?;
    }
    Ok(parent)
}
fn remap_binaries(entry: &mut Entry, map: &HashMap<AttachmentId, AttachmentId>) {
    for id in entry.attachments.values_mut() {
        if let Some(new) = map.get(id) {
            *id = *new;
        }
    }
    if let Some(history) = &mut entry.history {
        for item in &mut history.entries {
            remap_binaries(item, map);
        }
    }
}
fn add_history(history: &mut Vec<Entry>, mut entry: Entry) {
    entry.history = None;
    if !history.contains(&entry) {
        history.push(entry);
    }
}
/// Rebuild inverse references after loading or editing historical versions.
pub fn rebuild_references(db: &mut Database) -> Result<(), MergeError> {
    for icon in db.custom_icons.values_mut() {
        icon.entries.clear();
        icon.groups.clear();
    }
    for binary in db.attachments.values_mut() {
        binary.entries.clear();
    }
    // Stable ordering keeps repeated merges reproducible.
    let mut groups: Vec<_> = db.groups.keys().copied().collect();
    groups.sort_by_key(|id| id.uuid());
    for id in groups {
        let group = db.groups.get(&id).ok_or(MergeError::InvalidStructure)?;
        let parent = group.parent;
        let icon = group.icon.clone();
        if id != db.root {
            let mut seen = HashSet::new();
            seen.insert(id);
            let mut ancestor = parent;
            while let Some(p) = ancestor {
                if !seen.insert(p) {
                    return Err(MergeError::InvalidStructure);
                }
                ancestor = db
                    .groups
                    .get(&p)
                    .ok_or(MergeError::InvalidStructure)?
                    .parent;
            }
            db.groups
                .get_mut(&parent.ok_or(MergeError::InvalidStructure)?)
                .ok_or(MergeError::InvalidStructure)?
                .groups
                .insert(id);
        }
        if let Some(Icon::Custom(icon)) = icon {
            db.custom_icons
                .get_mut(&icon)
                .ok_or(MergeError::InvalidStructure)?
                .groups
                .insert(id);
        }
    }
    let mut entries: Vec<_> = db.entries.keys().copied().collect();
    entries.sort_by_key(|id| id.uuid());
    for id in entries {
        let entry = db.entries.get(&id).ok_or(MergeError::InvalidStructure)?;
        let parent: GroupId = entry.parent;
        let versions: Vec<_> = std::iter::once((None, entry.clone()))
            .chain(entry.history.iter().flat_map(|h| {
                h.entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| (Some(i), e.clone()))
            }))
            .collect();
        db.groups
            .get_mut(&parent)
            .ok_or(MergeError::InvalidStructure)?
            .entries
            .insert(id);
        for (index, version) in versions {
            for attachment in version.attachments.values() {
                db.attachments
                    .get_mut(attachment)
                    .ok_or(MergeError::InvalidStructure)?
                    .entries
                    .insert((id, index));
            }
            if let Some(Icon::Custom(icon)) = version.icon {
                db.custom_icons
                    .get_mut(&icon)
                    .ok_or(MergeError::InvalidStructure)?
                    .entries
                    .insert((id, index));
            }
        }
    }
    Ok(())
}
