// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure merge of two versions of the same KeePass database.
pub use keepass::db::signet_merge::MergeError;
pub fn merge(local: &mut keepass::Database, remote: &keepass::Database) -> Result<(), MergeError> {
    keepass::db::signet_merge::merge(local, remote)
}
