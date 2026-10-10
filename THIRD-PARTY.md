# Third-party source

`vendor/keepass` is keepass-rs 0.15.0 from crates.io, licensed under MIT
(see its `LICENSE`). Signet's new merge module is GPL-3.0-or-later;
the fork's Cargo metadata names both licenses. Signet adds `db/signet_merge.rs` and exports it from
`db/mod.rs`. The parser also rebuilds inverse attachment and icon references
after opening a database, and rejects malformed history UUIDs before they can
reach an upstream unchecked lookup. This merge handles attachments, both histories, independent
location timestamps, deleted objects and database settings. The upstream
experimental merge does not preserve all of these. The encryption code is unchanged. XML structs reject unknown fields to prevent silently dropping unmodeled extensions when saving.

`crates/signet/src/keygrip.rs` adapts Sequoia IPC 0.37.0-pqc.1's keygrip
implementation, by the Sequoia authors, under LGPL-2.0-or-later. The source
is available at https://gitlab.com/sequoia-pgp/sequoia. Curve constants come
from libgcrypt. The LGPL license text is included as
`packaging/LICENSE-sequoia-ipc`.

The fork orders entry history oldest first, resolves concurrent group-move
cycles, validates KDBX 3 HeaderHash, and upgrades KDBX 3 files when saving.
