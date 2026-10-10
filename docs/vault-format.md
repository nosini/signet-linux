# Vault format and sync

Signet keeps OpenPGP keys in an ordinary KeePass database (KDBX 4). The
Linux agent and the Android app read and write the same file, and you can
open it with any KeePass client to inspect or back up your keys.

A database used only for Signet is recommended. Signet preserves unrelated
entries, groups, fields, history, attachments, custom data and icons. XML
extensions that its codecs cannot represent are rejected before editing;
this includes `MasterKeyChangeForceOnce`. A dedicated file keeps your
password database out of reach of a second program that writes to it.

## Key entries

A key is an entry, in any group except the recycle bin, with these string
fields:

| Field | Protected | Content |
| --- | --- | --- |
| `gpg_privateKeyArmored` | yes | ASCII-armored secret key (transferable secret key) |
| `gpg_publicKeyArmored` | no | ASCII-armored public key (certificate) |
| `gpg_fingerprint` | no | Primary key fingerprint, upper-case hex without spaces |

An entry with at least one of the two armored fields is a key entry. An
entry with only a public key is a contact: Signet can encrypt to it and
verify its signatures, but cannot sign or decrypt with it. The entry title
defaults to the key's primary user ID and can be changed freely.

These are the field names [Keyguard](https://keyguard.dev/docs/gpg-keys/)
uses for its GPG key items in KeePass databases, so the same database works
in both apps.

### Secret key protection

Signet stores secret keys without an OpenPGP passphrase. The database
encryption protects them. When you import a passphrase-protected key, Signet
asks for the passphrase and stores the key unprotected. Linux reuses the
passphrase for subkeys protected with the same password; separately protected
subkeys need their own passphrase.

When reading, Signet also accepts entries whose secret key is still
passphrase-protected. It tries the entry's Password field as the passphrase,
which lets you add keys by hand in another KeePass client. If that fails, the key remains protected. Linux lists it as locked; import it
again with its passphrase to make it usable. Android can also unlock that key
for the current vault session from the approval screen.

### Writing rules

When Signet changes a key entry it:

- keeps the entry's UUID, other fields, attachments, tags and history;
- writes the previous version to the entry history;
- updates the entry's last modification time;
- regenerates `gpg_publicKeyArmored` and `gpg_fingerprint` from the secret
  key, so the three fields always describe the same key.

Deleting a key moves the entry to the recycle bin when the database has one
enabled, and otherwise deletes it and records the deletion in the database's
deleted-objects list.

## WebDAV sync

Both apps keep a local copy of the database and sync it with one file on a
WebDAV server, such as Nextcloud, ownCloud or any server that supports
`GET` and `PUT` with ETags. The remote file is the same encrypted KDBX file;
the server never sees the keys.

Each device remembers, from its last successful sync, the remote file's ETag
and a SHA-256 hash of its contents, and the hash of the local file it wrote
or read at that point. A sync then works like this:

1. Download the remote file, sending the remembered ETag as `If-None-Match`.
   A `304 Not Modified` response, or a body with the remembered hash, means
   the remote copy hasn't changed.
2. If only the remote copy changed, it replaces the local one.
3. If only the local copy changed, it's uploaded with `If-Match` set to the
   remembered ETag. If the server has no copy yet, the upload uses
   `If-None-Match: *`.
4. If both changed, the two databases are merged (below), and the result is
   uploaded with `If-Match`. The local file is replaced after the upload succeeds,
   so a failed sync leaves the working copy intact.
5. When an upload is rejected with `412 Precondition Failed`, someone else
   uploaded in between; the sync starts over from step 1, up to three times.

Before replacing the local file, the previous local file is kept in a
`backups` directory next to it; the five newest backups are retained. Servers
that send no ETag are handled by comparing content hashes, without the
protection that `If-Match` gives against two uploads at the same moment.

### Merging

Merging needs both databases unlocked with the same credentials. If the
remote database uses a different master password or key file, the sync stops with a remote-credentials error. Make both copies use the same
password and key file before syncing again.

The merge works per entry and per group, matched by UUID:

- An entry or group present in both copies takes the version with the newer
  last modification time. The other version is added to the entry history
  unless an identical history item already exists.
- An entry or group present in only one copy is kept, unless the other
  copy's deleted-objects list records its UUID with a deletion time at or
  after its last modification time.
- The deleted-objects lists are combined.
- A moved entry follows the location of the newer version, based on its
  location-changed time.
- Database settings come from the copy whose settings changed most recently.

Attachments and custom icons are retained, including those used by historical
versions. Icon and custom-data conflicts use their modification times. Icon ties keep
the local value; custom-data ties follow the newer database settings. A surviving child of a deleted group
moves to the nearest surviving ancestor. Vaults with different root UUIDs
cannot be merged: devices must start from copies of the same vault, rather
than creating a new vault independently on each device.
