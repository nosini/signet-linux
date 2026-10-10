# Signet

Signet keeps OpenPGP keys in an encrypted KeePass vault and asks before
signing or decrypting. This is the Linux agent: a GnuPG-compatible agent.
Signet for Android, an OpenKeychain-compatible OpenPGP provider, is a separate
project; both can sync the same KDBX file over WebDAV.

The name comes from a signet ring: a seal used to sign documents. The code is
licensed under **GPL-3.0-or-later**.

## Installation and use

You need GnuPG and a pinentry program. Build and install from the repository:

```sh
cargo build --release --locked
sudo install -m 755 target/release/signet /usr/bin/signet
sudo install -Dm 644 packaging/signet.service /usr/lib/systemd/user/signet.service
```

Compiler and development-package requirements are in
[README-dev.md](README-dev.md).

Create a vault, import a key, and prepare the dedicated GnuPG home:

```sh
signet init
signet import /path/to/private-key.asc
signet setup-gnupg
systemctl --user daemon-reload
systemctl --user enable --now signet.service
export GNUPGHOME="${XDG_DATA_HOME:-$HOME/.local/share}/signet/gnupg"
gpg --list-secret-keys
```

`signet setup-gnupg` prints the exact `GNUPGHOME` assignment if you use a
custom location. Set it in the shell or application that should use Signet.
The dedicated home contains public certificates and owner-trust information;
secret keys stay in the vault. Run `signet setup-gnupg` again after importing
keys or syncing new certificates.

To connect an existing vault, use `signet init --vault /path/to/vault.kdbx`
instead. An existing file is opened and validated. `--keyfile /path/to/key`
adds a key file; an empty password is accepted only with a key file.

Signing and decryption open pinentry approval dialogs showing the operation,
key fingerprint, and requesting process chain. Signet starts locked and
unlocks through pinentry when needed. It locks after 15 idle minutes by
default. `signet lock`, `signet unlock`, and `signet status` control the daemon.
Process descriptions help identify a request, but an application can change
its own command line.

For Git signing, choose the key's full fingerprint:

```sh
git config --global gpg.format openpgp
git config --global user.signingkey YOUR_FULL_FINGERPRINT
git config --global commit.gpgsign true
git commit -S
```

Git inherits `GNUPGHOME`. Signet asks for approval on each signing operation.
Agent requests to export secret keys are refused. `signet export FINGERPRINT`
exports only the public certificate.

Configuration is in `~/.config/signet/config.toml`, respecting
`XDG_CONFIG_HOME`. For graphical dialogs, set `pinentry` to your GUI pinentry,
for example `/usr/bin/pinentry-qt`. `lock_after_idle = "15m"` and
`[approval] remember = "0s"` control locking and approval reuse. Keeping
`remember` at zero asks every time. With a custom vault or XDG data directory,
add its writable directories to the service's `ReadWritePaths` using
`systemctl --user edit signet.service`.

## WebDAV and storage

Use the HTTPS URL of a `.kdbx` file:

```sh
signet webdav set https://cloud.example.org/dav/Signet.kdbx --user YOUR_USERNAME
signet unlock
signet sync
```

The password is stored in the desktop Secret Service. Alternatively set
`password_command` in the `[webdav]` section of the configuration; the first
line of its output supplies the password. Signet uses Basic authentication
over HTTPS.

Sync runs while unlocked, after local changes, and on request. ETags protect
conditional uploads. Concurrent edits merge by UUID, retaining history and
attachments; the previous five local files are kept as backups. Servers
without ETags have weaker protection against simultaneous uploads.
[docs/vault-format.md](docs/vault-format.md) describes the file format and
merge rules, including unsupported XML extensions. Every device sharing the
vault must use the same vault password and key file.

The server receives only the encrypted vault. Signet has no analytics or
keyserver traffic. Locking drops decrypted vault and key references. Importing
a key removes its OpenPGP passphrase, so protect your vault password and
backups accordingly.

The key-entry field names match Keyguard's KeePass format. Signet does not
contain Keyguard source code. Third-party notices are in
[THIRD-PARTY.md](THIRD-PARTY.md).
