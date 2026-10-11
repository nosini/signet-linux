# Signet

Signet keeps OpenPGP keys in an encrypted KeePass vault and asks before
signing or decrypting. The Linux app works with GnuPG and Git and runs an
agent in the background. [Signet for Android](https://github.com/nosini/signet-android)
can sync the same KDBX file over WebDAV.

The name comes from a signet ring: a seal used to sign documents. The code is
licensed under **GPL-3.0-or-later**.

## Installation and use

Install the native app using the [build and installation instructions](README-dev.md).
Launch **Signet** from your application menu. You can create a new vault,
open a vault file, or download one using the full HTTPS URL of a WebDAV
file. Opened vaults and optional key files are copied into Signet's storage;
the source files are left unchanged.

Choose **Import Key** to add an OpenPGP key file. Signet asks for its
passphrase when needed and prepares the dedicated GnuPG home automatically.
Open a key's details to copy its fingerprint, copy or save its public
certificate, copy Git signing commands, or remove it from the vault.
**Export Secret Key…** saves a backup after you confirm the master password;
Signet protects the file with a new passphrase that you choose. Programs that
use the agent, such as Seahorse or `gpg --export-secret-keys`, can't export
secret keys.

Use **Copy GNUPGHOME** and paste the assignment into the shell that will run
GnuPG or Git. The dedicated home contains public certificates and trust
information; secret keys stay in the vault. After syncing new keys from
another device, choose **Set Up GnuPG** to update those certificates.

To skip `GNUPGHOME` entirely, turn on **Serve the standard GnuPG home** in
Preferences. Signet then answers on the agent socket of `~/.gnupg`, so GnuPG,
Git and mail clients find it without any setup. It replaces GnuPG's own
agent, which Signet stops when it starts: keys stored in GnuPG itself can't
be used while Signet runs, and gpg-agent's SSH support stops too. Where
systemd starts GnuPG's agent, disable that first; Preferences shows the
commands. Reopen Signet after changing the setting, then choose **Set Up
GnuPG**. For the command-line agent, set `gnupg_home = "~/.gnupg"` in the
configuration.

Flatpak apps such as Evolution also need GnuPG's socket folder. Without it,
their GnuPG starts its own agent, which has none of your keys, and can lock
the key database for everyone else. Grant it on the host, then restart the
app:

```sh
flatpak override --user --filesystem=xdg-run/gnupg org.gnome.Evolution
flatpak kill org.gnome.Evolution
```

Signet starts locked and asks for the master password when a key is needed.
It asks for approval before signing or decrypting and locks after 15 idle
minutes by default. **Lock**, **Unlock**, and **Sync** are also available
in the window. Preferences control idle locking, approval reuse, startup at
login, and WebDAV. Set approval reuse to `0s` to ask every time. Callers that
cannot be identified are never remembered. **Ask before signing** and **Ask
before decrypting** can be turned off separately; then any program you run
can use the key for that operation while the vault is unlocked.

Closing the window keeps the agent running. Reopen Signet from the menu to
manage it, or use **Quit Signet** to stop it. Use one agent at a time: if you
previously enabled the command-line service, stop it before opening the app:

```sh
systemctl --user disable --now signet.service
```

## Command-line use

The `signet` CLI can run without the graphical app, using pinentry for its
password and approval dialogs. Install the optional user service as described
in [README-dev.md](README-dev.md), then set it up:

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
Approval dialogs use the agent's session display and terminal, so clients
cannot choose where confirmation appears. Process descriptions help identify
a request, but an application can change its own command line. Programs in a
Flatpak sandbox are shown with their verified app ID, such as
`org.gnome.Evolution`, and remembered approvals apply to that app only. Approval is
not a security boundary against unrestricted code running as the same Linux
user, which can edit Signet's configuration.

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
`remember` at zero asks every time. `[approval] sign = false` or
`decrypt = false` turns off the prompt for that operation. With a custom vault or XDG data directory,
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
