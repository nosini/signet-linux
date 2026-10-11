# Linux development

The CLI needs Rust 1.89 or newer, OpenSSL 3 development headers, libclang,
pkg-config, D-Bus development headers, GnuPG, and pinentry. The GTK app needs
Rust 1.92 or newer, GTK 4.14 or newer, and libadwaita 1.6 or newer.
On a Debian release with sufficiently recent GTK and libadwaita:

```sh
sudo apt install build-essential pkg-config libssl-dev libclang-dev libdbus-1-dev gnupg pinentry-qt libgtk-4-dev libadwaita-1-dev
```

```sh
cargo build --release --locked
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --workspace
```

Install the app, CLI, launcher, and icon:

```sh
sudo install -Dm 755 target/release/signet /usr/local/bin/signet
sudo install -Dm 755 target/release/signet-gui /usr/local/bin/signet-gui
sudo install -Dm 644 data/eu.nosini.Signet.desktop /usr/local/share/applications/eu.nosini.Signet.desktop
sudo install -Dm 644 data/eu.nosini.Signet.metainfo.xml /usr/local/share/metainfo/eu.nosini.Signet.metainfo.xml
sudo install -Dm 644 data/eu.nosini.Signet.svg /usr/local/share/icons/hicolor/scalable/apps/eu.nosini.Signet.svg
```

For CLI-only builds, use `cargo build --release --locked -p signet`; GTK and
libadwaita are not required. The optional pinentry-based service installs with:

```sh
sudo install -Dm 644 packaging/signet.service /usr/local/lib/systemd/user/signet.service
systemctl --user daemon-reload
```

The app hosts its own agent and should not run alongside that service.
`signet-gui --background` starts without showing the window; the app's
Preferences can arrange this at login. Native startup uses an XDG autostart
entry. Sandboxed startup uses the desktop Background portal.

`signet-vault` handles KDBX storage, import, transactional UUID merge, and
WebDAV. `signet` implements Assuan, GnuPG keygrips, pinentry, the local JSON
control socket, configuration, and CLI commands. Its library exposes
`Agent::start`, a blocking `Handle`, shared setup functions, and a `Prompter`
interface. `signet-gui` uses GTK 4 and libadwaita, with worker threads for
vault and network work and bounded requests to the GTK thread for prompts.
The agent itself needs no async runtime. Prompts are serialized separately from agent state;
network sync runs in workers. Locking invalidates pending unlocks and approvals. The lockfile currently resolves keepass 0.15.0,
Sequoia 2.4.1, OpenSSL crate 0.10.81, ureq 3.4.2 and keyring 3.6.3.
The OpenSSL backend supplies Sequoia's cryptography. The dedicated GnuPG home
has `no-autostart`, so GnuPG cannot start its own agent there.

The integration test starts isolated GnuPG homes and a fake pinentry. It
checks RSA, Ed25519/Cv25519, P-256 and P-384 signing/decryption, keygrips,
locked public queries, denied operations and refused secret export. Run it
with another GnuPG version first on `PATH` to check its protocol. The other
tests cover KDBX fidelity, Android-produced fixtures, merge, stale writes,
and WebDAV races and error paths. Fixture passwords and keys are public test
data.

Classic OpenPGP RSA and ECC agent operations are supported. Post-quantum
KEMs and the standalone RFC 9580 Ed25519/X25519 packet forms are not exposed
by the Linux keygrip/Assuan implementation. Malformed or unsupported requests
return errors. GUI prompts and Secret Service integration require a desktop session.
The hosted-agent test covers the library lifecycle and copying an existing
vault without changing its source, and checks that subkey changes reach
GnuPG, including deletions, which `gpg --import` never applies. The vault's
edit tests cover new subkeys of each algorithm, expiry, revocation, deletion,
attaching keys from another certificate and keeping secrets that an entry
protects with its own password. Manual UI checks should include creating
and opening vaults, importing a protected key, denied and accepted approvals,
locking during a prompt, reopening a hidden window, startup at login, and
each action in the subkey dialog.
The vault tests also cover GnuPG's fixed-width legacy Ed25519/Cv25519 secret MPI
encoding. Import normalizes that specific encoding only after verifying
the decrypted checksum; incorrect passphrases stop after three attempts.

`vendor/keepass` is MIT-licensed keepass-rs 0.15.0 with Signet's merge,
reference-rebuilding, and strict XML parsing changes. The changes preserve
modeled unrelated KeePass data and reject unmodeled XML rather than silently
remove it. Attribution and the Sequoia keygrip license are in
[THIRD-PARTY.md](THIRD-PARTY.md).
