# Linux development

Use Rust 1.89 or newer, OpenSSL 3 development headers, libclang, pkg-config,
D-Bus development headers, GnuPG, and pinentry. On Debian these system
packages can be installed with:

```sh
sudo apt install build-essential pkg-config libssl-dev libclang-dev libdbus-1-dev gnupg pinentry-qt
```

```sh
cargo build --release --locked
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --workspace
```

`signet-vault` handles KDBX storage, import, transactional UUID merge, and
WebDAV. `signet` implements Assuan, GnuPG keygrips, pinentry, the local JSON
control socket, configuration, and CLI commands. No async runtime is used. Prompts are serialized separately from agent state;
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
return errors. GUI prompts and Secret Service integration require a desktop
session; the tests substitute pinentry and do not exercise that desktop UI.

`vendor/keepass` is MIT-licensed keepass-rs 0.15.0 with Signet's merge,
reference-rebuilding, and strict XML parsing changes. The changes preserve
modeled unrelated KeePass data and reject unmodeled XML rather than silently
remove it. Attribution and the Sequoia keygrip license are in
[THIRD-PARTY.md](THIRD-PARTY.md).
