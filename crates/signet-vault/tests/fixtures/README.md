# Test keys

`gpg-ed25519-protected.asc` is a throwaway GnuPG 2.5.22 Ed25519 signing key.
Its public test passphrase is `import-test`. Its encrypted secret MPI uses
the fixed 256-bit length emitted by GnuPG even when the seed's high bit is
clear. It exercises import compatibility, checksum validation, and signing
after normalizing that encoding.

`gpg-25519-protected.asc` adds a Cv25519 encryption subkey with the same
fixed-width encoding. Its passphrase is also `import-test`; it exercises
session-key decryption and rejection of a corrupted checksum. Both fixtures
use a reduced S2K count for fast tests and must never be used outside tests.

`gpg-ed25519-unprotected-primary.asc` and `gpg-ed25519-unprotected-subkey.asc`
are throwaway GnuPG 2.5.22 keys exported without a passphrase: an Ed25519
primary key, an Ed25519 signing subkey and a Cv25519 encryption subkey. In
the first, the primary key's seed starts with a zero byte; in the second,
the signing subkey's does. GnuPG then writes a 256-bit MPI with a leading
zero byte, which Sequoia can't parse. They exercise import of all three
secrets and signing with the repaired keys.
