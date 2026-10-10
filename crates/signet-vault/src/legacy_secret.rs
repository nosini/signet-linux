// SPDX-License-Identifier: GPL-3.0-or-later
//! GnuPG's legacy Ed25519/Cv25519 secret exports can use a fixed 256-bit MPI
//! length even when the seed's high bit is clear. Sequoia rejects that
//! encoding. Accept only this specific v4 format, after checking the
//! decrypted SHA-1 checksum, and normalize the scalar in protected memory.
use openssl::symm::{Cipher, Crypter, Mode};
use sequoia_openpgp::{
    Error, Result,
    crypto::{Password, mem, mpi},
    packet::{Key, key},
    types::{Curve, SymmetricAlgorithm},
};
use zeroize::Zeroizing;

pub fn decrypt<R: key::KeyRole>(
    key: Key<key::SecretParts, R>,
    password: &Password,
) -> Result<Key<key::SecretParts, R>> {
    match key.clone().decrypt_secret(password) {
        Ok(key) => Ok(key),
        Err(original) => normalize(&key, password).map_err(|_| original),
    }
}

fn normalize<R: key::KeyRole>(
    key: &Key<key::SecretParts, R>,
    password: &Password,
) -> Result<Key<key::SecretParts, R>> {
    if key.version() != 4
        || !matches!(
            key.mpis(),
            mpi::PublicKey::EdDSA {
                curve: Curve::Ed25519,
                ..
            } | mpi::PublicKey::ECDH {
                curve: Curve::Cv25519,
                ..
            }
        )
    {
        return Err(Error::InvalidOperation("not a legacy 25519 key".into()).into());
    }
    let key::SecretKeyMaterial::Encrypted(encrypted) = key.secret() else {
        return Err(Error::InvalidOperation("key is not encrypted".into()).into());
    };
    if encrypted.aead_algo().is_some() || encrypted.checksum() != Some(mpi::SecretKeyChecksum::SHA1)
    {
        return Err(Error::InvalidOperation("not a SHA-1 protected CFB key".into()).into());
    }
    let cipher = match encrypted.algo() {
        SymmetricAlgorithm::AES128 => Cipher::aes_128_cfb128(),
        SymmetricAlgorithm::AES192 => Cipher::aes_192_cfb128(),
        SymmetricAlgorithm::AES256 => Cipher::aes_256_cfb128(),
        _ => return Err(Error::InvalidOperation("not an AES protected key".into()).into()),
    };
    // One IV, one 32-byte seed with a two-byte MPI header, and its checksum.
    let ciphertext = encrypted.ciphertext()?;
    if ciphertext.len() != 16 + 2 + 32 + 20 {
        return Err(Error::MalformedPacket("unexpected secret key length".into()).into());
    }
    let derived = encrypted.s2k().derive_key(password, cipher.key_len())?;
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &derived, Some(&ciphertext[..16]))?;
    crypter.pad(false);
    let mut plaintext = Zeroizing::new(vec![0; ciphertext.len() - 16 + cipher.block_size()]);
    let written = crypter.update(&ciphertext[16..], &mut plaintext)?;
    let written = written + crypter.finalize(&mut plaintext[written..])?;
    if written != 54 {
        return Err(Error::MalformedPacket("unexpected secret key length".into()).into());
    }
    let digest = Zeroizing::new(openssl::sha::sha1(&plaintext[..34]));
    if mem::secure_cmp(&digest[..], &plaintext[34..54]) != std::cmp::Ordering::Equal {
        return Err(Error::InvalidPassword.into());
    }
    if plaintext[..2] != [1, 0] || plaintext[2] & 0x80 != 0 {
        return Err(Error::MalformedPacket("not a fixed-width secret MPI".into()).into());
    }
    let scalar = mpi::ProtectedMPI::from(&plaintext[2..34]);
    let material = if matches!(key.mpis(), mpi::PublicKey::EdDSA { .. }) {
        mpi::SecretKeyMaterial::EdDSA { scalar }
    } else {
        mpi::SecretKeyMaterial::ECDH { scalar }
    };
    let secret = key::SecretKeyMaterial::Unencrypted(material.into());
    Ok(key.clone().add_secret(secret).0)
}
