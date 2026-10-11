// SPDX-License-Identifier: GPL-3.0-or-later
//! GnuPG's legacy Ed25519/Cv25519 secret exports can use a fixed 256-bit MPI
//! length even when the seed's high bit is clear. Sequoia rejects that
//! encoding. Accept only this specific v4 format, after checking the
//! decrypted SHA-1 checksum, and normalize the scalar in protected memory.
//!
//! Unprotected exports have a variant of this: when an Ed25519 seed starts
//! with a zero byte, GnuPG keeps all 32 bytes in a "256-bit" MPI, and
//! Sequoia can't parse the packet at all. [`normalize_unprotected`]
//! re-encodes such a packet after checking its checksum.
//!
//! The same checksum identifies a wrong passphrase for any v4 AES key.
//! Sequoia parses the decrypted data first and then reports a parse error,
//! which looks like an unsupported key.
use openssl::symm::{Cipher, Crypter, Mode};
use sequoia_openpgp::{
    Error, Packet, PacketPile, Result,
    crypto::{Password, mem, mpi},
    packet::{Key, Tag, key},
    parse::Parse,
    serialize::Serialize,
    types::{Curve, SymmetricAlgorithm},
};
use zeroize::Zeroizing;

/// Re-encodes unprotected Ed25519 secret packets that Sequoia couldn't
/// parse. Returns `None` when the input needs no change.
pub fn normalize_unprotected(data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let pile = PacketPile::from_bytes(data).ok()?;
    let mut changed = false;
    let mut output = Zeroizing::new(Vec::new());
    for packet in pile.into_children() {
        let packet = match packet {
            Packet::Unknown(unknown)
                if matches!(unknown.tag(), Tag::SecretKey | Tag::SecretSubkey) =>
            {
                match repair_unprotected(unknown.tag(), unknown.body()) {
                    Some(packet) => {
                        changed = true;
                        packet
                    }
                    None => Packet::Unknown(unknown),
                }
            }
            packet => packet,
        };
        packet.serialize(&mut *output).ok()?;
    }
    changed.then_some(output)
}

fn repair_unprotected(tag: Tag, body: &[u8]) -> Option<Packet> {
    const ED25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
    // Version 4, creation time, EdDSA, then the curve OID and public point.
    if body.len() < 7 || body[0] != 4 || body[5] != 22 {
        return None;
    }
    let mut at = 6;
    let oid_len = usize::from(*body.get(at)?);
    if body.get(at + 1..at + 1 + oid_len)? != ED25519 {
        return None;
    }
    at += 1 + oid_len;
    let point_bits = usize::from(u16::from_be_bytes([*body.get(at)?, *body.get(at + 1)?]));
    at += 2 + point_bits.div_ceil(8);
    // Unprotected: a zero usage byte, the MPI and its two-byte checksum.
    if *body.get(at)? != 0 {
        return None;
    }
    at += 1;
    let secret = body.get(at..)?;
    if secret.len() != 2 + 32 + 2 || secret[..3] != [1, 0, 0] {
        return None;
    }
    if checksum(&secret[..34]) != secret[34..] {
        return None;
    }
    let value = &secret[2..34];
    let value = &value[value.iter().position(|b| *b != 0)?..];
    let bits = (value.len() * 8 - value[0].leading_zeros() as usize) as u16;
    let mut fixed = Zeroizing::new(body[..at].to_vec());
    fixed.extend_from_slice(&bits.to_be_bytes());
    fixed.extend_from_slice(value);
    let sum = checksum(&fixed[at..]);
    fixed.extend_from_slice(&sum);
    // A new-format packet header; secret key bodies stay well below 8384.
    let mut packet = Zeroizing::new(vec![0xc0 | u8::from(tag)]);
    let length = fixed.len().checked_sub(192);
    match length {
        None => packet.push(fixed.len() as u8),
        Some(rest) if rest < 8192 => {
            packet.extend_from_slice(&[(rest >> 8) as u8 + 192, rest as u8])
        }
        Some(_) => return None,
    }
    packet.extend_from_slice(&fixed);
    Packet::from_bytes(&packet[..]).ok()
}

/// OpenPGP's checksum for unprotected secret key material.
fn checksum(data: &[u8]) -> [u8; 2] {
    data.iter()
        .fold(0u16, |sum, byte| sum.wrapping_add(u16::from(*byte)))
        .to_be_bytes()
}

pub fn decrypt<R: key::KeyRole>(
    key: Key<key::SecretParts, R>,
    password: &Password,
) -> Result<Key<key::SecretParts, R>> {
    match key.clone().decrypt_secret(password) {
        Ok(key) => Ok(key),
        Err(original) => match normalize(&key, password) {
            Ok(key) => Ok(key),
            Err(error) if matches!(error.downcast_ref::<Error>(), Some(Error::InvalidPassword)) => {
                Err(error)
            }
            Err(_) => Err(original),
        },
    }
}

fn normalize<R: key::KeyRole>(
    key: &Key<key::SecretParts, R>,
    password: &Password,
) -> Result<Key<key::SecretParts, R>> {
    let key::SecretKeyMaterial::Encrypted(encrypted) = key.secret() else {
        return Err(Error::InvalidOperation("key is not encrypted".into()).into());
    };
    if key.version() != 4
        || encrypted.aead_algo().is_some()
        || encrypted.checksum() != Some(mpi::SecretKeyChecksum::SHA1)
    {
        return Err(Error::InvalidOperation("not a SHA-1 protected CFB key".into()).into());
    }
    let cipher = match encrypted.algo() {
        SymmetricAlgorithm::AES128 => Cipher::aes_128_cfb128(),
        SymmetricAlgorithm::AES192 => Cipher::aes_192_cfb128(),
        SymmetricAlgorithm::AES256 => Cipher::aes_256_cfb128(),
        _ => return Err(Error::InvalidOperation("not an AES protected key".into()).into()),
    };
    // An IV, the secret MPIs and their SHA-1 checksum.
    let ciphertext = encrypted.ciphertext()?;
    if ciphertext.len() < 16 + 20 {
        return Err(Error::MalformedPacket("unexpected secret key length".into()).into());
    }
    let derived = encrypted.s2k().derive_key(password, cipher.key_len())?;
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &derived, Some(&ciphertext[..16]))?;
    crypter.pad(false);
    let mut plaintext = Zeroizing::new(vec![0; ciphertext.len() - 16 + cipher.block_size()]);
    let written = crypter.update(&ciphertext[16..], &mut plaintext)?;
    let written = written + crypter.finalize(&mut plaintext[written..])?;
    if written != ciphertext.len() - 16 {
        return Err(Error::MalformedPacket("unexpected secret key length".into()).into());
    }
    let (body, checksum) = plaintext[..written].split_at(written - 20);
    let digest = Zeroizing::new(openssl::sha::sha1(body));
    if mem::secure_cmp(&digest[..], checksum) != std::cmp::Ordering::Equal {
        return Err(Error::InvalidPassword.into());
    }
    // Only GnuPG's fixed-width 25519 encoding is repaired: a 32-byte seed
    // with a two-byte MPI header.
    if !matches!(
        key.mpis(),
        mpi::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            ..
        } | mpi::PublicKey::ECDH {
            curve: Curve::Cv25519,
            ..
        }
    ) {
        return Err(Error::InvalidOperation("not a legacy 25519 key".into()).into());
    }
    if written != 54 {
        return Err(Error::MalformedPacket("unexpected secret key length".into()).into());
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
