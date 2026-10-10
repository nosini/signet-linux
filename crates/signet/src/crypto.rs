// SPDX-License-Identifier: GPL-3.0-or-later
use crate::assuan::Sexp;
use anyhow::{Context, Result, bail};
use openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::{Id, PKey},
};
use sequoia_openpgp::{
    crypto::{
        Decryptor, KeyPair, Signer,
        mpi::{Ciphertext, MPI, PublicKey, SecretKeyMaterial, Signature},
    },
    packet::{
        Key,
        key::{PublicParts, UnspecifiedRole},
    },
    types::{Curve, HashAlgorithm},
};
use zeroize::Zeroizing;
fn integer(value: &[u8]) -> Vec<u8> {
    if value.first().is_some_and(|b| b & 0x80 != 0) {
        let mut bytes = vec![0];
        bytes.extend_from_slice(value);
        bytes
    } else {
        value.to_vec()
    }
}
fn curve_name(curve: &Curve) -> Result<&'static str> {
    match curve {
        Curve::Ed25519 => Ok("Ed25519"),
        Curve::Cv25519 => Ok("Curve25519"),
        Curve::NistP256 => Ok("NIST P-256"),
        Curve::NistP384 => Ok("NIST P-384"),
        Curve::NistP521 => Ok("NIST P-521"),
        _ => bail!("unsupported curve"),
    }
}
pub fn public(key: &Key<PublicParts, UnspecifiedRole>) -> Result<Vec<u8>> {
    let parts = match key.mpis() {
        PublicKey::RSA { n, e } => vec![
            Sexp::atom("rsa"),
            Sexp::named("n", integer(n.value())),
            Sexp::named("e", integer(e.value())),
        ],
        PublicKey::EdDSA { curve, q }
        | PublicKey::ECDSA { curve, q }
        | PublicKey::ECDH { curve, q, .. } => {
            let mut parts = vec![
                Sexp::atom("ecc"),
                Sexp::named("curve", curve_name(curve)?),
                Sexp::named("q", q.value()),
            ];
            if *curve == Curve::Ed25519 {
                parts.push(Sexp::named("flags", "eddsa"));
            }
            if *curve == Curve::Cv25519 {
                parts.push(Sexp::list(vec![
                    Sexp::atom("flags"),
                    Sexp::atom("djb-tweak"),
                ]));
            }
            parts
        }
        PublicKey::Ed25519 { a } => vec![
            Sexp::atom("ecc"),
            Sexp::named("curve", "Ed25519"),
            Sexp::named("q", a.as_ref()),
            Sexp::named("flags", "eddsa"),
        ],
        _ => bail!("unsupported public key algorithm"),
    };
    Ok(Sexp::list(vec![Sexp::atom("public-key"), Sexp::list(parts)]).encode())
}
pub fn sign(pair: &mut KeyPair, algorithm: HashAlgorithm, digest: &[u8]) -> Result<Vec<u8>> {
    if algorithm.digest_size()? != digest.len() {
        bail!("invalid digest length");
    }
    let parts = match pair.sign(algorithm, digest)? {
        Signature::RSA { s } => vec![Sexp::atom("rsa"), Sexp::named("s", integer(s.value()))],
        Signature::EdDSA { r, s } => vec![
            Sexp::atom("eddsa"),
            Sexp::named("r", r.value_padded(32)?),
            Sexp::named("s", s.value_padded(32)?),
        ],
        Signature::ECDSA { r, s } => vec![
            Sexp::atom("ecdsa"),
            Sexp::named("r", integer(r.value())),
            Sexp::named("s", integer(s.value())),
        ],
        Signature::Ed25519 { s } => vec![
            Sexp::atom("eddsa"),
            Sexp::named("r", &s[..32]),
            Sexp::named("s", &s[32..]),
        ],
        _ => bail!("unsupported signing algorithm"),
    };
    Ok(Sexp::list(vec![Sexp::atom("sig-val"), Sexp::list(parts)]).encode())
}
pub fn decrypt(pair: &mut KeyPair, ciphertext: &[u8], kem: bool) -> Result<Zeroizing<Vec<u8>>> {
    let expression = Sexp::parse(ciphertext)?;
    let bytes: Zeroizing<Vec<u8>> = match pair.public().mpis() {
        PublicKey::RSA { .. } if !kem => {
            let c = expression.find(b"a").context("missing RSA ciphertext")?;
            Zeroizing::new(
                pair.decrypt(&Ciphertext::RSA { c: MPI::new(c) }, None)?
                    .to_vec(),
            )
        }
        PublicKey::ECDH { .. } if kem => {
            let e = expression.find(b"e").context("missing ephemeral point")?;
            let wrapped = expression.find(b"s").context("missing wrapped key")?;
            if wrapped.first().copied().map(usize::from) != Some(wrapped.len().saturating_sub(1)) {
                bail!("invalid wrapped key length");
            }
            let raw = pair.decrypt(
                &Ciphertext::ECDH {
                    e: MPI::new(e),
                    key: wrapped[1..].to_vec().into_boxed_slice(),
                },
                None,
            )?;
            // GnuPG's KEM protocol leaves RFC 6637 padding removal to the client.
            let mut padded = Zeroizing::new(raw.to_vec());
            let padding = 8 - padded.len() % 8;
            padded.extend(std::iter::repeat_n(padding as u8, padding));
            padded
        }
        PublicKey::ECDH { curve, .. } if !kem => {
            let curve = curve.clone();
            let point = expression.find(b"e").context("missing ephemeral point")?;
            pair.secret().map(|secret| -> Result<Zeroizing<Vec<u8>>> {
                let SecretKeyMaterial::ECDH { scalar } = secret else {
                    bail!("invalid ECDH secret");
                };
                if curve == Curve::Cv25519 {
                    let mut scalar = Zeroizing::new(scalar.value_padded(32).to_vec());
                    scalar.reverse();
                    let point = point
                        .strip_prefix(&[0x40])
                        .context("invalid Curve25519 point")?;
                    if point.len() != 32 {
                        bail!("invalid Curve25519 point length");
                    }
                    let key = PKey::private_key_from_raw_bytes(&scalar, Id::X25519)?;
                    let peer = PKey::public_key_from_raw_bytes(point, Id::X25519)?;
                    let mut derive = Deriver::new(&key)?;
                    derive.set_peer(&peer)?;
                    let shared = Zeroizing::new(derive.derive_to_vec()?);
                    let mut out = Zeroizing::new(vec![0x40]);
                    out.extend_from_slice(&shared);
                    Ok(out)
                } else {
                    let nid = match curve {
                        Curve::NistP256 => Nid::X9_62_PRIME256V1,
                        Curve::NistP384 => Nid::SECP384R1,
                        Curve::NistP521 => Nid::SECP521R1,
                        _ => bail!("unsupported ECDH curve"),
                    };
                    let group = EcGroup::from_curve_name(nid)?;
                    let mut ctx = BigNumContext::new_secure()?;
                    let point = EcPoint::from_bytes(&group, point, &mut ctx)?;
                    if point.is_infinity(&group) || !point.is_on_curve(&group, &mut ctx)? {
                        bail!("invalid ECDH point");
                    }
                    let mut scalar = BigNum::from_slice(scalar.value())?;
                    scalar.set_const_time();
                    let mut shared = EcPoint::new(&group)?;
                    let result = shared.mul2(&group, &point, &scalar, &mut ctx);
                    scalar.clear();
                    result?;
                    Ok(Zeroizing::new(shared.to_bytes(
                        &group,
                        PointConversionForm::UNCOMPRESSED,
                        &mut ctx,
                    )?))
                }
            })?
        }
        _ => bail!("unsupported decryption algorithm or KEM"),
    };
    let mut result = Zeroizing::new(format!("(5:value{}:", bytes.len()).into_bytes());
    result.extend_from_slice(&bytes);
    result.push(b')');
    Ok(result)
}
