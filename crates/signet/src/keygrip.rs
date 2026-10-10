// Adapted from Sequoia IPC 0.37.0-pqc.1, LGPL-2.0-or-later.
// Copyright the Sequoia authors; see THIRD-PARTY.md.
use std::fmt;
use std::io::Write;

use openpgp::Error;
use openpgp::Result;
use openpgp::crypto::mpi::{MPI, PublicKey};
use openpgp::types::{Curve, HashAlgorithm};
use sequoia_openpgp as openpgp;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Keygrip([u8; 20]);

impl fmt::Debug for Keygrip {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02X}", *b)?;
        }
        Ok(())
    }
}

impl fmt::Display for Keygrip {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.0.iter() {
            write!(f, "{:02X}", *b)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Keygrip {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let bytes = openpgp::fmt::hex::decode_pretty(s)?;
        if bytes.len() == 20 {
            let mut digest = [0; 20];
            digest[..].copy_from_slice(&bytes[..]);
            Ok(Keygrip(digest))
        } else {
            Err(Error::InvalidArgument(format!("Expected 20 bytes, got {}", bytes.len())).into())
        }
    }
}

impl Keygrip {
    pub fn of(key: &PublicKey) -> Result<Keygrip> {
        use self::PublicKey::*;
        use openpgp::crypto::hash;
        let mut hash = HashAlgorithm::SHA1.context().unwrap().for_digest();

        fn hash_sexp_mpi(hash: &mut hash::Context, kind: char, mpi: &MPI) {
            // gcrypt's MPIs can be signed or unsigned.  Our MPIs are
            // always unsigned (well, for us they are opaque byte
            // strings, so the concept of a sign does not apply).
            // Every now and then we need to pay attention to this, as
            // gcrypt sometimes prepends a zero to prevent the most
            // significant bit from being interpreted as a sign bit.
            // Computing keygrips is one of these times.
            let prefix = if mpi
                .value()
                .first()
                .map(|msb| msb & 0x80 > 0)
                .unwrap_or(false)
            {
                // The most significant bit is set.  Prepend a zero
                // byte so that the MSB will not be interpreted as a
                // sign bit.
                &b"\x00"[..]
            } else {
                // The MSB is not set, no need to prepend anything.
                &b""[..]
            };
            hash_sexp(hash, kind, prefix, mpi.value());
        }

        fn hash_sexp(hash: &mut hash::Context, kind: char, prefix: &[u8], buf: &[u8]) {
            write!(hash, "(1:{}{}:", kind, buf.len() + prefix.len()).unwrap();
            hash.update(prefix);
            hash.update(buf);
            write!(hash, ")").unwrap();
        }

        fn hash_ecc(hash: &mut hash::Context, curve: &Curve, q: &MPI) -> Result<()> {
            for (i, name) in "pabgnhq".chars().enumerate() {
                if i == 5 {
                    continue; // Skip cofactor.
                }

                let param;
                let mut m = if i == 6 {
                    q.value()
                } else {
                    param = ecc_param(curve, i)?;
                    param.value()
                };

                // Opaque encoding?
                if m.first() == Some(&0x40) {
                    // Drop the prefix!
                    m = &m[1..];
                }

                hash_sexp(hash, name, &[], m);
            }

            Ok(())
        }

        match key {
            // From libgcrypt/cipher/rsa.c:
            //
            //     PKCS-15 says that for RSA only the modulus should be
            //     hashed - however, it is not clear whether this is meant
            //     to use the raw bytes (assuming this is an unsigned
            //     integer) or whether the DER required 0 should be
            //     prefixed.  We hash the raw bytes.
            RSA { n, .. } => {
                // Contrary to the comment reproduced above,
                // overwhelming empirical evidence suggest that we
                // need to prepend a 0.
                hash.update(&[0]);
                hash.update(n.value());
            }

            DSA { p, q, g, y } => {
                hash_sexp_mpi(&mut hash, 'p', p);
                hash_sexp_mpi(&mut hash, 'q', q);
                hash_sexp_mpi(&mut hash, 'g', g);
                hash_sexp_mpi(&mut hash, 'y', y);
            }

            ElGamal { p, g, y } => {
                hash_sexp_mpi(&mut hash, 'p', p);
                hash_sexp_mpi(&mut hash, 'g', g);
                hash_sexp_mpi(&mut hash, 'y', y);
            }

            EdDSA { curve, q } => hash_ecc(&mut hash, curve, q)?,
            ECDSA { curve, q } => hash_ecc(&mut hash, curve, q)?,
            ECDH { curve, q, .. } => hash_ecc(&mut hash, curve, q)?,

            // crypto::mpi::PublicKey is non_exhaustive, match on &_ to handle
            // future additions.
            _ => {
                return Err(Error::InvalidOperation(
                    "Keygrip not defined for this kind of public key".into(),
                )
                .into());
            }
        }

        let mut digest = [0; 20];
        let _ = hash.digest(&mut digest);
        Ok(Keygrip(digest))
    }
}

fn ecc_param(curve: &Curve, i: usize) -> Result<MPI> {
    use self::Curve::*;
    assert!(i < 6);
    let hex = match (curve, i) {
        (NistP256, 0) => "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        (NistP256, 1) => "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
        (NistP256, 2) => "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        (NistP256, 4) => "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        (NistP256, 3) => {
            "0x04\
                          6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                          4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        }
        (NistP256, 5) => "0x01",

        (NistP384, 0) => {
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"
        }
        (NistP384, 1) => {
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"
        }
        (NistP384, 2) => {
            "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"
        }
        (NistP384, 4) => {
            "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
        }
        (NistP384, 3) => {
            "0x04\
                          aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7\
                          3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
        }
        (NistP384, 5) => "0x01",

        (NistP521, 0) => {
            "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }
        (NistP521, 1) => {
            "0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc"
        }
        (NistP521, 2) => {
            "0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"
        }
        (NistP521, 4) => {
            "0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
        }
        (NistP521, 3) => {
            "0x04\
                          00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66\
                          011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
        }
        (NistP521, 5) => "0x01",

        (BrainpoolP256, 0) => "0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
        (BrainpoolP256, 1) => "0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
        (BrainpoolP256, 2) => "0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
        (BrainpoolP256, 4) => "0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
        (BrainpoolP256, 3) => {
            "0x04\
                               8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262\
                               547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997"
        }
        (BrainpoolP256, 5) => "0x01",

        (BrainpoolP512, 0) => {
            "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3"
        }
        (BrainpoolP512, 1) => {
            "0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca"
        }
        (BrainpoolP512, 2) => {
            "0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723"
        }
        (BrainpoolP512, 4) => {
            "0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069"
        }
        (BrainpoolP512, 3) => {
            "0x04\
                               81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822\
                               7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892"
        }
        (BrainpoolP512, 5) => "0x01",

        (Ed25519, 0) => "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
        (Ed25519, 1) =>
        /* - */
        {
            "0x01"
        }
        (Ed25519, 2) =>
        /* - */
        {
            "0x2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A"
        }
        (Ed25519, 4) => "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
        (Ed25519, 3) => {
            "0x04\
                         216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A\
                         6666666666666666666666666666666666666666666666666666666666666658"
        }
        (Ed25519, 5) => "0x08",

        (Cv25519, 0) => "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
        (Cv25519, 1) => "0x01DB41",
        (Cv25519, 2) => "0x01",
        (Cv25519, 4) => "0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
        (Cv25519, 3) => {
            "0x04\
                         0000000000000000000000000000000000000000000000000000000000000009\
                         20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9"
        }
        (Cv25519, 5) => "0x08",

        (_, _) => {
            let error = || {
                Err(Error::InvalidArgument(format!(
                    "Invalid or unknown curve parameters: \
                             curve: {}, i: {}",
                    curve, i
                ))
                .into())
            };

            const BRAINPOOL_P384_OID: &[u8] =
                &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];

            if curve.oid() == BRAINPOOL_P384_OID {
                match i {
                    0 => {
                        "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53"
                    }
                    1 => {
                        "0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826"
                    }
                    2 => {
                        "0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11"
                    }
                    4 => {
                        "0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565"
                    }
                    3 => {
                        "0x04\
                          1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e\
                          8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315"
                    }
                    5 => "0x01",
                    _ => return error(),
                }
            } else {
                return error();
            }
        }
    };

    Ok(openpgp::fmt::hex::decode_pretty(hex).unwrap().into())
}
