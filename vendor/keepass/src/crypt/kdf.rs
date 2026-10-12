use std::convert::TryInto;

use aes::Aes256;
use cipher::{BlockCipherEncrypt, KeyInit};
use hybrid_array::{typenum::U32, Array as GenericArray};
use sha2::{Digest, Sha256};

use super::CryptographyError;

// Files choose their own KDF costs, and derivation runs before the key can be checked.
// These bounds keep a hostile file from taking unbounded time or memory while staying far
// above what KeePass clients choose for a few seconds of derivation.
const MAX_AES_ROUNDS: u64 = 1 << 30;
const MAX_ARGON2_MEMORY: u64 = 2 << 30;
const MAX_ARGON2_WORK: u128 = 64 << 30; // memory in bytes multiplied by iterations
const MAX_ARGON2_PARALLELISM: u32 = 256;
// rust-argon2's parallel mode starts a thread for every lane in each of the four slices of
// every pass. Above this many threads, startup costs more than the lanes save: a few KiB per
// lane over millions of passes would start tens of millions of threads.
const MAX_ARGON2_THREADS: u128 = 1 << 16;

pub(crate) trait Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError>;
}

pub struct AesKdf {
    pub seed: Vec<u8>,
    pub rounds: u64,
}

impl Kdf for AesKdf {
    #[allow(clippy::indexing_slicing)] // Slicing is safe because composite_key is always 32 bytes
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        let seed_arr = self
            .seed
            .as_slice()
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        if self.rounds > MAX_AES_ROUNDS {
            return Err(CryptographyError::KdfLimit);
        }
        let cipher = Aes256::new(&seed_arr);
        let mut block1: GenericArray<u8, _> = composite_key[..16]
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        let mut block2: GenericArray<u8, _> = composite_key[16..]
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        for _ in 0..self.rounds {
            cipher.encrypt_block(&mut block1);
            cipher.encrypt_block(&mut block2);
        }

        let mut digest = Sha256::new();

        digest.update(block1);
        digest.update(block2);

        Ok(digest.finalize())
    }
}

pub struct Argon2Kdf {
    pub memory: u64,
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub parallelism: u32,
    pub version: argon2::Version,
    pub variant: argon2::Variant,
}

impl Kdf for Argon2Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        if self.memory > MAX_ARGON2_MEMORY
            || u128::from(self.memory) * u128::from(self.iterations) > MAX_ARGON2_WORK
            || self.iterations > u64::from(u32::MAX)
            || self.parallelism > MAX_ARGON2_PARALLELISM
        {
            return Err(CryptographyError::KdfLimit);
        }
        let threads = 4 * u128::from(self.parallelism) * u128::from(self.iterations);

        // Disable Argon2 multithreading on wasm32 targets to avoid panics on platforms without thread support.
        let thread_mode = if cfg!(target_arch = "wasm32") || threads > MAX_ARGON2_THREADS {
            argon2::ThreadMode::Sequential
        } else {
            argon2::ThreadMode::Parallel
        };

        let config = argon2::Config {
            thread_mode,
            ad: &[],
            hash_length: 32,
            lanes: self.parallelism,
            mem_cost: (self.memory / 1024) as u32,
            secret: &[],
            time_cost: self.iterations as u32,
            variant: self.variant,
            version: self.version,
        };

        let key = argon2::hash_raw(composite_key, &self.salt, &config)?;

        key.as_slice()
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))
    }
}

#[cfg(test)]
mod tests {
    use argon2::{hash_raw, Config, ThreadMode, Variant, Version};
    use hybrid_array::{typenum::U32, Array as GenericArray};

    use super::{Argon2Kdf, Kdf};

    #[test]
    fn argon2_memory_is_interpreted_as_bytes() {
        let composite_key = GenericArray::<u8, U32>::from([7_u8; 32]);
        let salt = vec![9_u8; 32];
        let kdf = Argon2Kdf {
            memory: 64 * 1024,
            salt: salt.clone(),
            iterations: 1,
            parallelism: 1,
            version: Version::Version13,
            variant: Variant::Argon2id,
        };

        let expected = hash_raw(
            &composite_key,
            &salt,
            &Config {
                thread_mode: ThreadMode::Parallel,
                ad: &[],
                hash_length: 32,
                lanes: 1,
                mem_cost: 64,
                secret: &[],
                time_cost: 1,
                variant: Variant::Argon2id,
                version: Version::Version13,
            },
        )
        .expect("argon2 test vector should derive successfully");

        let actual = kdf
            .transform_key(&composite_key)
            .expect("argon2 kdf should derive successfully");

        assert_eq!(actual.as_slice(), expected.as_slice());
    }
}
