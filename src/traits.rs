use rand::{CryptoRng, RngCore};

use crate::errors::Error;
pub trait PkeScheme {
    type DecryptKey;
    type EncryptKey;

    fn key_gen(&self, d: &[u8; 32]) -> Result<(Self::EncryptKey, Self::DecryptKey), Error>;

    fn encrypt(&self, ek: &Self::EncryptKey, m: &[u8; 32], r: &[u8; 32]) -> Result<Vec<u8>, Error>;

    fn decrypt(&self, dk: &Self::DecryptKey, c: &[u8]) -> Result<[u8; 32], Error>;
}

pub trait KemScheme {
    type DecapsKey;
    type EncapsKey;
    type SharedSecret;

    fn key_gen_internal(
        &self,
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Result<(Self::EncapsKey, Self::DecapsKey), Error>;

    fn key_gen<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Self::EncapsKey, Self::DecapsKey), Error>;

    fn encaps_internal(
        &self,
        ek: &Self::EncapsKey,
        m: &[u8; 32],
    ) -> Result<(Self::SharedSecret, Vec<u8>), Error>;

    fn encaps<R: RngCore + CryptoRng>(
        &self,
        ek: &Self::EncapsKey,
        rng: &mut R,
    ) -> Result<(Self::SharedSecret, Vec<u8>), Error>;

    fn decaps_internal(&self, dk: &Self::DecapsKey, c: &[u8]) -> Result<Self::SharedSecret, Error>;

    fn decaps(&self, dk: &Self::DecapsKey, c: &[u8]) -> Result<Self::SharedSecret, Error>;
}
