use super::low::*;
use crate::error::*;

#[derive(Debug)]
pub struct Aead {
    state: SymmetricState,
}

impl Aead {
    pub fn keygen(alg: &'static str) -> Result<Vec<u8>, Error> {
        let symmetric_key = SymmetricKey::generate(alg, None)?;
        symmetric_key.raw()
    }

    pub fn new(
        alg: &'static str,
        raw_key: impl AsRef<[u8]>,
        nonce: Option<&[u8]>,
        ad: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let symmetric_key = SymmetricKey::from_raw(alg, raw_key)?;
        let options = if let Some(nonce) = nonce {
            let mut options = SymmetricOptions::new();
            options.set("nonce", nonce)?;
            Some(options)
        } else {
            None
        };
        let mut state = SymmetricState::new(alg, Some(&symmetric_key), options.as_ref())?;
        if let Some(ad) = ad {
            state.absorb(ad)?;
        }
        Ok(Aead { state })
    }

    pub fn encrypt(&mut self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        self.state.encrypt(data)
    }

    pub fn decrypt(&mut self, ciphertext: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        self.state.decrypt(ciphertext)
    }
}
