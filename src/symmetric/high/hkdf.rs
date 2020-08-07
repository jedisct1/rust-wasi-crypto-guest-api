use super::low::*;
use crate::error::*;

type HkdfKey = SymmetricKey;
type HkdfPrk = SymmetricKey;

#[derive(Debug)]
pub struct Hkdf {
    prk: HkdfPrk,
    exp_alg: &'static str,
}

impl Hkdf {
    pub fn keygen(prk_alg: &'static str) -> Result<HkdfPrk, Error> {
        SymmetricKey::generate(prk_alg, None)
    }

    pub fn new(
        prk_alg: &'static str,
        exp_alg: &'static str,
        key: &HkdfKey,
        salt: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let salt = salt.as_ref().map(|x| x.as_ref());
        let mut state = SymmetricState::new(prk_alg, Some(&key), None)?;
        if let Some(salt) = salt {
            state.absorb(salt)?;
        };
        let prk = state.squeeze_key(exp_alg)?;
        Ok(Hkdf { prk, exp_alg })
    }

    pub fn expand(&self, info: impl AsRef<[u8]>, len: usize) -> Result<Vec<u8>, Error> {
        let info = info.as_ref();
        let mut state = SymmetricState::new(self.exp_alg, Some(&self.prk), None)?;
        state.absorb(info)?;
        state.squeeze(len)
    }
}
