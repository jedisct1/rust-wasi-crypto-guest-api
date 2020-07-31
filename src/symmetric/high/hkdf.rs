use super::low::*;
use crate::error::*;

#[derive(Debug)]
pub struct Hkdf {
    prk: SymmetricKey,
    exp_alg: &'static str,
}

impl Hkdf {
    pub fn keygen(prk_alg: &'static str) -> Result<Vec<u8>, Error> {
        let symmetric_key = SymmetricKey::generate(prk_alg, None)?;
        symmetric_key.raw()
    }

    pub fn new(
        prk_alg: &'static str,
        exp_alg: &'static str,
        raw_key: impl AsRef<[u8]>,
        salt: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let raw_key = raw_key.as_ref();
        let salt = salt.as_ref().map(|x| x.as_ref());
        let symmetric_key = SymmetricKey::from_raw(prk_alg, raw_key)?;
        let mut state = SymmetricState::new(prk_alg, Some(&symmetric_key), None)?;
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
