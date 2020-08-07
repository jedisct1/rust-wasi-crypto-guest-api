use super::low::*;
use crate::error::*;

pub type HashKey = SymmetricKey;
#[derive(Debug)]
pub struct Hash {
    state: SymmetricState,
}

impl Hash {
    pub fn keygen(alg: &'static str) -> Result<Vec<u8>, Error> {
        let symmetric_key = SymmetricKey::generate(alg, None)?;
        symmetric_key.raw()
    }

    pub fn keyed(alg: &'static str, key: &HashKey) -> Result<Self, Error> {
        let state = SymmetricState::new(alg, Some(key), None)?;
        Ok(Hash { state })
    }

    pub fn unkeyed(alg: &'static str) -> Result<Self, Error> {
        let state = SymmetricState::new(alg, None, None)?;
        Ok(Hash { state })
    }

    pub fn absorb(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        self.state.absorb(data)
    }

    pub fn squeeze(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        self.state.squeeze(len)
    }

    pub fn hash(
        alg: &'static str,
        data: impl AsRef<[u8]>,
        out_len: usize,
        key: Option<&HashKey>,
    ) -> Result<Vec<u8>, Error> {
        let mut state = if let Some(key) = key {
            Hash::keyed(alg, key)
        } else {
            Hash::unkeyed(alg)
        }?;
        state.absorb(data)?;
        state.squeeze(out_len)
    }
}
