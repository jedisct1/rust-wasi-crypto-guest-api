use super::low::*;
use crate::error::*;

#[derive(Debug)]
pub struct Hash {
    state: SymmetricState,
    symmetric_key: Option<SymmetricKey>,
}

impl Hash {
    pub fn keygen(alg: &'static str) -> Result<Vec<u8>, Error> {
        let symmetric_key = SymmetricKey::generate(alg, None)?;
        symmetric_key.raw()
    }

    pub fn keyed(alg: &'static str, raw_key: impl AsRef<[u8]>) -> Result<Self, Error> {
        let raw_key = raw_key.as_ref();
        let symmetric_key = SymmetricKey::from_raw(alg, raw_key)?;
        let state = SymmetricState::new(alg, Some(&symmetric_key), None)?;
        Ok(Hash {
            state,
            symmetric_key: Some(symmetric_key),
        })
    }

    pub fn unkeyed(alg: &'static str) -> Result<Self, Error> {
        let state = SymmetricState::new(alg, None, None)?;
        Ok(Hash {
            state,
            symmetric_key: None,
        })
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
        raw_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut state = if let Some(raw_key) = raw_key {
            Hash::keyed(alg, raw_key)
        } else {
            Hash::unkeyed(alg)
        }?;
        state.absorb(data)?;
        state.squeeze(out_len)
    }
}
