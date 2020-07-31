use super::low::*;
use crate::error::*;

#[derive(Debug)]
pub struct Auth {
    state: SymmetricState,
    symmetric_key: Option<SymmetricKey>,
}

impl Auth {
    pub fn keygen(alg: &'static str) -> Result<Vec<u8>, Error> {
        let symmetric_key = SymmetricKey::generate(alg, None)?;
        symmetric_key.raw()
    }

    pub fn new(alg: &'static str, raw_key: impl AsRef<[u8]>) -> Result<Self, Error> {
        let raw_key = raw_key.as_ref();
        let symmetric_key = SymmetricKey::from_raw(alg, raw_key)?;
        let state = SymmetricState::new(alg, Some(&symmetric_key), None)?;
        Ok(Auth {
            state,
            symmetric_key: Some(symmetric_key),
        })
    }

    pub fn absorb(&mut self, data: impl AsRef<[u8]>) -> Result<(), Error> {
        self.state.absorb(data)
    }

    pub fn tag(&mut self) -> Result<Vec<u8>, Error> {
        self.state.squeeze_tag()
    }

    pub fn tag_verify(&mut self, raw_tag: impl AsRef<[u8]>) -> Result<(), Error> {
        self.state.verify(raw_tag)
    }

    pub fn auth(
        alg: &'static str,
        data: impl AsRef<[u8]>,
        raw_key: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut state = Auth::new(alg, raw_key)?;
        state.absorb(data)?;
        state.tag()
    }

    pub fn auth_verify(
        alg: &'static str,
        data: impl AsRef<[u8]>,
        raw_key: impl AsRef<[u8]>,
        raw_tag: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut state = Auth::new(alg, raw_key)?;
        state.absorb(data)?;
        state.tag_verify(raw_tag)
    }
}
