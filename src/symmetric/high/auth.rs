use super::low::*;
use crate::error::*;

pub type AuthKey = SymmetricKey;

#[derive(Debug)]
pub struct Auth {
    state: SymmetricState,
}

impl Auth {
    pub fn keygen(alg: &'static str) -> Result<AuthKey, Error> {
        SymmetricKey::generate(alg, None)
    }

    pub fn new(alg: &'static str, key: &AuthKey) -> Result<Self, Error> {
        let state = SymmetricState::new(alg, Some(&key), None)?;
        Ok(Auth { state })
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
        key: &AuthKey,
    ) -> Result<Vec<u8>, Error> {
        let mut state = Auth::new(alg, key)?;
        state.absorb(data)?;
        state.tag()
    }

    pub fn auth_verify(
        alg: &'static str,
        data: impl AsRef<[u8]>,
        key: &AuthKey,
        raw_tag: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let mut state = Auth::new(alg, key)?;
        state.absorb(data)?;
        state.tag_verify(raw_tag)
    }
}
