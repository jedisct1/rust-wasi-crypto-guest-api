mod key_pair;
mod public_key;
mod state;
pub use key_pair::*;
pub use public_key::*;
pub use state::*;

use crate::common::*;
use crate::error::*;
use crate::raw;
use std::borrow::Cow;

#[derive(Debug)]
pub struct Signature {
    pub(crate) handle: raw::Signature,
    pub alg: Cow<'static, str>,
}

impl Drop for Signature {
    fn drop(&mut self) {
        unsafe { raw::signature_close(self.handle) }.unwrap()
    }
}

impl Signature {
    fn decode_from(
        alg: &'static str,
        encoded: impl AsRef<[u8]>,
        encoding: raw::PublickeyEncoding,
    ) -> Result<Self, Error> {
        let encoded = encoded.as_ref();
        let handle =
            unsafe { raw::signature_import(alg, encoding, encoded.as_ptr(), encoded.len()) }?;
        Ok(Signature {
            handle,
            alg: Cow::Borrowed(alg),
        })
    }

    pub fn from_raw(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::decode_from(alg, encoded, raw::SIGNATURE_ENCODING_RAW)
    }

    pub fn from_der(alg: &'static str, encoded: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::decode_from(alg, encoded, raw::SIGNATURE_ENCODING_DER)
    }

    fn encode_as(&self, encoding: raw::SignatureEncoding) -> Result<Vec<u8>, Error> {
        let array_handle = unsafe { raw::signature_export(self.handle, encoding) }?;
        ArrayOutput::new(array_handle).into_vec()
    }

    pub fn raw(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::PUBLICKEY_ENCODING_RAW)
    }

    pub fn der(&self) -> Result<Vec<u8>, Error> {
        self.encode_as(raw::PUBLICKEY_ENCODING_DER)
    }
}
