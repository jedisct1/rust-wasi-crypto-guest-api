use crate::raw;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct Error(u16);

impl Error {
    pub fn from_raw_error(e: u16) -> Option<Self> {
        match e {
            raw::CRYPTO_ERRNO_SUCCESS => None,
            e => Some(Error(e)),
        }
    }
}
