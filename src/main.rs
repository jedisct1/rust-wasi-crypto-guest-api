mod error;
mod raw;

#[derive(Debug)]
struct Options(raw::Options);

impl Options {
    fn new(alg_type: raw::AlgorithmType) -> Self {
        let handle = unsafe { raw::options_open(alg_type) }.unwrap();
        Options(handle)
    }
}

#[derive(Debug)]
struct SymmetricOptions(Options);

impl SymmetricOptions {
    pub fn new() -> Self {
        SymmetricOptions(Options::new(raw::ALGORITHM_TYPE_SYMMETRIC))
    }
}

fn main() {
    let options = SymmetricOptions::new();
}
