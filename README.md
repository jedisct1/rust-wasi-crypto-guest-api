# wasi-crypto guest API for Rust

This Rust crate implements low-level and high-level bindings for a [WASI cryptography API proposal](https://github.com/jedisct1/wasi-crypto-preview).

This create is not meant to be used by applications yet: the sole purpose of these bindings is to evaluate the usability of the API in different programming languages.

For more information:

- [WASI cryptography API proposal and implementation](https://github.com/jedisct1/wasi-crypto-preview) (WIP)
- [wasmtime fork supporting the proposed API](https://github.com/jedisct1/wasmtime-crypto)
- [AssemblyScript library](https://github.com/jedisct1/as-crypto) for `wasi-crypto`
