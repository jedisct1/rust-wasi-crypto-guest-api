# wasi-crypto guest API for Rust

Sample Rust bindings for a [WASI cryptography API proposal](https://github.com/jedisct1/wasi-crypto-preview).

The purpose of these bindings is to evaluate the usability of the API in different programming languages.

Executing the resulting WebAssembly file requires [a version of `wasmtime` that includes the crypto modules](https://github.com/jedisct1/wasmtime-crypto).