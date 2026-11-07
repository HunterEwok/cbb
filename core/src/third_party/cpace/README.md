# cpace

The CPace password-authenticated key exchange (cipher suite CPACE-X25519-SHA512 of
draft-irtf-cfrg-cpace-21), translated to Rust from the Go package in
[`internal/third_party/cpace`](../../../../internal/third_party/cpace), which is copied
without changes from the package `internal/cpace` of the module
[`rsc.io/cmd/mote`](https://pkg.go.dev/rsc.io/cmd/mote) v0.1.3
(module checksum `h1:sfC7Uo9LaCuSYEuMaXCA2y/M2LC4m1h8VTq/mVNO4k4=`).

The translation keeps the structure, the names (in Rust's style) and the comments of the
Go code. The field arithmetic and the Elligator 2 map are translated line by line; X25519
itself comes from the `x25519-dalek` crate, and SHA-512 and HMAC from the RustCrypto crates `sha2` and `hmac`, where the Go
code uses the standard library. The tests include the draft's test vectors, as the Go tests
do.

The code is under the BSD-style license in [LICENSE](LICENSE), not under the AGPL; each file
keeps the original copyright notice.

To update it, translate the changes of a newer version of the Go package, record the
version here, and run the tests.
