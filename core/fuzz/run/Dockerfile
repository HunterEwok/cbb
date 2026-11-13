# The fuzzing image: nightly Rust and cargo-fuzz, nothing else.
FROM rust:1-bookworm
RUN rustup toolchain install nightly --profile minimal \
 && cargo +nightly install cargo-fuzz --version 0.13.2 --locked
WORKDIR /work/core/fuzz
