# Packaging and Installation Guide

## Building from Source

To build the `sanctifier-cli` from source:

1. Ensure you have the latest stable Rust installed.
2. Install the `z3` theorem prover (required for SMT solving capabilities).
3. Run `cargo build --release -p sanctifier-cli`.
4. The compiled binary will be available at `target/release/sanctifier`.

## Distribution

When packaging `sanctifier` for distribution, note the following dependencies:
- Z3 must be dynamically or statically linked. For static linking, follow the `z3-sys` static compilation instructions.

## Installation via Cargo

You can install the CLI directly from crates.io (once published):
```sh
cargo install sanctifier-cli
```

## Running Backwards Compatibility Tests

We maintain backwards compatibility for standard output and flags. Run the versioning and compatibility suite via:
```sh
cargo test -p sanctifier-cli --test versioning_tests
```
