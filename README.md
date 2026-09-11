# Minimal Rust implementation of ML-KEM

A very small but complete reference implementation of ML-KEM.

## Build & run

Run KAT tests:
```
cargo xtask kat
```

This builds the release wrapper, installs KATWalk 0.0.15 in
`target/kat-tools`, and checks out the ACVP test vectors at a pinned commit
in `crypto-test-vectors`. Results are written to `keygen_out.json` and
`encapsDecap_out.json`.

Run benchmarks:
```
cargo bench
```

## Security
This is just reference implementation. No security guarantees.
