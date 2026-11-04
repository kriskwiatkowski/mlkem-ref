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

## Memory placement

`ml_kem_keygen`/`encaps`/`decaps` take a `&mut Workspace` holding all the
scratch memory they need. The library never allocates: you own the
`Workspace` and decide where it lives (stack, `static`, `Box` via the
`alloc` feature, or a `heapless` pool via the `heapless` feature — see
`examples/heapless_pool.rs`).

### Measuring stack usage

`examples/stack_watermark.rs` measures the real peak stack usage of
`ml_kem_keygen`/`encaps`/`decaps` using the "stack watermark" technique:
paint the unused part of the thread's stack with a sentinel byte, run the
call, then scan for how far the sentinel got overwritten. This gives an
exact, reproducible number for what actually ran, rather than a static
per-function estimate.

```
cargo run --release --example stack_watermark --features alloc
```

Prints the measured bytes for each operation, e.g.:
```
keygen: 1368 bytes
encaps: 1384 bytes
decaps: 1391 bytes
```

(Numbers vary by platform, Rust version and ML-KEM parameter set — the
example uses ML-KEM-1024, the largest.)

## Security
This is just reference implementation. No security guarantees.
