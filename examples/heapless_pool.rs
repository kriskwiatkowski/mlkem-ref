//! Demonstrates the built-in `heapless` object pool for `Workspace`
//! (enabled via the `heapless` feature): `Object<WorkspacePool>` instances
//! are checked out and returned (via `Drop`) like any heapless pool object,
//! backed by a single static block provisioned once at startup.
//!
//! Run with: cargo run --example heapless_pool --features heapless

use mlkem_ref::heapless_pool::{provision, WorkspacePool};
use mlkem_ref::{ml_kem_decaps, ml_kem_encaps, ml_kem_keygen, MLKEMParameters};

fn main() {
    provision();

    let p = MLKEMParameters::new("ML-KEM-1024").unwrap();
    let d = [0u8; 32];
    let z = [0u8; 32];
    let m = [0u8; 32];

    let mut ek = vec![0u8; p.public_key_length];
    let mut dk = vec![0u8; p.secret_key_length];
    {
        // Check a `Workspace` out of the pool; it's returned automatically
        // when `ws` is dropped at the end of this block.
        let mut ws = WorkspacePool.request().expect("pool is empty");
        ml_kem_keygen(&d, &z, &p, &mut ek, &mut dk, &mut ws);
    }

    let mut k_enc = [0u8; 32];
    let mut c = vec![0u8; p.ciphertext_length];
    {
        let mut ws = WorkspacePool.request().expect("pool is empty");
        ml_kem_encaps(&ek, &m, &p, &mut k_enc, &mut c, &mut ws);
    }

    let mut k_dec = [0u8; 32];
    {
        let mut ws = WorkspacePool.request().expect("pool is empty");
        ml_kem_decaps(&dk, &c, &p, &mut k_dec, &mut ws);
    }

    assert_eq!(k_enc, k_dec);
    println!("heapless pool roundtrip OK, shared secret = {:02x?}", k_enc);
}
