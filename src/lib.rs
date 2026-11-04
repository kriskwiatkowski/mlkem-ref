// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

//! ML-KEM (FIPS-203) Implementation
//!
//! Rust implementation of ML-KEM based on FIPS-203 standard.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};

/// Modulus for polynomial arithmetic
const Q: i32 = 3329;
const N: usize = 256; // Polynomial degree
const ROOT: i32 = 17; // Primitive root of unity mod Q

/// Maximum k value (for ML-KEM-1024)
const MAX_K: usize = 4;

/// Maximum key/ciphertext sizes
pub const MAX_PUBLIC_KEY_BYTES: usize = 1568; // ML-KEM-1024
pub const MAX_SECRET_KEY_BYTES: usize = 3168; // ML-KEM-1024
pub const MAX_CIPHERTEXT_BYTES: usize = 1568; // ML-KEM-1024

/// ML-KEM parameter set
#[derive(Debug, Clone, Copy)]
pub struct MLKEMParameters {
    /// Parameter set name (e.g., "ML-KEM-768")
    pub name: &'static str,
    /// Defines size of the matrix (kxk)
    pub k: usize,
    pub eta1: usize,
    pub eta2: usize,
    pub du: usize,
    pub dv: usize,
    /// Public key byte length
    pub public_key_length: usize,
    /// Private key byte length
    pub secret_key_length: usize,
    /// Ciphertext byte length
    pub ciphertext_length: usize,
}

impl MLKEMParameters {
    /// Creates a new parameter set by name.
    ///
    /// # Arguments
    /// * `name` - Parameter set identifier: "ML-KEM-512", "ML-KEM-768", or "ML-KEM-1024"
    ///
    /// # Returns
    /// * `Ok:(MLKEMParameters)` - Valid parameter set
    /// * `Err(String)` - Unknown parameter set name
    ///
    /// # Example
    /// ```
    /// use mlkem_ref::MLKEMParameters;
    /// let params = MLKEMParameters::new("ML-KEM-1024").unwrap();
    /// ```

    pub fn new(name: &str) -> Result<Self, &'static str> {
        match name {
            "ML-KEM-512" => Ok(MLKEMParameters {
                name: "ML-KEM-512",
                k: 2,
                eta1: 3,
                eta2: 2,
                du: 10,
                dv: 4,
                public_key_length: 800,
                secret_key_length: 1632,
                ciphertext_length: 768,
            }),
            "ML-KEM-768" => Ok(MLKEMParameters {
                name: "ML-KEM-768",
                k: 3,
                eta1: 2,
                eta2: 2,
                du: 10,
                dv: 4,
                public_key_length: 1184,
                secret_key_length: 2400,
                ciphertext_length: 1088,
            }),
            "ML-KEM-1024" => Ok(MLKEMParameters {
                name: "ML-KEM-1024",
                k: 4,
                eta1: 2,
                eta2: 2,
                du: 11,
                dv: 5,
                public_key_length: 1568,
                secret_key_length: 3168,
                ciphertext_length: 1568,
            }),
            _ => Err("Unknown parameter set"),
        }
    }
}

// --- Workspace -------------------------------------------------------------
//
// Every polynomial/matrix-sized temporary used while generating keys,
// encapsulating or decapsulating is kept here instead of being a local stack
// variable. The caller owns a `Workspace` and decides where it lives: as a
// local on their own stack, in a `static`, behind a `Box` (with `alloc`), or
// managed by a `heapless` memory pool (e.g. `heapless::object_pool!`) backed
// by a block placed wherever they like. The library never allocates memory
// of its own; it only ever borrows the `Workspace` the caller passes in.

struct MatVecScratch {
    acc: [i32; N],
    prod: [i32; N],
    temp: [i32; N],
}

impl MatVecScratch {
    const fn new() -> Self {
        Self {
            acc: [0i32; N],
            prod: [0i32; N],
            temp: [0i32; N],
        }
    }
}

struct DotScratch {
    acc: [i32; N],
    prod: [i32; N],
    temp: [i32; N],
}

impl DotScratch {
    const fn new() -> Self {
        Self {
            acc: [0i32; N],
            prod: [0i32; N],
            temp: [0i32; N],
        }
    }
}

struct PkeGenScratch {
    input: [u8; 33],
    rho: [u8; 32],
    sigma: [u8; 32],
    ntt_a: [[[i32; N]; MAX_K]; MAX_K],
    s: [[i32; N]; MAX_K],
    e: [[i32; N]; MAX_K],
    prf_out: [u8; 64 * 3], // Max: 64 * eta1 (eta1 max = 3)
    ntt_s: [[i32; N]; MAX_K],
    ntt_e: [[i32; N]; MAX_K],
    ntt_t: [[i32; N]; MAX_K],
    temp: [[i32; N]; MAX_K],
    mv: MatVecScratch,
    bits: [bool; N * 12],
}

impl PkeGenScratch {
    const fn new() -> Self {
        Self {
            input: [0u8; 33],
            rho: [0u8; 32],
            sigma: [0u8; 32],
            ntt_a: [[[0i32; N]; MAX_K]; MAX_K],
            s: [[0i32; N]; MAX_K],
            e: [[0i32; N]; MAX_K],
            prf_out: [0u8; 64 * 3],
            ntt_s: [[0i32; N]; MAX_K],
            ntt_e: [[0i32; N]; MAX_K],
            ntt_t: [[0i32; N]; MAX_K],
            temp: [[0i32; N]; MAX_K],
            mv: MatVecScratch::new(),
            bits: [false; N * 12],
        }
    }
}

struct PkeEncScratch {
    ntt_t: [[i32; N]; MAX_K],
    ntt_a: [[[i32; N]; MAX_K]; MAX_K],
    y: [[i32; N]; MAX_K],
    e1: [[i32; N]; MAX_K],
    prf_out: [u8; 64 * 3],
    e2: [i32; N],
    ntt_y: [[i32; N]; MAX_K],
    u_temp: [[i32; N]; MAX_K],
    u: [[i32; N]; MAX_K],
    inv_tmp: [i32; N],
    mu: [i32; N],
    dot_result: [i32; N],
    inv_result: [i32; N],
    ve_temp: [i32; N],
    v: [i32; N],
    compressed: [i32; N],
    compressed_v: [i32; N],
    mv: MatVecScratch,
    dt: DotScratch,
    bits: [bool; N * 12],
}

impl PkeEncScratch {
    const fn new() -> Self {
        Self {
            ntt_t: [[0i32; N]; MAX_K],
            ntt_a: [[[0i32; N]; MAX_K]; MAX_K],
            y: [[0i32; N]; MAX_K],
            e1: [[0i32; N]; MAX_K],
            prf_out: [0u8; 64 * 3],
            e2: [0i32; N],
            ntt_y: [[0i32; N]; MAX_K],
            u_temp: [[0i32; N]; MAX_K],
            u: [[0i32; N]; MAX_K],
            inv_tmp: [0i32; N],
            mu: [0i32; N],
            dot_result: [0i32; N],
            inv_result: [0i32; N],
            ve_temp: [0i32; N],
            v: [0i32; N],
            compressed: [0i32; N],
            compressed_v: [0i32; N],
            mv: MatVecScratch::new(),
            dt: DotScratch::new(),
            bits: [false; N * 12],
        }
    }
}

struct PkeDecScratch {
    u: [[i32; N]; MAX_K],
    v: [i32; N],
    decoded_v: [i32; N],
    ntt_s: [[i32; N]; MAX_K],
    u_hat: [[i32; N]; MAX_K],
    decoded: [i32; N],
    dot_result: [i32; N],
    inv_result: [i32; N],
    w: [i32; N],
    compressed: [i32; N],
    dt: DotScratch,
    bits: [bool; N * 12],
}

impl PkeDecScratch {
    const fn new() -> Self {
        Self {
            u: [[0i32; N]; MAX_K],
            v: [0i32; N],
            decoded_v: [0i32; N],
            ntt_s: [[0i32; N]; MAX_K],
            u_hat: [[0i32; N]; MAX_K],
            decoded: [0i32; N],
            dot_result: [0i32; N],
            inv_result: [0i32; N],
            w: [0i32; N],
            compressed: [0i32; N],
            dt: DotScratch::new(),
            bits: [false; N * 12],
        }
    }
}

struct KeygenScratch {
    ek_pke: [u8; MAX_PUBLIC_KEY_BYTES],
    dk_pke: [u8; MAX_PUBLIC_KEY_BYTES * 2],
    h: [u8; 32],
}

impl KeygenScratch {
    const fn new() -> Self {
        Self {
            ek_pke: [0u8; MAX_PUBLIC_KEY_BYTES],
            dk_pke: [0u8; MAX_PUBLIC_KEY_BYTES * 2],
            h: [0u8; 32],
        }
    }
}

struct EncapsScratch {
    h_ek: [u8; 32],
    input: [u8; 64],
    k_out: [u8; 32],
    r: [u8; 32],
}

impl EncapsScratch {
    const fn new() -> Self {
        Self {
            h_ek: [0u8; 32],
            input: [0u8; 64],
            k_out: [0u8; 32],
            r: [0u8; 32],
        }
    }
}

struct DecapsScratch {
    m_prime: [u8; 32],
    input: [u8; 64],
    k_prime: [u8; 32],
    r_prime: [u8; 32],
    c_prime: [u8; MAX_CIPHERTEXT_BYTES],
    input_rej: [u8; MAX_CIPHERTEXT_BYTES + 32],
}

impl DecapsScratch {
    const fn new() -> Self {
        Self {
            m_prime: [0u8; 32],
            input: [0u8; 64],
            k_prime: [0u8; 32],
            r_prime: [0u8; 32],
            c_prime: [0u8; MAX_CIPHERTEXT_BYTES],
            input_rej: [0u8; MAX_CIPHERTEXT_BYTES + 32],
        }
    }
}

struct CheckEkScratch {
    ek_test: [u8; MAX_PUBLIC_KEY_BYTES],
    decoded: [i32; N],
    bits: [bool; N * 12],
}

impl CheckEkScratch {
    const fn new() -> Self {
        Self {
            ek_test: [0u8; MAX_PUBLIC_KEY_BYTES],
            decoded: [0i32; N],
            bits: [false; N * 12],
        }
    }
}

/// All scratch memory needed by [`ml_kem_keygen`], [`ml_kem_encaps`],
/// [`ml_kem_decaps`] and [`check_ek`]. Construct one with [`Workspace::new`]
/// and place it wherever you want (stack, `static`, `Box`, a `heapless`
/// memory pool, ...), then pass `&mut` it to those functions.
pub struct Workspace {
    keygen: KeygenScratch,
    pgen: PkeGenScratch,
    encaps: EncapsScratch,
    penc: PkeEncScratch,
    decaps: DecapsScratch,
    pdec: PkeDecScratch,
    cek: CheckEkScratch,
}

impl Workspace {
    /// Creates a new, zeroed workspace.
    pub const fn new() -> Self {
        Self {
            keygen: KeygenScratch::new(),
            pgen: PkeGenScratch::new(),
            encaps: EncapsScratch::new(),
            penc: PkeEncScratch::new(),
            decaps: DecapsScratch::new(),
            pdec: PkeDecScratch::new(),
            cek: CheckEkScratch::new(),
        }
    }
}

impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl Workspace {
    /// Allocates a zeroed `Workspace` directly on the heap.
    ///
    /// Unlike `Box::new(Workspace::new())`, this never materializes the
    /// (large) `Workspace` value on the caller's stack: the heap allocation
    /// is zeroed in place.
    pub fn new_boxed() -> alloc::boxed::Box<Self> {
        // SAFETY: every field of `Workspace` is a plain integer array, so
        // the all-zero bit pattern produced by `new_zeroed` is a valid
        // value of the type, and is exactly what `Workspace::new` builds.
        unsafe { alloc::boxed::Box::<Self>::new_zeroed().assume_init() }
    }
}

/// A ready-made `heapless` object pool for [`Workspace`], available when the
/// `heapless` feature is enabled.
///
/// This covers the common case of a single statically-allocated `Workspace`
/// checked out and returned (via `Drop`) as needed. For more control (e.g.
/// multiple blocks for concurrent use), use `heapless::object_pool!` directly
/// with your own `'static` block(s), as shown in this crate's
/// `examples/heapless_pool.rs`.
#[cfg(feature = "heapless")]
pub mod heapless_pool {
    use crate::Workspace;
    use core::ptr::addr_of_mut;
    use heapless::pool::object::ObjectBlock;

    heapless::object_pool!(WorkspacePool: Workspace);

    /// Gives [`WorkspacePool`] its one statically-allocated [`Workspace`]
    /// block. Call this once, before the first `WorkspacePool.request()`.
    pub fn provision() {
        static mut BLOCK: ObjectBlock<Workspace> = ObjectBlock::new(Workspace::new());
        // SAFETY: `BLOCK` is only ever referenced here, and `provision` is
        // meant to be called once, so nothing else can be aliasing it.
        let block = unsafe { addr_of_mut!(BLOCK).as_mut().unwrap() };
        WorkspacePool.manage(block);
    }
}

// Helpers
fn modq(x: i32, modulus: i32) -> i32 {
    let r = x % modulus;
    if r < 0 {
        r + modulus
    } else {
        r
    }
}

fn modq64(x: i64, modulus: i32) -> i32 {
    let r = (x % (modulus as i64)) as i32;
    if r < 0 {
        r + modulus
    } else {
        r
    }
}

fn pow_mod(mut base: u64, mut exp: u64, modu: u64) -> u64 {
    base %= modu;
    let mut result: u64 = 1;

    while exp > 0 {
        if (exp & 1) == 1 {
            result = (result * base) % modu;
        }
        base = (base * base) % modu;
        exp >>= 1;
    }
    result
}

// 8-bit reversal for indices 0..255
fn bitrev(k: usize) -> usize {
    let mut result = 0usize;
    for i in 0..7 {
        if (k & (1 << i)) != 0 {
            result |= 1 << (6 - i);
        }
    }
    result
}

fn calc_zeta(exp: usize) -> i32 {
    pow_mod(ROOT as u64, exp as u64, Q as u64) as i32
}

// zeta(k) = ROOT^(bitrev(k)) mod Q
fn zeta(k: usize) -> i32 {
    calc_zeta(bitrev(k))
}

// zeta2(k) = ROOT^(2*bitrev(k) + 1) mod Q  (odd exponents)
fn zeta2(k: usize) -> i32 {
    let r = bitrev(k);
    calc_zeta(2 * r + 1)
}

// Algorithm 3: Convert bits to bytes (LSB first)
fn to_bytes(bits: &[bool], result: &mut [u8]) {
    for (i, chunk) in bits.chunks(8).enumerate() {
        if i >= result.len() {
            break;
        }
        let mut byte = 0u8;
        for (j, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << j;
            }
        }
        result[i] = byte;
    }
}

// Algorithm 4: Convert bytes to bits (LSB first)
fn to_bits(b: &[u8], bits: &mut [bool]) {
    let mut idx = 0;
    for byte in b {
        for j in 0..8 {
            if idx < bits.len() {
                bits[idx] = (byte >> j) & 1 == 1;
                idx += 1;
            }
        }
    }
}

// Algorithm 5: Encode polynomial coefficients into bytes
fn encode(d: usize, f: &[i32; N], out: &mut [u8], bits: &mut [bool; N * 12]) {
    let mut bit_idx = 0;

    for &val in f.iter() {
        let mut a = val;
        for _ in 0..d {
            if bit_idx < bits.len() {
                bits[bit_idx] = (a & 1) == 1;
                bit_idx += 1;
                a >>= 1;
            }
        }
    }

    to_bytes(&bits[..bit_idx], out);
}

// Algorithm 6: Decode bytes into polynomial coefficients
fn decode(d: usize, b: &[u8], f: &mut [i32; N], bits: &mut [bool; N * 12]) {
    to_bits(b, bits);
    let m = if d == 12 { Q } else { 1 << d };

    for i in 0..N {
        let mut val = 0i32;
        for j in 0..d {
            if bits[i * d + j] {
                val |= 1 << j;
            }
        }
        f[i] = val % m;
    }
}

// Algorithm 7: Sample uniform polynomial from seed
#[inline(never)]
fn sample_uniform(rho: &[u8], i: usize, j: usize, out: &mut [i32; N]) {
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[j as u8, i as u8]);
    let mut reader = xof.finalize_xof();

    let mut count = 0;
    let mut buf = [0u8; 3];

    while count < N {
        reader.read(&mut buf);

        let d1 = (buf[0] as i32) | (((buf[1] as i32) & 0x0F) << 8);
        let d2 = ((buf[1] as i32) >> 4) | ((buf[2] as i32) << 4);

        if d1 < Q {
            out[count] = d1;
            count += 1;
        }
        if d2 < Q && count < N {
            out[count] = d2;
            count += 1;
        }
    }
}

// Algorithm 8: Sample noise polynomial from centered binomial distribution
#[inline(never)]
fn sample_noise(eta: usize, b: &[u8], out: &mut [i32; 256], bits: &mut [bool; N * 12]) {
    to_bits(b, bits);

    for i in 0..N {
        let mut x = 0;
        let mut y = 0;

        for j in 0..eta {
            if bits[2 * i * eta + j] {
                x += 1;
            }
            if bits[2 * i * eta + eta + j] {
                y += 1;
            }
        }

        out[i] = modq(x - y, Q);
    }
}

// Algorithm 9: Forward NTT
fn ntt(f: &[i32; N], out: &mut [i32; N]) {
    out.copy_from_slice(f);
    let mut k = 1;
    let mut length = 128;

    while length >= 2 {
        let mut start = 0;
        while start < N {
            let z = zeta(k);
            k += 1;

            for j in start..start + length {
                let t = modq64((z as i64) * (out[j + length] as i64), Q);
                out[j + length] = modq(out[j] - t, Q);
                out[j] = modq(out[j] + t, Q);
            }

            start += 2 * length;
        }
        length /= 2;
    }
}

// Algorithm 10: Inverse NTT
fn inv_ntt(ntt_f: &[i32; N], out: &mut [i32; N]) {
    out.copy_from_slice(ntt_f);
    let mut k = 127;
    let mut length = 2;

    while length <= N / 2 {
        let mut start = 0;
        while start < N {
            let z = zeta(k);
            k -= 1;

            for j in start..start + length {
                let t = out[j];
                out[j] = modq(t + out[j + length], Q);
                out[j + length] = modq64((z as i64) * ((out[j + length] - t) as i64), Q);
            }

            start += 2 * length;
        }
        length *= 2;
    }

    for val in out.iter_mut() {
        *val = modq64((*val as i64) * 3303, Q);
    }
}

// Algorithm 11: Multiply two polynomials in NTT domain
fn mul_ntt(ntt_f: &[i32; N], ntt_g: &[i32; N], out: &mut [i32; N]) {
    for i in 0..(N / 2) {
        let a0 = ntt_f[2 * i] as i64;
        let a1 = ntt_f[2 * i + 1] as i64;
        let b0 = ntt_g[2 * i] as i64;
        let b1 = ntt_g[2 * i + 1] as i64;
        let gamma = zeta2(i) as i64;

        let c0 = modq64(a0 * b0 + a1 * b1 * gamma, Q);
        let c1 = modq64(a0 * b1 + a1 * b0, Q);

        out[2 * i] = c0;
        out[2 * i + 1] = c1;
    }
}

fn compress(d: usize, x: i32) -> i32 {
    (((x << d) + Q / 2) / Q) % (1 << d)
}

fn decompress(d: usize, y: i32) -> i32 {
    ((y * Q + (1 << (d - 1))) >> d) % Q
}

// PRF using SHAKE256
#[inline(never)]
fn prf(_eta: usize, s: &[u8], b: u8, out: &mut [u8]) {
    let mut xof = Shake256::default();
    xof.update(s);
    xof.update(&[b]);
    let mut reader = xof.finalize_xof();
    reader.read(out);
}

// Hash using SHA3-256
#[inline(never)]
fn hash(s: &[u8], out: &mut [u8; 32]) {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, s);
    let result = hasher.finalize();
    out.copy_from_slice(&result);
}

// KDF using SHAKE256
#[inline(never)]
fn kdf(s: &[u8], out: &mut [u8; 32]) {
    let mut xof = Shake256::default();
    Update::update(&mut xof, s);
    let mut reader = xof.finalize_xof();
    reader.read(out);
}

// Expand using SHA3-512
#[inline(never)]
fn expand(s: &[u8], out1: &mut [u8; 32], out2: &mut [u8; 32]) {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, s);
    let digest = hasher.finalize();
    out1.copy_from_slice(&digest[..32]);
    out2.copy_from_slice(&digest[32..]);
}

fn padd(u: &[i32; N], v: &[i32; N], out: &mut [i32; N]) {
    for i in 0..N {
        out[i] = modq(u[i] + v[i], Q);
    }
}

fn psub(u: &[i32; N], v: &[i32; N], out: &mut [i32; N]) {
    for i in 0..N {
        out[i] = modq(u[i] - v[i], Q);
    }
}

// Matrix-vector multiplication in NTT domain
fn mat_vec(
    a: &[[[i32; N]; MAX_K]; MAX_K],
    s: &[[i32; N]; MAX_K],
    k: usize,
    out: &mut [[i32; N]; MAX_K],
    sc: &mut MatVecScratch,
) {
    let MatVecScratch { acc, prod, temp } = sc;
    for i in 0..k {
        *acc = [0i32; N];
        for j in 0..k {
            mul_ntt(&a[i][j], &s[j], prod);
            padd(acc, prod, temp);
            *acc = *temp;
        }
        out[i] = *acc;
    }
}

// Dot product in NTT domain
fn dot(
    u: &[[i32; N]; MAX_K],
    v: &[[i32; N]; MAX_K],
    k: usize,
    out: &mut [i32; N],
    sc: &mut DotScratch,
) {
    let DotScratch { acc, prod, temp } = sc;
    *acc = [0i32; N];

    for i in 0..k {
        mul_ntt(&u[i], &v[i], prod);
        padd(acc, prod, temp);
        *acc = *temp;
    }

    *out = *acc;
}

// Vector addition
fn vadd(u: &[[i32; 256]; MAX_K], v: &[[i32; 256]; MAX_K], k: usize, out: &mut [[i32; 256]; MAX_K]) {
    for i in 0..k {
        padd(&u[i], &v[i], &mut out[i]);
    }
}

// Algorithm 13: PKE Key Generation
fn pke_gen(d: &[u8], p: &MLKEMParameters, ek: &mut [u8], dk: &mut [u8], sc: &mut PkeGenScratch) {
    let PkeGenScratch {
        input,
        rho,
        sigma,
        ntt_a,
        s,
        e,
        prf_out,
        ntt_s,
        ntt_e,
        ntt_t,
        temp,
        mv,
        bits,
    } = sc;

    input[..d.len()].copy_from_slice(d);
    input[32] = p.k as u8;

    expand(&input[..], rho, sigma);

    // Sample matrix A
    for i in 0..p.k {
        for j in 0..p.k {
            sample_uniform(&rho[..], i, j, &mut ntt_a[i][j]);
        }
    }

    // Sample secret and error vectors
    for i in 0..p.k {
        prf(p.eta1, &sigma[..], i as u8, &mut prf_out[..64 * p.eta1]);
        sample_noise(p.eta1, &prf_out[..64 * p.eta1], &mut s[i], bits);

        prf(
            p.eta1,
            &sigma[..],
            (p.k + i) as u8,
            &mut prf_out[..64 * p.eta1],
        );
        sample_noise(p.eta1, &prf_out[..64 * p.eta1], &mut e[i], bits);
    }

    // Convert to NTT domain
    for i in 0..p.k {
        ntt(&s[i], &mut ntt_s[i]);
        ntt(&e[i], &mut ntt_e[i]);
    }

    // Compute ntt_t = A * ntt_s + ntt_e
    mat_vec(ntt_a, ntt_s, p.k, temp, mv);
    vadd(temp, ntt_e, p.k, ntt_t);

    // Encode public key
    let mut offset = 0;
    for i in 0..p.k {
        encode(12, &ntt_t[i], &mut ek[offset..offset + 384], bits);
        offset += 384;
    }
    ek[offset..offset + 32].copy_from_slice(&rho[..]);

    // Encode secret key
    offset = 0;
    for i in 0..p.k {
        encode(12, &ntt_s[i], &mut dk[offset..offset + 384], bits);
        offset += 384;
    }
}

// Algorithm 14: PKE Encryption
fn pke_enc(ek: &[u8], m: &[u8], r: &[u8], p: &MLKEMParameters, c: &mut [u8], sc: &mut PkeEncScratch) {
    let PkeEncScratch {
        ntt_t,
        ntt_a,
        y,
        e1,
        prf_out,
        e2,
        ntt_y,
        u_temp,
        u,
        inv_tmp,
        mu,
        dot_result,
        inv_result,
        ve_temp,
        v,
        compressed,
        compressed_v,
        mv,
        dt,
        bits,
    } = sc;

    // Parse public key
    for i in 0..p.k {
        decode(12, &ek[384 * i..384 * (i + 1)], &mut ntt_t[i], bits);
    }
    let rho = &ek[384 * p.k..384 * p.k + 32];

    // Sample matrix A^T
    for i in 0..p.k {
        for j in 0..p.k {
            sample_uniform(rho, j, i, &mut ntt_a[i][j]);
        }
    }

    // Sample vectors
    for i in 0..p.k {
        prf(p.eta1, r, i as u8, &mut prf_out[..64 * p.eta1]);
        sample_noise(p.eta1, &prf_out[..64 * p.eta1], &mut y[i], bits);

        prf(p.eta2, r, (p.k + i) as u8, &mut prf_out[..64 * p.eta2]);
        sample_noise(p.eta2, &prf_out[..64 * p.eta2], &mut e1[i], bits);
    }

    prf(p.eta2, r, (2 * p.k) as u8, &mut prf_out[..64 * p.eta2]);
    sample_noise(p.eta2, &prf_out[..64 * p.eta2], e2, bits);

    // Convert y to NTT domain
    for i in 0..p.k {
        ntt(&y[i], &mut ntt_y[i]);
    }

    // Compute u = NTT^-1(A^T * ntt_y) + e1
    mat_vec(ntt_a, ntt_y, p.k, u_temp, mv);

    for i in 0..p.k {
        inv_ntt(&u_temp[i], inv_tmp);
        padd(inv_tmp, &e1[i], &mut u[i]);
    }

    // Decode and decompress message
    decode(1, m, mu, bits);
    for i in 0..256 {
        mu[i] = decompress(1, mu[i]);
    }

    // Compute v = NTT^-1(ntt_t^T * ntt_y) + e2 + mu
    dot(ntt_t, ntt_y, p.k, dot_result, dt);
    inv_ntt(dot_result, inv_result);
    padd(inv_result, e2, ve_temp);
    padd(ve_temp, mu, v);

    // Compress and encode ciphertext
    let mut offset = 0;
    for i in 0..p.k {
        for j in 0..256 {
            compressed[j] = compress(p.du, u[i][j]);
        }
        encode(p.du, compressed, &mut c[offset..offset + 32 * p.du], bits);
        offset += 32 * p.du;
    }

    for i in 0..256 {
        compressed_v[i] = compress(p.dv, v[i]);
    }
    encode(p.dv, compressed_v, &mut c[offset..offset + 32 * p.dv], bits);
}

// Algorithm 15: PKE Decryption
fn pke_dec(dk: &[u8], c: &[u8], p: &MLKEMParameters, m: &mut [u8], sc: &mut PkeDecScratch) {
    let PkeDecScratch {
        u,
        v,
        decoded_v,
        ntt_s,
        u_hat,
        decoded,
        dot_result,
        inv_result,
        w,
        compressed,
        dt,
        bits,
    } = sc;

    let c1 = &c[..32 * p.du * p.k];
    let c2 = &c[32 * p.du * p.k..];

    // Decode and decompress u
    for i in 0..p.k {
        let start = i * 32 * p.du;
        let end = (i + 1) * 32 * p.du;
        decode(p.du, &c1[start..end], decoded, bits);
        for j in 0..256 {
            u[i][j] = decompress(p.du, decoded[j]);
        }
    }

    // Decode and decompress v
    decode(p.dv, c2, decoded_v, bits);
    for i in 0..256 {
        v[i] = decompress(p.dv, decoded_v[i]);
    }

    // Parse secret key
    for i in 0..p.k {
        decode(12, &dk[384 * i..384 * (i + 1)], &mut ntt_s[i], bits);
    }

    // Convert u to NTT domain
    for i in 0..p.k {
        ntt(&u[i], &mut u_hat[i]);
    }

    // Compute w = v - NTT^-1(ntt_s^T * u_hat)
    dot(ntt_s, u_hat, p.k, dot_result, dt);
    inv_ntt(dot_result, inv_result);
    psub(v, inv_result, w);

    // Compress and encode message
    for i in 0..256 {
        compressed[i] = compress(1, w[i]);
    }
    encode(1, compressed, m, bits);
}

// Algorithm 19: ML-KEM Key Generation
pub fn ml_kem_keygen(
    d: &[u8; 32],
    z: &[u8; 32],
    p: &MLKEMParameters,
    ek: &mut [u8],
    dk: &mut [u8],
    ws: &mut Workspace,
) {
    let Workspace { keygen, pgen, .. } = ws;
    let KeygenScratch { ek_pke, dk_pke, h } = keygen;

    pke_gen(
        &d[..],
        p,
        &mut ek_pke[..p.public_key_length],
        &mut dk_pke[..384 * p.k],
        pgen,
    );

    // Build ek
    ek[..p.public_key_length].copy_from_slice(&ek_pke[..p.public_key_length]);

    // Build dk
    let mut offset = 0;
    dk[offset..offset + 384 * p.k].copy_from_slice(&dk_pke[..384 * p.k]);
    offset += 384 * p.k;
    dk[offset..offset + p.public_key_length].copy_from_slice(&ek_pke[..p.public_key_length]);
    offset += p.public_key_length;

    hash(&ek_pke[..p.public_key_length], h);
    dk[offset..offset + 32].copy_from_slice(&h[..]);
    offset += 32;
    dk[offset..offset + 32].copy_from_slice(z);
}

// Algorithm 20: ML-KEM Encapsulation
pub fn ml_kem_encaps(
    ek: &[u8],
    m: &[u8; 32],
    p: &MLKEMParameters,
    k: &mut [u8; 32],
    c: &mut [u8],
    ws: &mut Workspace,
) {
    let Workspace { encaps, penc, .. } = ws;
    let EncapsScratch {
        h_ek,
        input,
        k_out,
        r,
    } = encaps;

    hash(&ek[..p.public_key_length], h_ek);

    input[..32].copy_from_slice(m);
    input[32..].copy_from_slice(&h_ek[..]);

    expand(&input[..], k_out, r);

    pke_enc(
        &ek[..p.public_key_length],
        &m[..],
        &r[..],
        p,
        &mut c[..p.ciphertext_length],
        penc,
    );
    k.copy_from_slice(&k_out[..]);
}

// Algorithm 21: ML-KEM Decapsulation
pub fn ml_kem_decaps(dk: &[u8], c: &[u8], p: &MLKEMParameters, k: &mut [u8; 32], ws: &mut Workspace) {
    let Workspace {
        decaps,
        pdec,
        penc,
        ..
    } = ws;
    let DecapsScratch {
        m_prime,
        input,
        k_prime,
        r_prime,
        c_prime,
        input_rej,
    } = decaps;

    let dk_pke = &dk[..384 * p.k];
    let ek_pke = &dk[384 * p.k..384 * p.k + p.public_key_length];
    let h = &dk[384 * p.k + p.public_key_length..384 * p.k + p.public_key_length + 32];
    let z = &dk[384 * p.k + p.public_key_length + 32..384 * p.k + p.public_key_length + 64];

    // Decrypt
    pke_dec(dk_pke, &c[..p.ciphertext_length], p, m_prime, pdec);

    // Re-encrypt
    input[..32].copy_from_slice(&m_prime[..]);
    input[32..].copy_from_slice(h);

    expand(&input[..], k_prime, r_prime);

    pke_enc(
        ek_pke,
        &m_prime[..],
        &r_prime[..],
        p,
        &mut c_prime[..p.ciphertext_length],
        penc,
    );

    // Implicit rejection
    let mut match_ct = true;
    for i in 0..p.ciphertext_length {
        if c[i] != c_prime[i] {
            match_ct = false;
            break;
        }
    }

    if !match_ct {
        input_rej[..32].copy_from_slice(z);
        input_rej[32..32 + p.ciphertext_length].copy_from_slice(&c[..p.ciphertext_length]);
        kdf(&input_rej[..32 + p.ciphertext_length], k);
    } else {
        k.copy_from_slice(&k_prime[..]);
    }
}

// Validate encapsulation key (public key)
pub fn check_ek(ek: &[u8], p: &MLKEMParameters, ws: &mut Workspace) -> bool {
    // Check exact length
    if ek.len() != p.public_key_length {
        return false;
    }

    let t_hat_bytes = &ek[..384 * p.k];

    let CheckEkScratch {
        ek_test,
        decoded,
        bits,
    } = &mut ws.cek;

    // Decode and re-encode to check validity
    for i in 0..p.k {
        let start = i * 384;
        let end = (i + 1) * 384;
        decode(12, &t_hat_bytes[start..end], decoded, bits);
        encode(12, decoded, &mut ek_test[start..end], bits);
    }

    // Compare
    for i in 0..384 * p.k {
        if t_hat_bytes[i] != ek_test[i] {
            return false;
        }
    }
    true
}

// Validate decapsulation key (secret key)
pub fn check_dk(dk: &[u8], p: &MLKEMParameters) -> bool {
    // Check exact length
    if dk.len() != p.secret_key_length {
        return false;
    }

    let ek_pke = &dk[384 * p.k..768 * p.k + 32];
    let h_stored = &dk[768 * p.k + 32..768 * p.k + 64];

    let mut h_computed = [0u8; 32];
    hash(ek_pke, &mut h_computed);

    // Compare
    for i in 0..32 {
        if h_stored[i] != h_computed[i] {
            return false;
        }
    }
    true
}

