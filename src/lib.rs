// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

//! ML-KEM (FIPS-203) Implementation
//!
//! Rust implementation of ML-KEM based on FIPS-203 standard.

#![no_std]

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
    /// use mlkem_edu::MLKEMParameters;
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
fn encode(d: usize, f: &[i32; N], out: &mut [u8]) {
    let mut bits = [false; N * 12]; // Max bits needed
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
fn decode(d: usize, b: &[u8], f: &mut [i32; N]) {
    let mut bits = [false; N * 12];
    to_bits(b, &mut bits);
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
fn sample_noise(eta: usize, b: &[u8], out: &mut [i32; 256]) {
    let mut bits = [false; N * 2 * 3]; // Max: 256 * 2 * eta (eta max = 3)
    to_bits(b, &mut bits);

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
fn prf(_eta: usize, s: &[u8], b: u8, out: &mut [u8]) {
    let mut xof = Shake256::default();
    xof.update(s);
    xof.update(&[b]);
    let mut reader = xof.finalize_xof();
    reader.read(out);
}

// Hash using SHA3-256
fn hash(s: &[u8], out: &mut [u8; 32]) {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, s);
    let result = hasher.finalize();
    out.copy_from_slice(&result);
}

// KDF using SHAKE256
fn kdf(s: &[u8], out: &mut [u8; 32]) {
    let mut xof = Shake256::default();
    Update::update(&mut xof, s);
    let mut reader = xof.finalize_xof();
    reader.read(out);
}

// Expand using SHA3-512
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
) {
    for i in 0..k {
        let mut acc = [0i32; N];
        for j in 0..k {
            let mut prod = [0i32; N];
            mul_ntt(&a[i][j], &s[j], &mut prod);
            let mut temp = [0i32; N];
            padd(&acc, &prod, &mut temp);
            acc = temp;
        }
        out[i] = acc;
    }
}

// Dot product in NTT domain
fn dot(u: &[[i32; N]; MAX_K], v: &[[i32; N]; MAX_K], k: usize, out: &mut [i32; N]) {
    let mut acc = [0i32; N];

    for i in 0..k {
        let mut prod = [0i32; N];
        mul_ntt(&u[i], &v[i], &mut prod);
        let mut temp = [0i32; N];
        padd(&acc, &prod, &mut temp);
        acc = temp;
    }

    *out = acc;
}

// Vector addition
fn vadd(u: &[[i32; 256]; MAX_K], v: &[[i32; 256]; MAX_K], k: usize, out: &mut [[i32; 256]; MAX_K]) {
    for i in 0..k {
        padd(&u[i], &v[i], &mut out[i]);
    }
}

// Algorithm 13: PKE Key Generation
pub fn pke_gen(d: &[u8], p: &MLKEMParameters, ek: &mut [u8], dk: &mut [u8]) {
    let mut input = [0u8; 33];
    input[..d.len()].copy_from_slice(d);
    input[32] = p.k as u8;

    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    expand(&input, &mut rho, &mut sigma);

    // Sample matrix A
    let mut ntt_a = [[[0i32; 256]; MAX_K]; MAX_K];
    for i in 0..p.k {
        for j in 0..p.k {
            sample_uniform(&rho, i, j, &mut ntt_a[i][j]);
        }
    }

    // Sample secret and error vectors
    let mut s = [[0i32; 256]; MAX_K];
    let mut e = [[0i32; 256]; MAX_K];
    let mut prf_out = [0u8; 64 * 3]; // Max: 64 * eta1 (eta1 max = 3)

    for i in 0..p.k {
        prf(p.eta1, &sigma, i as u8, &mut prf_out[..64 * p.eta1]);
        sample_noise(p.eta1, &prf_out[..64 * p.eta1], &mut s[i]);

        prf(p.eta1, &sigma, (p.k + i) as u8, &mut prf_out[..64 * p.eta1]);
        sample_noise(p.eta1, &prf_out[..64 * p.eta1], &mut e[i]);
    }

    // Convert to NTT domain
    let mut ntt_s = [[0i32; 256]; MAX_K];
    let mut ntt_e = [[0i32; 256]; MAX_K];
    for i in 0..p.k {
        ntt(&s[i], &mut ntt_s[i]);
        ntt(&e[i], &mut ntt_e[i]);
    }

    // Compute ntt_t = A * ntt_s + ntt_e
    let mut ntt_t = [[0i32; 256]; MAX_K];
    let mut temp = [[0i32; 256]; MAX_K];
    mat_vec(&ntt_a, &ntt_s, p.k, &mut temp);
    vadd(&temp, &ntt_e, p.k, &mut ntt_t);

    // Encode public key
    let mut offset = 0;
    for i in 0..p.k {
        encode(12, &ntt_t[i], &mut ek[offset..offset + 384]);
        offset += 384;
    }
    ek[offset..offset + 32].copy_from_slice(&rho);

    // Encode secret key
    offset = 0;
    for i in 0..p.k {
        encode(12, &ntt_s[i], &mut dk[offset..offset + 384]);
        offset += 384;
    }
}

// Algorithm 14: PKE Encryption
fn pke_enc(ek: &[u8], m: &[u8], r: &[u8], p: &MLKEMParameters, c: &mut [u8]) {
    // Parse public key
    let mut ntt_t = [[0i32; 256]; MAX_K];
    for i in 0..p.k {
        decode(12, &ek[384 * i..384 * (i + 1)], &mut ntt_t[i]);
    }
    let rho = &ek[384 * p.k..384 * p.k + 32];

    // Sample matrix A^T
    let mut ntt_a = [[[0i32; 256]; MAX_K]; MAX_K];
    for i in 0..p.k {
        for j in 0..p.k {
            sample_uniform(rho, j, i, &mut ntt_a[i][j]);
        }
    }

    // Sample vectors
    let mut y = [[0i32; 256]; MAX_K];
    let mut e1 = [[0i32; 256]; MAX_K];
    let mut prf_out = [0u8; 64 * 3];

    for i in 0..p.k {
        prf(p.eta1, r, i as u8, &mut prf_out[..64 * p.eta1]);
        sample_noise(p.eta1, &prf_out[..64 * p.eta1], &mut y[i]);

        prf(p.eta2, r, (p.k + i) as u8, &mut prf_out[..64 * p.eta2]);
        sample_noise(p.eta2, &prf_out[..64 * p.eta2], &mut e1[i]);
    }

    let mut e2 = [0i32; 256];
    prf(p.eta2, r, (2 * p.k) as u8, &mut prf_out[..64 * p.eta2]);
    sample_noise(p.eta2, &prf_out[..64 * p.eta2], &mut e2);

    // Convert y to NTT domain
    let mut ntt_y = [[0i32; 256]; MAX_K];
    for i in 0..p.k {
        ntt(&y[i], &mut ntt_y[i]);
    }

    // Compute u = NTT^-1(A^T * ntt_y) + e1
    let mut u_temp = [[0i32; 256]; MAX_K];
    mat_vec(&ntt_a, &ntt_y, p.k, &mut u_temp);

    let mut u = [[0i32; 256]; MAX_K];
    for i in 0..p.k {
        let mut temp = [0i32; 256];
        inv_ntt(&u_temp[i], &mut temp);
        padd(&temp, &e1[i], &mut u[i]);
    }

    // Decode and decompress message
    let mut mu = [0i32; 256];
    decode(1, m, &mut mu);
    for i in 0..256 {
        mu[i] = decompress(1, mu[i]);
    }

    // Compute v = NTT^-1(ntt_t^T * ntt_y) + e2 + mu
    let mut dot_result = [0i32; 256];
    dot(&ntt_t, &ntt_y, p.k, &mut dot_result);
    let mut inv_result = [0i32; 256];
    inv_ntt(&dot_result, &mut inv_result);
    let mut temp = [0i32; 256];
    padd(&inv_result, &e2, &mut temp);
    let mut v = [0i32; 256];
    padd(&temp, &mu, &mut v);

    // Compress and encode ciphertext
    let mut offset = 0;
    for i in 0..p.k {
        let mut compressed = [0i32; 256];
        for j in 0..256 {
            compressed[j] = compress(p.du, u[i][j]);
        }
        encode(p.du, &compressed, &mut c[offset..offset + 32 * p.du]);
        offset += 32 * p.du;
    }

    let mut compressed_v = [0i32; 256];
    for i in 0..256 {
        compressed_v[i] = compress(p.dv, v[i]);
    }
    encode(p.dv, &compressed_v, &mut c[offset..offset + 32 * p.dv]);
}

// Algorithm 15: PKE Decryption
fn pke_dec(dk: &[u8], c: &[u8], p: &MLKEMParameters, m: &mut [u8]) {
    let c1 = &c[..32 * p.du * p.k];
    let c2 = &c[32 * p.du * p.k..];

    // Decode and decompress u
    let mut u = [[0i32; 256]; MAX_K];
    for i in 0..p.k {
        let start = i * 32 * p.du;
        let end = (i + 1) * 32 * p.du;
        let mut decoded = [0i32; 256];
        decode(p.du, &c1[start..end], &mut decoded);
        for j in 0..256 {
            u[i][j] = decompress(p.du, decoded[j]);
        }
    }

    // Decode and decompress v
    let mut v = [0i32; 256];
    let mut decoded_v = [0i32; 256];
    decode(p.dv, c2, &mut decoded_v);
    for i in 0..256 {
        v[i] = decompress(p.dv, decoded_v[i]);
    }

    // Parse secret key
    let mut ntt_s = [[0i32; 256]; MAX_K];
    for i in 0..p.k {
        decode(12, &dk[384 * i..384 * (i + 1)], &mut ntt_s[i]);
    }

    // Convert u to NTT domain
    let mut u_hat = [[0i32; 256]; MAX_K];
    for i in 0..p.k {
        ntt(&u[i], &mut u_hat[i]);
    }

    // Compute w = v - NTT^-1(ntt_s^T * u_hat)
    let mut dot_result = [0i32; 256];
    dot(&ntt_s, &u_hat, p.k, &mut dot_result);
    let mut inv_result = [0i32; 256];
    inv_ntt(&dot_result, &mut inv_result);
    let mut w = [0i32; 256];
    psub(&v, &inv_result, &mut w);

    // Compress and encode message
    let mut compressed = [0i32; 256];
    for i in 0..256 {
        compressed[i] = compress(1, w[i]);
    }
    encode(1, &compressed, m);
}

// Algorithm 19: ML-KEM Key Generation
pub fn ml_kem_keygen(
    d: &[u8; 32],
    z: &[u8; 32],
    p: &MLKEMParameters,
    ek: &mut [u8],
    dk: &mut [u8],
) {
    let mut ek_pke = [0u8; MAX_PUBLIC_KEY_BYTES];
    let mut dk_pke = [0u8; MAX_PUBLIC_KEY_BYTES * 2];

    pke_gen(
        d,
        p,
        &mut ek_pke[..p.public_key_length],
        &mut dk_pke[..384 * p.k],
    );

    // Build ek
    ek[..p.public_key_length].copy_from_slice(&ek_pke[..p.public_key_length]);

    // Build dk
    let mut offset = 0;
    dk[offset..offset + 384 * p.k].copy_from_slice(&dk_pke[..384 * p.k]);
    offset += 384 * p.k;
    dk[offset..offset + p.public_key_length].copy_from_slice(&ek_pke[..p.public_key_length]);
    offset += p.public_key_length;

    let mut h = [0u8; 32];
    hash(&ek_pke[..p.public_key_length], &mut h);
    dk[offset..offset + 32].copy_from_slice(&h);
    offset += 32;
    dk[offset..offset + 32].copy_from_slice(z);
}

// Algorithm 20: ML-KEM Encapsulation
pub fn ml_kem_encaps(ek: &[u8], m: &[u8; 32], p: &MLKEMParameters, k: &mut [u8; 32], c: &mut [u8]) {
    let mut h_ek = [0u8; 32];
    hash(&ek[..p.public_key_length], &mut h_ek);

    let mut input = [0u8; 64];
    input[..32].copy_from_slice(m);
    input[32..].copy_from_slice(&h_ek);

    let mut k_out = [0u8; 32];
    let mut r = [0u8; 32];
    expand(&input, &mut k_out, &mut r);

    pke_enc(
        &ek[..p.public_key_length],
        m,
        &r,
        p,
        &mut c[..p.ciphertext_length],
    );
    k.copy_from_slice(&k_out);
}

// Algorithm 21: ML-KEM Decapsulation
pub fn ml_kem_decaps(dk: &[u8], c: &[u8], p: &MLKEMParameters, k: &mut [u8; 32]) {
    let dk_pke = &dk[..384 * p.k];
    let ek_pke = &dk[384 * p.k..384 * p.k + p.public_key_length];
    let h = &dk[384 * p.k + p.public_key_length..384 * p.k + p.public_key_length + 32];
    let z = &dk[384 * p.k + p.public_key_length + 32..384 * p.k + p.public_key_length + 64];

    // Decrypt
    let mut m_prime = [0u8; 32];
    pke_dec(dk_pke, &c[..p.ciphertext_length], p, &mut m_prime);

    // Re-encrypt
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&m_prime);
    input[32..].copy_from_slice(h);

    let mut k_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    expand(&input, &mut k_prime, &mut r_prime);

    let mut c_prime = [0u8; MAX_CIPHERTEXT_BYTES];
    pke_enc(
        ek_pke,
        &m_prime,
        &r_prime,
        p,
        &mut c_prime[..p.ciphertext_length],
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
        let mut input_rej = [0u8; MAX_CIPHERTEXT_BYTES + 32];
        input_rej[..32].copy_from_slice(z);
        input_rej[32..32 + p.ciphertext_length].copy_from_slice(&c[..p.ciphertext_length]);
        kdf(&input_rej[..32 + p.ciphertext_length], k);
    } else {
        k.copy_from_slice(&k_prime);
    }
}

// Validate encapsulation key (public key)
pub fn check_ek(ek: &[u8], p: &MLKEMParameters) -> bool {
    // Check exact length
    if ek.len() != p.public_key_length {
        return false;
    }

    let t_hat_bytes = &ek[..384 * p.k];

    // Decode and re-encode to check validity
    let mut ek_test = [0u8; MAX_PUBLIC_KEY_BYTES];
    for i in 0..p.k {
        let start = i * 384;
        let end = (i + 1) * 384;
        let mut decoded = [0i32; 256];
        decode(12, &t_hat_bytes[start..end], &mut decoded);
        encode(12, &decoded, &mut ek_test[start..end]);
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
