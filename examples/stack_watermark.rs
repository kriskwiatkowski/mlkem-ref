//! Measures the real peak stack usage of `ml_kem_keygen`/`encaps`/`decaps`
//! using the "stack watermark" (a.k.a. stack painting) technique:
//!
//! 1. Find the real bounds of this thread's stack via `pthread_getattr_np`.
//! 2. Paint the currently-unused region below the stack pointer with a
//!    sentinel byte (nothing has touched that memory yet, so it's safe to
//!    overwrite).
//! 3. Call the function being measured. Since x86-64 stacks grow downward,
//!    every frame it (and anything it calls) pushes overwrites some of the
//!    sentinel with real data.
//! 4. Scan from the bottom of the stack upward for the lowest address that's
//!    no longer the sentinel value — that's the deepest point the stack
//!    pointer reached. The distance from that point back up to where the
//!    call started is exactly how many bytes of stack the call used.
//!
//! This gives an exact, reproducible number for whatever path actually
//! executed, unlike a static per-function frame-size analysis (which
//! overcounts dead branches and can't see real call-chain depth) or
//! binary-searching a thread's requested stack size (which is limited by
//! the OS/libc's own minimum stack size and page-granularity rounding).
//!
//! Run with: cargo run --release --example stack_watermark --features alloc

use mlkem_ref::{ml_kem_decaps, ml_kem_encaps, ml_kem_keygen, MLKEMParameters, Workspace};
use std::os::raw::{c_int, c_void};

#[repr(C, align(16))]
struct PthreadAttr([u8; 128]);

extern "C" {
    fn pthread_self() -> usize;
    fn pthread_getattr_np(thread: usize, attr: *mut PthreadAttr) -> c_int;
    fn pthread_attr_getstack(
        attr: *const PthreadAttr,
        addr: *mut *mut c_void,
        size: *mut usize,
    ) -> c_int;
    fn pthread_attr_destroy(attr: *mut PthreadAttr) -> c_int;
}

const SENTINEL: u8 = 0xAA;

/// How far below the current stack pointer to leave unpainted, so the
/// painting routine itself (and its own small stack frame) can't clobber
/// memory it still needs while writing.
const SAFETY_MARGIN: usize = 32;

struct PaintedRegion {
    base_addr: usize,
    fill_top: usize,
    fill_len: usize,
}

/// Finds this thread's stack bounds and paints everything below the current
/// stack pointer (minus [`SAFETY_MARGIN`]) with [`SENTINEL`].
///
/// Deliberately does *not* hand back a "stack pointer before the call"
/// reference: capturing that here, inside a helper, would record a point
/// one call *deeper* than where the measured call actually starts (this
/// function's own frame, including the 128-byte `PthreadAttr` buffer, would
/// already have been popped by the time the real call happens), silently
/// under-reporting usage by exactly that helper's frame size. The caller
/// must take that reference itself, in its own frame, immediately before
/// the measured call — see [`watermark_scan`] and its use in `main`.
///
/// # Safety
/// Must be called on a thread whose stack was obtained normally (true for
/// `main` and any `std::thread` thread), and the returned region must not
/// be read or written by anything other than the single call being measured
/// before [`watermark_scan`] is called.
unsafe fn watermark_paint() -> PaintedRegion {
    let mut attr = PthreadAttr([0u8; 128]);
    assert_eq!(pthread_getattr_np(pthread_self(), &mut attr), 0);
    let mut base: *mut c_void = std::ptr::null_mut();
    let mut size: usize = 0;
    assert_eq!(pthread_attr_getstack(&attr, &mut base, &mut size), 0);
    pthread_attr_destroy(&mut attr);
    let base = base as *mut u8;
    let base_addr = base as usize;

    let sp_marker: u8 = 0;
    let sp_now = &sp_marker as *const u8 as usize;
    let fill_top = sp_now.saturating_sub(SAFETY_MARGIN);
    assert!(
        fill_top > base_addr,
        "fill region invalid: base={base_addr:#x} top={fill_top:#x}"
    );
    let fill_len = fill_top - base_addr;
    std::ptr::write_bytes(base, SENTINEL, fill_len);

    PaintedRegion {
        base_addr,
        fill_top,
        fill_len,
    }
}

/// Scans the painted region for the high-water mark and returns the number
/// of bytes of stack used between `sp_pre_call` (the stack pointer at the
/// start of the measured call, as taken by the caller — see [`watermark_paint`])
/// and the deepest point reached.
///
/// # Safety
/// Must be paired with a preceding [`watermark_paint`] call whose painted
/// region is still intact (nothing but the measured call touched it).
unsafe fn watermark_scan(r: &PaintedRegion, sp_pre_call: usize) -> usize {
    let region = std::slice::from_raw_parts(r.base_addr as *const u8, r.fill_len);
    let mut touched_base = r.fill_top;
    for (i, &b) in region.iter().enumerate() {
        if b != SENTINEL {
            touched_base = r.base_addr + i;
            break;
        }
    }
    sp_pre_call.saturating_sub(touched_base)
}

#[inline(never)]
fn run_keygen(ws: &mut Workspace, p: &MLKEMParameters, ek: &mut [u8], dk: &mut [u8]) {
    let d = [0u8; 32];
    let z = [0u8; 32];
    ml_kem_keygen(
        std::hint::black_box(&d),
        std::hint::black_box(&z),
        std::hint::black_box(p),
        ek,
        dk,
        ws,
    );
}

#[inline(never)]
fn run_encaps(
    ws: &mut Workspace,
    p: &MLKEMParameters,
    ek: &[u8],
    k: &mut [u8; 32],
    c: &mut [u8],
) {
    let m = [0u8; 32];
    ml_kem_encaps(
        std::hint::black_box(ek),
        std::hint::black_box(&m),
        std::hint::black_box(p),
        k,
        c,
        ws,
    );
}

#[inline(never)]
fn run_decaps(ws: &mut Workspace, p: &MLKEMParameters, dk: &[u8], c: &[u8], k: &mut [u8; 32]) {
    ml_kem_decaps(
        std::hint::black_box(dk),
        std::hint::black_box(c),
        std::hint::black_box(p),
        k,
        ws,
    );
}

fn main() {
    let p = MLKEMParameters::new("ML-KEM-1024").unwrap();
    let mut ws = Workspace::new_boxed();

    let mut ek = vec![0u8; p.public_key_length];
    let mut dk = vec![0u8; p.secret_key_length];
    unsafe {
        let region = watermark_paint();
        // Captured here, in `main`'s own frame, immediately before the
        // call — not inside `watermark_paint` (see its doc comment).
        let pre_call_marker: u8 = 0;
        let sp_pre_call = &pre_call_marker as *const u8 as usize;
        run_keygen(&mut ws, &p, &mut ek, &mut dk);
        std::hint::black_box(&ws);
        println!("keygen: {} bytes", watermark_scan(&region, sp_pre_call));
    }

    let mut k_enc = [0u8; 32];
    let mut c = vec![0u8; p.ciphertext_length];
    unsafe {
        let region = watermark_paint();
        let pre_call_marker: u8 = 0;
        let sp_pre_call = &pre_call_marker as *const u8 as usize;
        run_encaps(&mut ws, &p, &ek, &mut k_enc, &mut c);
        std::hint::black_box(&ws);
        println!("encaps: {} bytes", watermark_scan(&region, sp_pre_call));
    }

    let mut k_dec = [0u8; 32];
    unsafe {
        let region = watermark_paint();
        let pre_call_marker: u8 = 0;
        let sp_pre_call = &pre_call_marker as *const u8 as usize;
        run_decaps(&mut ws, &p, &dk, &c, &mut k_dec);
        std::hint::black_box(&ws);
        println!("decaps: {} bytes", watermark_scan(&region, sp_pre_call));
    }

    assert_eq!(k_enc, k_dec, "encaps/decaps shared secret mismatch");
}
