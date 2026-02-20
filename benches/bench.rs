// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion_cycles_per_byte::CyclesPerByte;
use mlkem_edu::*;
use std::hint::black_box;

fn benchmark_keygen<M: Measurement>(c: &mut Criterion<M>) {
    let mut group = c.benchmark_group("keygen");

    // Set throughput to 1 key generation per second
    group.throughput(Throughput::Elements(1));

    let parameter_sets = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
    let d = [0u8; 32];
    let z = [0u8; 32];

    for param_name in parameter_sets.iter() {
        let param = MLKEMParameters::new(param_name).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &param,
            |b, param| {
                b.iter(|| {
                    let mut pk = vec![0u8; param.public_key_length];
                    let mut sk: Vec<u8> = vec![0u8; param.secret_key_length];
                    ml_kem_keygen(
                        black_box(&d),
                        black_box(&z),
                        black_box(param),
                        &mut pk,
                        &mut sk,
                    );
                });
            },
        );
    }

    group.finish();
}

fn benchmark_encaps<M: Measurement>(c: &mut Criterion<M>) {
    let mut group = c.benchmark_group("encaps");

    // Set throughput to 1 key generation per second
    group.throughput(Throughput::Elements(1));

    let parameter_sets = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
    let d = [0u8; 32];
    let z = [0u8; 32];

    for param_name in parameter_sets.iter() {
        let param = MLKEMParameters::new(param_name).unwrap();
        let mut pk = [0u8; MAX_PUBLIC_KEY_BYTES];
        let mut sk = [0u8; MAX_SECRET_KEY_BYTES];
        let m = [0u8; 32];
        ml_kem_keygen(&d, &z, &param, &mut pk, &mut sk);
        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &param,
            |b, param| {
                b.iter(|| {
                    let mut k = [0u8; 32];
                    let mut c = [0u8; MAX_CIPHERTEXT_BYTES];
                    ml_kem_encaps(
                        black_box(&pk),
                        black_box(&m),
                        black_box(param),
                        &mut k,
                        &mut c,
                    );
                });
            },
        );
    }

    group.finish();
}

fn benchmark_decaps<M: Measurement>(c: &mut Criterion<M>) {
    let mut group = c.benchmark_group("decaps");

    // Set throughput to 1 key generation per second
    group.throughput(Throughput::Elements(1));

    let parameter_sets = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
    let d = [0u8; 32];
    let z = [0u8; 32];

    for param_name in parameter_sets.iter() {
        let param = MLKEMParameters::new(param_name).unwrap();
        let mut pk = [0u8; MAX_PUBLIC_KEY_BYTES];
        let mut sk = [0u8; MAX_SECRET_KEY_BYTES];
        let m = [0u8; 32];
        let mut k = [0u8; 32];
        let mut c = [0u8; MAX_CIPHERTEXT_BYTES];

        ml_kem_keygen(&d, &z, &param, &mut pk, &mut sk);
        ml_kem_encaps(&pk, &m, &param, &mut k, &mut c);
        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &param,
            |b, param| {
                b.iter(|| {
                    ml_kem_decaps(black_box(&sk), black_box(&c), black_box(param), &mut k);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    name = benches_cycles;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = benchmark_keygen, benchmark_encaps, benchmark_decaps
);
criterion_group!(
    benches_time,
    benchmark_keygen,
    benchmark_encaps,
    benchmark_decaps
);

criterion_main!(benches_time, benches_cycles);
