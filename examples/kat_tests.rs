// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

//! KAT (Known Answer Tests) for ML-KEM implementation
//! Tests key generation, encapsulation, and decapsulation
//! using NIST FIPS-203 test vectors

use mlkem_edu::*;
use serde::Deserialize;
use std::fs;

// KAT deserialization
#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "parameterSet")]
    parameter_set: Option<String>,
    tests: Vec<Test>,
}

#[derive(Debug, Deserialize)]
struct Test {
    #[serde(rename = "tcId")]
    tc_id: u32,
    d: Option<String>,
    z: Option<String>,
    ek: Option<String>,
    dk: Option<String>,
    m: Option<String>,
    c: Option<String>,
    k: Option<String>,
    #[serde(rename = "testPassed")]
    test_passed: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct TestVector {
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

fn main() {
    test_keygen();
    test_encaps_decaps();
}

fn print_result<T: std::fmt::Debug>(label: &str, total: i32, success: i32, failed_tests: &[T]) {
    println!(
        "{}{} Results: {}/{} tests passed",
        " ".repeat(10),
        label,
        success,
        total
    );

    if !failed_tests.is_empty() {
        println!("Failed tests: {:?}", failed_tests);
    }
}

fn test_keygen() {
    let prompt_data = fs::read_to_string("FIPS-203/keyGen/prompt.json")
        .expect("Failed to read keyGen prompt file");
    let expected_data = fs::read_to_string("FIPS-203/keyGen/expectedResults.json")
        .expect("Failed to read keyGen expected results file");

    let prompt: TestVector =
        serde_json::from_str(&prompt_data).expect("Failed to parse prompt JSON");
    let expected: TestVector =
        serde_json::from_str(&expected_data).expect("Failed to parse expected JSON");

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut failed_tests = Vec::new();
    println!("Testing ML-KEM Key Generation");

    for (tg_idx, test_group) in prompt.test_groups.iter().enumerate() {
        let param_set = test_group.parameter_set.as_ref().unwrap();
        let p = MLKEMParameters::new(param_set)
            .expect(&format!("Unknown parameter set: {}", param_set));

        for (test_idx, test) in test_group.tests.iter().enumerate() {
            let d_vec = hex::decode(test.d.as_ref().unwrap()).unwrap();
            let z_vec = hex::decode(test.z.as_ref().unwrap()).unwrap();

            total_tests += 1;

            let mut d = [0u8; 32];
            let mut z = [0u8; 32];
            d.copy_from_slice(&d_vec);
            z.copy_from_slice(&z_vec);

            let mut ek = vec![0u8; p.public_key_length];
            let mut dk = vec![0u8; p.secret_key_length];
            ml_kem_keygen(&d, &z, &p, &mut ek, &mut dk);

            let expected_test = &expected.test_groups[tg_idx].tests[test_idx];
            let expected_ek = hex::decode(expected_test.ek.as_ref().unwrap()).unwrap();
            let expected_dk = hex::decode(expected_test.dk.as_ref().unwrap()).unwrap();

            let ek_match = ek == expected_ek;
            let dk_match = dk == expected_dk;

            if ek_match && dk_match {
                passed_tests += 1;
            } else {
                failed_tests.push((param_set.clone(), test.tc_id));
                println!("  Test {}/{}", test_group.tg_id, test.tc_id);
                if !ek_match {
                    println!("    EK mismatch!");
                }
                if !dk_match {
                    println!("    DK mismatch!");
                }
            }
        }
    }
    print_result("KeyGen", total_tests, passed_tests, &failed_tests);
}

fn test_encaps_decaps() {
    let prompt_data = fs::read_to_string("FIPS-203/encapsDecap/prompt.json")
        .expect("Failed to read encapsDecap prompt file");
    let expected_data = fs::read_to_string("FIPS-203/encapsDecap/expectedResults.json")
        .expect("Failed to read encapsDecap expected results file");

    let prompt: TestVector =
        serde_json::from_str(&prompt_data).expect("Failed to parse prompt JSON");
    let expected: TestVector =
        serde_json::from_str(&expected_data).expect("Failed to parse expected JSON");

    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut failed_tests = Vec::new();
    println!("Testing ML-KEM Encaps/Decaps");

    for (tg_idx, test_group) in prompt.test_groups.iter().enumerate() {
        let param_set = test_group.parameter_set.as_ref().unwrap();
        let p = MLKEMParameters::new(param_set)
            .expect(&format!("Unknown parameter set: {}", param_set));

        for (test_idx, test) in test_group.tests.iter().enumerate() {
            total_tests += 1;
            let expected_test = &expected.test_groups[tg_idx].tests[test_idx];

            if test.ek.is_some() && test.m.is_some() {
                // Encapsulation test
                let ek = hex::decode(test.ek.as_ref().unwrap()).unwrap();
                let m_vec = hex::decode(test.m.as_ref().unwrap()).unwrap();
                let mut m = [0u8; 32];
                m.copy_from_slice(&m_vec);

                let mut k = [0u8; 32];
                let mut c = vec![0u8; p.ciphertext_length];
                ml_kem_encaps(&ek, &m, &p, &mut k, &mut c);

                let expected_k = hex::decode(expected_test.k.as_ref().unwrap()).unwrap();
                let expected_c = hex::decode(expected_test.c.as_ref().unwrap()).unwrap();

                let k_match = k.to_vec() == expected_k;
                let c_match = c == expected_c;

                if k_match && c_match {
                    passed_tests += 1;
                } else {
                    failed_tests.push((param_set.clone(), test.tc_id));
                    println!(
                        "  Test {}/{}: Encaps - {} mismatch!",
                        test_group.tg_id,
                        test.tc_id,
                        if !k_match { "K" } else { "C" }
                    );
                }
            } else if test.dk.is_some() && test.c.is_some() {
                // Decapsulation test
                let dk = hex::decode(test.dk.as_ref().unwrap()).unwrap();
                let c = hex::decode(test.c.as_ref().unwrap()).unwrap();

                let mut k = [0u8; 32];
                ml_kem_decaps(&dk, &c, &p, &mut k);

                let expected_k = hex::decode(expected_test.k.as_ref().unwrap()).unwrap();
                let k_match = k.to_vec() == expected_k;
                if k_match {
                    passed_tests += 1;
                } else {
                    failed_tests.push((param_set.clone(), test.tc_id));
                    println!(
                        "  Test {}/{}: Decaps - K mismatch",
                        test_group.tg_id, test.tc_id
                    );
                }
            } else if test.dk.is_some() && test.ek.is_none() {
                // DK validation test
                let dk = hex::decode(test.dk.as_ref().unwrap()).unwrap();

                let result = check_dk(&dk, &p);

                let expected_result = expected_test.test_passed.unwrap();
                let match_result = result == expected_result;

                if match_result {
                    passed_tests += 1;
                } else {
                    failed_tests.push((param_set.clone(), test.tc_id));
                    println!(
                        "  Test {}/{}: Check Private Key mismatch",
                        test_group.tg_id, test.tc_id
                    );
                }
            } else if test.ek.is_some() && test.m.is_none() {
                // EK validation test
                let ek = hex::decode(test.ek.as_ref().unwrap()).unwrap();

                let result = check_ek(&ek, &p);

                let expected_result = expected_test.test_passed.unwrap();
                let match_result = result == expected_result;

                if match_result {
                    passed_tests += 1;
                } else {
                    failed_tests.push((param_set.clone(), test.tc_id));
                    println!(
                        "  Test {}/{}: Check Public Key mismatch",
                        test_group.tg_id, test.tc_id
                    );
                }
            } else {
                panic!(
                    "  Test {}/{}: (unknown test type)",
                    test_group.tg_id, test.tc_id
                );
            }
        }
    }

    print_result("Encaps/Decaps", total_tests, passed_tests, &failed_tests);
}
