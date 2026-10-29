use sha2::{Digest, Sha256};
use std::{hint::black_box, time::Instant};
use vprouter_core::{
    allocation::{AllocationRecord, ExitAllocation},
    config::ExitMode,
};

// Scratch candidate only: SHA operation and input remain identical to actual oracle.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
#[inline(never)]
fn proposed(input: &[u8]) -> String {
    hex(&Sha256::digest(input))
}
fn check_hex() -> usize {
    let mut count = 0;
    let mut check = |bytes: &[u8; 32]| {
        let formatted: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex(bytes), formatted);
        count += 1;
    };
    for byte in 0..=255u8 {
        for position in 0..32 {
            let mut bytes = [0; 32];
            bytes[position] = byte;
            check(&bytes);
        }
    }
    for seed in 0..=255u8 {
        check(&std::array::from_fn(|i| {
            seed.wrapping_mul(17)
                .wrapping_add((i as u8).wrapping_mul(13))
        }));
    }
    check(&[0; 32]);
    check(&[255; 32]);
    count
}
fn allocation_bytes() -> Vec<u8> {
    let exit = |id: &str, mode, wireguard_interface| ExitAllocation {
        exit_id: id.into(),
        mode,
        state_dir: format!("/synthetic/hexlab/{id}").into(),
        data_namespace: format!("vr-data-{id}"),
        transport_namespace: format!("vr-trans-{id}"),
        nft_table: format!("vr_{id}"),
        host_interface: format!("vh{id}"),
        data_interface: format!("vd{id}"),
        wireguard_interface,
        transport_subnet: "10.202.1.0/30".into(),
    };
    serde_json::to_vec(&AllocationRecord {
        schema_version: 2,
        deployment_id: "hexlab-public".into(),
        generation: 7,
        exits: vec![
            exit("one", ExitMode::Mullvad, Some("wgone".into())),
            exit("two", ExitMode::Direct, None),
        ],
    })
    .unwrap()
}
fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    let mut result = vec![("empty", Vec::new()), ("abc", b"abc".to_vec())];
    for byte in 0..=255u8 {
        result.push(("single_byte", vec![byte]));
    }
    for length in [
        0usize, 1, 2, 3, 15, 31, 32, 33, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511,
        512, 513, 1023, 1024, 4095, 4096, 8192, 65535, 65536,
    ] {
        result.push((
            "deterministic_binary",
            (0..length)
                .map(|i| (i.wrapping_mul(37) ^ (i >> 3) ^ 0xa5) as u8)
                .collect(),
        ));
    }
    for repeats in [1, 2, 16, 256] {
        result.push((
            "all_byte_ramp",
            (0..repeats).flat_map(|_| 0..=255u8).collect(),
        ));
    }
    for text in ["é", "e\u{301}", "💾", "\0", "\n\r\t\"\\\0é"] {
        result.push(("unicode_control", text.as_bytes().to_vec()));
    }
    result.push(("unicode_65536", "💾".repeat(16384).into_bytes()));
    result.push((
        "owner_unit_input",
        b"vprouter-v2-deployment-owner-v1:hexlab-public".to_vec(),
    ));
    result.push(("allocation_json", allocation_bytes()));
    result
}
fn oracle(inputs: &[(&str, Vec<u8>)]) -> usize {
    for (label, input) in inputs {
        let actual = vprouter_worker::bootstrap::digest(input);
        let candidate = proposed(input);
        assert_eq!(actual, candidate, "{label}, length {}", input.len());
        assert_eq!(actual.len(), 64);
        assert!(
            actual
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
    for (input, expected) in [
        (
            b"".as_slice(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".as_slice(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ] {
        assert_eq!(vprouter_worker::bootstrap::digest(input), expected);
        assert_eq!(proposed(input), expected);
    }
    inputs.len()
}
fn measure(function: fn(&[u8]) -> String, input: &[u8], iterations: u64) -> u128 {
    let call = black_box(function);
    let started = Instant::now();
    for _ in 0..iterations {
        drop(black_box(call(black_box(input))));
    }
    started.elapsed().as_nanos()
}
fn main() {
    let cases = inputs();
    let hex_cases = check_hex();
    let digest_cases = oracle(&cases);
    println!(
        "{}",
        serde_json::json!({"event":"oracle_before", "result":"PASS",
        "digest_cases":digest_cases, "hex_cases":hex_cases, "known_vectors":2})
    );
    let owner = b"vprouter-v2-deployment-owner-v1:hexlab-public".to_vec();
    let allocation = allocation_bytes();
    let binary4096: Vec<_> = (0usize..4096)
        .map(|i| (i.wrapping_mul(37) ^ (i >> 3) ^ 0xa5) as u8)
        .collect();
    let binary65536: Vec<_> = (0usize..65536)
        .map(|i| (i.wrapping_mul(37) ^ (i >> 3) ^ 0xa5) as u8)
        .collect();
    // Fixed before timing; no adaptive samples, iterations or reruns.
    for (label, input, iterations) in [
        ("owner_unit_input", owner, 20_000u64),
        ("allocation_json", allocation, 20_000),
        ("binary4096", binary4096, 5_000),
        ("binary65536", binary65536, 1_000),
    ] {
        for _ in 0..128 {
            drop(black_box(vprouter_worker::bootstrap::digest(black_box(
                &input,
            ))));
            drop(black_box(proposed(black_box(&input))));
        }
        let mut old_samples = Vec::new();
        let mut proposed_samples = Vec::new();
        for batch in 0..7 {
            let (old_ns, proposed_ns) = if batch % 2 == 0 {
                (
                    measure(vprouter_worker::bootstrap::digest, &input, iterations),
                    measure(proposed, &input, iterations),
                )
            } else {
                let proposed_ns = measure(proposed, &input, iterations);
                (
                    measure(vprouter_worker::bootstrap::digest, &input, iterations),
                    proposed_ns,
                )
            };
            old_samples.push(old_ns);
            proposed_samples.push(proposed_ns);
            println!(
                "{}",
                serde_json::json!({"event":"sample", "scenario":label,
                "batch":batch,"order":if batch % 2 == 0 {"actual_then_proposed"} else {"proposed_then_actual"},
                "iterations":iterations,"input_bytes":input.len(),"actual_elapsed_ns":old_ns,
                "proposed_elapsed_ns":proposed_ns})
            );
        }
        old_samples.sort_unstable();
        proposed_samples.sort_unstable();
        let old = old_samples[3] as f64 / iterations as f64;
        let new = proposed_samples[3] as f64 / iterations as f64;
        println!(
            "{}",
            serde_json::json!({"event":"summary","scenario":label,
            "input_bytes":input.len(),"input_digest":vprouter_worker::bootstrap::digest(&input),
            "actual_ns_per_call_min_median_max":[old_samples[0] as f64 / iterations as f64,old,old_samples[6] as f64 / iterations as f64],
            "proposed_ns_per_call_min_median_max":[proposed_samples[0] as f64 / iterations as f64,new,proposed_samples[6] as f64 / iterations as f64],
            "median_actual_divided_by_proposed":old/new})
        );
    }
    let after_hex = check_hex();
    let after_digest = oracle(&cases);
    assert_eq!((after_hex, after_digest), (hex_cases, digest_cases));
    println!(
        "{}",
        serde_json::json!({"event":"oracle_after","result":"PASS",
        "digest_cases":after_digest,"hex_cases":after_hex,"known_vectors":2})
    );
}
