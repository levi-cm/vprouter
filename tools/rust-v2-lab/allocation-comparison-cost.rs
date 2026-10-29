use std::{hint::black_box, os::unix::ffi::OsStringExt, path::PathBuf, time::Instant};
use vprouter_core::allocation::{AllocationRecord, ExitAllocation};

#[derive(Debug, PartialEq, Eq)]
enum Error { OwnershipMismatch }
type Result<T> = std::result::Result<T, Error>;

// Exact existing same_allocation body, with its sole Error variant local to scratch.
fn old(a: &AllocationRecord, b: &AllocationRecord) -> Result<bool> {
    Ok(serde_json::to_vec(a).map_err(|_| Error::OwnershipMismatch)?
        == serde_json::to_vec(b).map_err(|_| Error::OwnershipMismatch)?)
}

fn exit_equal(a: &ExitAllocation, b: &ExitAllocation) -> bool {
    let ExitAllocation {
        exit_id: ai, mode: am, state_dir: ap, data_namespace: ad,
        transport_namespace: at, nft_table: an, host_interface: ah,
        data_interface: adi, wireguard_interface: aw, transport_subnet: asub,
    } = a;
    let ExitAllocation {
        exit_id: bi, mode: bm, state_dir: bp, data_namespace: bd,
        transport_namespace: bt, nft_table: bn, host_interface: bh,
        data_interface: bdi, wireguard_interface: bw, transport_subnet: bsub,
    } = b;
    ai == bi && am == bm && ap.as_os_str() == bp.as_os_str()
        && ad == bd && at == bt && an == bn && ah == bh && adi == bdi
        && aw == bw && asub == bsub
}

fn proposed(a: &AllocationRecord, b: &AllocationRecord) -> Result<bool> {
    let AllocationRecord {schema_version: av, deployment_id: ai, generation: ag, exits: ae} = a;
    let AllocationRecord {schema_version: bv, deployment_id: bi, generation: bg, exits: be} = b;
    // All typed serialization errors must still be observed before any mismatch return.
    for record in [ae, be] {
        for exit in record {
            exit.state_dir.to_str().ok_or(Error::OwnershipMismatch)?;
        }
    }
    Ok(av == bv && ai == bi && ag == bg && ae.len() == be.len()
        && ae.iter().zip(be).all(|(a,b)| exit_equal(a,b)))
}

fn changed(base: &AllocationRecord, key: &str, value: serde_json::Value) -> AllocationRecord {
    let mut encoded = serde_json::to_value(base).unwrap();
    encoded["exits"][0][key] = value;
    serde_json::from_value(encoded).unwrap()
}

fn oracle(primary: &AllocationRecord, actual: &AllocationRecord) -> usize {
    let mut cases = Vec::new();
    cases.push(("equal", primary.clone(), primary.clone()));
    let mut schema = primary.clone();schema.schema_version += 1;
    cases.push(("schema", primary.clone(), schema));
    let mut deployment = primary.clone();deployment.deployment_id.push('x');
    cases.push(("deployment", primary.clone(), deployment));
    let mut generation = primary.clone();generation.generation += 1;
    cases.push(("generation", primary.clone(), generation));
    for key in ["exit_id", "data_namespace", "transport_namespace", "nft_table",
        "host_interface", "data_interface", "transport_subnet"] {
        cases.push((key, primary.clone(), changed(primary,key,serde_json::json!("different"))));
    }
    cases.push(("mode",primary.clone(),changed(primary,"mode",serde_json::json!("direct"))));
    cases.push(("wireguard_none",primary.clone(),changed(primary,"wireguard_interface",serde_json::Value::Null)));
    cases.push(("wireguard_empty",primary.clone(),changed(primary,"wireguard_interface",serde_json::json!(""))));
    for path in ["", "/fixture/a", "/fixture//a", "/fixture/./a", "/fixture/a/", "/fixture/é", "/fixture/a\0b"] {
        cases.push(("path_exact_clone",changed(primary,"state_dir",serde_json::json!(path)),changed(primary,"state_dir",serde_json::json!(path))));
    }
    for path in ["/fixture//a", "/fixture/./a", "/fixture/a/"] {
        cases.push(("path_text_difference",changed(primary,"state_dir",serde_json::json!("/fixture/a")),changed(primary,"state_dir",serde_json::json!(path))));
    }
    for text in ["", "\0", "\n\"\\", "é", "e\u{301}"] {
        cases.push(("string_exact_clone",changed(primary,"exit_id",serde_json::json!(text)),changed(primary,"exit_id",serde_json::json!(text))));
        cases.push(("string_difference",primary.clone(),changed(primary,"exit_id",serde_json::json!(text))));
    }
    let mut empty = primary.clone();empty.exits.clear();
    cases.push(("length",primary.clone(),empty.clone()));
    cases.push(("empty_equal",empty.clone(),empty.clone()));
    let mut ordered = actual.clone();ordered.exits.reverse();
    cases.push(("exit_order",actual.clone(),ordered));
    let mut duplicate = primary.clone();duplicate.exits.push(duplicate.exits[0].clone());
    cases.push(("duplicate_length",primary.clone(),duplicate.clone()));
    cases.push(("duplicate_equal",duplicate.clone(),duplicate));
    let mut malformed = primary.clone();
    malformed.exits[0].state_dir = PathBuf::from(std::ffi::OsString::from_vec(vec![b'/',0xff]));
    cases.push(("invalid_left",malformed.clone(),primary.clone()));
    cases.push(("invalid_right",primary.clone(),malformed.clone()));
    cases.push(("invalid_equal",malformed.clone(),malformed.clone()));
    let mut earlier = primary.clone();earlier.schema_version += 1;
    cases.push(("invalid_after_schema_mismatch",earlier,malformed.clone()));
    cases.push(("invalid_after_length_mismatch",empty,malformed.clone()));
    let mut late = actual.clone();late.exits.push(malformed.exits[0].clone());
    cases.push(("invalid_late_exit",primary.clone(),late));
    let count = cases.len();
    for (label,a,b) in cases {
        assert_eq!(old(&a,&b),proposed(&a,&b),"oracle case {label}");
    }
    count
}

fn measure(function: fn(&AllocationRecord,&AllocationRecord)->Result<bool>, a: &AllocationRecord, b: &AllocationRecord, iterations: u64) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(function(black_box(a),black_box(b))).unwrap();
    }
    start.elapsed().as_nanos()
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let primary: AllocationRecord = serde_json::from_slice(&std::fs::read(&arguments[1]).unwrap()).unwrap();
    let actual: AllocationRecord = serde_json::from_slice(&std::fs::read(&arguments[2]).unwrap()).unwrap();
    let cases = oracle(&primary,&actual);
    let iterations=20_000u64;let repeats=7u64;
    let mut differing = primary.clone();differing.exits[0].transport_subnet.push('x');
    let scenarios=[("primary_equal",&primary,&primary.clone()),("actual_equal",&actual,&actual.clone()),("primary_mismatch",&primary,&differing)];
    println!("{}",serde_json::json!({"oracle_cases":cases,"oracle":"PASS","iterations":iterations,"repeats":repeats,"compiler_target":"host_glibc","scope":"isolated_pure_comparison_not_native_cost_share"}));
    for (label,a,b) in scenarios {
        for _ in 0..100 {black_box(old(black_box(a),black_box(b))).unwrap();black_box(proposed(black_box(a),black_box(b))).unwrap();}
        let mut old_samples=Vec::new();let mut proposed_samples=Vec::new();
        for repeat in 0..repeats {
            if repeat%2==0 {old_samples.push(measure(old,a,b,iterations));proposed_samples.push(measure(proposed,a,b,iterations));}
            else {proposed_samples.push(measure(proposed,a,b,iterations));old_samples.push(measure(old,a,b,iterations));}
        }
        println!("{}",serde_json::json!({"scenario":label,"exits":a.exits.len(),"serialized_bytes":serde_json::to_vec(a).unwrap().len(),"iterations":iterations,"old_elapsed_ns":old_samples,"proposed_elapsed_ns":proposed_samples}));
    }
}
