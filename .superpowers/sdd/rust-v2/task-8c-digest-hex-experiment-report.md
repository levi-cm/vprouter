# Actual public digest: bounded lowercase-hex experiment

2026-10-29. Frozen separate offline experiment authorized by Root's
`task-8c-digest-hex-experiment-brief.md`. The406 diagnosis froze first at SHA256
`e37a5160cf446fc245f3742b399392a72affd8f5a11ae779f0dc8b461312f2e2`.
Only ignored-target harness/build/artifacts and this report were written.
Application source remains frozen; no implementation, Git, coherent build,
native VM/SSH/Docker/privileged/profile/provider/identity action was performed.

The actual current public vprouter_worker::bootstrap::digest is the oracle.
299 input cases plus known SHA vectors, and8450 encoder comparisons, passed
before and after the single bounded timing run. The local candidate removes
per-byte temporary formatting Strings and has lower host cost in these inputs.
No native cost share, saved budget, two-second fit or Bootstrap success follows.

## Current function and scratch candidate

Current `crates/vprouter-worker/src/bootstrap.rs:76-80`:

```rust
pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
```

The scratch candidate uses the exact same Sha256::digest(input), then pushes
both nibbles of each of its32 bytes through b"0123456789abcdef" into one
String::with_capacity(64). SHA algorithm, input, complete lowercase64hex result
and recomputation are unchanged. No serialization, input/config value, cache,
call site, native observation, record or authority is changed. The encoder is
local to the harness and not inserted into application code. Source construction
of32 temporary Strings is the mechanism; allocation-call counts were not profiled.

The harness links the actual worker library built from the frozen current path
dependency, not a copied old function. Its source file SHA256 is
`1ddbb31c0e0a058fbc68522b17688d37bf0923282261f3accf83ad86b79fcff5`;
exact extracted digest snippet hash is
`f1201202c4b55b268840cc049e9648f9ef3ab7a71d3812ce8ab20afaf1f3311e`.
Current sha2 version is0.11.1, serde_json1.0.150. Target lock selects145 packages;
every dependency identity matches the repository lock, with only the scratch
harness package extra. No repository lock/manifest was edited.

## Build, call boundaries and single execution

All artifacts are under `target/task8c-digest-hex-experiment`.
A separate target-local Cargo workspace/profile compiled the actual current
library and harness offline. Exact commands:

```text
cargo build --offline --release --manifest-path target/task8c-digest-hex-experiment/harness/Cargo.toml --target-dir target/task8c-digest-hex-experiment/build --target x86_64-unknown-linux-gnu -j 2 -vv
target/task8c-digest-hex-experiment/build/x86_64-unknown-linux-gnu/release/task8c-digest-hex-cost
```

rustc1.97.0 `2d8144b7880597b6e6d3dfd63a9a9efae3f533d3`, LLVM22.1.6;
cargo1.97.0. Host target x86_64-unknown-linux-gnu, glibc2.41, default system
allocator, opt-level3, codegen-units16, debug=false, lto=false, panic=unwind;
RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS/CARGO_TARGET_DIR were unset. No allocation/CPU
profiler, pinning or host-load control was used. These are host GNU artifacts,
not the native static musl VM artifact. Full compiler commands/features/dependency
paths are retained in verbose build logs and context.json.

Actual helper is a dependency function without an inline attribute, with noLTO.
Before ANY timing run, Root requested aligned proposed boundaries; proposed was
marked #[inline(never)] and the harness rebuilt. Both timed paths use the same
black_box-opaque function pointer and black_box inputs/outputs; returned String
drop is inside timing. The local hex helper may inline inside proposed, just as
formatting internals optimize inside actual; residual crate/code-layout/cache/
allocator differences remain. No cross-crate versus local outer inlining claim
is hidden in the ratios.

Initial offline build exit0 in49.37s, retained as build-first.log. After the
inline attribute/formatting change, harness-only rebuild exit0; no data run had
occurred. Both build logs retain upstream dependency/build warnings (rustix hints,
ring/lifetime/deprecation/check-cfg warnings); these were not hidden or repaired.
The sole timing execution ran17:28:13.360375Z to17:28:14.157764Z, exit0,
wall0.797391s, empty run.stderr. There was no adaptive/selective rerun.

## Byte equivalence and timing method

Each pre/post pass compares complete outputs of actual and proposed for299
synthetic input cases: empty/abc, every one-byte value, deterministic binary at29
lengths through65536 (including SHA padding/block boundaries), all-byte ramps,
Unicode/composed/decomposed/control/NUL/65536byte Unicode, a public synthetic
owner-unit input and typed synthetic two-exit AllocationRecord JSON. No current
nonce/state/profile/deployment identity is an input. Known empty/abc expected
SHA256 strings are asserted separately against BOTH functions. Some case bytes
repeat;299 means executed cases, not299 distinct mathematical inputs.

Each pass also compares proposed hex to per-byte formatting on8450 arrays:
every possible byte at each of32 positions (8192),256 deterministic mixed32byte
arrays, and two uniform arrays. Output length64 and lowercase hex are checked.
This finite suite plus the unchanged SHA operation and direct nibble mapping
supports current byte equivalence; it is not a blanket proof for future edits.

Before timing, source fixed four scenarios,128 warmups per implementation, seven
batches and iterations20,000/20,000/5,000/1,000 respectively. Order alternates
actual/proposed then proposed/actual. Fixture serialization, oracle work, JSON
output and summary work are outside measured loops. Each sample times only the
opaque function call, black_box input/output and String drop. All28 paired batch
samples remain in results.jsonl. A separate read-only summary calculation checked
fixed counts/order and recomputed min/median/max and median ratios.

## Local bounded results

| Synthetic scenario | Input bytes | Actual ns/call min / median / max | Proposed ns/call min / median / max | Actual median / proposed median |
| --- | ---: | ---: | ---: | ---: |
| owner_unit_input |45|722.209 / 768.282 / 806.023|60.319 / 61.992 / 63.736|12.393|
| allocation_json |623|984.719 / 1000.822 / 1015.372|269.778 / 274.531 / 282.598|3.646|
| binary4096 |4096|2196.103 / 2260.785 / 2334.977|1542.079 / 1553.291 / 1625.535|1.455|
| binary65536 |65536|24599.022 / 24924.572 / 27098.693|23837.412 / 24045.091 / 24818.811|1.037|

Ratios describe only this host experiment. They cannot be multiplied by native
entry counts or applied to owner.record221/202ms: that boundary includes live
native checks, while measured history digest additionally serializes allocation.
Native counts differ between contexts/runs and include errors. No native gain,
CPU share, required end-to-end budget or release performance is measured here.
Shared parser/namespace/borrowed-record candidates remain future proposals only.

## Exact freeze and preservation

| Artifact relative to experiment directory | SHA256 |
| --- | --- |
| harness/src/main.rs | `820b47932e1fbe8ea97380c3df0caea9e67d5a47ec537df721d75fea7ad05337` |
| harness/Cargo.toml | `55184b0337e85d791cee165c1ffeead470f18b26642434365c19bc502a04f0cf` |
| harness/Cargo.lock | `96ba6ef2a5ddf1140e82ad107c406481e7f1fced81b31ffca66d7e555b4e3621` |
| executable | `1c4897e03af8f77b7f883372bc02a72c7b6dad90578573b49f1523326216d9c7` |
| worker rlib | `20ff96460f97b59653bd23173dd0209fce545266781d03eb8b8ac5ac9504f905` |
| sha2 rlib | `63b909ead70bc9608e95c4c019d15e5ae10b3f76b91aaf6d526315ffa16e3195` |
| results.jsonl | `e6bc417000c30765e2974d48fb8a654a6ae5d415be894fce3d7761246c070a49` |
| summary.json | `e676f31b806cbd687653a89e8865e3f853e5788419e914fce5c8d9d9afd54ad1` |
| context.json | `a4708a602c820dbb26561995515b4a6efe87f84fb2d1dd29f118c6f1cc813361` |
| execution.json | `99dfc1d985bba2041a4214b855709c19b6985e95dee921c51a02143439292cdc` |
| application-source-preserved.json | `7a343999bf98bdd179c036f338627bfa34f66b6d5c21b35b9f318757bc31d6f3` |

context.json binds exact rlib/executable paths and hashes, compiler/profile,
argv, GNU libc linkage and call boundaries. dependency-pins.json retains all
selected versions. artifact-hashes.json binds all root experiment files and
harness source/manifest/lock; the build tree retains exact linked artifacts.

All179 application Rust sources match their before hashes: zero changed/added/
deleted paths. Ten repository manifest/lock paths also match before hashes.
Self-review found no input/SHA/format/authority mutation, timing-oracle leakage,
inlining mismatch left undisclosed, selective samples or state/profile use.

Root owns independent evidence/source review, public-safe harness archival and
any separately authorized one-file application brief. No app digest change is
authorized by this report. Original398-406 failures, full Bootstrap/task8c/ARM/
client/migration/performance/release gates remain open/NOT_RUN where unaccepted.
