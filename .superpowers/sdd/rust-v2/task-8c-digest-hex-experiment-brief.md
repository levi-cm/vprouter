# Actual digest lowercase-hex mechanism experiment

Worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, base1188b26.
Application source remains frozen. First finish/freeze the read-only406 diagnosis
and its hashes before beginning this experiment. No application edit is allowed.

Use an isolated ignored-target Rust harness to call the actual current public
`vprouter_worker::bootstrap::digest` and a local proposed equivalent that retains
the exact same Sha256::digest(input) operation and encodes its32 output bytes
using a fixed lowercase hex lookup into one preallocated64byte String. No
changed digest/input/serialization, cache, call site or native observation.

Bind the exact existing function/source/dependency versions and harness hashes.
Use the actual current library for the oracle. A separate target-local Cargo
project/lock and release build are allowed, offline only; no repository manifest,
lock, source or program-manifest edits/coherent freeze. Clearly record compiler,
flags and host-only libc/allocator/optimization boundaries. Do not run native
VM/SSH/Docker/privileged/profile/identity/provider operations or subagents/Git.

Use public synthetic bytes only: empty/abc known SHA256 vectors, all single-byte
values, all-byte ramps and deterministic binary/Unicode/control/NUL fixtures,
several lengths through65536, and representative synthetic owner-unit/allocation
JSON bytes. Compare complete64lowercasehex outputs, not prefixes. Also compare
the local proposed hex encoder against formatting for every possible byte and
mixed32byte arrays. No current private nonce/state/profile is a fixture.

Measure a small fixed set of representative owner/allocation/binary byte inputs
with warmups, black_box, seven alternating A/B batches and bounded iterations
chosen before timing. Preserve every sample and summarize median ns/call and
ratios. Verify equivalence before and after measurements. No selective reruns,
native-count extrapolation, CPU share, two-second fit, release performance or
Bootstrap success claim. The experiment establishes only a local mechanism.

Freeze task-8c-digest-hex-experiment-report.md with exact source/harness/lock/
commands/logs/results/self-review/limits and proof all179 Rust source hashes
unchanged. Retain all private outputs under target; Root will separately review
public-safe harness archival and any future one-file implementation brief.
