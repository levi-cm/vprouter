# Ignored-target pure allocation comparison experiment

2026-10-29. Separate bounded offline experiment authorized by Root after the
404 base diagnosis. Experiment and report are frozen. No application source
edit, native/VM action, Git operation or semantic fix was performed. The current
404 diagnosis SHA256 is
`7274438192f33cc1197f070a35c16bae5b302379a956ae994c28c63ec08b7191`.

The experiment passed45 differential Result cases against the existing helper
and measured the pure comparison alone. It establishes a local mechanism for
removing repeated temporary JSON serialization/buffer work. It does **not**
measure allocation equality's share of native retained validation, demonstrate
a native speedup or sufficient budget, or authorize an application change.

## Scope and exact artifacts

All scratch source, fixtures, executable and outputs are under ignored
`target/task8c-allocation-comparison-cost`. Root also archived the exact safe
benchmark source as `tools/rust-v2-lab/allocation-comparison-cost.rs`
(SHA256 `dbc0568124d477577c588908dccdb22ae63edee7efc5174dde4be03ea3e883c1`)
for review/recovery; allocation fixtures and executable remain ignored. Fixtures contain only the public
AllocationRecord from Root's saved404 namespaces inspection. The primary fixture
projects its one selected exit; the second fixture retains the actual two exits.
No profile/private file is read, no path is resolved or mutated, and these plain
values construct no fixture resource or ownership authority.

The experiment uses the actual public AllocationRecord/ExitAllocation types from
an existing host vprouter_core release rlib, rather than a serde_json::Value
performance proxy. The original same_allocation function body is copied exactly.
Its only Error variant, OwnershipMismatch, is represented by a scratch-local
enum with that one variant, preserving the compared Result class without
linking the launch runtime. No new comparator was inserted in application code.

The candidate exhaustively destructures all four allocation and ten exit fields.
It checks every state_dir for UTF8 in A then B before any mismatch return,
compares path OsStr bytes exactly, and compares all other fields and ordered
vector length/positions. It allocates no serialization buffer or validation
cache. Exhaustive patterns contain no `..`. No Eq derive, normalization, path
canonicalization, sorting or set comparison is used.

| Artifact | SHA256 |
| --- | --- |
| bench.rs |`dbc0568124d477577c588908dccdb22ae63edee7efc5174dde4be03ea3e883c1`|
| bench executable |`c3541815a44fb961d17ad9ba86014124293e238f5bfce76d7322c1ba968e2d05`|
| context.json |`6de05722d0118680d2fcf12c686d54889187d251496a012e55d6d399fcd9b086`|
| primary-allocation.json |`bc9aaf73bbe61d64ed56e38baef585c298b3cb01a61f45edd688bb31d8b9c8c5`|
| actual-allocation.json |`f5babf6aed7f728ebd33c72211a0273816a6b0f5060e4333b68492e22ff02379`|
| results.jsonl |`7218014ac7d3fae2aaa7fbf0ef567c3d75fc2840d6d9960cc8761ae39a856860`|
| summary.json |`0f4e61c7f9f90ccbb1208b1eeedddf882663ab48e2a8eab06b0d495eb745cc20`|
| build.log and run.stderr (both empty) |`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`|
| application-source-preserved.json |`a49625c761936e549bc5c314c915b37789c67f302229d0633a5c723c4a7c2450`|

The preservation artifact compares all179 current application Rust files against
the frozen nested-cost after-hash snapshot: zero changed/added/deleted paths.
Application source remains exactly as in404.

## Compiler and execution

Host toolchain: rustc1.97.0 `2d8144b7880597b6e6d3dfd63a9a9efae3f533d3`,
LLVM22.1.6, target x86_64-unknown-linux-gnu. The scratch unit is opt-level3:

```text
rustc --edition 2024 -C opt-level=3 -L dependency=target/release/deps --extern vprouter_core=target/release/deps/libvprouter_core-7cdd24b3d11fb56a.rlib --extern serde_json=target/release/deps/libserde_json-4ae9ad4fa10f6286.rlib target/task8c-allocation-comparison-cost/bench.rs -o target/task8c-allocation-comparison-cost/bench
target/task8c-allocation-comparison-cost/bench target/task8c-allocation-comparison-cost/primary-allocation.json target/task8c-allocation-comparison-cost/actual-allocation.json
```

Both commands exited0. Exact argv, full rustc -Vv and existing linked rlib hashes
are captured in context.json. Core rlib SHA256 is
`8a46a6baa18db5c8e0b7a583b2c81a65dbb2b8c17b7c8344aa02cee990add91e`;
serde_json rlib SHA256 is
`6e1c0193f21d41f5bced03862840c5b5a73356980cdd3abdc02e1843c49d3b08`.
The existing dependencies were reused without rebuilding them; their complete
original optimization invocation was not independently reconstructed here.

This is host glibc, not the owned Debian VM's static musl artifact/context. It
does not include custody, live syscall/metadata checks, allocation digest/history
validation, original clocks, pending proofs, journaling or the diagnostic timers.
No CPU pinning, VM load control or hardware acceptance benchmark was attempted.

## Functional oracle

Before timing,45 cases assert exact equality of original and proposed Result:

- exact clones and mutations of schema, deployment, generation and every exit
  field, mode, optional WireGuard None/Some-empty;
- empty, reordered and duplicated exit vectors and length mismatches;
- exact/path-different empty, Unicode, NUL, repeated-separator, dot-component
  and trailing-separator paths;
- exact/different empty, NUL, escaped/control and Unicode exit strings;
- invalid UTF8 in A, in B, in both, in a late exit, and hidden behind an earlier
  schema/vector-length mismatch.

The original serializer remains the oracle, so invalid-path Errors must match
even when an early scalar comparison alone could return false. This is finite
fixture coverage plus exhaustive-field/source reasoning, not an exhaustive
proof over all possible future serializers or fields. A future application
change must retain meaningful equivalent tests and all original native proof
and hold/negative coverage.

## Bounded measured results

Each scenario has100 warmup comparisons per implementation, then seven batches
of20,000 calls. Old/new order alternates by batch. Inputs and outputs pass through
black_box; parsing, fixture creation and equivalence cases are outside the timed
loop. Equal inputs use a separate cloned record; the mismatch changes the last
exit field, avoiding an artificial early-schema-only comparison. Timings are
Instant elapsed per batch, divided by calls; this is not process CPU accounting.

| Scenario | Serialized bytes | Original ns/call min / median / max | Candidate ns/call min / median / max |
| --- | ---: | ---: | ---: |
| Primary one-exit equal |541|577.144 /592.396 /598.629|18.604 /19.568 /38.198|
| Actual two-exit equal |999|918.975 /963.732 /1189.084|34.688 /37.422 /60.360|
| Primary late-field mismatch |541|549.831 /567.924 /588.991|18.044 /18.085 /19.051|

Full seven-batch nanosecond samples are retained in results.jsonl; summary.json
retains unrounded min/median/max per call. The local timings support a concrete
pure-work mechanism: compare these exact typed fields without constructing two
JSON Vec buffers each time. They do not show that this helper explains the bulk
of the native335/339ms retained-binding category. Those native rows include live
checks, full histories, nested costs, scheduling and observer overhead. Scaling
these host timings by native timer counts would not establish actual saved time.

## Next boundary

Root's draft `task-8c-allocation-comparison-brief.md` awaits separate concrete
authorization/review. A possible one-file application change would preserve all
same_allocation call sites and Result/error behavior, all current live checks,
original2s clocks, pending ownership/IO/registry/fence proofs, held polls/negatives,
release/ACK handling and diagnostic categories. No source or native change has
been made by this experiment.

404 is a synthetic Bootstrap run with provider_profiles_used=false, not a live
Mullvad connection. User steering about unavailable relays does not explain this
Deadline or change this offline experiment; Root owns the later approved live
provider selection while preserving identity/credentials. No tunnel was tested.

Native equivalence, actual cost effect, complete Bootstrap scopes, real-client,
runtime and release acceptance remain NOT_RUN/open. Root owns the next brief,
independent review, builds/artifact binding, preservation and any native attempt.
