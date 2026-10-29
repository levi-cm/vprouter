# Shared digest lowercase-hex: frozen one-file implementation

2026-10-29. Root explicitly authorized the reviewed implementation brief after
accepting experimenta4d7f6a9/finalreview120050bf and remotely confirming mechanism
checkpoint7b50834. Root rechecked all203 source inputs before editing. This
implementation owns only `crates/vprouter-worker/src/bootstrap.rs`; no other
application path, import, manifest, dependency, lock or tooling changed.

Frozen for fresh spec/quality review. No Git/coherent build/native/VM/SSH/Docker/
privileged/profile/identity/provider operation or subagent was used.

## Mechanism and exact equivalence

Public digest(bytes:&[u8])->String retains the exact Sha256::digest(bytes)
operation on every call and passes those same32 result bytes to a minimal private
digest_hex helper. That helper uses b"0123456789abcdef", one
String::with_capacity(64), and two character pushes per byte: high nibble first,
then low nibble. Each nibble lies0..15; lookup characters are single-byte ASCII.
For exactly32 SHA256 bytes this yields exactly64 lowercase characters with the
same leading-zero padding and byte order as the former format!("{b:02x}").

No call site, input, algorithm, serialization, output/API, digest/domain/record
identity, native observation, ownership proof or authoritative clock changes.
There is no cache, unsafe code or new dependency. The private encoder is called
in production only with the fixed32-byte SHA output. Every other original byte
outside the digest/helper/test insertion reconstructs identically, including
all custody/IO/frame/ACK/hold/negative/release/fence/failure/deadline behavior.

## Meaningful equivalence tests and retained mutation

Three added tests exercise actual application digest/helper behavior:

- Known empty/abc SHA256 literals, including empty after abc, catch a stale or
  wrong digest and require complete exact output.
- 299 old-SHA/formatter differential input checks cover every one-byte value;
 29 binary lengths through65536 and padding/block boundaries; all-byte ramps;
 Unicode/composed/decomposed/control/NUL/65536byte Unicode; public synthetic
 owner-unit input; and typed synthetic two-exit allocation JSON. No resource,
 authority or real profile is constructed for these inputs.
- 8450 encoder comparisons use every byte at every32-byte position,256 mixed
 arrays and two uniform arrays. An additional hand-checked ordered0..31 literal
 explicitly distinguishes leading zeros, lowercase and byte order. Expected
 outputs use the old formatter, not a second nibble algorithm.

Tests were written first; tests-first.log retains exit101 from the not-yet-added
private helper (two missing-symbol errors), not a claimed assertion failure.
After implementation the digest_ filter passed four tests (three new and an
existing digest/nonce test). A deliberate wrong-low-nibble mutation then made
all three new tests fail while the existing test passed (exit101); the actual
failures are retained in wrong-nibble-mutation.log. Exact saved source bytes
were restored before full checks. No historical failure is hidden or relabeled.

## Final focused checks

Logs/artifacts are under ignored `target/task8c-digest-hex-implementation`.

| Command | Result | Log |
| --- | --- | --- |
| cargo test -p vprouter-worker --lib digest_ | exit0; 4 passed | focused-green.log |
| cargo test -p vprouter-worker --lib | exit0; 65 passed, 0 failed | worker-lib.log |
| cargo clippy -p vprouter-worker --lib --tests -- -D warnings | exit0; no warning | clippy.log |
| rustfmt --edition 2024 --config skip_children=true --check crates/vprouter-worker/src/bootstrap.rs | exit0; empty output | fmt.log |
| python3 target/task8c-digest-hex-implementation/check_scope.py | exit0 | scope.log |

## Exact source freeze and preservation

| Artifact | SHA256 |
| --- | --- |
| bootstrap.rs before | `1ddbb31c0e0a058fbc68522b17688d37bf0923282261f3accf83ad86b79fcff5` |
| bootstrap.rs final | `f4b01c3d7cbc04ee9b1a2133bc9354d6ca8f2b8d893fa58d21310479f7732fdd` |
| source.diff | `49cd18642eb365826aa9e66d62321d50093b321ebf30924c6584c0a22abdcba4` |
| source-preserved.json | `b84b30b6aec6c85f6c824a0b6e9f8827ddb4d47a002800c22618559bc108058d` |
| rust-before.json | `0fc869e607e2a987abeaff7724dee2824d0e25d448500f88967b2d5f162ff38d` |
| rust-after.json | `f31ce696bd7f647a841da2904f8a383d4ab8fee37662d3678539e86a6ac03b3b` |
| worker-lib.log | `a7190d593449fc1a665ee252bed0da45aa78b4aa9368a73e1507d8f5f034c022` |
| clippy.log | `5c72f0078922a4123f1f22f03469215d6be0d6faa59e6643173eef865f99b75a` |
| fmt.log | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

All179 Rust files were snapshotted before editing. Exactly bootstrap.rs changed;
all178 unowned paths remain unchanged, with no added/deleted Rust path. The
replayable scope checker replaces only the digest/private-helper region with its
before bytes and removes the added test block; the entire original file then
matches byte-for-byte. No formatting normalization or other original expression/
import/item replacement is needed. Source hashes were rechecked after final
worker tests/Clippy/fmt. artifact-hashes.json binds all local evidence, including
initial compile failure, deliberate mutation and exact restoration metadata.

## Self-review and limits

Self-review found no omitted byte/nibble, uppercase/truncation/order error,
unsafe/API/cache/dependency change, altered SHA input/operation, call-site change
or unrelated original statement edit. The old formatter remains only in cfg(test)
expectations; no production fallback is added. Source construction of temporary
formatting Strings is removed; actual allocator calls were not profiled.

The frozen host experiment established a local mechanism only. No timing was
repeated here and no native cost share, optimization effect, Bootstrap scope,
original two-second fit or release performance is claimed. Root owns fresh
workspace checks, both static builds/normal manifests/strict contexts, exact
source/artifact binding, independently authored preserved59-link baseline,
independent artifact/public review, checkpoint/push and any next local native run.
Original398-406 failures remain preserved; full8c/ARM/client/migration/performance/
release gates remain open. Source outside this one path stays frozen.
