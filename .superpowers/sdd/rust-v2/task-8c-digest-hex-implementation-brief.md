# Shared SHA-256 lowercase-hex representation change

Worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, source1188b26.
Conditional requirements only: no application edit until Root accepts the frozen
actual-digest mechanism experiment and independent requirements review.

Own only `crates/vprouter-worker/src/bootstrap.rs`: the public digest helper,
an optional minimal private hex helper, and meaningful focused tests. Retain
the public digest(bytes:&[u8])->String API and the exact existing
Sha256::digest(bytes) operation. Encode its32 bytes in original order as exactly
64 lowercase ASCII hex characters using a fixed lookup and one preallocated
64byte String. Preserve the old formatting for every byte including leading
zeros. No unsafe code, new dependency, stored digest, verdict/authority cache,
different hash, serialization, normalization, truncation or output/API change.

Every call site and all other existing code stay unchanged. The helper is shared
by identity/domain/records, so its exact output equivalence is binding; no owner,
nonce, state, policy, image, credential or canonical digest value may change.
This removes temporary formatting allocations only, and preserves recomputation
and all live native checks on every existing call. No timeout, retry, provider,
custody/proof, IO/frame/ACK/hold/negative/release/fence or acceptance change.

Before editing snapshot all179 Rust source hashes. Add meaningful differential
tests against the old formatter/SHA computation, including known empty/abc
vectors, all single-byte values, deterministic binary/Unicode/control/NUL/public
owner/allocation bytes and boundary lengths through65536. Exercise lowercase,
leading-zero and byte-order distinctions. If a private encoder is introduced,
compare all256 values in mixed32byte arrays. Check mutation sensitivity to a
wrong nibble/case/order variant, then restore exact source. Do not create a
standalone test mirroring the new implementation or repeat host timing as native
proof. The separate experiment must remain frozen before app edits.

Run focused worker library tests, fmt and strict worker lib/tests Clippy; retain
commands/full logs under ignored target. Prove only this one source file changed,
all178 other Rust paths unchanged, and every other expression/import/item unchanged
except necessary minimal helper/test/import changes. Freeze exact diff/source and
task-8c-digest-hex-implementation-report.md for fresh spec/quality review.

No Git mutation, coherent artifact freeze, VM/SSH/Docker/privileged/profile/
identity/native test or subagents. Root owns fresh workspace checks, both static
builds/updated normal program manifests and strict contexts, exact source/archive
binding, independently authored preserved59-link baseline from406canonical DOWN
endpoint plus prior58, independent artifact/public review, checkpoint push/tag,
and any next local native experiment. No baseline may adopt observed live fields.

No native cost share, optimization effect or original2s fit follows from the
host experiment or entry counts. Original398-406 failures remain preserved;
full8c/ARM/client/migration/performance/release gates stay open.
