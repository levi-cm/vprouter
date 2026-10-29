# Independent review: shared SHA-256 lowercase hex implementation

2026-10-29. Review of the frozen one-file implementation on branch `rust/v2`,
HEAD `7b508344ff1c6b1b36c767d0637bb6490725bbab`. The bounded implementation
brief was read first. This review performed source/log/document reads and
independent byte/hash comparisons; it did not execute tests, builds or timing.

| Dimension | Verdict |
| --- | --- |
| Implementation specification compliance | **PASS** |
| Source quality and meaningful test coverage | **PASS** |
| Retained focused verification evidence | **PASS**, with provenance limits below |
| Actionable findings | **None identified** |

These verdicts bind the exact source and evidence below. They permit Root to
continue its separately owned workspace/artifact review; they do not accept
native performance, Bootstrap, task8c or any release gate.

## Exact binding

All hashes below were independently calculated from the files read here.

| File or artifact | SHA256 |
| --- | --- |
| `task-8c-digest-hex-implementation-brief.md` | `0ec4fb2dc62edfa77cbd7f958469ef5b135e58cc5da07baabab585c107b48c47` |
| `task-8c-digest-hex-implementation-report.md` | `f81f347379246f0e8fc679523932490444d37a522280bf659434f3cd912ff69a` |
| `task-8c-bootstrap406-diagnosis-review.md` | `120050bfee12ef3032c5c57175e4fa04c7ad7aaa1a8f83dc82d480206f285eb4` |
| `task-8c-digest-hex-experiment-report.md` | `a4d7f6a90d7546605484a159ee5161281a1c808cebbd4e2049a4fca532ada55c` |
| Original `bootstrap.rs` / retained `bootstrap-before.rs` | `1ddbb31c0e0a058fbc68522b17688d37bf0923282261f3accf83ad86b79fcff5` |
| Final `crates/vprouter-worker/src/bootstrap.rs` | `f4b01c3d7cbc04ee9b1a2133bc9354d6ca8f2b8d893fa58d21310479f7732fdd` |
| `source.diff` | `49cd18642eb365826aa9e66d62321d50093b321ebf30924c6584c0a22abdcba4` |
| `artifact-hashes.json` | `258d32c557841cfaa4df418ac8bd295ae24ea59b6372908ce220136458e7c97c` |
| `rust-before.json` | `0fc869e607e2a987abeaff7724dee2824d0e25d448500f88967b2d5f162ff38d` |
| `rust-after.json` | `f31ce696bd7f647a841da2904f8a383d4ab8fee37662d3678539e86a6ac03b3b` |
| `source-preserved.json` / `scope.log` | `b84b30b6aec6c85f6c824a0b6e9f8827ddb4d47a002800c22618559bc108058d` |
| `check_scope.py` | `d408a6cf4bf12cd6e714d506a338df579371707d0e4633fd4640767b57153be2` |
| `tests-first.log` | `8bb7abeac3cc1d211be6a83411b88ac9180ea821b65efc9afa174f9b6988d255` |
| `focused-green.log` | `920341bf3ee9752c3aeb14364c4978eace014f8c4c56f51bd29f983f6dc2cf10` |
| `wrong-nibble-mutation.log` | `0904a9f674466293fea7c7e972f38b93d7bfa9c5e1057545ca380313b7a2a2f8` |
| `mutation.json` | `4f8a2f8e047dba4e537183f85dcf01ee596ad6969c63ebb2733f72f702d66a3a` |
| `worker-lib.log` | `a7190d593449fc1a665ee252bed0da45aa78b4aa9368a73e1507d8f5f034c022` |
| `clippy.log` | `5c72f0078922a4123f1f22f03469215d6be0d6faa59e6643173eef865f99b75a` |
| `fmt.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

Target artifact names in this report are relative to
`target/task8c-digest-hex-implementation`. All 14 entries of its artifact index
match their actual hashes. The prior experiment/readiness documents match the
supplied frozen identities; their earlier review is context, not a new timing
experiment performed by this reviewer.

## Specification and preservation

The public `digest(bytes: &[u8]) -> String` API is unchanged. Its sole operation
remains the exact `Sha256::digest(bytes)` on the original caller-provided slice
on every call; the resulting 32 bytes are borrowed into the private encoder.
There is no stored result, cache, extra input, normalization, serialization,
truncation or changed SHA operation.

For each byte b, the high nibble `b >> 4` and low nibble `b & 15` lie in 0..15.
Indexing the fixed `b"0123456789abcdef"` table therefore yields the same two
lowercase ASCII characters as the original `format!("{b:02x}")`. High nibble
comes first, both characters are always emitted, and slice iteration preserves
byte order. Concatenating the 32 pairs gives exactly 64 ASCII bytes, including
leading zeros, for every SHA output. This direct byte argument establishes
output equivalence beyond the finite input fixtures.

One `String::with_capacity(64)` receives these 64 one-byte character pushes.
The only production call to the private slice encoder supplies the fixed-size
SHA result, so its capacity is sufficient without growth on this path. The
source removes the 32 temporary formatting Strings. Actual allocator calls and
native savings were not profiled or established. The implementation uses no
unsafe code, new dependency or new import.

Independent read-only reconstruction, without executing the supplied scope
checker, confirmed all of the following:

- The retained original file equals the normal HEAD version byte-for-byte.
- Regenerating the unified diff from the original and current bytes produces
  exactly the frozen `source.diff`.
- Replacing only the digest/helper region with the original digest and removing
  only the inserted test block reconstructs the entire original file exactly.
  Its original prefix, imports, items and suffix require no other replacement.
- All 179 current Rust paths equal the after snapshot; comparison with the
  before snapshot finds only `crates/vprouter-worker/src/bootstrap.rs` changed,
  all 178 other Rust paths unchanged, and no added/deleted Rust paths.

The call sites consequently remain unchanged, as do the bytes they hash.
Representative source use includes allocation bindings and deployment-owner
unit names in `supervision.rs`, bootstrap configuration/program hashes, and
launch/program/enrollment/transport/resource records. The global equivalence
argument applies to each identity/domain/record consumer, not just allocation
History. No canonical digest, nonce, owner or stored identity migration occurs.
Recomputation and existing live checks remain at every original call. The diff
does not change provider retry behavior, deadlines, custody/proof, IO/framing,
ACK/hold/negative/release/fence behavior or acceptance policy.

## Test quality and retained evidence

The three added tests exercise the actual public helper and its actual private
encoder. The differential oracle independently retains the old SHA computation
and per-byte formatter; it does not duplicate the new nibble lookup. Known
empty/abc literals check the complete expected SHA strings, with empty checked
again after abc. Full String equality also checks length and lowercase shape.

The input test executes 299 old/new comparisons: 256 single-byte values,
29 deterministic binary lengths through 65536 including padding/block
boundaries, four all-byte ramps, eight text inputs, one 65536-byte Unicode
input, and one typed synthetic two-exit allocation JSON input. Text fixtures
include composed/decomposed Unicode, control/NUL bytes and the exact public
synthetic owner-unit input form. Serialization is only a test-input producer;
production serialization is unchanged. These fixtures construct no native
resource and read no current profile, nonce, credential or state.

The encoder test compares 8450 32-byte arrays with the old formatter: all 256
byte values at each of 32 positions, 256 mixed arrays, and two uniform arrays.
Its additional hand-checked ordered 0..31 literal explicitly distinguishes
leading zeros, lowercase a..f, nibble order and byte order. These checks are
meaningful for the narrow representation change and complement the known
vectors and direct mapping argument.

The complete retained logs were read. `tests-first.log` records two missing
`digest_hex` symbol errors before the helper existed; this is a compile failure,
not a claimed assertion failure. `focused-green.log` records four passing
filtered tests: all three new tests and one existing nonce/digest test.
`wrong-nibble-mutation.log` records all three new tests failing, including an
ordered-vector output that repeats the high nibble as the low nibble; the
existing test passes. Thus the new tests demonstrably distinguish this wrong
nibble variant. Separate case/order mutants were not run or claimed.

`mutation.json` records exit 101 and restoration. The final source hash and
subsequent retained worker-library log corroborate the restored implementation:
the latter records 65 passed, zero failed. The Clippy log reaches a successful
finish without warnings, and the fmt log is empty. The implementation report
records the exact commands as worker `--lib` tests, worker `--lib --tests`
Clippy with `-D warnings`, and a bootstrap-only rustfmt check. The logs lack a
separate command/exit envelope, so exact invocation flags and chronology are
report-attributed; this review verifies their retained contents/hashes and
current source binding, not an independently observed process launch. This is
not an actionable source/spec defect in the bounded package.

## Limits and remaining gates

No test/build/timing command was rerun. Only this review file was written; no
source, Git state, VM/SSH/Docker, privileged operation, helper-main, profile,
credential, identity, production/native resource or provider state was changed.
No subagent was used. Repository comparisons were read-only. Existing unrelated
work and the bounded provider retry repair are outside this edit and preserved
by the unchanged-source comparison.

Root retains fresh workspace checks, both static builds, updated normal program
manifests and strict contexts, exact source/archive/artifact binding, the
independently authored preserved 59-link baseline using the 406 canonical DOWN
endpoint plus prior 58, independent artifact/public review, checkpoint/push/tag
and any separately authorized native experiment. This source review does not
perform or accept those steps and supplies no observed live baseline fields.

The earlier host experiment provides a bounded local mechanism observation.
Neither its ratios nor native entry counts establish native cost share,
optimization effect, original two-second fit or Bootstrap completion. Original
398-406 failures remain FAIL; full task8c, ARM, real-client, migration,
performance and release acceptance gates remain open where unaccepted.
