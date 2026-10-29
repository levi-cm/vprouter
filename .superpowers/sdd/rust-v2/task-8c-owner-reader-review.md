# Independent review: closed owner-cost reader

2026-10-29. **Specification: PASS. Quality: PASS. Public-scope/sensitivity:
PASS** for the maintained parser and requested implementation report. No
actionable finding or required revision was identified. This is a reader review,
not an owner diagnostic implementation, native metric or runtime acceptance.

## Exact reviewed artifacts

| Artifact | Independently verified SHA256 |
| --- | --- |
| `task-8c-owner-reader-brief.md` | `5014888be5770c229f6877a086e055e65a6d8db564aba780e139f9376157464f` |
| `task-8c-owner-reader-report.md` | `94d822d966f8601840e46191d271485e9564c9871d0e9daf11cd5e7aa6eedc09` |
| Maintained `parse-bootstrap-cost-diagnostics.py` | `4392b39327f3f9c518b5eeb8e0bacbe1eb76d4779e00b45fd2addc84ee6bcd67` |
| Saved original parser | `4309e4881c9aaeb27191ca35957a23f215a9764d37f5afdb00820aafd0518206` |
| `target/task8c-owner-reader-local/source.diff` | `1a84e12cb5c8a99b486ca935151ea587369a663eca49724782ea99b30ac04d30` |
| `artifact-hashes.json` in that directory | `64cad5f250ad17c177510561dfe2144e57c1e787d98088f762b574486ce57d37` |

The complete original/final parser, full diff, brief/report and saved check
source/logs were read. Recomputing the unified diff reproduced its frozen bytes.
Removing only the new category constant, optional parse block and optional
output assignment reconstructed the complete original parser exactly. No
existing parser statement was rewritten. The evolving two-file Rust owner
diagnostics were not inspected.

## Contract and quality assessment

The optional marker is handled strictly: every occurrence of
LAB_SECRET_BOOTSTRAP_OWNER_TOTAL anywhere in a stderr line is routed to fields
with the required exact prefix. Bare, tabbed, leading, embedded and suffixed
malformed occurrences cannot silently look like an absent extension.

Each row requires exactly family/category/calls/elapsed_ns/measurement/grouping.
The existing unique-field parser rejects duplicates; fixed measurement and
grouping values are validated and removed before output. Existing canonical
decimal parsing enforces nonnegative u64 calls/u128 nanoseconds, rejecting signs,
leading zeros, alternate numeric forms and overflow. Zero calls require zero
elapsed time. The new owner table correctly has no count-only category: positive
duration remains valid for every category with positive calls.

The ordered tuple comparison requires exactly query/policy/other times the five
brief categories, in order: owner_host_preflight, owner_record_validate,
owner_namespace_identities, owner_current_identity_chain, owner_record_clone.
Thus a present extension has exactly15 rows; omissions, repetitions, extras,
foreign labels, retained-category substitutions and reordered family blocks or
entries cannot match. Valid all-zero rows still form a nonempty15-row list and
produce owner; a completely absent extension leaves owner absent.

The old16MiB bound, duplicate JSON-key handling, source bindings, optional
original2s clocks, required13 wrapper/30 nested rows, optional exact24 retained
rows and both retained count-only constraints remain unchanged. No owner or
nested totals are summed; the old wrapper-only sum and original output fields,
spelling/order/formatting remain intact. Owner adds only its optional output key.

All validation occurs before exclusive output creation. Existing open('x')
continues to refuse a preexisting destination without overwriting it, and the
unchanged final chmod sets successful output to0600. This is the existing final
mode behavior; the extension does not introduce a stronger creation-time mode
claim or change handling of later filesystem failures. The small, explicit
addition follows the established retained-reader style and adds no new runtime
I/O, native/state authority or control-flow coupling.

## Retained evidence and fresh read-only checks

All345 artifact-manifest entries were independently hash-verified. The retained
checks.py was read rather than executed; it invokes the maintained parser,
constructs expected owner rows from independent literal labels/values, compares
complete output bytes and checks refusal destinations. It does not import the
new parser implementation as its expected algorithm. The retained AST and
compatibility/exclusive logs agree with verification.json and source-freeze.json.

Fresh read-only comparisons confirm before-change, after-change and historical
outputs are byte-identical for both real records:

- Actual405: `f743c668eaefc61a3681dbcf94f2c8e269d6d69bb8c8f26f690aa1fe24c039e3`;
  owner absent, retained absent.
- Actual407: `2a61b8c7774c5461c99ac2ed51d73a1200e2492da5bfd283a8ff90d5a33a32ff`;
  owner absent, original24 retained rows preserved.

Both saved successful outputs currently have mode0600. Current raw405/raw407
hashes also match source-freeze.json; historical evidence was not rewritten by
this review.

All six stored synthetic successes were independently compared byte-for-byte
against historical metadata plus the exact fixture hash and15 literal expected
owner rows: normal7calls/11ns, zero0/0 and u64/u128 maxima, with and without the
retained table. Every other output value and wrapper total stays identical, and
successful saved modes are0600. These are synthetic parsing fixtures, not
observed owner costs.

The112 named retained results comprise two compatibility cases, six successes
and104 refusals. The latter cover62 owner cases,19 original-contract cases and
all23 prior retained refusals. Saved results report nonzero exits/no destination;
fresh inspection confirms all104 destinations absent, stdout empty and retained
stderr nonempty. Cases exercise closed order/labels/fields, marker variants,
numeric spelling/bounds, zero-call duration, original input/binding/clock/JSON
constraints and both retained count-only constraints. No identical parser checks
were rerun. The existing exclusive destination still contains its exact sentinel
bytes and original0640 mode, consistent with the retained refusal log.

The saved red results retain original-parser acceptance of the bare marker and
omission of valid owner rows. Those failed new expectations precede the edit;
they are not represented as final behavior. The source-freeze/check records
report203 application build inputs unchanged at the implementer's freeze. This
review did not reopen evolving application source to repeat that unrelated
preservation check.

## Publication and verification limits

The new output exposes only validated closed family/category names and bounded
counts/nanoseconds. It copies no raw lines, request contents, arbitrary strings,
paths, identities or credentials from owner markers into metadata. Existing
source hashes, boundary fields and the local destination-path success message
retain their prior meanings. The report contains source/evidence hashes, fixed
labels, commands and limitations, without private runtime payloads. Publication
scope is the maintained parser and requested report; target fixtures, check
script, raw inputs, local outputs/logs and captures remain excluded.

Only this review file was written. No Git/source mutation, test/build/helper main,
VM/profile/privileged/native operation or subagent was used. Fresh verification
was limited to reads, hashes, diff reconstruction, saved-output comparisons and
filesystem metadata. Retained AST/subprocess results were inspected, not rerun.

No owner-inner native metric exists in this evidence. The separate emitter,
its two-file Rust source, artifact binding and any future owned native run need
their own authorization/review. This PASS establishes no CPU/exclusive-cost
attribution, optimization effect, original2s fit, completed Bootstrap or runtime/
client/ARM/release acceptance. Original407FAIL/zero cases and earlier failures
remain unaccepted; Root owns future staging/push and subsequent gates.
