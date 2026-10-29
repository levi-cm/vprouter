# First Bootstrap query: error preservation and diagnostics

2026-10-29. Base `ce41a0ade4a7252b8b9eb75ed61c732fe596d88e` on `rust/v2`.
Implemented only the scope in `task-8c-bootstrap-query-diagnostic-brief.md`
after Root confirmed that checkpoint. Source is frozen for independent review.

Only source edit:
`crates/vprouter-launch/src/attachment/operational/bootstrap.rs`, final SHA256
`b30f7d1879950e1e75d335989279954b64a8c46ccc3f15bdaded65d401e099da`.
The delta is31 insertions and1 deletion. Other source files are untouched.

## Behavior and diagnostic contract

The existing test-only `lab_run` poll-error handler now reports the original
error before looking up its later policy request:

```text
LAB_SECRET_BOOTSTRAP_POLL_FAILURE step=<fixed Step name> reason=<existing Error class> request_present=<bool> query_child_present=<bool>
```

Step names are the ten fixed literals `query_intent`, `query_birth`,
`query_reading`, `query_result`, `intent`, `birth`, `reading`, `result`, `next`,
and `complete`, selected by exhaustive matching of the existing enum. This
adds no runtime validation/access call or clock read.

When the policy request is absent, the handler returns the original
`Err(error)`, replacing the proved diagnostic bug that returned a new
Interrupted error. The native poller already latched the original failure;
this change does not alter that latch or collection/retention behavior. When
the request exists, the same Rc is cloned and the entire previous failure log,
expected injected-fault discriminator, collection and oracle path continue
unchanged after the new diagnostic line.

The existing QueryIntent branch also adds individually `cfg(test)` markers:

```text
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_intent event=ok
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_spawn event=begin
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_spawn event=ok
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_birth_queue event=begin
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_birth_queue event=ok
```

The first appears only after `poll_inspection_intent` returns Some(Intent),
not on pending polls. The next two pairs surround the original query constructor
and service/Birth queue expressions without changing them. There is no added
per-pending-poll output. Missing intent success leaves the post-ACK Intent
construction/verification boundary open; unfinished spawn or Birth queue pairs
identify those respective boundaries. A phase marker is not native completion,
policy installation, or a PASS witness.

No added logs contain IDs, descriptor values, paths, profile/credential data,
argv/env, or clocks. The source adds no enforcement/policy/ownership predicate,
authority, validation call, deadline, retry or cleanup behavior. The only Result
change is preservation of the original error in the test-only missing-request
reporting path.

## Checks and preservation

- Direct `rustfmt --check --edition 2024 --config skip_children=true` on the
  single edited file: exit0, no output.
- `git diff --check -- crates/vprouter-launch/src/attachment/operational/bootstrap.rs`:
  exit0, no output.
- Read-only diff inspection confirmed the bounded source delta. Hash comparison
  confirmed the other two prior diagnostic source files and all six approved
  task8c.1 source files still match their recorded frozen hashes.
- Root's pre-existing concurrent change to
  `.superpowers/sdd/rust-v2/task-8c-bootstrap399-review.md` was observed and
  preserved; it is not part of this implementation.
- Compile, tests, builds and native execution: **NOT_RUN** under Root's stated
  scope. No logger-mirroring tests were added. Rustfmt parsing is not a typecheck.

No subagents, Git mutations, build manifests/contexts, static builds,
privileged/VM/SSH/Docker commands, protected profile/credential/identity access,
cleanup, retry or production changes were performed. This report is the only
non-source file written for the increment. Original runs398 and399 remain
preserved failures. No semantic enforcement fix has been selected; full8c is
ACTIVE and no Bootstrap/runtime/recovery/client/release acceptance is claimed.

## Root review/build/native addendum

Scoped independent spec/qualityPASS; informational insertioncount corrected to31.
Root coherent sourcefbfa3bbc75abe2878216e520f5be6534083cf600 matches202current/
archive/Git inputs; bothstaticELF/payloads/strictpubliccontexts, AMD64filterpreflight,
fmt/diff/focusedstrictClippyPASS. Exact52link preservationbaseline independently
reviewed. Native400 thenFAIL/zero cases, originalOwnershipMismatch preserved at
query_intent with no policyrequest/querychild and no query-intent-success marker.
CanonicaldiskHostIntent present/no birth/facts/verification is durable-write
evidence, not process-localparentACK. Raw400/publicsummary retained. Independent
content+exact6selectorpreservationreviewPASS; RootfreshchecksPASS+6archived, allother
fixture resources retained/no signals/unmounts. Pending-state conflict investigation
continues separately; no enforcementfix or nativeBootstrapacceptance claimed.
