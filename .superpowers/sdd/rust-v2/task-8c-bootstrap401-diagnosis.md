# Run401: first HOST query Result and producer ancestry boundary

2026-10-29. Read-only source/evidence localization requested by Root. Only this
report was written. No Rust edit, build/test, VM/SSH/Docker/privileged operation,
Git mutation, retry, selector/resource cleanup or subagent was performed. Source
remains frozen. Root's concurrent progress/verification/attempt401 documents were
observed and preserved.

## Observed failure and source binding

`target/lab-state/actual-program-run-401.json` SHA256
`40a6ca6c3dc9b430a87e5dba11a4b4446f9ee71a6f825aea2a514d5b2d6e9bc7`
records source `cc0081baeb14caaa15fd4577258f6d01cc6de8bc`, archive
`1c2ece5f0707a41d7de8a28ac9d59c4dbe20a3cd5c32af8c3c767f45502a5d67`,
202 verified build inputs, aggregate
`ac3db8ba5dc32abaf8bef7d63a0736cef4319f2b81212329f020bc813b848fad`,
and artifact
`f8e6c9b1fc0669b1fe937ff543a7773d3d072bf65ffebb7d2c0c33404b1f83c1`.
The corrected binding location is
`target/continuation-20261029T134857Z/bootstrap-pending-progress-20261029/directory-binding.json`.

Run401 is FAIL, exit1, zero completed case witnesses, outer wall12.485s. Its
303 stderr lines include90 journal inventory/verified pairs and73 phase lines.
The final sequence is:

```text
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_intent event=ok
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_spawn event=begin
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_spawn event=ok
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_birth_queue event=begin
LAB_SECRET_BOOTSTRAP_PHASE stage=bootstrap.query_birth_queue event=ok
LAB_JOURNAL_STAGE stage=io_inventory
LAB_JOURNAL_STAGE stage=io_inventory_verified
LAB_JOURNAL_STAGE stage=io_inventory
LAB_JOURNAL_STAGE stage=io_inventory_verified
LAB_SECRET_BOOTSTRAP_POLL_FAILURE step=query_result reason=CgroupMismatch request_present=false query_child_present=true
secret_bootstrap_lab: cgroup_mismatch
```

This is progress past run400's first pending Intent conflict: Intent returned,
the original query constructor returned and its Birth was queued. Reaching the
`query_result` step additionally requires the original Birth/Gate release, query
child polling returning Verified, and Result queue operation returning. The two
later writer inventories fit Birth and Result. There is no first policy Request
or completed Bootstrap witness. Whole-family native acceptance remains open.

Root's retained read-only failure snapshot
`target/lab-state/secret-bootstrap-failure-run-401.json` SHA256
`cd82789829434e0b8f15ccdd36391c7b01d86b2cd1e3867f6f98ae27b49c9e7d`
binds the same raw record and source. Its first BootstrapHostRecheck has durable
Birth/facts/verified_at, two later query slots are null, and Bootstrap policy
history is absent. These durable bytes do not independently prove parent ACK or
Verified::accept. The original gateway is retained/running; the owner unit is
already absent at Root's later inspection. That later absence is not proof that
owner cgroup disappearance caused the original error.

## The recorded step includes policy Request construction

`attachment/operational/bootstrap.rs:420-439` does all of the following before
changing `self.step` from QueryResult to Intent:

1. `OperationalOwner::poll_query_result` checks retained exact20 custody and
   Binding's exact typed Query Result progress, then polls the original Server.
2. `Server::poll_inspection_result` verifies original service, polls/accepts the
   original journal writer and constructs/verifies its Receipt.
3. `kernel::docker_query::Verified::accept` verifies that Receipt, original
   deadline, sockets and successful native reap, then moves the same request and
   facts into Accepted.
4. `Request::new` checks the original owner, Source, query/service, process pins,
   and acquires/verifies the fresh eight producer/ancestry pins.
5. Only after `Request::new` returns does `self.request = Some(...)` occur.
   Bootstrap policy Intent is then queued and the step changes to Intent.

Consequently `query_result` plus `request_present=false` permits an error in
steps1-4, including the post-ACK Request/Pins constructor. It does not by itself
identify a journal Result polling failure. The log has no marker after Result
receipt/accept or inside Request/Pins, and no `query_accepted` state flag.

## Concrete source-established ancestry defect

The highest-value new boundary is:

```text
Request::new                         operational/bootstrap.rs:76
 -> Pins::new                       operational/producer.rs:41-42
 -> mount::Request::original_producer_ancestry   attachment/mount.rs:175-179
 -> PinnedProcess::producer_ancestry            process.rs:577-597
 -> PinnedProcess::verify_producer_ancestry     process.rs:599-632
 -> statat(root, "..") compared with fstat(root) process.rs:615-629
```

The original retained `cgroup_root` is opened from the host `/sys/fs/cgroup`
(`process.rs:470-477`). Initial mount parsing requires the cgroup2 filesystem
root `/` mounted at exactly `/sys/fs/cgroup` (`process.rs:332-349`). The ancestry
verifier first revalidates the admitted process, checks root descriptor equality,
directory trust and both filesystems. Its first named relation is then:

```rust
(root, "..".to_owned(), root)
```

The resulting stat tuple must equal the cgroup root's tuple or it returns
CgroupMismatch. For an ordinary host mount at `/sys/fs/cgroup`, relative `..`
crosses the mounted filesystem boundary to `/sys/fs`; it is not the cgroup mount
root itself. This relation is invalid as a host cgroup ancestry requirement.
It is reached before producer control-file pin opens or Pins slot verification.
`process.rs` was not modified by the thirteen-file pending-progress increment;
the repaired query progress now permits reaching this later first-use boundary.

Root independently captured the read-only same-guest oracle
`target/task8c-pending-20261029T133358Z/cgroup-root-dotdot-oracle.json`, SHA256
`c8d0d7e1117ef9c3029db1e09b5f46a44247086d2b592701f039b9aec347db93`,
bound to run401's raw-record hash and source. It observes:

| Observation | dev | ino | permissions | owner |
| --- | --- | --- | --- | --- |
| current `/sys/fs/cgroup` root |27|1|0555|0:0|
| root-relative `..` |22|2|0755|0:0|
| root-relative `system.slice` |27|67|0755|0:0|

Its mountinfo identifies cgroup2 mountroot `/`, mountpoint `/sys/fs/cgroup`.
The oracle explicitly records `current_namespace_only=true` and
`original_owner_return_trace_proven=false`. The root's decimal mode16749 is
040555, not040755; this mode is permitted by the existing trust checks.

Thus an actual source defect and a matching current-guest predicate are proved.
They strongly explain run401 if Request::new reached that boundary. They are
**not** a captured return trace from the original owner, nor proof that no earlier
CgroupMismatch predicate fired. No global validation should be weakened based on
the outer error class alone.

## Other reachable CgroupMismatch predicates

The following are still possible from the recorded outer step. They delimit the
remaining uncertainty and should not be collapsed into a definite runtime cause:

- Retained OperationalOwner custody rechecks original producer-binding and HOST
  receipts. Producer-binding Request's six original pin checks
  (`attachment/producer_binding.rs:128-135`) return CgroupMismatch for fstat/fstatfs
  errors, lost registration, changed dev/ino/mode, nonroot ownership or wrong
  filesystem. Source retained checks include its original producer parent trust
  (`attachment/quarantine/producer.rs:139-147`). These are repeatedly exercised
  before this new boundary, so a new drift would need separate evidence.
- Binding/receipt custody also propagates owner-domain verification errors.
  `OwnerDomain::record` calls `verify` (`supervision.rs:125-145`), including group
  lookup and `/proc/self/cgroup` access. Owner-domain read/lookup failure can map
  to CgroupMismatch; mismatched recorded identity itself commonly maps to
  OwnershipMismatch. No such read/lookup failure was captured in401.
- `Request::new` revalidates the admitted gateway process before acquiring pins
  (`bootstrap.rs:67`). `PinnedProcess::revalidate` checks the fixed cgroup path,
  pinned cgroup identity and root device, then actual cgroup membership
  (`process.rs:706-712,728`; cgroup path/membership helpers). Process ancestry
  acquisition repeats that revalidation. A changed path, group or membership
  can therefore fail before the invalid root-`..` relation.
- Ancestry acquisition also maps failure to open `system.slice` with
  BENEATH/NO_SYMLINKS/NO_XDEV to CgroupMismatch (`process.rs:588-595`). Verification
  refuses a different root descriptor (`:607-608`), stat errors and mismatched
  named root/system.slice/docker-scope relations (`:623-629`). Its directory-trust
  and filesystem helpers return UnsafeInput/UnsupportedPlatform for their own
  failures, rather than necessarily this error class.
- If ancestry acquisition succeeds, `Pins::new` maps each of four read-only
  cgroup control-file open failures to CgroupMismatch
  (`operational/producer.rs:62-69`), and each added pin fstat failure likewise
  (`:83`). Its final `verify_slots` maps fstat/fstatfs failures or lost token,
  identity/mode, nonroot ownership, group/world write, incorrect file/dir type,
  incorrect cgroup2 filesystem or writable access mode to CgroupMismatch
  (`:148-165`). Parent/group dev/ino disagreement also returns that error
  (`:168-174`), then the same named ancestry verification is repeated (`:176-181`).

The scalar typed Result proposal checks and new PendingWriter ownership core
themselves return OwnershipMismatch/Deadline, not CgroupMismatch. They can
propagate the surrounding retained-custody checks above. Raw `Verified::accept`
does not itself construct producer ancestry, and its direct acceptance predicates
use the existing receipt/deadline/socket/reap errors. First Bootstrap policy
source/descriptor checks only begin in Request::new, before a Request is installed.

## New held-query orchestration

The new test-only orchestration arms the existing before-sync hold on the first
original query Intent, index87. Every held checkpoint/writer read/release first
verifies that same typed query progress and original custody. While held it
requires ordinary Context and the originally retained Source history to return
exactly OwnershipMismatch. An unexpected CgroupMismatch from those tests would
make the loop return a replacement OwnershipMismatch before `pending.poll`, not
the observed `POLL_FAILURE ... query_result ... CgroupMismatch` line.

Intent success and the later QueryResult step mean the hold was released and the
same query advanced; no alternate request, native child, clock or deadline is
introduced. Two existing held polls add bounded scheduling delay inside the same
original two-second window. A deadline failure would be Deadline. The hold does
not change cgroup ancestry or make a root mount's parent equal itself. It is not
credible evidence for relaxing producer or ownership checks. Its complete success
witness remains absent because the whole operation failed before final output.

## Smallest next proof/fix proposal, not implemented

The same false assumption exists in the later confined/native-role path:
`vprouter-native-role/src/producer_bootstrap.rs:264` calls
`verify_link(self.root, ROOT_PARENT, self.root)`. Its exact seccomp ancestry rule
at `:239` permits that same root-FD/`..`-pointer pair. A launch-only correction
would leave this later policy-constructor/runtime boundary broken. The confined
verifier maps the mismatch to its Error::Descriptor; it cannot be run401's
original failing native Bootstrap child because no policy Request/child exists
yet. Existing renamed-ancestry tests at `:335-376` exercise individual forward
links and their replacement/symlink refusals, but omit this complete edge set.

The narrow correction is to replace the invalid launch root-self-parent edge with the
actual internal reverse edge:

```rust
(system, "..".to_owned(), root)
```

Retain original root Rc/descriptor provenance, admitted-process revalidation,
trust/type/filesystem checks, root-to-system.slice exact named identity, and
system.slice-to-exact-original-Docker-scope exact named identity. This proves the
actual immediate ancestry rather than deleting the check or allowing arbitrary
parent traversal. It requires no new descriptor getter, authority constructor,
placement/policy permission, mount/namespace operation or deadline extension.

Make the corresponding confined verifier use
`verify_link(self.system_slice, ROOT_PARENT, self.root)` and change only its first
exact ancestry syscall rule's directory FD from root to system_slice. Keep the
same fixed immutable `..` pointer, syscall, AT_SYMLINK_NOFOLLOW flags, four-rule
count, remaining forward edges and original parent-to-exact-producer-group edge.
Rename the private constant if helpful to avoid a misleading root-parent name.
Do not retain both FD permissions or widen any old WireGuard role, syscall,
path, descriptor or authority. All original root/cgroup2/trust/inventory/identity
and confinement checks remain required in the launch and native-role layers.

Before authorizing implementation, Root can extend its read-only oracle to
observe `system.slice/..` equal the same cgroup root and the exact original Docker
scope under system.slice. These current-namespace facts remain distinct from
an original owner return trace.

For a local regression, exercise the same private named-edge comparison core
with real borrowed directory FDs and a temporary hierarchy named
`system.slice/docker-<fixture>.scope`. Its root has a distinct external parent:
the old root-self-parent test must fail at runtime, and the corrected real
parent/child relation must pass. Refuse foreign root/system/scope FDs and replaced
named children without moving resources. The helper must validate only borrowed
edges; the existing production caller must retain all cgroup2/admission checks,
and the fixture must not manufacture a full PinnedProcess/Source/OperationalOwner
from scalar metadata. If extraction would broaden scope, use Root's real
read-only native ancestry check instead and label local full-chain tests NOT_RUN.

Apply the same real-FD edge regression to the confined verifier's complete
named-edge core, retaining its separate cgroup2/type/ownership checks. Keep the
existing renamed/replaced/symlink negative fixture. Its exact-filter regression
should consume the actual Ancestry-generated rule list, allow the original
system_slice-FD/fixed-`..`-pointer/NOFOLLOW stat, and deny the former root-FD/that
same pointer tuple, a foreign FD/path pointer, follow mode and all pre-existing
forbidden operations. The old role must still deny the Bootstrap ancestry
extension. Test behavior rather than asserting source text or only constructing
a generic unrelated rule array. Root retains cross-architecture native/filter
validation responsibility after a coherent reviewed source change.

A minimal fixed-label diagnostic bracket around Result receipt return,
Verified::accept, Request construction and original producer ancestry acquisition
would capture the exact remaining boundary on a future reviewed candidate if
needed. It should preserve the original error, add no per-pending-poll output,
and log no profile/cgroup/path/descriptor values. It is a proposed diagnostic,
not required permission to weaken a check or repeat the identical candidate.

Root should obtain review and coherent artifact/source binding for any authorized
correction, then execute a new native attempt with the held-query/policy oracle.
No identical retry is proposed. Run401, its selectors, gateway and canonical/
mount resources remain retained failures. Full Bootstrap/8c/client/release
acceptance is not established by the current oracle or previous component PASS.
