# Task 12 fixture migration preparation

PREPARATION ONLY. Task8c runtime, ARM and client acceptance remains OPEN. This
increment implements a local synthetic directory transaction and a public lifecycle
contract. It does not validate any real installation, authenticate native receipts,
install a service, read credentials, back up Tailscale state, or authorize release.
The production CLI's review-only inspect/plan behavior is unchanged. No native
code consumes these fixture journals or plans. Independent review is required.

`vprouter_core::migration` extends the existing core schema validator,
`AllocationRecord::from_structure`, naming and allocation storage lease. It uses
the same `.allocations.lock` inode/flock and protected descriptor checks, rather
than a second allocation store, nft implementation or native lifecycle. Task9–11
fleet/client preparations and the existing netfilter authority boundary remain
binding. The engine has no network, subprocess, timer, service-manager or unsafe
code. The **test harness only** launches its own exact test executable and sends
SIGKILL to that child itself; it never signals Cargo or another project.

The fixture tree is intentionally incompatible with a real legacy deployment:

```text
fixture-root/                        owner=current euid; mode0700
  offline-migration.fixture          exact synthetic-only-v1 newline; mode0600
  .allocations.lock                  PREEXISTING regular single-link mode0600
  inventory.json                     strict public fixture declaration
  opaque/                            mode0700
    profile.wg                       synthetic opaque regular file, mode0600
    state/                           synthetic opaque directory, mode0700
      tailscaled.state               synthetic bytes, metadata-only O_PATH custody
  current/                           REAL public directory, mode0700
    config.json                      strict legacy unversioned public config
    image.fixture                    synthetic image bytes, not an OCI image
    router_runtime.py, router.nft, Dockerfile, docker-compose.yaml
    host/orchestrate.py, host/vprouter@.service
    host/collector_services.py, host/collector-services.conf
    host/NAME.json                   only explicitly declared public custom hooks
  staged/                            created by apply; public data only
  journal.json                       checksummed plan + direction + progress
  .journal.pending                   bounded incomplete write, if interrupted
```

There may be unrelated root files; the engine neither inventories nor removes
them. The public release directory has a closed filename set: unknown files,
directories, aliases and special files refuse before their data is opened. State
and profile paths in configuration are **data**, never host paths to open. Only
fixed fixture `opaque` tree receives metadata-only custody: the container,
`profile.wg`, `state`, and **every descendant** of `state`. Directories are
enumerated through checked directory descriptors; each file leaf gets only
O_PATH/NOFOLLOW metadata access, never a data descriptor. Admission refuses
symlinks, file hardlinks, special files, foreign devices/owners, nonprivate modes,
ambiguous names, and trees exceeding the custody bounds. Pins bind device, inode,
size, mode, owner, group, link count and type. O_PATH handles retained for the
`FixtureTree` lifetime prevent reuse of admitted inode numbers. Reinspection
compares that initial tree; recovery additionally binds the original plan before
marker/journal reads or cleanup. A fresh admission cannot reconstruct inode
history from before its first inspection; fixtures must begin with synthetic data.

Every admitted or plan-bound protected inode is excluded **before** public data
opens, even under a public, pending, staging or retained name. Public access first
checks an O_PATH descriptor against that set, then opens with NOFOLLOW and checks
fstat plus the named inode again. Cleanup also proves that bounded raw bytes form
an engine-planned file prefix or a valid next journal prefix and rechecks the
opened descriptor at unlink. Unknown bytes are retained and refused. Opaque data
is never read, hashed, copied, restored, deleted or serialized. Tests alone compare
synthetic placeholders independently before/after cutover and rollback.

These checks enforce non-mutation and metadata custody of the admitted synthetic
opaque tree, and refuse descendant replacement/addition/removal. Metadata pins
cannot detect an in-place, same-size secret-content edit. Same nodeID/IP/
approval/server assertions are public fixture observations, **not** secret-content
attestations or authenticated native evidence. A real driver still needs reviewed
stopped-state custody and private backup/restore outside this engine; it must never
interpret these metadata pins as unchanged-credential proof.

## Inspection and plan

`FixtureTree::open(root)` requires a canonical ASCII absolute path, protected
ancestors (the existing sticky-temp exception is for fixtures), exact private
owner/mode, marker and existing lock. Missing locks are never recreated by this
API. Opening establishes metadata custody; inspection and plan-bound operations
validate the exact marker bytes before public inspection. Inspection takes the
existing exclusive flock but writes no file or state.
It reads only allowlisted public assets; image and source checksum declarations,
legacy names/paths, versions, declared hooks and public node/IP/approval/server
facts are fixture inventory, not host discovery. Layout tags cover current main,
retained retry528fece and retry84fb353. Their synthetic runtime descriptions retain
the source-observed provider-data return and single bounded retry distinction.
No original source, credential, enrollment or stopped-state copy is used.

`Inspection::plan(Request)` validates the complete existing schema2 structure,
allocations and adapter grammar **without** a profile/key reader. It requires one
enabled Mullvad `primary`, the same state/profile paths and expected provider
server, pinned synthetic image content matching its declared SHA256, and exact
source bundle checksums for old and new public assets. Stable primary exit ID is
separate from preserved deployment service/container/uplink names. Names use the
existing schema calculator; no enrollment, server selection or direct fallback
occurs. A new release format must retain the exact original opaque state format:
this engine has no state-format conversion capability.

Unsupported declared host, unknown ownership, absent/mismatched provenance,
unknown hostname users, undeclared custom hook or missing/extra adapter refuses
before cutover. `hostname_users=complete_fixture_declaration` is an explicit
fixture declaration; it is not automatic dependency discovery. Every dependency
names its hook, adapter and stable-node or declared-hostname selector. Unknown
hostname selectors block rename. Hook autodetection is never execution authority.

The plan contains the complete old and new public bundles, public metadata pins,
unchanged opaque metadata and exact intended config/allocation/wrapper changes.
Tailnet IPv4 and canonical fd7a:115c:a1e0::/48 addresses, including IPv6 default
approval metadata, may be retained as identity facts; they grant no IPv6 forwarding
authority. Explicit empty/null hostname refuses; only a missing legacy hostname
defaults to the existing primary instance.

Its canonical SHA256 binds every inspected public byte (including inventory JSON
spelling), inode/device/size/mode/owner/group/link-count/type pins, all declarations and generated data.
No timestamps, boot-time guesses or random IDs enter fingerprints. Reading the
same tree and request gives identical sorted output. A fingerprint is a content
binding, never provenance authentication. Changed inputs refuse apply. New public
bundle checksums are rechecked before directory exchange, at terminal journal
publication, and when returning terminal results.

## Ordered contract and rollback

All obligations bind the exact plan fingerprint, ordinal, primary exit, service,
container/uplink names, stable nodeID and unchanged state/profile paths. Receipts
must echo that scope and carry the required structured observation. There are no
optional verification booleans or shell commands in the engine.

1. Require independent quarantine (enforcer distinct from old supervisor).
2. Stage and fsync the complete public release/image/checksums/config/allocations.
3. Drain each sorted adapter; pre-start stop; stop the scoped old service;
   post-stop stop; verify **all** identity users stopped.
4. Require stopped-state retention metadata, exact old release checksum, original
   state format and same nodeID/IP/approval/server facts. No secret backup is made.
5. Exchange `current` and `staged` with one `renameat2(RENAME_EXCHANGE)`, retaining
   the complete old real directory in `staged`. There is no two-rename gap or
   symlink activation. Restore/verify same public identity/IP/approvals/exact
   server, then rename that existing node, never recreate it.
6. Require fixture mode/isolation/client check; scoped service start; sorted
   adapter rebind/post-start start/health check; durably commit the fixture result.

The fixture checker enforces stop-before-start and rejects a nonempty identity-user
set. The model driver tests reject duplicate starts. This is an ordering contract,
not proof that a real process is stopped or clients are protected. Every plan and
JSON result says synthetic_fixture_only, client coverage unverified and quarantine
required. There is no quarantine-release action, protected status or native driver.

Explicit rollback first requires independent quarantine, drain/stop and all users
stopped. **Both** the old release checksum and the retained compatible state
format, metadata and public identity must match before reversal. It exchanges back
the old real directory when necessary; verifies the same nodeID/IP/approval/server
before restoring the old hostname; then follows the scoped start/adapter ordering.
Missing compatibility, state mismatch, wrong identity/IP/server/approval, failed
adapter or any wrong receipt durably requests cleanup, then requires independent
quarantine before bounded scoped stop/adapter/all-user checks. Once quarantine is
affirmed, adapter failure does not suppress service stop or the all-user check.
Terminal `offline` is published only when quarantine and **all** cleanup
obligations succeed. Failed cleanup returns an error with nonterminal retry-only
intent; both resume and rollback retry cleanup and cannot start a service. An
unproved quarantine never licenses stopping the old supervisor; no native offline
state is claimed from a failed assertion. An old image checksum alone can never satisfy this
contract. The engine leaves opaque data in place; it does not attest byte equality
or implement a native backup.

Committed and rolled-back journals replay without writes or lifecycle calls.
Explicit rollback is the only reversal of a committed transaction. Offline is
terminal; apply/resume/repeated rollback cannot revive it. Terminal result checks
refuse active-tree drift without rewriting the journal. There is no late-callback
API. Synchronous receipts with wrong plan/scope/ordinal or observations refuse.

## Journal, recovery, filesystems and limits

Each record includes schema, checked u64 generation, complete plan, direction,
monotonic completion cursor, cleanup intent and terminal outcome, with a checksum
of the record. Planning checks the full worst-sized journal envelope, including
maximum-width counters/cursor and the longest terminal spelling, so an admitted
plan cannot run out of encoding capacity at a later transition.
Write to an exclusively created mode0600 pending file in bounded4096-byte writes;
verify the still-named private file; file fsync; publish by atomic rename; fsync
parent. Initial publication uses NOREPLACE. Existing journals are checksum/content
CAS checked before replacement. Torn/malformed committed journals are retained
and refused, never reset. Partial pending writes are removed only on explicit
resume/rollback under the same lock, after protected-tree admission and validation
against byte prefixes of admissible next journal records for the exact plan. Apply
refuses leftover staging/pending evidence instead of silently adopting it.

A nonterminal resume without cleanup intent repeats quarantine, stop, state/identity verification and
restart obligations even when the journal already recorded those actions. The
cursor prevents durable progress regression; it never waives current safety work.
Known partial public staging is validated as bounded raw byte prefixes of the
planned new files before bounded cleanup/recreation. A truncated UTF-8 codepoint
does not require decoding; unrelated or mismatched bytes refuse cleanup. If
exchange occurred before journal publication, old/new content classification
avoids exchanging twice; parent fsync repeats. Either the old or new COMPLETE
bundle occupies `current` at every interruption. The old backup remains retained.
If reversal intent was interrupted before publication, resume may see the prior
complete committed new state; explicit rollback durably establishes reversal.

Exclusive flock covers inspection/plan input capture and every migration operation.
Two actual racers are tested; only one enters the lifecycle executor. Kernel
process death releases flock, but the inode is **never** unlinked or replaced by
recovery. Lock contention is Busy. Stale logical transaction recovery is explicit
resume/rollback, with exact plan and journal validation; no age/timeout lock break.
A missing/replaced/aliased lock refuses. Checked generation overflow refuses;
there is no growing history, retry queue or generation directory accumulation.

Every file/dir is descriptor-relative, NOFOLLOW, same-device, private owned;
regular files must have one link. Existing allocation ancestor/lock checks are
shared. Root replacement, symlink/hardlink aliases, permissive files, changed
inputs and rename-over attacks refuse. Custody is captured without taking a data
lock descriptor; each operation excludes admission and original-plan protected
inodes using O_PATH before flock acquisition, then rechecks the metadata tree
under that lock. Held lock-name checks themselves are metadata-only. Exchange has no cross-device or unsupported
filesystem fallback. These guarantees assume cooperative writers within the private
owner directory; check+syscall cannot defeat a malicious same-UID/root writer who
can bypass permissions or forge metadata. No privileged mount/bind-mount attack
or hardware power-loss qualification was performed.

Limits: JSON2MiB (checked before decoding), source files128KiB each, complete
public bundle512KiB, per-directory32 entries, opaque tree128 entries/depth16
(including its container and roots), opaque components63 bytes, declaration16 dependencies, canonical
path256 bytes, names63 (legacy instance/hostname2–50 with initial lowercase
letter), observation IPs16, adapter argv64 x256 printable ASCII,
existing action timeout1–300 integer seconds and required idempotence. Duplicate
JSON keys at every nesting, unknown fields, traversal, percent/backslash/control/
Unicode path spellings, invalid identifiers and oversized inputs refuse. All
untrusted typed constructors are revalidated at consumers. Invalid directly
Serde-decoded plans emit no lifecycle obligations.

There are **no host-time operational entry points**: apply/resume/rollback/status
use durable sequence, not elapsed time. There is no expiry/refill/automatic recovery
clock. Negative/NaN/fractional/overflow timeout declarations refuse at the integer
parser; zero/>300 refuse shared adapter validation. No clock can discard quarantine
or rollback obligations. Future native deadline enforcement must use the existing
reviewed monotonic-clock and fail-closed watchdog contracts at every callback.

## Agent instructions and compatibility

Only synthetic tempdirs may be supplied. Never point this API at a real install,
add its marker to one, copy real profiles/state into fixtures, or invoke native
legacy status (which can mutate quarantine). Prepare fixture ownership and all
public declarations first. Keep the plan JSON separately before starting; resume
requires that exact plan even if the initial journal never became durable.

Use the library methods `open -> inspect -> Inspection::plan -> Plan::encode`.
Reopen with `Plan::parse`, then `apply(&plan, fixture_driver, fault)`. On any error,
retain quarantine-required/offline disposition and all evidence; explicitly use
`resume(&plan, ...)` or `rollback(&plan, ...)`. Do not manually delete locks,
committed journals or backups, normalize corrupt state or reset identity. Validate
complete current bundle, checksum journal, exact public identity receipts and
independently compare synthetic opaque bytes. Repeat resume twice and compare
journal bytes. Real safety may never be inferred from these fixture assertions.

Library-only JSON dispatch is `FixtureTree::execute_json`, accepting:

```json
{"operation":"inspect"}
{"operation":"plan","request":{"configuration":"FULL_SCHEMA2_OBJECT","release":"FULL_PUBLIC_BUNDLE_OBJECT","provenance":"FULL_PIN_OBJECT"}}
{"operation":"apply","plan":"FULL_PLAN_OBJECT"}
{"operation":"resume","plan":"FULL_PLAN_OBJECT"}
{"operation":"rollback","plan":"FULL_PLAN_OBJECT"}
```

The strings above are documentation placeholders, not accepted payloads. All
objects must be complete strict schemas. Results carry scope/client/quarantine
labels. There is no production CLI command or activation flag for these actions.

Wrapper generation is pure `Vec<Shim>` data: legacy router-runtime --status
(no stdout; unknown gives exit1), --probe (legacy public_exit/relay/tunnel fields,
DNS/IPv6 not_tested), and host status/validate. Each maps to Rust CLI argv arrays
with a synthetic config path; primary service name and stable primary exit are
separate. They execute nothing and install no script or persistent Python. Actual
runtime JSON translation/freshness and host wrapper acceptance remain unimplemented;
constant successful legacy DNS/IPv6 claims are never generated here.

| Environment / operation | Preparation support / actual acceptance |
| --- | --- |
| Main /528fece /84fb353 public synthetic stopped-state layouts | covered in tempdir tests; real installations NOT_RUN |
| Declared custom hooks, collector pre-stop/post-start/post-stop ordering | typed fixture contract only; no arbitrary exec |
| Debian13 systemd, Arch systemd, Void glibc runit | declared enum admission only; service integration NOT_RUN |
| Unknown ownership/hostname users, missing adapters, unpinned/mismatched source/image | blocked before cutover |
| State-format conversion or identity replacement/cloning | unsupported; refuse |
| Real OCI import, kernel quarantine, protected-client checks, service calls | unimplemented; NOT_RUN |
| Remote installations / remote SSH | outside local-only scope; never requested |

Future **systemd** procedure must establish an independent persistent quarantine
unit with verified readiness before old service stop, new service start or any
protected workload. Capture readiness precedes protected traffic. Preserve the
primary instance and collector stop/start/stop order. `After=` alone is not
readiness; failed guard/capture/adapters leave offline. Ordinary ExecStop retains
guards; only separate exact-owned uninstall may remove them. No unit is installed.

Future **runit** procedure must establish independent quarantine and capture in
boot stage1, gate stage2 protected services on actual readiness, and retain guards
through finish/stop. Preserve the same scoped adapter and rollback barriers; no
broad Docker/containerd restart or unknown hook eval. No run/finish script is
installed. Until native prerequisites and Task8c pass, the exact instruction for
both service managers is **do not run a real migration**.

## Evidence boundary

The report records exact behavioral REDs, validation commands/exits, source hashes
and before/after checkpoint counts. Tests use real temporary files, journal writes,
fsync and atomic exchange. The harness injects errors before/after every mutation
and SIGKILLs its own child at every apply/rollback checkpoint, then resumes or
reverses and verifies old/new completeness, idempotence and synthetic opaque bytes.
Recovery-cleanup and cleanup-intent/terminal boundaries have separate error and
own-child SIGKILL sweeps. Every lifecycle invocation has before/after checkpoints;
separate receipt failures cover before-effect, after-effect and wrong receipts.
Generated fixed-seed exhaustive rename permutations cover every admitted identity
inode against each public/pending/staging/retained destination. Synthetic file
inotify watches plus positive controls check that refusal did not first open,
read or write the protected inode. A dedicated
same-executable child lowers only its own RLIMIT_FSIZE to1024, proving an actual
kernel short write leaves a1024-byte pending prefix and recovery succeeds.
A second owned-child control limits only a staged public write, deliberately
splits a UTF-8 codepoint, and verifies both forward and reverse recovery.
Injected ENOSPC/fsync-style errors use the same interruption path; there is no actual disk-filling or
hardware torn-sector test. Source checksum fixtures are not release provenance.

Three `migration_owned_guest.rs` tests are ignored, fail-if-forced acceptance
specifications, all NOT_RUN. Required later evidence: NEW separate local legacy
installation with its own established test identity and declared fake dependents,
root-only stopped-state backup and compatible restoration, no duplicate native
identity process, exact same nodeID/IP/approval/server then name reconciliation,
every native durable-boundary kill/full-disk/reboot, real wrappers/adapters and
protected-client captures. No remote-installation validation is claimed. Real
client IPv4/DNS/IPv6/TCP/UDP positive controls and zero fallback/cross-exit markers,
ARM kernel execution, systemd/runit platforms, native custody, performance, soak,
canary and release gates remain OPEN. Passing fixtures cannot close any of them.
