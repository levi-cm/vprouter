# Draft agent migration, validation, recovery and rollback

UNRELEASED / PREPARATION ONLY. The exact current instruction for systemd AND
runit migrations is: **do not install, enable, start or migrate a real service**.
Task8c runtime/ARM/client acceptance is OPEN. No native apply/resume/rollback,
client installation or release installer command is available. This guide
records future obligations and exact currently available offline interfaces;
it grants no service/identity/credential/production authority.

## Agent preflight and configuration

1. Confirm branch/source, dirty-tree baseline, locked toolchain/dependencies and
   immutable artifact hashes. Preserve HEAD/index and unrelated work. No network,
   sudo, service calls, VM, signing or publication for Task13 preparation.
2. Read [IMPLEMENTATION.md](IMPLEMENTATION.md), Task8c acceptance ledger,
   [service/artifact API](release-preparation.md) and Tasks9–12 preparation guides.
   Unknown is unverified. Existing component reports are not release approval.
3. Review [configuration.schema.json](configuration.schema.json),
   [configuration reference](configuration.md) and
   [one](../../examples/v2/one.json)/[five](../../examples/v2/five.json)/
   [mixed](../../examples/v2/mixed.json) example files. Paths here resolve from
   this document. Examples use synthetic credentials and placeholder image digests;
   never install them or send traffic with them. The JSON Schema is shape-only;
   duplicate JSON fields, byte limits, duplicate private keys/state/IDs/resources,
   node references and naming must pass binding Rust validators. It cannot prove
   private ownership, image availability, identity or client protection.
4. Supply only public declarations to `preflight(host)` and public bytes to
   `build_bundle`. Unsupported platform declarations refuse; all supported
   declarations still block install. Do not supply real profiles/enrollment/state
   to any Python tool, artifact, report, fixture or argv.
5. Run the exact local test commands from release-preparation.md. Its `build_recipe`
   is data, not execution authorization or compilation evidence. Retain independently
   trusted SHA256(SHA256SUMS), then verify complete bundle with `verify_bundle`.
   UNSIGNED always blocks release approval. Check lock and pinned inventories,
   both target architectures, root-owner manifest and all current blockers.

The existing observational CLI syntax is documented in [agent-guide.md](agent-guide.md).
Its validate/status/probe/diagnose and migrate inspect/plan expose unverified fields
and exit2 when checks remain incomplete. Do not invent native `install`, `apply`,
`enable`, `resume` or `rollback` commands, nor wrap old scripts to bypass gates.
Fixture migration uses the exact library-only APIs in
[migration-preparation.md](migration-preparation.md); its receipts are synthetic.

## Future systemd procedure (NOT IMPLEMENTED / NOT_RUN)

1. Before stopping an old supervisor, establish an INDEPENDENT authenticated host
   quarantine and persistent client guards. Verify capture on actual observation
   interfaces for THIS boot. Old service/primary container/uplink names and private
   paths remain exact; aliases or display-name matches cannot identify resources.
2. Inventory exact root-owned files/resources and every hostname dependency;
   unknown ownership, external hostname consumer or missing adapter blocks cutover.
   Run pure `plan("install"|"update", current, desired, observed)` for review;
   its records are not native receipts. No foreign policy flush, daemon restart,
   unknown hook evaluation or identity copying is allowed.
3. A future driver must durably stage complete verified public release data under
   retained private lock/generation CAS, drain adapters and pre-start stop,
   stop scoped service, post-stop stop and verify ALL identity users stopped.
   Take a root-private stopped-state backup, bind compatible state format and
   verify original node ID/IP/approval/server. Do not enroll/recreate/clone.
4. Atomic real-directory RENAME_EXCHANGE selects current/staged on one filesystem;
   fsync the files/directories and retain the old real release. A symlink flip or
   two-rename gap does not meet this contract. Restore/verify the SAME identity/
   addresses/approval/exact server, THEN reconcile the node hostname.
5. Require actual independent guard/capture, exact nft/namespace/cgroup/route/
   DNS/IPv6/client evidence before scoped start/rebind/post-start/health checks,
   protected workloads and commit. Ordering/notify declarations alone are no proof.
   Ordinary stop leaves all policy resident. This package cannot perform steps1–5.

## Future runit procedure (NOT IMPLEMENTED / NOT_RUN)

Use the same ownership, adapter, stopped-state, identity and real-directory
transaction as systemd. In boot stage1, BEFORE stage2 usable network/protected
services, establish independent quarantine/client guards and capture readiness.
A missing authenticated readiness receipt keeps stage2 workloads offline. The
native supervisor must enforce90s host watchdog independently of45s worker health,
bounded startup/shutdown/restart, exact cgroup v2 kill/accounting, capability/LSM/
seccomp confinement and failure quarantine. Those controls do not exist in the
inert run/finish/down drafts. Never link the drafts into an enabled runsvdir.
A finish script must retain policy; it must not remove nft or client guards.
Systemd declarations cannot be assumed to constrain host-launched children here.

## Failure, recovery and compatible rollback

Any uncertainty requires quarantine FIRST. Retain failed source, artifacts, old
release, backups, journals and locks. Inspect current process/boot/ownership using
fresh admitted evidence; an old successful test or stale journal receipt is not
current safety. Never age-break a lock, delete corrupt committed evidence, reset
identity, reenroll or start duplicate identity users to make a retry pass.

For artifact fixtures only: open the same FixtureStore, call `read(anchor)` after
an error that may have followed rename; then call `recover(exact_files, anchor)`
only on the original expected complete bundle. It removes only validated matching
partial public prefixes and an empty pending directory. If bytes/ownership/type/
lock/ancestor/current content differ, it refuses and retains evidence. Repeated
publish/recovery is deterministic and cannot bless unsigned input as release-ready.
Both identical publication replay and recovery repeat parent-directory fsync.
Recovery also fsyncs the root when neither name exists, completing any earlier
rmdir whose final fsync failed. Do not skip recovery based on directory absence.
No fixture receipt authorizes a native lifecycle action.

For a future native driver: resume must repeat quarantine/drain/stop/all-user and
state/identity checks for the current boot, not skip them because a cursor advanced.
If rollback is requested, independently quarantine and stop all users before
restoring BOTH compatible retained old release AND compatible stopped state.
Verify the same node/IP/approval/server before old hostname and controlled start.
An old image checksum alone is insufficient. Missing backup, incompatible state,
failed adapter/capture/ownership or ambiguous restore means remain offline with
quarantine; no automatic server, direct, DNS or IPv6 fallback. Task13 pure
`plan("rollback", current, desired, observed)` only describes this contract.
Its explicit retained-backup selection/binding, stopped-state restore and
restoration verification steps precede controlled restart and protected workloads;
the required native evidence remains unavailable, so the plan stays blocked.
Pure `plan("reboot-recovery", current, current, observed)` likewise declares fresh
ownership reconciliation/current-pair verification; it never starts a service.
See [the full lifecycle and fault matrix](release-review-closure.md).

## Ordinary uninstall and separate client-policy removal

`plan("uninstall", manifest, None, observed)` requires exact verified current
records and emits exact owned leaf removals and empty-directory removals only.
It retains identity, credentials, profiles, state, backups, foreign files, host
quarantine and client policy. Do not use recursive rm, remove parent/shared dirs,
flush unrelated nft, restart Docker/containerd or delete enrollment. Existing
quarantine/client policy removal must be a separate explicit reviewed operation;
no such operation is implemented in this package. Ambiguity leaves protection.

## Owned-guest acceptance checklist (ALL NOT_RUN here)

For Debian13 and Arch/CachyOS systemd, Void glibc runit, each architecture:
clean install; failed startup; interrupted update at every durable boundary;
compatible release+state rollback; ownership-only uninstall; reboot with capture
ready BEFORE traffic; allocation/namespace ambiguity; watchdog/guard freeze,
crash/OOM; Docker restart; full disk/EIO and stale/foreign journals. Preserve
foreign sentinels and compare original identity/state using a reviewed private
backup procedure, never artifacts/reports. Use an independently enrolled existing
local compatibility deployment for the second migration; no remote host testing.

Real disposable clients must continuously exercise IPv4/DNS/IPv6/TCP/UDP with
positive controls, captures at client WAN/host WAN/transport/data and zero forbidden
plaintext/cross-exit markers in one/five/direct/mixed cases under all faults.
Compile/link/ELF checks are never ARM runtime, boot, network or release acceptance.
Then repeated fully accounted ten-minute benchmarks, independent review, canary
and24h mixed soak must pass. Every unknown/skip remains NOT_RUN and blocks the
corresponding certification. No acceptance ledger gate is changed by this guide.
