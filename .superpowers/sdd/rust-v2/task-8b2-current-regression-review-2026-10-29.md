# Task 8b2 current-source regression review — 2026-10-29

## Verdict and exact scope

**Scoped source regression review: PASS. No open Critical, Important, or Minor finding identified in this review.** The coherent candidate at `b51b5d7dd7a127d88a6e770f0b8780951190805b` does not introduce a demonstrated regression of the previously reviewed task-8b2 actual-program authority, authenticated handoff, revocation, or confinement boundaries. The ARM64 filter compilation defect identified during the first coherent build is corrected without expanding the intended syscall authority.

This is a separate, narrow follow-up to `task-8b2-independent-review-2026-10-29.md`. That earlier report's task-8b2 conclusion remains bound to `90a7dcc756f073cccd3a1c34959676f001eb7601` and its run396 evidence. This report reviews the relevant source delta from that baseline, including the operational-owner/Bootstrap additions first checkpointed at `990526a3d7b21aad3b7f51d0ec8dea3fd6d0bd72`, and the subsequent ABI correction in the final frozen source. There are 41 changed files under `crates/` across the baseline-to-final comparison, including module exports, tests, and one Cargo manifest; this is not a claim to audit every added document, historical lab utility, or performance tool in the much larger repository checkpoint.

**Existing-path runtime regression: PASS within the isolated AMD64 Debian actual-program suite, run397, 17 cases. New secret Bootstrap native integration acceptance: NOT_RUN. ARM64 runtime: NOT_RUN. Release readiness: false.** No task8c, real-client, migration, multi-exit, deployment, benchmark, reboot, or soak acceptance follows from this verdict.

The reviewer performed source/evidence reads and wrote only this review Markdown. No source edit, build, test execution, Git/index mutation, VM command, privileged operation, or production change was performed by the reviewer. Root owns the supplied builds and isolated runtime executions.

## Source regression assessment

### Existing actual-program and policy boundaries

Git comparison confirms `crates/vprouter-launch/src/actual.rs`, `daemon.rs`, `handoff.rs`, and `actual_lab.rs` are unchanged between the reviewed baseline and final freeze. `crates/vprouter-netfilter/src/policy.rs` is also unchanged. The existing native actual-role execution/filter bodies are not replaced by the new Bootstrap path. The `kernel.rs` delta registers the new module and its retained-owner polling/reaping.

The new operational path is not a parsed-report route to original placement authority. Its high-level request and owner types are private to the crate/module, retain the live original owners, and bind the exact Source, service/member, admission, query, epoch, namespaces, policy digest, pin identities, and fixed request deadline. The resulting `BootstrappedOwner` has private state and no method yielding Placed/READY/UP, original producer authority, an unrestricted actuator, or a production activation capability.

The new native test entry is explicit: `actual_lab_main.rs:158-170` dispatches seven `--ignored-secret-bootstrap*` modes. Their presence is not evidence that the ordinary actual-program suite executes them. The new transport-lab forwarding entry is test-gated.

### Original-owner retention, reservation, and failure fencing

`attachment/operational.rs:17-173` moves the complete `HostAddedPrimary`, exact plan, and nonclone reservation into retained native custody before subsequent fallible work. Polling checks the pending reservation; failure latches and collects without manufacturing completion. Completion requires the canonical finished state and retained operational custody. Drop retains the whole owner in creator-thread storage; a foreign-creator drop does not release the underlying pins.

`owned/preparation/assembly.rs` preserves the original 15-job assembly and adds only the exact five-job suffix: one FixedNetfilter and four FixedVeth transfers. The extension validates the same service/member/epoch/shared journal, distinct suffix resources, and the exact canonical 20-job set. The suffix is reserved before charged retirement transfers. Repeated, foreign, pending, or fenced handoffs are refused; partial/failure paths retain the original nonquiet accounting and owner custody. The owner and active-child limits are not enlarged by this handoff. `attachment/host_addition/operation.rs:209-310` derives the suffix from completed original host-link ownership rather than historical receipt bytes alone.

`attachment/operational/bootstrap.rs:13-202,220-548` consumes the operational owner and advances Host → Transport → Data in order. Each scope uses a fresh, exact-source Docker query with the fixed two-second request window, canonical durable Intent → Birth gate → native result → Result receipt transitions, and source/pin revalidation after completion. Failed operations permanently fence the original input and cancel pending children. Whole-owner retention also applies to startup errors and Drop.

`owned/preparation/bootstrap.rs:39-250` validates ordered scope/index history, exact query/deadline, original generation/group/namespace and prior host/netfilter history, original producer binding, eight distinct pins, policy digest, and finite birth/observation/acceptance bounds. The prior authority must be the exact initial quarantine for Host/Transport or the exact observed producer for Data. The new inspection slots are separate from original Docker admission history. Defaulted/empty serialization does not relax the old admission path.

### Native Bootstrap and original producer ancestry

`attachment/operational/producer.rs:28-168` retains the original Source and eight registered read-only descriptors. Its clock remains anchored to the original request, and verification checks the original acknowledged history, all descriptor identities/registrations, protected cgroup2 directories/files, and the exact original parent/group ancestry.

`process.rs:575-631` pins the admitted root/system.slice ancestry using constrained `openat2`, validates the retained root identity and protected cgroup2 properties, and rechecks each actual ancestry link using no-follow metadata. A retained inode alone is not treated as proof that the original directory name still refers to it.

`native-role/src/producer_bootstrap.rs:197-328` validates the selected 64-character lowercase hexadecimal container identifier and safe group name; retains the root/system pins and immutable selected names; and verifies root-owned, nonwritable cgroup2 directories and their actual parent/name links. Its confined group object is creator-bound, deadline-bound, and constructed only from the installed Bootstrap role. Group verification returns identity observations, not producer-placement authority. The filesystem tests at `335-377` cover renamed/replaced/symlinked ancestry.

The native role is distinct from existing WireGuard and ProducerNetfilter roles. Existing roles pass no ancestry rules. The Bootstrap role selects the netfilter direction and original prepared descriptors, installs the selected confinement before group observation, and does not expose a mutable raw Source.

`kernel/bootstrap.rs:132-331` checks the exact canonical intent and prior gate, stores the whole lower pending operation and borrowed registration ownership before later fallible validation, registers selected endpoints/descriptors before native birth, and binds birth to the canonical journal. Result acceptance requires the exact constructor's actual native status zero, correct namespace/policy/pin identity, and original deadline. Verified historical acknowledgement is not promoted into renewed present-tense producer truth.

### Mutation boundary and public lower APIs

`netfilter/src/fixed_bootstrap.rs:29-147,149-314` consumes the exact `VerifiedInitialQuarantine` or `VerifiedProducerObservation` into retained origin custody before fallible setup. Scope mismatches are refused. Prepared descriptor ownership is available to the caller for registration before later validation/birth; cancellation, partial failure, and Drop retain original ownership.

`fixed_bootstrap.rs:367-479` accepts only the exact native completion/report with matching namespace, policy, six producer-pin identities, fixed deadline, and original native birth. In the confined child it observes the protected empty producer group, verifies Offline quarantine, acquires the exclusive original Bootstrap permit, installs it, and rechecks both group and policy before producing the fixed result. Group observation checks protected cgroup2 metadata, empty procs/subtree, `populated 0`, `frozen 0`, and domain state using read-only inputs.

`actuator.rs` adds an original-permit path requiring Offline state, matching quarantine/emergency policy, and an absent permit. Installation uses exclusive create semantics; it does not adopt an existing matching permit. Exact Bootstrap verification requires the matching quarantine and permit with emergency absent and the expected generation. The Data producer constructor is available only inside the installed confined role; Host/Transport do not gain a socket producer. Existing StageBootstrap policy still restricts the health socket producer and does not forward application traffic.

The lower public preparers require consumed original owners and typed confined-role execution. `VerifiedBootstrap` exposes original child/observation identity and history getters, not an actuator, enforcement owner, or socket producer. Socket rebinding requires the original shared timer/sequence binding and an empty queue; failures poison the operation. Producer continuity requires the exact original native constructor and same Source/binding/namespace/policy rather than reconstruction from serialized receipts.

## ARM64 correction

The first coherent build's E0425 failure for `libc::SYS_fstatat` is preserved in the build evidence and described in `task-8b2-arm64-filter-fix-2026-10-29.md`. The only crate-source delta from checkpoint `990526a3...` to final freeze `b51b5d7...` is in `native-role/src/filter.rs`: both production code and the focused test now select `libc::SYS_newfstatat` on both supported ABIs.

The pinned libc 0.2.189 AArch64 GNU and musl definitions export `SYS_newfstatat = 79`; the x86_64 value remains 262. The correction changes the invalid ARM identifier, not the argument positions or intended permission. The rule at `filter.rs:143-152` still constrains the exact original directory FD, immutable selected name pointer, and `AT_SYMLINK_NOFOLLOW`, including both words of constrained arguments through `rule` at `22-61`. The output stat buffer is deliberately not pinned. Old roles receive an empty ancestry list. The focused test at `289-335` checks selected success and foreign FD/name/flags/high-word denials and retains write/open/dup/mkdir/unlink/setns denials.

The supplied focused validation records 12 native-role tests, formatting, and ARM musl `--tests` compilation passing; Root additionally reports strict native-role all-target Clippy passing. Earlier full-workspace validation reports 393 tests, formatting, and strict all-target workspace Clippy passing. These are supplied component checks, not reviewer-run or ARM runtime evidence. The new coherent static payloads exist for both ABIs after the correction.

The AMD64 filter preflight has actual wait status zero, exact statat reaching the kernel, wrong-directory/name-pointer/follow/high-word denials, and all group writes denied. It explicitly records `actual_bootstrap_installation=false`, `actual_group_ancestry_observation=false`, and `no_netlink_transactions=true`; those limits remain binding.

## Frozen artifact and runtime evidence

Evidence root: `target/continuation-20261029T122356Z/`. The reviewer independently recomputed the source/payload/context hashes and compared every one of the source archive's 202 regular build-input files against the exact `b51b5d7...` Git objects: zero mismatches. This remains an exact frozen-source assessment even as later documentation checkpoints advance HEAD.

| Binding | SHA256 |
| --- | --- |
| Source archive | `efd893b6b136e2f0bae55cadcea6cfe1823ecd0129bef32fe76093271201d98d` |
| Source aggregate | `0ce0488bee605e94f7aaf6fa4df915cc1284227efa3d773d78b6130bbfd06fe6` |
| AMD64 payload | `7383d330350bdf445f2a77d95229955de38060426aa6ec7f8df17d7d2fb8d21b` |
| ARM64 payload | `a6404d4f15124558fbef98f4156a5bcf57ee8f3d375c69a581fcb651bf4a4676` |
| AMD64 immutable context | `1170bc2a5980ab5adfb140e81bd91ed8fd28b6d2d7c2d58da91dff22119032e7` |
| ARM64 immutable context | `64e82ba3b9332e5c97cedd146dbc5cdf276b957863df0b14860ace19807ccd94` |

`root-verification.json` records the same source binding and strict seven-file/four-role contexts. The manifest digests are AMD64 `cf976bc8511e515f0c84f1fb997fad0f730c2f98b8a9a65e89f404a0c7465bbc` and ARM64 `c42366712ae06021cc610988dfc1b32c732e0823b3459236f7ec2fda17a8bbdb`. Candidate-local immutable contexts were used for the hash checks; the candidate JSON's mutable builder-context pathname is not itself treated as immutability proof.

The reviewer independently inspected `target/lab-state/actual-program-run-397.json`, `vm-actual-summary.json`, and the read-only exported collection under `task8b2-current-20261029/`:

- `controller.json` matches the raw run397 fields, including stderr, exact 202-file source binding, source/archive/payload/context/manifest hashes, and seven-file inventory. It reports exit zero and `PASS_PARTIAL_ACTUAL_PROGRAMS`; its ordered 17 passing runtime events occur in the raw stdout. These include the four actual post-pin MTU/address/route/rule drift cases, old-authority rejection after repair, daemon-death revocation, authenticated lifecycle/observer behavior, confinement, bounded reaping, packet controls, and natural container-death cleanup.
- `directory-binding.json` binds run397 and the exact frozen AMD64 artifact to the sole new isolated directory `/var/lib/vprouter-v2-lab/task8b2-38027`.
- `captures.json` contains exported read-only framing/hash/counter/marker metadata for six captures: positive data/transport/host record counts 2/7/7, and negative data/transport/host counts 32/32/32. All six are `FRAMING_VERIFIED`; totals are 112 records, zero forbidden-prefix markers, and zero reported kernel drops. Positive producer markers occur in the data control; positive plaintext controls occur in transport/host; authorized-during-denial markers occur in the data denial capture. The aggregate agrees with these totals.
- `metadata.json` records three scope observations and packet accounting with 16 unauthorized attempts, 16 kernel permission denials, zero locally queued sends, zero unauthorized peer receives, and 16 authorized round trips during denial. The result retains quarantine and reports readiness false, no approved identity access, and no production changes. Both `task8b2-image` and `task8b2-host-acceptance` admission markers are absent.

The reviewer inspected the exported independent collection, not live VM state or raw remote pcap files. The capture collector labels its scope `synthetic_capture_metadata_only=true`, `complete_fault_verdict=NOT_ESTABLISHED_BY_THIS_TOOL`, and continuous sender `NOT_PRESENT`. Accordingly, the captures support this isolated component regression result and packet-control accounting; they do not establish a continuous fault campaign or full leak acceptance.

## Cannot Verify / retained gates

The seven new secret Bootstrap native oracle modes have no supplied accepted exact-source runtime family in this review. The ordinary 17-case run397 suite is the existing actual-program suite, despite one historical case name containing “bootstrap”; it is not proof of the new private operational Bootstrap chain. Successful real native installation, three-scope original-owner continuity, ancestry observation during installation, and the new postbirth/result/registration/handoff-fence/partial/duplicate failure cases therefore remain **NOT_RUN for Bootstrap acceptance**.

The successful ARM build, pinned syscall definitions, static payloads, and compile checks do not establish ARM kernel/runtime behavior. Real-client readiness, production activation, full task8c continuation, migration, multi-exit behavior, other platform/native runtime gates, router performance, reboot recovery, and long soak remain outside this review and unaccepted. The supplied 84 Python performance-tool unit-test passes are tool validation only and add no runtime benchmark claim.

No production or release gate is relaxed. The scoped source/regression PASS permits further isolated Bootstrap implementation and validation work; it does not authorize runtime promotion or substitute for its missing native evidence.
