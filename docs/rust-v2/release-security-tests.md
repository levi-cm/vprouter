# Draft release security-to-test mapping

OFFLINE_PREPARATION_ONLY. Python tests run only against public bytes and private
TemporaryDirectory fixtures. No passing cell qualifies native/runtime/release
acceptance. Entry points have no host clock; epoch0 is fixed and terminal closed
stores cannot revive. No queue, deadline or age-based cleanup is introduced.

| Security property | Offline test in tools/release_engineering/test_release.py | Remaining actual gate |
| --- | --- | --- |
| Unit/runit injection refused; paths/commands fixed; disabled drafts | Services.test_no_generated_service_can_activate_and_order_is_explicit; Plans.test_foreign_mutated_and_injected_inputs_refuse | actual service hardening, seccomp/LSM/caps for host children |
| Exact owner/mode/content removal; state retained; real release inventory | Plans tests; ClassClosure.test_ownership_must_cover_real_release_directory_and_binary_bindings; StrictBoundaries.test_binary_install_inventory_requires_complete_fixed_name_set | authenticated native ownership and install/uninstall with sentinels |
| Compatible real-directory exchange, retained backup restoration before restart, all lifecycle order/failure policy | Plans.test_update_and_rollback_exchange_real_directory_preserving_state; ReviewLifecycle.test_all_lifecycle_plans_keep_required_order_and_offline_failure_policy | native atomic release+state restoration, actual identity/IP/server/approval |
| Unsupported declarations refuse before changes; eligible still blocked | StrictBoundaries.test_unknown_host_preflight_and_unproved_runit_contract_remain_blocked | actual kernel/libc/Docker/NSFS/service preflight and runit parity |
| No unsigned readiness promotion | Artifacts.test_deterministic_inventory_sbom_provenance_and_no_unsigned_release | trusted signing/provenance review and every mandatory release gate |
| Any changed payload/metadata, extra/missing/path alias member refuses | Artifacts.test_every_bundle_byte_and_membership_mutation_refuses | real-source binding, independent anchor/authentication custody |
| Static target ELF shape; all header fields, size/overflow/section/LOAD/static mutations; exact binary set | Artifacts.test_static_elf_and_exact_target_set_required; ReviewELF (all five tests) | repeated real static builds, ARM runtime/kernel and artifact functionality |
| Lock/inventory provenance strict, no role/path confusion | ClassClosure.test_inventory_role_path_swap_is_not_a_valid_pinned_program_input; test_source_materials_cannot_smuggle_undeclared_host_path_or_timestamp | complete prebuilt Go dependency/license SBOM and signed build attestation |
| Descriptor-relative NOFOLLOW, pre-open type/link/mode admission, inode drift | FixturePublication.test_publish_reopen_identical_and_refuse_all_metadata_attacks; test_root_lock_pending_symlink_and_rename_attacks_never_adopt_or_delete | mounted/hostile-root race qualification; no privileged installer here |
| fsync/temp/rename/dir-fsync, retained torn prefixes, deterministic replay; parent fsync repeated after rmdir/rename errors | FixturePublication.test_fault_at_every_publish_boundary_retains_evidence_and_recovers; ReviewDurability; ReviewSyscallSweep.test_every_durable_syscall_boundary_recovers_syncs_parents_and_replays | hardware ENOSPC/EIO/power loss and real native SIGKILL recovery |
| Ancestor permission drift refuses; closed store terminal | StrictBoundaries.test_store_rejects_ancestor_permissions_drift_and_closed_store_is_terminal | native authority lifecycle and reboot reconciliation |
| Sequential offline locked build recipe with four jobs and fixed epoch | StrictBoundaries.test_pure_build_recipe_pins_offline_cross_toolchain_and_four_jobs | clean source, pinned CC wrapper, memory admission and remapped repeated builds |

Independent host90s watchdog versus worker45s expiry, guard freeze/crash/OOM,
restart bounds, real cgroup killing/accounting, boot-stage capture, native ownership,
Docker restart, client DNS/IPv6/no-fallback/selected-node isolation, migration
fault matrix, performance/canary/24h soak are all NOT_RUN. The inert service
generators intentionally cannot claim these properties. See the existing
[security evidence map](security-evidence-map.md) and Tasks5–12 reports for the
narrower component/fixture evidence; none supplies Task13 native release acceptance.

Additional custody/type controls: `RecoveryAndCustody` proves before/after every
pending-file unlink can recover, lock contention preserves the existing inode,
and unsafe types/links/modes refuse before a payload data open. `BundleScope`
checks complete filename-set admission before data access and separately hashed
supplied-binary SBOM subjects. `ExactTypes` rejects JSON/Python boolean, integer
and float aliases for ownership/schema fields; equality uses canonical typed
records rather than Python's `True == 1` semantics. These remain fixture-only.

[Review round 1 class matrices](release-review-closure.md) enumerate every
durable syscall, pure lifecycle transition and ELF header admission category.
The syscall interposer retains real writes and fsyncs, injects before/after each
durable boundary including lock/close, records affected parent inodes, and checks
all mutation obligations have a later successful real parent fsync. Reopen models
process descriptor teardown; it does not model physical filesystem power loss.
Lifecycle plans have no durable syscall boundaries: their native fault sweeps
remain NOT_RUN, and both managers remain blocked.
