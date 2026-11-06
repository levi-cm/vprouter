# Task 15 independent re-review

Verdict: **PASS for offline acceptance scaffolding.** No reproduced Critical or Important findings. No new Minor defect requiring a change. The earlier **I1 and I2 reproductions are closed within the now-explicit cooperative input-handoff contract**. This verdict does not close any real acceptance, migration, runtime, performance, platform or release gate.

Reviewed `rust/v2` at `bb026565cd94be2b051f0b7443411c81115b430b`, including the uncommitted `tools/acceptance/**`, `docs/rust-v2/acceptance-scaffolding.md`, the brief, earlier review and implementation report including “Review round 1”. The report's claims were checked against source and fresh executions. No subagents, sudo, network, VM actions or Git writes were used. Scratch files are under `/tmp/vprouter-task15-rereview/`. The only repository write from this review is this report.

## Earlier Important findings

### I1 — Fixed: independent container restart and migration boundaries

Locations checked: `tools/acceptance/acceptance.py:387` and `:674`, `tools/acceptance/build_requirements.py:15`, `tools/acceptance/mandatory-requirements.json`, `tools/acceptance/evidence-schema.json`, `docs/rust-v2/acceptance-scaffolding.md:51`.

Recreated the earlier enumeration reproduction in scratch, including all four configurations and the four formerly absent scenario names: `process.container_restart`, `migration.drain`, `migration.stop`, `migration.rename`. All **16 formerly missing configuration/scenario bindings now exist**. The fixture generator accepts each binding; complete synthetic bundles yield oracle PASS with acceptance UNVERIFIED and `release_ready=false`. The retained legacy `migration.drain_stop` row cannot replace either separate row.

This check was supplemented by a reviewer-authored prose inventory, rather than merely comparing implementation constants with their own export. The independent inventory matches all **1,535 rows**, with **zero missing and zero unexplained extra cells**. It includes the additional failure sub-items and migration operations described below. Scratch evidence: `inventory.py`, `inventory.json`, `inventory.out`.

### I2 — Fixed: original mixed-version acquisition no longer yields synthetic PASS

Locations checked: `tools/acceptance/acceptance.py:634`, especially `:647`, `:653`, `:659`, `:660`; CLI snapshot consumption at `:805`; custody documentation at `docs/rust-v2/acceptance-scaffolding.md:173`.

Recreated the original >64 KiB padded JSON arrangement in scratch. Version A has the original context but positive-control count 11 instead of 10; version B has valid captures but run ID `syn-run-002` with the original manifest. Both versions independently assess UNVERIFIED against the unchanged external expected object.

The hook performs the same real same-size rewrite immediately after the first real `os.read`. It changes neither fstat values nor timestamps artificially. Across **30 full-read attempts**, the actual CLI never returned oracle PASS or exit 0. It either rejected observed mutation or validated the acquired invalid A buffer. Across **30 additional forced-short-read attempts**, acquisition refused the short buffer instead of stitching a second version. Each attempt issued exactly one read of the input inode. Scratch evidence: `Probes.test_i2_original_interleaving_and_short_read` and `i2-results.json`.

Also replaced input contents, swapped the input leaf to a symlink, and replaced its parent directory **after the real SHA256 computation and before JSON parsing**. In all three cases validation and publication used the acquired original buffer; `input_sha256` identified those exact original bytes. These synthetic PASS results are expected: the validated acquired evidence was complete and unchanged, while the later pathname contents differed. No mixed or misbound acquired evidence passed. A separate parent-to-symlink swap immediately before leaf open acquired the original pinned directory's bytes, not the replacement directory's bytes. Leaf-to-symlink replacement before open was refused.

The correction closes the reproduced multi-read assembly and hash/parse pathname-reread classes. It does **not** establish an immutable kernel snapshot against an arbitrary writer. Single-read acquisition, shared flock and metadata checks assume cooperative producer handoff, now expressly stated in code/docs. A producer holding exclusive flock was refused immediately. No arbitrary concurrent-writer or malicious same-UID filesystem guarantee is inferred.

## Independent spec inventory and ledger diff

Sources: `docs/rust-v2/IMPLEMENTATION.md:87` Mandatory acceptance and `:107` local-testing amendment; the Task 15 brief; the unchanged `docs/rust-v2/acceptance.json`; migration cross-check against `docs/rust-v2/migration-preparation.md:122`, `:148`, `:171`, `:187`, `:199`.

`/tmp/vprouter-task15-rereview/inventory.py` is the reviewer-authored derivation. It walks the actual failure phrases and slash items, selects their semantic cases, then maps them to the ledger vocabulary. It does not import `build_requirements.py` or read/copy `mandatory-requirements.json` as its inventory source. Importing the validator necessarily loads its package-owned scenario enumeration; that is the actual side of the diff. Separately, the implementer's table was read and its generator reproducibility checked; neither was used as the expected inventory.

Configurations: one Mullvad, five Mullvad, explicitly authorized one direct, five Mullvad plus one direct. No fault is silently excluded from direct mode. Traffic: IPv4, DNS, IPv6, TCP, UDP, generated by real disposable Tailscale clients when actual acceptance is eventually run. Capture points: client WAN, host WAN, every transport and every data plane, for each exit. Positive sensitivity controls, zero forbidden plaintext/cross-exit/host-as-Mullvad egress, and operational boot capture before protected traffic are separate obligations. These are preparation bindings, not claims that real captures exist.

Reviewer-derived semantic fault inventory, normalized to ledger names (**80 distinct cases**):

```text
tunnel_provider (12): wireguard_deleted wireguard_down handshake_stale
  peer_wrong peer_key_wrong endpoint_wrong transport_loss http_transient
  http_permanent provider_malformed provider_negative server_wrong
routing (8): route_drift ordinary_default_restored endpoint_route
  docker_subnet_route docker_gateway_route ipv6_route unexpected_interface
  spoofed_source
firewall (7): data_policy_removed host_guard_removed data_policy_drift
  host_guard_drift atomic_update_failed foreign_conflict bridge_identity_changed
process (11): worker_crash host_guard_crash tailscale_crash container_kill
  worker_freeze host_guard_freeze tailscale_freeze oom container_restart
  docker_restart service_restart
resources (7): disk_full tmpfs_full runtime_operation_failure
  docker_api_unavailable api_delayed health_malformed host_reboot
identity (9): identity_revoked credential_revoked credential_expired
  duplicate_identity control_revoked control_plane_loss approval_revoked
  name_revoked name_server_mismatch
isolation (5): direct_active_during_mullvad_faults exit_failure_others_active
  exit_restart_others_active shared_endpoint overlapping_vpn_addresses
clients (8): exit_disappears selected_node_changes tailscale_restarts routes_reset
  dns_cache_empty proxy_upstream_failed proxy_settings_absent proxy_settings_bypassed
migration (13): inspect stage plan protect drain stop backup activate
  restore_identity rename verify commit recover
```

The existing source ledger supplies additional specificity under the short prose phrases; its 71 original fault names remain preserved. Of those, 70 are in the semantic inventory above; the 71st is the retained legacy combined `migration.drain_stop`. The expansion adds ten independent cases, producing 81 fault IDs including that historical combined row.

Independently walked the migration preparation's ordered contract, rollback, cleanup, journal and recovery paragraphs. The following **44 independently addressable operation families** are represented at both edges, for all three directions (`apply`, `resume`, `rollback`) and all four configurations:

```text
quarantine
stage_create stage_write stage_verify stage_file_fsync stage_directory_fsync
stage_checksums
adapter_drain adapter_pre_start_stop service_stop adapter_post_stop_stop
all_users_stopped
stopped_state_retention old_release_checksum state_format identity_verify
release_exchange release_parent_fsync restore_identity node_rename
client_verify service_start adapter_rebind adapter_post_start adapter_health
journal_pending_create journal_write journal_verify journal_file_fsync
journal_rename journal_parent_fsync journal_cas
pending_validate pending_unlink stage_cleanup_validate stage_cleanup_unlink
cleanup_intent cleanup_quarantine cleanup_adapter_stop cleanup_service_stop
cleanup_all_users_stopped terminal_publish reversal_intent terminal_replay
```

The cross-check includes separate dependency drain/pre-start-stop/post-stop-stop/rebind/start/health obligations; stop-before-start and all identity users stopped; same identity/IP/approval/server before rename; old hostname restoration during rollback; compatible release **and** state; directory exchange and parent fsync; pending journal create/write/verify/fsync/rename/parent fsync; prior-journal CAS; partial pending/staging validation before cleanup; cleanup intent and quarantine/stop/user checks; reversal intent; terminal publication and write-free terminal replay. Inspection, plan and protection have their own general migration rows. Lock/custody checks remain required across operations. The inventory does not add a nonexistent quarantine-release action.

These families do not encode a fixed number of files, write chunks, journal generations or adapter ordinals. The documented ordinal obligation requires a future native producer to sweep each actual instance and repeated barrier. Enumeration alone establishes neither native checkpoint completeness nor interruption execution. The docs explicitly preserve this limit.

Artifact obligations were separately expanded: schema and one/five/mixed examples; exact agent/systemd/runit migration instructions; validation/recovery/rollback guides; compatibility matrix; redacted reports; security-to-test mapping; workload and fully accounted benchmarks; immutable artifacts; SBOM and provenance; unsupported environments. Skip and unknown checks cannot satisfy claims; unmanaged/non-Linux client guarantees are excluded; publication waits for all gates.

The 11 global gates are also represented: single-exit parity; independent namespace/firewall/unsafe review; helper confinement; preserved debdev primary; separate existing local legacy migration; mixed 24-hour soak; repeated ten-minute one/five/six-exit benchmarks; throughput/latency; architecture artifacts/provenance; systemd lifecycle; runit lifecycle. The local amendment requires a separate **local** legacy installation, independently established existing test identity, recorded state and declared adapters, preserved through cutover and compatible rollback. Remote installation validation is excluded, not silently claimed. Actual proof of these obligations remains unavailable.

| Independent row accounting | Cells |
|---|---:|
| 81 fault IDs including legacy combined row, four configurations | 324 |
| Five traffic, four point, positive-control and boot requirements, four configurations | 44 |
| 44 migration operations, three directions, two edges, four configurations | 1,056 |
| Three marker, two status, two scope and 18 artifact IDs, four configurations | 100 |
| Global gates | 11 |
| **Total expected / actual** | **1,535 / 1,535** |
| **Missing / unexplained extra** | **0 / 0** |

Initial ledger counts: `NOT_RUN=1535`, `PASS=0`, `FAIL=0`, `UNVERIFIED=0`.

## Reproduced Minor notes and limits

These are observed, documented scope limits, not new defects blocking this preparation-only change.

**M1 — Admission is externally bound but stateless.** `tools/acceptance/acceptance.py:253`; `docs/rust-v2/acceptance-scaffolding.md:116`. Replaying the same valid bundle with the same expected admission twice still returns synthetic oracle PASS twice. The example `[0,100]` monotonic window is not compared with current wall time. Changing the independently supplied run ID/epoch, excluding capture endpoints from its window, or shifting all producer timestamps outside it is rejected through CLI and library paths, including resealed bundles. This fixes producer-only relabel/reseal admission but does not supply authentication or one-use consumption. The docs explicitly require those from a future real authority.

**M2 — Summary validity is not packet/classifier correctness.** `tools/acceptance/acceptance.py:282`; `docs/rust-v2/acceptance-scaffolding.md:127`. The mixed fixture's 24 point/exit summaries share one source-record digest. These synthetic records contain protocol/marker/time, not independently observed origin/route/address facts. Unknown/encoded/IP marker spellings, hidden count fields at root/context/execution/capture/record/manifest, and positive forbidden counts did not produce oracle PASS. A JSON-escaped `cross_exit` marker decoded to the forbidden label and returned FAIL. No pcap parser exists here, so packet parser correctness remains NOT_RUN.

**M3 — Synthetic content PASS can accompany SKIP/UNKNOWN.** `tools/acceptance/acceptance.py:373`; `docs/rust-v2/acceptance-scaffolding.md:94`. A complete valid synthetic bundle with requested SKIP or UNKNOWN still gives `oracle_status=PASS` and row `status=UNVERIFIED`. Neither grants acceptance. All tested result/report paths retained `release_ready=false`; setting source verdicts to PASS everywhere still admitted zero PASS rows. Direct report serialization refused `acceptance_status=PASS` and `release_ready=true`.

## Adversarial ingestion and publication results

The independent scratch suite exercises `strict_load`, `read_snapshot`/`read_input`, `assess_bundle`, `resolve_status`, `build_ledger` observation admission, `preflight`, `report_bytes`, `publish`, and actual `main()` CLI dispatch. Three additional checks launch the real CLI as a local Python subprocess; no child agents or external commands/services are launched by the scaffold itself.

- **51 semantic cases through CLI check/ledger and library paths**, resealed where applicable: missing/duplicate captures, omitted manifest/controls, candidate/ledger/configuration/scenario mismatch, relabelled runs/epochs, capture ready at/after traffic, capture-after-traffic, wrong mode/ownership/cleanup/boundary, real-evidence claims, unknown hidden counts, control-order errors, and forbidden counts with integer/bool/string/negative variants. No invalid acquired evidence gave oracle PASS, row PASS or release readiness.
- **52 individual capture omissions** across all four configurations; every omitted protocol's controls/workloads tested with internally consistent record counts and source hashes. None passed.
- **990 numeric mutations** across all numeric bundle leaves: bools, strings, floats, null, negative, overflow, NaN and both infinities. No synthetic oracle PASS. Where the strict canonicalizer refused values, the direct library still received them and refused admission.
- **18 raw decoder cases**, each through the strict library decoder and CLI check/observation/preflight paths: duplicate keys and escaped equivalent keys, nested duplicates, nonfinite/exponent/fractional/negative/overflow numbers, invalid UTF/BOM/surrogate/control bytes, trailing junk, excessive depth and >1 MiB input. All refused.
- Input admission refused leaf symlinks, hardlinks, directories, FIFO, `/dev/null`, `/dev/zero`, huge regular files and an exclusive writer lock. FIFO/special-file checks completed without blocking. Directory/leaf swaps behaved as described under I2.
- Duplicate/foreign observations, mismatched candidate, changed ledger bytes, and wrong external run admission were refused or UNVERIFIED in CLI/library paths. Previously recorded FAIL and source forbidden-marker failures survived newly bound valid synthetic observations. All-prerequisite PASS declarations remained DECLARED_ONLY/NOT_RUN, with execution unsupported.
- **2,056 redaction injections** across every bundle leaf using key/private-key/identity/path/IPv4/IPv6/credential-like strings. No injected value appeared in rendered reports. Arbitrary reasons and CLI path failures were refused/redacted.
- Publication: short writes produced the exact hash-named 0400 file; existing file/symlink destinations remained intact; eight concurrent publishers produced one winner and seven refusals. Injected write/chmod/rename/file-fsync failures left no publication or temporary residue. Directory-fsync failure retained the complete visible file and returned `publication_durability_unknown`. Repository tests additionally reproduced colliding temporary symlinks, late destination creation and pinned output-parent replacement. No overwrite or false durability success was reproduced.

## Documentation honesty

PASS for the reviewed offline scope. The current document explicitly distinguishes synthetic oracle PASS from acceptance; source status assertions cannot create acceptance. It discloses cooperative custody, raw acquired-buffer hashes, lack of authentication/replay consumption, classifier-summary limitations, future migration ordinal sweeps, unsupported clients/platforms, unimplemented apply/rollback/controller interfaces, local-only testing, both preserved local migrations, required independent reviews/performance/24h soak and `release_ready=false`.

The historical implementation report contains earlier test counts followed by the clearly identified Review round 1 final result. The current 46-test result was reproduced. No real traffic, identity preservation, migration safety, platform support, no-leak result or release readiness was established by this review.

## Verification ledger

| Check | Result | Evidence / limits |
|---|---|---|
| `python3 -B -I -m unittest discover -s tools/acceptance -p test_acceptance.py` | **PASS**, exit 0 | 46 tests, 2.011 seconds. Includes the expanded property sweep, schema subset, registry, input and publication races. |
| `python3 -B -I /tmp/vprouter-task15-rereview/probe.py` | **PASS**, exit 0 | 10 independent probe groups, 4.080 seconds. Counts in `counts.json`; output in `probe.out`. |
| `python3 -B -I /tmp/vprouter-task15-rereview/inventory.py` | **PASS**, exit 0 | Independent phrase/sub-item and migration derivation; exact 1,535-cell diff; former I1 cases accepted only synthetically. Scratch draft initially needed whitespace normalization for a line-wrapped prose assertion; this was a reviewer-script correction, not a product failure. |
| Original I2 scheduling plus short reads | **PASS**, original defect not reproduced | 60 real-read/real-write interleavings; no metadata fabrication; one input read per attempt. `i2-results.json`. |
| Hash-to-parse content/symlink/directory replacement | **PASS** | Three variants retain exact acquired bytes/hash through validation and publication. Pinned-parent swap also checked before leaf open. |
| Supplemental status/scope/hidden-count/M2/M3 checks | **PASS**, exit 0 | `supplemental.py`, `supplemental.json`. |
| JSON / AST checks | **PASS**, exit 0 | Three Python files parsed with `ast.parse`; 14 package JSON files plus the source acceptance JSON (15 total) parsed with ordinary and production strict decoders. |
| Requirement generator reproducibility | **PASS** | Called `build()` in memory and compared with checked-in data; generator file-writing main was not run. |
| Registry / security mapping / schema subset | **PASS** | Fresh repository suite verifies all 29 rule references/exports, 12 security-map rows/source digest and closed schema refs/enums. |
| Full external Draft 2020-12 schema validation | **NOT_RUN** | `jsonschema` unavailable in isolated Python; no dependency installed. This is distinct from the passing local subset checks. |
| Reviewed-file preservation | **PASS** | Scratch baseline hash manifest unchanged after probes and syntax checks; `baseline-hashes.json`. No bytecode created. |
| `docs/rust-v2/acceptance.json` preservation | **PASS** | Byte-for-byte equal to `git show HEAD:docs/rust-v2/acceptance.json`; SHA256 `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`; release readiness false. |
| HEAD / branch | **PASS**, unchanged | `bb026565cd94be2b051f0b7443411c81115b430b` / `rust/v2`. |
| Real clients/captures/provider faults, native migrations, platforms, benchmarks, 24h soak and release acceptance | **NOT_RUN** | Outside the authorized offline review; no acceptance claims inferred. |

No implementation changes are requested by this re-review. The PASS applies to the scaffold and the reproduced fixes under its stated custody/admission contracts, not to real acceptance or release authorization.
