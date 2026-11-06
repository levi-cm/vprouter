# Task 15 independent review

Verdict: **FAIL — two Important findings; no Critical findings.**

Reviewed branch `rust/v2`, HEAD `bb026565cd94be2b051f0b7443411c81115b430b` and the uncommitted `tools/acceptance/**` plus `docs/rust-v2/acceptance-scaffolding.md`. Read the ignored brief/report directly. The implementation report was treated as an assertion, not verification. Review scope is credential-free, offline scaffolding.

The real-acceptance boundary holds in the inspected code and exercised cases: there is no implemented acceptance-PASS path, and all report paths retain `release_ready=false`. Complete synthetic fixtures yield oracle PASS and acceptance UNVERIFIED. The findings below concern completeness and a reproduced synthetic-oracle/input-custody failure, not a demonstrated release-acceptance bypass.

## Important findings

**I1 — The mandatory enumeration omits container restart and independently addressable migration boundaries.**

Locations: `tools/acceptance/acceptance.py:31`, `:36`, `:46`, `:188`, `:249`, `:403`; corresponding scenario enums in `tools/acceptance/evidence-schema.json`. The completeness claim is repeated at `docs/rust-v2/acceptance-scaffolding.md:41`.

Requirements: `docs/rust-v2/IMPLEMENTATION.md:48-53,73-74,95-98` and `.superpowers/sdd/rust-v2/task-15-brief.md:24-28`. Container restart is explicit. Migration must cover interruption at every boundary, including drain, stop and rename. The actual observational migration plan also names separate `drain`, `stop`, and `rename` steps at `crates/vprouter-linux/src/migration.rs:536,541,561`.

Reproduction: `python3 -B -I /tmp/vprouter-task15-review/enumeration.py` independently expands the prose into requirements and compares them with `build_ledger()` rows. For **each of all four configurations**, these independently addressable cases are absent:

- `process.container_restart` — container kill, service restart and Docker daemon restart are different listed faults.
- `migration.rename` — restore identity and verify do not enumerate the separately declared rename boundary.
- `migration.drain` and `migration.stop` — the existing `migration.drain_stop` combines two declared boundaries.

All four missing scenario names are refused by `synthetic_fixture(..., scenario=...)` with `scenario_mismatch`. Merely using the combined drain/stop row cannot record both interruption cases independently: the closed bundle has one `execution.boundary`, and duplicate observations for the same ledger row are refused. There is no required subcase list or second boundary field.

The independent expansion has 74 fault requirements versus the existing 71. Replacing the combined drain/stop requirement with two requirements gives 351 semantic rows versus 339 actual rows: 16 absent bindings, offset by four existing combined drain/stop bindings. These counts describe this explicit expansion; scenario spelling is not normative. Preserving all current rows and adding the four missing names per configuration would instead give 355 rows.

Impact: a future producer following the advertised complete enumeration has no place to independently record required faults. R03 and the current completeness test agree with the same incomplete hardcoded lists; they do not establish completeness against the prose.

Requested correction: retain the read-only original `acceptance.json`, add supplemental requirements or strictly required separately bound subcases for the omitted operations, and update schema, completeness tests and documentation. The completeness test should include an independent spec-derived inventory rather than only the implementation's own lists.

**I2 — The stable-file check accepts a mixed read of two invalid bundle versions and the CLI returns synthetic oracle PASS.**

Locations: `tools/acceptance/acceptance.py:599-623`, especially the metadata equality at `:619-622`; the stable-input claim at `docs/rust-v2/acceptance-scaffolding.md:129-132`; registry R21 at `tools/acceptance/acceptance.py:710`.

Reproduction: `python3 -B -I /tmp/vprouter-task15-review/mixed-bundle.py`.

1. Create a 70,735-byte valid JSON file under `/tmp`, with context before byte 65,536 and captures/manifest afterwards. Whitespace padding is legal and below the input limit.
2. Version A has the original context but a bad positive-control count (11 instead of 10). It independently assesses UNVERIFIED.
3. Version B has the original valid captures but `run_id=syn-run-002`, retaining the original manifest. It independently assesses UNVERIFIED.
4. Immediately after the first real `os.read`, rewrite the same file with version B. Only the scheduling of that write is hooked; the read operations, file metadata, file contents and filesystem are real. No `fstat` values or timestamps are mocked or set.
5. On this host's `/tmp` tmpfs the same-size rewrite occurs within one timestamp tick. Device/inode/size/mtime/ctime all satisfy the current equality check.
6. `read_input()` returns A's context plus B's capture/manifest region. These acquired bytes differ from both complete on-disk versions and parse as the original valid fixture.
7. With the **unchanged checked-in external expected file**, actual `main(['check', ...])` returns exit **0**, `oracle_status=PASS`, `acceptance_status=UNVERIFIED`, `release_ready=false`.

Observed reproduction: first attempt; mtime before/after `1793957501616000000`, ctime before/after `1793957501616000000`. The ordinary scratch test expecting mutation rejection also fails independently. Exact output is retained in `/tmp/vprouter-task15-review/mixed-bundle.json`.

Impact: metadata equality does not prove a stable source snapshot, and valid hashes do not repair that acquisition claim. Here the assembled bytes happen to match the expected synthetic content, so the content hashes themselves verify correctly. The demonstrated failure is accepting concurrently mutated source acquisition under R21, including a synthetic PASS assembled from two individually invalid versions. Acceptance remains guarded.

Requested correction: define and enforce an immutable or explicitly cooperative producer handoff for input acquisition, add this same-tick multi-chunk mutation regression, and state the custody limit precisely. Timestamp equality alone cannot support the current stable-file guarantee. A second read can detect this particular interleaving but is not a general immutable-snapshot proof against an arbitrary concurrent writer.

## Minor notes and observed limits

**M1 — Run/freshness validation is internal and hash based, not an independent run-admission contract.** `tools/acceptance/acceptance.py:236-246,279,497-525`. The external expected object contains configuration, scenario, candidate digest, ledger digest and bundle digest, but no independently expected run ID, epoch or admissible time window. Replaying the same bundle/expected pair twice returns synthetic PASS twice. Changing only the run label, resealing the manifest and explicitly updating the expected bundle digest also passes with all old capture records unchanged. Conversely, changing the run label while retaining the original external digest is correctly rejected. These observations do not establish a hash bypass or acceptance PASS. A future real producer needs independent run/freshness admission; current docs explicitly disclaim wall-clock comparison.

**M2 — Marker detection is a classifier-summary check.** `tools/acceptance/acceptance.py:209-233,297-313,509-516`. Exact forbidden labels/counts fail; unknown or encoded labels and IP-address strings are refused, never oracle PASS. JSON escapes resolving to `cross_exit` correctly fail. The 24 mixed-configuration captures share one identical synthetic record-array digest, and record fields have no origin-exit or address value. Consequently this scaffold cannot independently derive cross-exit routing or host-IP equivalence from packet bytes. This is consistent with its documented synthetic-summary boundary; future packet/classifier correctness remains NOT_RUN. There is no classic-pcap parser to fuzz for record length, snaplen, linktype or timestamp parsing.

**M3 — UNKNOWN/SKIP does not grant acceptance.** `tools/acceptance/acceptance.py:352-363`. With a complete valid synthetic bundle, `resolve_status('SKIP', ...)` returns row status UNVERIFIED and oracle status PASS. The latter describes independent synthetic content validity. Consumers must use row/acceptance status for gate admission. The current CLI/docs distinguish these meanings; no acceptance upgrade was reproduced.

## Independent requirement inventory and diff

The inventory was derived from Mandatory acceptance, its referenced migration contract, the task brief and local-testing amendment before comparing sets. Shared names below normalize prose synonyms to existing scenario names; additions and split boundaries are explained in I1.

Configurations: one Mullvad, five Mullvad, one explicitly authorized direct, five Mullvad plus one direct. Every fault below is required for each configuration; none was silently treated as inapplicable.

Traffic: IPv4, DNS, IPv6, TCP, UDP. Capture points: client WAN, host WAN, every transport and every data plane. Every point/exit requires positive controls before and after traffic and workload coverage during traffic. Separate capture-positive-controls and boot-capture-before-traffic requirements apply to every configuration.

Reviewer fault inventory (74):

```text
tunnel_provider (11): wireguard_deleted wireguard_down handshake_stale
  peer_key_wrong endpoint_wrong transport_loss http_transient http_permanent
  provider_malformed provider_negative server_wrong
routing (7): ordinary_default_restored endpoint_route docker_subnet_route
  docker_gateway_route ipv6_route unexpected_interface spoofed_source
firewall (7): data_policy_removed data_policy_drift host_guard_removed
  host_guard_drift atomic_update_failed foreign_conflict bridge_identity_changed
process (10): worker_crash worker_freeze host_guard_crash host_guard_freeze
  tailscale_crash container_kill container_restart docker_restart service_restart oom
resources (7): disk_full tmpfs_full runtime_operation_failure docker_api_unavailable
  api_delayed health_malformed host_reboot
identity (6): credential_revoked credential_expired approval_revoked
  control_plane_loss duplicate_identity name_server_mismatch
isolation (5): exit_failure_others_active exit_restart_others_active
  direct_active_during_mullvad_faults shared_endpoint overlapping_vpn_addresses
clients (8): exit_disappears selected_node_changes tailscale_restarts routes_reset
  dns_cache_empty proxy_upstream_failed proxy_settings_absent proxy_settings_bypassed
migration (13): inspect stage plan protect drain stop backup activate
  restore_identity rename verify commit recover
```

The 11 global gate groups are also present: single-exit parity; independent namespace/firewall/unsafe review; helper confinement; preserved debdev primary; separate existing local legacy migration; mixed 24-hour soak; repeated ten-minute one/five/six-exit benchmarks; throughput/latency; architecture artifacts/provenance; systemd lifecycle; runit lifecycle. The local amendment is checked exactly, including independent existing test identity, declared adapters, compatible rollback and no remote-installation validation. All remain unexecuted.

Mandatory artifact deliverables additionally include schema/examples, exact migration/service/agent instructions, validation/recovery/rollback guide, compatibility matrix, redacted reports, security-to-test mapping, accounted benchmarks, immutable artifacts, SBOM/provenance and unsupported environments. This review does not establish those release deliverables through the scaffold's broad global gate names. No global gate can become acceptance PASS here.

Observed ledger: **339 NOT_RUN; zero PASS, FAIL or UNVERIFIED rows** without observations. All five traffic and four point requirements, positive-control and boot requirements are represented for every configuration. The fault/boundary differences are exactly those reported by I1 in this expansion. Scratch inventory/diff: `/tmp/vprouter-task15-review/enumeration.py` and `enumeration.json`.

## Verification ledger

All commands were offline, unprivileged, without sudo, VM interaction, network or Git writes. Scratch code/data were written only under `/tmp/vprouter-task15-review/`. The only repository write is this report.

| Check | Result | Evidence and limits |
|---|---|---|
| `python3 -B -I -m unittest discover -s tools/acceptance -p test_acceptance.py` | PASS, exit 0 | 37 tests, 0.718 seconds. This verifies the existing suite, not real acceptance. |
| `python3 -B -I /tmp/vprouter-task15-review/adversarial.py` | FAIL, exit 1 | 13 tests: 12 passed; the stable-input mutation test failed because mutation was accepted. Complete output retained as `adversarial.out`. |
| Independent numeric sweep | PASS | 891 mutations across every numeric bundle field: bool aliases, numeric strings, floats, null, negative, oversized, NaN and infinity; producer resealing where representable. No oracle PASS from these invalid values. |
| Independent redaction sweep | PASS | 2,056 secret/key/identity/path/IPv4/IPv6 injections across all fixture leaves; controlled report bytes never echoed injected values. CLI refusal and report reason allowlist checked too. Digest fields remain integrity references under the documented producer contract. |
| Missing/partial coverage and controls | PASS | Every capture individually omitted in every configuration; each protocol's controls/workloads omitted with internally consistent counters and source hashes; no oracle PASS. Duplicate capture coverage is also covered by the repository suite. |
| Parsing and encoding | PASS | Duplicate keys including escaped equivalent names; int/bool distinctions; fractional/exponent/nonfinite/oversized numbers; UTF/control/surrogate/depth failures; unknown forbidden-marker fields all refused. Encoded/IP marker variants never passed. |
| Temporal and execution consistency | PASS within synthetic contract | Late/equal-ready capture, short windows, reordered records, control in traffic window, different epochs, zero controls, drops, wrong mode/ownership/result/boundary refused. Existing suite covers exact large integer boundaries. Stale replay limitation is M1. |
| Source/manifest/external binding | PASS within content contract | Wrong configuration/scenario/candidate/ledger/bundle and source hashes refused. Unchanged external digest rejects run-label mutation. Repository suite walks 257 bundle leaves with three perturbations each. Stable acquisition fails as I2. |
| Status admission | PASS | Missing/unknown/skipped/partial evidence never yielded row or acceptance PASS. Setting every source status to PASS still yielded zero accepted PASS rows. FAIL retention and duplicate/foreign observations checked across the existing suite and `ledger-adversaries.py`, including a valid newly bound bundle over a recorded source FAIL and source forbidden-marker count. |
| Preflight and execution boundary | PASS | Even every prerequisite declared PASS with digest yields DECLARED_ONLY, NOT_RUN and execution_supported false; each missing evidence digest blocks its prerequisite. Shell/network entry points guarded in scratch tests; AST shows no shell/network API/import. `ctypes` is used for local exclusive rename only. |
| Publication | PASS in documented custody model | Existing suite covers pinned parents, symlink collision, late destination, competing publishers, file/directory fsync failures. Scratch checks add partial writes and write/chmod/rename failure cleanup. Output bytes/hash/0400 mode and no overwrite checked. Malicious same-UID temporary mutation is expressly outside the documented publication model. |
| Input resource/size bounds | PASS except stability I2 | Existing suite checks symlinks, special files and oversized files. Scratch checks hardlink refusal. Multi-chunk stable snapshot assertion fails on real tmpfs metadata granularity. |
| JSON and AST syntax | PASS | Both Python files parsed with `ast.parse`; all 13 new JSON files plus `docs/rust-v2/acceptance.json` parsed. All 13 new JSON files also passed the production strict decoder. No bytecode emitted. |
| External Draft 2020-12 schema validation | NOT_RUN | `jsonschema` unavailable; no dependency installed. Existing independent schema-subset checks pass and source schema was inspected. |
| Registry and security map | PASS for references | All 26 rule entries resolve to enforcement functions and named tests; checked-in export matches. All 12 security-map rows (more than the requested 10) were resolved through R08–R12 to existing tests, and the source-map SHA256 matches. The reference test does not establish prose completeness; see I1. |
| Documentation honesty | PASS with I1/I2 qualifications | Explicitly says no acceptance evidence and no release readiness; needs real credentials, clients, independent boot-capable capture, both preserved local canaries, adapters/rollback, supported-host checks and 24-hour soak. Future interfaces are labeled unimplemented; preflight cannot run them. |
| `docs/rust-v2/acceptance.json` preservation | PASS | No diff against HEAD; SHA256 `3d467451dd03d1663e3c79b24eea6a18aac461f9291f8fdfe1031e1da6e86e97`; `release_ready` is false. |
| Real clients, captures, providers, migrations, supported-host runtime, 24h soak, release acceptance | NOT_RUN | No such acceptance evidence was produced or inferred. |

All 12 security-map invariant rows resolved: configuration_and_modes, helper_confinement, encrypted_transport, producer_only_bootstrap, firewall_ownership, interruption_ownership, provider_exact_server, managed_client_no_fallback, cross_exit_isolation, preserved_identity_migration, efficiency_without_monitor_loss, supported_host_preflight. Exact reference resolutions are recorded in `adversarial.out`.

The two findings remain unfixed because this is an independent review. This verdict applies to the current offline scaffold and does not authorize host execution or acceptance activity.
