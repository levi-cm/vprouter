# SDD ledger — plan: docs/rust-v2/IMPLEMENTATION.md

Base 84fb353; worktree /DATA/AppData/vprouter-rust-v2 branch rust/v2.
User handoff is the binding spec; IMPLEMENTATION.md records it locally.

## Preflight interface scan

| Packages | Producer / consumer | Finding |
|---|---|---|
| 1 -> 2-10 | legacy fixture and preserved retry behavior | active source hashes match deployed release; main behind repair |
| 2 -> 3-9 | config, ownership, allocation, reason and health types | strict typed API required before privileged runtime |
| 3 -> 4-7 | verified namespaces/firewall/placement | parity gate must precede multi-exit activation |
| 4 -> 5 | worker executable/native APIs | pinned existing Tailscale retained |
| 6 -> 7-8 | selected exit ID + mode | direct never fallback; naming alone no authority |
| 8 -> 9 | client coverage evidence | missing coverage explicitly unverified |
| 9 -> 10 | compatible stopped state and release | real directory, no symlink activation |
| 10 -> 11-12 | immutable candidate | benchmark and client evidence before canary |
| 1-12 each | acceptance vs deliverable | no intrinsic contradiction; tests require external lab/credentials/second host |

External test resources requested asynchronously; no live cutover before gates.
All twelve packages pending. Source tree and deployed Python remain intact.

Acceptance matrix recorded in docs/rust-v2/acceptance.json, all mandatory runtime
claims NOT_RUN. No external lab/client/profile/second-host response yet.

Task 1 bounded baseline/fixtures: complete (84fb353..3b85fc8, review approved).
Full WP1 benchmark acceptance still NOT_RUN. Review minor: baseline.md:102
collector lifecycle is pre-start stop, post-start start, post-stop stop; fix in
final documentation wave. Reviewer /root/review_baseline.
Task 2 base 3b85fc8; strict core implementation in progress.

Core first dispatch /root/core failed before implementation with provider
409 account_policy_owner_unknown. No retry burst; delegated once to the working
gpt-6.1-sol model /root/core_impl.
Read-only legacy probe reports de-fra-wg-404 / 169.150.211.139. Imported profile
endpoint169.150.211.175:51820 independently matches same relay via bounded HTTPS
Mullvad catalog. Recorded public-only observation, no client leakage claim.

User pointed to immo-collector profile folder. No local immo directory found;
Tailscale lists two online immo-collector-live nodes100.71.233.88 and
100.118.100.79. Read-only SSH root id-u attempts timed out both (no remote
commands executed). Asked host/path/access clarification.
Local protected534-profile archive checked IN MEMORY only: one distinct device
private key/address set; ALL match live primary. No extracted/modified files,
key bytes or digests. Cannot provide required five distinct configured keys;
new account device provisioning excluded. test-resource-inventory.json records
redacted facts. Single-exit development continues; no canary/fault activation.
Both immo peers answered one Tailscale ping (one DERP, one direct); SSH access
remains unavailable, distinct from node connectivity. No reset/reconfiguration.

User supplied /DATA/AppData/vprouter/wiregurad-auth.zip. Read-only in-memory
inventory: five profiles/five distinct keys/five addresses/no active-key reuse.
Servers de-fra-wg-402,de-dus-wg-102,de-fra-wg-003,de-ber-wg-102,de-ber-wg-002 all
endpoint-match current HTTPS Mullvad catalog. Only Device comment, no server
comment. Tightened ROOT-owned archive0644->0600 via O_NOFOLLOW fd, contents
unchanged, no extraction. New profiles AVAILABLE; earlier original archive
limitation no longer blocks five independent keys. Not yet enrolled/Tailscale
client credentials unavailable. Core leading-zero server validation corrected.

Task2 implemented e18191a (32 tests reported; fmt/check/clippy PASS); independent
review /root/review_core pending against b9eaae7..e18191a. Not marked complete.
User selected interactive Tailscale login-link enrollment. Staged ONE fresh
userspace acceptance client with pinned existing Tailscale1.102.5, cap_dropALL,
read-only root, no privileged/device/ports/proxy listeners, log-drivernone,
root0700 NEW state directory. No identity cloned; existing router untouched.
Login link presented ONLY to user, not recorded in evidence. Approval pending.
Client has no protected workloads; client no-fallback guard not yet implemented.

Task2 fix1 40449d5: reviewer Important findings on shared-transaction CAS,
X25519 ignored scalar-bit aliases and expired-evidence recovery all fixed;
reported36 runtime tests+1compile-fail passing. Scoped rereview pending.

Task2: complete offline foundation (b9eaae7..40449d5, review all findings closed).
Task2 runtime/foreign-resource/profile-owner gates remain outside scoped core.
Task3 read-only host/CLI/migration preparation begins at40449d5. This is safe
preparatory work for WP3/9, not their privileged guard/migration apply completion.

Interactive approval succeeded: new disposable acceptance-client node Running,
ID nnhXNghWF621CNTRL, IP100.120.226.13. No existing identity copied or renamed.
No protected workloads/client guard/real traffic acceptance yet. Five supplied
archive profiles passed reviewed native core parser in memory, no extraction
or key output. This does not verify account/tunnel/provider runtime.

Ruling: legacy migrations use stable internal exit ID `primary`; legacy has no
exit-ID concept. Preserve existing container/service names separately. This
resolves contradictory task3 brief wording without coupling IDs to display names
or rejecting valid long legacy container names.

Task3 implemented2b259c5; 54 runtime+1doc tests, fmt/clippy/offline release
build reported PASS. Independent reviewer /root/review_host_cli pending.
Root evidence-only f2316d3 records imported profile availability, approved
new disposable client and isolated Debian13 guest. Guest bootstrap complete;
owned one-use netns successfully created kernel WireGuard and nft table then
removed. Host interfaces/firewall untouched. TCG guest excluded from performance
acceptance. Root-owned0600 guest marker /var/lib/vprouter-v2-lab/isolated-acceptance.

Task3 fix round1 implementedab6a597; 56runtime fmt/clippy covering tests PASS.
Important host-libc build-target inference replaced with Void NOT_TESTED absent
proof; minor actual-parser redaction regression added. Scoped rereview pending.
Lab guest powered off cleanly and relaunched KVM/pc,smm=off/CPUhost; owned QMP
query-kvm confirms enabled/present, guest Debian13 SSH/Docker/bootstrap intact.
Earlier emulated samples unusable; controlled native performance remains NOT_RUN.
No production resources or identities changed.

Task3 fix round1/5: 2 addressed, 0open; commits2b259c5..ab6a597.
Task3 minor (deferred): cli.rs34 unsafe_path fixture assumes temp_dir has an
untrusted ancestor; a root-owned protected TMPDIR could produce invalid_configuration
instead. Set explicit group-write mode on fixture before final wholebranch review.
Task3: complete observational preparation (f2316d3..ab6a597, review approved).
Real host-libc proof/static artifact execution and all runtime/migration/client
gates remain NOT_TESTED/NOT_RUN. Task4 native scoped nft policy begins atab6a597.

Post-review live read-only smoke: rebuilt native CLI; migrate inspect inventoried
2legacy containers with Docker/release inventories successful but incomplete
identity/ownership checks as intended. migrate plan failed invalid_configuration.
Root in-memory native parser diagnostic confirmed InvalidProfile for existing
root0600 profile, whose known standard field names are lowercase (ConfigParser
legacy output). No credential bytes logged/no production changes. Supplemental
task3b regression fix assigned to current implementer /root/native_netfilter
before task4; task4 paused pending scoped core review. Normalize known field
names BEFORE duplicate detection; no permissive unknown-field fallback.

Task3b: complete compatibility fix (ab6a597..a107fa6, independent review clean).
Actual protected-profile native plan now succeeds as non-applicable review:
keeps max-vprouter/container/service, /etc/vprouter/max-vprouter.conf and
/var/lib/vprouter/max-vprouter, proposed name mullvad-debdev-exit-de-fra-wg-404.
Root rebuilt release and recorded redacted live-cli-smoke.json; exit2 deliberate
plan_not_applicable with all missing gates. No writes to existing installation.
Task4 native policy resumed /root/native_netfilter after supplemental gate.

Task4 implementationf78e86d compiled/reported75runtime+1ignored+1doc tests
andfmt/clippy PASS. First real kernel harness in guestdisposable unshare netns
FAILEDexit101 after Data quarantine_exact PASS; Err(Drifted) before nextcase.
No trafficgenerated; namespace destroyed onexit. Root recorded failure in
netfilter-lab-evidence.json, implementer diagnosing before review. No acceptance
claim. ACK/stateCAS followup inprogress must include actual kernel fix.
Root also generated root0600 review-only schema2 candidate alongside plan;
validate schema true, 10observational checksPASS and3kernel/guard checksNOT_TESTED;
status guard_runtime_unimplemented, noREADY/protected/DNS/IPv6 claims.

Task4 isolated kernel attempt3 PASS: binary08d58097b3e26bcb1b15f27f1043ac005a9db295ff42779cdddc3f8c8127ccf1; native_acceptance exit0, 0.44s. All6cases passed for Data/Transport/Host in disposable guest netns. First2attempts retained as failures. Cause GETCHAIN kernel dump included other tables; strict table-identity filter added before reconciliation, no verification relaxation. No application traffic generated; real-client leakage/performance/release gates NOT_RUN. Final code/report and independent review pending.

Task4 code finalized f78e86d+6f7255d, exact-code report785c99e; fresh77runtime+1ignored+1doc/fmt/clippy/release library PASS reported. Independent review /root/review_netfilter dispatched against a107fa6..785c99e, not yet approved. Root evidence commit preserves live read-only CLI observations and all3native attempts. Next component task5 brief prepared; implementation awaits this gate.

Task4: complete bounded native nft actuator (a107fa6..785c99e, independent review /root/review_netfilter spec PASS/quality approved, no Critical/Important). Review unknowns remain explicit later WP3/4/6/8 gates: namespace/link admission, allocation lock integration, real packet/cross-exit/leakage behavior. No full guard claim. Minor deferred: lab.rs167 external nft rendering only checks list success+hook forward; expand independent assertions or narrow wording before final review. Task5 native route/WG starts at b87b498; no next runtime activation.

Task5 /root/native_network implementing at37034ea. Ruling: keep native network mutations DOWN-only until guard integration has a non-forgeable retained quarantine contract; allow owned DOWN link creation/configuration/move and cleanup, no public activation/address/default-route mutators. Caller booleans cannot authorize transport activation. This delays full provisioning to the guard/helper package; cost if wrong is later API integration rework, not an unguarded WAN path.
Root created ONE fresh enrollment-only lab gateway container in owned KVM guest, exact pinned Tailscale1.102.5 image. Root0700 new state, userspace/read-only/capdropALL/noports/lognone, noadvertisedroutes/noexit selected. Login-link approval requested asynchronously; no existing identity cloned. Existing approved disposable client remains unchanged. Lab node not protected runtime; no provider credentials copied.
