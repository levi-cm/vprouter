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

Root prepared task6 helper brief for later review gate, including independent per-exit PID/proc views to prevent same-UID /proc/PID/root access to another mount/state view. No helper implementation yet. Pinned1.97.0 x86_64/aarch64 musl targets installed (no static build/host support claim). Lab diagnostic preparation via guest-only authenticated apt completed: tcpdump/wg/curl/iproute2 already present, bind9-dnsutils installed and bind9 libraries upgraded. No service/container restart requested by guest package manager; production unchanged.

Task5 native guest attempt1 FAILEDexit101/0.01s before firstcase: NamespaceUnverified. Binarybadf4508fa2920e70a6ef172d610d25a6e4f445661a1532e15ea88a46899ccff. Strict direct proc-netns FD check rejected harness bindmount-form FD; implementer updating TEST-only helper to reopen /proc/thread-self/ns/net after dedicated namespace entry, with fixed stage diagnostics. No production verification relaxation or traffic. Failure retained in network-lab-evidence.json.

Task5 native attempt2 FAILEDexit101/0.02s before firstcase: unsupported link attribute32830 -> Drifted after namespace checks passed. Binarya577f624e0467212d3f52124061ad9c3226489e182785ad0fcf9aa3d2cbd112b. No activation or traffic. Implementer identifying exact kernel attribute and harmless inactive representations; functional drift checks remain strict.

Task5 native attempts3-5 retained as failures: empty DPLL metadata first refused; then valid metadata+foreign-name refusal passed but new DOWN veth peer alias missing. Attempt5 diagnostic confirms kindtrue/UPfalse/MTU1420/aliasfalse for index3. Implementer correcting exclusive-new-pair initialization without adopting unlabeled existing resources. Independent synthetic kernel /32 and attached TUN route oracles completed with no private keys, peer or WAN; read-only legacy route/rule/address-class diagnostic supplies compatibility shapes (no exact peer addresses/secret output). No native activation/traffic acceptance.

Task5 native attempt8 PASSexit0/0.22s,1passed/13filtered, binaryd2d739d6bd7e8bfb2ecca88c66d86b70de99c717efb618c83f949d78233cc308. All5scopedcases passed, guard_runtime:false activation:false. All7failedattempts retained. Corrections: directproc test FDs; exactinactive empty devlink/DPLL metadata; exclusive-new DOWN peer alias initialization; exact disabled rule suppress-prefix sentinel with functionalvalues rejected. Actual UDP socket birth-path/traffic, native activation, full guard, Tailscale and client leakage remain NOT_RUN. Final report/code checks and independent review pending.

Task5 finalized a01d28d code +0631fb0 report; reviewer /root/review_network dispatched against48293d5..0631fb0 with brief/report/diff. Final passed payload bound to code hash in root evidence. Source suites not redundantly rerun;90tests+1doc, fmt/check/clippy and ARM64-library compile reported. Independent approval pending.

Enrollment recheck: user-approved disposable client Running/online, same nnhXNghWF621CNTRL and100.120.226.13, not advertising exit. Separate guest gateway still NeedsLogin; current separate login link presented asynchronously. No identity reset, route advertisement, protected workload or production changes.

Task5 reviewer identified Important ownership issue: public VethPair members permit mixing host/transport tokens from independent same-plan pairs whose namespace-local ifindices collide. Cleanup may delete actual unverified peer before post-check detects mismatch. No production exposure (DOWN-only component); task6 gate remains closed pending full verdict/fix/re-review.

Task5 review verdict FAIL/Needs fixes; Important mixed pair cleanup and Minor Single multipart completion. Original implementer /root/native_network resumed fix1 for both, compile-fail + collision-before-mutation and framing regressions. Review preserved task-5-review.md. Unknown full runtime/traffic checks explicitly later gates, not component acceptance.

Ruling: split prepared launch-helper package into task6 admission and task6b execution, keeping full requirements in task-6-launch-full-requirements.md — process/container/staging validation and privileged execution have distinct review surfaces; neither alone authorizes runtime. Cost if wrong: another integration/review boundary, with no reduced security requirement. Task6 not dispatched until task5 approval.

Task5 fix1 code8a1c97c reports247991f+d63050e;15unit+compilefaildoc/fmt/clippy/ARM64compile/staticbuild PASS reported. Root reran changed cleanup payload584577685bd0b61a45dc610c0e708ef04f0171e823060681d1f8d6a6b7a2f284: guest attempt9 PASSexit0/.23s with5cases and0residualnamespaces. Review /root/review_network resumed scoped0631fb0..d63050e; approval pending.

Task5 fix round1/5:2addressed,0open; commits0631fb0..d63050e, independent /root/review_network spec PASS/quality Approved. Task5 complete bounded DOWN-only native network component (48293d5..d63050e, review clean). Full WP3/4/5 guard/activation/runtime gates remain pending; no READY claim. Task6 admission may begin after root evidence bookkeeping commit.

Task6 /root/launch_admission dispatched at47381e8, admission only per split ruling; exact pinned Tailscale digest added to task6 brief and supplied to implementer.

Root independent WG socket-birth kernel oracle (external ip/wg, no native component invoked) attempt1 FAILED positive capture sensitivity before tunnel; fixed tcpdump immediate mode. Attempt2 PASS with3encrypted ping replies after moving WG to data namespace containing only lo+WG. Positive control2plaintext markers; tunnel capture8outer WG UDP/0ICMP/0plaintext markers, root verified0residualnamednamespaces. Source+hash/evidence retained, no provider/Tailscale/fulltraffic gate claim. Native end-to-end socket-birth verification remains pending.

Task6 guest attempt1 FAILED docker_unavailable after synthetic container creation, hash223d4c87dc61c9d10c4b189b4d5f758af83be32be30b283ff99ba0478aa2eb91,exit1/.698s, no cases. Socket direct/version200 and fresh exact synthetic run0 isolate native projection. Redacted field presence/type diagnostics supplied: Docker omits inactive Mounts/Init/Tmpfs/Sysctls and emits null lists. Implementer adding precise optional handling and fixed error/stage diagnostics; failure retained in launch-admission-lab-evidence.json. No production changes.

Task6 guest attempt2 failedunsupported_configuration after native inspect. Root synthetic metadata diagnosis found exact default11maskedpaths omits/proc/interrupts; regular0444/rdev0,not exactmounted,no file bytes read. Explicit known11/12 profile support+negative subset tests added. Attempt3hash4185cb9 PASS6cases/1.279s. Final rebuilt code5dbcccb hashcc51f123326640a730639171d138f4132d09ca71dff98d243f14a2de2928605b attempt4 PASS6cases/1.139s,0residualsyntheticcontainers, guard_runtime:false activation:false. Two failedattempts retained. Exact code report and independent review pending; no worker exec/placement claim.

Task6 code5dbcccb9d37af11d11cb5e0f0fc766a89f71ea87 reportc071837;101workspace tests,fmt/check/clippy,ARM64rlib build reported PASS. Independent /root/review_launch_admission dispatched against47381e8..c071837 with brief/report/diff and root kernel evidence. Final approval pending. Task6b execution brief prepared only; no next implementation dispatch until gate.

Future guard integration risk: an owned early nft base-chain ACCEPT does not override a later Docker FORWARD DROP. Host veth transport forwarding must prove coexistence with Docker policy without unrelated flushes/restarts or broad exceptions. Need exact scoped ownership and quarantine retention for any necessary cooperation rule; do not assume endpoint-only owned tables alone grant forwarding. Read-only guest policy diagnostic performed; no policy mutation. Carry this into guard-task brief and mandatory real packet tests.

Task6 independent /root/review_launch_admission spec FAIL/quality Needs fixes, sole Important daemon SecurityOptions denylistacceptsempty/unknown/customseccomp; container nnp doesnotbind inheriteddaemon default. Original /root/launch_admission resumed fix1 for exact supported profiles and negativefixtures. Task6b gate remains closed. Review preserved task-6-review.md.

Task6 fix1 code338dcba280dbe0699640def7c63f9ed7f17e16c3: enumerated private daemon securityprofiles, exactbuiltinseccomp+cgroupns required, optionalAppArmor coherentwithcontainer, refreshandrevalidate.26focusedtests/fmt/check/clippy PASSreported. Root guest attempt5 hash312d59da7caa0e3ea97bfecc1e97be234c69a32608283517efcfcc6b26790144 PASSexit0/1.362s,6cases,0residualcontainers. Actual guestSecurityOptionsAppArmor+builtinseccomp+cgroupns andcontainerdocker-default selectedfieldsonly. NoAppArmor profile kernelNOT_RUN. Fixreport/re-reviewpending.

Task6 fix round1/5:1addressed,0open; codec071837..6a00433 reviewed independently specPASS/qualityApproved. Task6 complete bounded admission component (47381e8..6a00433, reviewclean). Production launch remains unavailable. Task6b maybegin followingrootbookkeepingcommit.

Ruling: task6b must verify seccomp/LSM confinement for host-launched workers rather than assume Docker inspect defaults are inherited — host exec doesnotinherit container taskfilters/labels. Testprobe mayuse test-only reviewedprofile, but production staysunavailable until realworker/Go policy is reviewed. Costifwrong: extra policy/staging integration work or compatibilityrestriction; avoids claiming confinement from unrelatedcontainerinit.

Task6b /root/launch_execution dispatched from c4b2236 after task6 independent approval. No production activation or real state/profile reads; root alone runs isolated harness.

Ruling: task6b synthetic execution profile retains zero worker capabilities and requires exact docker-default AppArmor plus reviewed minimal seccomp only for test probes — real worker/Go policies are absent and host-launched tasks do not inherit Docker confinement. Production loader remains unavailable; this component does not certify no-AppArmor execution or narrow the final Debian/Arch/Void platform contract. Cost if wrong: later confinement/capability integration work and additional kernel acceptance, rather than assuming unproved confinement.

Enrollment recheck this continuation: disposable client Running/online with unchanged nnhXNghWF621CNTRL and100.120.226.13; separate lab gateway NeedsLogin on existing enrollment link. Neither advertises an exit; no state reset or routes changed.

Ruling: namespace ownership records explicitly carry primary_exit_id, exact allocation membership, generation binding and admitted gateway base-netns dev/inode — allocation order or exit name must not guess which identity gets the compatibility base network. Test-only staging supplies it now; production creation waits for protected migration/config authority. Cost if wrong: explicit primary selection/config integration during migration; no silently adopted foreign identity or namespace. Synthetic resolver is fixed TEST-NET only; production validated resolver/profile integration remains unimplemented.

Root independent read-only pinned1.102.5 LocalAPI oracle: native Unix HTTP GET status/prefs both200; redacted field/type projections retained localapi-lab-evidence.json and linked future worker brief. Enrollment-only NeedsLogin/defaultNetfilterMode2/noadvertisement is not readiness; no preference writes or runtime/traffic acceptance.

Task6b smoke attempts1e9e5a47 and2diagnostic5c495a0 bothFAIL mount_isolation before successful worker exec. Owned namespace case passes; exact payloads/stages/times retained launch-execution-lab-evidence.json. Child mount substage propagation needs correction; no confinement/readiness claim. Root attempt1pin cleanup proved lockedrecord/dev/inode/membership, no live netns users, onlylo/no defaults before exact4unpins; snapshot/records retained. Initial cleanup assertion incorrectly required primary Docker loDOWN; diagnostic proved only primaryloUP, no otherlinks/defaults; no cleanup occurred until corrected bounded loopback-only predicate.

User approved separate lab gateway; native status Running/online n8P8U86ryZ11CNTRL100.101.230.31, notadvertisingexit. Existing disposable client and production untouched. No further enrollment requested.

Task6b attempt4source051c40f FAILexit1/.819s, fixed errno invalid at executable bind (not readonly remount). All4failedattempts and exact unused ownedpin cleanup retained; no workerexec/confinement acceptance. Root sent concrete foreign-mount-FD after unshare hypothesis for native descriptor-relative mount solution.

Ruling: permit a minimal safe core AllocationTransaction::verify_directory(BorrowedFd) authority check with focused mismatch tests — namespace persistence needs direct binding of its directory to the actual retained allocation lock/store, rather than indirect flock-busy inference. No raw FD getter, caller proof boolean or unrelated core refactor. Cost if wrong: one small cross-crate API/review surface; avoids claiming directory ownership from lock contention alone.
