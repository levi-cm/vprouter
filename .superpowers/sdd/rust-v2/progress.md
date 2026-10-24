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

Ruling: carry verified executable/state mounts with descriptor-relative open_tree CLONE+AT_EMPTY_PATH before namespace entry and move_mount on fixed private targets — binding proc-FD magiclinks after unshare produced EINVAL for foreign mount objects. No pathname fallback or weaker readonly/provenance requirement. Cost if wrong: additional reviewed mount API/handle inventory and focused kernel verification; preserves stable admitted identity. Implementer also tightening exact internal inherited-FD inventory instead of socket-only denylist, with directory/peer-netns negative tests.

Root public-source oracle: official annotated Tailscalev1.102.5 tag peeled5fb2a81b065b0a0bbbfc67ab20a0d9c6a1108115 matches actual lab versionprefix; source hashes/rule intent retained tailscale-routing-source-oracle.json for futureworker. Old routerpath404 followed observed directory listing to osrouter; no source assumption from404. Source-only oracle is NOT native/kernel routing acceptance. Both approved identities prefs independently show nullAdvertiseRoutes/emptyExitNodeID+IP, no selection/advertisement.

Task6b attempt5source041806d FAILexit1/.981s executable open_tree clone before worker placement; first3cases pass ownership/wrong selected exit/unexpected directory+peer namespace+socket rejection. Exact payloads and ownership cleanup retained.

Ruling amendment: descriptor-relative mount cloning must run while each source mount belongs to the current admitted mount context — host state before entry; container executable after entering admitted container mounts and before private unshare. Initial before-all-entry wording did not account for the executable FD foreign to host mount namespace. Cost if wrong: additional ordering/handle audit and another exact kernel run; no pathname fallback or provenance/readonly relaxation.

Task6b attempt6source9785b7c: descriptor-relative executable transfer no longer fails; FAILexit1/.877s descriptor_policy after setup/readiness stage; first3ownership/negative cases pass. Need exact fixed FD substage before attributing failure. Exact artifacts/result and cleanup retained; no post-exec success/readiness claim.

Task6b attempt7 source56fcb5c FAILexit1/.886s descriptor_stdio; exact null FD pathname was brittle after private detached root. Ownership/wrong-exit/unexpected host-directory/peer-namespace/socket cases passed. Root verified0remaining owned pins and0syntheticcontainers after strict offline cleanup.
Task6b attempt8 sourcedf4716e FAILexit1/.881s descriptor_inventory; prior descriptor_stdio no longer failed, first3cases passed. Exact payloads/result/ownership cleanup retained. No successful post-exec readiness claim.

Ruling: every surviving launcher wrapper must release implicit host root/cwd as well as inherited descriptors and capabilities — use an empty private root with no proc/state/old-root, then dedicated wait-only seccomp+LSM, caps0/nnp/securebits, parent-death rearm and pinned-parent race check. Path syscall denial alone does not satisfy release of host authority. Cost if wrong: another minimal mount boundary and kernel test surface; no broadened worker privilege. Root requires actual host-observed root/caps/FD inventory for each surviving child. Implementer confirmed persistent privileged wrappers gap before this correction; PID1 credential-drop PDEATHSIG already rearmed but explicit check/test retained.

Task6b attempt9 source8f8afd1 FAILexit1/.914s confinement_policy at first private probe readiness. Four cases passed including killed-gated-child actual placement failure (PlacementFailed/noexec); this does not verify wrapper final confinement yet. Root verified exact-owned0pins/0syntheticcontainers cleanup. Guest kernel journal exactrunwindow14:00:28..37UTC andlast120entries showed0AppArmorDENIED/ERROR; cause remains unverified pending fixed role/stage diagnostics. Both previously approved identities rechecked Running/online and notexitoptions; noreenrollment/statechanges. Production serviceactive, bothcontainersrunning/0restarts/OOMfalse (read-only check).

Root prepared task9 multi-Mullvad lifecycle brief only; dispatch gated on task6b+7+8 independent approvals. No runtime multi-exit/CLI activation authority supplied by preparation.

Task6b attempt10 sourcee1f5b41 FAILexit1/.882s wait_filter after4cases. Named code inspection found apply_filter postinstall PR_GET_SECCOMP self-check denied by wait-only BPF; narrow getter-only correction required, no general prctl permission. Attempt11 sourcee473304 FAILexit1/.919s descriptor_scan_denied after4cases, previous wait-filter failure cleared. Both strict owned cleanups0pins/0containers retained. Root static exact-probe disassembly (sha416f6eca) proves musl opendir uses open flags0x90000 and x86_64SYS_open2, excluded by probe filter; source witness retained launch-musl-opendir-oracle.json. Prefer safe descriptor-relative rustix directory enumeration preserving exact inventory without syscall-policy widening; implementer owns fix.

Task6b attempt12 source2a38658 FAILexit1/.907s mount_isolation after4cases; descriptor-relative rustix FD/proc enumeration cleared prior scan-denied failure. Attempt13 source775af5c FAILexit1/.918s same mount_isolation; stable source inspection proved probe checks no longer emit that generic enum, so hidden-init/proc hypothesis was not the observed fault. Root retained both exact results/strict ownership cleanups0pins/0containers. Implementer source audit identified PID1 pivot_root mutating mount namespace initially shared with intermediate; correction requires PID1 unshare private mount namespace before root changes, not timing sleeps or a weaker check. Kernel verification pending.

Task6b attempt14 source3a49908 FAILexit1/.932s descriptor_scan_denied after4cases, no success claim. Strict owned cleanup0pins/0containers. Root pinpointed rustix1.1.4backend/linux_raw/fs/syscalls.rs55: fs::open choosesSYS_open onx86_64 (onlyARM64 maps toopenat); explicitfs::openat(CWD,...) required for maintained Dir/getdents path. Prior phrase scanfailurecleared inattempt12 meant it was not the first observed failure, not proof the scanning branch passed. Same applies to mountfix until successful all-role verification.

Task6b attempt15 sourcee515c86 FAILexit1/.901s capability_policy after4cases. Attempt16 sourcef5503e1 FAILexit1/.944s exactrole probe_after_exec status_read (before credential field parsing). Both strict ownedcleanups0pins/0containers retained. Root candidate16 static binary oracle confirms std::fs::read_to_string -> stdunixFile::open_c ->muslopen->SYS_open2, extending launch-musl-opendir-oracle.json. Earlier assumption normalstdfileI/O usedopenat was unverified and incorrect for this static target; correction uses bounded explicitopenat without SYS_open widening. No credential weakening or postexec success claimed.

Task6b attempt17 source98176e7 FAILexit1/.953s probe_proc_hidden_init after4cases. Explicit postexecboundedopenat removed prior statusreadfailure as first error; new exact witness is visibleprocset{2}/getpid2. Rootstrictcleanup0pins/0containers retained.

Ruling: private proc test requires selfPID2 and accepts only visible sets{2} or{1,2}, rejecting any otherPID; anyvisiblePID1 root must be same selected root or explicitPermissionDenied. Independent host MUST establish actual privatePID1 NSpid1 and matching worker root/mount/PIDnamespace plus separate exit isolation. hidepid2 plus nondumpablePID1 intentionally hides that process, so requiring its enumeration contradicts the stronger visibility boundary. Keep hidepid2/dumpability and all host checks unchanged. Cost if wrong: test could overaccept a missinginit absent the required independent host witness; witness is mandatory before component acceptance.

Task6b attempt18 sourcef803f5b FAILoverall exit1/2.071s ownership_mismatch during finalcleanup after10actual casesPASS: placement fault, twoexit privatePID/proc/root/state/FD/caps/seccomp/AppArmor, allsurvivingwrapperemptyroots, frozenreaping, launcherparentdeath andcontainerdeath. This is partial runtime evidence, not component acceptance. Root collector foundall4pins stillpresent,0netnsusers,onlylo/nodefaults and0syntheticcontainers; strict externalexactownedcleanup succeeded. Harness therefore refusedbeforefirstunpin, causepending fixedstage/errno diagnostics. No fullsuccess/readiness/release claim.

Task6b attempt19 source97fd1b8 FAILexit1/2.014s after10actualcasesPASS: exactfirstdata unmount busy, verificationFD itself retainedpinnedmountreference. All4pins retaineduntil strict externalcleanup,0residualresources. Attempt20 sourcebff77724213f0c275ecc1b1b119a3fcb605871fe PASSexit0/2.187s all11cases includingnormal exactownedunpin/container/directorycleanup. Exactlabhasha49a89a3e5db007e20242615422fed039f06bdf7e9dd32a33e324b9285e38be8/probehash7c6a7d16c02a48963dfbe79babbc353d46d37c78c2202dd28f85cd82ab42ae1c. Rootindependentlyverified0launchlabcontainers/0ownedpins; harnessselfcleanup,controllerremovednothing.19failedattemptsretained. Implementer exactsource109tests/0fail/2ignored/3standalonelabskip,fmt/clippy/ARM64libcheckPASSreported; reportfinalization/independentreviewpending. Task6b NOTcomplete yet; no actualworker/guard/transport/realclient/releaseacceptance.

Task6b finalized report6a2cbb30af1bf803aaf22a4bed80204b115b96e1; sourcebff7772 unchanged. Root verifiedall20reportfile/artifactSHA256rows against currentbytes. Independent /root/review_launch_execution dispatched with brief/report/full43commitdiff c4b2236..6a2cbb3 and binding userconstraints, wrapper/proc rulings, exactkernel109test evidence. Implementationconcern2166lineunsafe module explicitly carried into review. Nexttask7 NOTdispatched before reviewapproval.

Root prepared task10 explicitdirect brief only, gated on reviewed single/multiMullvad runtime; no direct configuration/identity/path created. Task6b independentreview ongoing, emerging concerns acknowledged but full verdict pending before fixdispatch.

Task6b independent review /root/review_launch_execution specFAIL/qualityNeedsfixes:3Important (PID1 close enumeration/errors+exactFDverification; repeatedsignalsresetboundeddeadline; signaltestforcescleanupbeforeassertingforwarding) and2Minor (stalecratedescription; kernelsectionboundaries). Fullreviewpreservedtask-6b-review.md. Originalimplementer resumesfixround1/5 for all3Important andbothMinor, scopedbase6a2cbb3. Task7 remainsgated. Run20 evidence is synthetic partialPASS, not approved component.

Task6b fix1 candidate b62cc5c kernel attempt21 PASS exit0/1.648s/all11cases. Actual stopped/forwarded/reaped/natural repeated-signal witness completed529ms; exact labccd0bcb8/probe808789d0 hashes verified locally+guest. Collector proves0residualpins/containers, harnessselfcleanup/controllerremovednothing. Original19failedattempts and run20 retained; run20 signalclaim explicitly invalidated by review. Fix report/fresh covering checks and scoped independent rereview pending. No production or release acceptance. Prepared tasks11client and12migration briefs only, commits41a5dc9/b08d299; no future implementation bypass.

Task6b fix round1/5:3Important+2Minor addressed/0open; commits6a2cbb3..427a124, independent scoped /root/review_launch_execution specPASS/qualityApproved/newbreakagenone. Root independently checked5amendedsourcehashes, exactstaticbytes/guestresult/absence. Task6b complete bounded synthetic execution (c4b2236..427a124, reviewclean); actual worker/Go policy, guard/transport/client/platform/release gates remainNOT_RUN. Sole unsafe2439lines concern retained for wholebranchreview. Task7 nativeworker begins after this approval, base recorded next dispatch.

Task7 /root/native_worker implementing nativeclients/decisionengine atbase7bf59fc. Production bridge to actual placement/guard/protocol is unavailable and remains task8; no forged bool/readiness constructor. Root independent pinned1.102.5 kernel oracle in NEWmemstate/no-login/netnone/NET_ADMIN+TUN container proves7IPv4/6IPv6rules and exact rawrule attrs; explicitmode0prefs leavespolicy rules unchanged. Defaulttailscale0 fe80/64/kernel_ll routes observed, must suppress/clean before protectedreadiness rather than loosen IPv6policy. Bothoraclecontainers exactremoved; no enrolledstate/WAN/advertisement/productionchange. Evidence711b450 storesbothobservations/sourceSHA256/rootmarker. Preparedfuturetasks13release/14performance/15realclientcanary briefs5ea0d78/327f61b only. Reasked missingsecond-install SSHhost/user/port asynchronously; ZIPandapprovals alreadyavailable, no reenrollment.

Ruling: worker withdrawn recovery may observe stableonlineidentity/safeprefs with ExitNodeOptionfalse, but neverREADY; after3freshprovider/structural samples explicitly advertise under retainedguard protection and require fresh offered+approvedtrue beforeREADY. Official1.102.5 ipnstate.go277 definesbit asoffered&&approved/local.go1637 derivesnetmapAllowedIPs, so requiringitbeforeadvertising coulddeadlock. Costifwrong:extra recoverytransition/approvalwaiting tests; nevergrantunapprovedREADY. Independent sourceoraclerecorded, actualcontroltransitionNOT_RUN.

Task7 final source ad9b38d/report e0cc64e:139workspace/26worker tests,fmt/clippy/check/static x86+ARM64 reportedPASS. Root independently verified24sourcehashes+aggregate050ad3d and exact static artifact hashes. Actual native parser attempt1 setupFAIL beforeexec (foreign mount canonicalization), retained; corrected readonly private tmpfs/proc-root exactsocket attempt2 PASSexit0/.150s, pinned1.102.5Running/online/mode2/noadvertisements, guard_runtime:false activation_ready:false. Evidence worker-localapi-lab-evidence.json/tools retained; no daemon/state/preferences/production changes. Independent review pending; task8 remainsgated.

Task7 independent /root/review_native_worker specFAIL/qualityNeedsfixes:2Important (realHyper/TLS underlying transient transport classification bypassesretry; staleRECOVERING offer and staleREADY OkBlocked bypasses guard/withdraw enforcement),0Critical/Minor. Fullfindings task-7-review.md. Original /root/native_worker resumesfixround1/5, base04ecfc6. Cannotverifyactualruntime items confirmed task8+gates; task8 remainsclosed.

Task7 fix1 source5955020/report115e626:2Important addressed reported; actual controlledEOF/reset retry+postdelaydrift/certnoRetry, pausedexpiry guardFIRST/withdraw redgreen;71focusedtests/fmt/clippy/ARM64check+rlib/staticx86 PASSreported. Root verified8amendedsource/doc hashes+26fileaggregateed1e1ec andARM64rlib; rebuiltx86artifact916a904b guestattempt3 PASSexit0/.159s with unchangedactualsocket/noWAN/noadvertisement. Originalattempts1/2 retained; sourcecorrectness re-reviewpending, production/realtraffic/guardgatesremainclosed. Controllerdriver now propagatesfailureexit; py_compilePASS.

Task7 fix round1/5:2Important addressed/0open; commits04ecfc6..0522fa1, independent /root/review_native_worker scoped specPASS/qualityApproved/no newbreakage. Task7 complete bounded native monitoring engine (7bf59fc..0522fa1,reviewclean); production worker construction/guard/image/traffic/platform/releasegates remainunavailable.

Ruling: execute task8 in three ordered integration slices:8a actualguard-owned nativeUP/address/route/WGsocketbirth and atomicbootstrap/cooperation packetproof;8b actualRust/Go manifests+placedworker/Tailscale kernel authority;8c autonomousguard/protocol/watchdog/lifecycle and fullsingleexit acceptance. Current APIs are intentionally DOWN-only and actual daemon manifests/guard endpoints absent, so prove live lower-layer containment before joining launch/monitoring. Fulltask8 remainsincomplete until allthree independentlyapproved; multi/direct/migration gatesunchanged. Costifwrong:additionalreview/integration boundaries and rework, no reduced useracceptance or productionauthority.

Task8a /root/guard_transport dispatchedfromfefde3d after task7 scopedapproval; actual nativeguarded transport/bootstrap packetpath only. Full8b/8cdaemon/guard/clientreadiness gates remainclosed. Rootalone runs ownedguestignoredpayloads; no productioncredentials/state.

Usersteer2026-10-24:alltestinglocally. No furtherremoteSSH attempts/questions. Contract/acceptancematrix/futuremigration+canarybriefs amended: secondmigrationcase uses separate locallegacydeployment with independentestablishedtestidentity+adapters and exactrollback; label evidence localcompatibility, not remoteinstallationvalidation. Alltraffic/fault/benchmark/soak/platformgates retained; localVM SSH127.0.0.1 remainsallowed.
Rootread-only DockerFORWARDshape oracle at15:17:20Z:actualguest ip/filter/FORWARD typefilter/hookforward/prio0/drop/FLAGS1/USE6 and6Docker rules; exactrawchainmessage+nftJSON retained docker-forward-chain-oracle.json/source2130ddbc. No mutations orpacketclaim; sent nativecooperation implementer.

Ruling: task8a bootstrap must constrain locally originated applicationtraffic aswell as TailscaleFORWARD because legacyconsumers shareprimarybaseNS. Add exactowned health/control cgroupv2 subgroup+native nft socket-cgroup selector with retainedID/level/parent/exit/generation/namespace authority and actualsameNSauthorized-vs-otherproducer packetproof;8b placesrealworkers before anysocketcreation. Do not restructureDockerparent/enablecontrollers; exactemptyownedcleanup, ambiguityquarantines. Costifwrong: additional kernelcapabilitypreflight/placementintegration and platformevidence; avoids mislabeled allWG-OUTPUT bootstrap. Userplatform/trafficgates remainunchanged and missingcapabilityfailsbeforeexistinginstallationchanges.

Task8a candidate01 diagnostic: immutable source archive5acd43a2/artifact723a7336,
root exact-hash host-netns admission in owned local VM at15:30:20Z. Failed
network_operation before native veth/WG creation; phaseactivating and owned
host/transport/data main+emergency quarantine tables observed. Docker FORWARD
preserved ignoring counters; no captures/traffic started. Full private run and
read-only inventories retained under target/lab-state; public redacted attempt
ledger docs/rust-v2/guarded-transport-lab-evidence.json. Implementer identified
strict host projector rejecting existing Docker bridge-slave metadata; next
candidate must distinguish observable foreign host metadata from prohibited
metadata on owned protected links. No identical-payload retry.
Root removed only exact failed-attempt synthetic WAN veth after matching
record/container labels, ifindex6/MAC/alias/kind/peer reverseindex, exact185.65.134.89
address and185.65.134.88 endpoint route. Route removed with link; test container,
namespace pins, producer group and quarantine retained. No guessed table cleanup.
Exact-artifact admission marker removed after run. Controller runner retains
source archives/payloads and all unsuccessful runs; no runtime acceptance claim.
Task8b brief prepared but undispatched pending8a approval. Current8a cgroup profile
is exactsystem.slice/Docker level3; derive from verified hierarchy or explicitly
retain runit/nonmatchingprofile certification as an unperformed release gate.
Task8a attempts2-4 (candidates03/04/05) retained: each failed before native
owned links, create_veth_down Unsupported then exactattrs54/56. Existing host
Docker slave promisc/master/bridge metadata and physical permanent-address/parent
metadata surfaced strict projector gaps; protected-link checks remain strict.
Controller initially guessedattr54 PROP_LIST incorrectly; implementer confirmed
IFLA_PERM_ADDRESS against pinned crate/UAPI, public evidence corrected. Complete
read-only RTM_GETLINK attribute inventory collected afterattr56 to avoid further
per-attribute mutation cycles. Only exact failed synthetic WAN veths removed with
snapshot identity/ownership checks; all quarantines/container/ns/group state
retained. Attempts and exact binaries/source archives kept, capturesNOT_RUN.
Task8a attempts5-9 retained with exactsource/payloads: raw bridge INFO_DATA
framing was still rejected before explicit projection; fixed with raw positive
bridge/negative peergrammar tests. Next whole-host address and route gaps were
resolved with complete read-only raw RTM address/route fixtures, retaining full
flags/broadcast/metric/NHID/preference and rejecting unexpected protected values.
Attempt8/9 reached actual WGcreate+move and IPv4assignment; hostpeer route failed
errno100 ENETDOWN while allcontrolledlinks stillDOWN behind offlinequarantine.
Ruling: bring exactownedlinksUP before routeinstallation, retaining fresh
three-scopeofflinepolicy verification beforeeveryoperation — kernelrequiresUP,
and userrequiresquarantinebeforeUP, not routesbeforeUP. Costifwrong: new ordering
needs exactpacket/fault proof; no activation/readyauthority granted.
Agent selfreview identified pre-staged broadpermit behindrestrictedbootstrapq:
removingq could expose localOUTPUT beforeaudit. Bothpermit+q must remain actual
producerrestricted bootstrapfilters and reconcile exactstage; independent removal
faulttests must show zeroforbiddenmarkers throughout. No readinessconstructor.
Ruling: task8a failedatomic test uses fixed ignoredharness nftCLI batch against
actualbootstrap, requires failure+exactunchangedpolicy+nativeaudit+health. Existing
task4 covers nativeactuator failurebatch; cite separately. No new Cargo test
actuationfeature/API — avoids expanding production authority just for injection.
Costifwrong: narrower component evidence; fullruntimefault acceptance staysclosed.

Task8a attempt11 candidate13 source1abe8b3d/artifactf3ed27df FAILexit1/2.126s. Initial native bootstrap/socketbirth, threepoint capture sensitivity, unauthorizedsameNSproducer and establishedtuple producerdenial casesPASS. Fault0(WGdown/up) reaches fullquarantine but exactrestorationauditDrifted. Capturedefaultpromiscuity may interfere with retainedhostbaseline; nextcandidate uses -p and scopednativeauditdiagnostics, no policy/deadline relaxation. ExactWAN11 provenancecleanupPASS, allother resources retained; fullfault/realclient/releaseclaimunavailable. Candidate12 supersededUNRUN.

Task8a attempt12 candidate14 FAILexit1/2.136s DataDrift onfault0restore. Nonpromiscuouscapture+freshprefaultaudit resolveinstrumentationambiguity; read-only data inventory proves WGdown removedIPv4default, linkUPalone didnotrestore. Correcttest mustrestoreexactauthorizedroutesunderofflinepolicy beforeaudit, no acceptance relaxation. ExactWAN12 provenancecleanupPASS; allotherownedresources retained. Initial4casesPASS arepartial, fullfault/client/releasegatesclosed. Task8c brief preparedonly, gatedon8a+8b independentapproval.

Root independent fixed-PCAP metadataoracle validates attempt12 framing+records+counters:2positivehealthpayloads indata,0healthplaintext intransport/host,1plaintextsensitivitycontrol eachtransport/host,0kerneldrops across6captures. Negativepartialcaptures0forbiddenprefix; failedfaultmatrix meansNOcompletecontainmentclaim. Collector firstrefusedDebiantcpdumpownedPCAPs, then explicitlyvalidatedroot/tcpdump UID+GID underroot0700testdirectory; no runtimepolicychange. py_compile+actualreadonlycollectionPASS.

Task8a attempt13 candidate16 FAILexit1/2.38s HostDrift restoringfault4; initial4+fault0-3PASS. Continuous2mssender spansfaultwindows; completeverdictunavailable. SyntheticWANautoconfnotdisabled, linklocalDADflagssettleafterhostbaseline; testfix disablesaddrgenbeforeUP, no auditrelaxation. ExactWAN13cleanupPASS; partialcapturemetadata retained. Candidate15 supersededUNRUN.

Task8a attempt14 candidate17 PASSexit0/3.981s boundedreversibletransport suite:15networkfault recoveries+failedatomic+bothindependentdatafilter removals+functionaldrift;0forbiddenmarkers insyntheticcaptures,positivecontrols present,0kerneldrops. Rootindependentlyframed6PCAPs and verified737continuoussendattempts/55checkpoints>=3attempts each/joined. Cleanupinspection:0nativeownedlinks all3scopes,producerabsent,phaseoffline,q+emergencyretained eachscope,originalDockerFORWARDrules+handlespreserved ignoringcounters. Root exactWAN14cleanupPASS. Terminaldeletion/collision/interrupt/cooperation cases stillrequired; no complete8a/realclient/releaseclaim. Controller runner now fixedscenarioenum, no arbitraryargv; py_compilePASS, actualscenario invocationpendingnextpayload.

Task8a finalsource222fa7c exactarchive7ce5d888 matches81trackedRust/Cargo/toolchainfiles, aggregate7f63dc65. Frozenartifactbd7d9a06 passesall7modes attempts15..21:deletedWG2.473s/deletedtransport2.381/cooperationdrift2.381/foreignWGtodummy2.369/activatingcheckpoint2.329/cleanupcheckpoint2.180/reversible3.938;0exitsfail. Rootindependent6PCAP framing/records/0drops/positivecontrols/0forbiddenmarkers andcontinuouscheckpoints verifiedeach. ForeignDockerFORWARDrules+handlespreserved ignoringcounters; terminalownedstate retainedwithemptyproducer, finalreversible0nativeownedlinks+producerabsent/phaseoffline. AllrootWANonlyexactcleanupsPASS. Ordinary152tests/fmt/clippy/ARM64/staticbuild reportedPASS; report+independentreviewpending. DeterministiccheckpointnotSIGKILL; foreignreplacementnotstartupcollision.
Ruling: 8a has no actual Tailscale forwarding/readiness, so forwarded spoof-source packet acceptance stays in8c/realclientmatrix, not inferred frompolicyunits. Replacementcollision+exactindex/kind/refusedreacquire are scoped8aownershipproof; add preexistingstartupcollision to8cstartupfaults. Costifwrong: laterintegrationtest/reviewrework, no release/readinessgate relaxed.

Task8a report3aad72e finalized, code222fa7c. Root verified81sourcearchivebindings + x86static67947757/ARMstatic348434c9 bytes, all7finalguestscenarios and independentcapture/ownership evidence. Authoritative11commit reviewpackage fefde3d..3aad72e generated431412bytes. Fresh /root/review_guard_transport dispatchedforindependent spec+quality; no8bimplementation beforeapproval. Rootfullq/production/client/platform/performance gatesunchanged.

Task8a independent /root/review_guard_transport specPASS/qualityApproved,0Critical/0Important/2Minor: networklib summary incorrectlysaysnoactivationAPI; reportoverstatesbootstrapIPv4addresspredicate versus actualfamily/WGpath/producer/establishedINPUT+separatestructuralaudit. Fullreviewretainedtask-8a-review.md. Bothminorcorrections carriedinto8b andfinalwholebranchreview. Task8a completeboundedguardedtransport (fefde3d..3aad72e, independentreviewapproved); fulltask8still8b/8c pending. Unverified realworker/autonomousguard/SIGKILL/forwardedspoof/platform/client cases confirmedgatedin8b/8c+acceptance.json. No releaseorproductionauthority.

Task8b /root/real_worker_placement dispatchedbase150dc7a, exactbriefreadfirst. Ruling: split8b into8b1 fixedprogrammanifest/producerplacement/authenticatedprotectedconfig/observationonlyworker, then8b2 actualGo fixedexecution/confinement/kernelmetadata+image;6b isprobeonly,7hasnoexecutable/Placedconstructor and8ahasnochildplacement. Costifwrong:additionalreviewboundary/rework; full8b+task8/client/releasegatesremainclosed. Implementercontinues8b1, noadditionalimplementer. Root publicamd64+ARM64 tailscaled/CLI/CAinventory bindsupstreamindexc507f3a2 andchilddigests08a1bc6c/472c549d; copiedfixedpublicfiles only fromnewstoppednetworknone/statefreecontainers, exactcontainersremoved, noexecutedprogram/identityaccess. DaemonSHAb2ec9812(x86)/3cf26400(ARM),CA028fca51both. Toolpy_compile+actualbothplatforminventoryPASS; runtime/platform/releaseprovenanceunverified.

Context resumption2026-10-24: user local-only scope retained; no remote access attempted/requested. Root freshly verified owned Debian guest6.12.113 markerroot0600,1443MiB available/9.5GiB free/22historicalcontainers; no mutation. Production serviceactive/routerhealthy/restarts0, unrelated dirty legacycheckout retained; legacy status/probe not invoked. Root independently rehashed all6publicprogram/CAfiles + ELFarchitecture + inventorytool; exactpinnedinventorymatches, runtimecertificationNOT_RUN. securitymap70d5967 records scoped8aapproval and pinnedprograminventory. ac8b697 codifies existing8b1split for review, no authority expansion. Original implementer continues; frozenpayload pending.
