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

Task8b1 candidate01source7c08bd6 archive73109a57: root independently matched all97trackedbuildinputs (including bothprogrammanifests), aggregate544cadb6; x86artifactfad89759/ARM26369b83 ELF+hash+static verified. Localproducerattempt1 FAILexit1/1.697s afterexacthash/ns/probe preflight, no testcasecomplete, placement_failed beforelaunchstage. Exactsource/artifacts/rawrun retained. Rootreadonlyinventory task8b1-31505: exactcontainerabsent/cgroupabsent, oneActivating+producerintent/twoOffline records retained, noobserver/transport, approvalmarkerremoved. No cleanup guessed. Implementer diagnoses earlier admission error beforekilledchildtest; nextcandidate adds boundedtestdiagnostics, no acceptance/predicate relaxation. Actualobserver/Go/client/releasegates remainNOT_RUN.

Task8b1 diagnosticcandidate02sourcec18f55f/artifactbde41de5/archivea4244176 independently97inputmatched; attempt2FAILexit1/1.408s. fixedprogram/allocation/nsbindingsPASS, containerrevalidationCgroupMismatch beforefirstcase. Likelyownedproducer-mkdir changed parentcgroupmtime/ctime capturedbeforemkdir; implementer checking stableidentity versusmutablemetadata, no path/owner/inode/membership bypass. Bothfailedattempts exactcontainers/cgroupsabsent, Activatingrecordsretained, markersremoved. Publicfailedhistoryproducer-placement-lab-evidence.json; rootverifiertool compares97committedbuildinputs without extraction.

Task8b1 candidate03sourceffb7053/archivea01c4d3b/artifactc48a8fcf: root97inputcomparisonPASS aggregate730d5841; localattempt3PASSexit0/2.207s all8exactcases independentlychecked. Fix distinguishes immutablecgroupdev/ino/fullmode/owner/group fromsize/timestamp changes; codecoveringregression reported22focusedtests. Rootpostruninventorycb70d8b1: all3exactcontainers/parentcgroupsabsent, interruptedActivatingrecordsretained, root600result.json pass_partial_producer_placement/observer+GoNOT_RUN/readinessfalse, approvalmarkerremoved. Postexitnamespacebindmountpersistenceoutsideprivaterunnermountns NOT_VERIFIED, no inferredclaim. ARM03c0f74c26/2982168/ELF183/noDYNAMICverifiedbuild-only; actualobserver/Go/clientreleasegatesclosed. Publicproducer-placement-lab-evidence.json preservesall3attempts and exactsource/artifact/history; report+independentreviewpending.

Task8b1 report8761fb8 finalized, sourceffb7053; rootverified x86finalstaticELF/hash and all3run+runnerhashes againstreport. No buildinputchanges throughreportcommit. Full10commitreviewpackage150dc7a..8761fb8 (165573bytes) generated, /root/review_worker_handoff dispatched freshforindependent spec+quality using samebounded8b1brief/report/globalconstraints; no8b2implementerbeforeapproval. Finalordinary161tests/22focused/fmt/clippy/ARMchecks+staticbuild reportedPASS. Root8caseguestPASS remainsfixedprobeproduceronly, noobserver/Go/readiness/clientreleaseclaim.

Task8b1 independentreview_worker_handoff specFAIL/qualityNeedsFixes,0Critical/2Important/0Minor. Important1: blocking UnixStream::connect beforeboundedframeIO canhangfullbacklog; implementnonblockingabsolute-deadlineconnect+focusedlocalbacklogtest. Important2: requiredconsume-on-failure/secondattempt/wrongnonce+digest/staleresponse refusaltestsabsent; productiongateexistsbutuntested. Fullreviewretainedtask-8b1-review.md. RootresolvedallCannotVerify items: liveobserver/Go/mount/ARM/client remainexplicit8b2/8c;97input/8case/ownershipevidence independentlyverifiedabove. Originalimplementer resumedfixround1/5 fromreviewhead8761fb8, bothfindingsverbatim, coveringbootstrap/handofftests and refreshedbotharchmanifests/artifacts required. No8b2dispatchbeforeapproval.

Task8b1 fixround1 source4511476/report7b1f453: blockingconnect regressionRED250ms thenNONBLOCK/CLOEXECdeadlineGREEN; privatehostoneuse+requestbindings and workerstaleresponse testsGREEN; mutations disablingconsume/noncechecksRED thenrestored. Report coveringbootstrap8/handoff2 tests,166workspace/24launch/fmt/clippy/ARMchecks/staticbuildPASS. Rootcandidate04sourcearchive73b5eabd matches97inputs aggregate6bf9ab58, all4producer+observerstaticELF/hash/manifestsverified. Localproducerattempt4PASSexit0/2.154s same8caseobjects as03; inventorya39f935d all4exactcontainers/cgroupsabsent/Activatingrecordsretained/markerremoved. RootproducerrefreshdoesNOTproveobserverdeadline/replay; focusedunprivilegedtestscoverfixes, actuallivehandoff8b2remainsNOT_RUN. Publicevidencepreservesall4attempts. Re-reviewpendingfrom8761fb8.

Task8b1 fixround1/5 independentlyreviewed8761fb8..8d8611fdc470cbcfe654c45fedce0a4030a35ef5: bothImportantADDRESSED, no newbreakage, specPASS/qualityApproved; fulltask-8b1-fix1-review.md retained. Packageheader used literalHEAD; root separatelyresolvedfull8dSHA and reviewerrecordedexactpackagebytes. Additional04aed5a14line report-only actualcandidate04note independentlyrootverifiedagainstpublicevidence/rawhashes; no buildinputchanges4511476..04aed5a. Task8b1 completeboundedcomponent (150dc7a..04aed5a, independentapprovalafter1fixround). Original8aMinorcorrectionsincluded, no newminor/parkedfindings. Full8b remains8b2actualexecution/image/kernelmetadata,8cautonomousguard/clientacceptance; nogateinferredfromproducerprobe. Nextfreshimplementer8b2 onlyafterthisapproval.

Task8b2 fresh /root/actual_daemon_execution dispatched after8b1approval frombase836210a12a37860a8e0ba7771e787c3f77b0cfa1; exact8b2brief/parent/contract/report, root-onlyprivilegedlocalVM/testing and public-whitelistimagecontext rules supplied. Initialdesignfixedrolepolicies insolekernelhelper, actualimmutablepublicrootfs/init, identity-freeexecutionoracle, demonstratedTUN/NET_ADMINonly; noactualDocker/SSH/profile/identityaccessbyimplementer. Full8b2/runtime/clientreleasegatesremainclosed; nextfrozenpayload/context pending.

Task8b2 root-onlyprerequisite: ownedguestroot0700+isolatedacceptanceroot600freshverified, apt-getupdate/install--no-install-recommends strace bothPASS; strace6.13 installedonlyinlocalVM, no productionchange. Requiredtraceoutputmetadata/summaryonly, no decodedIO/getrandom/credential/environmentpayloads. Implementerconfirmedobservationmetadata excludesprivilegedWGGET so caps0unchanged; actualdaemonneeds exactTUNchar10:200rwmDockerdeviceadmission, no broaddevice/capabilityoverride. No8b2payload/imagesexecutedyet.

Contextresumption2026-10-24: rootfreshlyverified ownedlocalVM root0700/isolatedmarkerroot0600, kernel6.12.113/cgroup2,1425MiBavailable/9.6GiBfree; allhistoricalandenrollmentcontainerspreserved. Productionreadonlyserviceactive/routerhealthy/bothcontainersrunning/restarts0; legacydirtycheckoutunchangedandlegacyprobesnotinvoked. Existingsole8b2implementercontinues. Rootaddedcontroller-only actual-program-oracle.py: frozencommitsourcebinding, strictpubliccontexttar/ELF/hashwhitelist, localguestnetworknone scratchbuild, protectedexactimage+payloadmarkers, boundedfixed--ignoredpayload andfailurepreservation; py_compile/diffcheckPASS, runtimeNOT_RUN. Rootraisedfd4reuse distinction; implementerconfirmscombinedprivate-root/noexec/proc/nondumpable confinement ratherthanone-shotseccompclaim, addingexplicitstateexec/init-procdenialtestsbeforefreeze. Noauthority/releasegateopened.

Rootcontrollerobservabilitypreparation: exacttask8b2metadata-only actual-program-inspect.py added; sharedcaptureoracle now admitsonlyexacttask8a/task8b2directories withseparatemarker/countsets, WANcleanup acceptsbothexactprefixeswhilekeepingretainedresource/link/peer/routeprovenancechecks. Host+embeddedguestsyntax/diffchecksPASS; actualinventory/captures/cleanupNOT_RUN. No daemonstate/argv/environment/configuration/payloadreadouts; no runtimepolicyedits.

Task8b2candidate01source61201d8/archive2b8f5662 root101buildinputsmatchedaggregate8e5e6801,all13frozenfilesandbotharchstaticELFsverified; amd64strict6publicfilecontext10b80188 passedwhitelist,noprivatematerial. Rootbuiltlocalnetworknoneimageca415d3f/layerf37c1d35. Attempt1FAIL5.468s afterfirst2bootstrapcases, child_failedinactual_daemon_fixed_program_launch; attempt2same01rawmetadata-onlytraceFAIL4.322s. All34rawtracefilesverifiednoquoted/decodedstrings, child33895openEROFSafterlastTUNbind/remount, exit0x76, noexecveatreached. Sourceactual_rootIPv6sysctlwriteorderingunderreadonlycontainerprocidentifiedforfix, no capability/syscallrelaxation. Rawrun/inventory/trace+source/artifactsretained; publicactual-program-lab-evidence.jsonrecords failures. Rootliveattempt1dataNSdev4ino4026536019bindsrecord+DockerPID:onlylo+ownedWG,dp/dqpresent,producerempty,syntheticWANabsent; no guessedcleanup. Bothadmissionmarkersremovedaftereachrun; bindmountpersistencenotverifiedoutsideprivatemountns. ActualGo/observer/captures/clientgatesNOT_RUN, no releaseclaim. RootrunnernowretainscontentaddressedinitplusEXCLfixed01artifact and supportsfixedraw=allmetadata tracing.

Task8b2candidate02source9e39b547/archive869e7e64 root101inputsverifiedaggregatedc040a0d,all13frozenfiles/botharchstaticELFsverified; contextf996b59a strictwhitelistPASS. Attempt3FAIL6.875s includingbuild: owned-dataIPv6suppressionnowbeforecontainerreadonlyproc successfullypasses; Goexecveatreached(trace34322bce858ad) butsupervisinginitfailsdescriptor_scan_openafterinstallinginitfilter (trace34321af28bcbb,openatflags0x98000EPERM,healtherror,exit0x73). All36rawtracefilesnoquoted/decodedstrings; Gohealth/LocalAPI/observer/capturesNOT_RUN. Exactrawrecords/source/images/inventoriesretained, no guessedcleanup. Rootaddedboundedactual-program-trace-summary.py andextendedindependentcaptureoracletoall3actualscopes+markers. Positivewhitelist01andforeignmember-rejectioncheckPASS; syntaxchecksPASS. Agentfixingpostfilterinitdescriptorverificationwithfocusedregressions; no releaseauthority.

Task8b2candidate03source5be564b3/archive2c00d01c root101inputsverifiedaggregated9309ae2,all13frozenfiles/botharchstaticELFsverified; contextfc7f332b strictwhitelistPASS. Attempt4FAIL6.875s includingbuild. Actualinitsupervisor now exactFDinventoryimmediatelybeforefilter, postfilterscalarverification/healthack/close/loop; no openallowanceaddedand6bsyntheticverificationunchanged. ActualGotrace34751d85c403f shows execsuccess then cloneflags0xd0f00EPERM (demonstratedthreadSETTLSvariantnotallowedby0x50f00/0x3d0f00), exits2andhelperspropagatefailure. Raw36filesnoquotes; allimages/source/artifacts/inventory/recordsretained, markersremoved; actualhealth/LocalAPI/observer/capturesNOT_RUN. Agentaddingexactflaggrammar+negativefork/ns/upperwordtests; rootendorsesprivatefuturedaemonshapetokenonlyafterliveexe/starttime/pidfd/group/ns/manifest/generationverification, never setupackorlearnedwildcards. No readiness/client/releasegateopened.

Task8b2 candidate04 sourced87112f/archive2fd23e42 root101inputsverifiedaggregate4811dc6e/all13files/botharchstatic. Attempts5rawtrace FAIL6.707s and6fixed-file-metadata FAIL4.326s: exactGo0xd0f00 threadflag fix passes; pinnedlogpolicy ignores statedir, witnesses .local EROFS/getcwd EPERM/missingtmpfallback (35392 SHA335127a9). Inventories5/6 collected rootreadonly; no fixture metadata result yet, all resources/records retained and markers removed. No broadened confinement; fixed daemon-only TS_LOGS_DIR=/state + TS_DEBUG_FIREWALL_MODE=nftables source-proven nextcandidate.

Task8b2 candidate05 source3ff8431/archive500c9acf root101inputsverifiedaggregate49f565aa/all13files/botharchstatic/context12d17a5d strict6publicfilePASS. Attempt7 FAIL6.812s, first2bootstrapcasesPASS, Goexec35765 SHA316981a0 reaches eventloop; process_unavailable in harness before durableprocess/metadatahealth evidence. Raw42files verifiednoquotes/decodedIO; fixed logstate/nativefirewall setting removes previous panic, no syscall changes. Readonlyinventory7/source/artifacts/image/rawtrace retained; admissionmarkers absent. Existing soleimplementer diagnosing processcheck; no8c/realclient/releasegateopened. Local-only testing retained; production Python/identities untouched.

Task8b2 attempt8 samecandidate05 fixed-file-onlytrace FAIL3.556s confinement_policy,42files exactwhitelist independentlyverified, inventory8+source/hash retained and markersremoved. Correctionattempt7: leaderGo35765eventloopdoesnotprovehealth; Gokernelthread35770 SHAc5ed9b1e executes exit_group1 afterdiagnosticwrite. Rootnotifiedimplementer; setupLSM/current andlaterGofatalrequireexactdiagnosis. Addedrootmetadataonlypathcollector (not runtime), actualcollectionPASS, no decodedIO/random/env. Complete8b2/client/releasegatesclosed.

Ruling: root may capture bounded FD2-only diagnostics for exact fixed fresh unenrolled identity-free fixture in root0700 localVM trace; no reads/random/env/config/LocalAPI/approved-identity payload decoding. Public/controller outputs only predefined error tokens+hashes, never raw logs/IDs. Costifwrong: additional private synthetic log exposure; no production input is present.

Task8b2 attempt9 same05 FAIL4.005s mount_isolation, FD2only42tracefiles verifiedwrite/writevfd2grammar, rawlogs stayguestprivate. TUNengine EPERM tokens36536 SHA487556df plus raw7thread35771 successTUNioctls→pipe2O_CLOEXEC EPERMx3 establish narrow missingdaemonpipe2flag need. Sharedproc-remount versus supervisorLSM race independentlyidentifiedinsource; implementeraddsprivatechildmountns beforeprocRO and daemon-only exactpipeflags, no genericpermissiveexec/cap change. Newstderrclassifier+runnerfixedmode syntax+actualcollectionPASS, inventory9retained, markersabsent, health/client/releasegatesclosed.

Controllercheckcorrection: initial recursiveASTchecker included runtime guest variable assignment and failed literal_eval after evidencewrite; shell stillcontinuedto53550f2commit. Immediately reran top-level-onlyASTchecker: bothcontrollers+embeddedguests+publicJSONPASS. Actualrunner/classifierhadalreadyexecutedPASSsyntax/collection; no runtimecodechange. Correctedattempt9tracefilecount42 from recordedsummary.

Task8b2 candidate06 sourceae1983e/archived2eace2f root101inputsaggregate435c4ddb/all13frozenfiles/botharchstatic/context8d81b3efwhitelistPASS. Attempt10 FAIL6.937s with43rawtracefilesnoquotes; newstages proveactualdaemonsetupACK+liveprogram/socketidentityreached (Go37015 SHA632a3800), thenharnessdescriptor_policybeforeprocessproof. Narrowprivateproc+exactdaemonCLOEXECpipefixpassespriorstartupfailures; runtimepipeinspectgrammarhypothesisforwardedtoimplementerwithoutlooseningauthority. Readonlyinventory10+raw/source/artifacts/imagesretained, markersabsent. Actualmetadata/observer/captures/complete8b2stillNOT_RUN.

Rootcontrollercontextvalidator now independently handles exactpinnedamd64+ARM64 sourceplatform/daemon/ELFmachine withsame6publicfiletarwhitelist andnoadditionalexecutionauthority. Fresh05+06 botharchitecturecontextsPASS (4contexts); bothcross-architecture substitutionnegativesrefused. Defaultguestexecutionstillamd64only, ARM64runtimeNOT_RUN. No productioninputused.

Task8b2 diagnostic07 sourced4725b1/archive997215c7 root101inputsaggregate6e9e72ee/all13files/botharchstatic+contextsPASS. Attempt11 FAIL5.049s descriptor_policy aftersetup/liveidentity; diagnosticFDsnapshot b0f373f2 firstrejectstdio0-2 target/null (samecharidentity), plusonepairreadCLOEXEC/writeNONBLOCKCLOEXEC sameFIFOinode. Actualkernelsnapshot6fb58a2c recordsfixedTUNifindex2/MTU1280/noaddrs, exact4IPv4rule shapes5210/5230/5250/5270 andnonewIPv6routes/nfttables. SequentialCLI snapshotsincludeTUNdown→uptransition, not atomicstateproof. Evidence-only, no learnedbaseline accepted. RootmetadatawhitelistextendedonlytwoexplicitdescriptorJSONnames; readonlyinventory11/rawtrace/source/artifacts retained, markersabsent. Implementerpreparesstrictlive-token-bound exactshape validation; no8c/releaseauthority.

Task8b2 candidate08 source7bac46d/archive0cd0854a root101inputsaggregate509f9c2f/all13files/botharchstatic+contextsPASS. Attempt12 FAIL5.193s AFTERactualGoUID65534/NET_ADMINonly/LSM/seccomp/private-root/state/FDcasePASS; actualobserverlaunchMountIsolation. All52rawtracefilesnoquotesverified; ALLdescendantmountscan identifies helper37614 open_tree(hostplacementfd5)=EINVAL aftercontainer-mount-entry, CA/nullclonesPASS. Parentonlysuccesses didnotexcludechildfailure; rootcorrecteddiagnosis andsentnamespaceprovenance/orderfixsuggestion. Exactdaemonproof4fa88693/metadata/inventory12/source/artifactsretained, markersabsent. Observer/LocalAPI/tokenstablemetadata/lifecycle/captures8b2notcomplete; no8c/client/releaseclaim.

Task8b2 candidate09 source56f462d/archivefa3c4565 root102inputsaggregatec818a1f5/all13frozenfiles/botharchstatic+contexts verified in prior context. Attempt13 rawFAIL6.924s descriptor_inventory after actualGo confinementPASS and identity pinned; observer38142exec/connect/SO_PEERCREDsuccess thenclose/noRequest (SHA8418db3a), parentinspectionracesexit. Attempt14 peer-onlyFAIL4.919s same3casesPASS;53getsockopt/signalgrammarfiles containZERO SO_PEERCREDcalls, inconclusivekernelcredentialvalues. Pinnedrustix1.1.4 UCred NonZeroI32 cannotrepresentlegitimatePID0acrossprivatePIDnamespace; implementerswitchesreviewedrawintegernixAPI preservingrootUID/GIDauthentication and inspectsafterauthenticatedRequestbeforepermission. Rootcollector emitsonlypeerintegers+hashes, actualread-onlycollection+controller/guestsyntaxPASS. Inventories13/14retained, alladmissionmarkersabsent, failedresourcesnotguessedcleanup. No8c/client/releasegateopened. Alltestinglocalperuser; approvedproduction/testidentitiespreserved.

Task8b2candidate10 source2396bda/archivedf330887 root102inputsaggregatebdac5d51/all13frozenfiles/botharchstaticandstrict6publiccontextsPASS. Attempt15peerFAIL7.042s/16rawFAIL5.238s child_failed AFTERactualGo+observerconfinementandoneuseauthenticatedrequestinspection.15actualSO_PEERCREDwitnessobserver39000 pid0/uid0/gid0 andhost38835 seesobserver39000 uid/gid65534; pinnednixrepresentation/rootauthenticationruntimePASS.16observer39244SHA65c56f28/681lines makes2LocalAPIHTTPexchangesaftermetadata, norelevantnewsyscalldeny; rejects beforeobservationrecord.55rawfilesnoquotedstringsverified; bounded180linetailcollectorvariationremainsrawonly, noLocalAPIpayloaddecoding. Allsource/artifacts/images/inventories13-16retained, admissionmarkersabsent. Typedparser/unenrolledpredicate and strictstabletokenboundkernelshape/lifecycle/captures stillpending; no8c/client/releasegateopened. Rootreadonlyguestresourcecheck1341676KiBavailable/8732123136bytesfree.

Task8b2diagnostic11 sourceed22053/archive32a7401f rootall13frozenfiles/102sourceinputsaggregatebef6b9fa/botharchstaticandstrictcontextsPASS. Attempt17FAIL6.697s same3casesPASS;54FD2tracefilesgrammarverified, observer39758SHA565e88bd emitsclosedcodebook statusTypes[4,4,6,1]/SelfTypes[4,2,2,1]/prefsTypes[2,2,2,2,5,3,4,4,2,2,2], status_parse_refused. PinnedfreshdisabledGoSelfobjectandnulltop+SelfIPscontradictexistingVecparser. NoLocalAPIvalues/IDs/body/errorsdecoded/emitted. Rootclassifiernowonlyknownlength/typeboundedvectors+fixedrefusals; syntheticpositivesandforeignkey/value/length/type/suffixnegativesPASS, actualcollectionPASS. Strictzero/unenrolledSelfsemanticsandunchangedreadyidentitychecksrequirednext; noarbitrarySelfadmission. Inventory17/hash/resourcefailuresretained, markersabsent; no8c/client/releasegateopened.

Task8b2candidate12 source263e8a7/archive1d3a74dc rootall13frozenfiles/102inputsaggregate5c05d851/botharchstaticandstrictcontextsPASS. Attempt18FAIL7.529s network_operation AFTER5casesPASS inclactualRustreadonlyconfig/authoneuse/kernelmetadata/unenrolledLocalAPI + GoTERMforward/boundedreap/emptyproducer/parentcontrolsunchanged.54FD2filesverified; observer40217SHA3faaa931 node4/status4/prefs10 predicatesALLTRUE; separateobservationonlyparser acceptsnullableIPs+zeroSelf, Readyparserunchanged. PostdaemonrootboundliveDockerdataNSdev4ino4026537088 independentlyshowslo+WG/noTUN/noresidualGo4rules/noIPv6routes; sequentialobservationsnotatomicadmission. OriginalIPv6baselinecaptureprecededactualchildsuppression; nextfixmovesunderOfflinebeforebaseline+addsstrictlive-tokenboundexactdaemonshapes. No learnedkernelbaselineadoption. Inventory18/livefdmetadata/rawsource/artifactsretained, markersabsent. Rootclosedcollectoradds4boolnodecodebook;positive/wrongtype/countnegative+syntaxPASS. Captures/stablemetadata/revocation/containerdeath/independentreview/8c/clientreleasegatespending.

2026-10-26 continuation: preserved all preexisting dirty source and production Python runtime. Fresh full workspace185passed/0failed/2ignored plus7ordinary guest harness skips; fmt/diffcheck/strictworkspace-alltargetclippyPASS. Exact final102buildinputs match immutable local snapshot1b0d7e723f51c54e0c2d624f2fb15a8d32b6fdaa (refs/vprouter-test-candidates; branch/index unchanged). Static x86+ARM observer/init/payload/context buildPASS; ARM runtimeNOT_RUN. Actual19FAILmissingIPv6multicastexpectation after correct early suppression; failing unit added then exactIPv4bootstrap fixed, allIPv6metadata rejected. Actual20PASS10cases; independentreview found generic hostTUN overly constrained to pinnedGo. Fixed by retaining canonical boundedTUNmetadata forhostbaseline and requiring strictprofile onlyowneddata tailscale0; regressionred/greenPASS and reviewresolved. Actual21/22PASS10cases each, final22sixindependentcaptures0forbidden/0drops,16unauthorizedkerneldenials/0peerreceives/16authorizedroundtrips. ActualGo/Rustconfinement, authenticatedreadonlyLocalAPI, liveboundmetadata, TERM/reap, naturalcontainerdeath/revocation/fullOfflinequarantinePASS. Fresh transport22 reversibleFAILatfault7injection becauseIPv6nowdisabled; ignoredfixture nowprovesrefusal then explicitlyenablesonlyownedWGIPv6, injectsrealroutefault, demandsquarantine, restoresdisabledstate. Transport23..29PASSall7scenarios,42independentcaptures0forbidden/0drops; exactWAN-onlyprovenancecleanupPASS, otherfixturestatepreserved. Auditorderedfastpath128entries32768->128comparisons; exhaustive14641pairmultisettestPASS. u64microbenchmark isnotfullrouterCPUacceptance. Report docs/rust-v2/testing-2026-10-26.md/json, benchmarkJSON and historicalevidenceappendedsafely. Productionread-onlyserviceactive/routerhealthy. StillNOT_RUN: livepost-pinTUN/rulefaultinjection, autonomousguard/provider/readiness, realclient/no-fallback/DNS/IPv6/fullfaultmatrix, migration/reboot/platform/fullperformance/24hsoak. release_readyfalse; nopush/noproductionactivation.


2026-10-29 task8b2 recovery milestone: old actual_daemon_execution agent unavailable; no duplicate implementer launched. Recovered final1b0d7e (102 input/archive proof) and latest90a7dcc (195 inputs; both static payload/context hashes verified). Root fresh owned local Debian attempt396 PASS17 actual-program cases incl four post-pin faults/revocation; independent6captures112records0forbidden/0drops, admissionmarkersabsent, allfixturesretained. Current workspace393passed0failed2ignored/fmt/diffcheck/strictworkspaceclippyPASS;33inputs differ90, so new source remains WIP without exact runtime promotion. Independent review_task8b2 against836210a pending;8c remains gated. User explicitly requests all progress pushed after milestones: publish only source/tests/public docs/tools and audited Markdown reports to fork/rust/v2; private target artifacts/credentials excluded. HEAD/index preservation requirement is superseded only for these authorized checkpoint commits; production/identities/retryrepair remain protected. See docs/rust-v2/testing-2026-10-29.md/json.

Task8b2: complete bounded actual-program component (base836210a..reviewed90a7dcc, independent review_task8b2 specPASS/qualityPASS/0Critical0Important). Original1b0d postpin proof gap remains historical; exact90 source actual396 supplies17cases/4livefaults and6independentcaptures0forbidden0drops. MinorM1 stale task report resolved by dated report/evidence reconciliation, no historical failure/gate rewritten. Current post90 Bootstrap/exact20 work outside approval. Task8c implementation may proceed only within existing local-only/no-production/identity-preserving constraints; autonomousready/enrolled/client/multi/migration/platform/performance/release gates remainOPEN. Initial source checkpoint990526a remote-confirmed fork/rust/v2; subsequent milestones must also be pushed per user instruction.

2026-10-29 current-source milestone: after remote-confirmed review checkpoint21955a3, first coherent buildFAILARM64E0425 SYS_fstatat (original log retained). Focused fix_arm64_filter changed only nonexistent ARM constant to pinned SYS_newfstatat (ARM79/x86262), preserved exact FD/name/flags restrictions;12native tests+ARMtestscheck+fmtPASS, Root independently confirmed constants/source and strictclippy. Coherent fix1freeze b51b5d7 (target/continuation-20261029T122356Z)202current/archive/commit inputs equal, bothstaticELF/payloads/strictcontextsPASS. Actual397 ownedlocalDebPASS17, independent6captures112records0forbidden0drops/markersabsent/allresourcesretained.84performance-tool unittestsPASS; benchmarksNOT_RUN. Current regression review separate from task8b2 original90approval. NewBootstrap native/runtime/client/platform/migration/performance/24h release gatesOPEN. Publish exact testsource tag plus source/manifests/reports checkpoint after review.

Current b51b5d7 scoped regression independently PASS/0open findings; task-8b2-current-regression-review-2026-10-29.md verifies33inputdelta/ARMABI fix and exact397 capture evidence. Final current workspace393/0/2ignored and strictalltargetworkspaceclippyPASS after regenerated manifests. Task8b2 source/runtime checkpoint verified; newBootstrap native/ARMcurrentruntime remainNOT_RUN, all broader task8c/client/migration/performance/release gates unchanged. Source/test tag rust-v2-test-20261029T122356Z and final milestone commit are to be remote-confirmed on fork/rust/v2.


Task8c ACTIVE 2026-10-29, baseb678e7bf98e0c311109ce82a3893b40127ef0825,
implementer /root/autonomous_guard. Existing task8a/task8b2 independent approvals
and exactb51 actual397 proof remain bounded prerequisites; production unavailable.
Ruling: implement8c in coherent slices:8c.1 private authenticated policy receipts
and quarantine-first failure semantics;8c.2 consuming native Bootstrap custody,
independently scheduled guard/runtime/recovery and integrated fault/client gates.
A received HealthState is not proof of actual policy. Prepare must read back
Offline before worker withdrawal; failure Blocked(reason/noevidence),Stopping,
Failed commits stay Offline. Worker returns original sample error after bounded
failure publication rather than continuing provider queries behind full quarantine.
Healthy verification recovery may use producer-only Bootstrap; failure recovery
must have a separate independent withdrawal/rebootstrap observation. Costifwrong:
additional explicit recovery transition/restart work, never premature forwarding.
No component slice can complete full8c or authorize task9/multi/direct/migration.
Root alone handles all privileged localVM/profile/identity work; no remote tests,
production mutation/enrollment/state clones or boundedretry weakening. User's
milestone checkpoint/push instruction persists for all safe source/docs/tools.

Task8c.1 stable six-file source independently hash-matched to slice report; Root
local offline worker+launch library tests209/0, fmt/diffcheck and focused strict
ClippyPASS. Fresh review_task8c_slice1 independently checks spec+quality against
b678e7b. No runtime promotion; old manifests not regenerated for this delta yet.
Root archived exact two independently audited Bootstrap controllers, preserving
all285 originals: source-manifest now287 entries, every archived hash verified.

Task8c prerequisite native attempt398 on OLD frozenb51 source FAILexit1/14.175s,
zero completed cases, secret_bootstrap_lab ownership_mismatch stillUNLOCALIZED.
Initial attachment phases and inventory checks succeed; no Bootstrap witness.
Outer controller verified prior foreign host network and original inert gateway
preserved, one exact DOWN endpoint retained; owner unit/cgroup absent afterward.
All six fixed selectors retained; no resource cleanup or identical-payload retry.
Raw target/lab-state/actual-program-run-398.json and candidate-local controller
snapshots preserved; public redacted docs/rust-v2/task8c-bootstrap-attempt398.json.
Original implementer performing read-only localization while slice1 is frozen.
Full8c remainsACTIVE and nativeBootstrap/runtime/client/release gates remainOPEN.

Task8c.1 independent specPASS/qualityPASS/no findings. Root coherent offline
freeze5a224c16 source/archive/current202inputsequal; bothstaticELF/payloads and
seven-file contexts verified, all Rust programmanifest hashes/sizes exact;
AMD64filterpreflightPASS. Both immutable contexts retained candidate-local.
Publication scope reviewPASS; refreshed manifest-only hashes/sizes add no authority.
Task8c.1 complete bounded source/component/static milestone; native receipts and
full8c/runtime/client acceptance remainOPEN. Publicverification hashes recorded
in docs/rust-v2/task8c-slice1-verification.json. Commit/push follows review.

Task8c.1 milestone b318eac remote-confirmed fork/rust/v2; exact source5a224c16
remote-confirmed tag rust-v2-test-20261029T124811Z. Production read-only active.
Task8c prerequisite398 read-only diagnosis narrowed to post-host assertions,
exact20 handoff or Bootstrap constructor; all4canonical host results acknowledged.
No exact failing predicate/semanticfix established. Diagnostic-only3file increment
authorized to existing sole implementer, fixed cfg(test) stages/error classes only.
Root new metadata inspector/source-family adaptation audited independently; exact
6selectors archived by hardlink/unlink into original root0700 input directory after
fresh unitabsence+gatewaypidfd/start/netns+selectorinode/hash/mode checks. All profile,
canonical,mount,network and inertgateway resources retained; no signals/unmounts.
Reference target/lab-state/secret-bootstrap-selector-archive-run-398.json. Original
raw398 unchanged. Two controller sources added safe archive, now289hash entries.

Task8c diagnostic-only3file increment independently specPASS/qualityPASS/no findings;
fixed cfg(test) stage markers preserve predicates/errors/clocks/custody. Root coherent
offline botharchbuilds and AMD64filterpreflightPASS; source73a35260 archive/current/
Git202inputsequal, bothstaticELF/payloads+strict7filecontexts verified/copied immutable.
Fmt/diff/focusedstrictClippyPASS. Initial inline Root proof had Python whitespace
SyntaxError; shell continued to existing self-verifying read-only projector+baseline
authoring, bothPASS. Corrected full Root proof thenPASS; no mutating native test ran.
Baseline helper review found .py references incompatible with JSON-only template
contract and missing reconciliation fields; fixed, independently narrowed re-review
PASS plus6pure multiset/duplicate/namespace checks. Authored51link expected foreign
baseline from old50+exact398canonicalDOWN endpoint; current frozen projection equality
PASS. Final candidate/template provenance review pending before diagnostic invocation.
No baseline ownership/removal/activation authority granted. New helper safely archived,
source manifest290entries. Original398FAIL remains unchanged; full8cACTIVE.

Diagnostic399 finalsource/baseline independentlyPASS; ownedDebiannative399FAILexit1,
zero cases,88journalinventorypairs. All instrumented hostpostchecks, exact20handoff,
fiveretirements/preparationequal and initialBootstrapconstructor/queue/return markers
OK. FirstBootstrapquerywriter starts then fixture reportsInterrupted, masking its
original polling error because failurehandler requires absentpolicyrequest. This
is a differentfailure, NOT a proven398fix. Raw399/source/artifacts/outerpreservation
and6selectors retained; public docs/rust-v2/task8c-bootstrap-attempt399.json. Root
readonlyinspector399PASS; no nextnativecase/cleanup/identicalretry. Original sole
implementer examining diagnosticerror-preservation fix; full8c remainsACTIVE.

Diagnostic399 content and exact6selectorpreservation independentlyPASS. Unchanged
archiver then freshchecksPASS+6selectorsarchived into originalprotectedinputdir;
allother resources retained/no signals/unmounts. Native399remainsFAIL; no retry.
Provenlabmaskingbug planned next: preserve originalpre-policyquery error instead
of replacing it withInterrupted; no guessed enforcementfix.

Diagnostic milestone ce41a0a remote-confirmed fork/rust/v2 plus exactsource73a35260
remote tag rust-v2-test-20261029T125748Z. Late independent canonical/preservation
report addendum retained for nextcheckpoint. Production read-only active.
Original sole implementer authorized ONEFILE operational/bootstrap.rs laberror
preservation and fixed QueryIntent/spawn/birthqueue phases, no enforcementfix.
Root generic baseline successor preserves original398helper bytes/provenance and
adds nextfailed-run directorybinding/outerexactendpoint checks; narrowreviewpending.

Evidence correction400diagnosis: on-disk bootstrap_queries[0] proves durable
proposal/write, NOT parent process-local ACK. Earlier Root399 wording saying
Intentacknowledged is overstrong; the present/absent field observations stand.
Samequalification applies to398disk-only result/verified fields; foreign endpoint
preservation remains bound to originalcanonicalproposal+exactouter observation,
with no membership/removal authority. Native399marked host/handoffgroups provide
separate source-level completion evidence, never rawdiskalone. Original rawdata
unchanged. Readonlysource trace finds pending-state conflict in bootstrap progress:
input.context historicalSource receipt rejects shared.pending before original
Server can advance that same querywriter. Narrowtypedprogress fix under design;
globalpending rejection mustremain, no enforcementrelaxation authorized.

Onefile querydiagnostics independently spec/qualityPASS; Root sourcefbfa3bbc
coherent202inputs/bothstaticELF+contexts/fmt/diff/focusedstrictClippyPASS. Native400
FAILzero cases exposes OwnershipMismatch/query_intent/no policyrequest/querychild,
no IntentOK/spawnmarkers,88writerinventorypairs. Public/rawfailure retained.
Content/exact6selectorpreservation independentPASS; unchangedarchiver freshgates
PASS and6selectorsarchived, allotherfixture resources retained/no signals/unmounts.
No identicalretry. Full8cACTIVE; next narrowtypedpendingprogressfix underdesign.

Error-preservation milestone ae8450c and exactfbfa3bbc source tag remote-confirmed
fork/rust/v2. Source-established pending-state conflict documented independently
from the runtime-fit inference; no captured localflag/exactreturn proof overstated.
Ruling: nextfix must coherently cover exact original query AND policy writers,
not just bypass first eagercontext call; globalhistory pendingrejection retained,
progress-specific access only with closed originalServer/typedexpectedwriter proof.
Costifwrong: broader internalcustody proof/review work, never arbitrarypending
acceptance or newpolicy/UP/Ready authority. Original sole implementer authorized
bounded pendingprogress increment; full8c/client/release remainACTIVE/OPEN.

2026-10-29 continuation at ad95951: user directs continue8c and milestone pushes.
Reconciled live sole implementer /root/autonomous_guard; original3dirty Rust paths
are owned pending-progress WIP, not a frozen candidate. Sole implementer resumed
existing coherent query+policy brief; no duplicate implementer/source editor.
Root fresh read-only ownedDebian-clean preflightPASS: markerroot0600, selectors
absent,1076672KiB available/16146022400bytes free; productionserviceactive.
Remote fork/rust/v2 independently confirmed ad95951. Auditor observed292 archived
controller sources with exact target equality (earlier290 count superseded by
already committed generic+v2helpers). New Root offline candidate verifier pending
review; it grants no runtime authority. Run398/399/400 remain retainedFAIL; no
unchanged native retry and no task8c/client/migration/release acceptance inferred.

Tooling/recovery checkpoint: independent controller preflight spec/scopePASS;
exact expected53-link baseline and unchanged Root runner/preservation chain
verified. New offline verifier303b231a static/ASTPASS, archived as293rd exact
original; all293source/archive/hash/syntaxchecksPASS. No verifier main or native
execution yet. Public-sensitivity/scopePASS for explicit tooling/report/ledger
paths; active semantic RustWIP deliberately excluded until frozen/reviewed.

Pending-progress source frozen13paths/report07707dec; Root independently matched
all13hashes. Freshfullworkspace396passed0failed2ignored/fmt/strictalltargetClippy
PASS. Fresh independent reviewer review_pending_bootstrap assigned exactae8450c
delta; native gate pending. Root coherent botharchfreezecc0081ba (202inputs,
archive1c2ece5f/aggregateac3db8ba) source/current/Git equalityPASS; bothstaticELF/
payload/strict7filecontextsPASS, AMD64exactmuslfilter+realpendingcorepreflightPASS.
Bothimmutablecontexts/proof retained candidate-local. Source review and separate
artifact provenance review pending; no nativeBootstrap or full8c acceptance yet.

Pending-progress increment independent source SPEC+QUALITYPASS/no blockers,
review2687169c (exact13hashes unchanged). Fullnative wrongRc remainsNOT_RUN.
Separate candidate provenancePASS/all202+bothstaticpayloads/strictcontexts and
retention/preflight checks. Root fixed read-only ownedDebianprojectionPASS, then
reviewedv2helper reconstructs exact53/51/154/5 preservedforeign baseline from400;
exactfullmultisets equal, order-only alignment. Finalbaseline/template references
and protectedmodes independentlyPASS; no baseline membership/removal/activation
or nativeBootstrap acceptance inferred. Source/component/static milestone ready
for explicit checkpoint before frozen nativeBootstrap execution; full8cACTIVE.

Pending-progress source milestone ca061fc remote-confirmed fork/rust/v2; exact
cc0081ba source tag rust-v2-test-20261029T134857Z remote-confirmed. Exact review
.diff retained ignored with its original reviewedhash (diffcontext spaces trigger
Git whitespace checks); source and allsafe Markdown/publicevidence committed.
Native ownedDebian401FAILexit1/12.485s zero cases, query_result CgroupMismatch.
Queryintent/spawn/birthqueue markers reached; no successfulBootstrap witness.
Root exactreadonlyinspectionPASS; sixselectors/allfixtures retained, original
inertgateway and priorforeignnetwork preserved plusexactoneDOWN endpoint. First
querydiskrecord birth/facts/verified_at aredurablefields, notparentACK proof.
No identicalretry/cleanup. Soleimplementer readonlydiagnosis; independent401
preservationreview pending beforeauditedselectorarchive. Full8cACTIVE, broader
gatesOPEN and release_readyfalse. Original398/399/400 remainretainedFAIL.

Native401 independent preservationreviewPASS; unchanged exactarchiver freshgates
PASS and sixselectors archived intooriginalprotectedinputs. Allotherfixture/
canonical/profile/mount/gateway resources retained; no signals/unmounts.
Root boundreadonlycurrentVM mountroot oracle: /sys/fs/cgroup dev27/ino1/040555
versus '..' dev22/ino2/040755, cgroup2 mountroot'/' confirms false selfparent
predicate under currenthostmount view. No originalowner executed-return trace
claimed. Soleimplementer completing readonlypredicate inventory/nextfixproposal;
no newsourcechange or identicalnative retry authorized. Full8c remainsACTIVE.

401failure milestone e986cfd remote-confirmed. Readonlydiagnosis a5d3b382 identifies
invalid root-self-parent edge in both process/native-role ancestry; root current
VM reverse-edge oracle confirms system.slice/'..'==originalroot and exactgateway
PID/start/membership/Dockerscope preserved, notoriginalexecutedreturnproof.
Authorized soleimplementer narrow3file ancestry brief at e986cfd: replace false
edge with actualinternalreverseedge and changeonly firstexactstatFD; preserveall
originalroot/forwardedge/cgroup2/identity/confinementchecks. RealFD sharedcore and
actualAncestry-generated filter regressions required; old13+approved6 untouched.
No newnative action untilreview/coherentbinding; full8cACTIVE.

Ancestry correction frozen3sources/reporta17c212f; fresh independent reviewer
review_ancestry_fix SPEC+QUALITYPASS/no findings reviewddb932e7. Both verifiers
now prove actualsystem.slice/'..' originalroot and onlyfirstexactstatFD changes;
prior13pendingrepair+sixreceipt hashes unchanged. RealFD and actualgeneratedrule
regressions RED3->GREEN3; Root freshworkspace399/0/2ignored/fmt/strictalltargetClippy
PASS. Root botharchcoherentfreezeab20f1d7/202inputs/archive7e284b0d/aggregatee7bf990e
current/archive/Git equalityPASS, bothstaticpayload/strict7filecontextsPASS,
exactAMD64muslfilter+pendingcorepreflightPASS. ReadonlyownedDebianprojectionPASS;
unchangedv2helper reconstructs preserved54/51/154/5 baselinefrom401, exactmultisets
and order-onlyalignmentPASS. Separate finalartifact/template/publicscope audit
pending; no nativeBootstrap run yet forab20; full8cACTIVE/release_readyfalse.

Ancestry finalcandidate202input/artifact/strictcontexts/rootproof/preflight and
protected54linkbaseline/projection/JSONrefs independentlyPASS/no findings. Source
review remainsPASS/all19protectedfilesunchanged; publicchecks399/0/2+fmt/clippy,
source/staticcomponentmilestone only. Nativeforab20 remainsNOT_RUN, ARM runtime
NOT_RUN/full8cACTIVE. Finalpublicscope audit/explicitcheckpoint follows before
newnativeBootstrap invocation; no original401failure rewritten.

Ancestry source milestone fdf1d89 and exactab20 tag rust-v2-test-20261029T141400Z
remote-confirmed fork/rust/v2. NativeownedDebian402FAILexit1/17.65s zero cases,
finalDeadline/noPOLL_FAILURE,73phaselines/91journalinventorypairs. Root readonly
inspectionPASS; firstquerydurablebirth/facts/verifiedfields, observation1.294765s
inside original2swindow; notparentACK or failedclocktrace. Soleimplementerreadonly
localizes production versus lab-control boundary; no deadlineweakening/retry.
Independent402preservationgatePASS; unchangedarchiverfreshgatesPASS andexact6
selectorsarchived/allotherfixturesretained/no signals/unmounts. Root finalpost-
manifest workspace399/0/2ignored+strictalltargetClippyPASS. Full8cACTIVE,402andall
priorfailuresretained; noBootstrap/native/releaseacceptance promotion.

402failure milestone50cf9c4 remote-confirmed. Readonlydiagnosis3e96878e distinguishes
outerlabhelper reporting from underlying originalproductiondeadline;91stwriter
source/counter inference points firstpolicyIntent, no exacthelper/cost/failedclock
captured. Authorized soleimplementer ONEFILE cfg(test) fixedhelper/error/Step/
originalclock/counter diagnostic plus bounded measuredwrappercosts, no fallible
logverification/error masking/perpolloutput or semantic/deadline/testweakening.
Brief task-8c-bootstrap-helper-diagnostic-brief.md at50cf9c4; allother21protected
sourcepaths stayunchanged. Full8cACTIVE; nextnativeonlyafterreview/artifactgate.

Helperdiagnostic ONEFILEcfg(test) source88320812/reportfe3b6223 frozen. Independent
freshreview_helper_diagnostic SPEC+QUALITYPASS/no findings review158fdd1e; exact
productionprefix/errorhandlertail unchanged and other177Rustfiles unchanged.
Root freshlaunch148/0/fmt/strictlaunchlibtestsClippyPASS. Coherent botharchfreeze
c6f3c5e8/202inputs current/archive/Git equalityPASS, bothstaticpayload/strict7file
contextsPASS, exactAMD64muslfilter/pendingcorepreflightPASS. ReadonlyownedDebian
projection and unchangedv2helper expected55/51/154/5 fullmultiset/order-only
alignmentPASS; finalartifact/template/publicscope review pending. Metrics only
measurewrapperelapsed inclnestedwork; no failedclock/predicatecost/native403
witness yet. Full8cACTIVE, no semantic/deadline/enforcement/testweakening.

Helperdiagnostic final202input/artifact/staticELF/strictcontext/preflight/rootproof
and protected55link projection/fullmultiset/order-onlybaseline/refs/modes
independentlyPASS/no findings. Root148/0/fmt/clippy evidence corroborated. Public
provenance/baselineflags finalizedPASS; cfgtest-onlydiagnostic/nativeNOT_RUN,
ARMNOT_RUN/releasefalse retained. Source/runtimeauthority unchanged. Explicit
milestonecheckpoint and newdiagnostic nativeinvocation followfinalpublicaudit;
full8cACTIVE, original402andearlierfailurespreserved.

Diagnostic milestoneb459edf and exactc6f3tag rust-v2-test-20261029T153856Z remote-
confirmed fork/rust/v2. OwnedDebian403FAILexit1/13.92s zero cases/91journalpairs.
Newprocess-local boundary=native_poll/intent/Deadline: firstqueryaccepted/policy
present, queryheld2/negative6/released, policyheld2/negative12/notreleased.
13closedwrapperelapsed rows total1959655450ns, nativepoll13calls923556681ns;
querywrappers722550398ns/policy313548371ns inclnestedwork/IO/scheduling, notCPU.
Postfailedcallclock7.374366ms beyondoriginal2send, notexactinnerpredicateclock
or retrospective402helperproof. Root exactreadonlyinspection+closedmetadata
parserPASS; sixselectors/allresourcesretained pendingindependentpreservation
review. Soleimplementer readonlycost/optimizationproposal; no source/deadline/
enforcement/testweakening or identicalretry. Full8cACTIVE/release_readyfalse.

403 independent failure/provenance/preservation/exactsix prerequisite review PASS;
Root unchanged archiver e36a8e8c fresh originalowner/gateway/selector gates PASS,
exclusive receipt retained, exact6 selectors archived/all other resources retained,
no signals/unmounts or profile reads. Public originalFAIL and bounded diagnostic
limits retained; completion/publicscope audit pending before milestone push.

403failure milestone46239ec remote-confirmed fork/rust/v2; production read-only
active. Ruling: measure nested allocation/custody/encoding/proof/journal cost
before optimizing immutable expected-record encoding—wrapper totals establish
no dominant mechanism; cost if wrong is one diagnostic build/experiment, with
no ownership or deadline relaxation. Sole implementer authorized cfg(test)-only
six-path task-8c-bootstrap-nested-cost-brief.md; original2s/all calls/negatives/
held-polls/errors remain exact. Full8c ACTIVE; all acceptance gates unchanged.

Nestedcost diagnostic ruling: allow COW-private child counter accumulation, never
exported/merged as parent metrics. Journal child record_digest executes under a
filter allowing clock_gettime but denying getpid; per-entry creator syscalls or
new fork/filter hooks would exceed diagnostic scope. Creator checks remain only
at unrestricted lab arm/stop/snapshot; fixed timer entry/drop uses no getpid.
Cost if wrong: child diagnostic overhead can perturb scheduling/parent elapsed,
so report it explicitly and do not infer isolated CPU or exact predicate costs.
Original child kernel::die/no-unwind and no child emission must be reviewed.

Nestedcost brief interpretation: one cfg(test) infallible cached-Step family hook
at existing lab-loop entry is allowed within operational/bootstrap.rs, to split
fixed3x10 rows into query/policy/other. Timer captures entry family; a poll may
transition, so grouping is lab-loop-entry Step family, not inner phase/CPU.
Initial family explicit before PendingBootstrap construction; no new fallible
getter, clock check, authority or original call/order change. Cost if wrong is
misattributed diagnostic grouping, bounded by labels and independent review.

Nestedcost sixpath source/report bcd7e6f0 frozen, independent fresh review pending.
Root fresh152launch/0failed/fmt/strictlaunchClippy+179sourcehash/exclusion PASS.
Botharch coherent freeze4451c8a/203inputs/archive4fc3b75e/aggregate4e28ac65,
Root current/archive/Git equality+staticELF+strict7filecontexts PASS; exactAMD64
filter/pendingcorepreflight PASS. Normal program manifests/contexts unchanged.
OwnedDebian readonly marker/selectors/capacitypreflight PASS; no newBootstrap
fixture run yet. Nativecost witnessNOT_RUN/ARMNOT_RUN/full8cACTIVE/releasefalse.

Fresh review_nested_cost SPEC+QUALITYPASS/no findings reviewfa70e3e5; sixpath
cfgtest/normalbytes/173unowned Rust preservation independently verified. Root
ownedDebian readonly projection PASS; unchangedv2helper reconstructs expected
56/51/154/5 from403 exactcanonicalDOWNendpoint+prior55 authoredbaseline and
requires fullmultiset equality/order-onlyalignment PASS, no livefieldadoption.
Final candidate/provenance/baseline/publicscope audit pending; nativecostNOT_RUN.

Nestedcost final203input/artifact/staticELF/strictcontext/preflight/rootproof and
protected56link projection/fullmultiset/orderonlybaseline/refs/modes independent
PASS/no findings. Root152/0/fmt/clippy corroborated. Final public provenance and
baseline flags PASS; cfgtest-only diagnostic/nativeNOT_RUN/ARMNOT_RUN/releasefalse
retained. No semantic optimization or runtime authority changed. Explicit reviewed
milestone push plus exactsource tag precedes next local nativecost experiment.

Nestedcost milestone0af1b9f and exact4451tag rust-v2-test-20261029T161134Z remote-
confirmed fork/rust/v2. OwnedDebian404FAILexit1/8.69s zero cases; native_poll/result/
Deadline, query+policyheld2/negatives6+12/releasedtrue, original2s unchanged.
Root unchanged exactinspection PASS; sixselectors/allotherresources retained.
Closedpublic-reader parsed13wrapper+30inclusive nestedrows; expectedencoding
query2.747405ms/policy13.715089ms, Bindingretained4292/4396calls with335.094473/
339.254664ms. Categories overlap, not CPU or exactinnerclock; laterphase doesnot
prove performanceimprovement or completeHOSTscope. Independent404preservation
review pending; soleimplementer readonlymechanismproposal, no sourcefix/retry.
Full8cACTIVE/releasefalse; all earlier failures preserved.

404 independent preservation/exact6 archival prerequisite PASS. Root unchanged
archiver freshowner/gateway/selector gates PASS, exclusive receipt retained,
exact6 selectors archived/all other resources retained/no signals or unmounts.
Public closedparser source retained separately from293historicalarchive; actual
404parse+AST and4malformed duplicate/foreign/unknown/nonfinite cases refused
withoutoutput PASS. Final parser/publicscope+completionaudit pending beforepush.

User steering: some Mullvadservers down; may select another supplied labserver.
Root boundedcertificateverified readonly publiccatalog16:32:41UTC: supplied
 de-fra-wg-402 catalogactivefalse; de-dus-wg-102/de-fra-wg-003/de-ber-wg-102/
 de-ber-wg-002 activeflags true. Catalogonly, actualtunnel/handshake/provider
reachabilityNOT_RUN. Prefer active supplied profile for futurelive qualification,
preserveexistingapproved Tailscaleidentity/state and credentials; no profile,
identity or production mutation. Current404syntheticprovider_profiles_usedfalse;
no evidence that a remote relay caused its original Bootstrap deadline.

404diagnosis72744381 and allocationcomparisonbrief independent SPEC/QUALITY/
EVIDENCE/requirementsPASS review30279b0d; two minor report wording/version fixes
resolved. Offline publicshape purecomparison experiment PASS45oraclecases,
7alternating batchesx20000; hostglibcopt3 medians primary592.396->19.568ns,
twoexit963.732->37.422ns, mismatch567.924->18.085ns. Not nativeallocationcostshare,
no2sfit/runtime/releaseperformanceclaim. Ruling: authorize exactonefile
same_allocation representation-work removal under reviewed brief, preserving
allcall sites/livechecks and originalResult/UTF8/rawpath/errorsemantics.
Costifwrong: additional equivalence/native experiment, with no deadline or
ownership relaxation; do not claim saved native budget from timerentrycounts.
Soleimplementer must freezebenchmarkreport beforeappsourceedit and obtain fresh
source review +coherentbinding/checkpoint before next ownedlocalVMtest.

Mechanism/catalog/docs milestone446845b remote-confirmed fork/rust/v2. Onefile
allocationcomparison frozen owned b1490090/report940b40b6/diff87b0f288: 80actual
Result oraclepairs/4tests PASS; two deliberately incorrect path/precheckmutants
failed as intended and restored. Root fresh workspace407/0/2ignored, fmt and
strictworkspacealltargetsClippy PASS; all178unowned Rust inputs unchanged.
Fresh independent source review pending; nativeeffect/2sfit unproved,404FAIL
retained. Botharch coherentbuild next, no new VMfixture before remaining gates.

Fresh review_allocation_comparison SPEC+QUALITYPASS/no findings review7968a825;
onefileResult/equivalence/import+helper+tests reconstruction and178unowned hashes
independently verified. Botharch coherent freeze05238109/203inputs/archivec32d6c1b/
aggregate4386b3a9; Root current/archive/Git +staticELF/strict7filecontexts/exact
AMD64filterpreflight PASS. Normal manifests/contexts unchanged. OwnedDebian
readonly projection and unchangedv2helper expected57/51/154/5 from404canonical
DOWNendpoint+prior56baseline fullmultiset/orderonlyalignment PASS. Independent
finalcandidate/baseline/publicscope audit pending; no nativecosteffect witness.

Allocationcomparison final203input/artifact/staticELF/strictcontext/preflight/
Rootproof and expected57link fullmultiset/orderonlybaseline/ref/helper/404receipt
independentPASS/no findings. Root407/0/2+fmt/strictalltargetsClippy corroborated;
public provenance/baselineflags PASS, nativecost/Bootstrap/ARMNOT_RUN/releasefalse.
Finalimmutablepublicaudit precedes explicit source/checkpoint/tag push and next
ownedlocalVMexperiment. No claimed nativebudget/performance or acceptance fix.

Allocationcomparison milestonebf3247b and exact05238109 tag rust-v2-test-20261029T164255Z
remote-confirmed fork/rust/v2. OwnedDebian405FAILexit1/11.728s zero cases;
HOSTnative_poll/result/Deadline, query+policyheld2/negatives6+12/releasedtrue.
Original2s unchanged; post-error observation6.191181ms past end, not innerclock.
Root unchanged exactreadonlyinspection+closedmetadata parserPASS; exactly6
selectors/allotherresources retained pending independent preservation review.
13wrapperelapsed total1953713909ns; queryretained4292/346400525ns, policy4324/
327523870ns; nestedcategories overlap, notCPU or controllednativeA/B.
Comparison change has not made Bootstrap pass; source remains frozen. Sole
implementer readonly405diagnosis/retained-inner proposal; no unchangedretry,
deadlineextension or removal of livechecks. Full8cACTIVE/release_readyfalse.

405 independent provenance/preservation/exact-six archival prerequisitePASS. Root
unchangedarchiver e36a8e8c freshoriginalowner/gateway/selector gatesPASS; exact6
selectors archived with exclusive receipt, allotherresources retained/no profile
reads/signals/unmounts. OriginalFAIL/zero cases and diagnostic limits retained.
Completion/publicscope immutable audit pending before failuremilestone push.
Production read-only freshlyactive; full8cACTIVE/release_readyfalse.

405failure milestone115e500 remote-confirmed fork/rust/v2. Corrected405diagnosis
2620a12c and retainedcostbrief5624e0e2 independently diagnosis/SPEC/QUALITY/
requirementsPASS review32cf5cff; one conflated query/policy snapshot sentence
resolved before freeze. Ruling: measure retained transport/DATA/owner/history/
digest/native-group work and Sourcefanout before further optimization; existing
inclusive totals establish no dominant purework. Costifwrong: one bounded
diagnostic experiment/observeroverhead, never deadline or livecheck relaxation.
Soleimplementer autonomous_guard authorized exactly5cfg(test)sourcepaths; separate
24fixedrows, selectedrow updates, original13+30rows and all2s/custody/hold/negative/
release/ACK checks exact. Independent source review/coherentartifact/preservation/
push gates required before newnativeVMrun. Parser-only extension separately
assigned bootstrap_fixture_audit; no other source work. Full8cACTIVE/releasefalse.

Retained-reader parser4309e488 report2a912599 independent SPEC/QUALITYPASS/no
findings reviewa06313e9. Root fresh AST/exact405 byteequalityPASS; retained
implementer3valid syntheticcases/23malformedrefusals/exclusiveoutput checksPASS.
Optional exact24rows/countonlyzero/closedlabels validated; prior405bytesf743c668
unchanged, no existing evidence rewritten. Reader arithmetic doesnot sumnew
inclusiverows; syntheticparserchecks are notnativecost evidence. Explicit
parser/docs checkpoint excludes in-progress5Rustpaths and allprivatetargetdata.
Full8cACTIVE/releasefalse; nativeforretaineddiagnosticNOT_RUN.

Retainedcost exactly5cfg(test)source/reportb8064671/diff941a4638 frozen; independent
review_nested_cost SPEC+QUALITYPASS/no findings review95c85554. Root freshworkspace
410/0/2ignored,fmt+strictalltargetsClippyPASS; all179afterhashesmatch/all174unowned
unchanged. Normalreconstruction and oldState/Timer/13+30rows preserved. Coherent
botharch freeze17c914f4/203inputs/archivec022151a/aggregatec2e1052c; Root current/
archive/Git equality/staticELF/strict7filecontexts/exactAMD64preflightPASS. Normal
program manifests/contexts unchanged. OwnedDebian readonlyprojectionPASS; unchanged
v2helper reconstructsexpected58/51/154/5 from405canonicalDOWNendpoint+prior57
authoredbaseline, exactmultiset/orderonlyalignmentPASS/no livefieldsubstitution.
Finalcandidate/preservation/publicscope independent audit pending; nativecost
witnessNOT_RUN/ARMNOT_RUN/full8cACTIVE/release_readyfalse.

Retainedcost final203input/artifact/staticELF/strictcontexts/preflight/Rootproof
and expected58link exactmultiset/orderonlybaseline/refs/405receipt independent
PASS/no findings reviewce41945d. Root410/0/2+fmt/strictalltargetsClippy corroborated.
Public candidate/baselinereviewflags finalizedPASS; cfgtestdiagnostics only,
nativecost/Bootstrap/ARMNOT_RUN/releasefalse remain. Exactsource17c914f4 and
source/checkpoint push follow finalimmutablepublicaudit before newownedVMrun.
No livecheck/deadline/authority changed or nativeoptimization claim established.

Retainedcost source milestone1188b26 and exact17c914f4 tagrust-v2-test-20261029T170915Z
remote-confirmed fork/rust/v2. OwnedDebian406FAILexit1/12.889s/zerocases, HOST
native_poll/reading/Deadline after query+policyheld2/negatives6+12/releasestrue.
Original2s unchanged; post-error observation0.797276ms late, notinnerfailedclock.
Root unchanged exactreadonlyinspectionPASS;13wrapper+30nested+24retained closed
metadataparsePASS. Same-count Binding ownerquery4292/221134431ns, policy4171/
202379170ns; fullhistory4292/35636127ns,4171/33933759ns. Inclusivecategories
overlap; digestcountsdiffer, noCPU/exclusivewall/optimizationeffect/2sfit proof.
Exactly6selectors/allotherresources retained pending independent406preservation
review. Source frozen; soleimplementer readonlymechanism/proposal, no identical
retry/checkremoval/deadlineextension. Full8cACTIVE/release_readyfalse.

406 independent preservation/provenance/exactsix prerequisitePASS. Root unchanged
archiver freshowner/gateway/selector gatesPASS; exact6 archived with exclusive
receipt/allotherresources retained/no signals/unmounts/profile reads. Public
originalFAIL/zerocases and24rowoverlap/observerlimits retained. Completion/public
audit pending before failuremilestone push. Source frozen/full8cACTIVE/releasefalse.

406failure milestoneb58231e remote-confirmed fork/rust/v2. Diagnosis e37a5160,
digestexperiment a4d7f6a9 and conditionalonefilebrief independently diagnosis/
requirements/experimentSPEC+QUALITY+EVIDENCEPASS review120050bf. Offlineactual
workerpublicdigestoracle before/after299inputs+2knownvectors/8450hexchecksPASS;
7alternatingbatches/28pairedsamples retained, no timingrerun. HostGNUopt3/noLTO
median actual/proposed ns owner45B768.282/61.992, allocation623B1000.822/274.531;
notnativecostshare/CPU/savedbudget/2sfit or releaseperformance. Root rechecked203
currentinputs unchanged; experiment179Rust+10configunchanged corroborated.
Ruling: accept exactonefile sharedSHA256 lowercasehex representation-work removal
under reviewed brief, preserving hash/input/output/calls/livechecks/identities.
Costifwrong: equivalence/native experiment and rework, never identity recreation
or deadline/ownership relaxation. Soleimplementer may edit only workerbootstrap
helper/tests after this mechanismcheckpoint push; sourcefreeze/freshreview/
coherentartifacts/authored59baseline/checkpoint precede nextnativeVMrun. Full8c
ACTIVE/release_readyfalse; original398-406 failures preserved.
