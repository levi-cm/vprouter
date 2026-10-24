# Task8b2 actual-program integration: candidate01

Status: implementation candidate, **runtime NOT_RUN and task incomplete**. No
production launch, readiness, Placed authority, approved state, enrollment, or
privileged guest execution was performed by this agent. Root alone executes the
frozen identity-free local-VM oracle; independent review remains required.

The private launcher now binds retained admission, namespace, producer-group,
program manifests, CA, role-specific state, descriptors and fixed argument arrays
to real Rust observer / Tailscale1.102.5 execution. Image PID1 is a fixed inert
Rust init. Helpers join the exact producer group before namespace/runtime/socket
work, create private roots and cgroup views, close host controls, set65534 UID/GID,
retain caps0(observer) or only NET_ADMIN(daemon), NNP, AppArmor and fixed seccomp.
Writable state is noexec/nodev/nosuid; config/CA/proc are read-only. Go has fixed
locked disabled preferences, no CLI/shell/iptables binaries, and no enrolled state.
Observer authenticates the existing one-use handoff before native metadata and
GET-only LocalAPI status/prefs construction. Observation cannot mint readiness.

The execveat seccomp rule is FD4/AT_EMPTY_PATH-bound, **not a one-shot syscall**.
Combined confinement leaves only the selected fixed executable in a private root;
state is noexec, executable mappings/memfd and process-memory APIs are denied,
and descriptors close on exec. Re-execution of the same fixed executable is not
claimed impossible. Arbitrary secondary-program execution is not admitted.

Candidate01 offline checks: focused launch/worker tests65 passed; focused clippy
with warnings denied passed; both architecture static observer/init/actual payload
builds passed. Full-workspace checks and mutation evidence remain pending.
A packaging mismatch was caught before freezing: cargo test-target compilation
rebuilt init using different per-invocation flags. Frozen build order is observer,
init, refresh manifests, explicit init rebuild + equality check, payload build,
then **explicit init rebuild again**, followed by context verification of every
actual file against manifests. Both architecture init bytes matched the manifest
after that final rebuild. Do not run further cargo commands and reuse binaries
without repeating manifest/context verification. Deterministic scratch contexts
contain only whitelisted public pinned binaries/CA, current Rust artifacts,
program manifest and fixed Dockerfile; Python, CLI and identity/state are absent.

Remaining required work: fresh actual Go syscall/capability/LSM/TUN witness;
exact source/namespace/ifindex/generation-bound admission of observed daemon
kernel shapes; bounded real Rust+Go lifecycle and container-death evidence;
positive and negative packet/drop accounting; full validation and independent
spec/quality review. Actual image/runtime certification on ARM64 is NOT_RUN.
Task8c autonomous protocol/readiness/provider/client/fault acceptance and all
multi-exit, migration, production and release gates remain closed.

## Candidate02 diagnostic correction

Root-owned candidate01 attempts1/2 failed before exec; no actual Go success.
Attempt2 metadata-only `strace -ff -e raw=all` records child33895: last successful
readonly TUN bind-remount0x102b followed by `open`0x88241 returning EROFS and
helper exit118. This exact source ordering binds the failure to first IPv6 sysctl
write after entering Docker's readonly proc/sys view. Candidate02 enters and
rechecks only the retained owned data netns, suppresses IPv6 there through host
proc before container mount entry, then preserves the readonly private proc.
No seccomp/capability/LSM relaxation was made. Early outer failures now report
bounded error codes; NetworkOperation is distinguished from generic child failure.
Init staging is content-addressed per immutable manifest digest. Packet witnesses
now require independent data/transport/host positive controls, all three negative
captures with zero kernel capture drops, sixteen unauthorized attempts, sixteen
authorized roundtrips and explicit receive/send accounting. Candidate02 focused
26-test suite and launch clippy passed. Runtime remains pending.

## Candidate03 init filter sequencing

Root attempt3 reached exact Go `execveat`, but private PID1 then failed its
post-filter descriptor rescan: raw child34321 shows successful seccomp install
and scalar query followed by `openat` flags0x98000 returning EPERM. Candidate03
preserves the exact pre-filter PID1 descriptor closure/inventory and installs the
reduced filter immediately afterward. Installation creates no descriptor; only
its read-only scalar PR_GET_SECCOMP verification and health acknowledgement/close
follow before the fixed signal/reap loop. The actual wait filter still denies
all path opens, sockets, namespace operations, fork and exec. The6b probe retains
its existing before-and-after checks. Actual exec retains exact0..4 check, with
CLOEXEC health3/executable4; both supervisor and program host controls close.

Explicit clone3 ENOSYS and architecture-guard assertions were added. A temporary
mutation broadening clone3 to ALLOW was rejected(exit101); restored policy test
passed. The initial mutation exposed the missing explicit assertion and was not
misreported as covered. Exact evidence is retained in controller-local
/tmp/task8b2-clone3-{mutation,restored}-test.txt. Focused26tests and launch clippy
pass. Fresh03 runtime, kernel-shape admission and container-death remain pending.

## Candidate04 exact demonstrated Go thread clone

Root attempt4 resolved PID1 sequencing and demonstrated pinned Go
`clone(0xd0f00, stack, 0, 0, tls)` denied EPERM, followed by exit2. Candidate04
admits only that additional canonical thread flag set (VM/FS/FILES/SIGHAND/THREAD/
SYSVSEM/SETTLS), alongside prior exact sets; fork, signal-bearing or namespace
variants and every upper-word bit remain denied and are regression checked.
No general clone, clone3, exec, privilege, socket-family or mount allowance was
added. Focused26tests and clippy pass; both static payload/image-input builds
and post-payload init manifest verification pass. Further actual runtime pending.

## Candidate05 pinned native firewall and log-state environment

Root unchanged04 attempts5(raw syscall metadata) and6(file-metadata-only trace,
no IO/random/exec/environment decoding) bind startup panic to readonly `.local`
creation and absent `/tmp/tailscaled-log-*` fallback. Exact pinned source
`https://raw.githubusercontent.com/tailscale/tailscale/v1.102.5/logpolicy/logpolicy.go`
SHA2561668c4d220b34bca51d482ddef08b8ce251c8a2944e28ed61d3ef2a9ec7d4321
shows LogsDir ignores --statedir, tries default/user/current/tmp paths and panics
when none exists. Fixed **daemon-only** TS_LOGS_DIR=/state directs log state to
its already selected private noexec/nosuid/nodev700 directory. Root/tmp remain
readonly/absent; getcwd and access are not broadened to hide the path error.

Pinned native firewall source
`https://raw.githubusercontent.com/tailscale/tailscale/v1.102.5/util/linuxfw/nftables_runner.go`
SHA256198b3472a1905577df2ea91de7a15d6be37eec0eba603fb0dd21caded44314b7
New defaults to the iptables runner unless prefHint/environment requests nftables.
Router setup initializes that runner even when netfilterMode=off. ConfigVAlpha
has no NetfilterKind field. Fixed **daemon-only**
TS_DEBUG_FIREWALL_MODE=nftables binds the native runner without secondary exec.
Observer retains exact LANG=C/PATH=/bin only. New exact environment regression
passes; focused27tests and clippy pass. Both static architecture builds and final
post-payload init/context hashes verified. Actual05 runtime remains pending.


## Candidate06 private mount isolation and demonstrated TUN pipe

Unchanged05 root attempts7-9 remain FAIL and are retained. Attempt7 raw syscall
metadata identifies successful TUNGETFEATURES/TUNSETIFF/offload/SIOCGIFINDEX,
followed by three pipe2(O_CLOEXEC) calls denied EPERM in actual Go thread35771.
Root attempt9 used an explicitly bounded FD2-only diagnostic in the fresh
unenrolled fixture; root retained raw logs privately and emitted only fixed
public-source error classifications for engine/TUN/operation-not-permitted.
No state, LocalAPI, read/random, environment or identity payload was decoded.
Candidate06 adds daemon-only pipe2 with exactly O_CLOEXEC and zero upper word;
observer, inheritable, nonblocking/direct-mode and extra-bit variants stay denied.
The broad pipe2-ALLOW mutation fails the focused policy test(exit101), and the
restored exact policy passes(exit0). Evidence is retained in controller-local
/tmp/task8b2-pipe2-{mutation,restored}-test.txt. The demonstrated nonfatal
inotify_init1 failure receives no new allowance.

The source also reveals an independent setup race: after fork, actual_exec
remounted /proc readonly in the supervisor's shared mount namespace while that
supervisor still needed its fixed AppArmor attr/current transition. Child setup
now unshares its mount namespace before the readonly remount. This strengthens
private mount isolation without adding post-exec authority; setup SYS_ADMIN is
still removed before the fixed program exec. Two ignored-harness stage markers
distinguish setup acknowledgement from live socket/program identity, neither of
which mints readiness. Focused27tests, fmt and launch all-target clippy pass.
Actual06 runtime/regression, exact daemon kernel-shape admission and lifecycle
acceptance remain pending; no actual runtime PASS or production authority claimed.


## Candidate07 rejected-descriptor diagnostic witness

Root unchanged06 attempt10 reached setup acknowledgement and live exact Go
program/socket identity, then rejected DescriptorPolicy in the ignored inspector.
Candidate07 changes only that test observer: it retains at most256 numeric FD
kernel targets, flags, stat device/inode/mode before grammar validation; it also
captures public link/address/route/rule/netfilter metadata immediately before
process inspection. Pipes remain rejected pending this fresh witness. No guessed
pipe count, descriptor inheritance, runtime filter or kernel baseline is admitted.
Launch all-target clippy and both static payload/context builds pass. Runtime
remains pending and failure evidence/quarantine are retained by root.
