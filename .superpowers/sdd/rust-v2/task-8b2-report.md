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


## Candidate08 exact observed descriptor grammar

Root unchanged07 attempt11 retained daemon descriptor SHA256
b0f373f2e78654c563c82b0040ffd73c7e7adfa49bed61fb171dd36ae8e4dfa8 and
kernel metadata SHA2566fb58a2cdfa5c3549beeb5ee930b51c8906fe4310c5094b13b2f9c01214914f6.
The first rejection was null stdio's backing target spelling /null, rather than
its device identity. Inspector now requires exact selected private-root null
(dev,inode,rdev), character type, major1/minor3 and RDWR flags for all0..2;
backing-path spelling grants no authority. It also checks the ONE witnessed
post-exec daemon FIFO pair: same positive dev/inode, canonical pipe:[inode],
mode010600, rdev0, exact reader O_CLOEXEC and writer O_WRONLY|O_NONBLOCK|O_CLOEXEC.
Observer allows no pipes. Nine distinct inode/device/flags/type/count/stdio faults
are rejected by focused offline regression; launch28tests and clippy pass.
The inherited-FD pre-exec0..4 closure remains unchanged. Metadata from11 is
transitional (TUN down then UP across dumps), so it is not adopted as a stable
kernel baseline or readiness. Live-daemon token/structural admission remains work.


## Candidate09 host mount provenance and retained daemon authority

Root unchanged08 attempt12 passed actual Go UID/NET_ADMIN-only/LSM/seccomp/
private-root/state/descriptor checks, then failed observer mount preparation.
All52 raw metadata trace files identify observer helper37614 open_tree(fd5,
AT_EMPTY_PATH|CLONE|CLOEXEC) EINVAL after successful executable and CA clones.
The fixed host-owned placement directory was being cloned after entering the
container mount namespace. Candidate09 clones only host placement/socket sources
before namespace entry, registers their detached-tree descriptors, and duplicates
those exact trees for private move_mount after entry. CA/TUN/null retain their
container-view cloning. Neither parent path nor another state view is exposed.
All controls and detached mounts still close before fixed exec.

A new private LiveDaemon object is minted only after actual Go is live. It
retains fixed executable/configuration descriptors, five namespace objects,
pidfds/proc/starttimes for the exact three-parent chain ending in the launcher's
retained unreaped Child, owned producer membership, initial UID/GID maps,
post-exec65534 credentials, NET_ADMIN-only allfive capability sets, NNP/seccomp/LSM,
manifest digest, protected bootstrap digest and generation-bound transaction.
Revalidation checks these objects before/after metadata and observer execution;
any error permanently revokes. Setup acknowledgements mint no such object.
Ignored lifecycle now requires repeated refusal after actual daemon TERM/reap.
No kernel-shape permission or readiness is added by this object. Pure parsing and
credential fault regressions pass; launch30tests/clippy pass. Botharchitecture
static artifacts/contexts are rebuilt after final source changes. Root runtime
and all remaining structural/lifecycle acceptance remain pending.


## Candidate10 bounded authenticated observer handoff

Root unchanged09 attempts13/14 remain FAIL and are retained. Attempt13 reached
actual_daemon_identity_pinned and passed actual Go confinement, then both Go and
Rust observer exec succeeded. Observer refused bootstrap after successful
SO_PEERCRED; the existing inspection raced transient bootstrap descriptors/exit.
The metadata-only attempt14 collector validated53 files but saw no SO_PEERCRED
calls, so no actual PID0 credential witness is claimed from either attempt.

Pinned rustix1.1.4 UCred represents pid with NonZeroI32, although a host listener
outside the observer's private PID namespace may legitimately translate to pid0.
Worker now uses exact nix0.30.1 safe PeerCredentials with raw libc pid_t layout;
root UID AND GID remain mandatory, followed by the same protected socket, nonce,
digest and independently pinned sender checks. The public nix crate's SHA256
74523f3a35e05aba87a1d978330aef40f67b0304ac79c1c00b294c9830543db6 matches the lock.
Only nix0.30.1, cfg_aliases0.2.2 and memoffset0.9.1 are new lock packages; no prior
locked version changed. Direct pid0/root positive and either-nonroot negative
regressions pass. Weakening OR to AND fails that regression(exit101); restored
policy passes(exit0), retained in /tmp/task8b2-root-peer-{mutation,restored}-test.txt.

The ignored test inspector now runs only after a request's digest/nonce and
actual sender have been checked, while the observer awaits its response. The
one-use attempt is consumed before accept; sender, authority and absolute
exchange deadline are checked again after inspection and before ObserveOnce.
Production uses the same path with an empty inspection callback. This changes
no permission and avoids racing observer exit/bootstrap descriptor closure.

Framing uses safe fcntl_getfl/setfl preserving all existing flags plus NONBLOCK,
instead of std's Linux FIONBIO ioctl; no syscall permission is added. Status-flag
preservation and bounded backlog/stalled/trickling exchange regressions pass.
Final launch30 and worker41 tests pass, including all10 focused bootstrap
regressions; launch/worker all-target clippy and fmt pass with the final code. Static observers, init, payloads and contexts for both
architectures are rebuilt and source-bound before root execution. Successful
actual observer/LocalAPI, strict token-bound kernel shape and lifecycle remain
pending; production launch/Placed/readiness stay refused.
