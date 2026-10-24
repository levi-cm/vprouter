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
