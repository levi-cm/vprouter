# Draft release compatibility and unsupported environments

UNRELEASED / PREPARATION ONLY. Every platform's release/runtime/service acceptance
is NOT_RUN in Task13. This table describes intended eligibility, not support.
Static musl ELF packaging does not establish a host's libc or runtime compatibility.

| Host / manager | x86_64 artifact | ARM64 artifact | Native service/runtime acceptance | Current disposition |
| --- | --- | --- | --- | --- |
| Debian13 glibc / systemd, Linux6.1+ | builder/verifier fixture coverage; real release build NOT_RUN | same; no execution | NOT_RUN | declaration eligible; install blocked |
| Arch/CachyOS glibc / systemd, Linux6.1+ | same | same | NOT_RUN | declaration eligible; install blocked |
| Void glibc / runit, Linux6.1+ | same | same | NOT_RUN; native cgroup/watchdog/readiness parity absent | declaration eligible; install blocked |
| Void musl / runit | may be ELF-compatible, unqualified | unqualified | unsupported | preflight refuses |
| Other distributions/managers, kernel<6.1, non-Linux, non-x86_64/ARM64 | unqualified | unqualified | unsupported | preflight refuses |

All eligible declarations require cgroupv2, usable nftables, kernel WireGuard and
TUN. Actual Docker/API/security/cgroup hierarchy, LSM/seccomp/capability, NSFS/FD,
provider/Tailscale/client and host-libc observations remain separate native gates.
The current native CLI's Void host-glibc check is NOT_TESTED; a supplied public
Python declaration cannot close it. The currently reviewed producer authority
requires its tested systemd Docker cgroup hierarchy; runit has no equivalent
accepted native placement/enforcement path. Host-launched children's confinement
must be directly reviewed, not inferred from container inspect settings.

Unsupported/unverified: cgroupv1/hybrid, rootless/userns gateway execution, privileged
Docker, host-network gateway, Docker socket inside gateway, persistent SYS_ADMIN,
unknown namespace/identity/resource ownership, mutable image tags, state-format
conversion, missing exact-compatible backup, undeclared hostname dependencies,
foreign/unmanaged policy cleanup, remote installation acceptance in this local-only
scope, unmanaged/non-Linux clients, host-shared client namespaces/sockets/resolver,
proxy settings without native enclosure, automatic direct/server/DNS/IPv6 fallback.
Unsupported or unknown prerequisites block changes before any installation.

Real release cross builds are NOT_RUN: pinned C wrappers/Zig/musl-gcc absent;
no network permitted, shared nested-guest memory constrained. Both Rust musl
standard targets being installed is compile infrastructure only. The deterministic
metadata/fixture checks cover two target names and ELF machines62/183. They do
not prove either actual binary build, reproducible compilation or ARM execution.
See [redacted evidence](release-preparation-evidence.json) and the unchanged
[acceptance ledger](acceptance.json).
