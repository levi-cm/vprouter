# Task 10 direct-exit preparation

OFFLINE_PREPARATION_ONLY. Task8c runtime, ARM and real-client acceptance remain
OPEN. No native direct driver, activation flag, enrollment operation, quarantine
release, service change or runtime import is added. `release_ready=false` remains
unchanged. JSON policy plans and synthetic READY states are not native authority.

Task10 extends Task9's `PreparedFleet`, `FleetRecord`, `ExitChange` and
`FleetPolicy`; it does not introduce a parallel fleet or allocation store.
Explicit `mode: {"kind":"direct"}` entries support add/remove/enable/disable
and the same generation + canonical-content CAS atomic preparation bundle.
Mixed metadata and fallback fields refuse. `pin_server` cannot convert direct
into Mullvad. Direct enrollment-key files refuse: future enrollment must be a
fresh interactive identity in independently protected state, never cloned.
Removing entries never deletes or copies credentials/state.

The hostname is `unsafe-direct-host-ip-debdev-exit`; all duplicate direct names,
including disabled entries, receive their stable exit ID suffix. DNS labels over
63 bytes refuse without truncation. Stable resource/node/state identity remains
independent of the hostname. `select` provides internal callback correlation;
`select_client` and `client_plan` require exit ID, exact stable node ID and explicit
client mode. Protected selection refuses direct, direct selection refuses Mullvad,
and absent/disabled exits refuse both. No failure selects another exit or mode.
Plans say `direct-exposed`; their egress/DNS/IPv6 observations are `not_tested`.
Runtime status reuses independently supplied health evidence and never labels
direct protected or infers a Mullvad server/handshake. Existing generic
`Evidence.provider_ok` must mean a successful independent direct reachability
witness in this mode; it is not Mullvad confirmation. No direct witness producer
is implemented. Missing egress verification cannot yield policy READY.

`direct::DirectPlan::prepare` requires an enabled direct member, matching complete
allocations, a `HostSnapshot` and an explicit `DirectPath`. Snapshot parsing is
strict, bounded to64KiB and256 entries per address/prefix list, with nonempty
addresses/connected prefixes, generation>0 and canonical IPv4 CIDRs. Preparation
revalidates these conditions even for a directly deserialized snapshot. Include
ALL host public/local addresses (including public NAT mappings), connected
prefixes and declared local/management prefixes, even if globally numbered.
No hostname resolution or host resolver exception exists. Completeness is an
external observation obligation, not something a caller-supplied snapshot proves.

The JSON renderer describes an initially quarantined, default-drop IPv4 TCP/UDP
application policy, exact allocated namespaces/interfaces and generation, dedicated
WAN name/ifindices, a stable per-exit conntrack zone, client source100.64/10,
denied destinations and exact-original-flow NAT / exact-reverse-established reply
predicates. `allows` evaluates the intended application policy after a future
guard admission; it does not describe live forwarding. Only nonzero ports and the
exact path are admitted. DNS follows those identical predicates. IPv6, unsupported
protocols, new inbound traffic and mismatched interfaces/tuples/scopes refuse.
Return tuples are evaluated after reverse NAT, outbound tuples before source NAT.
The policy fingerprint binds configuration, allocation, host generation/content,
path and denied-range version. Zone collisions across all reservations refuse.
Existing-flow claims are public data for this evaluator, not authenticated kernel
conntrack evidence. Future native integration must flush exactly owned conntrack
on lifecycle/path changes and independently bind kernel zones, namespaces, NAT,
flow provenance and retained epoch authority.

Denied-range policy `direct-ipv4-2026-11-06-v1` is a manually curated conservative
snapshot based on the [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/),
[RFC6890](https://www.rfc-editor.org/rfc/rfc6890) and RFC8190 updates. No network
refresh was performed. It denies entire special-purpose blocks, including the
publicly reachable exceptions/AS112/AMT/6to4 infrastructure, instead of treating
RFC1918 exclusion as sufficient. Additional conservative /32 denials cover Azure's
[168.63.129.16 platform address](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16),
Equinix Metal metadata147.75.207.207 and legacy Packet metadata192.80.8.124.
AWS/link-local metadata and Alibaba100.100.100.200 fall within denied larger
blocks. These references explain the local version; they are not a claim of an
exhaustive or freshly fetched list of every provider's services. Host/site-specific
infrastructure must be declared in local prefixes. Future policy revisions require
review and fresh qualification. Host addresses and connected/local prefixes are
additional denials in both new and established directions.

`reconcile_direct_host` validates the host clock first and checks exact plan/
binding and snapshot equality. Missing evidence, changed generation/address/prefix
or a mismatched plan blocks only the selected exit and queues quarantine before
sample work. It never refreshes health, releases quarantine or replaces the plan.
Blocked sessions stay revoked until explicit fresh-lifecycle restart. All six
operational time-bearing entry points share the same high-water mark; NaN,
infinity, negative, regressing and >1e12-second clocks trigger fleet emergency.
The ceiling preserves millisecond f64 cadence precision. Only enforcement polls
renew the90s watchdog. Six slots (at most five Mullvad),128 reservations,1024
lifecycles and at most12 actions/poll remain bounded. Late callbacks cannot weaken
terminal states; repeated container failure does not re-arm drained emergency
requests. Missed sample slots are skipped, including direct-only and mixed fleets.

Storage reuses the existing private directory/flock/NOFOLLOW/single-link/O_EXCL/
file-fsync/rename/directory-fsync writer. Each transaction operation rechecks the
still-named lock inode. Before rename, the original temp FD and named temp must
still match and remain private single-link regular files. Symlink/hardlink/lock
substitution refuses without repairing foreign bytes. Protected directory and
cooperative locking remain the concurrency boundary; these checks cannot make
check+rename atomic against a malicious privileged writer. Power-loss, SIGKILL,
disk-full and native journal recovery are not qualified by ordinary file tests.

`tests/direct_owned_guest.rs` has four ignored, fail-if-forced specifications:
one direct public/forbidden-marker matrix; five Mullvad plus direct faults and
cross-exit established flows; fresh enrollment/private roles/no primary path;
and quarantine-first startup/address drift/interruption/exact cleanup. All are
NOT_RUN and are not implemented native harnesses. A future admitted driver must
retain independent guard emergency/activation authority, dedicated direct WAN
policy unreachable from every Mullvad data/transport namespace, private PID/
mount/proc/state/FD/cgroup boundaries, exact-owned cleanup and failure-first
quarantine while retaining one gateway. Existing artifact/syscall/LSM admission
must remain mandatory; the current native network/netfilter/worker paths still
refuse direct. No real traffic, DNS/IPv6 safety, ARM execution, migration,
performance, reboot, soak or release acceptance is established here. Independent
review and controller-owned real-client qualification precede integration.
