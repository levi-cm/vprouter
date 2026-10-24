# Independent traffic acceptance and preserved-identity canaries

PREPARATION ONLY; dispatch after reviewed complete implementation and immutable
candidate, including client guards/migration/release/performance. Workdir
/DATA/AppData/vprouter-rust-v2, rust/v2, no subagents. Binding original handoff and
IMPLEMENTATION.md; acceptance.json enumerates mandatory scenarios. Controller
alone performs privileged/external/credential-bearing actions. No publication or
shared-branch push before all release gates; never fake unavailable acceptance.

Build/run real disposable Tailscale clients generating continuous distinct IPv4,
DNS, IPv6, TCP and UDP markers. Capture at clientWAN, hostWAN, each transport and
data plane with positive controls proving sensitivity. Configurations:1Mullvad,
5Mullvad,1direct,5Mullvad+1direct. Capture operational interface before workloads,
including boot. Zero forbidden plaintext/cross-exit markers is absolute gate;
host residential application egress during Mullvad tests immediately fails.
Direct residential egress expected only for explicitly selected authorized direct
node, always direct-exposed. One exit failure cannot alter healthy-exit routes or
mode; direct remains active during each Mullvad fault. Synthetic namespace tests
do not substitute for real Tailscale clients.

Exercise EVERY listed tunnel/provider/routing/firewall/process/resource/identity/
isolation/client/migration fault in acceptance.json/original mandatory matrix,
including freezes/crashes/OOM, container/Docker/service restart/reboot, full disk,
malformed/delayed/unavailable APIs, wrong keys/endpoints/server, approval/credential
revocation/control loss, duplicate identities/foreign resources, selected-node/
route resets/proxy absence/bypass, and kill/rerun at each migration boundary.
Record exact injected boundaries, positive controls, capture windows/source bytes,
cleanup/ownership, expected and actual results; no skipped/unknown check becomes
PASS. Preserve failed attempts and independently assess unsafe/firewall/namespace
and client enforcement against exact candidate.

Only after preceding compatibility/security/artifact gates: migrate debdev's
existing primary through reviewed declared adapters while preserving identity,
credentials/IPs/approval; verify renamed node using actual protected client; add
further imported distinct-device profiles; add direct ONLY via explicit config;
run mixed faults and24hour soak. Migrate a second existing installation through
its declared adapters and verify compatible rollback. Its access currently
unavailable; report external blocker precisely without substituting new lab for
existing installation. Interactive approval links are user-selected enrollment;
preserve approved lab client/gateway identities and do not re-enroll/reset them.

Deliver machine-readable validation/security-test mappings, redacted migration
reports, performance/resource reports, immutable identifiers/dependency/provenance,
exact agent/systemd/runit instructions and unsupported/unverified list. Release
ready only when all required gates PASS with source binding and independent whole
branch review. Task-15-report.md records exact evidence and any unavailable check;
no completion/no-leak claim from READY/advertisements, mock suites or static builds.
