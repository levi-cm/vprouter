# Task 8b1: fixed programs, producer gate and observation handoff

Final implementation source: `ffb7053456ac025154991c92624d668ab9e4671e`.
Initial implementation `7c08bd63d63e9d62ea7b2ecb71f7d93d5ba3b76d`, bounded
test diagnostics `c18f55fa20523afa0150dd193162333886786e4a`, parent cgroup identity
correction/regression `ffb7053456ac025154991c92624d668ab9e4671e`.
This implements the bounded task-8b1 brief. Task8b remains incomplete: actual
observer/Go execution and immutable image confinement are8b2; autonomous
guard/protocol/watchdog/readiness and real-client acceptance are8c. Production
CLI, `Admission::launch` and normal worker startup still refuse; no public
`Placed` constructor, readiness, advertisement or quarantine-release bypass exists.

## Changes and authority boundary

The compile-included amd64/arm64 manifests bind exactly two program roles, fixed
paths, architecture, pinned Tailscale1.102.5 index/platform bytes and explicit
policy. Unknown/duplicate roles, paths, policy, arguments and platform substitutions
refuse. Executable verification checks root ownership, nonwritability, regular
file, bounded exact size/hash, static ELF machine and stable metadata. Private
`Program` is data binding, not execution permission. Tailscaled policy explicitly
states execution unavailable until8b2.

Producer release accepts only a live unreleased pidfd-owned child. It rechecks
the retained allocation/container parent/namespaces/subgroup, joins the subgroup,
then freshly checks exact host membership and starttime before release. Docker
parent controllers/limits are untouched. Descriptor registration accounts only
for the additional exact parent and two subgroup descriptors; unrelated FDs fail.
The parent cgroup directory identity binds dev/inode/type/mode/UID/GID. Its size
and timestamps may change when the owned child directory is created or removed;
they are not treated as object identity. Exact process membership, cgroup2 mount
provenance, pidfd, namespace, Docker and owned-subgroup checks remain required.

Only freshly audited `GuardTransport` can prepare the private one-use handoff.
The selected state parent stays root0700; a root0755 placement directory holds
root0444 configuration and a root-owned socket. The host consumes the attempt
before accept/validation. Its actual SO_PEERCRED peer must have UID/GID65534;
retained pidfd/starttime, initial UID maps, exact host producer membership,
namespace and fixed executable are checked before a digest/nonce-bound
`ObserveOnce` response. Changed retained authorities fail. Namespace-relative
cgroup `/` and worker-visible peer PID0 are explicitly not host process proof.

The observation executable takes no arguments or overrides. Before its first
socket it validates protected root-owned, read-only mounted config, exact
allocation member, local namespace/cgroup, own hash, UID/GID65534, empty groups,
all five empty capability sets, NNP1, exact environment and null-only FDs0..2.
It then authenticates the fixed root-owned control socket and digest/nonce reply.
Protocol frames are at most4096 bytes; one absolute deadline spans read prefix
and body, including trickling peers. A private non-Send observation token allows
only namespace-local metadata snapshots, with identity rechecks around clients.
`MonitoringPlan` contains public endpoint/address/key/device facts, no WG private
key. Metadata snapshots cannot satisfy the full structural audit/activation API.

The two task8a Minor documentation corrections are included: guarded activation
requires retained quarantine authority; bootstrap INPUT wording now distinguishes
family/WG/producer/established predicates from separately audited addresses.
No firewall predicate was added to satisfy the old overstated report.

## Offline validation and reproducibility

Completed locally, without privileged payload execution:

- `cargo fmt --all --check`; `git diff --check`: pass.
- Final `cargo test --workspace --all-targets --offline --locked`:161 passed,
  2 ignored; all custom privileged entrypoints were inert.
- Final `cargo test -p vprouter-launch --lib --offline --locked`:22 passed,
  including the manifests and cgroup identity mutation/substitution regression.
  Earlier focused launch/network/worker libraries:78 passed,1 ignored.
- `cargo clippy --workspace --all-targets --offline --locked -- -D warnings`:pass.
- `CC_aarch64_unknown_linux_musl="$PWD/target/toolchains/aarch64-linux-musl-cc"
  cargo check -p vprouter-launch -p vprouter-worker -p vprouter-network
  --all-targets --target aarch64-unknown-linux-musl --offline --locked`:pass.

Both observer and producer payload static release builds passed for both targets.
Use `cargo rustc -p vprouter-worker --bin vprouter-worker-observe --release
--target TARGET --offline --locked -- -C relocation-model=static`, and
`cargo rustc -p vprouter-launch --test producer_lab --release --target TARGET
--offline --locked -- -C relocation-model=static`. Set target-specific
`CC_x86_64_unknown_linux_musl="$PWD/target/toolchains/x86_64-linux-musl-cc"`
or `CC_aarch64_unknown_linux_musl="$PWD/target/toolchains/aarch64-linux-musl-cc"`;
ARM additionally uses `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld`.
ELF program headers were independently parsed: neither PT_INTERP nor PT_DYNAMIC
is present; machine62 x86_64 /183 ARM64. Root independently verified both
observer hashes, sizes, machines and these static predicates.

| Frozen artifact | Bytes | SHA256 |
| --- | ---: | --- |
| x86 observer |2078120|`6ccb35685cbf9f62997d74ca341cf518d2d996a61d2dfcbf829cf1d80d448dd2`|
| ARM observer |2390984|`f6b923d25ab310bbaefbc3cd9738d37d69c8d52a2765ae6e47b70931388d77d5`|
| `/tmp/task8b1-candidate01` |2493200|`fad89759c5687e7279ea9257313eb7f7e77aa0fc9000b5a6c2256ff0cfd73964`|
| `/tmp/task8b1-candidate01-arm64` |2975816|`26369b835cfba148581e37c06cdd22ef13f4280093a581c724718f64f50420be`|
| `/tmp/task8b1-candidate01-source.tar` |1075200|`73109a5707e5eadd9730b01d5014a3603cfe7e278112d6e27a3f4f5bc1728517`|
| `/tmp/task8b1-candidate02` |2500144|`bde41de5ad7111c16dea1c473c4b77ecb21db4de2a448c8bad153f4e90fb3b6e`|
| `/tmp/task8b1-candidate02-source.tar` |1075200|`a4244176924bfe682019b5931e73e973ee2c2cb1f377e6eed2fc539c8ef6ed6c`|
| `/tmp/task8b1-candidate03` (final x86) |2500056|`c48a8fcf43982e00070dc15d49239d42a06c1d2b3732939e1d1d1c92a69c6b74`|
| `/tmp/task8b1-candidate03-arm64` (final ARM) |2982168|`c0f74c26f1bb01cc219fc6347a53932915c805adf120a1c22210f14c36d4a0bd`|
| `/tmp/task8b1-candidate03-source.tar` (final) |1075200|`a01c4d3b3863bcae84162d2d24335a7dc6d77c19cecf4f208b381f517e2d512e`|

The archive is `git archive` of the source commit with Cargo.toml/Cargo.lock,
rust-toolchain.toml, all crates, examples/v2 and both program manifests. Observer
paths are `target/{x86_64,aarch64}-unknown-linux-musl/release/vprouter-worker-observe`.
Regular release initially produced a static PIE containing PT_DYNAMIC; self-review
caught this before any runtime attempt. The explicit static relocation builds
above corrected it. Those initial development binaries were not admitted or run.

## Privileged producer oracle

Root alone ran the frozen `candidate03 --ignored` in its owned local VM and a
fresh isolated netns, never production. Admission checks existing lab marker,
single thread, netns unequal PID1, and protected root0600
`/var/lib/vprouter-v2-lab/task8b1-producer-acceptance` JSON fields
`artifact_sha256`, `network_dev`, `network_ino` matching current executable/netns.
It requires the unchanged approved root:root0555 single-link6b probe at
`/var/lib/vprouter-v2-lab/launch-execution-probe`, SHA256
`808789d0d5d59b673c7f6fd55b306c3ecfc05ef0bbdd65731cff2ae7695bd828`.

The payload creates only a new pinned network-none, read-only, capdropALL/NNP,
identity-free probe container and `/var/lib/vprouter-v2-lab/task8b1-PID` synthetic
state. It never creates transport, WG, routes, forwarding, captures, observers or
Go daemons. It tests killed gated child/no execution; wrong exit before fork;
five exact subgroup processes including frozen descendant; selected private
worker state/network; unchanged Docker parent membership/controls; bounded
SIGTERM/reap; normal exact group cleanup/Offline; and container-death reap.

On container death Docker may remove its parent cgroup. Cleanup then refuses to
manufacture replacement authority, retains durable Activating pins/intents, and
proves reopened acquire refuses Interrupted. This expected branch prints
`LAB_PRODUCER_CLEANUP interrupted_pins_retained=true`; zero remaining pins is not
its acceptance criterion. Exact new container removal is required; ambiguous
resources are retained, never broadly deleted.

Root retained every attempt and exact ownership inventory:

| Attempt | Source | Result | Evidence |
| --- | --- | --- | --- |
|1|`7c08bd6`|FAIL exit1,1.697s, preflight pass; no cases|`target/lab-state/producer-placement-run-1.json`|
|2|`c18f55f`|FAIL exit1,1.408s; diagnostics isolated CgroupMismatch during pre-spawn container revalidation|`target/lab-state/producer-placement-run-2.json`|
|3|`ffb7053`|PASS_PARTIAL_PRODUCER_GATE exit0,2.207s; all8 cases pass|`target/lab-state/producer-placement-run-3.json`|

Run-evidence SHA256, attempts1/2/3 respectively:
`d89e007122f4a938b64ab57c4b5d8075de074428225c078c6ebfd4a003bb8557`,
`55703079a5d442745e9bbdfcfbc0513698dcf6c12977f10cfbf40da6d7e69681`,
`4b48aabe05cd3f0a9ce2a3921f0a7b6ef0d0038329e5bfcbedb0b83be7655ede`.

Attempts1/2 retained Activating ownership records/pin files; their exact containers/parent cgroups
were absent after bounded failure cleanup. No broad cleanup was performed. The
first error was masked by the killed-child negative oracle, so attempt2 added
test-only stages and printed the unexpected error without relaxing acceptance.
It confirmed parent cgroup directory timestamp changes caused by the owned mkdir.
The final fix/regression binds the exact stable identity fields described above.
No child execution occurred in these failed attempts.

Root independently matched all97 archive build inputs to the final source
(aggregate `730d5841` prefix), verified source/artifact hashes and static ELF, and
ran the passing payload. The runner SHA256 was
`321b75faaea873e40ab16ab217d77dae27f7f51ff4aacdb84714de591b5f2fc1`.
Passing stdout contains all8 cases listed above; stderr explicitly records
`interrupted_pins_retained=true`. Actual observer/Go/real-client execution is
explicitly NOT_RUN and production_changes=false in the root evidence.

Final root read-only terminal inventory is
`target/lab-state/producer-placement-inspect-3.json`, SHA256
`cb70d8b1cdd7ca117b5c83af8867746aa85b1b0dc5b776944ef6383e11fced91`.
All3 exact test containers and parent cgroups were absent; each attempt's `one`
entry retained Activating producer ownership, `two` stayed Offline. No observer
or transport was created; the approval marker was removed. Final attempt directory
was `task8b1-32199`; root independently read root0600 `result.json` with exact
`pass_partial_producer_placement`, observer/Go NOT_RUN and readiness=false.
This verifies retained ownership records/pin files. Actual namespace bind-mount
persistence outside the runner's private mount namespace was not independently
verified and is not claimed. Root also independently verified final ARM03 hash,
length, ELF machine183 and absence of PT_INTERP/PT_DYNAMIC; ARM runtime is unrun.

## Inventory, self-review and remaining gates

No new unsafe statement or raw syscall was added. All existing unsafe remains
in kernel.rs; its sole addition checks the existing unreleased child gate using
existing pidfd polling. Host additions use safe rustix/std file/proc/cgroup,
pidfd, Unix credential/socket and poll APIs. No capability, LSM/seccomp permit,
TUN, network transport or production subprocess was added. The ignored test
uses only the existing fixed-argv Docker lab helper for its one new container.
Observer creates its fixed AF_UNIX control socket only after local checks, then
native metadata clients only after authenticated observation permission.

Self-review checked exact host versus cgroup-namespace identity, FD accounting,
consume-before-validation replay refusal, bounded framing, manifest build-input
closure, five-process frozen-descendant accounting, terminal cgroup disappearance,
and continued lack of public production authority. Unit/loopback tests cover
malformed/duplicate/unknown/truncated/oversize wire data, exact config member and
public-only projection, permission restriction, trickling deadlines and startup
refusal. Live replay and protected-file/authenticated-peer checks remain unrun.

NOT_RUN: actual observer configuration/control read-only mounts, confinement and
self-checks; live host/worker SO_PEERCRED/executable exchange; actual Go syscall,
capability, LSM/seccomp/TUN needs and startup; fresh actual-daemon kernel metadata;
final minimal immutable image; ARM64 runtime; enrollment/approved identity;
provider/real-client traffic, watchdog/readiness/release staging. The probe cannot
certify these. Independent spec and quality review is required before8b2.
