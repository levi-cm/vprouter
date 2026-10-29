# Task 3 report — native read-only host/CLI/migration preparation

Status: IMPLEMENTED; focused checks PASS; independent review pending. This
implements observational preparation only, not packages 3/9 guard or apply
runtime completion and not release or real-client acceptance.

Code base: 40449d519a2572643523945ded1ed4b880ba6cd0. Root's evidence-only
f2316d3 landed while this package was being prepared; its files were untouched.
Commit: 2b259c5e58ae5d4e28df48ca081de2df1ab6fa1b
Subject: feat: add native read-only host inspection and migration plans

## Delivered

- `vprouter-linux` and `vprouter` workspace members with pinned direct
  dependencies and resolved Cargo.lock. Both crates forbid unsafe code. Host
  implementation uses files, safe rustix, Tokio Unix sockets and Hyper; it has
  no shell/process launcher, Docker exec, daemon mutation or allocation-store
  open/lock. Production paths are fixed and ownership has no CLI bypass.
- Descriptor-relative no-symlink path checking from `/`; root owner, type,
  group/other write, special-bit and hardlink checks; keys no broader than 0600;
  state/health directories no broader than 0700. Explicit plan output uses
  create-new 0600, file fsync and parent fsync, without overwrite/parent creation.
- Observational preflight: Linux 6.1+, x86_64/aarch64, Debian13/systemd,
  Arch/CachyOS/systemd, Void-glibc/runit, cgroup2 filesystem, TUN char device
  10:200, protected release/profile/state/enrollment metadata, Docker compatibility.
  Active nftables/WireGuard probes and native guard ownership/liveness remain
  NOT_TESTED. Unknown checks prevent host support/readiness confirmation.
- Bounded GET-only Docker API: `/run/docker.sock` avoids the normal `/var/run`
  symlink; trusted root parents and root socket are checked (normal socket/device
  access modes are accepted). Engine >=26.0 and API1.45 compatibility negotiation;
  explicit versioned inventory; Hyper HTTP/chunked parsing; 1MiB body, 16KiB HTTP
  receive buffer, 3-second stage and 9-second overall deadlines; full inventory
  bounded to 128 containers and 9 seconds. Selective projection excludes Env,
  raw Config/State, external errors and foreign label values.
- Strict cached snapshot envelope binds deployment, exit, mode, display, expected
  server, canonical config fingerprint, boot ID and config-declared node ID.
  Core evidence validation handles freshness/handshake/server/node checks.
  Snapshot validity/age is separate from runtime state; enabled exits always
  remain NOT_TESTED, guard_runtime:false and activation_ready:false. Direct
  always reports direct-exposed; disabled exits are explicit. No provider, DNS,
  IPv6, egress or node success is invented from legacy health.
- Clap exposes only validate, status, probe, migrate inspect/plan and diagnose.
  Invalid arguments/errors are authored JSON without argv/raw error contents;
  help/version remain requested text. Validate performs observational preflight
  and fails for observed failed checks; unknowns remain explicit. Incomplete
  status/diagnose/plans and inspections return2. Capabilities list exact missing
  commands and guard_runtime:false. Diagnose contains sanitized statuses and a
  NOT_RUN acceptance manifest, without environment/config/journal dumps.
- Strict legacy schema and metadata-only identity inspection; no Tailscale
  state reads. Bounded current/history/compose release hashes, known unit and
  drop-in hashes, safe collector file declaration and typed Docker primary,
  uplink and NetworkMode-dependent metadata. Unknown ownership and dependencies
  remain explicit rather than inferred from names.
- Strict deterministic review-plan DTOs preserve profile/state/image and legacy
  container/service names. Stable internal exit ID is `primary`, as clarified
  by root: legacy has no existing internal exit ID. Old and new hostnames are
  separate; core validates proposed naming/profile pin. Profile restriction hashes
  public configuration only, never opaque secret bytes. Plans include source
  config hash, file metadata, actual compose/current/history release hashes,
  units/hooks/collector declarations, observed container ID/PID/start time,
  ordered quarantine/adapter/backup/activation/acceptance/rollback requirements,
  blockers and canonical content SHA-256. Every plan is non-applicable and
  verification incomplete; no identity is copied and no direct exit is added.
- `docs/rust-v2/agent-guide.md` documents exact offline commands, exit semantics,
  snapshot format, ownership checks, review limitations and missing operations.
  It contains no fictional apply/deploy/rollback procedure.

## Fresh verification

On pinned Rust1.97.0 from `/DATA/AppData/vprouter-rust-v2`:

- cargo fmt --all -- --check: PASS
- cargo test --locked --offline --all-targets: PASS, 54 runtime tests, 0 failures
  (36 existing core, 15 native host/migration/storage/Docker/status, 3 CLI).
- cargo test --locked --offline --doc: PASS, 1 existing compile-fail safety test.
- cargo clippy --locked --offline --all-targets -- -D warnings: PASS
- cargo build --locked --offline --release -p vprouter: PASS
- git diff --check and staged diff --check: PASS

Meaningful added coverage: temporary ownership/mode/type/hardlink/symlink paths,
bounded reads, exclusive private output and refusal of replacement; native mock
Docker Unix servers for chunked framing, HTTP/body caps, malformed JSON/protocol,
403, redirect refusal, header/body deadlines, actual Docker version field casing,
API compatibility and GET-only versioned inspection; environment/foreign-label
redaction; unsupported platform fixtures; strict legacy/candidate path retention;
deterministic/tamper-detecting strict plan hashes; private-key changes leaving the
public-only profile fingerprint unchanged; stale/mismatched snapshot fields,
wrong node/policy, missing health and disabled direct exposure; CLI invalid argv
and fake-secret invalid input redaction plus implemented-only help.

Initial verification caught a public-file fixture created group-writable under
the current umask; the implementation correctly rejected it and the fixture was
corrected to0644. Compiler/Clippy issues were fixed before the final full run.
No behavioral red/green history beyond these observed failures is claimed.
Python tests were not run because no legacy source changed.

## Required gates still unimplemented / concerns

1. No guard, namespace/netlink/nft quarantine, worker, launcher, client guard,
   mutating lifecycle, service installer or migration apply/resume/rollback.
   No host support or runtime READY is claimed from this package.
2. Active kernel feature usability, owned-resource/liveness proof, exact native
   runtime identity/server/provider evidence, client coverage and acceptance
   must be established separately in the isolated lab. A cached snapshot is
   insufficient. Config-declared node binding is required to validate a cache.
3. Legacy ownership cannot be proven by names/metadata. Bounded release/unit/
   drop-in/collector inventories are preparation, not a complete dependency
   discovery mechanism. Missing vendor-unit locations, unknown hooks/collector
   fields, unsupported paths or truncated inventories remain gaps and blockers.
4. Plan fingerprint is deterministic serialization integrity, not a signature or
   semantic authorization. Metadata/public profile binding intentionally does
   not provide an offline private-key fingerprint. Exact identity and compatible
   release+state rollback still need runtime review and independent acceptance.
5. Tests use synthetic profile fixtures, temp files and mock Docker only. No
   real credential/profile reads, service/container/identity/state mutations,
   live Docker/API probes, isolated-client changes or root evidence edits were
   performed by this package. Root's separate client enrollment and KVM lab
   work were not used as native acceptance evidence.
6. Single/five/direct/mixed real-client captures, complete fault matrix,
   reboot/boot capture, 24h soak, performance, second host, independent launcher
   review, ARM64 artifact builds and immutable artifacts/SBOM/provenance remain
   NOT_RUN. Independent review of this package is pending.

Only the 13 explicit owned code/manifest/lock/guide paths were committed. This
report follows the existing ignored `.superpowers` report convention and is
available in the shared worktree; unrelated root evidence was not staged.

## Round 1 independent review fixes

Status: Important and Minor findings fixed; repeat independent review pending.
Commit: ab6a5973a412e5d3a0edc6bf503369490c8a5430
Subject: fix: keep Void host libc verification independent of build target

Important — compiler target was not host-libc evidence. Removed the production
`cfg!(target_env = "gnu")` inference. Distribution/manager recognition is now
separate from the Void-only tri-state host-glibc prerequisite. This package has
no reliable native host-libc probe, so production supplies unknown evidence and
emits `void_host_glibc` with state `NOT_TESTED`. Void host support cannot be
confirmed without that proof; neither a GNU nor a musl static binary guesses
the host libc or produces a false pass/fail from its compiler target. No shell,
unsafe runtime libc calls or speculative filesystem heuristic was added. The
new fixture matrix varies GNU-static/musl binary labels independently from
observed glibc, observed non-glibc and unknown host evidence. These are fixture
checks, not cross-compilation or execution of actual static artifacts.

Minor — existing `/tmp` CLI test only covered unsafe-path redaction. Its
assertion now explicitly checks `unsafe_path`. Extracted the unchanged production
configuration byte parsing/error mapping into `parse_configuration`, which the
protected file loader calls after its existing ownership checks. The added CLI
integration test passes malformed fake-secret-bearing bytes through that same
parser and the production failure JSON formatter, asserts `invalid_configuration`
and proves the secret and source key field are omitted. Referenced profiles
still use secure native reads; no ownership bypass or CLI flag was introduced.

Fresh verification on Rust1.97.0, from the repository root:

- cargo test --locked --offline -p vprouter-linux
  void_host_libc_is_unknown_without_observation_regardless_of_build_target:
  PASS, 1 focused test, 15 filtered out.
- cargo test --locked --offline -p vprouter --test cli
  malformed_config_content_uses_production_error_mapping_and_redacts_secrets:
  PASS, 1 focused test, 3 filtered out.
- cargo fmt --all -- --check: PASS, exit0.
- cargo test --locked --offline --all-targets: PASS, 56 runtime tests, 0 failures
  (36 existing core +16 Linux +4 CLI).
- cargo clippy --locked --offline --all-targets -- -D warnings: PASS, exit0.
- git diff --check and git diff --cached --check: PASS, exit0.

No additional broad checks followed these passing covering checks. The original
doctest/release-build evidence remains associated with the initial package;
release artifacts were not rebuilt in this fix wave. No real credentials,
service/container/state/client/lab changes or root evidence edits occurred.
All cross-task runtime, migration/apply, host-libc probe and acceptance/artifact
gates remain unimplemented or NOT_TESTED/NOT_RUN as applicable. Only the four
explicit host/parser/test/guide files were committed, and tracked status is clean.
