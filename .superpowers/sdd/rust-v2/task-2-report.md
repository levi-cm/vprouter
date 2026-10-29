# Task 2 report — offline Rust core

Status: IMPLEMENTED; focused checks PASS; independent review pending. Offline
foundation only. No runtime/release/client/migration acceptance claim.

Review base: b9eaae7 (root's committed implementation/acceptance documents).
Commit: e18191a034a614cf9dc1bcd1d11faca87dbd84a7
Subject: feat: add strict offline Rust router core

## Scope delivered

- Rust 2024 workspace, pinned installed 1.97.0 minimal toolchain with fmt/clippy;
  exact serde/serde_json/rustix dependency declarations and tracked resolved lock.
- vprouter-core config/profile/state/allocation/reason modules; core forbids
  unsafe and has no shell or process execution.
- Strict bounded serde configuration, nested deny-unknown mode objects, explicit
  direct selection, absolute lexical paths, disabled ID/state/key/name
  reservation, private-key duplicate rejection, safe authored error codes.
- Exact display-name rules with suffixes for all duplicates; state/resource
  identity derived from stable deployment + exit ID rather than display/order.
- Strict bounded WireGuard parsing and descriptor-relative no-symlink profile
  reads. Explicit expected server required. Real zero-padded server IDs accepted.
  Device/Name comments do not claim server identity.
- Health machine implements STARTING/BLOCKED/RECOVERING/READY/STOPPING/FAILED,
  three distinct successful fresh observations before recovery, subsequent
  approved exact node/server/online/egress evidence for READY, immediate failure
  blocking, explicit stopped reconfiguration, finite monotonic time validation,
  independent DNS/IPv6 not_tested, cached handshake aging and stale status refusal.
- Stable scoped interface/namespace/nft resources, /30 transport reservations,
  foreign/internal conflict rejection and configuration compatibility checks.
- Descriptor-relative root-owned 0700 directory + 0600 regular singly-linked
  files; safe nonblocking flock; generation CAS; exclusive temporary creation,
  write/fsync/rename/parent-fsync, retained unknown/incomplete temporary files.
  Current-user temp-root construction is restricted to cfg(test).
- Detailed reference plus one/five/mixed schema examples with synthetic keys
  and clearly identified digest placeholders. No actual credentials copied.
- target/ and .superpowers/ excluded from Docker build contexts and Git.

Legacy Python source and runtime files were not edited. No live namespace,
firewall, Docker, service, routing, provider or network configuration mutation.
Other root-owned evidence documents were left untracked and unmodified.

## Verification

All run from /DATA/AppData/vprouter-rust-v2 on pinned Rust 1.97.0, offline:

- cargo fmt --all -- --check: PASS
- cargo check --offline --all-targets: PASS
- cargo test --offline --all-targets: PASS, 32 tests, 0 failures
- cargo clippy --offline --all-targets -- -D warnings: PASS
- git diff --check: PASS

Test breakdown: 7 filesystem/concurrency unit tests; 4 allocation contract tests;
13 configuration/profile tests; 1 injected synthetic one/five/mixed-fleet test;
7 health state/evidence tests. Behavioral red/green runs observed for initial
configuration/profile, health and allocation/storage contracts, malformed image
repository grammar, broadcast tunnel addresses, zero-padded servers, ambiguous
device-name comments, changed storage permissions and aging cached handshakes.

Security-relevant exercised cases include real independent-open concurrent flock
exclusion; two simultaneous writers competing for one generation; stale/skipped
CAS; incomplete orphan temp surviving further commits; symlink components,
lock/record substitution, hardlinks, wrong permissions and malformed committed
records; actual finite-pool collision; unknown/duplicate/mixed-mode schemas;
disabled duplicate private keys/states/IDs; adapter bounds/references; timestamp
180s/45s boundaries, replay, future/negative/NaN/infinite times, wrong server,
missing node/egress/verification, negative DNS/IPv6 checks and failed-state gates.

## Remaining limits and concerns

1. Profile metadata/filename matching is not cryptographic server authentication;
   generic filenames are accepted only with the explicit pin. Runtime catalog,
   provider, exact live server, account and endpoint checks remain required.
2. Core profile reads reject symlinks but production protected-file owner/mode,
   enrollment-key loading and broader host ownership checks belong to Linux
   work package 3. This is not reported as protected-file ownership proof.
3. The fixed 10.200.0.0/14 pool uses stable allocation hashing. Collisions fail
   closed; no silent reassignment. Host resource/subnet claims must be supplied
   and rechecked by runtime code before activation; this offline library cannot
   discover live resource ownership.
4. Storage tests use actual syscalls and concurrent threads with independent
   opens, not destructive power-loss/full-disk/fsync fault injection. A failure
   after rename/at parent fsync returns DurabilityUncertain for reinspection.
5. Adapter declarations are validated, not executed or proven idempotent.
   Stable node IDs and protection evidence still require actual runtime proofs.
6. No namespace/firewall/client tests, performance measurements, multi-platform
   builds, live migration, container activation or release acceptance performed.
   All corresponding IMPLEMENTATION.md gates remain pending.

Commit identity was supplied per command from the existing repository author;
no global/local Git identity configuration was changed. Initial plain commit
failed solely because this shell lacked configured identity; the authorized
commit then succeeded with the existing opsec identity.

## Round 1 independent review fixes

Status: all three Important findings fixed; repeat independent review pending.
Follow-up commit: 40449d519a2572643523945ded1ed4b880ba6cd0
Subject: fix: close offline core review concurrency and identity gaps

1. Same-transaction generation races: `AllocationTransaction::commit` now
   requires `&mut self`. A shared transaction reference cannot issue simultaneous
   commits even though reads remain shareable. Added a compile-fail scoped-thread
   test that compiled successfully against the former `&self` API (observed red)
   and fails compilation with the fixed API. Added a real two-thread shared
   transaction test through Mutex: simultaneous candidates for generation 1
   yield exactly one success and one GenerationConflict, and the committed
   record is the successful candidate's payload. Independent-open flock/CAS
   regressions still pass.
2. Equivalent X25519 identities: private-key duplicate comparison now normalizes
   the ignored/clamped scalar bits (low three bits of byte 0; top two bits of
   byte 31 as specified by X25519) inside the crate. No public secret accessor,
   secret Debug/Serialize, key or digest reporting was added. The regression
   compares synthetic `[1;32]` with first-byte-zero/rest-one, high-bit variations
   and the forced-bit variation, for enabled and disabled second exits. The
   first variant previously admitted duplicate effective identity (observed red)
   and all variants now report the fixed DuplicatePrivateKey code.
3. Cached evidence/streak expiration: before processing an incoming observation,
   the machine checks the previously cached evidence at the new time and blocks/
   resets any expired success streak or READY state. Status queries remain
   strictly observational. Long-gap regressions cover STARTING, BLOCKED,
   RECOVERING and READY, including READY at 115, stale status at 160 and a new
   observation at 161. Each requires three new fresh checks, then a subsequent
   approved observation for READY. Additional tests cover cached handshake expiry
   in all four states while other evidence remains fresh. Both long-gap and
   handshake scenarios now reset rather than borrowing the previous streak.

Fresh post-fix verification on Rust 1.97.0:

- cargo fmt --all -- --check: PASS
- cargo check --offline --all-targets: PASS
- cargo test --offline --all-targets: PASS, 36 runtime tests, 0 failures
- cargo test --offline --doc: PASS, 1 compile-fail safety test
- cargo clippy --offline --all-targets -- -D warnings: PASS
- git diff --check: PASS

No runtime, service, namespace, firewall, network or real credential changes.
The original runtime/release/ownership/platform acceptance limits remain open.
