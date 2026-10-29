# Task 8b2 recovery and publication audit — 2026-10-29

Read-only recovery by the scope auditor; Root owns all VM execution and Git
publication. No VM, production, identity, profile, service or enrollment action
was performed. Only this report was created. Existing source, failed evidence,
HEAD and index were preserved during this audit.

## Recovered result

The old implementation agent is unnecessary for recovering the source and
evidence. `task-8b2-report.md` stops at candidate12 and was never reconciled with
the later successful continuation. No separate candidate13 completion report
was found in the inspected task reports. Do not infer overall task/release
approval from a historical candidate label.

The original final source is
`target/continuation-20261026T104832Z/candidate.json`, commit
`1b0d7e723f51c54e0c2d624f2fb15a8d32b6fdaa`. The original report
`docs/rust-v2/testing-2026-10-26.md` correctly records 185 ordinary tests,
actual-program runs20/21/22 passing10 cases, and seven transport scenarios.
It correctly marked post-pin drift NOT_RUN **at that checkpoint**.

That drift gap was subsequently implemented and passed. The corrected milestone
is `target/continuation-20261026T122321Z/candidate.json`, source
`899a874ac70b1710b23d766d498f5068297a5657`. Raw run24 has exit0 and four
individual passing post-pin cases. Its record SHA256 is
`2e7d7a6d9e7accce9d96af749c4bbfdc044b5d6660e4d65acf5cf892285490a2`.
The complete explanatory report is
`.superpowers/sdd/implementation-2026-10-26/task-1-report.md`; the later
`progress.md` in that directory continues the history.

Current `crates/vprouter-launch/src/actual_lab.rs:516` injects real mutations
after the actual Go daemon and Rust observer have run:

- TUN MTU1280→1400.
- TUN address100.64.99.9/32.
- Route8.8.8.8/32 through tailscale0 in table52.
- Rule preference4900 lookup52.

Each fault requires native verification refusal, exact Offline policy inspection
**before repair**, refusal by the old token after repair, then an independently
verified fresh pin under Offline policy. Repair never restores the old token.
These are component tests, not operational/client acceptance.

Fresh recorded repetitions include Debian45 and Arch46 on66d8f676, ARM53 on
59c61e2, Debian362 and Arch363 onbdc3f32, and most recently Debian381 and Arch386
on4bdd241. Each of these raw records contains all four passing drift labels.
The last two are indexed in
`target/continuation-20261028T044917Z/{amd64-clean-4bdd241-regression,arch-4bdd241-regression}/`.
Their capture aggregates each record six captures,112 packet records, zero
forbidden markers and zero kernel drops; real-client acceptance remains NOT_RUN.

## Exact frozen candidates and current source

All three snapshot commits share the real parent
`c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a`; they are alternate-index snapshots,
not consecutive commits on the protected branch. Do not use ancestry alone to
infer their cumulative contents.

Original1b0d7e source/archive and both payload SHA256 values were rechecked and
match candidate.json. Its candidate references mutable gateway-context paths;
neither candidate-local context copy exists. The exact original AMD64 context
is retained at
`target/lab-state/task8b2-efcd7c4f944dec3b18cb95262649189073b83291a1298b18b1acba930a649ac3.context.tar`
and its digest was rechecked. The corresponding content-addressed ARM context
was not found at the analogous lab-state path. Do not substitute current context
bytes for this historical source.

Latest frozen source:
`target/continuation-20261028T080736Z/candidate.json`, commit
`90a7dcc756f073cccd3a1c34959676f001eb7601`,195 verified inputs. The following
candidate-local bytes were independently rehashed and match candidate.json:

| File | SHA256 |
|---|---|
| source.tar | efbf8fd12c7a521cd7ba83544ceb99185dca5e0a7d9c737b702647cc1756e373 |
| amd64.payload | f7ddba302b8d49d4d6ca64dfd39742427636992b13ff30089e8b538a4f33b36d |
| arm64.payload | 817c5a92e39676864ea6bcb0fd7b716bb72aaacd7b99f48692e5e7392c97779f |
| amd64.context.tar | 67d05621a8e5efbdaddfd53d0deaadb1bf5e84707b705a42b2552818764d1d46 |
| arm64.context.tar | fa442564fec9cbf28d03597656f433bb94d5a4c03a014f1e49070aa649d7080b |

The frozen90 source contains all four live drift cases and the immediate Offline
assertion. Current actual_lab.rs is byte-identical to its frozen copy. Current
actual_lab_main.rs differs because later operational-bootstrap work has been
added. A new publication checkpoint therefore must distinguish current WIP from
the exact90 runtime binding.

At the auditor's read, real HEAD remainedc6a138c and index SHA256 remained
`59f3aec05fa66f161482e5705f1a3c50c68c528980a51b5da4a869a510a24692`.
Root's later authorized checkpoint commit intentionally changes that Git state;
this statement describes the prepublication audit boundary.

## Root-only executable entrypoints

The actual payload CLI is the fixed `--ignored` mode, dispatched by
`crates/vprouter-launch/src/actual_lab_main.rs`. Do not execute it on the host.
The current controller wrapper is
`target/platform-lab/run-frozen-platform-actual.py`:

```text
python3 target/platform-lab/run-frozen-platform-actual.py \
  target/continuation-20261028T080736Z/candidate.json \
  debian-clean-x86_64 UNIQUE_NEW_LABEL actual
```

Root may instead select `debian-x86_64` for the retained Debian lab. The clean
platform dispatches to `run-actual-monitor-debian-clean-x86_64.py`; retained
Debian dispatches to `tools/actual-program-oracle.py`. The wrapper uses the
candidate-local immutable context and binds the newly created task8b2 directory.
It must use a previously nonexistent label and exact checked bytes. It performs
SSH/privileged fixture operations and is not an offline verifier.

The actual runner performs hash and frozen-input checks before execution, then
verifies public-only four-role context contents and native host-namespace
admission. Its protected disposable fixture requires isolated-acceptance0700/
0600 ownership checks. Its test includes exact fixture daemon/container terminal
behavior and temporary admission-file removal; no external cleanup script,
production state/profile/identity or enrollment is necessary or permitted.
Retain all new records and fixture resources. Independent capture collection
must bind the new exact directory; prior captures cannot certify a new source.

No task8b2 post-pin implementation delta is needed. The immediate useful delta
is durable report reconciliation and a current-source-specific regression, if
Root needs refreshed evidence. Later connected HOST/operational bootstrap work
is a separate continuation; original387 and394 failures/corrections must remain
preserved. Runtime/provider/client/migration/platform/performance/24h gates are
not closed by these component tests.

## Safe publication scope

User subsequently authorized saving all intentional v2 implementation progress,
including WIP, at milestones. Read-only configuration shows `fork` is
`https://github.com/levi-cm/vprouter.git`; `origin` is the upstream
`https://github.com/infinit1ve/vprouter.git`. rust/v2 has no upstream; the other
worktree owns main. Read-only `git ls-remote fork refs/heads/rust/v2 refs/heads/main`
found no rust/v2 branch and main at
`e135adacd33501422fb24ba3ef2bce8693956557`. Publish the preserved rust/v2
checkpoint to `fork` as `HEAD:refs/heads/rust/v2`; do not switch another worktree
or rewrite main. Root must repeat the remote check when actually pushing.

Before this report/archive creation, the intended regular Git status set was182
paths:160 crates paths,12 docs,7 tools,2 Cargo files and tracked historical
progress. Every path belongs to the user-authorized v2 work. Also include all
currently ignored Markdown briefs/reports/progress in these two directories:

```text
.superpowers/sdd/rust-v2/*.md
.superpowers/sdd/implementation-2026-10-26/*.md
```

That added31 previously ignored Markdown files, for213 intended paths before
this recovery report. Use an explicit path list and force-add only those ignored
Markdown paths. Preserve already tracked reports even if their historical status
is incomplete. Do not force-add .superpowers as a whole. Exclude its ignored
JSON/txt/private VM snapshots, baseline.patch, redundant .diff review packages,
and local .gitignore. Existing tracked evidence JSON files under docs/rust-v2
remain part of the public component report scope.

Audit of that213-path source/Markdown set: all are ordinary text, no symlinks,
NULs or files above2MB, approximately6.1MB total; `git diff --check` passes.
Private-PEM and common credential-token scans found none. Eight WireGuard key
literal matches were manually inspected: all are explicitly synthetic test
fixtures under cfg(test) or test modules. No actual profile or identity file
was opened for this audit.

Substantive controller/test implementations also exist outside Git. The exact
safe archive source list is the union of these **nonrecursive** globs:

```text
target/*.py                       151 files
target/platform-lab/*.py         134 files
```

These285 Python source files total3,093,943 bytes. All AST-parse successfully;
none are symlinks or contain NULs. Secret signature scans found no embedded PEM,
WireGuard key literal, GitHub/AWS/OpenAI/Tailscale auth token. Credential-word
matches were inspected: scripts read an existing public SSH key at runtime or
generate fresh synthetic WireGuard key material; no literal auth secret is
embedded. This is an audit of source bytes, never authorization to run scripts.

Root may archive these byte-for-byte under
`tools/rust-v2-lab/target/` and `tools/rust-v2-lab/target/platform-lab/`, saving
original-relative paths and SHA256 in a manifest. Include an archive README:
scripts generally expect original target paths and existing Root-owned disposable
VM fixtures; restore reviewed bytes to those paths before execution, and never
run an archived script just because it is present. Historical variants,
collectors, schema predicates, build/freezing drivers and failure inspectors are
all substantive recovery source, even when not the latest operational entrypoint.

Never recursively copy target. Exclude its credentials, known-host/state records,
profiles, enrollment metadata, VM evidence, source/payload/context archives,
images, captures, downloads and binary caches. The two exact Python source globs
are the approved audit boundary; any later added file needs its own scan.
