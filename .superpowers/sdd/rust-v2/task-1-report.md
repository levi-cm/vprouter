# Task 1 report — baseline and compatibility fixtures

Status: COMPLETE for the bounded baseline/fixture work package; mandatory
runtime/performance/migration/release acceptance is NOT_RUN and remains blocked.

## Deliverables

- `docs/rust-v2/baseline.md`: full verified source/runtime inventory, legacy
  CLI/health contracts, retry/monitor semantics, hook/dependency and rollback
  limitations, scoped resource observations and explicit acceptance gaps.
- `docs/rust-v2/baseline-source-inventory.json`: fresh eight-file SHA-256
  source/release equality inventory at base `84fb353`.
- `docs/rust-v2/baseline-resource-sample.json`: 21 read-only snapshots across
  20.0001s of the existing live host Python/router/uplink cgroups.
- `tests/fixtures/legacy/`: synthetic site/profile/validate/status/health/probe
  documents, with clearly fake 32-byte keys and dedicated provenance README.
- `tools/baseline-resource-sample.py`: read-only selected metadata/cgroup/PSS
  sampler; no argv/env/config collection.
- `tools/baseline-verify-fixtures.py`: four offline compatibility checks.

## Evidence and tests

Fresh GitHub ls-remote confirms fork/main `e135adacd33501422fb24ba3ef2bce8693956557`.
Base is `84fb353b128c0b6f7ca222be9cd3934183a4e34a`, retaining local repair
`528feced48f14fd46d48da0abdd64a2587e42b4f`. Runtime source hashes all match.
Unit remains active/running, no attached drop-ins, zero restarts. Containers
remain running with zero restarts and OOM false. Tailscale version command
reports `1.102.5`. Both live containers use image
`sha256:62c283e6a4d350992ed2b9a99a48c7834e60e1c9af92f9e1699a2b2d0c920de3`.

`python3 -m unittest discover -s tests -q`: 50 tests passed.
`python3 tools/baseline-verify-fixtures.py -q`: 4 tests passed.
JSON parsing/AST parsing and `git diff --check` are run before commit.

Observed sample CPU: host 3.8764%, router 1.8596%, uplink 0% of one core.
Mean PSS: 11,020 / 92,871.6 / 430 KiB respectively. Existing traffic is
uncontrolled; shared infrastructure overhead and throughput/latency are not
accounted. Repeated 10-minute same-workload acceptance remains NOT_RUN.

## Concerns and limits

1. Legacy host status can quarantine on drift, so it was not invoked. Current
   client egress/protection is not newly established by this task.
2. Collector hooks target a different installation and are disabled for this
   unit. Unknown external dependencies remain undeclared and block unattended
   migration/rename until explicit adapters and ownership evidence exist.
3. Global bridge/subnet/table names and name/label-only cleanup cannot be
   reused as multi-exit allocation or namespace/cgroup ownership proof.
4. Retained rollback directories/tag exist; backup contents/restore compatibility
   were not inspected or tested. Existing manual rollback is not transactional
   v2 release+state rollback with interrupted migration recovery.
5. Synthetic fixtures/mocked observations do not prove runtime behavior. No
   destructive/live fault tests, production mutations, secret collection or
   upstream publish occurred. No service, config, profile or identity changed.

Commit: this report is included in the baseline package commit; use
`git log -1 --format=%H -- docs/rust-v2/baseline.md` for its immutable ID.
