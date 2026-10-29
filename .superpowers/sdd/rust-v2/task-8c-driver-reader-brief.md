# Optional closed driver diagnostic reader

2026-10-29. Proposal; Root dispatch only after the driver-cost plan is independently
approved. Read task-8c-driver-cost-brief.md for the exact fifteen-row contract.
All source/runtime semantics and privileged actions remain outside this task.

Own only tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py and its bounded
README description. No Rust/app-input, controller, dependency, raw evidence,
acceptance or existing output-byte rewrite. No subagents/Git/native/VM/profile
or resource operations. Preserve all required13+30 and optional24+15 constraints.

Add optional exact13 CPU rows, one sleep row and one constructor row, as one
all-or-none fifteen-row extension. Reject every malformed occurrence, partial,
duplicate/reordered/foreign helper/table/field, wrong measurement/grouping,
noncanonical/negative/overflow/nonfinite value, including marker text that would
otherwise silently look absent. Validate exact closed labels/fields/order from
the approved driver brief. Use u64 counts/u128 durations, constructor counts0/1
with sum<=1, zero duration when no valid sample. CPU sample completeness is
saturating(samples+sample_errors)==calls, and CPU calls must match the corresponding
old wrapper calls. Do not require CPU<=wall or derive off-CPU/subtractions.
Sleep requested_ns must equal calls*1000000 before u64-call saturation; if calls
is u64max, allow independently accumulated requested_ns>=calls*1000000. No
elapsed/requested threshold. All fifteen rows must appear in their required
relative order. Extension absence retains byte-identical historical output.

Only when present append driver_cpu, driver_sleep, driver_constructor and a
bounded fixed driver_scope explanation. Preserve the existing scope string and
all prior serialization/key-order bytes when absent. Explain CPU is parent-thread
bracketing CPU, excludes children and does not identify scheduling; wall spans
differ and clocks/observer/sampling failures limit inference. CPU/wall attribution
is allowed only for complete unsaturated helper rows; incomplete/saturated rows
remain unattributable. Keep failed run
requirements/exclusive output0600 and destination preservation unchanged.

Before edits freeze parser SHA and all203 current build inputs. Prove all inputs
unchanged after reader work. Retain private checks under target/task8c-driver-reader-local,
never publish synthesized raw records. Verify byte-identical old405/407/408 outputs
against retained closed metadata. Add meaningful synthetic valid complete,
zero/unavailable/mixed CPU, saturation, prefix missing/error/success and malformed
refusal cases; verify exclusive-existing-destination bytes/mode preservation.
Include partial/reordered tables, malformed marker occurrences, invalid count
completeness/cross-wrapper counts, invalid unavailable duration, sleep relation
and constructor count constraints among refusals. No runtime or timing claim.

Freeze diff/full evidence-hash manifest/check logs, parser+README hashes and report
.superpowers/sdd/rust-v2/task-8c-driver-reader-report.md. Report exact checks,
meaningful failures and limits; no benchmark or application acceptance. Root owns
independent source/quality/sensitivity review, checkpoint/push and all subsequent
native use. No dispatch is conferred by this proposal itself.
