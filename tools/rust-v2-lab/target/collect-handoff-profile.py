"""Bind a native owner run's bounded handoff profile to its payload.

Nested RPC spans are inclusive. Only the five top-level verification phases are
summed; no microbenchmark or bootstrap margin is general router acceptance.
"""
import datetime
import hashlib
import json
import pathlib
import re
import sys

candidate_path = pathlib.Path(sys.argv[1])
run = int(sys.argv[2])
assert run > 0
assert sys.argv[3:] in ([], ["--failed-original-deadline"])
failed_deadline = bool(sys.argv[3:])
candidate = json.loads(candidate_path.read_text())
path = pathlib.Path(f"target/lab-state/actual-program-run-{run}.json")
raw = path.read_bytes()
record = json.loads(raw)
assert record["component_test_mode"] == "owner_process_inspection"
if failed_deadline:
    assert record["exit_code"] != 0
    assert record["stderr"].splitlines().count("LAB_OWNED_GUARD_FAILURE phase=before_retained_drain reason=deadline") == 1
else:
    assert record["exit_code"] == 0
assert record["source_binding"]["source_commit"] == candidate["source_commit"]
assert record["source_archive_sha256"] == candidate["source_sha256"]
assert record["artifact_sha256"] in {v["artifact_sha256"] for v in candidate["platforms"].values()}
pattern = re.compile(r"^LAB_HANDOFF_PROFILE phase=(\w+) sequence=(\d+) elapsed_us=(\d+) ok=(true|false) original_remaining_us=(\d+)$")
rows = []
summary = []
handoff = []
for line in record["stderr"].splitlines():
    match = pattern.fullmatch(line)
    if match:
        rows.append({"phase": match[1], "sequence": int(match[2]), "elapsed_us": int(match[3]),
                     "ok": match[4] == "true", "enclosing_original_remaining_us": int(match[5])})
    elif line.startswith("LAB_HANDOFF_PROFILE phase=summary "):
        summary.append(line)
    elif line.startswith("LAB_HANDOFF_PHASE "):
        handoff.append(line)
assert 0 < len(rows) <= 63 and all(v["ok"] for v in rows)
assert len(summary) == 1
match = re.fullmatch(r"LAB_HANDOFF_PROFILE phase=summary events=(\d+) omitted=(\d+) original_remaining_us=(\d+)", summary[0])
assert match and int(match[1]) == len(rows) and int(match[2]) == 0
if failed_deadline:
    assert int(match[3]) == 0 and len(rows) == 23
    assert any(re.fullmatch(r"LAB_HANDOFF_PHASE phase=full_permission_verification milliseconds=\d+ original_remaining_ms=0 verification_ok=true", line) for line in handoff)
phases = ("handoff_base", "daemon_before_audit", "host_and_native_shape", "daemon_after_audit", "sender_verify")
top = {}
for phase in phases:
    values = [v["elapsed_us"] for v in rows if v["phase"] == phase]
    assert len(values) == 1
    top[phase] = values[0]
output = {
    "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "record": str(path), "record_sha256": hashlib.sha256(raw).hexdigest(),
    "source_binding": record["source_binding"], "artifact_sha256": record["artifact_sha256"],
    "native_run_exit_code": record["exit_code"], "original_deadline_failed": failed_deadline,
    "wall_seconds": record["wall_seconds"], "disjoint_full_permission_phases_us": top,
    "disjoint_sum_us": sum(top.values()), "profile_rows": rows,
    "summary": summary[0], "observed_final_remaining_us": int(match[3]),
    "handoff_diagnostics": handoff, "stderr_bytes": len(record["stderr"].encode()),
    "limit": "observed single-run margin only; nested RPC spans inclusive; unchanged two-second handoff contract; no router performance acceptance",
    "real_client_acceptance": "NOT_RUN",
}
prefix = "handoff-profile-failed-run-" if failed_deadline else "handoff-profile-run-"
destination = pathlib.Path(f"target/lab-state/{prefix}{run}.json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps({"sidecar": str(destination), "source_commit": candidate["source_commit"],
                  "disjoint_sum_us": sum(top.values()), "observed_final_remaining_us": int(match[3]),
                  "handoff_diagnostics": handoff}, indent=2))
