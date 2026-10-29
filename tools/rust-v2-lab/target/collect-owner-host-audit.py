"""Bind non-vacuous held native host-audit witnesses to frozen source and bytes.

Read-only local collection. Native assertions execute in the owned VM oracle.
An actual root reap is distinct from full bundle drainage and cleanup authority.
"""
import datetime
import hashlib
import json
import math
import os
import pathlib
import re
import signal
import subprocess
import sys
import tarfile


candidate_path = pathlib.Path(sys.argv[1])
label = sys.argv[2]
assert re.fullmatch(r"[a-z0-9_-]+", label)
candidate = json.loads(candidate_path.read_text())
directory = candidate_path.parent / label
binding = json.loads((directory / "directory-binding.json").read_text())
controller = json.loads((directory / "controller.json").read_text())
record_path = pathlib.Path(controller["record"])
match = re.fullmatch(r"actual-program-run-(\d+)\.json", record_path.name)
assert match and pathlib.Path(binding["record"]).resolve() == record_path.resolve()
raw = record_path.read_bytes()
record = json.loads(raw)
assert controller["exit_code"] == record["exit_code"] == 0
mode = record["component_test_mode"]
cases = {
    "owner_host_audit": "actual_owner_route_only_host_audit_caps0_negative_stalled_a_original_deadline_b_healthy_owned_host_drift",
}
case = cases[mode]
pass_case = "actual_owner_route_only_host_audit_original_deadline_neighbor_and_owned_drift"
assert record["real_client_acceptance"] == "NOT_RUN" and record["production_changes"] is False
assert not any(record[key] for key in ("raw_syscall_metadata", "file_path_metadata", "stderr_diagnostic", "peer_credential_metadata"))
assert binding["new_directories"] == []
assert binding["source_commit"] == record["source_binding"]["source_commit"] == candidate["source_commit"]
assert binding["source_archive_sha256"] == record["source_archive_sha256"] == candidate["source_sha256"]
arch = {"debian-clean-x86_64": "amd64", "debian-x86_64": "amd64", "debian-arm64": "arm64", "arch-x86_64": "amd64"}[binding["platform"]]
assert binding["artifact_sha256"] == record["artifact_sha256"] == candidate["platforms"][arch]["artifact_sha256"]
assert record["context_sha256"] == candidate["platforms"][arch]["context_sha256"]
source = pathlib.Path(candidate["source"])
assert hashlib.sha256(source.read_bytes()).hexdigest() == candidate["source_sha256"]
verified = json.loads(subprocess.check_output([sys.executable, "tools/verify-frozen-build-inputs.py", str(source), candidate["source_commit"]]))
assert verified == record["source_binding"] == candidate["binding"]
with tarfile.open(source) as archive:
    assert archive.extractfile("crates/vprouter-launch/src/owned.rs").read().count(case.encode()) == 1
    flag = "--ignored-" + mode.replace("_", "-")
    assert ('"' + flag + '"').encode() in archive.extractfile("crates/vprouter-launch/src/actual_lab_main.rs").read()
raw_events = []
for line in record["stdout"].splitlines():
    try:
        value = json.loads(line)
    except ValueError:
        continue
    if "case" in value or "trace_directory" in value:
        raw_events.append(value)
assert raw_events == controller["runtime_events"] and len(raw_events) == 3
shared = "actual_two_member_shared_parent_host_authority_native_producer_link_quarantine_bootstrap_and_neighbor_reaudit"
assert [value for value in raw_events if value.get("result") == "pass"] == [
    {"case": shared, "result": "pass"}, {"case": pass_case, "result": "pass"},
]
witnesses = [value for value in raw_events if value.get("case") == case and "result" not in value]
assert len(witnesses) == 1
witness = witnesses[0]

def integer(key):
    value = witness[key]
    assert type(value) is int and value > 1, key
    return value

def finite(key):
    value = witness[key]
    assert type(value) in (int, float) and math.isfinite(value) and value > 0, key
    return value

assert witness["component_only"] is True and witness["ready_or_provider_acceptance"] is False
held_pid = integer("held_audit_pid")
integer("held_audit_start")
guard_a, guard_b = integer("guard_a_pid"), integer("guard_b_pid")
assert len({held_pid, guard_a, guard_b}) == 3
integer("guard_a_start")
integer("guard_b_start")
deadline, terminal, drift = finite("original_deadline"), finite("a_terminal_at"), finite("drift_at")
assert deadline <= terminal <= deadline + 0.5 and drift >= terminal
at_terminal, before_drift = integer("b_audits_at_a_terminal"), integer("b_audits_before_drift")
assert before_drift >= at_terminal + 2
reaps = []
for line in record["stderr"].splitlines():
    parsed = re.fullmatch(r"LAB_HOST_AUDIT_CHILD status=(\d+) killed=(true|false) deadline=([0-9.]+)", line)
    if parsed and float(parsed[3]) == deadline:
        reaps.append((int(parsed[1]), parsed[2]))
assert reaps == [(signal.SIGKILL, "true")], reaps
assert "forbidden_route_mutation=EPERM" in record["stderr"]
with tarfile.open(source) as archive:
    code = archive.extractfile("crates/vprouter-launch/src/owned.rs").read()
    assert b"while !deployment.lab_host_drained(0)" in code
    assert b"|| !deployment.lab_host_drained(1)" in code
    assert b"&& deployment.lab_host_drained(0)" in code

output = dict(
    observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    record=str(record_path), record_sha256=hashlib.sha256(raw).hexdigest(),
    source_commit=candidate["source_commit"], source_archive_sha256=candidate["source_sha256"],
    artifact_sha256=record["artifact_sha256"], context_sha256=record["context_sha256"],
    platform=binding["platform"], witness=witness, original_held_child_actual_wait_status=signal.SIGKILL,
    original_deadline_error_detected_after_seconds=terminal-deadline,
    held_native_job_and_both_host_services_collected_in_source_bound_fixture=True,
    real_client_acceptance="NOT_RUN", production_changes=False,
    limit="Active held HostAudit and sibling progress component only; no whole-member retirement or operational/provider/client acceptance",
)
destination = pathlib.Path("target/lab-state/owner-host-audit-run-" + match[1] + ".json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps(dict(witness=str(destination), platform=binding["platform"],
                     source_commit=candidate["source_commit"], held_actual_wait_status=signal.SIGKILL,
                     original_deadline_late_ms=(terminal-deadline)*1000,
                     b_audits_at_terminal=at_terminal, b_audits_before_drift=before_drift,
                     real_client_acceptance="NOT_RUN")))
