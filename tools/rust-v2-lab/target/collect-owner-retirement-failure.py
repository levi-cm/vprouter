"""Bind exact retirement failure and retention witnesses to frozen source and bytes.

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
    "owner_retirement_queued_failure": "actual_owner_retirement_queued_deadline_releases_only_own_slot_neighbor_mutation",
    "owner_retirement_writer_failure": "actual_owner_retirement_writer_poll_failure_actual_reap_retains_global_uncertainty",
}
case = cases[mode]
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
    {"case": shared, "result": "pass"}, {"case": case, "result": "pass"},
]
witnesses = [value for value in raw_events if value.get("case") == case and "result" not in value]
assert len(witnesses) == 1
witness = witnesses[0]

def integer(value, minimum=0):
    assert type(value) is int and value >= minimum
    return value

def finite(value):
    assert type(value) in (int, float) and math.isfinite(value) and value > 0
    return value

writer = mode == "owner_retirement_writer_failure"
assert witness["failure_kind"] == (2 if writer else 1)
for key in ("component_only", "whole_failed_retirement_retained_after_drop", "a_native_io_drained"):
    assert witness[key] is True, key
for key in ("retirement_complete", "cleanup_or_reuse_authorized", "expiry_signalled", "resumed"):
    assert witness[key] is False, key
integer(witness["guard_pid"], 2)
integer(witness["guard_start"], 1)
assert witness["guard_actual_wait_status"] == signal.SIGKILL
born, gate = finite(witness["original_born_at"]), finite(witness["original_gate_deadline"])
assert abs(gate - born - 3) < 0.00001
failure = witness["failure"]
assert failure["queue_removed"] is failure["service_reserved"] is True
assert failure["native_actual_drained"] is (not writer)
assert failure["uncertain_mutation_fence"] is writer
assert failure["canonical_pending_retained"] is writer
assert failure["writer_actual_wait_status"] == (signal.SIGKILL if writer else None)
before = integer(witness["a_completed_before_failure"])
at_failure = integer(witness["a_completed_at_failure"])
after = integer(witness["a_completed_after_failure"])
assert at_failure >= before and after >= at_failure + 3
assert witness["a_next_mutation_actual_durable_reaped"] is (not writer)
assert witness["a_next_mutation_refused_by_uncertainty"] is writer

output = dict(
    observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    record=str(record_path), record_sha256=hashlib.sha256(raw).hexdigest(),
    source_commit=candidate["source_commit"], source_archive_sha256=candidate["source_sha256"],
    artifact_sha256=record["artifact_sha256"], context_sha256=record["context_sha256"],
    platform=binding["platform"], component_test_mode=mode, witness=witness,
    real_client_acceptance="NOT_RUN", production_changes=False,
    limit="Native retirement failure component only; failed whole driver and canonical reservation retained; writer reap distinct from full collection; no cleanup/reuse/operational/provider/client acceptance",
)
destination = pathlib.Path("target/lab-state/owner-retirement-failure-run-" + match[1] + ".json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps(dict(witness=str(destination), platform=binding["platform"], mode=mode,
                     source_commit=candidate["source_commit"], whole_failed_driver_retained=True,
                     a_fresh_audits_after_failure=after-at_failure, real_client_acceptance="NOT_RUN")))
