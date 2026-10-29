"""Source-bind the strong native admission-stop witness in retained public logs.

Local read-only collection, not runtime authority or independent actor execution.
Host-drain true is not evidence of cancelling an active host-audit child.
"""
import datetime
import hashlib
import json
import math
import pathlib
import re
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
assert record["component_test_mode"] == "owner_admission_stop"
assert record["real_client_acceptance"] == "NOT_RUN" and record["production_changes"] is False
assert binding["source_commit"] == record["source_binding"]["source_commit"] == candidate["source_commit"]
assert binding["source_archive_sha256"] == record["source_archive_sha256"] == candidate["source_sha256"]
arch = {"debian-clean-x86_64": "amd64", "debian-x86_64": "amd64", "debian-arm64": "arm64", "arch-x86_64": "amd64"}[binding["platform"]]
assert binding["artifact_sha256"] == record["artifact_sha256"] == candidate["platforms"][arch]["artifact_sha256"]
assert record["context_sha256"] == candidate["platforms"][arch]["context_sha256"]
source = pathlib.Path(candidate["source"])
assert hashlib.sha256(source.read_bytes()).hexdigest() == candidate["source_sha256"]
with tarfile.open(source) as archive:
    code = archive.extractfile("crates/vprouter-launch/src/inspection.rs").read()
    assert code.count(b"LAB_ADMISSION_HELD_READ") == 1
case = "actual_owner_stop_latched_across_existing_and_pending_member_before_release"
witnesses = [v for v in controller["runtime_events"] if v.get("case") == case and "result" not in v]
assert len(witnesses) == 1
witness = witnesses[0]
for key in (
    "native_births_unchanged_after_stop", "pending_actual_reaped", "no_guard_release",
    "planned_record_retained_without_birth_receipt", "held_read_native_stopped_before_signal",
    "held_read_actual_reaped", "held_read_never_resumed", "held_read_progress_retained_without_ack",
    "a_journal_actual_drained", "b_journal_actual_drained", "host_audit_actual_drained", "component_only",
):
    assert witness.get(key) is True, key
for key in ("pending_pid", "pending_start", "held_read_pid", "held_read_start"):
    assert type(witness[key]) is int and witness[key] > 1
for key in ("original_gate_deadline", "held_read_original_deadline"):
    assert math.isfinite(witness[key]) and witness[key] > 0
lines = record["stderr"].splitlines()
held = [json.loads(v.split(" ", 1)[1]) for v in lines if v.startswith("LAB_ADMISSION_HELD_READ ")]
assert held == [{"pid": witness["held_read_pid"], "start": witness["held_read_start"],
                 "original_deadline": witness["held_read_original_deadline"],
                 "native_stopped": True, "never_resume": True}]
cross_member = "LAB_GUARD_ATTEMPT cross_member_same_lifecycle_rejected_before_clone=true native_births_unchanged=true"
assert lines.count(cross_member) == 1
output = {
    "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "record": str(record_path), "record_sha256": hashlib.sha256(raw).hexdigest(),
    "source_commit": candidate["source_commit"], "source_archive_sha256": candidate["source_sha256"],
    "artifact_sha256": record["artifact_sha256"], "platform": binding["platform"],
    "witness": witness, "held_read_native_observation": held[0], "cross_member_preclone_negative": True,
    "limit": "constructed host-audit drain predicate only; no active host-audit cancellation proof",
    "real_client_acceptance": "NOT_RUN", "production_changes": False,
}
destination = pathlib.Path("target/lab-state/admission-stop-run-" + match[1] + ".json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps({"witness": str(destination), "platform": binding["platform"],
                  "source_commit": candidate["source_commit"], "held_read_actual_reaped": True,
                  "no_guard_release": True, "real_client_acceptance": "NOT_RUN"}, indent=2))
