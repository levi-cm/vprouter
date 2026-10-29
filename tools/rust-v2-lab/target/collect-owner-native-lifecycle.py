"""Bind actual owner-drop/birth-failure witnesses to frozen source and bytes.

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
    "owner_retained_drop": "actual_owner_retained_host_audit_and_managed_guard_drop_original_receipts_neighbor_progress",
    "owner_admission_birth_failure": "actual_owner_failed_initial_birth_write_retained_plan_actual_guard_reap_neighbor_progress",
}
case = cases[mode]
assert record["real_client_acceptance"] == "NOT_RUN" and record["production_changes"] is False
assert not any(record[key] for key in ("raw_syscall_metadata", "file_path_metadata", "stderr_diagnostic", "peer_credential_metadata"))
assert binding["new_directories"] == []
assert binding["source_commit"] == record["source_binding"]["source_commit"] == candidate["source_commit"]
assert binding["source_archive_sha256"] == record["source_archive_sha256"] == candidate["source_sha256"]
arch = {"debian-clean-x86_64": "amd64", "debian-x86_64": "amd64", "debian-arm64": "arm64"}[binding["platform"]]
assert binding["artifact_sha256"] == record["artifact_sha256"] == candidate["platforms"][arch]["artifact_sha256"]
assert record["context_sha256"] == candidate["platforms"][arch]["context_sha256"]
source = pathlib.Path(candidate["source"])
assert hashlib.sha256(source.read_bytes()).hexdigest() == candidate["source_sha256"]
verified = json.loads(subprocess.check_output([sys.executable, "tools/verify-frozen-build-inputs.py", str(source), candidate["source_commit"]]))
assert verified == record["source_binding"] == candidate["binding"]
with tarfile.open(source) as archive:
    owned_source = archive.extractfile("crates/vprouter-launch/src/owned.rs").read()
    assert owned_source.count(case.encode()) == 1
    host_window_lifetime_expected = b'"host_window_retained_after_drop_and_reap"' in owned_source
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


def true(key):
    assert witness.get(key) is True, key


def false(key):
    assert witness.get(key) is False, key


def integer(key, minimum=0):
    assert type(witness[key]) is int and witness[key] >= minimum, key
    return witness[key]


def finite(key):
    value = witness[key]
    assert type(value) in (int, float) and math.isfinite(value) and value > 0, key
    return value


def killed_reap(key):
    status = integer(key)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL, key


for key in ("component_only", "wrong_member_journal_refused", "a_native_io_drained", "guard_actual_reaped"):
    true(key)
false("resumed")
integer("guard_pid", 2)
integer("guard_start", 1)
killed_reap("guard_actual_wait_status")
born, deadline = finite("original_born_at"), finite("original_gate_deadline")
assert abs(deadline - born - 3) < 0.00001
if mode == "owner_admission_birth_failure":
    for key in ("initial_birth_write_failed", "planned_bytes_unchanged", "pending_native_drained", "journal_actual_drained"):
        true(key)
    false("released")
    assert integer("a_completed_after_drain") >= integer("a_completed_at_drain") + 3
else:
    for key in ("audit_native_stopped", "audit_actual_reaped", "audit_bundle_collected", "private_owner_ipc_revoked", "durable_released_before_drop"):
        true(key)
    for key in ("ack_sent", "cleanup_or_reuse_authorized"):
        false(key)
    if host_window_lifetime_expected:
        true("host_window_retained_after_drop_and_reap")
        true("host_window_released_only_after_collection")
        if b'"host_window_postclone_failure_retained"' in owned_source:
            true("host_window_postclone_failure_retained")
            true("host_window_postclone_actual_collection_released")
    integer("audit_pid", 2)
    integer("audit_start", 1)
    assert witness["audit_pid"] != witness["guard_pid"]
    integer("original_sequence", 1)
    finite("original_deadline")
    integer("audit_hold_count_after_drop_and_reap", 1)
    killed_reap("audit_actual_wait_status")
    drained, retained = witness["guard_bundle_drained"], witness["uncertain_scope_bundle_retained"]
    assert type(drained) is type(retained) is bool and drained != retained
    assert integer("a_completed_after_drop") >= integer("a_completed_before_drop") + 3

output = dict(
    observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    record=str(record_path), record_sha256=hashlib.sha256(raw).hexdigest(),
    source_commit=candidate["source_commit"], source_archive_sha256=candidate["source_sha256"],
    artifact_sha256=record["artifact_sha256"], context_sha256=record["context_sha256"],
    platform=binding["platform"], component_test_mode=mode, witness=witness,
    host_window_lifetime_expected=host_window_lifetime_expected,
    real_client_acceptance="NOT_RUN", production_changes=False,
    limit="Native lifecycle fixture only; uncertain bundles remain retained; no cleanup/reuse/retirement/operational acceptance",
)
destination = pathlib.Path("target/lab-state/owner-native-lifecycle-run-" + match[1] + ".json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps(dict(witness=str(destination), platform=binding["platform"], mode=mode,
                     source_commit=candidate["source_commit"], guard_actual_reaped=True,
                     uncertain_scope_bundle_retained=witness.get("uncertain_scope_bundle_retained"),
                     real_client_acceptance="NOT_RUN")))
