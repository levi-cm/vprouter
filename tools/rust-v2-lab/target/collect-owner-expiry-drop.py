"""Bind actual expiry-owner drop witnesses to frozen source and bytes.

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
    "owner_expiry_drop": "actual_owner_registered_expiry_drop_retains_three_original_completions_and_native_reaps",
    "owner_expiry_partial_drop": "actual_owner_partial_expiry_birth_drop_retains_original_native_context_without_signal",
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


def number(value, minimum=0):
    assert type(value) in (int, float) and math.isfinite(value) and value > minimum
    return value


def integer(value, minimum=0):
    assert type(value) is int and value >= minimum
    return value


def identity(value):
    assert set(value) == {"scope", "pid", "start_time", "namespace"}
    scope = integer(value["scope"])
    assert scope in (0, 1, 2)
    pid = integer(value["pid"], 2)
    start = integer(value["start_time"], 1)
    assert set(value["namespace"]) == {"dev", "ino"}
    integer(value["namespace"]["dev"], 1)
    integer(value["namespace"]["ino"], 1)
    return scope, pid, start, value["namespace"]["dev"], value["namespace"]["ino"]


for key in ("component_only", "a_native_io_drained", "guard_actual_reaped",
            "durable_released_before_drop", "original_native_context_retained",
            "b_journal_native_drained", "guard_removed_original_scope_observed",
            "guard_bundle_drained"):
    assert witness[key] is True, key
for key in ("resumed", "expiry_signal_sent", "canonical_completion_claimed",
            "cleanup_or_reuse_authorized"):
    assert witness[key] is False, key
guard_pid = integer(witness["guard_pid"], 2)
integer(witness["guard_start"], 1)
assert integer(witness["guard_actual_wait_status"]) == signal.SIGKILL
born = number(witness["original_born_at"])
gate = number(witness["original_gate_deadline"])
assert abs(gate - born - 3) < 0.00001
started = number(witness["original_expiry_started_at"])
assert started >= born
assert integer(witness["a_completed_after_drop"]) >= integer(witness["a_completed_before_drop"]) + 3
partial = mode == "owner_expiry_partial_drop"
assert witness["partial"] is partial
assert witness["canonical_registered_acknowledged_before_drop"] is (not partial)
assert witness["partial_birth_failed_before_return"] is partial
assert type(witness["canonical_completion_count"]) is int and witness["canonical_completion_count"] == 0
identities = witness["registered_identities"]
assert type(identities) is list

if partial:
    assert identities == []
    actor = witness["partial_actor_identity"]
    assert type(actor) is list and len(actor) == 2
    assert integer(actor[0], 2) != guard_pid
    integer(actor[1], 1)
    assert witness["partial_actor_wait_status"] == 122 << 8
    assert witness["retained_after_drop"] is witness["retained_after_reap"] is None
else:
    assert len(identities) == 3
    original = {identity(value) for value in identities}
    assert len(original) == 3 and {value[0] for value in original} == {0, 1, 2}
    assert len({value[1] for value in original}) == 3
    assert guard_pid not in {value[1] for value in original}
    assert witness["partial_actor_identity"] is witness["partial_actor_wait_status"] is None
    original_deadlines = {}
    for phase in ("retained_after_drop", "retained_after_reap"):
        retained = witness[phase]
        assert retained["original_started_at"] == started
        assert retained["failure"] is None
        assert retained["all_native_context_retained"] is True
        assert retained["uncommitted_receipts_retained"] is True
        actors = retained["actors"]
        assert type(actors) is list and len(actors) == 3
        assert {identity(actor["identity"]) for actor in actors} == original
        for actor in actors:
            key = identity(actor["identity"])
            deadline = number(actor["original_deadline"])
            assert deadline > started
            if phase == "retained_after_drop":
                original_deadlines[key] = deadline
            else:
                assert original_deadlines[key] == deadline
                assert actor["actual_wait_status"] == 122 << 8
                assert actor["actual_reaped"] is actor["no_live_tasks"] is True
        if phase == "retained_after_reap":
            assert retained["all_actual_reaped"] is True
            completions = retained["completions"]
            assert type(completions) is list and len(completions) == 3
            assert {identity(receipt["identity"]) for receipt in completions} == original
            for receipt in completions:
                key = identity(receipt["identity"])
                assert receipt["result"] == "verified_before_deadline"
                assert receipt["deadline"] == original_deadlines[key]
                assert started <= number(receipt["finished_at"]) < receipt["deadline"]

output = dict(
    observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    record=str(record_path), record_sha256=hashlib.sha256(raw).hexdigest(),
    source_commit=candidate["source_commit"], source_archive_sha256=candidate["source_sha256"],
    artifact_sha256=record["artifact_sha256"], context_sha256=record["context_sha256"],
    platform=binding["platform"], component_test_mode=mode, witness=witness,
    real_client_acceptance="NOT_RUN", production_changes=False,
    limit="Native expiry-owner retention only; no expiry signals or resume; canonical completion/cleanup/reuse/retirement/operational acceptance NOT established",
)
destination = pathlib.Path("target/lab-state/owner-expiry-drop-run-" + match[1] + ".json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps(dict(witness=str(destination), platform=binding["platform"], mode=mode,
                     source_commit=candidate["source_commit"], guard_actual_reaped=True,
                     original_expiry_context_retained=True, real_client_acceptance="NOT_RUN")))

