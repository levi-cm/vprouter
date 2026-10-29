"""Bind full links/producer retirement witnesses to frozen source and bytes.

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
    "owner_retirement": "actual_owner_consuming_retirement_original_native_cleanup_final_durable_reap_neighbor_progress",
    "owner_retirement_host_span": "actual_owner_retirement_original_a_dump_spans_b_removal_and_fresh_ticket_rejects_replay",
}
case = cases[mode]
span = mode == "owner_retirement_host_span"
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
    owned_source = archive.extractfile("crates/vprouter-launch/src/owned.rs").read()
    assert owned_source.count(case.encode()) == 1
    held_writer_required = b'"links_removed_writer":links_writer' in owned_source
    cleanup_timing_required = b"LAB_RETIREMENT_CLEANUP_TIMING" in owned_source
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

def identity(value):
    assert set(value) == {"dev", "ino"}
    return integer(value["dev"], 1), integer(value["ino"], 1)

def executor(value):
    assert set(value) == {"scope", "pid", "start_time", "namespace"}
    scope = integer(value["scope"])
    assert scope in (0, 1, 2)
    return scope, integer(value["pid"], 2), integer(value["start_time"], 1), identity(value["namespace"])

for key in ("component_only", "a_native_io_drained", "final_writer_actual_reaped",
            "canonical_service_retained_through_final_reap", "original_producer_unlinked_by_bound_helper",
            "original_guard_scope_removed", "namespaces_and_quarantine_retained"):
    assert witness[key] is True, key
for key in ("expiry_signalled", "resumed", "operational_reuse_authorized", "producer_live_stop_proven"):
    assert witness[key] is False, key
assert witness["a_dump_spans_host_removal_proven"] is span
pid, start = integer(witness["guard_pid"], 2), integer(witness["guard_start"], 1)
assert witness["guard_actual_wait_status"] == signal.SIGKILL
born, gate = finite(witness["original_born_at"]), finite(witness["original_gate_deadline"])
assert abs(gate - born - 3) < 0.00001
actors = witness["expiry_identities"]
assert type(actors) is list and len(actors) == 3
original = {executor(value) for value in actors}
assert len(original) == 3 and {value[0] for value in original} == {0, 1, 2}
assert len({value[1] for value in original}) == 3 and pid not in {value[1] for value in original}
assert witness["expiry_actual_wait_statuses"] == [122 << 8] * 3

entry = witness["final_record"]
assert entry["phase"] == "offline"
assert entry.get("links") is None and entry.get("producer") is None
attempt, terminal = entry["attempt"], entry["terminal"]
assert attempt["stage"] == "retired" and attempt["exit_id"] == entry["exit_id"]
assert re.fullmatch("[a-f0-9]{64}", attempt["lifecycle"])
assert terminal["lifecycle"] == attempt["lifecycle"]
assert terminal["guard_pid"] == pid and terminal["guard_start"] == start
assert terminal["acknowledged"] == [0, 1, 2]
assert {executor(value) for value in terminal["executors"]} == original
assert attempt["birth"] == dict(pid=pid, start=start, born_at=born, gate_deadline=gate)
assert len(attempt["scopes"]) == len(set(attempt["scopes"])) == 4
for key in ("allocation", "launch", "resources"):
    assert re.fullmatch("[a-f0-9]{64}", attempt[key])
assert attempt["scopes"] == [
    "vprouter-v2-" + attempt["allocation"] + "-" + attempt["lifecycle"] + "-" + role + ".scope"
    for role in ("guard", "expiry-host", "expiry-transport", "expiry-data")
]
assert terminal["binding"]["exit_id"] == entry["exit_id"]
assert terminal["binding"]["boot_id"] == attempt["owner"]["boot"]
history = attempt["retirement"]
assert history["cleanup"] == "producer_removed"
for key in ("terminal_digest", "host_transition"):
    assert re.fullmatch("[a-f0-9]{64}", history[key])
planned, retiring, quiescent, retired = map(finite, (attempt["planned_at"], history["started_at"], history["quiescent_at"], history["retired_at"]))
assert planned <= born <= retiring <= quiescent <= retired
if held_writer_required:
    writer = witness["links_removed_writer"]
    assert set(writer) == {"pid", "start", "original_started_at", "original_deadline", "verified_at", "pending_parent_polls", "prequeue_prepared_member_job_refused", "actual_wait_status", "original_deadline_unchanged", "ack_readback_and_actual_reap"}
    assert integer(writer["pid"], 2) not in {pid, *(value[1] for value in original)}
    integer(writer["start"], 1)
    integer(writer["pending_parent_polls"], 2)
    began, deadline, verified_at = map(finite, (writer["original_started_at"], writer["original_deadline"], writer["verified_at"]))
    assert abs(deadline - began - 2) < 0.00001
    assert quiescent <= began <= verified_at < deadline and verified_at <= retired
    assert writer["actual_wait_status"] == 0
    for key in ("prequeue_prepared_member_job_refused", "original_deadline_unchanged", "ack_readback_and_actual_reap"):
        assert writer[key] is True, key
resources = history["original"]
for key in ("exit_id", "data_name", "transport_name", "data", "transport"):
    assert resources[key] == entry[key], key
assert resources["links"] is not None and resources["producer"] is not None
expected_namespaces = {
    0: identity(resources["links"]["host_namespace"]),
    1: identity(resources["transport"]),
    2: identity(resources["data"]),
}
assert all(value[3] == expected_namespaces[value[0]] for value in original)
receipts = terminal["completions"]
assert type(receipts) is list and len(receipts) == 3
assert {executor(value["identity"]) for value in receipts} == original
for receipt in receipts:
    assert receipt["result"] == "verified_before_deadline"
    finished, deadline = finite(receipt["finished_at"]), finite(receipt["deadline"])
    assert born <= finished < deadline and finished <= retiring

counts = {key: integer(witness[key]) for key in (
    "a_completed_before_retirement", "a_completed_at_native_cleanup_hold",
    "a_completed_before_native_cleanup_release", "a_completed_at_cleanup_start",
    "a_completed_at_cleanup_end", "a_completed_after_retirement", "a_completed_after_final_reap",
)}
assert counts["a_completed_at_cleanup_start"] >= counts["a_completed_before_retirement"]
assert counts["a_completed_at_native_cleanup_hold"] >= counts["a_completed_at_cleanup_start"]
assert counts["a_completed_before_native_cleanup_release"] >= counts["a_completed_at_native_cleanup_hold"] + (0 if span else 3)
assert counts["a_completed_at_cleanup_end"] >= counts["a_completed_before_native_cleanup_release"]
assert counts["a_completed_after_retirement"] >= counts["a_completed_at_cleanup_end"]
assert counts["a_completed_after_final_reap"] >= counts["a_completed_after_retirement"] + 3

cleanup_timings = []
if cleanup_timing_required:
    cleanup_timings = [json.loads(line.split(" ", 1)[1]) for line in record["stderr"].splitlines() if line.startswith("LAB_RETIREMENT_CLEANUP_TIMING ")]
    assert [value["event"] for value in cleanup_timings] == ["launched", "checkpoint", "completed"]
    launched, held, completed = cleanup_timings
    native = launched["native"]
    assert set(native) == {"pid", "start", "original_started_at", "original_deadline", "actual_wait_status", "native_reaped", "failed"}
    native_pid, native_start = integer(native["pid"], 2), integer(native["start"], 1)
    assert native_pid not in {pid, *(value[1] for value in original)}
    native_began, native_deadline = map(finite, (native["original_started_at"], native["original_deadline"]))
    assert abs(native_deadline - native_began - 2) < 0.00001
    assert native["actual_wait_status"] is None and native["native_reaped"] is False and native["failed"] is False
    assert held["native"] == completed["native"] == native
    launched_at, held_at = map(finite, (launched["observed_at"], held["observed_at"]))
    released_at = finite(completed["checkpoint_released_at"])
    assert completed["checkpoint_at"] == held_at
    assert native_began <= launched_at <= held_at <= released_at < native_deadline
    assert finite(completed["observed_at"]) >= released_at
    assert held["a_completed"] == completed["a_at_checkpoint"] == counts["a_completed_at_native_cleanup_hold"]
    assert completed["a_at_release"] == counts["a_completed_before_native_cleanup_release"]
if span:
    assert cleanup_timing_required and witness["a_mixed_observation_verified"] is witness["fresh_a_replay_refused"] is True
    job = witness["a_span_original_job"]
    assert type(job) is list and len(job) == 4
    a_pid, a_start, a_sequence = (integer(value, minimum) for value, minimum in zip(job[:3], (2, 1, 1)))
    assert a_pid not in {pid, native_pid, *(value[1] for value in original)}
    a_sent = finite(job[3])
    assert a_sent <= released_at < a_sent + 2
    a_checkpoint, a_released, a_verified = map(finite, (witness["a_span_checkpoint_at"], witness["a_span_released_at"], witness["a_span_verified_at"]))
    assert a_sent <= a_checkpoint <= a_released <= a_verified < a_sent + 2
    assert held_at <= a_checkpoint <= released_at <= a_released
    fresh = witness["fresh_a_job"]
    assert type(fresh) is list and len(fresh) == 3
    assert integer(fresh[0], 1) > a_sequence
    fresh_sent, fresh_verified = map(finite, fresh[1:])
    assert fresh_sent >= a_verified and fresh_sent <= fresh_verified < fresh_sent + 2
    assert integer(witness["b_original_host_index"], 1) == resources["links"]["host_index"]
    alias = witness["b_original_host_alias"]
    assert type(alias) is str and 0 < len(alias) <= 256 and all(32 <= ord(value) < 127 for value in alias)

output = dict(
    observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    record=str(record_path), record_sha256=hashlib.sha256(raw).hexdigest(),
    source_commit=candidate["source_commit"], source_archive_sha256=candidate["source_sha256"],
    artifact_sha256=record["artifact_sha256"], context_sha256=record["context_sha256"],
    platform=binding["platform"], witness=witness, cleanup_timings=cleanup_timings,
    controlled_a_dump_span=span,
    links_and_producer_retired=True, retained_namespace_identities_preserved=True,
    quarantine_retention_runtime_reparsed=False,
    real_client_acceptance="NOT_RUN", production_changes=False,
    limit=("Controlled original A dump across B native host removal and fresh-ticket replay refusal; " if span else "Controlled A dump across removal NOT proven; ") + "Native links/empty-producer-group retirement component only; live daemon/monitor producer stop is not proven; original namespaces/quarantine remain retained; safe operational reuse/recovery/provider/client/all-nine acceptance are not established by this collector",
)
destination = pathlib.Path("target/lab-state/owner-retirement-run-" + match[1] + ".json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps(dict(witness=str(destination), platform=binding["platform"],
                     source_commit=candidate["source_commit"], links_and_producer_retired=True,
                     fresh_neighbor_audits_during_cleanup=counts["a_completed_before_native_cleanup_release"]-counts["a_completed_at_native_cleanup_hold"],
                     final_writer_actual_reaped=True, real_client_acceptance="NOT_RUN")))
