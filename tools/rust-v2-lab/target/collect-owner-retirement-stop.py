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
cases = {"owner_retirement_global_stop": "actual_owner_dropped_retirement_global_stop_retains_unconsumed_durable_authority"}
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

for key in ("component_only", "a_native_io_drained", "durable_retiring_before_drop", "real_sigterm_queued_after_drop", "unconsumed_stop_permit_retained", "canonical_retiring_bytes_unchanged", "canonical_service_reserved", "whole_failed_retirement_retained_after_drop", "existing_a_terminal_interrupted"):
    assert witness[key] is True, key
for key in ("cleanup_or_reuse_authorized", "inventory_corruption_tested", "expiry_signalled", "resumed"):
    assert witness[key] is False, key
pid = integer(witness["guard_pid"], 2)
integer(witness["guard_start"], 1)
assert witness["guard_actual_wait_status"] == signal.SIGKILL
born, gate = finite(witness["original_born_at"]), finite(witness["original_gate_deadline"])
assert abs(gate - born - 3) < 0.00001
assert witness["retained_driver_polls"] == 3
births = integer(witness["native_births_before_stop"], 1)
assert integer(witness["native_births_after_stop"], 1) == births
actors = witness["expiry_identities"]
assert type(actors) is list and len(actors) == 3
identities = set()
for value in actors:
    assert set(value) == {"scope", "pid", "start_time", "namespace"}
    scope = integer(value["scope"])
    assert scope in (0, 1, 2)
    identity = value["namespace"]
    assert set(identity) == {"dev", "ino"}
    actor_pid = integer(value["pid"], 2)
    assert actor_pid != pid
    identities.add((scope, actor_pid, integer(value["start_time"], 1), integer(identity["dev"], 1), integer(identity["ino"], 1)))
assert len(identities) == 3 and {value[0] for value in identities} == {0, 1, 2} and len({value[1] for value in identities}) == 3
assert witness["expiry_actual_wait_statuses"] == [122 << 8] * 3
output = dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), record=str(record_path), record_sha256=hashlib.sha256(raw).hexdigest(), source_commit=candidate["source_commit"], source_archive_sha256=candidate["source_sha256"], artifact_sha256=record["artifact_sha256"], context_sha256=record["context_sha256"], collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(), platform=binding["platform"], witness=witness, guard_actual_reap_is_explicit_fixture_containment=True, inventory_corruption_tested=False, real_client_acceptance="NOT_RUN", production_changes=False, limit="Actual dropped retirement global SIGTERM stop-latch component only; exact durable authority/service retained and no native births during three polls. Guard is later explicitly contained by original fixture handle. No inventory-corruption, cleanup/reuse, recovery, live-provider/client or release acceptance.")
destination = pathlib.Path("target/lab-state/owner-retirement-stop-run-" + match[1] + ".json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps(dict(witness=str(destination), platform=binding["platform"], source_commit=candidate["source_commit"], dropped_driver_global_stop_verified=True, new_native_births=0, inventory_corruption_tested=False, real_client_acceptance="NOT_RUN")))
