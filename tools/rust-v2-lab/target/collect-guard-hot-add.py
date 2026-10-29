"""Collect the frozen held/setup guard-constructor witness from retained logs.

Read-only local collection; the native assertion runs in the existing fixed VM
oracle. This witness does not grant runtime authority or release acceptance.
"""
import datetime
import hashlib
import json
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
record_bytes = record_path.read_bytes()
record = json.loads(record_bytes)
assert controller["exit_code"] == record["exit_code"] == 0
assert record["component_test_mode"] in {"owner_inspection_held", "owner_inspection_setup"}
assert record["real_client_acceptance"] == "NOT_RUN" and record["production_changes"] is False
assert binding["source_commit"] == record["source_binding"]["source_commit"] == candidate["source_commit"]
assert binding["source_archive_sha256"] == record["source_archive_sha256"] == candidate["source_sha256"]
assert binding["artifact_sha256"] == record["artifact_sha256"]
arch = {"debian-clean-x86_64": "amd64", "debian-x86_64": "amd64", "debian-arm64": "arm64", "arch-x86_64": "amd64"}[binding["platform"]]
assert record["artifact_sha256"] == candidate["platforms"][arch]["artifact_sha256"]
assert record["context_sha256"] == candidate["platforms"][arch]["context_sha256"]
source = pathlib.Path(candidate["source"])
assert hashlib.sha256(source.read_bytes()).hexdigest() == candidate["source_sha256"]
marker = "LAB_GUARD_HOT_ADD private_native_excluded=true foreign_actor_drop_inert=true foreign_journal_fence_refused=true"
with tarfile.open(source) as archive:
    code = archive.extractfile("crates/vprouter-launch/src/inspection.rs").read()
    assert code.count(marker.encode()) == 1
lines = [line.strip() for line in record["stderr"].splitlines() if "LAB_GUARD_HOT_ADD" in line]
assert lines == [marker], lines
output = {
    "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "record": str(record_path), "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
    "source_commit": candidate["source_commit"], "source_archive_sha256": candidate["source_sha256"],
    "artifact_sha256": record["artifact_sha256"], "platform": binding["platform"],
    "component_test_mode": record["component_test_mode"], "native_guard_witness": lines[0],
    "runtime_events": controller["runtime_events"],
    "limit": "copied-Service destructor proof is the held branch; setup branch has no installed Service",
    "real_client_acceptance": "NOT_RUN", "production_changes": False,
}
destination = pathlib.Path("target/lab-state/guard-hot-add-run-" + match[1] + ".json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps({"witness": str(destination), "platform": binding["platform"], "mode": record["component_test_mode"], "source_commit": candidate["source_commit"], "native_guard_witness": lines[0], "real_client_acceptance": "NOT_RUN"}, indent=2))
