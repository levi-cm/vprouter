"""Validate and summarize bounded exact-payload metadata A/B measurements.

This microbenchmark does not establish router or bootstrap performance.
"""
import datetime
import hashlib
import json
import pathlib
import statistics
import sys

candidate_path = pathlib.Path(sys.argv[1])
platform = sys.argv[2]
assert len(sys.argv) in (3, 4)
optimized = len(sys.argv) == 4
if optimized:
    assert sys.argv[3] == "--optimized"
candidate = json.loads(candidate_path.read_text())
if platform == "host-amd64":
    source_record = pathlib.Path("target/process-inspection-root-verification-20261027") / (
        "frozen-preflight-" + candidate["source_commit"] + ".json")
    record = json.loads(source_record.read_text())
    assert record["exit_code"] == 0
    result = record
    arch = "amd64"
else:
    assert platform in {"debian-arm64", "debian-x86_64", "arch-x86_64"}
    source_record = candidate_path.parent / ("native-preflight-" + platform) / "record.json"
    record = json.loads(source_record.read_text())
    assert record["ssh_exit_code"] == 0
    result = record["result"]
    assert result["exit_code"] == 0 and not result["timed_out"] and result["uid"] != 0
    arch = "arm64" if platform == "debian-arm64" else "amd64"
assert record["source_commit"] == candidate["source_commit"]
assert record["artifact_sha256"] == candidate["platforms"][arch]["artifact_sha256"]
lines = [line for line in result["stdout"].splitlines() if line.startswith("LAB_METADATA_PAIR ")]
assert len(lines) == 1
data = json.loads(lines[0].split(" ", 1)[1])
expected_keys = {
    "fd_count", "iterations", "warmup_rounds", "order", "a", "b", "samples_ns",
    "timed_observations_per_path", "timed_statat_calls_per_path", "timed_a_fdinfo_opens",
    "timed_a_read_calls_lower_bound", "timed_a_fdinfo_closes", "timed_b_fcntl_getfd_calls",
    "both_cloexec_states_equal", "closed_fd_rejected", "registered_flag_drift_rejected",
    "unchanged_inspector_filter", "actual_waitpid_exit0", "production_path_unchanged",
}
if optimized:
    expected_keys.add("production_path")
assert set(data) == expected_keys, set(data) ^ expected_keys
assert (data["fd_count"], data["iterations"], data["warmup_rounds"]) == (22, 16, 4)
assert data["order"] == "ABBA_ABBA_ABBA_ABBA"
assert (data["a"], data["b"]) == ("statat_fdinfo", "statat_getfd")
samples = data["samples_ns"]
assert len(samples) == 16 and all(type(value) is int and value > 0 for value in samples)
observations = 22 * 16 * 8
for key in (
    "timed_observations_per_path", "timed_statat_calls_per_path", "timed_a_fdinfo_opens",
    "timed_a_read_calls_lower_bound", "timed_a_fdinfo_closes", "timed_b_fcntl_getfd_calls",
):
    assert data[key] == observations, (key, data[key])
for key in (
    "both_cloexec_states_equal", "closed_fd_rejected", "registered_flag_drift_rejected",
    "unchanged_inspector_filter", "actual_waitpid_exit0",
):
    assert data[key] is True, key
assert data["production_path_unchanged"] is (not optimized)
if optimized:
    assert data["production_path"] == "statat_getfd"
a = [value for index, value in enumerate(samples) if index % 4 in (0, 3)]
b = [value for index, value in enumerate(samples) if index % 4 in (1, 2)]
blocks = []
for offset in range(0, 16, 4):
    old = (samples[offset] + samples[offset + 3]) / 2
    new = (samples[offset + 1] + samples[offset + 2]) / 2
    blocks.append({"a_batch_mean_ns": old, "b_batch_mean_ns": new,
                   "b_reduction_fraction": 1 - new / old})
output = {
    "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "source_commit": candidate["source_commit"], "source_archive_sha256": candidate["source_sha256"],
    "artifact_sha256": record["artifact_sha256"], "platform": platform,
    "source_record": str(source_record),
    "source_record_sha256": hashlib.sha256(source_record.read_bytes()).hexdigest(),
    "raw_measurement": data, "paired_abba_blocks": blocks,
    "a_mean_ns_per_observation": sum(a) / observations,
    "b_mean_ns_per_observation": sum(b) / observations,
    "b_mean_reduction_fraction": 1 - sum(b) / sum(a),
    "a_median_batch_ns": statistics.median(a), "b_median_batch_ns": statistics.median(b),
    "production_getter_candidate": optimized,
    "scope": "bounded paired metadata microbenchmark only; "
             + ("production getter candidate; " if optimized else "production path unchanged; ")
             + "no bootstrap/router performance acceptance",
}
destination = candidate_path.parent / ("metadata-pair-" + platform + ".json")
with destination.open("x") as stream:
    json.dump(output, stream, indent=2)
    stream.write("\n")
print(json.dumps({key: output[key] for key in (
    "source_commit", "platform", "a_mean_ns_per_observation", "b_mean_ns_per_observation",
    "b_mean_reduction_fraction", "scope",
)}, indent=2))
