"""Read-only source/index proof before releasing the sole writer's freeze."""
import datetime
import hashlib
import json
import pathlib
import subprocess
import sys
import tarfile

candidate_path = pathlib.Path(sys.argv[1])
regression_path = pathlib.Path(sys.argv[2])
candidate = json.loads(candidate_path.read_text())
regression = json.loads(regression_path.read_text())
assert regression["source_commit"] == candidate["source_commit"]
assert regression["exit_code"] == regression["failed"] == 0 and regression["passed"] > 0
source = pathlib.Path(candidate["source"])
assert hashlib.sha256(source.read_bytes()).hexdigest() == candidate["source_sha256"]
binding = json.loads(subprocess.check_output([sys.executable, "tools/verify-frozen-build-inputs.py", str(source), candidate["source_commit"]]))
assert binding == candidate["binding"]
count, mismatches = 0, []
with tarfile.open(source) as archive:
    for member in archive:
        if not member.isfile():
            continue
        name = pathlib.PurePosixPath(member.name)
        assert not name.is_absolute() and ".." not in name.parts
        count += 1
        current = pathlib.Path(member.name)
        if not current.is_file() or current.read_bytes() != archive.extractfile(member).read():
            mismatches.append(member.name)
assert count == binding["tracked_build_inputs_verified"] and not mismatches
def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()
head, branch = git("rev-parse", "HEAD"), git("branch", "--show-current")
index_sha = hashlib.sha256(pathlib.Path(git("rev-parse", "--git-path", "index")).read_bytes()).hexdigest()
assert head == "c6a138c00b70163ba3cbfdf350e5cf8e2f3a3c6a" and branch == "rust/v2"
assert index_sha == "59f3aec05fa66f161482e5705f1a3c50c68c528980a51b5da4a869a510a24692"
record = dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), candidate=str(candidate_path),
              source_commit=candidate["source_commit"], current_archive_commit_inputs=count, mismatches=mismatches,
              head=head, branch=branch, index_sha256=index_sha,
              regression_record=str(regression_path), regression_record_sha256=hashlib.sha256(regression_path.read_bytes()).hexdigest(),
              scope="Current-source proof before ordinary continuation; later immutable native runs do not assert current source remains frozen")
destination = pathlib.Path("target/process-inspection-root-verification-20261027") / ("source-continuation-" + candidate["source_commit"][:7] + ".json")
with destination.open("x") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
print(json.dumps(record))
