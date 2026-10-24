"""Controller-only exact-artifact runner in the owned local Debian VM.

Records unsuccessful runs too; never cleans ambiguous test resources. The
privileged payload independently admits its exact hash and guest host namespace.
"""
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import time


def main():
    if len(sys.argv) not in (5, 6):
        raise SystemExit("usage: artifact artifact_sha256 source_archive source_sha256 [scenario]")
    artifact, digest, source, source_digest = sys.argv[1:5]
    scenario = sys.argv[5] if len(sys.argv) == 6 else "reversible"
    assert scenario in {"reversible", "deleted-wg", "deleted-transport",
                        "cooperation-drift", "foreign-collision",
                        "interrupted-activation", "interrupted-cleanup"}
    for value in (digest, source_digest):
        assert re.fullmatch(r"[a-f0-9]{64}", value)
    for path, expected in ((artifact, digest), (source, source_digest)):
        assert hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() == expected
    base = pathlib.Path("target/lab-state")
    for path, expected, suffix in ((artifact, digest, "payload"),
                                  (source, source_digest, "source.tar")):
        retained = base / ("task8a-" + expected + "." + suffix)
        if retained.exists():
            assert hashlib.sha256(retained.read_bytes()).hexdigest() == expected
        else:
            with retained.open("xb") as output, pathlib.Path(path).open("rb") as input_file:
                shutil.copyfileobj(input_file, output)
    opts = ["-i", str(base / "id_ed25519"), "-o", "IdentitiesOnly=yes",
            "-o", "UserKnownHostsFile=" + str(base / "known_hosts"),
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5"]
    ssh = ["ssh", *opts, "-p22032", "vprouterlab@127.0.0.1"]
    temporary = "/home/vprouterlab/task8a-" + digest
    destination = "/var/lib/vprouter-v2-lab/task8a-payload-" + digest
    subprocess.run(["scp", "-q", *opts, "-P22032", artifact,
                    "vprouterlab@127.0.0.1:" + temporary], check=True, timeout=20)
    # Only validated hexadecimal text is interpolated into SSH's command string.
    subprocess.run([*ssh, "sudo install -o root -g root -m 0555 " + temporary + " " + destination],
                   check=True, timeout=8)
    subprocess.run([*ssh, "rm -- " + temporary], check=True, timeout=8)
    setup = r'''
import os,pathlib,stat,hashlib,subprocess,json
root=pathlib.Path('/var/lib/vprouter-v2-lab')
for p in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),root]:
 s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_gid==0 and not s.st_mode&0o022
assert os.geteuid()==0
marker=root/'isolated-acceptance';s=marker.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
digest=DIGEST
scenario=SCENARIO
payload=root/('task8a-payload-'+digest);s=payload.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o555
assert hashlib.sha256(payload.read_bytes()).hexdigest()==digest
net=pathlib.Path('/proc/self/ns/net').stat();init=pathlib.Path('/proc/1/ns/net').stat()
assert (net.st_dev,net.st_ino)==(init.st_dev,init.st_ino)
def run(argv):
 return subprocess.run(argv,check=True,capture_output=True,text=True,timeout=5).stdout
routes=json.loads(run(['ip','-j','-4','route','show','table','all']))
addresses=json.loads(run(['ip','-j','address','show']))
assert not any(r.get('dst') in ['185.65.134.88','185.65.134.88/32','185.65.134.89','185.65.134.89/32'] for r in routes),'synthetic_endpoint_route_collision'
assert not any(a.get('local') in ['185.65.134.88','185.65.134.89'] for i in addresses for a in i.get('addr_info',[])),'synthetic_endpoint_address_collision'
chain=json.loads(run(['nft','-j','list','chain','ip','filter','FORWARD']))
assert any(v.get('chain',{}).get('policy')=='drop' for v in chain['nftables'])
probe=root/'launch-execution-probe';s=probe.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022
assert hashlib.sha256(probe.read_bytes()).hexdigest()=='808789d0d5d59b673c7f6fd55b306c3ecfc05ef0bbdd65731cff2ae7695bd828'
approval=root/'task8a-host-acceptance'
assert not approval.exists(),'stale_host_admission_marker_requires_review'
fd=os.open(approval,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:
 json.dump({'artifact_sha256':digest,'network_dev':net.st_dev,'network_ino':net.st_ino},f);f.flush();os.fsync(f.fileno())
print(json.dumps({'preflight':'PASS','host_namespace':{'dev':net.st_dev,'ino':net.st_ino},'docker_forward_before':chain,'routes_before':routes,'addresses_before':addresses}),flush=True)
try:
 result=subprocess.run(['timeout','--kill-after=3s','60s',str(payload),'--ignored','--scenario',scenario],timeout=66)
 print(json.dumps({'harness_exit_code':result.returncode,'docker_forward_after':json.loads(run(['nft','-j','list','chain','ip','filter','FORWARD']))}),flush=True)
finally:
 s=approval.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
 assert json.loads(approval.read_text())=={'artifact_sha256':digest,'network_dev':net.st_dev,'network_ino':net.st_ino}
 approval.unlink()
raise SystemExit(result.returncode)
'''.replace("DIGEST", repr(digest)).replace("SCENARIO", repr(scenario))
    started = time.monotonic()
    try:
        result = subprocess.run([*ssh, "sudo python3 -"], input=setup,
                                capture_output=True, text=True, timeout=78)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code = 124
        stdout = (error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
        stderr = (error.stderr or b"").decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
    evidence = {"scenario": scenario, "observed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "artifact_sha256": digest, "source_archive_sha256": source_digest,
                "runner_sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                "exit_code": code, "wall_seconds": round(time.monotonic() - started, 3),
                "stdout": stdout, "stderr": stderr,
                "result": "PASS_PARTIAL_TRANSPORT_SMOKE" if code == 0 else "FAIL",
                "real_client_acceptance": "NOT_RUN", "production_changes": False}
    attempt = 1
    while (base / f"guarded-transport-run-{attempt}.json").exists():
        attempt += 1
    with (base / f"guarded-transport-run-{attempt}.json").open("x") as output:
        json.dump(evidence, output, indent=2)
        output.write("\n")
    print(json.dumps(evidence, indent=2))
    return 0 if code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
