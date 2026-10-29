"""Root-only read-only inspection of exact failed expiry-drop fixture actors."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

run = int(sys.argv[1])
record_path = pathlib.Path(f"target/lab-state/actual-program-run-{run}.json")
raw = record_path.read_bytes()
record = json.loads(raw)
assert record["exit_code"] != 0 and record["component_test_mode"] in {"owner_expiry_drop", "owner_expiry_partial_drop", "owner_retirement", "owner_retirement_queued_failure", "owner_retirement_writer_failure", "owner_retirement_host_span"}
binding = json.loads(pathlib.Path(sys.argv[2]).read_text())
assert binding["record"] == str(record_path) and binding["new_directories"] == []
assert binding["artifact_sha256"] == record["artifact_sha256"]
assert binding["source_commit"] == record["source_binding"]["source_commit"]
intents = [json.loads(line.split(" ", 1)[1]) for line in record["stderr"].splitlines() if line.startswith("LAB_GUARD_SCOPE_INTENT ")]
assert len(intents) >= 2 and sum(e["role"] == "guard" for e in intents) == 2
assert all(e["role"] in {"guard", "expiry-host", "expiry-transport", "expiry-data"} for e in intents)
for e in intents:
    assert e["unit"] == f"vprouter-v2-{e['allocation_digest']}-{e['lifecycle']}-{e['role']}.scope"
    assert re.fullmatch(r"vprouter-v2-[a-f0-9]{64}-[a-f0-9]{64}-(guard|expiry-host|expiry-transport|expiry-data)[.]scope", e["unit"])
probes = []
for line in record["stdout"].splitlines():
    try:
        value = json.loads(line)
    except ValueError:
        continue
    if "owner_probe" in value:
        probes.append(value["owner_probe"])
assert len(probes) == 1
nonce = probes[0]["nonce"]
assert re.fullmatch("[a-f0-9]{64}", nonce)
port, known = {
    "debian-clean-x86_64": (22036, "target/platform-lab/debian-clean-x86_64/known_hosts"),
    "debian-x86_64": (22032, "target/lab-state/known_hosts"),
    "debian-arm64": (22034, "target/platform-lab/debian-arm64/known_hosts"),
    "arch-x86_64": (22033, "target/platform-lab/arch-x86_64/known_hosts"),
}[binding["platform"]]
script = r'''
import os,pathlib,json,hashlib,stat,subprocess,time
assert os.geteuid()==0
root=pathlib.Path('/var/lib/vprouter-v2-lab')
def regular(path):
 s=path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=1024*1024
noncepath=root/'owner-domain-nonce';regular(noncepath);assert noncepath.read_text()==NONCE
out={'observed_boottime':time.clock_gettime(7),'actors':[]}
for e in EXPECTED:
 p=pathlib.Path('/proc')/str(e['pid']);g=pathlib.Path('/sys/fs/cgroup/system.slice')/e['unit'];a={'expected':e,'proc_exists':p.exists(),'cgroup_exists':g.exists()}
 if p.exists():
  fields=(p/'stat').read_text().rsplit(') ',1)[1].split();a.update(state=fields[0],start=int(fields[19]),start_matches=int(fields[19])==e['start_time'])
  if a['start_matches']:a.update(cgroup=(p/'cgroup').read_text().strip(),exe=os.readlink(p/'exe'),exe_sha256=hashlib.sha256((p/'exe').read_bytes()).hexdigest())
 if g.exists():a.update(members=[int(x) for x in (g/'cgroup.procs').read_text().split()],inode=g.stat().st_ino)
 r=subprocess.run(['systemctl','show',e['unit'],'--property=LoadState','--value'],capture_output=True,text=True,timeout=4,check=True);a['load_state']=r.stdout.strip();out['actors'].append(a)
path=root/('owner-bootstrap-'+NONCE)/'records/namespaces.json';regular(path);doc=json.loads(path.read_text())
out['journal_entries']=doc['entries'];out['journal_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps(out))
'''
script = script.replace("NONCE", repr(nonce)).replace("EXPECTED", repr(intents))
result = subprocess.run(["ssh", "-i", "target/lab-state/id_ed25519", "-p" + str(port), "-o", "UserKnownHostsFile=" + known, "-o", "StrictHostKeyChecking=yes", "vprouterlab@127.0.0.1", "sudo -n python3 -I -"], input=script, capture_output=True, text=True, timeout=30)
assert result.returncode == 0, result.stderr
data = json.loads(result.stdout)
data.update(source_commit=binding["source_commit"], artifact_sha256=record["artifact_sha256"], record=str(record_path), record_sha256=hashlib.sha256(raw).hexdigest(), platform=binding["platform"], nonce=nonce)
destination = pathlib.Path(f"target/lab-state/expiry-drop-failed-actors-run-{run}.json")
with destination.open("x") as stream:
    json.dump(data, stream, indent=2)
    stream.write("\n")
print(json.dumps({"record": str(destination), "actors": data["actors"], "journal_entry_count": len(data["journal_entries"])}))
