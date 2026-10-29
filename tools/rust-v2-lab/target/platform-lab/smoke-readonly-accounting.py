"""Root-only instrumentation smoke in fresh, exclusive Debian lab cgroups.

No traffic, provider, identity, service, product code or functional-run counter.
Only the natively retained test cgroups are removed after actual direct-child
reap and empty readback. Any failure keeps remaining artifacts and resources.
"""
import base64
import hashlib
import json
import pathlib
import subprocess
import uuid


source = pathlib.Path("target/platform-lab/readonly-accounting.guest.py").read_bytes()
digest = hashlib.sha256(source).hexdigest()
nonce = uuid.uuid4().hex
output = pathlib.Path("target/lab-state") / ("accounting-smoke-" + nonce)
output.mkdir(mode=0o700)
guest = r'''
import contextlib,datetime,hashlib,io,json,os,pathlib,select,stat,subprocess,sys,time,types
assert os.geteuid()==0
assert hashlib.sha256(payload).hexdigest()==digest
root=pathlib.Path('/var/lib/vprouter-v2-lab')
assert stat.S_IMODE(root.stat().st_mode)==0o700
directory=root/('accounting-smoke-'+nonce)
directory.mkdir(mode=0o700)
script=directory/'collector.py'
fd=os.open(script,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o500)
with os.fdopen(fd,'wb') as f:f.write(payload);f.flush();os.fsync(f.fileno())
assert hashlib.sha256(script.read_bytes()).hexdigest()==digest
events=(directory/'events.jsonl').open('x')
def event(**value):
 events.write(json.dumps(value)+'\n');events.flush();os.fsync(events.fileno())
def native(fd):
 s=os.fstat(fd);return [s.st_dev,s.st_ino]
def created(name):
 path=pathlib.Path('/sys/fs/cgroup')/name;path.mkdir()
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
 event(event='exclusive_cgroup_created',relative=name,native_identity=native(fd))
 return path,fd
def remove_exact(path,fd):
 s=path.stat();assert [s.st_dev,s.st_ino]==native(fd)
 assert not (path/'cgroup.procs').read_text().strip()
 path.rmdir();event(event='exact_empty_cgroup_removed',relative=path.name,native_identity=native(fd))
def manifest(name,value):
 path=directory/name
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f);f.flush();os.fsync(f.fileno())
 return path
def run(name,value,optimized=False):
 path=manifest(name+'.json',value)
 argv=[sys.executable,'-I']+(['-O'] if optimized else [])+[str(script),str(path),'--seconds','1']
 r=subprocess.run(argv,capture_output=True,text=True,timeout=10)
 (directory/(name+'.stdout')).write_text(r.stdout);(directory/(name+'.stderr')).write_text(r.stderr)
 rows=[json.loads(line) for line in r.stdout.splitlines()]
 event(event='collector_case_completed',case=name,exit_code=r.returncode,kinds=[v['kind'] for v in rows])
 return r,rows
group_name='vpracct-'+nonce[:16]
group,group_fd=created(group_name)
probe=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(6)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
pidfd=os.pidfd_open(probe.pid,0)
proc=pathlib.Path('/proc',str(probe.pid));raw=(proc/'stat').read_text();start=int(raw[raw.rfind(')')+2:].split()[19])
event(event='native_probe_birth',pid=probe.pid,start=start,retained_pidfd=True)
# This is our own unreaped direct child, retained Popen plus pidfd; no observed
# or reusable numeric PID grants placement authority.
(group/'cgroup.procs').write_text(str(probe.pid))
assert (proc/'cgroup').read_text()=='0::/'+group_name+'\n'
assert (group/'cgroup.procs').read_text().split()==[str(probe.pid)]
exe=os.open(proc/'exe',os.O_RDONLY|os.O_CLOEXEC)
before=os.fstat(exe);h=hashlib.sha256()
while True:
 block=os.read(exe,1048576)
 if not block:break
 h.update(block)
after=os.fstat(exe);assert (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns);os.close(exe)
value=dict(schema=1,boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),groups=[dict(role='smoke',relative=group_name,native_identity=native(group_fd))],executable_labels={h.hexdigest():'workload'},workload_binding_sha256=hashlib.sha256(b'accounting-smoke-only').hexdigest())
r,rows=run('positive',value);assert r.returncode==0 and rows[0]['kind']=='begin' and rows[-1]['kind']=='end'
samples=[v for v in rows if v['kind']=='sample'];assert len(samples)>=2
for row in samples:
 assert not row['duplicate_process_identities']
 processes=row['groups'][0]['processes'];assert len(processes)==1
 p=processes[0];assert p['pid']==probe.pid and p['start']==start and p['label']=='workload' and p['pss_kib']>0
 assert row['groups'][0]['pss_kib']==p['pss_kib']
 assert row['pss_sum_valid'] and row['total_cohort_pss_kib']==p['pss_kib']
 g=row['groups'][0];assert g['counters_read_started_boottime_ns']<=g['counters_read_finished_boottime_ns']
 completion=next(v for v in rows if v['kind']=='sample_complete' and v['sequence']==row['sequence'])
 assert completion['read_started_boottime_ns']<=row['whole_host_read_started_boottime_ns']<=row['whole_host_read_finished_boottime_ns']<=completion['read_finished_boottime_ns']<=completion['sample_flush_finished_boottime_ns']
 assert completion['observer_cpu_seconds_through_sample_flush']>=row['observer_cpu_seconds']
assert not rows[-1]['ten_minute_duration_met'] and not rows[-1]['full_day_duration_met']
wrong=json.loads(json.dumps(value));wrong['groups'][0]['native_identity'][1]+=1
r,rows=run('wrong-native',wrong);assert r.returncode!=0 and rows[-1]['kind']=='incomplete' and not any(v['kind']=='sample' for v in rows)
overlap=json.loads(json.dumps(value));duplicate=dict(overlap['groups'][0]);duplicate['role']='overlap';overlap['groups'].append(duplicate)
r,rows=run('overlap',overlap);assert r.returncode!=0 and rows[-1]['kind']=='incomplete' and not any(v['kind']=='sample' for v in rows)
r,rows=run('optimized-python',value,True);assert r.returncode!=0 and rows[-1]['kind']=='incomplete' and not any(v['kind']=='sample' for v in rows)
# Native race tests use driver-only read-boundary wrappers. They change actual
# process/cohort objects, never fabricated collector replies or product flags.
module=types.ModuleType('readonly_accounting_native_test')
exec(compile(payload,str(script),'exec'),module.__dict__)
second,second_fd=created(group_name+'-b')
original_read=module.read_at
migrated=[False]
def migrate_on_pss(directory,name,limit=1048576):
 if name=='smaps_rollup' and not migrated[0]:
  assert probe.poll() is None
  (second/'cgroup.procs').write_text(str(probe.pid));migrated[0]=True
 return original_read(directory,name,limit)
module.read_at=migrate_on_pss
row,reason=module.process_sample(probe.pid,group_name,value['executable_labels'],{})
assert migrated[0] and row is None and reason=='cohort_membership_changed'
event(event='native_membership_change_rejected',pid=probe.pid,start=start,reason=reason)
module.read_at=original_read
(group/'cgroup.procs').write_text(str(probe.pid))
both=json.loads(json.dumps(value));both['groups'].append(dict(role='second',relative=second.name,native_identity=native(second_fd)))
both_path=manifest('duplicate-native.json',both)
original_sample=module.sample_group;shifted=[False]
def migrate_after_first_group(fd,entry,labels,cache):
 row=original_sample(fd,entry,labels,cache)
 if entry['role']=='smoke' and not shifted[0]:
  assert probe.poll() is None
  (second/'cgroup.procs').write_text(str(probe.pid));shifted[0]=True
 return row
module.sample_group=migrate_after_first_group
old_argv=sys.argv;sys.argv=[str(script),str(both_path),'--seconds','1','--interval','0.25'];captured=io.StringIO()
try:
 with contextlib.redirect_stdout(captured):module.main()
finally:sys.argv=old_argv;module.sample_group=original_sample
(directory/'duplicate-native.stdout').write_text(captured.getvalue())
duplicate_rows=[json.loads(line) for line in captured.getvalue().splitlines()]
first=next(v for v in duplicate_rows if v['kind']=='sample')
assert first['duplicate_process_identities']==[dict(pid=probe.pid,start=start)]
assert not first['pss_sum_valid'] and first['total_cohort_pss_kib'] is None
event(event='actual_cross_cohort_duplicate_sum_invalidated',pid=probe.pid,start=start)
status=probe.wait(timeout=10);assert status==0
event(event='native_probe_actual_waitpid',pid=probe.pid,start=start,return_code=status)
os.close(pidfd);remove_exact(group,group_fd);os.close(group_fd);remove_exact(second,second_fd);os.close(second_fd)
# Same PID/start exec between the retained initial exe and the PSS read must
# not let new-image memory inherit the old executable label.
exec_group,exec_group_fd=created(group_name+'-e')
read_gate,write_gate=os.pipe2(os.O_CLOEXEC)
exec_source='import os; print("READY",flush=True); os.read('+str(read_gate)+',1); os.execl("/usr/bin/sleep","sleep","3")'
exec_probe=subprocess.Popen([sys.executable,'-I','-c',exec_source],pass_fds=(read_gate,),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
exec_pidfd=os.pidfd_open(exec_probe.pid,0);os.close(read_gate)
assert select.select([exec_probe.stdout],[],[],5)[0] and exec_probe.stdout.readline()==b'READY\n'
exec_proc=pathlib.Path('/proc',str(exec_probe.pid));raw=(exec_proc/'stat').read_text();exec_start=int(raw[raw.rfind(')')+2:].split()[19])
event(event='native_exec_probe_birth',pid=exec_probe.pid,start=exec_start,retained_pidfd=True)
(exec_group/'cgroup.procs').write_text(str(exec_probe.pid))
target=pathlib.Path('/usr/bin/sleep').stat();released=[False]
def exec_on_pss(directory,name,limit=1048576):
 if name=='smaps_rollup' and not released[0]:
  os.write(write_gate,b'x');released[0]=True;end=time.monotonic()+2
  while True:
   current=(exec_proc/'exe').stat()
   if (current.st_dev,current.st_ino)==(target.st_dev,target.st_ino):break
   assert time.monotonic()<end;time.sleep(0.001)
 return original_read(directory,name,limit)
module.read_at=exec_on_pss
try:row,reason=module.process_sample(exec_probe.pid,exec_group.name,value['executable_labels'],{})
finally:module.read_at=original_read
assert released[0] and row is None and reason=='executable_changed'
exec_status=exec_probe.wait(timeout=5);assert exec_status==0
event(event='native_exec_change_rejected_actual_waitpid',pid=exec_probe.pid,start=exec_start,reason=reason,return_code=exec_status)
exec_probe.stdout.close();os.close(write_gate);os.close(exec_pidfd);remove_exact(exec_group,exec_group_fd);os.close(exec_group_fd)
# Replacement after the group read, even during the final sample, must fail
# the same iteration's post-read native identity check.
post_group,post_fd=created(group_name+'-p');replacement_pin=[]
post_value=json.loads(json.dumps(value));post_value['groups'][0].update(relative=post_group.name,native_identity=native(post_fd))
post_path=manifest('post-sample-replacement.json',post_value)
def replace_after_sample(fd,entry,labels,cache):
 row=original_sample(fd,entry,labels,cache);remove_exact(post_group,post_fd)
 path,pin=created(post_group.name);replacement_pin.append((path,pin));return row
module.sample_group=replace_after_sample
old_argv=sys.argv;sys.argv=[str(script),str(post_path),'--seconds','1'];captured=io.StringIO();rejected=False
try:
 with contextlib.redirect_stdout(captured):module.main()
except AssertionError:rejected=True
finally:sys.argv=old_argv;module.sample_group=original_sample
assert rejected and len(replacement_pin)==1
(directory/'post-sample-replacement.stdout').write_text(captured.getvalue())
assert not any(json.loads(line)['kind']=='sample' for line in captured.getvalue().splitlines())
path,pin=replacement_pin[0];remove_exact(path,pin);os.close(pin);os.close(post_fd)
event(event='post_sample_native_replacement_rejected')
# Empty cgroup replacement demonstrates that an open old directory handle and
# a reused pathname cannot silently supply a new measurement cohort.
replacement_name=group_name+'-r';replacement,old_fd=created(replacement_name)
changing=json.loads(json.dumps(value));changing['groups'][0].update(relative=replacement_name,native_identity=native(old_fd))
path=manifest('replacement.json',changing)
process=subprocess.Popen([sys.executable,'-I',str(script),str(path),'--seconds','2','--interval','0.5'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
initial=[]
for kind in ['begin','sample']:
 deadline=time.monotonic()+5;parts=[]
 while True:
  assert select.select([process.stdout],[],[],max(0,deadline-time.monotonic()))[0]
  byte=os.read(process.stdout.fileno(),1);assert byte
  parts.append(byte);assert len(parts)<=1048576
  if byte==b'\n':break
 line=b''.join(parts).decode();initial.append(line);assert json.loads(line)['kind']==kind
remove_exact(replacement,old_fd)
replacement,new_fd=created(replacement_name);assert native(new_fd)!=native(old_fd)
stdout,stderr=process.communicate(timeout=5);stdout=''.join(initial)+stdout.decode();stderr=stderr.decode()
(directory/'replacement.stdout').write_text(stdout);(directory/'replacement.stderr').write_text(stderr)
rows=[json.loads(line) for line in stdout.splitlines()]
assert process.returncode!=0 and rows[-1]['kind']=='incomplete'
assert len([v for v in rows if v['kind']=='sample'])==1
event(event='replacement_rejected',exit_code=process.returncode,old_native_identity=native(old_fd),new_native_identity=native(new_fd))
remove_exact(replacement,new_fd);os.close(new_fd);os.close(old_fd)
result=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),collector_sha256=digest,retained_directory=str(directory),cases=['native-process-pss-positive','wrong-native-rejected','overlap-rejected','optimized-python-rejected','native-membership-change-rejected','native-exec-change-rejected','actual-cross-cohort-duplicate-sum-invalidated','post-sample-replacement-rejected','mid-run-replacement-rejected'],probe=dict(pid=probe.pid,start=start,actual_waitpid_return_code=status),exec_probe=dict(pid=exec_probe.pid,start=exec_start,actual_waitpid_return_code=exec_status),remaining_test_cgroups=False,scope='instrumentation smoke only; no ten-minute workload or soak acceptance')
(directory/'result.json').write_text(json.dumps(result,indent=2)+'\n');events.close();print(json.dumps(result))
'''
prefix = "import base64\npayload=base64.b64decode(" + repr(base64.b64encode(source).decode()) + ")\ndigest=" + repr(digest) + "\nnonce=" + repr(nonce) + "\n"
command = ["ssh", "-i", "target/lab-state/id_ed25519", "-p22032", "-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=target/lab-state/known_hosts", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=5", "vprouterlab@127.0.0.1", "sudo -n python3 -I -"]
result = subprocess.run(command, input=prefix + guest, text=True, capture_output=True, timeout=40)
(output / "ssh.stdout").write_text(result.stdout)
(output / "ssh.stderr").write_text(result.stderr)
record = dict(collector_sha256=digest, nonce=nonce, ssh_exit_code=result.returncode,
              scope="instrumentation smoke only; no network/product/provider/client acceptance")
if result.returncode == 0:
    record["result"] = json.loads(result.stdout)
with (output / "record.json").open("x") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
print(json.dumps(dict(output=str(output), **record)))
raise SystemExit(result.returncode)
