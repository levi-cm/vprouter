import pathlib,subprocess,json,shlex
r=pathlib.Path.cwd();base=r/'target/lab-state';out=r/'target/platform-lab/proc-remount-race.json'
child=r'''import os,subprocess,json
subprocess.run(['mount','-o',OPTIONS,'/proc'],check=True)
try:fd=os.open('/proc/self/attr/current',os.O_WRONLY|os.O_CLOEXEC);os.close(fd);e=0
except OSError as ex:e=ex.errno
print(json.dumps({'child_open_write_errno':e}))
'''
parent=r'''import os,subprocess,json,pathlib
def probe():
 try:fd=os.open('/proc/self/attr/current',os.O_WRONLY|os.O_CLOEXEC);os.close(fd);return0=0
 except OSError as e:return0=e.errno
 return return0
before=probe()
code=CHILD
p=subprocess.run(['unshare','--mount','python3','-c',code],capture_output=True,text=True,check=True)
print(json.dumps({'options':OPTIONS,'parent_open_write_errno_before':before,'child':json.loads(p.stdout),'parent_open_write_errno_after':probe(),'parent_proc_mounts':[l for l in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if l.split(' - ')[0].split()[4]=='/proc']},indent=2))
'''
ssh=['ssh','-i',str(base/'id_ed25519'),'-p22032','-o','UserKnownHostsFile='+str(base/'known_hosts'),'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','vprouterlab@127.0.0.1','sudo unshare --mount --pid --fork --mount-proc python3 -']
rows=[]
for options in ['remount,ro,nosuid,nodev,noexec','remount,bind,ro,nosuid,nodev,noexec']:
 c=child.replace('OPTIONS',repr(options));code=parent.replace('CHILD',repr(c)).replace('OPTIONS',repr(options));p=subprocess.run(ssh,input=code,capture_output=True,text=True,timeout=15);assert p.returncode==0,p.stderr;rows.append(json.loads(p.stdout))
value={'scope':'separate owned disposable PID/mount namespaces; no profile writes or network changes','observations':rows};out.write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value,indent=2))
assert rows[0]['parent_open_write_errno_before']==0 and rows[0]['parent_open_write_errno_after']==30
assert rows[1]['parent_open_write_errno_before']==0 and rows[1]['parent_open_write_errno_after']==0
assert all(x['child']['child_open_write_errno']==30 for x in rows)
