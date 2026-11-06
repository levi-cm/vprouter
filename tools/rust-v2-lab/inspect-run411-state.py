#!/usr/bin/env python3
"""Read-only fresh-run411 snapshot, including early/no-raw controller failures.

No archival authority: incomplete identities are recorded as unavailable. Use the
strict historical inspector/archiver only when their original inputs exist.
"""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

REMOTE = r'''
import hashlib,json,os,pathlib,stat,subprocess
if not __debug__:raise RuntimeError('optimized_python_refused')
assert os.geteuid()==0
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();assert boot==EXPECTED_BOOT
root=pathlib.Path('/var/lib/vprouter-v2-lab');s=root.lstat()
assert stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o700
out={'guest_boot_id':boot,'selectors':{},'owner':None,'gateway':None,'private_profile_contents_read':False,'read_only':True}
for name in ('owner-domain-nonce','secret-attachment.json','secret-attachment-spec.json','secret-attachment-staging.json','secret-quarantine-host.json','secret-host-baseline.json','task8b2-image','task8b2-host-acceptance'):
 p=root/name
 if not os.path.lexists(p):out['selectors'][name]={'present':False};continue
 s=p.lstat();row={'present':True,'dev':s.st_dev,'ino':s.st_ino,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'nlink':s.st_nlink,'size':s.st_size}
 # Refuse unsafe files without following links or reading arbitrary content.
 if stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=1024*1024:
  data=p.read_bytes();row['sha256']=hashlib.sha256(data).hexdigest()
  try:row['public_content']=data.decode()if name=='owner-domain-nonce'else json.loads(data)
  except (ValueError,UnicodeDecodeError):row['public_content_status']='unparseable'
 else:row['public_content_status']='unsafe_not_read'
 out['selectors'][name]=row
if UNIT is not None:
 r=subprocess.run(['systemctl','show',UNIT,'--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,InvocationID','--no-pager'],capture_output=True,text=True,timeout=5)
 group=pathlib.Path('/sys/fs/cgroup/system.slice')/UNIT
 out['owner']={'unit':UNIT,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'cgroup_exists':group.exists()}
 if group.exists():s=group.stat();out['owner']['cgroup_identity']=[s.st_dev,s.st_ino];out['owner']['cgroup_procs']=(group/'cgroup.procs').read_text()
if GATEWAY is not None:
 import select
 expected=GATEWAY;r=subprocess.run(['docker','inspect','--format','{{json .State}}',expected['container_id']],capture_output=True,text=True,timeout=8)
 out['gateway']={'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'original_identity_matches':False}
 if r.returncode==0:
  state=json.loads(r.stdout);pin=os.pidfd_open(expected['pid'],0)
  try:
   raw=pathlib.Path('/proc',str(expected['pid']),'stat').read_text();start=int(raw[raw.rfind(')')+2:].split()[19]);ns=pathlib.Path('/proc',str(expected['pid']),'ns/net').stat()
   out['gateway']['original_identity_matches']=state['Running']is True and state['Pid']==expected['pid']and state['StartedAt']==expected['started_at']and start==expected['start']and [ns.st_dev,ns.st_ino]==expected['source_namespace']and not select.select([pin],[],[],0)[0]
  finally:os.close(pin)
print(json.dumps(out))
'''


def main():
    assert len(sys.argv)==2
    spec=importlib.util.spec_from_file_location('state_reservation','tools/rust-v2-lab/run411-reservation.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    m.freeze_inputs()
    m.allowed_path(sys.argv[1])
    r=m.validate_bindings(m.active());claim=m.protected(m.CLAIM)
    assert claim['run']==411 and claim['budget_remaining']==0 and claim['reservation_sha256']==m.sha(m.RESERVATION)and claim['controller_boot_id']==r['controller_boot_id']
    cp=pathlib.Path(r['candidate'])
    q=m.load_module('state_provenance','tools/rust-v2-lab/run411-provenance.py')
    template=json.loads(m.read_bytes(cp.parent/('authored-host-baseline-'+r['platform']+'.json')))
    review=json.loads(m.read_bytes(cp.parent/('host-baseline-reconciliation-'+r['platform']+'.json')));candidate=json.loads(m.read_bytes(cp))
    q.validate_fresh_provenance(template,review,candidate)
    unit=None;gateway=None
    m.allowed_path(m.RUN)
    if m.RUN.exists():
        record=json.loads(m.read_bytes(m.RUN))
        q.validate_fresh_provenance(template,review,candidate,record)
        for line in record['stdout'].splitlines():
            try:v=json.loads(line)
            except ValueError:continue
            if not isinstance(v,dict):continue
            if 'owner_probe'in v:unit=v['owner_probe']['unit']
            if 'secret_attachment_gateway'in v:gateway=v['secret_attachment_gateway']
    import re
    if unit is not None:assert re.fullmatch('vprouter-v2-owner@[a-f0-9]{64}[.]service',unit)
    script=REMOTE.replace('EXPECTED_BOOT',repr(r['guest_boot_id'])).replace('UNIT',repr(unit)).replace('GATEWAY',repr(gateway))
    compile(script,'run411-state-remote','exec')
    def diagnostic(value):return value.decode(errors='replace')if isinstance(value,bytes)else value or ''
    error_fields={}
    try:
        with m.ssh_material('target/lab-state/id_ed25519','target/platform-lab/debian-arm64/known_hosts') as (identity,known_hosts):
            ssh=['ssh','-F','/dev/null','-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','BatchMode=yes','-o','UpdateHostKeys=no','-i',identity,'-p22034','-o','UserKnownHostsFile='+known_hosts,'-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','vprouterlab@127.0.0.1','sudo -n python3 -I -']
            result=subprocess.run(ssh,input=script,capture_output=True,text=True,timeout=30)
        code,stdout,stderr=result.returncode,result.stdout,result.stderr
    except (subprocess.TimeoutExpired,OSError) as error:
        code=124 if isinstance(error,subprocess.TimeoutExpired)else 125
        stdout=diagnostic(getattr(error,'stdout',None));stderr=diagnostic(getattr(error,'stderr',None))
        error_fields=dict(error_type=type(error).__name__,error=str(error),
                          error_classification='transport_timeout'if code==124 else'transport_start_error')
    receipt=dict(argv=locals().get('ssh'),exit_code=code,stdout=stdout,stderr=stderr,**error_fields,
                 reservation_sha256=m.sha(m.RESERVATION),raw_record_sha256=m.sha(m.RUN)if m.RUN.exists()else None,
                 read_only=True,archival_authorized=False,runtime_acceptance=False)
    m.save(pathlib.Path(sys.argv[1]),receipt)
    print(json.dumps(receipt));return code


if __name__=='__main__':sys.exit(main())
