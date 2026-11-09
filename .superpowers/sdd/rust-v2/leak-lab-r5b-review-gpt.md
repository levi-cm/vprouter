# Focused leak lab adversarial review R5b

Target: rust/v2, 819547b3c7664b757458024ed5bf869bb800ad6a. Offline stdlib review only; no runtime qualification. Report created before investigation and extended incrementally.

## 1. R5-C1 fix — earlier false PASS closed in executed probes

Evidence: `tools/leak-lab/pcapscan.py:1182-1221` validates unused word, quoted IPv4 version/IHL/protocol/fragment field, exact full-quote or 548-byte boundary, matching UDP length, declared WireGuard length, reverse endpoint tuple and reserved type bytes. `:757` checks outer trailers; `:849-865` checks L2 before counting quotes. `tools/leak-lab/test_leak_lab.py:4593-4658` supplies the new exactness regressions (the class starts at `:4520`).

Actually executed: `TMPDIR=/var/tmp/leaklab-r5b-gpt python3 -B -W error /var/tmp/leaklab-r5b-gpt/icmp.py`: **36 adversarial shapes × three positions = 108 full-scanner scans**, all expected results, plus accepted DF-handshake and valid 548-byte truncated-data controls. Re-ran old appended-secret, quoted total lengths 0/20/65535, UDP lengths 8/65535, four-byte type-1/type-4 and quoted MF/offset reproducers: all now LEAK, including before and after controls. Also rejected reserved/combined inner fragment flags, each byte of the unused word, truncation below/above 548, bytes appended after truncation, outer nonzero/zero trailers beyond IP length, oversized outer IP length, VLAN, outer MF and outer nonfirst fragments.

The 548-byte quotes declaring total lengths 549/550/600/65535 with matching UDP lengths and a type-4 prefix were accepted, as intended: all observed quoted bytes lie inside the declared datagram and the absent suffix is the explicitly allowed truncation. This did not reproduce bytes outside the datagram or an invalid declared WireGuard message shape. Synthetic fixtures use zero checksums as the existing tests do; this review does not establish cryptographic authenticity or live endpoint provenance.

Representative executed logic (imports `test_leak_lab as t`):

```python
q = t.IcmpQuoteAllowanceTests()
bad = t.ipv4_frame(q._raw_quote(t.wg_initiation(),
    trailer=b"REAL_IP=198.51.100.77;SECRET=synthetic-canary"), protocol=1)
for frames in (t.phase_frames(bad, t.wg_outbound(), t.wg_inbound()),
               [bad, *t.phase_frames(t.wg_outbound(), t.wg_inbound())],
               [*t.phase_frames(t.wg_outbound(), t.wg_inbound()), bad]):
    assert t.scan(frames, expect_tunnel="up")["verdict"] == "LEAK"
```

No Critical/Important ICMP allowance bypass reproduced. Suggested fix: none required for R5-C1 by these results; retain the exact-length and outside-window regressions.

Also reran appended-secret and zero quoted-total-length cases with recomputed inner IPv4, outer IPv4 and ICMP checksums: **six full-scanner scans, all LEAK** (three positions per case). Outer IP and ICMP checksum sums were asserted to be zero. Executed `checksums.py`:

```python
import sys,struct
from pathlib import Path
sys.path.insert(0,str(Path('tools/leak-lab').resolve()))
import test_leak_lab as t
q=t.IcmpQuoteAllowanceTests()
def checksum(b):
 b+=bytes(len(b)%2);total=sum(struct.unpack('!%dH'%(len(b)//2),b))
 while total>>16:total=(total&65535)+(total>>16)
 return (~total)&65535
for label,icmp in [('appended',q._raw_quote(t.wg_initiation(),trailer=b'REAL_IP=198.51.100.77;SECRET=synthetic-canary')),('length-zero',q._raw_quote(t.wg_initiation(),total_length=0))]:
 icmp=bytearray(icmp)
 icmp[18:20]=struct.pack('!H',checksum(bytes(icmp[8:28])))
 icmp[2:4]=struct.pack('!H',checksum(bytes(icmp)))
 frame=bytearray(t.ipv4_frame(bytes(icmp),protocol=1));frame[24:26]=struct.pack('!H',checksum(bytes(frame[14:34])))
 assert checksum(bytes(frame[14:34]))==0 and checksum(bytes(frame[34:]))==0
 for frames in (t.phase_frames(bytes(frame),t.wg_outbound(),t.wg_inbound()),[bytes(frame),*t.phase_frames(t.wg_outbound(),t.wg_inbound())],[*t.phase_frames(t.wg_outbound(),t.wg_inbound()),bytes(frame)]):
  assert t.scan(frames,expect_tunnel='up')['verdict']=='LEAK'
 print(label,'valid outer IP/ICMP checksums; LEAK in all three positions')
```

### Executed ICMP reproducer

Run from repository root after creating the scratch directory.

```python
import sys,struct,json
from pathlib import Path
sys.path.insert(0,str(Path('tools/leak-lab').resolve()))
import test_leak_lab as t
q=t.IcmpQuoteAllowanceTests(); init=t.wg_initiation(); secret=b'REAL_IP=198.51.100.77;SECRET=synthetic-canary'
cases={}
def add(n,icmp,**kw): cases[n]=t.ipv4_frame(icmp,protocol=1,**kw)
add('old appended quote',q._raw_quote(init,trailer=secret))
for n in (0,20,65535):add('old total '+str(n),q._raw_quote(init,total_length=n))
for n in (8,65535):add('old udp '+str(n),q._raw_quote(init,udp_length=n))
for k in (1,4):add('old four-byte '+str(k),q._raw_quote(bytes([k,0,0,0])))
for n in (0x8000,0x2000,1,0x6001,0xbfff):add('inner flags '+hex(n),q._raw_quote(init,frag_field=n))
for pos in range(4):
 unused=bytearray(4);unused[pos]=1;add('unused '+str(pos),q._raw_quote(init,unused=bytes(unused)))
for n in (547,549,550,600,65535):
 add('truncated 548 declaring '+str(n),q._raw_quote(t.wg_data(blocks=88),truncate_to=548,total_length=n,udp_length=n-20))
for cut in (32,100,400,547,549,550,600):add('truncation at '+str(cut),q._raw_quote(t.wg_data(blocks=88),truncate_to=cut))
add('truncation appended',q._raw_quote(t.wg_data(blocks=88),truncate_to=548,trailer=secret))
add('outer hidden trailer',q._quote()+secret,total_length=20+len(q._quote()))
add('outer zero trailer',q._quote()+bytes(8),total_length=20+len(q._quote()))
add('outer too long',q._quote(),total_length=500)
add('vlan',q._quote(),vlan=1)
add('outer MF',q._quote(),more_fragments=True)
add('outer offset',q._quote(),frag_units=1)
# These are deliberate accepted controls, including exact Linux truncated data.
controls={'valid DF':q._raw_quote(init,frag_field=0x4000),'valid truncated data':q._raw_quote(t.wg_data(blocks=88),truncate_to=548)}
expected_pass={'truncated 548 declaring '+str(n) for n in (549,550,600,65535)}
results=[]
for name,frame in cases.items():
 for where in ('inside','before','after'):
  middle=[t.wg_outbound(),t.wg_inbound()]
  frames=t.phase_frames(frame,*middle) if where=='inside' else ([frame,*t.phase_frames(*middle)] if where=='before' else [*t.phase_frames(*middle),frame])
  r=t.scan(frames,expect_tunnel='up'); want='PASS' if name in expected_pass else 'LEAK'
  assert r['verdict']==want,(name,where,r)
  results.append((name,where,r['verdict']))
for name,icmp in controls.items():assert q._scan(icmp)['verdict']=='PASS',name
print(json.dumps({'matrix_cases':len(cases),'positions':3,'scans':len(results),'expected_pass_cases':sorted(expected_pass),'all_expectations_met':True,'controls':list(controls)},sort_keys=True))
```

## 2. Image binding — config substitution refused; archive completeness remains weaker than identity

Evidence: `tools/leak-lab/vm/provision.py:208-222` recomputes manifest/config blob hashes and refuses linked blobs; `:233-254` traverses the pinned index; `:257-260` requires the resulting config set to equal the expected config. The check is called at `:468-474` before staging (`:523`). Deployment checks the requested config ID after load (`tools/leak-lab/vm/guest.py:912-914`), verifies it again before phase setup (`tools/leak-lab/vm/run_phase.py:1177-1193`, called at `:2894`) and writes that immutable ID as `image_ref` (`:514-520`).

Actually executed: `TMPDIR=/var/tmp/leaklab-r5b-gpt python3 -B -W error /var/tmp/leaklab-r5b-gpt/images.py`, using synthetic content-addressed tar files, with these results:

| Variant | verify_image_tar_chain result |
| --- | --- |
| Baseline pinned index/config | ACCEPTED |
| Different expected config | REFUSED |
| Second unannotated linux/amd64 manifest, different config | REFUSED |
| Second linux/amd64 manifest, same config | ACCEPTED |
| Extra layer descriptor (blob absent; config has no diff_ids) | ACCEPTED |
| Second runnable linux/amd64 image labeled attestation | ACCEPTED |
| Symlinked index.json to an in-archive regular file | ACCEPTED |
| Symlinked manifest blob | REFUSED |
| Duplicate manifest member: bad first, correct last | ACCEPTED |
| Duplicate manifest member: correct first, bad last | REFUSED (hash mismatch) |

### Minor R5b-M1 — ambiguous/incomplete archives pass the preflight verifier

Locations: `tools/leak-lab/vm/provision.py:213` uses tarfile's final matching member, `:233` follows an index.json link without the blob regular-file check, `:245-246` skips a runnable image solely on its attestation annotation, and `:250-254` never validates layer descriptors or their blobs. The executed table above reproduces all four behaviors. The same-config second manifest is collapsed by the config set.

Suggested fix: reject duplicate names and links for metadata, require one runnable platform manifest, validate attestation platform and content rather than trusting its label, and verify layer hashes and the config diff_ids chain if this check is intended to prove archive completeness. Retain a separate immutable config-ID check at deployment.

These are preflight acceptance gaps, **not a reproduced different-image deployment**. Every synthetic variant has its own pinned index digest: changing index content cannot preserve a fixed production pin without a hash collision. A different runnable config is detected unless skipped as an attestation; even then the expected config is still present and remains the requested deployment ID. An extra layer inconsistent with that config should be refused by the image loader. Docker execution was forbidden, so loader behavior and actual substituted deployment are NOT_RUN. Do not promote archive acceptance to proof that a different image runs, or promote this offline review to deployment qualification.

### Executed image reproducer

```python
import sys,json,hashlib,io,tarfile
from pathlib import Path
sys.path.insert(0,str(Path('tools/leak-lab/vm').resolve()))
import provision as p,hostcheck
root=Path('/var/tmp/leaklab-r5b-gpt')
M='application/vnd.oci.image.manifest.v1+json'
results={}
def check(kind):
 blobs={}
 def blob(doc):
  data=json.dumps(doc,sort_keys=True).encode();d='sha256:'+hashlib.sha256(data).hexdigest();blobs['blobs/sha256/'+d[7:]]=data;return d
 cfg=blob({'architecture':'amd64','os':'linux','rootfs':{'type':'layers','diff_ids':[]}})
 other=blob({'architecture':'amd64','os':'linux','config':{'Cmd':['different-image']},'rootfs':{'type':'layers','diff_ids':[]}})
 manifest={'schemaVersion':2,'mediaType':M,'config':{'digest':cfg},'layers':[]}
 if kind=='extra layer':manifest['layers']=[{'digest':'sha256:'+'a'*64,'size':123,'mediaType':'application/vnd.oci.image.layer.v1.tar'}]
 md=blob(manifest)
 entries=[{'mediaType':M,'digest':md,'platform':{'os':'linux','architecture':'amd64'}}]
 if kind in ('second image','fake attestation','second same config'):
  second=blob({'schemaVersion':2,'mediaType':M,'config':{'digest':cfg if kind=='second same config' else other},'layers':[], 'annotations':{'probe':'second'}})
  entry={'mediaType':M,'digest':second,'platform':{'os':'linux','architecture':'amd64'}}
  if kind=='fake attestation':entry['annotations']={'vnd.docker.reference.type':'attestation-manifest'}
  entries.append(entry)
 idx=blob({'schemaVersion':2,'manifests':entries})
 top=json.dumps({'schemaVersion':2,'manifests':[{'digest':idx}]}).encode()
 path=root/(kind.replace(' ','-')+'.tar')
 with tarfile.open(path,'w') as tar:
  def put(n,d):
   info=tarfile.TarInfo(n);info.size=len(d);tar.addfile(info,io.BytesIO(d))
  if kind=='symlink index':
   put('real-index.json',top);info=tarfile.TarInfo('index.json');info.type=tarfile.SYMTYPE;info.linkname='real-index.json';tar.addfile(info)
  else:put('index.json',top)
  member='blobs/sha256/'+md[7:]
  if kind=='duplicate good last':put(member,b'{"different":"manifest"}')
  for name,data in blobs.items():
   if kind=='symlink blob' and name==member:
    put('real-manifest',data);info=tarfile.TarInfo(name);info.type=tarfile.SYMTYPE;info.linkname='real-manifest';tar.addfile(info)
   else:put(name,data)
  if kind=='duplicate bad last':put(member,b'{"different":"manifest"}')
 try:p.verify_image_tar_chain(path,idx,other if kind=='wrong config' else cfg)
 except hostcheck.Refusal as e:results[kind]='REFUSED: '+str(e)
 else:results[kind]='ACCEPTED'
for kind in ['baseline','wrong config','extra layer','second image','second same config','fake attestation','symlink index','symlink blob','duplicate good last','duplicate bad last']:check(kind)
assert results['wrong config'].startswith('REFUSED')
assert results['second image'].startswith('REFUSED')
assert results['symlink blob'].startswith('REFUSED')
assert results['duplicate bad last'].startswith('REFUSED')
print(json.dumps(results,sort_keys=True,indent=2))
```

## 3. Readiness diagnostic follow-up and refusal preservation

The Important finding below was also reproduced through the real `run_phase` orchestration with the existing offline `RunPhaseTests._run` harness: phase `stop-router`, readiness gate forced to refuse, synthetic health supplied to the real diagnostic helper, and a clean scanner report. The persisted **phase.json contained the full IPv4/hostname/segmented-token reason**. Stdout/stderr contained none of those injected values. The result was exit **2 / INVALID**, while the separate scan verdict remained PASS.

Two more actually executed runs forced (a) a diagnostic TypeError and (b) an actual unhashable JSON health state (`state: []`) inside `record_readiness_refusal`. Both returned exit **2 / INVALID**, `errors=["phase_exception:TypeError"]`, despite scanner PASS. The normal refusal returned `errors=["router_not_ready"]`. Evidence: `tools/leak-lab/vm/run_phase.py:2993-2997` records setup failure, `:3123-3125` catches phase exceptions, and `:3287-3298` prevents PASS when errors exist. No diagnostic path turning refusal into PASS was reproduced.

### Minor R5b-M2 — malformed health state breaks diagnostics, but fails closed

Location: `tools/leak-lab/vm/run_phase.py:1540`. JSON arrays/objects are unhashable and the set-membership test raises outside the diagnostic try/except. The executed `diagnostics.py` third full-phase run supplied `{"state": [], "reason": "READY"}` and got INVALID with TypeError instead of a useful refusal diagnostic. Suggested fix: require `isinstance(state, str)` before set membership and keep the entire diagnostic parsing/normalization block exception-contained. This is a diagnostic reliability issue, not a false PASS.

### Important R5b-I1 — readiness reasons disclose addresses, hostnames, and segmented tokens

Evidence: `tools/leak-lab/vm/run_phase.py:1502-1514` allows dots, colons and hyphens and rejects only contiguous alphanumeric runs of 20+ characters. `:1539-1542` copies filtered guest health reasons into the phase record; `:3300` persists that record. This is not a closed vocabulary.

Actually executed: `TMPDIR=/var/tmp/leaklab-r5b-gpt python3 -B -W error /var/tmp/leaklab-r5b-gpt/diagnostics.py` (stdlib, synthetic fake QGA). `_safe_text` returned each of the following unchanged:

- `peer 198.51.100.77:51820 host router-private.example`
- `peer 2001:db8::1234`
- `tskey-auth-abcdefghijklmno-pqrstuvwxyz012345` (synthetic segmented token, not a real credential)
- `token 12345678-1234-1234-1234-123456789abc`

A fake health document `{state: BLOCKED, reason: <first string plus token>}` passed through `record_readiness_refusal` unchanged into `readiness.release_health_reason`. No real secret was read. Conventional base64 WireGuard keys and complete HTTPS auth URLs were rejected as `unrecognized`; this does not make the general token/address filter safe. BackendState used the fixed vocabulary and became `unrecognized` for the same injected text. These findings establish disclosure into phase.json, not a stdout disclosure or false PASS.

Suggested fix: record fixed runner-defined reason codes (or an explicit allowlist of complete known release reasons), rather than arbitrary guest prose filtered by character/length heuristics. Keep any necessary raw detail in a separately protected operator-only artifact. Add regressions for IPv4, IPv6, hostname, UUID and segmented tokens.

### Executed diagnostics reproducer

```python
import sys,json,io,contextlib
from pathlib import Path
from unittest import mock
sys.path.insert(0,str(Path('tools/leak-lab').resolve()))
sys.path.insert(0,str(Path('tools/leak-lab/vm').resolve()))
import run_phase as r, test_vm as v, guest,hostcheck
samples=['peer 198.51.100.77:51820 host router-private.example','peer 2001:db8::1234','tskey-auth-abcdefghijklmno-pqrstuvwxyz012345','token 12345678-1234-1234-1234-123456789abc','yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=','https://login.tailscale.com/a/0123456789abcdef']
for x in samples: print('SAFE',repr(x),repr(r._safe_text(x)))
class C:
 def execute(self,*args,**kwargs):
  return r.ExecResult(exitcode=0,stdout=json.dumps({'state':'BLOCKED','reason':samples[0]+' '+samples[2]}).encode(),stderr=b'')
record={'tailscale':{}}
with mock.patch.object(r,'read_tailscale_status',return_value={'BackendState':samples[0],'Self':{'Online':True,'ExitNodeOption':False,'HostName':samples[0]}}):
 r.record_readiness_refusal(record,C(),guest.DEFAULT_NAME,hostcheck.Refusal('the release did not report READY'))
print('RECORD',json.dumps(record,sort_keys=True))
original=r.record_readiness_refusal
def inject(rec,*args):
 with mock.patch.object(r,'read_tailscale_status',return_value={'BackendState':samples[0],'Self':{'Online':True,'ExitNodeOption':False}}):
  original(rec,C(),guest.DEFAULT_NAME,hostcheck.Refusal('readiness failed'))
for mode in ('normal','diagnostic exception','unhashable health state'):
 case=v.RunPhaseTests();case.setUp()
 try:
  diagnostic=inject if mode=='normal' else (lambda *a: (_ for _ in ()).throw(TypeError('synthetic diagnostic failure')))
  if mode=='unhashable health state':
   class BadC:
    def execute(self,*a,**kw):return r.ExecResult(exitcode=0,stdout=b'{"state":[],"reason":"READY"}',stderr=b'')
   diagnostic=lambda rec,*a:original(rec,BadC(),guest.DEFAULT_NAME,hostcheck.Refusal('readiness failed'))
  with mock.patch.object(r,'wait_router_ready',side_effect=hostcheck.Refusal('the release did not report READY')),mock.patch.object(r,'record_readiness_refusal',side_effect=diagnostic):
   code,rec,client,events,out,err,directory=case._run('stop-router')
  text=(directory/guest.PHASE_RECORD_FILE).read_text()
  assert code==2 and rec['result']=='INVALID' and rec['scan']['verdict']=='PASS'
  if mode=='normal':
   assert samples[0] in text and samples[2] in text
   assert all(x not in out+err for x in samples)
  print('PHASE',mode,'exit',code,'result',rec['result'],'scan',rec['scan']['verdict'],'errors',rec['errors'],'stdout',out.strip())
 finally:
  case.tearDown();case.doCleanups()
```

Required suites were each invoked exactly once from `tools/leak-lab`, with `TMPDIR=/var/tmp/leaklab-r5b-gpt`:

- `python3 -B -W error -m unittest test_leak_lab`: **265 tests, OK**, 8.581 s.
- `python3 -B -W error -m unittest vm.test_vm`: **202 tests, OK**, 10.564 s.
- Total: **467 tests**, no failures/errors/skips reported.

Scratch directory `/var/tmp/leaklab-r5b-gpt` deleted after all probes. Reproducer sources are embedded above so they remain reviewable. Only this report was modified in the repository; no Git writes, privileged tools, network execution or live lab operations were performed. Baseline and final tracked worktree status were clean (the report path is ignored).

Verdict: FAIL (Important R5b-I1).
