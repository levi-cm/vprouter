# M3 focused adversarial review

Commit: b849e3cc40eabecd2fecf7e67171842c4156bfd6 (rust/v2).
Scope: client verdict scanners, run-phase client flow/combination, and their offline tests. Binding design read fully. Initial checkout clean. Offline review only; no guest, network, or privileged execution.

Findings are appended as reproduced. Final coverage and verdict follow below.

## Critical C1 — Forged controls and reordered records can satisfy the client capture proof

Location: `tools/leak-lab/clientscan.py:74-85`, `:213-225`.

Actual offline reproducer: imported `test_leak_lab` helpers and called `scan_client_capture` with valid pcap headers, zero-drop/count-matching client stats, correctly bound client argv and one router WireGuard frame. The client pcap contained just two records whose entire frame bytes were `b"VPRLEAKCTL1:" + NONCE_A.encode()` and the equivalent NONCE_B payload. These are not Ethernet/IPv4/UDP frames at all. Result: **PASS**, empty invalid reasons. No client-originated datagram was proved. A second fixture placed valid after-control then before-control frames in record order, with timestamps `[1700000002,1700000001]`; result: **PASS**. The scanner checks only byte substrings and increasing control timestamps, not packet identity or record order.

Suggested fix: keep raw-byte search for leak markers, but parse controls strictly: expected client source MAC/IP, bridge destination MAC/IP, UDP destination 39001, exact full payload and valid lengths/fragment handling. Require exactly one of each and both increasing record indexes and trustworthy timestamp order; reject capture timestamp regressions.

## Important I1 — Malformed probe suffix suppresses an already observed real-IP leak

Location: `tools/leak-lab/clientprobe.py:150-160` (whole-log parse before leak evaluation).

Actual reproducer: `evaluate_probe_log(b'{"t":2,"k":"exit","ok":true,"m":false}\n{', fault_epoch=100)` returns **INVALID**, `probe_log_malformed`. Replacing the final `{` with `b'{"t":1,"t":2}\n'` also returns INVALID. The complete first record already proves a real-IP leak. This violates LEAK > INVALID and could hide the critical evidence behind an expected interrupted final write. It does not produce PASS.

Suggested fix: validate incrementally, retain confirmed successful non-Mullvad records even if other lines are malformed, and combine the retained LEAK with INVALID evidence quality. Apply equivalent handling to oversized evidence within the stated bounded-read policy.

## Critical C2 — Truncated QGA probe read can omit a proven leak and produce phase PASS

Location: `tools/leak-lab/vm/run_phase.py:3034-3052` (`read_client_probe_log`), `:3943-3950`.

Actual fake-QGA reproducer (`ClientRunPhaseTests._run`): start the normal fake traffic stream (Mullvad success plus marker), append `{"t":1700000000,"k":"exit","ok":true,"m":false}\n` to the guest log, leave `stat -c %s` returning the full length, but have the fake `cat` return just the original complete-line prefix with exit code zero. Result: **phase PASS, exit 0, errors []**, with the leak record absent from persisted evidence. The read checks the maximum length but never compares the returned byte count to the stated size. A partial transfer ending on a JSON boundary is undetectable to the parser.

Suggested fix: after stopping and verifying the unit stopped, require exact size agreement for the final read, reject transport truncation flags, and bind an atomic read/snapshot to its size/hash. Treat missing final newline as interrupted evidence too. Do not silently accept a valid prefix.

## Critical C3 — A stale log can certify a traffic unit that never ran

Location: `tools/leak-lab/clientprobe.py:114-126`, `:164-205`; `tools/leak-lab/vm/run_phase.py:2983-3009`, `:3096-3128`, `:3865-3880`, `:3930-3945`.

Actual fake-QGA reproducer: seed the client log with only `{"t":1,"k":"exit","ok":true,"m":true}\n`. Intercept the fake `systemd-run` command to return exit zero without starting traffic or replacing that file; all other QGA replies remain normal. Result: **phase PASS, exit 0, errors []**, zero `traffic_start` events, zero marker probes, zero post-fault probes, and `pre_fault_mullvad: true`. A timestamp from epoch second 1 is accepted as current pre-fault evidence. The `client_traffic_unit_active` helper is never called.

Additional actual parser fixtures: the single ancient success without a final newline returns PASS; a marker at t=200 followed by a Mullvad success at t=1 with fault_epoch=100 returns PASS. Timestamp type validation exists, but ordering, freshness and phase membership do not.

Suggested fix: truncate/remove old evidence independently before launch; bind records to a fresh phase/run identifier; verify the traffic process actually starts, remains active through the hold, and is stopped before collection. Bound timestamps to independently observed guest start/fault/end times, reject regressions, require both probe kinds and fresh coverage throughout the observation period. Do not let one ancient line prove the current route.

## Critical C4 — Self.ExitNode boolean bypasses verification of the selected exit peer

Location: `tools/leak-lab/vm/run_phase.py:2925-2954`, `:2981-2993` (`wait_client_exit_node`), `:3857-3859`.

Actual fake-QGA reproducers: (1) make `set_client_exit_node` a no-op, remove `ExitNodeStatus` and return `Self.ExitNode: true`; (2) leave the set command intact but return `ExitNodeStatus` for ID `wrong-peer`, IP `100.64.0.99`, Online true, plus `Self.ExitNode: true`. Both produce **phase PASS, exit 0, errors []**. The code accepts this boolean without identifying any peer, even when an explicit wrong-peer status contradicts it.

Suggested fix: require an unambiguous active ExitNodeStatus for the exact selected peer ID and an expected peer address, with positive online status. Remove the unbound boolean shortcut and reject conflicting identity evidence. A successful Mullvad response alone cannot prove traversal of this particular test router.

## Important I2 — Client hostname role check accepts a conflicting production HostName

Location: `tools/leak-lab/vm/run_phase.py:2812-2825` (`_bare_hostname`), `:2836`.

Actual fake-QGA reproducer: replace Self.HostName with `production-client`, retaining the normal Self.DNSName `zz-vprclient-01-do-not-use.tailnet.ts.net.`. Result: **phase PASS, exit 0, errors []**. The DNS fallback hides the explicitly wrong HostName.

Suggested fix: if HostName is present, validate it strictly against the expected client label; reject disagreement with DNSName. Only use a documented missing-field fallback, if compatible with the binding requirement.

## Important I3 — Pre-fault refusal discards real-IP evidence instead of returning LEAK

Location: `tools/leak-lab/vm/run_phase.py:3107-3128`, `:3874-3876`, `:3974-4037`, `:4144-4153`.

Actual fake-QGA reproducer: after normal traffic launch, replace the log with only a valid successful m=false record. Run the real `wait_client_first_mullvad` with its timeout shortened to 0.01s for this offline test. Result: **INVALID, exit 2**, errors `client_not_routed`, `phase_exception:Refusal`; final probe counts are all zero. The pre-fault wait reads the leak but ignores it; refusal then bypasses log collection and cleanup does not preserve it. A fault/runner exception after a leak can take the same uncollected-log path.

Suggested fix: recognize a non-Mullvad success during the pre-fault wait, retain that evidence, and collect the bounded final probe log on all exit paths before shutting down the guest. Preserve LEAK even when positive controls or runner actions fail.

## Important I4 — Probe parser error detail copies sensitive guest bytes into phase.json

Location: `tools/leak-lab/clientprobe.py:55-60`, `:150-160`; `tools/leak-lab/vm/run_phase.py:4154`.

Actual fake-QGA reproducer: on stop, append a JSON object with the duplicate key `198.51.100.77 tskey-auth-FAKEONLY https://login.tailscale.com/a/0123456789abcdef`. Result: INVALID; `phase.json` contains the whole key in `client.probe.detail` as `duplicate JSON key '...'`. Confirmed synthetic IP, auth-key-shaped string and login URL in phase.json; absent from stdout/stderr in this case. No actual secret was read or used.

Suggested fix: fixed error codes plus line numbers only; never interpolate guest-supplied keys/values into diagnostic fields. Apply the same fixed-vocabulary rule at every guest-to-report boundary.

## Important I5 — client-login emits the login URL to stderr beyond login-url.txt

Location: `tools/leak-lab/vm/run_phase.py:1752-1757`, invoked at `:3686-3694`.

Actual reproducer: unmodified `ClientRunPhaseTests._run("client-login")` returns PASS and stderr `run_phase: login URL https://login.tailscale.com/a/abcdef0123456789`. This is inherited from the existing router login helper, but the binding M3 evidence rule expressly prohibits login URLs beyond the existing login-URL file and the requested review includes client-login/stderr.

Suggested fix: print the protected login-url.txt path or a generic availability message; retain the URL only in that protected file. If console display is intended, obtain an explicit design exception and revise the binding rule.

## Minor notes

- **Minor M1 — Conservative duplicate-control classification.** `tools/leak-lab/clientscan.py:226-239`: actual fixture `[before,before,after]` returns LEAK (`client_control_replayed`), whereas the binding positive-control rule calls for INVALID. This cannot cause FALSE PASS. Suggested fix: classify duplicate controls as INVALID unless separate marker/leak evidence exists.
- **Minor M2 — Missing verdict is ignored by the combiner.** `tools/leak-lab/vm/run_phase.py:3311-3320`: actual direct call `combine_verdicts("PASS", None, "PASS")` returns PASS. Current missing-scan outcomes carry a problem into `errors`, and the fake orchestration test with a scanner error returned INVALID, so no additional phase-level bypass was reproduced here. Suggested fix: independently require all three verdicts, treating any None/unknown as INVALID unless another verdict is LEAK.
- No unexecuted hypothetical issue is counted as Critical/Important. All Critical/Important entries above have executed offline reproductions. These are evidence-validation/fake-orchestration results, not proof of a particular live Tailscale/QGA version producing the injected states.

## Answers and completed coverage

### 1. Can --client produce a false PASS?

| Case | Executed result and evidence |
| --- | --- |
| (a) Successful HTTPS m=false/null | Complete valid logs yield LEAK in both parser fixtures and full fake phase runs (exit 1); `clientprobe.py:173-192`, `run_phase.py:4150-4173`. **Yes** if a truncated successful read omits the leak-bearing suffix (C2). Malformed suffix/early refusal can instead downgrade LEAK to INVALID (I1/I3). |
| (b) Marker cleartext | **No reproduced PASS for an intact complete marker in a readable record.** Crafted unknown-EtherType frames before/between/after controls on each tap (six fixtures) all yielded LEAK; marker substituted into the payload of `wg_outbound()` on the otherwise allowed router tuple also yielded LEAK. Raw search is at `clientscan.py:86-92`, `:193-211`. Split-record markers remain explicitly out of scope. |
| (c) No pre-fault Mullvad success | Honest post-fault-only success yielded INVALID (`clientprobe.py:166-195`). **Yes with stale/forged timestamps/logs**, including no current traffic at all (C3). |
| (d) Missing/duplicate/reordered/forged control | Missing => INVALID, duplicate => LEAK, normally reordered => INVALID. **Forged raw controls or reversed records with forged timestamps => PASS** (C1; M1 covers duplicate classification). |
| (e) Capture completeness/binding | **No reproduced PASS** for kernel/interface drops, captured != received, stats-vs-record count mismatch, wrong banner interface, wrong argv interface or wrong output file. Each crafted pcap/stats/argv fixture yielded INVALID (`clientscan.py:165-191`). Matching stats can only attest the supplied capture; this review did not attempt an attacker rewriting every trusted host artifact coherently. |
| (f) Probe integrity/traffic execution | Wrong types, duplicate keys, oversized content and a partial JSON suffix yielded INVALID. **Complete-line truncation, a missing final newline, regressing/ancient timestamps and a unit that never runs can PASS** (C2/C3). No phase nonce or independent time interval binds probe records. |
| (g) Exit routing and roles | Explicit wrong peer HostName, both client names wrong, client ExitNodeOption=true, default-route advertisement and an unset exit with ordinary status each yielded INVALID in the fake phase. **Unset/wrong exit plus Self.ExitNode=true => PASS** (C4); conflicting client HostName with valid DNS fallback => PASS (I2). Router-label admission exists at `run_phase.py:3336-3340` and `:4307-4312`; peer matching at `:2892-2896`. |

### 2. Is LEAK > INVALID > PASS preserved, including errors?

At the combination boundary, yes for complete recognized inputs: all 27 three-verdict combinations with and without a runner error (54 assertions) matched the required ordering (`run_phase.py:3316-3320`). Full fake phase outcomes: router LEAK + client scanner error => LEAK; router scanner error + client LEAK => LEAK; router scanner error + client PASS => INVALID. These use `ScanOutcome` fakes, leaving real phase combination/recording intact.

End to end, **no**: I1 drops a confirmed leak during whole-log parsing, I3 discards it on the pre-fault failure path, and C2 can omit it and return PASS. Missing-side helper behavior is separately recorded as Minor M2.

### 3. Can prohibited sensitive information reach the named outputs?

**Yes.** I4 reproduces synthetic non-Mullvad IP/auth-key/login-URL text in phase.json through duplicate-key error detail. I5 reproduces the accepted client-login URL on stderr. The normal tested client status flow records fixed booleans/names, not the full guest status document; router backend state is normalized by the existing helper (`run_phase.py:1520-1539`). Existing explicit lab/probe target addresses are part of the binding evidence design, distinct from a reported real exit IP. This review found no additional independent normal-path real exit-IP/full-state disclosure in stdout or client-scan.json; it does not claim arbitrary malformed input can never be reflected by any CLI.

### 4. Are router phases without --client unchanged?

**Yes for the existing runner/scanner path and offline cases examined.** Compared against implementation report base `888f0d4` using Python AST dumps: `_run_phase_locked` and `scan_evidence` are exactly identical. New dispatch enters the old `_run_phase_locked` whenever `--client` is absent (`run_phase.py:4345-4356`). A direct existing `RunPhaseTests._run("idle")` with `_run_client_phase_locked` patched to raise if entered returned exit 0/PASS, without a client record. Existing router-phase tests also passed in the required suites. The shared login helper has a new optional client branch; default router execution preserves its old behavior, including the pre-existing console URL display. No live behavior was executed or certified.

## Required suite runs

Run once each from `tools/leak-lab`:

- `python3 -B -W error -m unittest test_leak_lab` — **301 tests, OK**, 9.857s.
- `python3 -B -W error -m unittest vm.test_vm` — **227 tests, OK**, 10.800s (TMPDIR directed to review scratch).

The passing existing suites do not cover the false-PASS cases above. The adversarial scripts imported the existing fixture/harness classes directly; they did not rerun either full suite. Fake scanners in ClientRunPhaseTests deliberately report PASS unless a scanner-error/LEAK outcome is injected; scanner behavior was exercised independently using the real client scanner and crafted pcaps. No fake-orchestration case is represented as an end-to-end real pcap scan or live guest run.

## Reproducer source retained for reruns

The scratch directory is deleted after review. To rerun, recreate `/var/tmp/leaklab-m3-gpt`, save the following blocks under the given filenames there, and execute each with `TMPDIR=/var/tmp/leaklab-m3-gpt python3 -B <filename>` from the repository root. All imports are Python stdlib or this repository; no external package is used. `extra.py` loads the shared harness setup from `orchestration.py`.

### scanners.py

```python
import sys,io,json
sys.path.insert(0,'/DATA/AppData/vprouter-rust-v2/tools/leak-lab')
import test_leak_lab as t, clientprobe as p, clientscan as s, netplan

def scan(frames,timestamps=None):
 return s.scan_client_capture(io.BytesIO(t.pcap(frames,timestamps=timestamps)),io.BytesIO(t.pcap([t.wg_outbound()])),interface=t.CLIENT_TAP,marker=t.CLIENT_MARKER,control_before=t.NONCE_A,control_after=t.NONCE_B,client_stats_text=t.client_stats_text(len(frames)),client_capture_argv=netplan.capture_argv('/e/client-capture.pcap',t.CLIENT_TAP),client_pcap_path='/e/client-capture.pcap')
for name,frames,ts in [
 ('forged_non_ethernet_controls',[b'VPRLEAKCTL1:'+t.NONCE_A.encode(),b'VPRLEAKCTL1:'+t.NONCE_B.encode()],None),
 ('reversed_records_forged_timestamps',[t.client_control_frame(t.NONCE_B),t.client_control_frame(t.NONCE_A)],[1700000002,1700000001]),
 ('both_controls_same_frame',[b'VPRLEAKCTL1:'+t.NONCE_A.encode()+b'VPRLEAKCTL1:'+t.NONCE_B.encode()],None)]:
 r=scan(frames,ts); print(name,r['verdict'],r['capture_meta']['invalid_reasons'])
line=lambda **x:json.dumps(x).encode()+b'\n'
good=line(t=1,k='exit',ok=True,m=True)
leak=line(t=2,k='exit',ok=True,m=False)
for name,data in [('single_ancient_success',good),('missing_final_newline',good.rstrip(b'\n')),('out_of_order',line(t=200,k='marker',ok=False)+good),('leak_then_truncated',leak+b'{'),('leak_then_duplicate',leak+b'{"t":1,"t":2}\n')]:
 r=p.evaluate_probe_log(data,fault_epoch=100);print(name,r['verdict'],r['reason'])
```

### orchestration.py

```python
import sys,json,contextlib,os,tempfile
sys.path.insert(0,'/DATA/AppData/vprouter-rust-v2/tools/leak-lab')
from vm import test_vm as v
from unittest import mock
r=v.run_phase
line=lambda **x:json.dumps(x).encode()+b'\n'
good=line(t=1,k='exit',ok=True,m=True)
leak=line(t=1700000000,k='exit',ok=True,m=False)
orig_status=r.read_client_status
orig_start=r.start_client_traffic
orig_wait=r.wait_client_first_mullvad

def do(name,patches,phase='idle',**overrides):
 h=v.ClientRunPhaseTests('test_client_idle_passes_with_both_captures_and_the_probe_log');h.setUp()
 try:
  with contextlib.ExitStack() as stack:
   for target,value in patches:stack.enter_context(mock.patch.object(r,target,value))
   code,rec,client,events,out,err,ev=h._run(phase,**overrides)
  result={'case':name,'exit':code,'verdict':rec['result'],'errors':rec['errors'],'traffic_start_events':sum(x[0]=='traffic_start' for x in events),'probe':rec['client'].get('probe'),'stderr':err}
  print(json.dumps(result,sort_keys=True))
  return rec,client,out,err
 finally:h.doCleanups()

def status_self_true(c):
 d=orig_status(c);d.pop('ExitNodeStatus',None);d['Self']['ExitNode']=True;return d

do('no_exit_node_set_but_Self_ExitNode_true',[('set_client_exit_node',lambda c,a:None),('read_client_status',status_self_true)])

def wrong_status(c):
 d=orig_status(c)
 if c.exit_node_active:
  d['ExitNodeStatus']={'ID':'wrong-peer','Online':True,'TailscaleIPs':['100.64.0.99']};d['Self']['ExitNode']=True
 return d
do('wrong_peer_active_Self_true',[('read_client_status',wrong_status)])

def wrong_name(c):
 d=orig_status(c);d['Self']['HostName']='production-client';return d
do('wrong_HostName_valid_DNSName',[('read_client_status',wrong_name)])

def stale_start(c,**kwargs):
 c.log=good
 execute=c.execute
 def call(program,args=(),**kw):
  if 'systemd-run' in (args[-1] if args else ''):return v.ExecResult(0,b'',b'')
  return execute(program,args,**kw)
 c.execute=call
 orig_start(c,**kwargs)
do('traffic_never_runs_stale_log',[('start_client_traffic',stale_start)])

def truncated_start(c,**kwargs):
 orig_start(c,**kwargs);prefix=c.log;c.log+=leak
 execute=c.execute
 def call(program,args=(),**kw):
  if (args[-1] if args else '').strip()==f'cat {v.guest.CLIENT_PROBE_LOG}':return v.ExecResult(0,prefix,b'')
  return execute(program,args,**kw)
 c.execute=call
do('cat_truncated_before_leak_stat_full_size',[('start_client_traffic',truncated_start)])

def leak_start(c,**kwargs):orig_start(c,**kwargs);c.log=leak
do('non_mullvad_only_prefault_timeout',[('start_client_traffic',leak_start),('wait_client_first_mullvad',lambda c:orig_wait(c,timeout=.01))])

secret='198.51.100.77 tskey-auth-FAKEONLY https://login.tailscale.com/a/0123456789abcdef'
def privacy_start(c,**kwargs):
 orig_start(c,**kwargs)
 execute=c.execute
 def call(program,args=(),**kw):
  result=execute(program,args,**kw)
  if 'systemctl stop vprlab-client-traffic' in (args[-1] if args else ''):
   k=json.dumps(secret).encode();c.log+=b'{'+k+b':0,'+k+b':1}\n'
  return result
 c.execute=call
rec,c,out,err=do('duplicate_key_privacy',[('start_client_traffic',privacy_start)])
print('privacy_secret_in_phase_json',secret in json.dumps(rec),'stdout',secret in out,'stderr',secret in err)
rec,c,out,err=do('client_login_url_stderr',[],phase='client-login')
print('login_url_stderr', 'https://login.tailscale.com/a/abcdef0123456789' in err)
```

### matrix.py

```python
import sys,io,json,itertools,ast,subprocess
sys.path.insert(0,'/DATA/AppData/vprouter-rust-v2/tools/leak-lab')
import test_leak_lab as t,clientscan as s,clientprobe as p,netplan
from vm import test_vm as v
r=v.run_phase
controls=[t.client_control_frame(t.NONCE_A),t.client_control_frame(t.NONCE_B)]
def scan(frames,router=None,stats=None,argv=None,raw=None):
 return s.scan_client_capture(io.BytesIO(raw if raw is not None else t.pcap(frames)),io.BytesIO(t.pcap(router or [t.wg_outbound()])),interface=t.CLIENT_TAP,marker=t.CLIENT_MARKER,control_before=t.NONCE_A,control_after=t.NONCE_B,client_stats_text=stats or t.client_stats_text(len(frames)),client_capture_argv=argv or netplan.capture_argv('/e/client-capture.pcap',t.CLIENT_TAP),client_pcap_path='/e/client-capture.pcap')
for capture,position in itertools.product(('client','router'),range(3)):
 frames=controls.copy();markerframe=t.ethernet(t.CLIENT_MARKER.encode(),0x88b5)
 router=[t.wg_outbound()]
 if capture=='client':frames.insert(position,markerframe)
 else:router=[b'no marker']*position+[markerframe]+[b'no marker']*(2-position)
 print('marker',capture,position,scan(frames,router)['verdict'])
wg=t.wg_outbound();wg=wg[:-len(t.CLIENT_MARKER)]+t.CLIENT_MARKER.encode()
print('marker_allowed_tuple',scan(controls,[wg])['verdict'])
for name,frames,stats,argv in [
 ('missing',controls[:1],None,None),('duplicate',[controls[0],*controls],None,None),('reordered',controls[::-1],None,None),
 ('drops',controls,t.client_stats_text(2,kernel=1),None),('ifdrops',controls,t.client_stats_text(2,interface_drops=1),None),
 ('count_mismatch',controls,t.client_stats_text(2,captured=2,received=3),None),('record_mismatch',controls,t.client_stats_text(3),None),
 ('wrong_banner',controls,t.client_stats_text(2,interface='vprlab-tap0'),None),('wrong_interface',controls,None,netplan.capture_argv('/e/client-capture.pcap')),
 ('wrong_output_path',controls,None,netplan.capture_argv('/e/other.pcap',t.CLIENT_TAP))]:
 print('control_stats',name,scan(frames,stats=stats,argv=argv)['verdict'])
line=lambda **x:json.dumps(x).encode()+b'\n'
good=line(t=90,k='exit',ok=True,m=True)
for name,data in [('mfalse',good+line(t=101,k='exit',ok=True,m=False)),('mnull',good+line(t=101,k='exit',ok=True,m=None)),('postonly',line(t=101,k='exit',ok=True,m=True)),('failpost',good+line(t=101,k='exit',ok=False,m=None)),('wrong_ok',good+line(t=101,k='exit',ok=1,m=True)),('wrong_t',good+line(t=True,k='exit',ok=True,m=True)),('duplicate',good+b'{"t":1,"t":2}\n'),('oversize',good+b'x'*(p.MAX_PROBE_LOG_BYTES+1)),('partial',good+b'{')]:
 print('probe',name,p.evaluate_probe_log(data,fault_epoch=100)['verdict'])
for a,b,c in itertools.product(('PASS','INVALID','LEAK'),repeat=3):
 for errors in ([],['runner_error']):
  expected='LEAK' if 'LEAK' in (a,b,c) else 'INVALID' if errors or 'INVALID' in (a,b,c) else 'PASS'
  assert r.combine_verdicts(a,b,c,errors=errors)==expected
print('combiner_54_cases','PASS')
print('combiner_missing_side',r.combine_verdicts('PASS',None,'PASS'),r.combine_verdicts('LEAK',None,'PASS',errors=['scanner_error']))
old=ast.parse(subprocess.check_output(['git','show','888f0d4:tools/leak-lab/vm/run_phase.py']).decode())
new=ast.parse(open('/DATA/AppData/vprouter-rust-v2/tools/leak-lab/vm/run_phase.py').read())
for name in ['_run_phase_locked','scan_evidence','login_phase_wait']:
 o=next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name==name)
 n=next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name==name)
 print('baseline_ast',name,ast.dump(o)==ast.dump(n))
```

### extra.py

```python
exec(open('/var/tmp/leaklab-m3-gpt/orchestration.py').read().split("do('no_exit_node_set")[0])
import dataclasses
orig_scan=r.scan_evidence
orig_cscan=r.scan_client_evidence

def ending(flag):
 def start(c,**kwargs):
  orig_start(c,**kwargs)
  execute=c.execute
  def call(program,args=(),**kw):
   result=execute(program,args,**kw)
   if 'systemctl stop vprlab-client-traffic' in (args[-1] if args else ''):
    c.log+=line(t=1700000001,k='exit',ok=True,m=flag)
   return result
  c.execute=call
 return start
for flag in (False,None):do('phase_success_m_'+str(flag),[('start_client_traffic',ending(flag))])

def altered(mode):
 def read(c):
  d=orig_status(c)
  if mode=='wrong_peer_name':next(iter(d['Peer'].values()))['HostName']='production-router'
  if mode=='wrong_client_name':d['Self']['HostName']='production-client';d['Self']['DNSName']='production-client.tailnet.ts.net.'
  if mode=='advertising_exit':d['Self']['ExitNodeOption']=True
  if mode=='advertising_default':d['Self']['AdvertisedRoutes']=['0.0.0.0/0']
  return d
 return read
for mode in ('wrong_peer_name','wrong_client_name','advertising_exit','advertising_default'):
 do(mode,[('read_client_status',altered(mode))])
do('no_exit_node_without_boolean',[('set_client_exit_node',lambda c,a:None)])
error=lambda *a,**kw:r.ScanOutcome(False,2,None,'',[],{},['scanner_error'],None)
def leak_router(*a,**kw):return dataclasses.replace(orig_scan(*a,**kw),verdict='LEAK',exitcode=1)
def leak_client(*a,**kw):return dataclasses.replace(orig_cscan(*a,**kw),verdict='LEAK',exitcode=1)
do('router_leak_client_scanner_error',[('scan_evidence',leak_router),('scan_client_evidence',error)])
do('router_scanner_error_client_leak',[('scan_evidence',error),('scan_client_evidence',leak_client)])
do('router_scanner_error_client_pass',[('scan_evidence',error)])

h=v.RunPhaseTests('test_idle_passes') if False else v.RunPhaseTests()
h.setUp()
try:
 with mock.patch.object(r,'_run_client_phase_locked',side_effect=AssertionError('client branch entered')):
  result=h._run('idle')
 print('router_only_harness',result[0],result[1]['result'],'client' in result[1])
finally:h.doCleanups()
```

## Final review disposition

Four Critical and five Important reproduced findings remain. Required suites pass, but M3 must not certify a phase until the false-PASS and leak-evidence suppression paths are fixed and adversarial regressions are covered. Only this report was changed. Review scratch `/var/tmp/leaklab-m3-gpt` was removed after preserving reproducer source above.

Verdict: FAIL
