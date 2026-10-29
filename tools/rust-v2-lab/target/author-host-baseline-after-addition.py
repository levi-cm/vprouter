"""Preservation input from an acknowledged original addition; no VM actions."""
import copy,datetime,hashlib,importlib.util,json,pathlib,re,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
self_bytes=pathlib.Path(__file__).read_bytes()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def stable(v):return dict(namespace=v['namespace'],**{k:sorted(v[k],key=canonical)for k in ('links','addresses','routes','rules')})
def append_original(prior,added,observed):
 assert added['kind']=='veth'and added['up']is False
 assert all(v['index']!=added['index']and v['name']!=added['name']for v in prior['links'])
 expected=copy.deepcopy(prior);expected['links'].append(copy.deepcopy(added))
 assert stable(expected)==stable(observed),'unexplained_foreign_state_change'
 baseline=dict(namespace=expected['namespace'])
 for key in ('links','addresses','routes','rules'):
  remaining=list(expected[key]);baseline[key]=[]
  for row in observed[key]:
   i=next(i for i,value in enumerate(remaining)if value==row);baseline[key].append(remaining.pop(i))
  assert not remaining
 return baseline

def main():
 candidate_path=pathlib.Path(sys.argv[1]);label=sys.argv[2];assert re.fullmatch('[a-z0-9_-]+',label)
 candidate=json.loads(candidate_path.read_bytes());root=candidate_path.parent;directory=root/label
 p=pathlib.Path('target/collect-secret-host-addition.py');spec=importlib.util.spec_from_file_location('author_original_host_addition',p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 c=module.validate_prefix(str(candidate_path),label,host_addition=True);proof=module.validate_complete(c);w=c['host_addition_top'];assert c['host_addition_fault']==0 and w['canonical_host_addition_acknowledged']is True
 run=int(re.fullmatch('actual-program-run-([0-9]+).json',c['path'].name)[1]);sidecar_path=pathlib.Path(f'target/lab-state/secret-host-addition-run-{run}.json');sidecar=json.loads(sidecar_path.read_bytes())
 assert sidecar['record_sha256']==sha(c['path'])and sidecar['witness']==w and sidecar['source_binding']==candidate['binding']and sidecar['proof']['host_addition']==proof['host_addition']
 for ref in sidecar['collectors']:assert sha(ref['path'])==ref['sha256']
 old_path=directory/'controller-authored-baseline.json';old=json.loads(old_path.read_bytes());assert old['baseline']==w['admission']['declared_baseline']
 op=w['operations'][-1];assert op['acknowledged']is True and op['actual_wait_status']==0 and op['eof']is True
 added=op['result']['host'];assert added['index']==w['planned_host_link_index']
 observed=op['host_observation'];baseline=append_original(old['baseline'],added,observed)
 shape_path=pathlib.Path('target/platform-lab/host_baseline_declaration.py');shape_bytes=shape_path.read_bytes();shape={};exec(compile(shape_bytes,str(shape_path),'exec'),shape);shape['validate_shape'](baseline)
 platform=c['record']['platform'];baseline_sha=hashlib.sha256(canonical(baseline)).hexdigest()
 refs=[candidate_path,c['path'],sidecar_path,old_path,directory/'controller-baseline-reconciliation.json']
 references=[dict(path=str(p),sha256=sha(p))for p in refs]
 review=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_binding=candidate['binding'],platform=platform,namespace=baseline['namespace'],baseline_sha256=baseline_sha,counts={k:len(baseline[k])for k in ('links','addresses','routes','rules')},references=references,helpers=[dict(path=str(pathlib.Path(__file__)),sha256=hashlib.sha256(self_bytes).hexdigest()),dict(path=str(shape_path),sha256=hashlib.sha256(shape_bytes).hexdigest())],prior_structure_reconstructed=True,ordering_only_aligned_after_exact_multiset_comparison=True,previous_run=run,exact_original_acknowledged_addition=added,declaration_staged=False,host_authority_granted=False,review_scope='Preserve prior authored foreign state plus one historical original acknowledged DOWN endpoint; no live value substitution, ownership, cleanup or new authority. Independent review pending.')
 review_path=root/('host-baseline-reconciliation-'+platform+'.next.json')
 with review_path.open('x')as f:json.dump(review,f,indent=2);f.write('\n')
 template=dict(schema=1,platform=platform,source_binding=candidate['binding'],baseline=baseline,baseline_sha256=baseline_sha,prior_evidence=references,review_sha256=sha(review_path));shape['validate_template'](template,candidate['binding'],platform)
 out=root/('authored-host-baseline-'+platform+'.next.json')
 with out.open('xb')as f:f.write(canonical(template))
 out.chmod(0o600)
 for name,raw in [('author',self_bytes),('schema',shape_bytes)]:
  with(root/('baseline-after-'+str(run)+'-'+name+'.py')).open('xb')as f:f.write(raw)
 print(json.dumps(dict(template=str(out),sha256=sha(out),reconciliation=str(review_path),baseline_sha256=baseline_sha,counts=review['counts'],previous_run=run,fixed_inputs_replaced=False,host_authority_granted=False)))
if __name__=='__main__':main()
