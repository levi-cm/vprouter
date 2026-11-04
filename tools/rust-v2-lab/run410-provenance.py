#!/usr/bin/env python3
"""Run 410 fresh provenance; original 409 validator and artifacts remain separate."""
import ast,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
spec=importlib.util.spec_from_file_location('run410_baseline_base',pathlib.Path(__file__).resolve().parents[2]/'target/quarantine_evidence_base.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

def requires_fresh_provenance(record,review,run=None):
 return run==410 or base.requires_fresh_provenance(record,review,run)

def validate_fresh_provenance(template,review,candidate,record=None):
 """Pure local validation of the explicit fresh route, before or after run410.

 No historical flags are relaxed. Recompute exact multisets and execute only
 the frozen projector's pure custody/deadline definitions, never its main body.
 """
 def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
 def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
 helper=pathlib.Path('tools/rust-v2-lab/run410-reservation.py')
 spec=importlib.util.spec_from_file_location('fresh_reservation',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 r=module.validate_bindings(module.active());reservation=module.RESERVATION
 assert review['route']=='fresh-lab'and review['platform']==r['platform']
 assert all(review[key] is False for key in ('historical_continuity','prior_structure_reconstructed','ordering_only_aligned_after_exact_multiset_comparison','projection_used_to_author','host_authority_granted'))
 assert template['source_binding']==review['source_binding']==candidate['binding']
 cp=pathlib.Path(r['candidate']);assert json.loads(cp.read_bytes())==candidate
 tp=cp.parent/('authored-host-baseline-'+r['platform']+'.json');rp=cp.parent/('host-baseline-reconciliation-'+r['platform']+'.json');pp=cp.parent/('host-projection-'+r['platform'])/'record.json'
 assert json.loads(tp.read_bytes())==template and json.loads(rp.read_bytes())==review
 assert sha(rp)==template['review_sha256']
 shape_path=pathlib.Path('target/platform-lab/host_baseline_declaration.py')
 spec=importlib.util.spec_from_file_location('fresh_shape',shape_path);shape=importlib.util.module_from_spec(spec);spec.loader.exec_module(shape)
 shape.validate_template(template,candidate['binding'],r['platform'])
 for ref in template['prior_evidence']:
  path=pathlib.Path(ref['path']);assert not path.is_absolute()and path.parts[0]=='target'and '..'not in path.parts and path.suffix=='.json'
  assert sha(path)==ref['sha256']
 for ref in review.get('helpers',[]):assert sha(ref['path'])==ref['sha256']
 a=json.loads(pathlib.Path('target/run410-prep/admission.json').read_bytes())
 assert review['guest_boot_id']==a['boot_id']==r['guest_boot_id']
 assert review['namespace']==template['baseline']['namespace']==a['namespace']['/proc/1/ns/net']==a['namespace']['/proc/self/ns/net']
 check=json.loads(pathlib.Path('target/run410-prep/baseline-comparison.json').read_bytes());projection=json.loads(pp.read_bytes())
 assert check['exact_multisets_equal']is check['namespace_preserved']is check['no_authority']is True
 assert check['template_sha256']==sha(tp)and check['projection_sha256']==sha(pp)
 assert check['baseline_sha256']==template['baseline_sha256']==review['baseline_sha256']==hashlib.sha256(canonical(template['baseline'])).hexdigest()
 assert projection['source_binding']==candidate['binding']and projection['platform']==r['platform']and projection['artifact_sha256']==candidate['platforms']['amd64']['artifact_sha256']
 projector=pathlib.Path('target/platform-lab/run-frozen-host-projection.py');assert sha(projector)==projection['controller_sha256']
 tree=ast.parse(projector.read_bytes());defs=ast.Module(body=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]);namespace={};exec(compile(defs,str(projector),'exec'),namespace)
 assert namespace['validate_projection_envelope'](projection['remote'],'x86_64')==projection['report']
 expected=template['baseline'];actual=projection['report']['projection'];shape.validate_shape(actual);assert expected['namespace']==actual['namespace']
 for key in ('links','addresses','routes','rules'):assert sorted(map(canonical,expected[key]))==sorted(map(canonical,actual[key]))
 if record is not None:
  provenance=record['run_reservation'];assert provenance==dict(path=str(reservation),sha256=sha(reservation),claim=str(module.CLAIM),continuity='fresh-lab',historical_raw_records_recovered=False)
  claim=module.protected(module.CLAIM)
  assert claim['reservation']==str(reservation)and claim['reservation_sha256']==sha(reservation)and claim['run']==410 and claim['budget_remaining']==0
  assert claim['controller_boot_id']==r['controller_boot_id']
  assert record['platform']==r['platform']and record['source_binding']==candidate['binding']and record['component_test_mode']=='secret_bootstrap_success'
  assert record['guest_boot_id']==r['guest_boot_id']
  assert record['host_baseline_template_sha256']==sha(tp)and record['baseline_reconciliation_sha256']==sha(rp)
  assert record['source_archive_sha256']==candidate['source_sha256']and record['artifact_sha256']==candidate['platforms']['amd64']['artifact_sha256']
  assert record['context_sha256']==candidate['platforms']['amd64']['context_sha256']
  for key,path in [('runner_sha256','run-frozen-secret-bootstrap410.py'),('guest_sha256','secret-bootstrap.guest.py'),('context_checker_sha256','attachment_context_check.py'),('host_declaration_builder_sha256','quarantine_host_declaration.py'),('baseline_declaration_builder_sha256','host_baseline_declaration.py')]:assert record[key]==sha(pathlib.Path('target/platform-lab')/path)
 return r

base.validate_fresh_provenance=validate_fresh_provenance
validate_baseline_host=base.validate_baseline_host
