#!/usr/bin/env python3
"""Run 411 fresh provenance; original 409 validator and artifacts remain separate."""
import ast,hashlib,importlib.util,json,pathlib
if not __debug__:raise RuntimeError('optimized_python_refused')
if '_run411_guard' not in globals():
 spec=importlib.util.spec_from_file_location('provenance_guard',pathlib.Path(__file__).resolve().with_name('run411-reservation.py'));_run411_guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(_run411_guard)
base=_run411_guard.load_module('run411_baseline_base',pathlib.Path(__file__).resolve().parents[2]/'target/quarantine_evidence_base.py')

def requires_fresh_provenance(record,review,run=None):
 return run==411 or base.requires_fresh_provenance(record,review,run)

@_run411_guard.captured_call
def validate_fresh_provenance(template,review,candidate,record=None):
 """Pure local validation of the explicit fresh route, before or after run411.

 No historical flags are relaxed. Recompute exact multisets and execute only
 the frozen projector's pure custody/deadline definitions, never its main body.
 """
 def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
 def sha(p):return hashlib.sha256(module.read_bytes(pathlib.Path(p))).hexdigest()
 helper=pathlib.Path('tools/rust-v2-lab/run411-reservation.py')
 module=_run411_guard
 module.check_references(template);module.check_references(review);module.check_references(candidate)
 r=module.validate_bindings(module.active());reservation=module.RESERVATION
 assert review['route']=='fresh-lab'and review['platform']==r['platform']
 assert all(review[key] is False for key in ('historical_continuity','prior_structure_reconstructed','ordering_only_aligned_after_exact_multiset_comparison','projection_used_to_author','host_authority_granted'))
 assert template['source_binding']==review['source_binding']==candidate['binding']
 cp=pathlib.Path(r['candidate']);assert json.loads(module.read_bytes(cp))==candidate
 tp=cp.parent/('authored-host-baseline-'+r['platform']+'.json');rp=cp.parent/('host-baseline-reconciliation-'+r['platform']+'.json');pp=cp.parent/('host-projection-'+r['platform'])/'record.json'
 assert json.loads(module.read_bytes(tp))==template and json.loads(module.read_bytes(rp))==review
 assert sha(rp)==template['review_sha256']
 shape_path=pathlib.Path('target/platform-lab/host_baseline_declaration.py')
 shape=module.load_module('fresh_shape',shape_path)
 shape.validate_template(template,candidate['binding'],r['platform'])
 for ref in template['prior_evidence']:
  path=pathlib.Path(ref['path']);assert not path.is_absolute()and path.parts[0]=='target'and '..'not in path.parts and path.suffix=='.json'
  assert sha(path)==ref['sha256']
 for ref in review.get('helpers',[]):assert sha(ref['path'])==ref['sha256']
 a=json.loads(module.read_bytes(pathlib.Path('target/run411-prep/admission.json')))
 assert review['guest_boot_id']==a['boot_id']==r['guest_boot_id']
 assert review['namespace']==template['baseline']['namespace']==a['namespace']['/proc/1/ns/net']==a['namespace']['/proc/self/ns/net']
 check=json.loads(module.read_bytes(pathlib.Path('target/run411-prep/baseline-comparison.json')));projection=json.loads(module.read_bytes(pp))
 assert check['exact_multisets_equal']is check['namespace_preserved']is check['no_authority']is True
 assert check['template_sha256']==sha(tp)and check['projection_sha256']==sha(pp)
 assert check['baseline_sha256']==template['baseline_sha256']==review['baseline_sha256']==hashlib.sha256(canonical(template['baseline'])).hexdigest()
 assert projection['source_binding']==candidate['binding']and projection['platform']==r['platform']and projection['artifact_sha256']==candidate['platforms']['arm64']['artifact_sha256']
 projector=pathlib.Path('target/platform-lab/run-frozen-host-projection.py');assert sha(projector)==projection['controller_sha256']
 tree=ast.parse(module.read_bytes(projector));defs=ast.Module(body=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[]);namespace={};exec(compile(defs,str(projector),'exec'),namespace)
 assert namespace['validate_projection_envelope'](projection['remote'],'aarch64')==projection['report']
 expected=template['baseline'];actual=projection['report']['projection'];shape.validate_shape(actual);assert expected['namespace']==actual['namespace']
 for key in ('links','addresses','routes','rules'):assert sorted(map(canonical,expected[key]))==sorted(map(canonical,actual[key]))
 if record is not None:
  provenance=record['run_reservation'];assert provenance==dict(path=str(reservation),sha256=sha(reservation),claim=str(module.CLAIM),continuity='fresh-lab',historical_raw_records_recovered=False)
  claim=module.protected(module.CLAIM)
  assert claim['reservation']==str(reservation)and claim['reservation_sha256']==sha(reservation)and claim['run']==411 and claim['budget_remaining']==0
  assert claim['controller_boot_id']==r['controller_boot_id']
  assert record['platform']==r['platform']and record['source_binding']==candidate['binding']and record['component_test_mode']=='secret_bootstrap_success'
  assert record['guest_boot_id']==r['guest_boot_id']
  assert record['host_baseline_template_sha256']==sha(tp)and record['baseline_reconciliation_sha256']==sha(rp)
  assert record['source_archive_sha256']==candidate['source_sha256']and record['artifact_sha256']==candidate['platforms']['arm64']['artifact_sha256']
  assert record['context_sha256']==candidate['platforms']['arm64']['context_sha256']
  for key,path in [('runner_sha256','run-frozen-secret-bootstrap411.py'),('guest_sha256','secret-bootstrap.guest.py'),('context_checker_sha256','attachment_context_check.py'),('host_declaration_builder_sha256','quarantine_host_declaration.py'),('baseline_declaration_builder_sha256','host_baseline_declaration.py')]:assert record[key]==sha(pathlib.Path('target/platform-lab')/path)
 return r

base.validate_fresh_provenance=validate_fresh_provenance
# Compile only the baseline validator with every pathname read redirected to
# the same acquisition API. The historical module and its callers are unchanged.
class GuardReads(ast.NodeTransformer):
 def visit_Call(self,node):
  node=self.generic_visit(node)
  if isinstance(node.func,ast.Attribute) and node.func.attr in ('read_bytes','read_text'):
   assert not node.args and not node.keywords
   return ast.copy_location(ast.Call(func=ast.Attribute(value=ast.Name(id='_run411_guard',ctx=ast.Load()),attr=node.func.attr,ctx=ast.Load()),args=[node.func.value],keywords=[]),node)
  return node
_tree=ast.parse(base.__captured_source__)
_function=next(n for n in _tree.body if isinstance(n,ast.FunctionDef) and n.name=='validate_baseline_host')
_function=GuardReads().visit(_function)
base.__dict__['_run411_guard']=_run411_guard
exec(compile(ast.fix_missing_locations(ast.Module(body=[_function],type_ignores=[])),'captured-baseline-validator','exec'),base.__dict__)
validate_baseline_host=_run411_guard.captured_call(base.validate_baseline_host)
