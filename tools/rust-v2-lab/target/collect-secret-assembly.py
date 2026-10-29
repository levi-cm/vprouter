"""Strict frozen consuming whole-owner assembly and original capacity evidence."""
import datetime,hashlib,importlib.util,json,os,pathlib,re,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
from quarantine_evidence_base import validate_prefix
from assembly_evidence_schema import validate_assembly
mechanics_path=pathlib.Path(__file__).with_name('platform-lab')/'selftest_mechanics.py';mechanics_bytes=mechanics_path.read_bytes();mechanics={'__name__':'assembly_capacity_mechanics','__file__':str(mechanics_path)};exec(compile(mechanics_bytes,str(mechanics_path),'exec'),mechanics)
p=pathlib.Path(__file__).with_name('collect-secret-quarantine.py');spec=importlib.util.spec_from_file_location('assembly_quarantine',p);quarantine=importlib.util.module_from_spec(spec);spec.loader.exec_module(quarantine)
def validate_complete(c,continuation=False):
 assert type(continuation)is bool
 old=quarantine.validate_quarantine(c,continuation=True)
 assert old['producer']['quarantine_original_context_continued']is True and old['producer']['final_whole_chain_drop_verified']is False
 w=c['assembly_top'];resource=w['resources'][3];foreign=mechanics['validate_capacity_refusals'](w['foreign_eligibility'],eligible=(resource['original_pid'],resource['original_start']),counts=[15,11],after=c['environment']['after']['started_at'],earliest=c['quarantine_top']['final_process_verified_at'])
 assert w['foreign_eligibility']['original_pid']not in{v['pid']for v in w['preparation']['writers']}and w['foreign_eligibility']['original_pid']not in{v['original_pid']for v in w['resources']}
 return dict(quarantine=old,assembly=validate_assembly(c,continuation=continuation),foreign_eligibility=foreign)
if __name__=='__main__':
 c=validate_prefix(sys.argv[1],sys.argv[2],assembly=True);proof=validate_complete(c);r=c['record'];path=c['path'];run=re.fullmatch('actual-program-run-([0-9]+).json',path.name)[1]
 names=['collect-secret-assembly.py','assembly_evidence_schema.py','collect-secret-quarantine.py','quarantine_evidence_base.py','quarantine_history_schema.py','quarantine_native_schema.py','quarantine_producer_schema.py','collect-secret-movement.py','movement_evidence_base.py','collect-secret-provision.py','provision_evidence_base.py','wireguard_inventory_schema.py']
 out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(c['raw']).hexdigest(),source_binding=r['source_binding'],artifact_sha256=r['artifact_sha256'],context_sha256=r['context_sha256'],platform=r['platform'],component_test_mode=r['component_test_mode'],collectors=[dict(path=str(p),sha256=hashlib.sha256(mechanics_bytes if p==mechanics_path else p.read_bytes()).hexdigest())for p in[pathlib.Path(__file__).with_name(name)for name in names]+[mechanics_path]],input_manifest=c['manifest'],gateway=c['gateway'],host_declaration=c['host'],witness=c['assembly_top'],environment=c['environment'],proof=proof,real_client_acceptance='NOT_RUN',requirement8_complete=False,allnine_complete=False,limit='Single-exit custody-only capacity handoff: original69 writers/17 windows and15 exact original native receipts, retained whole owners, completed charge retirement and partial/duplicate refusal. Preparation snapshot precedes Drop; after-Drop anchors/counters are separate. Transferred resources remain nonquiet. No fresh policy, resource collection, producer publication/UP, cleanup/reuse, parent-death reconciliation, actual1/5/6 runtime, real provider/client, complete secret lifetime or release acceptance.')
 dest=pathlib.Path(f'target/lab-state/secret-assembly-run-{run}.json')
 with dest.open('x')as f:os.fchmod(f.fileno(),0o600);json.dump(out,f,indent=2);f.write('\n')
 print(json.dumps(dict(record=str(dest),platform=r['platform'],fault=c['assembly_fault'],**proof['assembly'],requirement8_complete=False)))
