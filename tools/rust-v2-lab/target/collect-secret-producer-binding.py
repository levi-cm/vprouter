"""Strict frozen same-group metadata binding; no operational authority export."""
import datetime,hashlib,importlib.util,json,os,pathlib,re,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
from quarantine_evidence_base import validate_prefix
from producer_binding_evidence_schema import validate_binding
p=pathlib.Path(__file__).with_name('collect-secret-assembly.py');spec=importlib.util.spec_from_file_location('binding_assembly',p);assembly=importlib.util.module_from_spec(spec);spec.loader.exec_module(assembly)
def validate_complete(c,continuation=False):
 assert type(continuation)is bool
 old=assembly.validate_complete(c,continuation=True);assert old['assembly']['assembly_original_context_continued']is True and old['assembly']['final_whole_chain_drop_verified']is False
 return dict(assembly=old,producer_binding=validate_binding(c,continuation=continuation))
if __name__=='__main__':
 c=validate_prefix(sys.argv[1],sys.argv[2],producer_binding=True);proof=validate_complete(c);r=c['record'];path=c['path'];run=re.fullmatch('actual-program-run-([0-9]+).json',path.name)[1]
 names=['collect-secret-producer-binding.py','producer_binding_evidence_schema.py','collect-secret-assembly.py','assembly_evidence_schema.py','collect-secret-quarantine.py','quarantine_evidence_base.py','quarantine_history_schema.py','quarantine_native_schema.py','quarantine_producer_schema.py','collect-secret-movement.py','movement_evidence_base.py','collect-secret-provision.py','provision_evidence_base.py','wireguard_inventory_schema.py']
 dependencies=[pathlib.Path(__file__).with_name(name)for name in names]+[assembly.mechanics_path]
 out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(c['raw']).hexdigest(),source_binding=r['source_binding'],artifact_sha256=r['artifact_sha256'],context_sha256=r['context_sha256'],platform=r['platform'],component_test_mode=r['component_test_mode'],collectors=[dict(path=str(p),sha256=hashlib.sha256(assembly.mechanics_bytes if p==assembly.mechanics_path else p.read_bytes()).hexdigest())for p in dependencies],input_manifest=c['manifest'],gateway=c['gateway'],host_declaration=c['host'],witness=c['producer_binding_top'],environment=c['environment'],proof=proof,real_client_acceptance='NOT_RUN',requirement8_complete=False,allnine_complete=False,limit='Same originally created empty group is bound to selected canonical metadata only after fresh DATA quarantine/group observation and actual Result ACK/readback/writer0. Original live assembly/69 writers/17 windows remain intact; new query+binding share one new original2 window. Unacknowledged/failed publication retains exact proposals, charges and owners. No SocketProducer, placement, permit, health READY, links/routes/UP, cleanup/reuse, parent-death reconciliation, actual1/5/6 runtime, real provider/client, complete secret lifetime or release acceptance.')
 dest=pathlib.Path(f'target/lab-state/secret-producer-binding-run-{run}.json')
 with dest.open('x')as f:os.fchmod(f.fileno(),0o600);json.dump(out,f,indent=2);f.write('\n')
 print(json.dumps(dict(record=str(dest),platform=r['platform'],fault=c['producer_binding_fault'],**proof['producer_binding'],requirement8_complete=False)))
