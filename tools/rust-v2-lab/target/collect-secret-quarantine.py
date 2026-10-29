"""Strict frozen exclusive initial-quarantine and original group evidence."""
import datetime,hashlib,importlib.util,json,os,pathlib,re,sys
if not __debug__:raise RuntimeError('optimized_python_refused')
from quarantine_evidence_base import validate_prefix
from quarantine_history_schema import validate_initial_history,validate_own_intent_polling
from quarantine_native_schema import validate_initial_receipts
from quarantine_producer_schema import validate_producer
movement_path=pathlib.Path(__file__).with_name('collect-secret-movement.py')
spec=importlib.util.spec_from_file_location('quarantine_movement_validation',movement_path);movement=importlib.util.module_from_spec(spec);spec.loader.exec_module(movement)
def validate_quarantine(c,continuation=False):
 assert type(continuation)is bool
 old=movement.validate_movement(c,continuation=True)
 assert old['movement_original_context_continued']is True and old['final_whole_chain_drop_verified']is False
 w=c['quarantine_top'];p=w['preparation']
 history=validate_initial_history(c,p)
 own_intent=validate_own_intent_polling(c,p)
 receipts=validate_initial_receipts(c,p,w['operations'],w['quarantine_query'],w['wan'])
 producer=validate_producer(c,continuation=continuation)
 return dict(movement=old,quarantine_history=history,own_intent_polling=own_intent,netfilter_receipts=receipts,producer=producer)
if __name__=='__main__':
 c=validate_prefix(sys.argv[1],sys.argv[2]);proof=validate_quarantine(c);r=c['record'];path=c['path'];run=re.fullmatch('actual-program-run-([0-9]+).json',path.name)[1]
 names=['collect-secret-quarantine.py','quarantine_evidence_base.py','quarantine_history_schema.py','quarantine_native_schema.py','quarantine_producer_schema.py','collect-secret-movement.py','movement_evidence_base.py','collect-secret-provision.py','provision_evidence_base.py','wireguard_inventory_schema.py']
 dependencies=[pathlib.Path(__file__).with_name(name)for name in names]
 out=dict(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),record=str(path),record_sha256=hashlib.sha256(c['raw']).hexdigest(),source_binding=r['source_binding'],artifact_sha256=r['artifact_sha256'],context_sha256=r['context_sha256'],platform=r['platform'],component_test_mode=r['component_test_mode'],collectors=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in dependencies],input_manifest=c['manifest'],gateway=c['gateway'],host_declaration=c['host'],witness=c['quarantine_top'],environment=c['environment'],proof=proof,real_client_acceptance='NOT_RUN',requirement8_complete=False,allnine_complete=False,limit='Original synthetic DOWN movement, six exclusive initial-quarantine installation receipts and exclusive original empty cgroup creation with constructor/writer fault retention. Child observations are historical; no post-reap current table, producer publication/exceptions, placement/UP, parent-death reconciliation, cleanup/reuse, real client/provider, complete secret lifetime or release acceptance.')
 destination=pathlib.Path(f'target/lab-state/secret-quarantine-run-{run}.json')
 with destination.open('x')as stream:os.fchmod(stream.fileno(),0o600);json.dump(out,stream,indent=2);stream.write('\n')
 print(json.dumps(dict(record=str(destination),platform=r['platform'],fault=c['quarantine_fault'],**proof['producer'],requirement8_complete=False)))
