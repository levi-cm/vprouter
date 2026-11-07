#!/usr/bin/env python3
"""Offline acceptance and adversarial tests; all fixture writes are temporary."""
import copy
import importlib.util
import json
import multiprocessing
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if not __debug__:
    raise RuntimeError('optimized_python_refused')

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'tools/rust-v2-lab/validate-run410-witness.py'
RAW = ROOT / 'target/lab-state/actual-program-run-410.json'


def split(record):
    lines = record['stdout'].splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith('LAB_SECRET_BOOTSTRAP '))
    return lines, index, json.loads(lines[index].split(' ', 1)[1])


def validator_module():
    spec = importlib.util.spec_from_file_location('contract_types',TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TYPE_VALIDATOR = None
LEAF_TYPES = None


def contract_types():
    global TYPE_VALIDATOR,LEAF_TYPES
    if TYPE_VALIDATOR is None:
        TYPE_VALIDATOR = validator_module()
        witness = split(json.loads(RAW.read_bytes()))[2]
        LEAF_TYPES = dict(TYPE_VALIDATOR.contract_leaves(witness))
    return TYPE_VALIDATOR,LEAF_TYPES


def split_rust_types(text, delimiter=','):
    depth, start, result = 0, 0, []
    for i,c in enumerate(text):
        if c in '(<[':
            depth += 1
        elif c in ')>]':
            depth -= 1
        elif c == delimiter and depth == 0:
            result.append(text[start:i].strip())
            start = i+1
    result.append(text[start:].strip())
    return result


def rust_primitive_paths(value, rust_type, path):
    """Independent Rust type decomposition; never consult validator SCHEMAS."""
    if rust_type.startswith('Option<'):
        yield from rust_primitive_paths(value,rust_type[7:-1],path)
    elif re.fullmatch(r'[ui](8|16|32|64)|usize|f64|bool',rust_type):
        yield path,rust_type
    elif rust_type.startswith('Vec<') and type(value) is list:
        for i,item in enumerate(value):
            yield from rust_primitive_paths(item,rust_type[4:-1],path+(i,))
    elif rust_type.startswith('[') and type(value) is list:
        item_type = split_rust_types(rust_type[1:-1],';')[0]
        for i,item in enumerate(value):
            yield from rust_primitive_paths(item,item_type,path+(i,))
    elif rust_type.startswith('(') and type(value) is list:
        for i,item_type in enumerate(split_rust_types(rust_type[1:-1])):
            yield from rust_primitive_paths(value[i],item_type,path+(i,))


def source_width_inventory(witness):
    module,_ = contract_types()
    sources = module.CONTRACT['field_sources']
    declarations = []
    seen = set()
    for name in sorted({key.split('.')[0] for key in sources}):
        entries = {key.split('.')[1]:value for key,value in sources.items() if key.startswith(name+'.')}
        declaration = next(iter(entries.values()))['declaration']
        file,rust_name = declaration.rsplit('::',1)
        declarations.append((file,rust_name,{k:v['rust_type'] for k,v in entries.items()}))
        seen.add((file,rust_name))
    return declarations,dict(module.contract_leaves(witness)),seen


def rust_fields(relative, name):
    text = (ROOT / relative).read_text()
    match = re.search(r'\bstruct ' + name + r'\s*\{(.*?)^}', text, re.S | re.M)
    assert match, (relative, name)
    return [(m.group(1),m.group(2).strip()) for m in re.finditer(
        r'^    (?:pub(?:\([^)]*\))? )?(\w+): (.*),$', match.group(1), re.M)]


def leaf_cases(value, path=()):
    if type(value) is dict:
        for key, item in value.items():
            yield from leaf_cases(item, path + (key,))
    elif type(value) is list and value:
        for index, item in enumerate(value):
            yield from leaf_cases(item, path + (index,))
    else:
        yield path, value


def integer_bits(path):
    module,leaf_types = contract_types()
    if path and path[0] == 'tun_info':
        # Resolve synthetic nonempty TUN tuples through Link's contract, even
        # though the real record contains an empty list. No key-to-width map.
        synthetic = dict(module.contract_leaves([[1,[2]],[3,[4]]],
                         module.SCHEMAS['Link']['tun_info'],('tun_info',)))
        spec = synthetic.get(path)
    else:
        spec = leaf_types.get(path)
    if spec not in module.INTEGER_RANGES:
        raise AssertionError('unmapped Rust integer path: '+repr(path))
    maximum = module.INTEGER_RANGES[spec][1]
    return maximum.bit_length()


def sweep_chunk(paths):
    spec = importlib.util.spec_from_file_location('sweep_validator', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    record = json.loads(RAW.read_bytes())
    lines, index, witness = split(record)
    failures, total = [], 0
    with tempfile.TemporaryDirectory(prefix='run410-leaf-') as tmp:
        raw = Path(tmp) / 'record.json'
        for path, original in paths:
            parent = witness
            for key in path[:-1]:
                parent = parent[key]
            key = path[-1]
            mutations = [('wrong_type', {'invalid_leaf_type': True})]
            if type(original) is int:
                mutations += [('negative', -1), ('overflow', 2 ** integer_bits(path))]
            # All non-null scalars have a required serialized key or fixed-array
            # slot. Absence tests object keys; null tests populated array slots.
            if type(key) is str:
                mutations.append(('absent', None))
            elif original is not None:
                mutations.append(('null', None))
            for kind, replacement in mutations:
                if kind == 'absent':
                    del parent[key]
                else:
                    parent[key] = replacement
                lines[index] = 'LAB_SECRET_BOOTSTRAP ' + json.dumps(witness, separators=(',', ':'))
                record['stdout'] = '\n'.join(lines) + '\n'
                raw.write_text(json.dumps(record, separators=(',', ':')))
                receipt = module.validate(raw)
                total += 1
                if receipt['verdict'] != 'FAIL':
                    failures.append((path, kind))
                parent[key] = original
    return total, failures



def reviewer_records(module, original):
    """Reconstruct documented probes; never claim these are lost reviewer bytes.

    The four reports specify 96 negative fixtures (18+15+37+26); round 5 adds
    13. Unnamed round-3 rejection controls are reconstructed by their documented
    predicate family. All changes run through the actual CLI, including raw
    duplicate-key and NaN bytes. No dependency on a previous boot's /tmp.
    """
    result = {}
    def add(name, change=None, row_change=None, raw_change=None):
        record = copy.deepcopy(original)
        lines, index, w = split(record)
        if change:
            change(w)
        lines[index] = 'LAB_SECRET_BOOTSTRAP ' + json.dumps(w, separators=(',', ':'))
        if row_change:
            rows = [json.loads(line) if line.startswith('{') else line for line in lines]
            row_change(rows, w)
            lines = [json.dumps(row, separators=(',', ':')) if type(row) is dict else row for row in rows]
        record['stdout'] = '\n'.join(lines)+'\n'
        raw = json.dumps(record, separators=(',', ':')).encode()
        if raw_change:
            raw = raw_change(raw)
        assert raw != json.dumps(original, separators=(',', ':')).encode(), name
        result[name] = raw
    def set_(obj, key, value): obj[key] = copy.deepcopy(value)
    def each(w, predicate, change):
        for _,obj in list(module.objects(w)):
            if predicate(obj): change(obj)
    def link(o, kind): return set(o) == set(module.SCHEMAS['Link']) and o['kind'] == kind
    def device(o): return 'peers' in o and 'public_key' in o
    def binding(o): return 'pins' in o and len(o['pins']) == 6
    def provision(w): return w['host_addition']['producer_binding']['assembly']['quarantine']['movement']['provision']
    def wan(w): return w['host_addition']['producer_binding']['assembly']['quarantine']['wan']
    def byte(o,k): o[k][0] ^= 1
    add('authorization',lambda w:set_(w['operations'][0],'placement_authorized',True))
    add('boot_id',lambda w:set_(w['preparation']['canonical_owner_epoch'],'boot_id','00000000-0000-0000-0000-000000000000'))
    add('charge',lambda w:set_(w,'charges_after_drop',[0,0]))
    add('deadline',lambda w:set_(w['queries'][0],'verified_at',w['queries'][0]['deadline']))
    add('drop_row',row_change=lambda rows,w:rows.pop(0))
    add('duplicate_key',raw_change=lambda b:b.replace(b'"exit_code":0',b'"exit_code":0,"exit_code":0',1))
    add('fault',lambda w:set_(w,'fault',1))
    add('nan',raw_change=lambda b:b.replace(b'final_process_verified_at\\":',b'final_process_verified_at\\":NaN,\\"discard\\":',1))
    add('unknown_field',lambda w:set_(w['operations'][0],'foreign',True))
    add('binding_result_8pins',lambda w:w['preparation']['producer_binding']['result']['pins'].extend([[1,2,3],[4,5,6]]))
    add('bootstrap_result_6pins',lambda w:set_(w['preparation']['bootstrap'][0]['result'],'pins',w['preparation']['bootstrap'][0]['result']['pins'][:6]))
    add('own_intent_identity',lambda w:set_(w['own_intent_polling'],'pid',w['own_intent_polling']['pid']+1))
    add('query_intent_index',lambda w:set_(w['own_query_intent_polling'],'index',0))
    for name,key,value in [('preparation_fenced','mutation_fenced',True),('preparation_pending','canonical_pending',True),
                           ('preparation_phase','entry_phase','failed'),('preparation_unreaped','native_children_reaped',False)]:
        add(name,lambda w,k=key,v=value:set_(w['preparation'],k,v))
    add('retained_prefix_birth',lambda w:set_(w['preparation']['writers'][0],'pid',w['preparation']['writers'][0]['pid']+1))
    def query_pid(w):
        w['queries'][0]['birth']['pid'] = w['preparation']['bootstrap_queries'][0]['birth']['pid'] = 2**32
    add('bootstrap_query_u32_pid_overflow',query_pid)
    def initial(w):
        q=w['preparation']['bootstrap_queries'][0]
        q['initial']={k:copy.deepcopy(q[k]) for k in ('request','birth','facts','verified_at')}
    add('bootstrap_query_has_initial',initial)
    for field,value in [('kind','sockets'),('scope','data')]:
        add('host_bootstrap_policy_wrong_'+field,lambda w,k=field,v=value:each(w,
            lambda o:o.get('kind')=='initial_quarantine' and o.get('scope')=='host',lambda o:set_(o,k,v)))
    add('entry_producer_binding_mismatch_all_prefixes',lambda w:each(w,lambda o:'binding' in o and 'parent' in o,lambda o:byte(o,'binding')))
    add('binding_policy_mismatch_canonical_all_prefixes',lambda w:each(w,lambda o:binding(o) and 'policy' in o,lambda o:byte(o,'policy')))
    add('binding_query_mismatch_all_prefixes',lambda w:each(w,lambda o:binding(o) and 'query' in o,lambda o:byte(o,'query')))
    def binding_data(w):
        each(w,lambda o:binding(o),lambda o:set_(o['data'] if 'data' in o else o['namespace'],'ino',(o['data'] if 'data' in o else o['namespace'])['ino']+100))
    add('binding_data_mismatch_all_prefixes',binding_data)
    for name,key,value in [('host_fault_nonzero','fault',1),('host_negative_count_zero','canonical_negative_checks',0)]:
        add(name,lambda w,k=key,v=value:set_(w['host_addition'],k,v))
    add('host_own_intent_identity',lambda w:set_(w['host_addition']['own_intent_polling'],'pid',2))
    # Four explicitly documented second-round rejection controls.
    add('control_binding_result_size',lambda w:w['preparation']['producer_binding']['result']['pins'].pop())
    add('control_preparation_unreserved',lambda w:set_(w['preparation'],'service_reserved',False))
    add('control_query_intent_start',lambda w:set_(w['own_query_intent_polling'],'start',1))
    add('control_two_queued_policy_polls',lambda w:set_(w['own_intent_polling'],'queued_polls',2))
    for suffix,source in [('host','host'),('data','data')]:
        add('transport_creation_source_is_'+suffix,lambda w,k=source:set_(provision(w)['transport_creation'],'source',provision(w)['transport_creation'][k]))
    for name,obj,key in [('transport_creation_source_foreign','transport_creation','source'),
                         ('transport_mount_source_foreign','transport_mount','original_source'),
                         ('transport_creation_host_foreign','transport_creation','host'),
                         ('transport_creation_data_foreign','transport_creation','data'),
                         ('transport_mount_directory_foreign','transport_mount','original_directory')]:
        add(name,lambda w,o=obj,k=key:set_(provision(w)[o][k],'ino',provision(w)[o][k]['ino']+100))
    def transport_pair(w):
        p=provision(w); p['transport_creation']['source']['ino']+=100
        p['transport_mount']['original_source']=copy.deepcopy(p['transport_creation']['source'])
    add('transport_creation_and_mount_foreign_source',transport_pair)
    add('transport_mount_wrong_placeholder_mode',lambda w:set_(provision(w)['transport_mount']['placeholder'],'mode',0o100666))
    for name,key,value in [('wireguard_up_all_copies','up',True),('wireguard_wrong_link_kind_all_copies','kind','veth')]:
        add(name,lambda w,k=key,v=value:each(w,lambda o:link(o,'wireguard'),lambda o:set_(o,k,v)))
    def moved(w,field,value):
        namespace=w['preparation']['data_network']
        def change(o):
            if field in ('name','alias'): o['link'][field]=value
            elif field=='public_key': byte(o['wireguard'],field)
            else: o['wireguard']['peers']=[]
        each(w,lambda o:o.get('namespace')==namespace and type(o.get('link')) is dict and 'wireguard' in o,change)
    for suffix,key,value in [('name','name','foreignwg'),('alias','alias','foreign-alias'),('key','public_key',None),('peers_removed','peers',None)]:
        name='moved_wireguard_'+suffix+('_substitution' if suffix!='peers_removed' else '')
        add(name,lambda w,k=key,v=value:moved(w,k,v))
    # 22 round-3 controls: documented families, fresh names where originals were
    # not named in the report. They are reconstruction, not exact-byte replay.
    controls=[('u8',256),('u16',65536),('u32',2**32),('u64',2**64),('i32',2**31)]
    types=dict(module.contract_leaves(split(original)[2]))
    for ty,value in controls:
        path=next(p for p,t in types.items() if t==ty)
        for label,v in [('overflow',value),('wrong_type',{})]:
            def change(w,p=path,v=v):
                for key in p[:-1]: w=w[key]
                w[p[-1]]=copy.deepcopy(v)
            add('r3_control_'+ty+'_'+label,change)
    for i in range(3):
        add('r3_control_bootstrap_pin_writable_'+str(i),lambda w,i=i:set_(w['operations'][i]['pins'][1],2,0o40777))
        add('r3_control_bootstrap_pin_duplicate_'+str(i),lambda w,i=i:set_(w['operations'][i]['pins'],1,w['operations'][i]['pins'][0]))
    add('r3_control_host_veth_up',lambda w:each(w,lambda o:link(o,'veth') and o['name'].startswith('vh'),lambda o:set_(o,'up',True)))
    add('r3_control_route_kind_256',lambda w:each(w,lambda o:set(o)==set(module.SCHEMAS['Route']),lambda o:set_(o,'kind',256)))
    add('r3_control_wrong_query_initial',initial)
    add('r3_control_wrong_intent_count',lambda w:set_(w['host_addition']['own_intent_polling'],'held_polls',0))
    add('r3_control_origin_digest',lambda w:byte(provision(w)['attachment']['preparation']['attachment']['origin'],'public_result'))
    add('r3_control_authority',lambda w:set_(w['operations'][0],'placement_authorized',True))
    # Fourth-round 26 reported contradictions.
    add('host_addition_zero_digest_all_copies',lambda w:each(w,lambda o:type(o.get('addition')) is list,lambda o:set_(o['addition'],0,[0]*32)))
    add('assembly_child_limit_wrong',lambda w:set_(w['host_addition']['producer_binding']['assembly'],'global_child_capacity_limit',65))
    def directory(w):
        each(w,lambda o:'directory' in o and 'name' in o and ('source' in o) and ('host' in o or 'mounted_at' in o),lambda o:set_(o['directory'],'ino',o['directory']['ino']+100))
        provision(w)['transport_mount']['original_directory']['ino']+=100
    add('transport_directory_foreign_from_original_journal',directory)
    def window(w):
        for k in ('requested_at','deadline','verified_at'): wan(w)[k]+=1
    add('wan_window_foreign_from_host_policy',window)
    add('wan_verified_after_host_policy_birth',lambda w:set_(wan(w),'verified_at',w['preparation']['netfilter'][1]['birth']['born_at']+0.001))
    for name,action in [
        ('wireguard_public_key_foreign_from_input_all_copies',lambda o:byte(o,'public_key')),
        ('wireguard_peers_removed_all_copies',lambda o:set_(o,'peers',[])),
        ('wireguard_result_device_name_differs_from_link',lambda o:set_(o,'name','foreignwg')),
        ('wireguard_result_device_index_differs_from_link',lambda o:set_(o,'index',o['index']+100)),
        ('wireguard_allowed_ips_empty_all_copies',lambda o:[set_(p,'allowed_ips',[]) for p in o['peers']])]:
        add(name,lambda w,action=action:each(w,device,action))
    for suffix,key,value in [('name','name','foreignwg'),('alias','alias','foreign-alias')]:
        add('wireguard_'+suffix+'_foreign_from_allocation_all_copies',lambda w,k=key,v=value:each(w,lambda o:link(o,'wireguard'),lambda o:set_(o,k,v)))
    def provision_only(w,key):
        def change(o):
            r=o['result']
            if key=='public_key': byte(r['wireguard'],key)
            else: r['link'][key]+=100
        each(w,lambda o:o.get('kind')=='provision' and type(o.get('result')) is dict and o['result'].get('link') is not None,change)
    add('wireguard_provision_query_key_mismatch',lambda w:provision_only(w,'public_key'))
    add('wireguard_original_provision_query_link_mismatch',lambda w:provision_only(w,'mtu'))
    for kind in ('wireguard','veth'):
        for field,value in [('mtu',1400),('controller',1),('port_kind','bridge'),('promiscuity',1),('all_multicast',1),('alternate_names',['foreign-alt'])]:
            add(kind+'_link_guard_'+field+'_all_copies',lambda w,k=kind,f=field,v=value:each(w,lambda o:link(o,k),lambda o:set_(o,f,v)))
    assert len(result)==96,len(result)
    # Round 5: preserve all copies and update the public declaration digest.
    for name,key,value in [('wan_zero_mac','address',[0]*6),('wan_multicast_mac','address',[1,2,3,4,5,6]),
                           ('wan_index_zero','index',0),('wan_forbidden_name','name','lo'),
                           ('wan_invalid_name','name','bad/name'),('wan_allocated_name','name',None)]:
        def change_rows(rows,w,key=key,value=value):
            host=next(r['secret_quarantine_host'] for r in rows if type(r) is dict and 'secret_quarantine_host' in r)
            descriptor=next(r['secret_attachment_descriptor'] for r in rows if type(r) is dict and 'secret_attachment_descriptor' in r)
            value=value if value is not None else descriptor['allocation']['exits'][0]['host_interface']
            host['declaration']['wan'][key]=copy.deepcopy(value); wan(w)[key]=copy.deepcopy(value)
            encoded=module.canonical(host['declaration']); old=host['sha256']
            import hashlib
            host['sha256']=hashlib.sha256(encoded).hexdigest();host['bytes']=len(encoded)
            old_bytes=list(bytes.fromhex(old));new_bytes=list(bytes.fromhex(host['sha256']))
            for _,o in module.objects(w):
                for field in ('host_declaration','declaration_digest'):
                    if o.get(field)==old_bytes:o[field]=new_bytes[:]
            # w was decoded separately; replace the embedded witness after edits.
            i=next(i for i,r in enumerate(rows) if type(r) is str and r.startswith('LAB_SECRET_BOOTSTRAP '))
            rows[i]='LAB_SECRET_BOOTSTRAP '+json.dumps(w,separators=(',',':'))
        add(name,row_change=change_rows)
    for name,kind,field,value in [('wireguard_index_zero','wireguard','index',0),
                                  ('wireguard_hardware_type_ethernet','wireguard','hardware_type',1),
                                  ('veth_hardware_type_wireguard','veth','hardware_type',65534),
                                  ('wireguard_peer_index_present','wireguard','peer_index',999),
                                  ('veth_tun_value_257','veth','tun_info',[[1,[0]*257]]),
                                  ('veth_tun_count_65','veth','tun_info',[[1,[0]]]*65)]:
        def change(w,k=kind,f=field,v=value):
            each(w,lambda o:link(o,k),lambda o:set_(o,f,v))
            if k=='wireguard' and f=='index':each(w,device,lambda o:set_(o,'index',0))
        add(name,change)
    add('binding_group_mode_writable',lambda w:each(w,binding,lambda o:set_(o['pins'][1],2,0o40777)))
    assert len(result)==109,len(result)
    return result


class WitnessValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing production validation is an assertion failure in the RED run.
        assert TOOL.is_file(), 'typed run410 validator is not implemented'
        spec = importlib.util.spec_from_file_location('run410_witness', TOOL)
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)
        cls.record = json.loads(RAW.read_bytes())
        cls.lines, cls.index, cls.witness = split(cls.record)

    def test_stale_predicate_lineage_id_is_refused(self):
        # Review r6 M7: a lineage ID with no extracted predicate must fail inventory integrity.
        lineage = self.m.CONTRACT['predicate_lineage']
        stale = 'f' * 20
        self.assertNotIn(stale, lineage)
        lineage[stale] = next(iter(lineage.values()))
        try:
            with self.assertRaisesRegex(ValueError, 'stale predicate lineage mapping'):
                self.m.guard_dispositions()
        finally:
            del lineage[stale]
        self.m.guard_dispositions()

    def receipt(self, record):
        with tempfile.TemporaryDirectory(prefix='run410-witness-') as tmp:
            path = Path(tmp) / 'record.json'
            path.write_text(json.dumps(record, allow_nan=False))
            return self.m.validate(path)

    def rejected(self, record, check):
        receipt = self.receipt(record)
        self.assertEqual(receipt['verdict'], 'FAIL')
        self.assertTrue(any(c['status'] == 'FAIL' and c['name'] == check
                            for c in receipt['checks']), receipt)

    def mutated(self, change):
        record = copy.deepcopy(self.record)
        lines, index, witness = split(record)
        change(witness)
        lines[index] = 'LAB_SECRET_BOOTSTRAP ' + json.dumps(witness)
        record['stdout'] = '\n'.join(lines) + '\n'
        return record

    def test_all_five_review_rounds_reconstructed_through_cli(self):
        fixtures = reviewer_records(self.m, self.record)
        self.assertEqual(len(fixtures), 109)
        with tempfile.TemporaryDirectory(prefix='run410-review-reconstructed-') as tmp:
            for name, raw in fixtures.items():
                with self.subTest(fixture=name):
                    path = Path(tmp)/(name+'.json'); path.write_bytes(raw)
                    result = subprocess.run([sys.executable,'-B',str(TOOL),str(path)],capture_output=True)
                    receipt = json.loads(result.stdout)
                    self.assertEqual(result.returncode,1,name)
                    self.assertEqual(receipt['verdict'],'FAIL',name)
                    self.assertTrue({c['name'] for c in receipt['checks'] if c['status']=='FAIL'}-{'frozen_bindings'},name)

    def test_extractor_multiline_guards_and_exact_serde_types(self):
        path = ROOT/'tools/rust-v2-lab/witness-contract-extract.py'
        self.assertTrue(path.is_file())
        spec = importlib.util.spec_from_file_location('contract_extractor',path)
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        source = """#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    // Width, Option and nested fixed arrays must come from Rust.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<[(u16, [u8; 32]); 6]>,
}
fn validate(&self) -> Result<()> {
    if self.namespace != if kind { a } else { b }
        || self.value.len() != 6 {
        return Err(Error::Bad);
    }
    if self.one { accept(); }
    if self.two { return Err(Error::Bad); }
    require(self.good)?;
    ensure!(self.safe);
    assert_eq!(self.count, 6);
    match self.result { Some(r) if r.namespace == self.namespace => Ok(()), _ => Err(Error::Bad) }
    Ok(())
}
"""
        declarations = m.declarations('sample.rs',source)
        field = declarations[0]['fields']['value']
        self.assertEqual(field['rust_type'],'Option<[(u16, [u8; 32]); 6]>')
        self.assertTrue(field['option'])
        self.assertEqual(field['line'],6)
        guards = m.guards_in('sample.rs',source)
        conditions = [g['expression'] for g in guards if g['kind']=='if_return_err']
        self.assertIn('self.namespace != if kind { a } else { b } || self.value.len() != 6',conditions)
        self.assertIn('self.two',conditions)
        self.assertNotIn('self.one { accept(); } if self.two',conditions)
        self.assertIn('r.namespace == self.namespace',[g['expression'] for g in guards if g['kind']=='match_guard'])
        self.assertEqual(len(guards),6)

    def test_every_public_allocation_exit_has_native_plan_guards(self):
        cases = [('host_interface','foreign'),('exit_id',self.witness['preparation']['member']),
                 ('state_dir','/'),('transport_subnet','10.0.0.0/30')]
        for key,value in cases:
            record = copy.deepcopy(self.record)
            lines = list(self.lines)
            for i,line in enumerate(lines):
                if line.startswith('{'):
                    row = json.loads(line)
                    if 'secret_attachment_descriptor' in row:
                        row['secret_attachment_descriptor']['allocation']['exits'][1][key] = value
                        lines[i] = json.dumps(row)
            record['stdout'] = '\n'.join(lines)+'\n'
            with self.subTest(field=key):
                self.rejected(record,'allocation_contract')

    def test_native_peer_plan_guards_beyond_reviewer_fixtures(self):
        for field in ('public_key','endpoint','allowed_ips'):
            def change(w):
                for _,obj in self.m.objects(w):
                    if 'peers' in obj and 'public_key' in obj:
                        for peer in obj['peers']:
                            if field == 'public_key':
                                peer[field][0] ^= 1
                            elif field == 'endpoint':
                                peer[field] = '185.66.0.2:51820'
                            else:
                                peer[field] = [['0.0.0.0',1]]
            with self.subTest(field=field):
                self.rejected(self.mutated(change),'contract_success')

    def test_contract_drift_and_exhaustive_guard_dispositions(self):
        extractor = ROOT/'tools/rust-v2-lab/witness-contract-extract.py'
        contract_path = ROOT/'tools/rust-v2-lab/witness-contract.json'
        self.assertTrue(extractor.is_file(), 'source contract extractor missing')
        self.assertTrue(contract_path.is_file(), 'generated source contract missing')
        result = subprocess.run([sys.executable,'-B',str(extractor)],capture_output=True,cwd=ROOT)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,contract_path.read_bytes(), 'source contract drift')
        contract = json.loads(result.stdout)
        self.assertGreater(len(contract['guards']),100)
        dispositions = self.m.guard_dispositions()
        self.assertEqual(set(dispositions), {g['id'] for g in contract['guards']})
        for guard in contract['guards']:
            with self.subTest(guard=guard['id']):
                self.assertTrue(guard['expression'])
                self.assertIn('fields',guard)
                disposition = dispositions[guard['id']]
                self.assertIn(disposition['status'],('enforced','partial'))
                for predicate in disposition['predicates'].values():
                    self.assertIn(predicate['status'],('enforced','unenforceable_offline','pending'))
                    if predicate['status']=='enforced':
                        self.assertTrue(predicate['projection_proof'])
                        self.assertTrue(all(callable(getattr(self.m,k,None)) for k in predicate['check_ids']))
                    else:
                        self.assertTrue(predicate['reason'])
        # An unseen Rust guard cannot acquire a blanket function/file mapping.
        self.assertRaises(ValueError,self.m.guard_dispositions,
                          contract['guards']+[dict(id='new-unmapped-guard',expression='x != y',fields=[])])

    def extractor(self):
        spec=importlib.util.spec_from_file_location('extract_r6',ROOT/'tools/rust-v2-lab/witness-contract-extract.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_transitive_closure_resolves_helpers_traits_closures_and_macros(self):
        m=self.extractor()
        texts={'entry.rs': 'fn success() { let f = || helper(); f(); wrap!(); obj.poll(); }',
               'helper.rs': 'fn helper() { leaf(); } fn leaf() {} macro_rules! wrap { () => { helper() }; } impl Trait for T { fn poll(&self) { helper(); } }'}
        graph=m.validation_call_graph(texts,{'entry.rs'})
        names={n['name'] for n in graph['nodes']}
        self.assertTrue({'helper','leaf','poll','wrap'} <= names)
        self.assertFalse(graph['unresolved'])
        for edge in graph['edges']:
            self.assertTrue(edge.get('targets') or (edge.get('external') and edge.get('reason')),edge)
        with self.assertRaisesRegex(ValueError,'unresolved.*unknown_callee'):
            m.validation_call_graph({'entry.rs':'fn success() { unknown_callee(); }'},{'entry.rs'})
        with self.assertRaisesRegex(ValueError,'unresolved.*missing_module'):
            m.validation_call_graph({'entry.rs':'fn success() { missing_module::len(); }'},{'entry.rs'})
        self.assertIn('crates/vprouter-netfilter/src/fixed_producer.rs',self.m.CONTRACT['source_files'])
        self.assertTrue(any(g['function']=='observe_group' for g in self.m.CONTRACT['guards']))

    def test_real_graph_closure_and_incomplete_full_claim(self):
        graph=self.m.CONTRACT['call_graph']
        ids={n['id'] for n in graph['nodes']}
        self.assertFalse(graph['unresolved'])
        for edge in graph['edges']:
            if edge.get('targets'):
                self.assertTrue(set(graph['target_sets'][edge['targets']]) <= ids,edge)
            else:
                self.assertTrue(edge.get('external') and edge.get('reason'),edge)
        receipt=self.m.validate(RAW)
        self.assertEqual(receipt['verdict'],'PASS')
        self.assertEqual(receipt['full_bootstrap_witness_validation'],'INCOMPLETE')
        self.assertFalse(receipt['complete_predicate_validation'])
        self.assertGreater(receipt['predicate_counts']['pending'],0)
        self.assertFalse(receipt['runtime_acceptance'])
        self.assertFalse(receipt['release_ready'])

    def test_atomic_predicates_and_mixed_guard_dispositions(self):
        m=self.extractor()
        atoms=m.atomic_predicates('a != b || (c == d && e.is_none()) || xs.iter().any(|x| x.n == 0 || x.m > 2)')
        self.assertEqual([a['expression'] for a in atoms],['a != b','c == d','e.is_none()','x.n == 0','x.m > 2'])
        self.assertEqual(m.atomic_predicates('fstatfs(fd).map_err(|_| Error::Foreign)?.f_type != 1')[0]['expression'],
                         'fstatfs(fd).map_err(|_| Error::Foreign)?.f_type != 1')
        for guard in self.m.CONTRACT['guards']:
            disposition=self.m.GUARD_DISPOSITIONS[guard['id']]
            self.assertEqual(set(disposition['predicates']),{p['id'] for p in guard['predicates']})
            complete=all(p['status']=='enforced' for p in disposition['predicates'].values())
            self.assertEqual(disposition['status']=='enforced',complete)
            self.assertEqual(set(disposition['skipped_predicates']),{k for k,p in disposition['predicates'].items() if p['status']!='enforced'})

    def test_offline_predicates_require_mechanical_absence_certificates(self):
        m=self.extractor();contract=self.m.CONTRACT
        for guard in contract['guards']:
            for predicate in guard['predicates']:
                disposition=self.m.GUARD_DISPOSITIONS[guard['id']]['predicates'][predicate['id']]
                decision=m.predicate_decidability(predicate,contract)
                self.assertEqual(disposition['decidability'],decision)
                if disposition['status']=='unenforceable_offline':
                    self.assertEqual(decision['status'],'absent_value')
                    self.assertTrue(decision['absence_proofs'])
                    for proof in decision['absence_proofs']:
                        self.assertEqual(proof['serialization_paths'],[])
        for expression in ('link.index == 0','link.hardware_type != hardware','created.peer_index.is_some()',
                           'l.tun_info.len() > 64','s.st_mode & 0o7777 != 0o700'):
            decision=m.predicate_decidability({'expression':expression},contract)
            self.assertNotEqual(decision['status'],'absent_value',expression)

    def test_direct_emitter_search_is_not_a_transitive_absence_proof(self):
        m=self.extractor()
        # A helper can carry the intrinsic to an emitter under another name.
        # Until def-use/alias paths are proved, absence of the literal expression
        # in json_builders is insufficient to label the predicate offline.
        contract=dict(field_sources={},json_builders=[dict(file='x.rs',line=1,fields={'owner':'identity_helper()'})])
        for expression in ('std::process::id() != creator','Rc::ptr_eq(&a, &b)','Instant::now() > end'):
            self.assertNotEqual(m.predicate_decidability({'expression':expression},contract)['status'],'absent_value')

    def test_every_real_witness_leaf_through_validate(self):
        leaves = list(leaf_cases(self.witness))
        self.assertEqual(len(leaves), 28782, 'review leaf inventory changed; audit it')
        chunks = [leaves[i:i+128] for i in range(0, len(leaves), 128)]
        # Local Python test workers only, no model delegation or guest execution.
        workers = min(8, len(os.sched_getaffinity(0)))
        total, failures = 0, []
        with multiprocessing.get_context('fork').Pool(workers) as pool:
            for count, errors in pool.imap_unordered(sweep_chunk, chunks):
                total += count
                failures.extend(errors)
        print('leaf sweep:', len(leaves), 'leaves,', total, 'end-to-end mutations', flush=True)
        self.assertEqual(failures, [], 'false PASS leaf mutations: ' + repr(failures))

    def test_route_kind_uses_actual_u8_boundary_through_validate(self):
        path, value = next((p,v) for p,v in leaf_cases(self.witness)
                           if p[-1] == 'kind' and type(v) is int)
        def change(w):
            obj = w
            for key in path[:-1]:
                obj = obj[key]
            obj['kind'] = 256
        self.rejected(self.mutated(change), 'typed_witness')
        self.assertEqual(integer_bits(path), 8, 'Route.kind must overflow at 256')

    def test_source_extracted_widths_cover_every_witness_leaf(self):
        declarations,widths,seen = source_width_inventory(self.witness)
        self.assertEqual(seen, {(file,name) for file,name,_ in declarations})
        # Source Optional primitive fields get a width assertion even when null
        # in this run; this catches missing headroom/fwmark/etc map entries too.
        errors = []
        for path,spec in widths.items():
            if re.fullmatch(r'u(8|16|32|64)|usize|i32|i64',spec):
                wanted = self.m.INTEGER_RANGES[spec][1].bit_length()
                try:
                    actual = integer_bits(path)
                except AssertionError as error:
                    actual = str(error)
                if actual != wanted:
                    errors.append((path,spec,actual))
        self.assertEqual(errors, [])
        # No default integer width is allowed for an unrecognized scalar/array.
        for path in (('unmapped_integer',),('unmapped_array',0)):
            with self.assertRaises(AssertionError):
                integer_bits(path)
        leaf_map = dict(self.m.contract_leaves(self.witness))
        self.assertEqual(len(leaf_map),28782)
        self.assertEqual(set(leaf_map),{p for p,_ in leaf_cases(self.witness)})
        print('contract type inventory:',len(declarations),'serde structs,',
              sum(len(f) for _,_,f in declarations),'fields,',len(leaf_map),'leaf entries',flush=True)

    def test_nested_tun_tuple_widths_from_rust_source(self):
        # Empty in run410, but still a reachable serialized Vec<(u16,Vec<u8>)>.
        field_type = dict(rust_fields('crates/vprouter-network/src/project.rs','Link'))['tun_info']
        for path,spec in rust_primitive_paths([[1,[2]],[3,[4]]],field_type,('tun_info',)):
            with self.subTest(path=path):
                self.assertEqual(integer_bits(path),int(spec[1:]))

    def test_binding_registry_covers_observations_and_refuses_unregistered_object(self):
        self.assertTrue(hasattr(self.m, 'binding_coverage'), 'explicit binding registry missing')
        coverage = self.m.binding_coverage(self.witness)
        self.assertEqual(coverage['uncovered'], [])
        self.assertGreater(coverage['observations'], 1000)
        changed = copy.deepcopy(self.witness)
        # Neither a new observation at root nor one nested in a covered
        # canonical object may inherit coverage merely from its parent.
        for parent in (changed, changed['preparation']['fresh_transport']):
            parent['unregistered_observation'] = dict(pid=99, start=99, deadline=99.)
        self.assertEqual(len(self.m.binding_coverage(changed)['uncovered']), 2)

    def test_registry_coverage_requires_each_identity_field(self):
        original = self.m.BINDING_REGISTRY
        try:
            self.m.BINDING_REGISTRY = tuple(dict(entry,fields=tuple(
                pair for pair in entry['fields'] if pair[0] != ('deadline',)))
                if entry['name'] == 'transport_creation' else entry for entry in original)
            uncovered = self.m.binding_coverage(self.witness)['uncovered']
            self.assertIn(self.m.PROVISION+('transport_creation',),uncovered,
                          'covering birth must not cover the independent request deadline')
        finally:
            self.m.BINDING_REGISTRY = original

    def test_all_transport_observation_binding_fields_through_validate(self):
        prefix = ('host_addition','producer_binding','assembly','quarantine','movement','provision')
        for observation, fields in (
            ('transport_creation', ('request','source','host','data','birth','requested_at','deadline','verified_at')),
            ('transport_mount', ('original_source','original_directory','placeholder','birth','requested_at','deadline'))):
            for field in fields:
                def change(w):
                    obj = w
                    for key in prefix:
                        obj = obj[key]
                    value = obj[observation][field]
                    if type(value) is dict:
                        value['pid' if field == 'birth' else 'mode' if field == 'placeholder' else 'ino'] += 1
                    elif type(value) is list:
                        value[0] ^= 1
                    else:
                        obj[observation][field] += .000001
                with self.subTest(observation=observation, field=field):
                    self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_initial_observation_kind_cannot_claim_another_query_stage(self):
        def change(w):
            obj = w
            for key in ('host_addition','producer_binding','assembly','quarantine','movement','provision','attachment'):
                obj = obj[key]
            obj['first_query']['kind'] = 'BootstrapHostRecheck'
        self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_retained_success_guards_through_validate(self):
        # Each is a retained successful continuation, prior to its own drop.
        host = ('host_addition',)
        binding = host + ('producer_binding',)
        assembly = binding + ('assembly',)
        quarantine = assembly + ('quarantine',)
        movement = quarantine + ('movement',)
        provision = movement + ('provision',)
        stages = [host, binding, assembly, quarantine, movement, provision]
        for path in stages:
            original = self.witness
            for key in path:
                original = original[key]
            values = {'fault': 1, 'schema': 2, 'parent_pristine': False,
                      'continued_original_context': False}
            values.update({k: True for k in original if k.endswith('_retained_after_drop')})
            for field, value in values.items():
                def change(w):
                    obj = w
                    for key in path:
                        obj = obj[key]
                    obj[field] = value
                with self.subTest(stage=path, field=field):
                    self.rejected(self.mutated(change), 'retained_success')
        for field, value in [('canonical_negative_checks', 0), ('charges_before', [0, 0]),
                             ('charges_before_drop', [0, 0]), ('result_writer_held', True),
                             ('unacknowledged_host_addition_retained', True)]:
            self.rejected(self.mutated(lambda w: w['host_addition'].__setitem__(field, value)),
                          'retained_success')
        for key in ('index', 'pid', 'start', 'queued_polls', 'held_pending_polls', 'negative_checks', 'released'):
            self.rejected(self.mutated(lambda w: w['host_addition']['own_intent_polling'].__setitem__(key, 0 if key != 'released' else False)),
                          'retained_success')

    def test_canonical_history_guards_coordinated_copies(self):
        # Mutate every retained Preparation together to avoid prefix-equality
        # checks accidentally serving as the only canonical oracle.
        cases = [
            ('binding_parent', lambda p: p['producer_binding']['parent'].__setitem__('ino', 2)),
            ('binding_name', lambda p: p['producer_binding'].__setitem__('name', 'wrong')),
            ('binding_creation', lambda p: p['producer_binding']['creation']['group'].__setitem__('ino', 2)),
            ('entry_binding', lambda p: p['entry_producer']['binding'].__setitem__(0, p['entry_producer']['binding'][0] ^ 1)),
            ('policy_kind', lambda p: p['netfilter'][1].__setitem__('kind', 'sockets')),
            ('policy_scope', lambda p: p['netfilter'][1].__setitem__('scope', 'data')),
            ('query_initial', lambda p: p['producer_binding_query'].__setitem__('initial', p['inspection']['initial'])),
            ('creation_data', lambda p: p['producer_creation']['data'].__setitem__('ino', 2)),
            ('quarantine_result', lambda p: p['netfilter'][1]['result']['policy'].__setitem__(0, 0)),
            ('host_order', lambda p: p['host_link'][0].__setitem__('kind', 'host_sockets') if p['host_link'] else None),
        ]
        for name, mutate in cases:
            def change(w):
                def visit(obj):
                    if type(obj) is dict:
                        if 'canonical_owner_epoch' in obj and obj.get('producer_binding') is not None:
                            mutate(obj)
                        for item in obj.values():
                            visit(item)
                    elif type(obj) is list:
                        for item in obj:
                            visit(item)
                visit(w)
            with self.subTest(guard=name):
                receipt = self.receipt(self.mutated(change))
                self.assertEqual(receipt['verdict'], 'FAIL', name)

    def test_remaining_narrow_native_emitter_types(self):
        cases = [
            ('admission_polls', lambda w: w['host_addition']['admission'], 'polls', 2**32),
            ('host_inventory', lambda w: w['host_addition']['operations'][0], 'postcompletion_inventory_polls', 2**32),
            ('mount_packets', lambda w: w['host_addition']['producer_binding']['assembly']['quarantine']['movement']['provision']['attachment']['mount'], 'received_packets', 256),
        ]
        for name, select, key, value in cases:
            with self.subTest(type=name):
                self.rejected(self.mutated(lambda w: select(w).__setitem__(key,value)), 'typed_witness')

    def test_all_success_booleans_in_retained_emitters(self):
        # Metadata booleans in typed emitter evidence, excluding network-model
        # fields whose validity follows the declared baseline/link contracts.
        cases = [(path,value) for path,value in leaf_cases(self.witness)
                 if type(value) is bool and path[-1] not in ('up','ipv6')]
        for path,value in cases:
            def change(w):
                obj = w
                for key in path[:-1]:
                    obj = obj[key]
                obj[path[-1]] = not value
            with self.subTest(path=path):
                self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_rust_serialized_field_inventory_and_primitive_ranges(self):
        sources = self.m.CONTRACT['field_sources']
        for schema in sorted({key.split('.')[0] for key in sources}):
            entries = {key.split('.')[1]:value for key,value in sources.items() if key.startswith(schema+'.')}
            file,name = next(iter(entries.values()))['declaration'].rsplit('::',1)
            fields = dict(rust_fields(file,name))
            self.assertEqual(set(entries),set(fields))
            for key,field in entries.items():
                self.assertEqual(fields[key],field['rust_type'])
                if key not in self.m.SCHEMAS[schema]:
                    self.assertTrue(any('skip_serializing_if' in a for a in field['serde_attributes']))
                    continue
                rust_type = fields[key]
                base = rust_type[7:-1] if rust_type.startswith('Option<') else rust_type
                if re.fullmatch(r'[ui](8|16|32|64)|usize|f64|bool',base):
                    self.assertIn(base,list(self.m.alternatives(self.m.SCHEMAS[schema][key])))
        for bits in (8,16,32,64):
            for value in (-1,2**bits,True,1.0,None):
                with self.assertRaises(ValueError):
                    self.m.typed(value,'u'+str(bits),'Rust range')
        for spec,bits in (('i32',32),('i64',64)):
            for value in (-2**(bits-1)-1,2**(bits-1),True,1.0,None):
                with self.assertRaises(ValueError):
                    self.m.typed(value,spec,'Rust signed range')

    def test_additional_recorded_success_guards(self):
        cases = [
            ('host_inventory', lambda w: w['host_addition']['operations'][3]['host_observation']['addresses'].clear()),
            ('host_inventory_extra', lambda w: w['host_addition']['operations'][3]['host_observation']['links'].pop()),
            ('owner_invocation', lambda w: [obj.__setitem__('invocation','0'*32) for _,obj in self.m.objects(w) if 'invocation' in obj]),
            ('owner_cgroup', lambda w: [obj['cgroup'].__setitem__('ino',0) for _,obj in self.m.objects(w) if 'invocation' in obj]),
            ('writer_phase', lambda w: [obj['writers'][0].__setitem__('phase','wrong') for _,obj in self.m.objects(w) if 'canonical_owner_epoch' in obj]),
            ('binding_oracle', lambda w: w['host_addition']['producer_binding'].__setitem__('canonical_negative_checks',0)),
        ]
        for name,change in cases:
            with self.subTest(guard=name):
                self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_audit_origin_fixed_query_array_and_canonical_names(self):
        cases = [
            ('query_array_size', lambda w: w['host_addition']['preparation']['bootstrap_queries'].append(None)),
            ('origin_launch', lambda w: [obj['attachment']['origin'].__setitem__('launch','invalid') for _,obj in self.m.objects(w) if 'canonical_owner_epoch' in obj]),
            ('producer_name', lambda w: [obj['producer_creation'].__setitem__('name','invalid') for _,obj in self.m.objects(w) if 'canonical_owner_epoch' in obj and obj['producer_creation'] is not None]),
        ]
        for name,change in cases:
            with self.subTest(guard=name):
                self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_foreign_capacity_pid_keeps_native_i32_width(self):
        self.rejected(self.mutated(lambda w: w['host_addition']['producer_binding']['assembly']['foreign_eligibility'].__setitem__('original_pid',2**31)), 'typed_witness')

    def test_quarantine_host_declaration_matches_all_recorded_copies(self):
        def change(w):
            for _,obj in self.m.objects(w):
                if 'host_declaration' in obj:
                    obj['host_declaration'][0] ^= 1
        self.assertEqual(self.receipt(self.mutated(change))['verdict'], 'FAIL')

    def test_real_and_reserialized_fixture_pass_without_byte_oracle(self):
        for receipt in (self.m.validate(RAW), self.receipt(self.record)):
            self.assertEqual(receipt['verdict'], 'PASS', receipt)
            self.assertFalse(receipt['runtime_acceptance'])
            self.assertFalse(receipt['release_ready'])
            self.assertTrue(receipt['does_not_prove'])
            self.assertTrue(all(c['status'] == 'PASS' for c in receipt['checks']))

    def test_every_required_top_level_field_removed_or_wrong_type(self):
        for key, value in self.witness.items():
            with self.subTest(field=key, mutation='missing'):
                self.rejected(self.mutated(lambda w: w.pop(key)), 'typed_witness')
            with self.subTest(field=key, mutation='type'):
                wrong = False if type(value) is int else 0 if type(value) is bool else 'wrong-type'
                self.rejected(self.mutated(lambda w: w.__setitem__(key, wrong)), 'typed_witness')

    def test_nested_required_fields_are_closed_and_typed(self):
        # Exercise every field of every distinct nested object shape, including
        # historical records. Schema omissions must not hide behind semantics.
        seen = set()
        def visit(value, path):
            if type(value) is dict:
                shape = tuple(sorted(value))
                if shape not in seen:
                    seen.add(shape)
                    for key in value:
                        altered = copy.deepcopy(value)
                        del altered[key]
                        with self.subTest(path=path, field=key, mutation='missing'):
                            with self.assertRaises(ValueError):
                                self.m.typed_object(altered, shape, path)
                        altered = copy.deepcopy(value)
                        altered[key] = {'unknown_type_sentinel': True}
                        with self.subTest(path=path, field=key, mutation='type'):
                            with self.assertRaises(ValueError):
                                self.m.typed_object(altered, shape, path)
                    altered = dict(value, unexpected=True)
                    with self.assertRaises(ValueError):
                        self.m.typed_object(altered, shape, path)
                for key, item in value.items():
                    visit(item, path + '.' + key)
            elif type(value) is list:
                for item in value:
                    visit(item, path + '[]')
        visit(self.witness, 'witness')
        self.assertGreaterEqual(len(seen), 60)

    def test_success_contract_mutations(self):
        cases = [
            ('fault', 1, 'bootstrap_success'), ('schema', 2, 'bootstrap_success'),
            ('canonical_negative_checks', 38, 'bootstrap_success'),
            ('charges_before_drop', [2, 3], 'charge_conservation'),
            ('charges_after_drop', [3, 2], 'charge_conservation'),
            ('parent_pristine', False, 'bootstrap_success'),
        ]
        cases += [(k, False, 'bootstrap_success') for k in self.witness
                  if k.endswith('_retained_after_drop') or k in
                  ('bootstrap_all_scopes_acknowledged', 'bootstrap_context_created')]
        cases += [(k, True, 'no_authority') for k in (
            'up_authorized', 'placement_authorized', 'health_ready_authorized',
            'resource_cleanup_authorized', 'multi_exit_runtime_proven', 'requirement8_complete')]
        for key, value, check in cases:
            with self.subTest(field=key):
                self.rejected(self.mutated(lambda w: w.__setitem__(key, value)), check)
        for field, value in [('charges_before', [4, 5]), ('charges_after', [1, 0]),
                             ('complete_original_job_set', 19), ('historical_original_jobs', 14),
                             ('retired_suffix_jobs', 4), ('complete', False)]:
            check = 'charge_conservation' if field.startswith('charges') else 'handoff'
            self.rejected(self.mutated(lambda w: w['handoff'].__setitem__(field, value)), check)

    def test_boot_deadlines_scope_identity_and_nested_authority(self):
        mutations = [
            (lambda w: w['preparation']['canonical_owner_epoch'].__setitem__('boot', '0'*36), 'owner_identity'),
            (lambda w: w['preparation']['canonical_owner_epoch'].__setitem__('unit', 'other.service'), 'owner_identity'),
            (lambda w: w['queries'][0]['birth'].__setitem__('born_at', w['queries'][0]['deadline']), 'monotonic_deadlines'),
            (lambda w: w['queries'][0].__setitem__('verified_at', w['queries'][0]['deadline']), 'monotonic_deadlines'),
            (lambda w: w['operations'][1].__setitem__('namespace', w['operations'][0]['namespace']), 'bootstrap_scopes'),
            (lambda w: w['operations'][0].__setitem__('up_authorized', True), 'no_authority'),
            (lambda w: w['preparation']['bootstrap'][0]['result']['policy'].__setitem__(0, 0), 'bootstrap_scopes'),
        ]
        for change, check in mutations:
            self.rejected(self.mutated(change), check)
        record = copy.deepcopy(self.record)
        record['guest_boot_id'] = '0'*36
        self.rejected(record, 'owner_identity')

    def test_missing_duplicate_and_inconsistent_rows(self):
        required = ['secret_attachment_input', 'secret_attachment_descriptor',
                    'secret_attachment_gateway', 'secret_attachment_environment',
                    'secret_attachment_owner_launcher', 'secret_attachment_controller',
                    'secret_attachment_admission', 'secret_host_baseline',
                    'secret_quarantine_host', 'owner_probe']
        for key in required:
            lines = [l for l in self.lines if not l.startswith('{"' + key + '"')]
            record = dict(self.record, stdout='\n'.join(lines)+'\n')
            self.rejected(record, 'stdout_rows')
        for key, value in [('inert_gateway_retained', False),
                           ('original_gateway_native_identity_unchanged', False),
                           ('host_links_and_stable_routes_unchanged', True),
                           ('host_single_down_link_added', False), ('owner_unit_absent', False),
                           ('host_allowed_index', 123), ('host_allowed_name', 'other')]:
            lines = list(self.lines)
            row = json.loads(lines[-1])
            row['secret_attachment_controller'][key] = value
            lines[-1] = json.dumps(row)
            self.rejected(dict(self.record, stdout='\n'.join(lines)+'\n'), 'controller_consistency')
        self.rejected(dict(self.record, stdout=self.record['stdout']+self.lines[-1]+'\n'), 'stdout_rows')

    def test_record_binding_mutations(self):
        for field in ('artifact_sha256', 'context_sha256', 'runner_sha256', 'guest_sha256',
                      'source_archive_sha256', 'context_checker_sha256'):
            self.rejected(dict(self.record, **{field: '0'*64}), 'frozen_bindings')
        record = copy.deepcopy(self.record)
        record['source_binding']['source_commit'] = '0'*40
        self.rejected(record, 'frozen_bindings')

    def test_host_admission_window_and_environment_order(self):
        self.rejected(self.mutated(lambda w: w['preparation']['host_link'][0]['admission'].__setitem__(2, 0)),
                      'monotonic_deadlines')
        record = copy.deepcopy(self.record)
        lines = list(self.lines)
        row = json.loads(lines[10])
        row['secret_attachment_environment']['after']['started_at'] = 0
        lines[10] = json.dumps(row)
        record['stdout'] = '\n'.join(lines)+'\n'
        self.rejected(record, 'controller_consistency')

    def test_birth_status_pin_and_writer_contract_mutations(self):
        mutations = [
            (lambda w: w['operations'][0].__setitem__('original_pid', 2), 'bootstrap_scopes'),
            (lambda w: w['operations'][0].__setitem__('actual_wait_status', 9), 'bootstrap_scopes'),
            (lambda w: w['preparation']['writers'][-1].__setitem__('phase', 'wrong'), 'bootstrap_scopes'),
            (lambda w: w['handoff']['resources'][0].__setitem__('fully_retired', False), 'handoff'),
            (lambda w: w['handoff']['resources'][0].__setitem__('original_pid', 2), 'handoff'),
            (lambda w: w['preparation']['bootstrap'][0]['policy'].__setitem__(0, 256), 'typed_witness'),
        ]
        for change, check in mutations:
            self.rejected(self.mutated(change), check)

    def test_fixed_arrays_and_byte_ranges_are_typed(self):
        source = self.witness['preparation']['bootstrap'][0]
        for key, value in [('request', [1]*31), ('request', [1]*31+[256]),
                           ('pins', [[1, 2, 3]]), ('pins', [[1, 2, 2**32]]*8),
                           ('scope', 'other')]:
            changed = copy.deepcopy(source)
            changed[key] = value
            with self.subTest(field=key, value=value):
                with self.assertRaises(ValueError):
                    self.m.typed(changed, 'BootstrapHistory', 'history')

    def test_result_and_request_pin_sizes_through_validate(self):
        # Same field names do not make these Rust fixed-array types identical.
        cases = [
            ('binding_result_8pins', lambda w: w['preparation']['producer_binding']['result'], 8),
            ('binding_observation_result_8pins', lambda w: w['host_addition']['producer_binding']['observation']['result'], 8),
            ('binding_request_8pins', lambda w: w['preparation']['producer_binding'], 8),
            ('binding_observation_request_8pins', lambda w: w['host_addition']['producer_binding']['observation'], 8),
            ('bootstrap_history_result_6pins', lambda w: w['preparation']['bootstrap'][0]['result'], 6),
            ('bootstrap_operation_result_6pins', lambda w: w['operations'][0]['result'], 6),
            ('bootstrap_history_request_6pins', lambda w: w['preparation']['bootstrap'][0], 6),
            ('bootstrap_operation_request_6pins', lambda w: w['operations'][0], 6),
        ]
        for name, select, size in cases:
            def change(w):
                obj = select(w)
                obj['pins'] = (obj['pins'] + [[1, 2, 3], [4, 5, 6]])[:size]
            with self.subTest(fixture=name):
                self.rejected(self.mutated(change), 'typed_witness')

    def test_preparation_success_guards_through_validate(self):
        cases = [
            ('preparation_unreaped', 'native_children_reaped', False),
            ('preparation_collected', 'member_native_jobs_collected', True),
            ('preparation_unreserved', 'service_reserved', False),
            ('preparation_fenced', 'mutation_fenced', True),
            ('preparation_pending', 'canonical_pending', True),
            ('preparation_phase', 'entry_phase', 'offline'),
            ('preparation_links', 'entry_links_absent', False),
            ('preparation_attempt', 'entry_attempt_absent', False),
            ('preparation_terminal', 'entry_terminal_absent', False),
        ]
        for name, field, value in cases:
            with self.subTest(fixture=name):
                self.rejected(self.mutated(lambda w: w['preparation'].__setitem__(field, value)),
                              'preparation_success')

    def test_retained_preparation_prefix_through_validate(self):
        # Each retained field must equal the host/handoff snapshot; no blanket
        # assertion about historical continuation or drop flags is appropriate.
        cases = [
            ('retained_prefix_birth', lambda w: w['preparation']['writers'][0], 'pid'),
            ('entry_producer', lambda w: w['preparation']['entry_producer']['parent'], 'ino'),
        ]
        for field in ('wireguard', 'netfilter', 'producer_creation', 'producer_binding',
                      'producer_binding_query', 'producer_query', 'quarantine_query',
                      'movement_query', 'inspection', 'attachment', 'fresh_transport', 'host_link'):
            def select(w, field=field):
                obj = w['preparation'][field]
                return (obj[0] if isinstance(obj, list) else obj)['birth']
            cases.append((field, select, 'pid'))
        for field in ('base_network', 'data_network', 'transport_network'):
            cases.append((field, lambda w, field=field: w['preparation'][field], 'ino'))
        cases.append(('canonical_owner_epoch', lambda w: w['preparation']['canonical_owner_epoch'], 'pid'))
        for name, select, field in cases:
            def change(w):
                obj = select(w)
                obj[field] += 1
            with self.subTest(field=name):
                self.rejected(self.mutated(change), 'preparation_success')

    def test_held_intents_bound_to_original_writers_through_validate(self):
        # Reproduce own_intent_identity/query_intent_index, plus the other
        # intent's index and both PID/start components independently.
        for intent in ('own_intent_polling', 'own_query_intent_polling'):
            for field in ('index', 'pid', 'start'):
                def change(w):
                    w[intent][field] = 0 if field == 'index' else w[intent][field] + 1
                with self.subTest(intent=intent, field=field):
                    self.rejected(self.mutated(change), 'bootstrap_success')

    def test_emitted_intent_queued_poll_count_through_validate(self):
        # bootstrap.rs:786,833 emit exactly one queued poll for each intent.
        for intent in ('own_intent_polling', 'own_query_intent_polling'):
            with self.subTest(intent=intent):
                self.rejected(self.mutated(lambda w: w[intent].__setitem__('queued_polls', 2)),
                              'bootstrap_success')

    def test_binding_result_matches_own_request_through_validate(self):
        # Keep all retained copies equal so the prefix check cannot mask a
        # same-sized result that disagrees with its own six-pin request.
        for field in ('namespace', 'group', 'policy', 'pins'):
            def change(w):
                def visit(obj):
                    if isinstance(obj, dict):
                        if all(key in obj for key in ('data', 'pins', 'result')):
                            result = obj['result']
                            if field in ('namespace', 'group'):
                                result[field]['ino'] += 1
                            elif field == 'policy':
                                result[field][0] ^= 1
                            else:
                                result[field][0][2] ^= 1
                        for item in obj.values():
                            visit(item)
                    elif isinstance(obj, list):
                        for item in obj:
                            visit(item)
                visit(w)
            with self.subTest(field=field):
                self.rejected(self.mutated(change), 'bootstrap_scopes')

    def test_original_down_host_endpoint_cannot_be_replaced(self):
        for field, value in [('addition', None), ('verified_at', None)]:
            self.rejected(self.mutated(lambda w: w['preparation']['host_link'][3].__setitem__(field, value)),
                          'typed_witness' if field == 'verified_at' else 'controller_consistency')

    def test_duplicate_unknown_nonfinite_and_malformed_json(self):
        texts = [RAW.read_text().replace('"exit_code": 0', '"exit_code": 0, "exit_code": 0', 1)]
        for bad in ('NaN', 'Infinity', '-Infinity', '1e999', 'true, "schema": 1'):
            lines = list(self.lines)
            lines[self.index] = lines[self.index].replace('"schema":1', '"schema":'+bad, 1)
            self.assertNotEqual(lines[self.index], self.lines[self.index])
            texts.append(json.dumps(dict(self.record, stdout='\n'.join(lines))))
        texts += [json.dumps(self.mutated(lambda w: w.__setitem__('unexpected', True)))]
        texts += [json.dumps(dict(self.record, stdout=self.record['stdout']+'{bad}\n'))]
        with tempfile.TemporaryDirectory(prefix='run410-json-') as tmp:
            path = Path(tmp) / 'record.json'
            for text in texts:
                path.write_text(text)
                self.assertEqual(self.m.validate(path)['verdict'], 'FAIL')

    def test_cli_exclusive_mode0600_and_optimized_refusal(self):
        with tempfile.TemporaryDirectory(prefix='run410-cli-') as tmp:
            receipt = Path(tmp) / 'receipt.json'
            command = [sys.executable, '-B', str(TOOL), str(RAW), str(receipt)]
            result = subprocess.run(command, capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            before = receipt.read_bytes()
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            self.assertEqual(receipt.read_bytes(), before)
            receipt.unlink()
            receipt.symlink_to(Path(tmp)/'absent')
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            self.assertFalse((Path(tmp)/'absent').exists())
            optimized = subprocess.run([sys.executable, '-B', '-O', str(TOOL), str(RAW)],
                                       capture_output=True, text=True)
            self.assertNotEqual(optimized.returncode, 0)
            self.assertIn('optimized_python_refused', optimized.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
