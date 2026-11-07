"""Expand the recorded-quantity model into exact, fail-closed predicates.

No schema inference or quantity-name-specific invariant code lives here. Numeric
leaf semantics, native key sets, equations and tolerances are model data. The
legacy receipt replay and structural/coverage validators remain separate gates.
"""
from fractions import Fraction
from functools import lru_cache
import importlib.util
import json
from pathlib import Path
import re

MODEL=json.loads(Path(__file__).with_name('quantity-model.json').read_text())
_catalog_spec=importlib.util.spec_from_file_location('_kernel_catalog',Path(__file__).with_name('kernel_identities.py'))
_catalog=importlib.util.module_from_spec(_catalog_spec);_catalog_spec.loader.exec_module(_catalog)
SCHEMA=json.loads(Path(__file__).with_name('run-schema.json').read_text())


def catalog_coverage(model=None, catalog=None, schema=None):
    return _catalog.coverage(MODEL if model is None else model,
                             SCHEMA if schema is None else schema,
                             _catalog.CATALOG if catalog is None else catalog)


CATALOG_PROBLEMS=catalog_coverage()
MISSING=object()


def select(value,path,missing=False):
    """Expand JSON pointer wildcards, retaining concrete paths for diagnostics."""
    parts=path.strip('/').split('/') if path else []
    def walk(v,rest,concrete):
        if not rest:
            yield concrete,v;return
        key=rest[0]
        if key=='*':
            items=v.items() if type(v) is dict else enumerate(v) if type(v) is list else []
            for k,item in items:yield from walk(item,rest[1:],concrete+(k,))
        elif type(v) is dict and key in v:yield from walk(v[key],rest[1:],concrete+(key,))
        elif missing:yield concrete+tuple(rest),MISSING
    yield from walk(value,parts,())


def get(context,path):
    parts=path.split('.');value=context[parts[0]]
    for key in parts[1:]:
        if type(value) is dict:value=value[key]
        else:raise ValueError('model_reference')
    return value


def freeze(value):
    return tuple(freeze(v) for v in value) if type(value) is list else value


@lru_cache(maxsize=4096)
def compile_expression(node):
    """Compile the closed DSL to exact callables once, without eval/codegen."""
    if type(node) is int:return lambda context:node
    if type(node) is str:
        keys=node.split('.')
        def reference(context):
            value=context[keys[0]]
            for key in keys[1:]:value=value[key]
            return value
        return reference
    op,*args=node
    if op=='present_sum':
        obj=compile_expression(args[0]);keys=args[1]
        return lambda c:sum(obj(c)[k] for k in keys if k in obj(c))
    fns=[compile_expression(arg) for arg in args]
    if op=='sum':return lambda c:sum(fns[1](c|{'item':v}) for v in fns[0](c))
    if op=='values':return lambda c:list(fns[0](c).values())
    if op=='len':return lambda c:len(fns[0](c))
    if op=='delta':return lambda c:fns[0](c)-fns[0](c['old'])
    if op=='before':return lambda c:fns[0](c['old'])
    if op=='device_get':return lambda c:fns[0](c).get(c['device'],{}).get(c['counter'],0)
    if op=='sum_delta':
        def stable_delta(c):
            identity=lambda p:(p['pid'],p['start_ticks'],p['executable_sha256'],p['domain'],p['component'])
            before={identity(p):p for p in fns[0](c['old'])}
            return sum(fns[1](c|{'item':p})-fns[1](c|{'item':before[identity(p)]}) for p in fns[0](c))
        return stable_delta
    if op=='add':return lambda c:sum(fn(c) for fn in fns)
    if op=='sub':return lambda c:fns[0](c)-fns[1](c)
    if op=='mul':
        def product(c):
            result=1
            for fn in fns:result*=fn(c)
            return result
        return product
    if op=='div':return lambda c:Fraction(fns[0](c),fns[1](c))
    if op=='max':return lambda c:max(fn(c) for fn in fns)
    raise ValueError('model_operator')


def expression(node,context):
    return compile_expression(freeze(node))(context)


def compile_relation(rule):
    operator=rule['operator']
    if operator=='implies_positive':
        # One-way implication a>0 => b>0. The converse is deliberately not
        # expressible: a torn native read may observe one field before a
        # concurrent update, so callers select a scope that tolerates it.
        # Presence is one-way too: an absent antecedent is vacuous, but a
        # present positive antecedent requires a present positive consequent.
        # A symmetric when_present gate would silently accept a positive
        # duration whose event count was not captured at all.
        if rule.get('when_present'):
            raise ValueError('model_relation')
        antecedent=compile_expression(freeze(rule['antecedent']))
        consequent=compile_expression(freeze(rule['consequent']))
        presence=[(compile_expression(group['object']),group['keys']) for group in rule.get('presence_pairs',[])]
        def implication(context):
            for obj_fn,keys in presence:
                obj=obj_fn(context)
                if any(k in obj for k in keys) and not all(k in obj for k in keys):return False
            try:left=antecedent(context)
            except KeyError:return True
            # Negative native counters are separately rejected by the schema;
            # fail closed here as well. A zero antecedent never requires the
            # consequent, because the converse is not asserted.
            if type(left) is not int or left<0:return False
            if left==0:return True
            try:right=consequent(context)
            except KeyError:return False
            return type(right) is int and right>0
        return implication
    if operator=='containment':
        # One-way count/duration containment: 0 <= sum(children) <= parent.
        # There is no converse/partition claim about the unrecorded remainder.
        parent=compile_expression(freeze(rule['parent']))
        children=[compile_expression(freeze(child)) for child in rule['children']]
        optional=[compile_expression(path) for path in rule.get('when_present',[])]
        presence=[(compile_expression(group['object']),group['keys']) for group in rule.get('presence_pairs',[])]
        def contained(context):
            for obj_fn,keys in presence:
                obj=obj_fn(context)
                if any(k in obj for k in keys) and not all(k in obj for k in keys):return False
            for fn in optional:
                try:fn(context)
                except KeyError:return True
            limit=parent(context)
            if type(limit) is not int or limit<0:return False
            values=[fn(context) for fn in children]
            return (all(type(value) is int and value>=0 for value in values)
                    and sum(values)<=limit)
        return contained
    if operator=='monotonic':
        def monotonic(context):
            seen={}
            for path,value in select(context['run'],rule['path']):
                identity=path[2:]
                if path[2]=='processes':
                    p=context['run']['samples'][path[1]]['processes'][path[3]]
                    identity=('process',p['pid'],p['start_ticks'],p['executable_sha256'],p['domain'],p['component'])+path[4:]
                if type(value) is not int:return False
                if identity in seen and value<seen[identity]:return False
                seen[identity]=value
            return True
        return monotonic
    parent=compile_expression(freeze(rule['parent']))
    children=[compile_expression(freeze(child)) for child in rule['children']]
    upper=compile_expression(freeze(rule.get('upper_tolerance',0)))
    lower=compile_expression(freeze(rule.get('lower_tolerance',0)))
    optional=[compile_expression(path) for path in rule.get('when_present',[])]
    presence=[(compile_expression(group['object']),group['keys']) for group in rule.get('presence_pairs',[])]
    def predicate(context):
        for obj_fn,keys in presence:
            obj=obj_fn(context)
            if any(k in obj for k in keys) and not all(k in obj for k in keys):return False
        for fn in optional:
            try:fn(context)
            except KeyError:return True
        left=parent(context);right=sum(fn(context) for fn in children)
        if operator=='partition':return right-left<=upper(context) and left-right<=lower(context)
        if operator=='completed_io':return 0<=right<=left and (right==0)==(left==0)
        if operator=='multiple':return type(left) is int and right>0 and left>=0 and left%right==0
        raise ValueError('model_relation')
    return predicate


def contexts(run,scope):
    samples=run['samples'];h=run['host']
    if scope in ('run','quantity'):yield {'run':run,'h':h};return
    if scope=='measured_interval':
        first=next((s for s in samples if s['mono_ns']-samples[0]['mono_ns']>=run['warmup_discard_ns']),None)
        if first is None:raise ValueError('model_measured_window')
        last=samples[-1]
        yield {'run':run,'h':h,'s':last,'c':last['host'],
               'old':{'run':run,'h':h,'s':first,'c':first['host']}}
        return
    for index,s in enumerate(samples):
        base={'run':run,'h':h,'s':s,'c':s['host'],'groups':list(s['domains'].values()),'processes':s['processes']}
        if scope=='sample':yield base
        elif scope=='domain_tail':
            # One-way read-tearing tolerance: every domain observation after the
            # first acquisition sample. A contradiction sustained beyond the
            # first sample is still refused.
            if index==0:continue
            for name,d in s['domains'].items():
                yield base|{'d':d,'members':[p for p in s['processes'] if p['domain']==name]}
        elif scope=='process':
            for p in s['processes']:yield base|{'p':p}
        elif scope=='domain':
            for name,d in s['domains'].items():yield base|{'d':d,'members':[p for p in s['processes'] if p['domain']==name]}
        elif scope=='device':
            for d in s['domains'].values():
                for device in set(d['io'])|set(d['io_other']):
                    parent=d['io'].get(device,{})
                    residual=d['io_other'].get(device,{})
                    for key in set(parent)|set(residual):
                        # Missing source values cannot become favorable zeros.
                        yield base|{'io_parent':parent[key],'io_residual':residual[key]}
        elif scope=='io':
            for obj in list(s['domains'].values())+s['processes']:
                for io_key in ('io','io_other'):
                    for io in obj.get(io_key,{}).values():yield base|{'io':io}
        elif scope in ('interval','domain_interval','device_interval','io_interval'):
            # Every original/measured anchored prefix AND adjacent endpoints.
            measured=next((i for i,v in enumerate(samples) if v['mono_ns']-samples[0]['mono_ns']>=run['warmup_discard_ns']),0)
            for j in sorted({0,measured,index-1}):
                if not 0<=j<index:continue
                prev=samples[j];old=base|{'s':prev,'c':prev['host'],'groups':list(prev['domains'].values()),'processes':prev['processes']}
                pair=base|{'old':old}
                if scope=='interval':yield pair
                elif scope in ('domain_interval','device_interval'):
                    for name,d in s['domains'].items():
                        oldd=prev['domains'][name]
                        group=pair|{'d':d,'members':[p for p in s['processes'] if p['domain']==name],
                                    'old':old|{'d':oldd,'members':[p for p in prev['processes'] if p['domain']==name]}}
                        if scope=='domain_interval':yield group
                        else:
                            maps=[obj[k] for obj in (d,oldd) for k in ('io','io_other')]+[p['io'] for p in group['members']+group['old']['members']]
                            for device in set().union(*(set(m) for m in maps)):
                                for counter in set().union(*(set(m.get(device,{})) for m in maps)):
                                    yield group|{'device':device,'counter':counter,'old':group['old']|{'device':device,'counter':counter}}
                else:
                    objects=[('domains',k,v) for k,v in s['domains'].items()]+[('processes',p['pid'],p) for p in s['processes']]
                    oldps={p['pid']:p for p in prev['processes']}
                    for kind,key,obj in objects:
                        oldobj=prev['domains'][key] if kind=='domains' else oldps[key]
                        for io_key in ('io','io_other'):
                            now=obj.get(io_key,{});before=oldobj.get(io_key,{})
                            if set(now)!=set(before):raise ValueError('model_io_identity')
                            for dev,io in now.items():yield pair|{'io':io,'old':old|{'io':before[dev]}}
        else:raise ValueError('model_scope')


def relation_ok(rule,context):
    return compile_relation(rule)(context)


def generated_constraints(run,model=None):
    yield 'catalog:coverage',not CATALOG_PROBLEMS
    model=MODEL if model is None else model
    for entry in model['quantities']:
        check='quantity:'+entry['name']
        seen={};ok=True
        try:
            for path,value in select(run,entry['path'],missing=True):
                if value is MISSING:
                    ok=ok and entry['absence_allowed'];continue
                if type(value) is dict and entry.get('object_alternative',False):continue
                if value is None and entry.get('null_allowed',False):continue
                valid=(type(value) is int and entry['minimum']<=value<=entry['maximum'] and value<2**entry['width'])
                if 'enum' in entry:valid=valid and value in entry['enum']
                ok=ok and valid
                if not valid:continue
                if entry['monotonic'] and len(path)>1 and path[0]=='samples':
                    sample=run['samples'][path[1]];identity=path[2:]
                    if len(path)>3 and path[2]=='processes':
                        p=sample['processes'][path[3]]
                        identity=('process',p['pid'],p['start_ticks'],p['executable_sha256'],p['domain'],p['component'])+path[4:]
                    if identity in seen:ok=ok and value>=seen[identity]
                    seen[identity]=value
        except (KeyError,TypeError,ValueError,IndexError):ok=False
        yield check,ok
    for map_rule in model['native_maps']:
        ok=True;seen={}
        try:
            for path,value in select(run,map_rule['path'],missing=True):
                if type(value) is not dict:ok=False;continue
                keys=set(value)
                allowed=(keys<=set(map_rule['allowed']) if 'allowed' in map_rule else
                         all(re.fullmatch(map_rule['key_pattern'],key) is not None for key in keys))
                ok=ok and set(map_rule['required'])<=keys and allowed
                identity=path[2:]
                if path[2]=='processes':
                    p=run['samples'][path[1]]['processes'][path[3]]
                    identity=('process',p['pid'],p['start_ticks'],p['executable_sha256'],p['domain'],p['component'])+path[4:]
                if identity in seen:ok=ok and keys==seen[identity]
                seen[identity]=keys
        except (KeyError,TypeError,ValueError):ok=False
        yield 'map:'+map_rule['id'],ok
    contract=model['clock_contract']
    yield 'contract:cpu_clock',run.get('host',{}).get(contract['field'])==contract['value']
    # A receipt adapter must not silently accept a newly introduced numeric
    # field before its units/width/absence semantics have been modeled.
    receipt_patterns={e['path'] for e in model['quantities'] if e['path'].startswith('/runtime_evidence/')}
    def receipt_leaves(value,path='/runtime_evidence'):
        if type(value) is int:yield path
        elif type(value) is dict:
            for key,item in value.items():yield from receipt_leaves(item,path+'/'+key)
        elif type(value) is list:
            for item in value:yield from receipt_leaves(item,path+'/*')
    yield 'inventory:receipt_numeric',all(path in receipt_patterns for path in receipt_leaves(run.get('runtime_evidence')))
    # Group by expansion scope: large runs do not repeat endpoint discovery for
    # every equation. No check is inferred from its textual ID.
    scopes={r['scope'] for r in model['relations']}
    for scope in sorted(scopes):
        rules=[(r,compile_relation(r)) for r in model['relations'] if r['scope']==scope]
        try:
            for context in contexts(run,scope):
                for rule,predicate in rules:
                    try:ok=predicate(context)
                    except (KeyError,TypeError,ValueError,IndexError,ZeroDivisionError):ok=False
                    yield 'relation:'+rule['id'],ok
        except (KeyError,TypeError,ValueError,IndexError,ZeroDivisionError,StopIteration):
            for rule,predicate in rules:yield 'relation:'+rule['id'],False


def check(run,reasons):
    for name,ok in generated_constraints(run):
        if not ok:reasons.add('quantity_model:'+name)
