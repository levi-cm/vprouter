"""Author preservation from an exact failed Bootstrap canonical history; never adopt live values."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def stable(value):
    return dict(namespace=value['namespace'],**{k:sorted(value[k],key=canonical) for k in ('links','addresses','routes','rules')})

def main():
    candidate_path=pathlib.Path(sys.argv[1]);candidate=json.loads(candidate_path.read_bytes());platform='debian-clean-x86_64'
    directory=pathlib.Path(sys.argv[2]);binding=json.loads((directory/'directory-binding.json').read_bytes())
    run=int(pathlib.Path(binding['record']).stem.removeprefix('actual-program-run-'));assert run>=398
    old_path=directory/'controller-authored-baseline.json'
    reference_path=pathlib.Path('target/lab-state')/('secret-bootstrap-failure-run-'+str(run)+'.json');reference=json.loads(reference_path.read_bytes())
    raw_path=pathlib.Path(reference['record']);raw=raw_path.read_bytes();record=json.loads(raw)
    assert str(raw_path)==binding['record'] and record['source_binding']['source_commit']==binding['source_commit'] and record['source_archive_sha256']==binding['source_archive_sha256'] and record['artifact_sha256']==binding['artifact_sha256']
    assert sha(raw_path)==reference['record_sha256'] and record['exit_code']==1 and record['component_test_mode']=='secret_bootstrap_success'
    assert record['source_binding']==reference['source_binding'] and record['platform']==reference['platform']==platform
    assert reference['owner_unit']['LoadState']=='not-found' and reference['owner_cgroup_exists']is False
    prior=json.loads(old_path.read_bytes());assert prior['source_binding']==record['source_binding']
    assert sha(old_path)==record['host_baseline_template_sha256']
    old_review=old_path.with_name('controller-baseline-reconciliation.json')
    assert sha(old_review)==prior['review_sha256']==record['baseline_reconciliation_sha256']
    for ref in prior['prior_evidence']:
        assert sha(pathlib.Path(ref['path']))==ref['sha256']
    entries=reference['canonical']['namespaces.json']['entries'];assert len(entries)==1
    history=entries[0]['preparation']['host_link'];assert len(history)==4 and [v['kind'] for v in history]==['transport_sockets','pair','host_sockets','move']
    assert all(v['birth']is not None and v['result']is not None and v['verified_at']is not None for v in history)
    added=history[-1]['result']['host'];assert added['kind']=='veth' and added['up']is False
    rows=[json.loads(line) for line in record['stdout'].splitlines() if line.startswith('{')]
    outer=[row['secret_attachment_controller'] for row in rows if 'secret_attachment_controller' in row];assert len(outer)==1
    assert outer[0]['host_single_down_link_added']is True and added['index']==outer[0]['host_allowed_index'] and added['name']==outer[0]['host_allowed_name']
    assert outer[0]['host_addresses_routes_rules_preserved']is outer[0]['host_stable_neighbors_preserved']is True
    expected=copy.deepcopy(prior['baseline']);assert all(v['index']!=added['index'] and v['name']!=added['name'] for v in expected['links']);expected['links'].append(copy.deepcopy(added))
    projection_path=candidate_path.parent/('host-projection-'+platform)/'record.json';projection=json.loads(projection_path.read_bytes())
    assert projection['source_binding']==candidate['binding'] and projection['artifact_sha256']==candidate['platforms']['amd64']['artifact_sha256'] and projection['platform']==platform
    assert projection['declaration_staged']is projection['host_authority_granted']is projection['production_changes']is projection['private_profile_contents_read']is False
    assert projection['report']['read_only']is True and projection['report']['declaration_authority']is projection['report']['host_change_authority']is False
    assert stable(expected)==stable(projection['report']['projection']),'unexplained_foreign_state_change'
    shape_path=pathlib.Path('target/platform-lab/host_baseline_declaration.py');spec=importlib.util.spec_from_file_location('preserved398_shape',shape_path);shape=importlib.util.module_from_spec(spec);spec.loader.exec_module(shape);shape.validate_template(prior,record['source_binding'],platform);shape.validate_shape(expected)
    aligned=dict(namespace=expected['namespace'])
    for key in ('links','addresses','routes','rules'):
        remaining=list(expected[key]);aligned[key]=[]
        for observed in projection['report']['projection'][key]:
            index=next(i for i,value in enumerate(remaining) if value==observed)
            aligned[key].append(remaining.pop(index))
        assert not remaining
    expected=aligned
    refs=[old_path,old_review,reference_path,raw_path,projection_path]
    references=[dict(path=str(path),sha256=sha(path)) for path in refs]
    digest=hashlib.sha256(canonical(expected)).hexdigest()
    review=dict(source_binding=candidate['binding'],platform=platform,baseline_sha256=digest,counts={k:len(expected[k]) for k in ('links','addresses','routes','rules')},references=references,helpers=[dict(path=str(path),sha256=sha(path)) for path in [pathlib.Path(__file__),shape_path]],namespace=expected['namespace'],prior_structure_reconstructed=True,ordering_only_aligned_after_exact_multiset_comparison=True,declaration_staged=False,prior_authored_baseline_preserved=True,original_acknowledged_host_endpoint_preserved=added,exact_multiset_projection_equality=True,live_fields_substituted=False,host_authority_granted=False,review_scope='Foreign preservation only; failed run remains unaccepted; no membership/removal/activation authority. Independent review required.')
    review_path=candidate_path.parent/('host-baseline-reconciliation-'+platform+'.json')
    with review_path.open('x') as stream:json.dump(review,stream,indent=2);stream.write('\n')
    review_path.chmod(0o600)
    template=dict(schema=1,platform=platform,source_binding=candidate['binding'],baseline=expected,baseline_sha256=digest,prior_evidence=references,review_sha256=sha(review_path));shape.validate_template(template,candidate['binding'],platform)
    path=candidate_path.parent/('authored-host-baseline-'+platform+'.json')
    with path.open('xb') as stream:stream.write(canonical(template))
    path.chmod(0o600)
    print(json.dumps(dict(template=str(path),template_sha256=sha(path),review=str(review_path),review_sha256=sha(review_path),counts=review['counts'],host_authority_granted=False)))

if __name__=='__main__':main()
