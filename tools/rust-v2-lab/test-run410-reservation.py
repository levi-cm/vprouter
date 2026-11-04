import importlib.util,json,os,pathlib,tempfile
spec=importlib.util.spec_from_file_location('reservation','tools/rust-v2-lab/run410-reservation.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
if not __debug__:raise RuntimeError('optimized_python_refused')
results=[]
with tempfile.TemporaryDirectory(prefix='phase3-reservation-test-') as tmp:
 root=pathlib.Path(tmp);m.RESERVATION=root/'reservation.json';m.CLAIM=root/'consumed.json';m.LOCK=root/'lock';m.RUN=root/'run.json';m.CANDIDATE=root/'candidate.json';m.SUPERSESSION=root/'supersession.json'
 m.CANDIDATE.write_text('{}');bound=root/'bound';bound.write_text('original')
 m.binding_paths=lambda:[bound]
 data=dict(schema=2,supersedes_sha256=None,controller_boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),run=410,one_shot_budget=1,historical_high_water_mark=409,historical_raw_records_recovered=False,continuity='fresh-lab',candidate=str(m.CANDIDATE),platform=m.PLATFORM,label=m.LABEL,mode='success',bindings=[dict(path=str(bound),sha256=m.sha(bound))]);m.save(m.RESERVATION,data)
 args=(m.RESERVATION,m.CANDIDATE,m.PLATFORM,m.LABEL,'success')
 def refused(name,fn):
  try:fn()
  except (AssertionError,FileExistsError,BlockingIOError):results.append(name);return
  raise AssertionError('did not refuse '+name)
 fd,_=m.admit(*args,preflight=True);assert not m.CLAIM.exists();refused('concurrent_lock',lambda:m.admit(*args,preflight=True));os.close(fd)
 results.append('preflight_does_not_consume')
 refused('wrong_label',lambda:m.admit(*args[:3],'other','success',preflight=True))
 bound.write_text('drift');refused('binding_drift',lambda:m.admit(*args,preflight=True));bound.write_text('original')
 m.RESERVATION.chmod(0o644);refused('unsafe_mode',lambda:m.admit(*args,preflight=True));m.RESERVATION.chmod(0o600)
 m.RUN.symlink_to(root/'nonexistent');refused('dangling_run_collision',lambda:m.admit(*args,preflight=True));m.RUN.unlink()
 (root/m.LABEL).mkdir();refused('output_collision',lambda:m.admit(*args,preflight=True));(root/m.LABEL).rmdir()
 def bad_provenance():raise AssertionError('synthetic_provenance_refusal')
 refused('provenance_before_claim',lambda:m.admit(*args,provenance_check=bad_provenance));assert not m.CLAIM.exists()
 refused('fault_mode_not_reserved',lambda:m.admit(*args[:4],'postbirth-failure',preflight=True))
 fd,_=m.admit(*args);os.close(fd);assert m.CLAIM.stat().st_mode&0o777==0o600;results.append('exclusive_claim_consumes_one_budget')
 refused('second_attempt',lambda:m.admit(*args));refused('duplicate_exclusive_reservation',lambda:m.save(m.RESERVATION,data))
print(json.dumps(dict(passed=results,count=len(results),real_lab_claim_created=False),indent=2))
