import hashlib,importlib.util,json,pathlib,shutil,sys
p=pathlib.Path(sys.argv[1]);c=json.loads(p.read_text())
spec=importlib.util.spec_from_file_location('oracle','tools/actual-program-oracle.py');o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
for arch in ('amd64','arm64'):
 v=c['platforms'][arch];source=pathlib.Path(v['context']);target=p.parent/(arch+'.context.tar');expected=v['context_sha256']
 if not target.exists():
  assert hashlib.sha256(source.read_bytes()).hexdigest()==expected,(arch,'mutable context changed before copy')
  with target.open('xb') as out,source.open('rb') as src:shutil.copyfileobj(src,out)
 assert hashlib.sha256(target.read_bytes()).hexdigest()==expected,(arch,'candidate context digest mismatch')
 o.context_check(target,c['source'],arch)
 print(arch,'immutable context and strict four-role inventory verified')
