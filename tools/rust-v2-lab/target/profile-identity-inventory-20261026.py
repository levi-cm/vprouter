import base64,configparser,datetime,hashlib,io,json,os,re,stat,subprocess,zipfile
from pathlib import Path
try:
 assert os.geteuid()==0
 path=Path('/DATA/AppData/vprouter/wiregurad-auth.zip');s=path.lstat()
 assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<64*1024*1024
 prod=subprocess.run(['/usr/bin/docker','exec','max-vprouter','wg','show','wg0','public-key'],capture_output=True,timeout=10,check=True).stdout.strip()
 assert len(base64.b64decode(prod,validate=True))==32
 def public(value):
  x=subprocess.run(['/usr/bin/wg','pubkey'],input=value.encode()+b'\n',capture_output=True,timeout=5,check=True).stdout.strip()
  assert len(base64.b64decode(x,validate=True))==32
  return hashlib.sha256(x).hexdigest()
 current=hashlib.sha256(prod).hexdigest();entries=[]
 with zipfile.ZipFile(path) as z:
  assert len(z.infolist())<100
  for member in z.infolist():
   if member.is_dir() or not member.filename.endswith('.conf'):continue
   assert 0<member.file_size<65536 and member.compress_size<65536
   server=Path(member.filename).name.removesuffix('.conf')
   assert re.fullmatch('[a-z]{2}-[a-z]{3}-wg-[0-9]{3}',server)
   raw=z.read(member)
   c=configparser.ConfigParser(interpolation=None,strict=True);c.read_string(raw.decode())
   key=c['Interface']['PrivateKey'].strip();assert len(base64.b64decode(key,validate=True))==32
   fingerprint=public(key)
   addresses=[x.strip() for x in c['Interface']['Address'].split(',')]
   entries.append({'server':server,'device_public_sha256':fingerprint,'addresses':addresses,'shares_current_production_device':fingerprint==current})
   del key,raw,c
 assert len(entries)==5
 assert len({x['server'] for x in entries})==5
 result={'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'archive':'wiregurad-auth.zip','profiles':entries,'distinct_device_public_identities':len({x['device_public_sha256'] for x in entries}),'production_device_matches':sum(x['shares_current_production_device'] for x in entries),'production_changes':False,'provider_connections':False,'secrets_logged':False}
 print(json.dumps(result,indent=2))
except Exception:
 print(json.dumps({'result':'FAIL','reason':'private_inventory_validation_failed','secrets_logged':False}))
 raise SystemExit(1)
