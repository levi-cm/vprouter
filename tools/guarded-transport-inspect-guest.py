import pathlib,json,subprocess,datetime
root=pathlib.Path('/var/lib/vprouter-v2-lab')
rows=[]
for d in root.glob('task8a-*'):
 if not d.is_dir() or not (d/'resources.json').exists():continue
 value=json.loads((d/'resources.json').read_text());a=value['allocation']['exits'][0]
 def call(argv):
  r=subprocess.run(argv,capture_output=True,text=True,timeout=4)
  try:out=json.loads(r.stdout)
  except ValueError:out=r.stdout
  return {'code':r.returncode,'data':out,'stderr':r.stderr}
 docker=call(['docker','inspect',value['container']])['data'][0]
 paths=[None,str(pathlib.Path(value['records'])/a['transport_namespace']),str(pathlib.Path(value['records'])/a['data_namespace'])]
 obs=[]
 for scope,ns in zip(['host','transport','data'],paths):
  prefix=[] if ns is None else ['nsenter','--net='+ns]
  obs.append({'scope':scope,'links':call([*prefix,'ip','-details','-j','link','show']),'addresses':call([*prefix,'ip','-j','address','show']),'routes4':call([*prefix,'ip','-j','-4','route','show','table','all']),'routes6':call([*prefix,'ip','-j','-6','route','show','table','all']),'rules4':call([*prefix,'ip','-j','-4','rule','show']),'rules6':call([*prefix,'ip','-j','-6','rule','show']),'nft':call([*prefix,'nft','-j','list','ruleset'])})
 rows.append({'directory':str(d),'resources':value,'container_state':docker['State'],'ownership_record':json.loads((pathlib.Path(value['records'])/'namespaces.json').read_text()),'scopes':obs})
print(json.dumps({'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'read_only':True,'deployments':rows},indent=2))
