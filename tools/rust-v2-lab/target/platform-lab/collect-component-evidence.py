import pathlib,json,subprocess,sys,hashlib
candidate=pathlib.Path(sys.argv[1]);platform=sys.argv[2];c=json.loads(candidate.read_text());out=candidate.parent/(sys.argv[3] if len(sys.argv)>3 else platform+'-actual');binding=json.loads((out/'directory-binding.json').read_text());assert binding['source_commit']==c['source_commit'] and binding['source_archive_sha256']==c['source_sha256'] and binding['platform']==platform
assert len(binding['new_directories'])==1;directory=binding['new_directories'][0]
choices={'debian-clean-x86_64':(22036,'target/platform-lab/debian-clean-x86_64/known_hosts'),'debian-x86_64':(22032,'target/lab-state/known_hosts'),'debian-arm64':(22034,'target/platform-lab/debian-arm64/known_hosts'),'arch-x86_64':(22033,'target/platform-lab/arch-x86_64/known_hosts'),'void-x86_64':(22035,'target/platform-lab/void-x86_64/known_hosts')};port,known=choices[platform]
for src,label in [('target/actual-program-inspect-monitor.py','metadata'),('tools/guarded-transport-capture-oracle.py','captures')]:
 s=pathlib.Path(src).read_text();assert s.count('-p22032')==1;s=s.replace('-p22032','-p'+str(port))
 if 'str(base/"known_hosts")'in s:s=s.replace('str(base/"known_hosts")','str(pathlib.Path('+repr(known)+'))')
 elif "str(base/'known_hosts')"in s:s=s.replace("str(base/'known_hosts')",'str(pathlib.Path('+repr(known)+'))')
 else:raise AssertionError('missing fixed known-host binding')
 if label=='captures':
  old='  account = pwd.getpwnam("tcpdump")\n  owners.add((account.pw_uid,account.pw_gid))'
  new='  try: account = pwd.getpwnam("tcpdump")\n  except KeyError: account = None\n  if account is not None: owners.add((account.pw_uid,account.pw_gid))'
  assert s.count(old)==1;s=s.replace(old,new)
 helper=out/(label+'-collector.py');assert not helper.exists();helper.write_text(s)
 with (out/(label+'.json')).open('w') as stream:subprocess.run(['python3',str(helper),directory],stdout=stream,check=True,timeout=75)
v=json.loads((out/'captures.json').read_text());caps=v['captures'];assert all(x['status']=='FRAMING_VERIFIED' and x['records']==x['capture_counters']['captured'] for x in caps)
summary={'platform':platform,'source_commit':c['source_commit'],'record':binding['record'],'directory':directory,'capture_files':len(caps),'packet_records':sum(x['records'] for x in caps),'forbidden_markers':sum(x['marker_occurrences']['forbidden_prefix'] for x in caps),'kernel_drops':sum(x['capture_counters']['dropped_by_kernel'] for x in caps),'real_client_acceptance':'NOT_RUN','evidence_scope':'isolated Starting/observer/daemon component only'}
(out/'capture-aggregate.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
