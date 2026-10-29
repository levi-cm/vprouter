"""Public authored local-lab declaration; no route discovery or permissions."""
import json,re
if not __debug__:raise RuntimeError('optimized_python_refused')
AUTHORED_WAN={'debian-clean-x86_64':'ens2','debian-x86_64':'ens2','debian-arm64':'enp0s1','arch-x86_64':'eth0'}
def host_declaration(descriptor,host_namespace,observed_link,platform):
 assert type(descriptor['schema_version'])is int and descriptor['schema_version']==1 and descriptor['profile_contents_read']is descriptor['docker_queried']is descriptor['production_startup_authorized']is False
 assert isinstance(descriptor['deployment_id'],str)and descriptor['deployment_id']and isinstance(descriptor['primary'],str)and descriptor['primary']
 allocation=descriptor['allocation'];assert allocation['deployment_id']==descriptor['deployment_id']and type(allocation['generation'])is int and 0<allocation['generation']<=18446744073709551615
 assert len([e for e in allocation['exits']if e['exit_id']==descriptor['primary']])==1
 digest=descriptor['allocation_digest'];assert isinstance(digest,str)and re.fullmatch('[a-f0-9]{64}',digest)
 assert set(host_namespace)=={'dev','ino'}and all(type(v)is int and 0<v<=18446744073709551615 for v in host_namespace.values())
 name=AUTHORED_WAN[platform];assert observed_link['ifname']==name and type(observed_link['ifindex'])is int and observed_link['ifindex']==2 and observed_link['address']=='52:54:00:12:34:56'and observed_link['link_type']=='ether'
 value=dict(schema_version=1,deployment_id=descriptor['deployment_id'],generation=allocation['generation'],member=descriptor['primary'],allocation_digest=digest,host_namespace=host_namespace,wan=dict(name=name,index=2,address=[82,84,0,18,52,86]))
 data=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode();assert 0<len(data)<=4096
 return value,data
