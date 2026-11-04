#!/usr/bin/env python3
"""Fresh-lab baseline from independent RTM_GET dumps, never historical substitution.

collect is read-only in the guest. author consumes saved dumps BEFORE frozen
projection. compare checks full multisets without changing authored authority.
Only the admitted three-link clean Debian environment is supported.
"""
import argparse
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import pathlib
import stat
import struct
import subprocess

if not __debug__:
    raise RuntimeError('optimized_python_refused')

REMOTE = r'''
import json,os,pathlib,socket,struct,time
assert os.geteuid()==0
ns=pathlib.Path('/proc/self/ns/net').stat();init=pathlib.Path('/proc/1/ns/net').stat()
assert (ns.st_dev,ns.st_ino)==(init.st_dev,init.st_ino)
output={'namespace':[ns.st_dev,ns.st_ino],'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'dumps':{}}
for kind,size in [(18,16),(22,8),(26,12),(34,12)]:
 families=[0] if kind in (18,22) else [2,10]
 for family in families:
  with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as sock:
   sock.bind((0,0));sock.settimeout(2);seq=kind*100+family
   body=bytes([family])+bytes(size-1);sock.send(struct.pack('=IHHII',16+size,kind,0x301,seq,0)+body)
   rows=[];end=time.monotonic()+2;done=False
   while not done:
    assert time.monotonic()<end
    raw,anc,flags,peer=sock.recvmsg(262144)
    assert peer[0]==0 and not flags & socket.MSG_TRUNC
    offset=0
    while offset<len(raw):
     length,typ,flg,sequence,pid=struct.unpack_from('=IHHII',raw,offset)
     assert 16<=length<=len(raw)-offset and sequence==seq and not flg & 16
     message=raw[offset:offset+length];offset+=(length+3)&~3
     if typ==3:
      assert len(message)==16 or struct.unpack_from('=i',message,16)[0]==0
      done=True
     else:
      assert typ==kind-2 and len(rows)<4096
      rows.append(message.hex())
   output['dumps'][str(kind)+'/'+str(family)]=rows
print(json.dumps(output,indent=2))
'''


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def save(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())


def attrs(raw, repeated=False):
    result={}
    while raw:
        length,kind=struct.unpack_from('=HH',raw)
        assert 4<=length<=len(raw) and not kind&0x4000
        kind &= 0x3fff
        assert repeated or kind not in result
        if repeated:result.setdefault(kind,[]).append(raw[4:length])
        else:result[kind]=raw[4:length]
        raw=raw[(length+3)&~3:]
    return result


def scalar(a,key,default=None,width=4):
    if key not in a:return default
    assert len(a[key])==width
    return int.from_bytes(a[key],'little')


def text(raw):
    assert raw.endswith(b'\0') and b'\0' not in raw[:-1]
    return raw[:-1].decode()


def decode(data):
    result=dict(namespace=data['namespace'],links=[],addresses=[],routes=[],rules=[])
    for group,rows in data['dumps'].items():
        request=int(group.split('/')[0])
        for row in rows:
            raw=bytes.fromhex(row)[16:]
            if request==18:
                family,pad,hardware,index,flags,change=struct.unpack_from('=BBHiII',raw);a=attrs(raw[16:]);info=attrs(a[18]) if 18 in a else {}
                kind=text(info[1]) if 1 in info else ''
                assert kind in ('','bridge') and set(info)<= {1,2},'fresh_lab_link_kind'
                props=attrs(a[52],repeated=True) if 52 in a else {};assert set(props)<={53}
                result['links'].append(dict(name=text(a[3]),index=index,kind=kind,up=bool(flags&1),mtu=scalar(a,4),alias=text(a[20]) if 20 in a else '',peer_index=scalar(a,5),hardware_type=hardware,controller=scalar(a,10,0),port_kind='',promiscuity=scalar(a,30,0),all_multicast=scalar(a,61,0),alternate_names=[text(v) for v in props[53]] if props else [],tun_info=[],max_pacing_offload_horizon=scalar(a,66),headroom=scalar(a,68,width=2),tailroom=scalar(a,69,width=2)))
            elif request==22:
                family,prefix,flags,scope,index=struct.unpack_from('=BBBBI',raw);a=attrs(raw[8:]);assert set(a)<={1,2,3,4,6,8,9,11}
                if 1 in a and 2 in a:assert a[1]==a[2]
                result['addresses'].append(dict(broadcast=str(ipaddress.ip_address(a[4])) if 4 in a else None,route_priority=scalar(a,9),flags=scalar(a,8,flags),index=index,address=str(ipaddress.ip_address(a.get(2,a.get(1)))),prefix=prefix,scope=scope))
            else:
                family,dst,src,tos,table,p1,p2,action,flags=struct.unpack_from('=BBBBBBBBI',raw);a=attrs(raw[12:]);assert family in (2,10) and src==tos==0
                if request==26:
                    assert set(a)<={1,4,5,6,7,12,15,20,30}
                    ip=lambda key: str(ipaddress.ip_address(a[key])) if key in a else None
                    result['routes'].append(dict(nexthop_id=scalar(a,30),preference=scalar(a,20,0,1),destination=ip(1) or ('0.0.0.0' if family==2 else '::'),prefix=dst,table=scalar(a,15,table),output=scalar(a,4,0),source=ip(7),gateway=ip(5),kind=action,scope=p2,protocol=p1,metric=scalar(a,6,0),flags=flags))
                else:
                    assert dst==0 and set(a)<={6,10,11,12,13,14,15,16,21}
                    result['rules'].append(dict(ipv6=family==10,priority=scalar(a,6,0),table=scalar(a,15,table),action=action,flags=flags,fwmark=scalar(a,10),fwmask=scalar(a,16),suppress_prefixlen=scalar(a,14),suppress_ifgroup=scalar(a,13),goto=scalar(a,12),realm=scalar(a,11),protocol=scalar(a,21,width=1)))
    return result


def shape_module():
    path=pathlib.Path('target/platform-lab/host_baseline_declaration.py')
    spec=importlib.util.spec_from_file_location('baseline_shape',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def stable(value):
    return dict(namespace=value['namespace'],**{k:sorted(value[k],key=canonical) for k in ('links','addresses','routes','rules')})


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['collect','author','compare']);parser.add_argument('candidate',type=pathlib.Path);parser.add_argument('evidence',type=pathlib.Path);args=parser.parse_args()
    c=json.loads(args.candidate.read_bytes());e=args.evidence;platform='debian-clean-x86_64'
    dump=e/'independent-netlink.json';admission=e/'admission.json'
    if args.action=='collect':
        ssh=['ssh','-F','/dev/null','-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','BatchMode=yes','-o','UpdateHostKeys=no','-i','target/lab-state/id_ed25519','-p22036','-o','UserKnownHostsFile=target/platform-lab/debian-clean-x86_64/known_hosts','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','vprouterlab@127.0.0.1','sudo -n python3 -I -']
        r=subprocess.run(ssh,input=REMOTE,capture_output=True,text=True,timeout=20)
        save(e/'independent-netlink-ssh.json',dict(argv=ssh,exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr,remote_sha256=hashlib.sha256(REMOTE.encode()).hexdigest()))
        assert r.returncode==0 and not r.stderr,r.stderr
        save(dump,json.loads(r.stdout));print(dump);return
    data=json.loads(dump.read_bytes());a=json.loads(admission.read_bytes());expected=decode(data);shape=shape_module();shape.validate_shape(expected)
    assert data['boot_id']==a['boot_id']=='e14efc10-050b-41b0-89d8-1e946725098c'
    assert expected['namespace']==a['namespace']['/proc/1/ns/net']==a['namespace']['/proc/self/ns/net']
    assert {v['name']:v['index'] for v in expected['links']}=={'lo':1,'ens2':2,'docker0':3}
    assert len(expected['addresses'])==6 and len(expected['routes'])==19 and len(expected['rules'])==5
    iplinks=json.loads(a['commands']['ip -j -d link show']['stdout'])
    for link in expected['links']:
        iplink=next(v for v in iplinks if v['ifindex']==link['index'])
        assert link['name']==iplink['ifname'] and link['mtu']==iplink['mtu'] and link['up']==('UP' in iplink['flags'])
        assert link['kind']==iplink.get('linkinfo',{}).get('info_kind','')
        assert link['alternate_names']==iplink.get('altnames',[])
    template_path=args.candidate.parent/('authored-host-baseline-'+platform+'.json');review_path=args.candidate.parent/('host-baseline-reconciliation-'+platform+'.json')
    if args.action=='author':
        assert not (args.candidate.parent/('host-projection-'+platform)).exists(),'author_before_frozen_projection'
        refs=[dict(path=str(p),sha256=sha(p)) for p in [dump,admission,e/'admission-status.stdout.json']]
        review=dict(schema=1,route='fresh-lab',source_binding=c['binding'],platform=platform,namespace=expected['namespace'],baseline_sha256=hashlib.sha256(canonical(expected)).hexdigest(),counts={k:len(expected[k]) for k in ('links','addresses','routes','rules')},references=refs,helpers=[dict(path=str(pathlib.Path(__file__)),sha256=sha(__file__)),dict(path='target/platform-lab/host_baseline_declaration.py',sha256=sha('target/platform-lab/host_baseline_declaration.py'))],guest_boot_id=data['boot_id'],historical_continuity=False,prior_structure_reconstructed=False,ordering_only_aligned_after_exact_multiset_comparison=False,declaration_staged=False,host_authority_granted=False,projection_used_to_author=False,provenance='New independent RTM_GET kernel dump, cross-checked against separate iproute2 admission; explicit fresh environment, no run398-408 lineage. Independent review pending.',differences='3/6/19/5 instead of historical 61/51/154/5; no retained failed endpoints or original identities. Not a causal speedup control.')
        save(review_path,review)
        template=dict(schema=1,platform=platform,source_binding=c['binding'],baseline=expected,baseline_sha256=review['baseline_sha256'],prior_evidence=refs,review_sha256=sha(review_path));shape.validate_template(template,c['binding'],platform);save(template_path,template)
        print(json.dumps(dict(template=str(template_path),review=str(review_path),counts=review['counts'])));return
    template=json.loads(template_path.read_bytes());shape.validate_template(template,c['binding'],platform)
    assert canonical(expected)==canonical(template['baseline'])
    projection_path=args.candidate.parent/('host-projection-'+platform)/'record.json';p=json.loads(projection_path.read_bytes())
    assert p['source_binding']==c['binding'] and p['artifact_sha256']==c['platforms']['amd64']['artifact_sha256'] and p['platform']==platform
    assert p['report']['read_only'] is True and p['report']['declaration_authority'] is p['report']['host_change_authority'] is False
    assert stable(expected)==stable(p['report']['projection']),'full_multiset_drift'
    save(e/'baseline-comparison.json',dict(exact_multisets_equal=True,namespace_preserved=True,baseline_sha256=template['baseline_sha256'],projection_sha256=sha(projection_path),template_sha256=sha(template_path),no_authority=True))
    print('full namespace/links/addresses/routes/rules multisets equal; authored baseline unchanged')


if __name__=='__main__':main()
