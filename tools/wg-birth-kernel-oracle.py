# Test-only independent kernel oracle. No production profile/state is read.
import os, pathlib, stat, subprocess, tempfile, json, time, socket, select, signal, struct

class Closed(Exception): pass

def run(args, data=None):
    r=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=6)
    if r.returncode: raise Closed('fixed_test_operation_failed')
    return r.stdout

def ip(*args): return run(['ip',*args])
def inside(ns,*args,data=None): return run(['ip','netns','exec',ns,*args],data)

def admit():
    if os.geteuid()!=0: raise Closed('root_required')
    p=pathlib.Path('/var/lib/vprouter-v2-lab')
    for part in [pathlib.Path('/'),pathlib.Path('/var'),pathlib.Path('/var/lib'),p]:
        s=part.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022: raise Closed('untrusted_marker_parent')
    m=(p/'isolated-acceptance').lstat()
    if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_gid!=0 or stat.S_IMODE(m.st_mode)!=0o600 or m.st_nlink!=1: raise Closed('lab_marker_required')
    if os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino: raise Closed('disposable_netns_required')

def capture(path):
    p=subprocess.Popen(['tcpdump','--immediate-mode','-U','-n','-s','0','-i','vbirthh','-w',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    end=time.monotonic()+4
    while time.monotonic()<end:
        if p.poll() is not None: raise Closed('capture_start_failed')
        if select.select([p.stderr],[],[],0.2)[0]:
            if b'listening on' in p.stderr.readline(): return p
    p.kill(); p.wait()
    raise Closed('capture_not_operational')

def stop_capture(p):
    p.send_signal(signal.SIGINT)
    try: p.communicate(timeout=3)
    except subprocess.TimeoutExpired: p.kill(); p.communicate(timeout=2); raise Closed('capture_stop_failed')

def inspect_capture(path,marker):
    b=path.read_bytes()
    if len(b)<24: raise Closed('capture_empty')
    endian='<' if b[:4] in [b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1'] else '>'
    linktype=struct.unpack_from(endian+'I',b,20)[0]
    if linktype!=1: raise Closed('unexpected_capture_linktype')
    offset=24; packets=udp=icmp=marks=0
    while offset<len(b):
        if offset+16>len(b): raise Closed('truncated_capture')
        caplen=struct.unpack_from(endian+'I',b,offset+8)[0]; offset+=16
        p=b[offset:offset+caplen]; offset+=caplen
        if len(p)!=caplen: raise Closed('truncated_capture')
        packets+=1; marks+=int(marker in p)
        if len(p)>=34 and p[12:14]==b'\x08\x00':
            proto=p[23]; ihl=(p[14]&15)*4
            if proto==17 and len(p)>=14+ihl+8:
                a,z=struct.unpack_from('!HH',p,14+ihl)
                udp+=int(a in [51820,51821] or z in [51820,51821])
            icmp+=int(proto==1)
    return {'packets':packets,'wireguard_port_udp_packets':udp,'icmp_packets':icmp,'plaintext_marker_packets':marks}

names=[]; captures=[]; directory=None
try:
    admit()
    suffix=str(os.getpid())
    data='vr-birth-d-'+suffix; peer='vr-birth-p-'+suffix
    for ns in [data,peer]:
        ip('netns','add',ns); names.append(ns)
    ip('link','add','vbirthh','type','veth','peer','name','vbirthp')
    ip('link','set','vbirthp','netns',peer)
    ip('addr','add','198.18.0.1/30','dev','vbirthh'); ip('link','set','vbirthh','up'); ip('link','set','lo','up')
    ip('-n',peer,'addr','add','198.18.0.2/30','dev','vbirthp'); ip('-n',peer,'link','set','vbirthp','up'); ip('-n',peer,'link','set','lo','up')
    ip('-n',data,'link','set','lo','up')
    directory=pathlib.Path(tempfile.mkdtemp(prefix='vr-birth-',dir='/run'))
    os.chmod(directory,0o700)
    marker=b'VPBIRTHMARKER001'
    cp=capture(directory/'positive.pcap'); captures.append(cp)
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('198.18.0.1',0)); s.sendto(marker,('198.18.0.2',40000)); s.close()
    time.sleep(.3); stop_capture(cp); captures.remove(cp)
    control=inspect_capture(directory/'positive.pcap',marker)
    if control['plaintext_marker_packets']<1:
        print(json.dumps({'stage':'positive_capture_control','counts':control}))
        raise Closed('positive_capture_control_failed')
    # Fresh keys stay in memory and stdin only; private-key arguments contain no secret.
    ka=run(['wg','genkey']); kb=run(['wg','genkey'])
    pa=run(['wg','pubkey'],ka).strip().decode(); pb=run(['wg','pubkey'],kb).strip().decode()
    ip('link','add','wgbirth','type','wireguard')
    run(['wg','set','wgbirth','private-key','/dev/stdin','listen-port','51821','peer',pb,'allowed-ips','10.64.1.1/32','endpoint','198.18.0.2:51820'],ka)
    ip('-n',peer,'link','add','wgpeer','type','wireguard')
    inside(peer,'wg','set','wgpeer','private-key','/dev/stdin','listen-port','51820','peer',pa,'allowed-ips','10.64.1.2/32',data=kb)
    ka=kb=b''
    ip('link','set','wgbirth','netns',data)
    ip('-n',data,'addr','add','10.64.1.2/32','dev','wgbirth'); ip('-n',data,'link','set','wgbirth','up')
    ip('-n',data,'route','add','10.64.1.1/32','dev','wgbirth','src','10.64.1.2')
    ip('-n',peer,'addr','add','10.64.1.1/32','dev','wgpeer'); ip('-n',peer,'link','set','wgpeer','up')
    ip('-n',peer,'route','add','10.64.1.2/32','dev','wgpeer','src','10.64.1.1')
    interfaces=json.loads(ip('-n',data,'-j','link','show'))
    if {x['ifname'] for x in interfaces}!={'lo','wgbirth'}: raise Closed('unexpected_data_interface')
    if any(x['ifname']=='wgbirth' for x in json.loads(ip('-j','link','show'))): raise Closed('wg_not_moved')
    cp=capture(directory/'encrypted.pcap'); captures.append(cp)
    inside(data,'ping','-n','-I','10.64.1.2','-c','3','-i','0.2','-W','2','-p',marker.hex(),'10.64.1.1')
    time.sleep(.3); stop_capture(cp); captures.remove(cp)
    observed=inspect_capture(directory/'encrypted.pcap',marker)
    hs=inside(data,'wg','show','wgbirth','latest-handshakes').splitlines()
    if len(hs)!=1 or not 0<=time.time()-int(hs[0].split()[-1])<10: raise Closed('no_fresh_handshake')
    if observed['wireguard_port_udp_packets']<2 or observed['icmp_packets'] or observed['plaintext_marker_packets']: raise Closed('birth_path_capture_failed')
    print(json.dumps({'case':'independent_wireguard_socket_birth_namespace','result':'PASS','encrypted_ping_replies':3,'data_interfaces':['lo','wgbirth'],'positive_capture':control,'encrypted_capture':observed,'keys':'fresh_disposable_not_output_or_persisted','provider_credentials_used':False,'native_component_invoked':False,'real_client_acceptance':'NOT_RUN'}))
except Exception as e:
    print(json.dumps({'case':'independent_wireguard_socket_birth_namespace','result':'FAIL','reason':str(e) if isinstance(e,Closed) else type(e).__name__}))
    raise SystemExit(1)
finally:
    for p in captures:
        p.kill(); p.communicate(timeout=2)
    for ns in reversed(names):
        subprocess.run(['ip','netns','delete',ns],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
    if directory is not None:
        import shutil
        shutil.rmtree(directory,ignore_errors=True)
