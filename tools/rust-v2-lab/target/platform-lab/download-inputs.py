import concurrent.futures,hashlib,json,pathlib,urllib.request,re
root=pathlib.Path(__file__).resolve().parent
downloads=root/'downloads'

def get(url,name):
    path=downloads/name
    if not path.exists():
        pending=path.with_suffix(path.suffix+'.partial')
        with urllib.request.urlopen(url,timeout=45) as response,pending.open('wb') as output:
            while block:=response.read(1024*1024):output.write(block)
        pending.rename(path)
    return path

def checksum(path,algorithm):
    h=hashlib.new(algorithm)
    with path.open('rb') as stream:
        while block:=stream.read(1024*1024):h.update(block)
    return h.hexdigest()

def download(spec):
    base,name,algorithm,list_name,local_list=spec
    checks=get(base+list_name,local_list).read_text()
    expected=None
    for line in checks.splitlines():
        if match:=re.fullmatch(r'SHA256 \((.+)\) = ([a-f0-9]+)',line):
            filename,digest=match.groups()
        else:
            fields=line.split()
            if len(fields)!=2:continue
            digest,filename=fields
        if filename.lstrip('*') in (name,'./'+name):expected=digest;break
    assert expected is not None,(name,'missing checksum')
    path=get(base+name,name)
    digest=checksum(path,algorithm)
    assert digest==expected,(name,'checksum mismatch')
    row={'url':base+name,'path':str(path),'bytes':path.stat().st_size,algorithm:digest,
         'checksum_source':base+list_name,'checksum_verified':True,'executed':False}
    print(json.dumps(row),flush=True)
    return row

specs=[
 ('https://geo.mirror.pkgbuild.com/images/latest/','Arch-Linux-x86_64-cloudimg-20261015.611680.qcow2','sha256','Arch-Linux-x86_64-cloudimg-20261015.611680.qcow2.SHA256','arch.SHA256'),
 ('https://cloud.debian.org/images/cloud/trixie/20261021-2638/','debian-13-genericcloud-arm64-20261021-2638.qcow2','sha512','SHA512SUMS','debian-arm64.SHA512SUMS'),
 ('https://repo-default.voidlinux.org/live/20250202/','void-live-x86_64-20250202-base.iso','sha256','sha256sum.txt','void.sha256sum.txt'),
 ('https://repo-default.voidlinux.org/live/20250202/','void-x86_64-ROOTFS-20250202.tar.xz','sha256','sha256sum.txt','void-rootfs.sha256sum.txt'),
]
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    rows=list(pool.map(download,specs))
get('https://repo-default.voidlinux.org/live/20250202/sha256sum.sig','void.sha256sum.sig')
get('https://raw.githubusercontent.com/void-linux/void-packages/master/srcpkgs/void-release-keys/files/void-release-20250202.pub','void-release-20250202.pub')
get('https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg-20261015.611680.qcow2.sig','arch.qcow2.sig')
(root/'input-inventory.json').write_text(json.dumps({'images':rows,'platform_runtime':'NOT_RUN','signatures_verified':False},indent=2)+'\n')
