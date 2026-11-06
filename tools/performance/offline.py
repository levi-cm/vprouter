"""Bounded offline accounting CLI; never collects or launches real workloads."""
import argparse
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat

_spec=importlib.util.spec_from_file_location('_task14_accounting',Path(__file__).with_name('accounting.py'))
a=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)
MAX_JSON=16*1024*1024


def decode(raw):
    a.require(type(raw) is bytes and len(raw)<=MAX_JSON,'json_bound')
    def unique(items):
        out={}
        for k,v in items:
            a.require(k not in out,'duplicate_json_key');out[k]=v
        return out
    def number(text):
        raise ValueError('json_decimal_forbidden')
    def integer(text):
        a.require(len(text)<=21,'json_integer');v=int(text)
        a.require(abs(v)<=a.U64,'json_integer');return v
    def bad(_):raise ValueError('nonfinite_json')
    # Pre-scan nesting outside strings before allocating a deep JSON tree.
    depth=0;quoted=False;escape=False
    for byte in raw:
        if quoted:
            if escape:escape=False
            elif byte==92:escape=True
            elif byte==34:quoted=False
        elif byte==34:quoted=True
        elif byte in (91,123):
            depth+=1;a.require(depth<=32,'json_depth')
        elif byte in (93,125):depth-=1
    try:
        return json.loads(raw,object_pairs_hook=unique,parse_int=integer,parse_float=number,parse_constant=bad)
    except (UnicodeError,RecursionError) as error:
        raise ValueError('invalid_json') from error


def parent_fd(path):
    """Pin every directory component without symlink traversal; no mkdir."""
    value=os.fspath(path)
    a.require(type(value) is str and 0<len(value)<=4096 and '\x00' not in value,'output_path')
    p=Path(value);a.require(p.name not in ('','.','..') and '..' not in p.parts,'output_path')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW
    directory=os.open('/' if p.is_absolute() else '.',flags)
    parts=p.parts[1:-1] if p.is_absolute() else p.parts[:-1]
    try:
        for part in parts:
            new=os.open(part,flags,dir_fd=directory);os.close(directory);directory=new
        return directory,p.name
    except BaseException:
        os.close(directory);raise


def load(path):
    directory,name=parent_fd(path)
    try:
        fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
        try:
            before=os.fstat(fd)
            a.require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=MAX_JSON,'input_file')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(MAX_JSON+1)
            after=os.fstat(fd)
            a.require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                      (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'input_changed')
            return decode(raw)
        finally:os.close(fd)
    finally:os.close(directory)


def rename_exclusive(directory,source,destination):
    # Linux 6.1+ is binding. RENAME_NOREPLACE is atomic, unlike an existence
    # check followed by os.rename/os.replace. No unsafe fallback is provided.
    libc=ctypes.CDLL(None,use_errno=True)
    rename=getattr(libc,'renameat2',None)
    if rename is None:raise OSError(errno.ENOSYS,'renameat2_unavailable')
    rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    rename.restype=ctypes.c_int
    if rename(directory,os.fsencode(source),directory,os.fsencode(destination),1):
        raise OSError(ctypes.get_errno(),'exclusive_rename_failed')


def publish(path,data):
    """Exclusive temp + fsync(file) + rename NOREPLACE + fsync(directory)."""
    a.require(type(data) is bytes and len(data)<=MAX_JSON,'output_bound')
    directory,name=parent_fd(path);temporary='.task14-'+secrets.token_hex(16);created=False
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
        created=True
        try:
            offset=0
            while offset<len(data):
                count=os.write(fd,data[offset:]);a.require(count>0,'short_write');offset+=count
            os.fsync(fd)
        finally:os.close(fd)
        rename_exclusive(directory,temporary,name);created=False
        os.fsync(directory)
    finally:
        if created:os.unlink(temporary,dir_fd=directory)
        os.close(directory)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    summary=commands.add_parser('summarize');summary.add_argument('run');summary.add_argument('--output')
    comp=commands.add_parser('compare');comp.add_argument('--baseline',nargs='*',default=[])
    comp.add_argument('--candidate',nargs='*',default=[]);comp.add_argument('--output')
    args=parser.parse_args(argv)
    try:
        if args.command=='summarize':result=a.summarize(load(args.run))
        else:
            a.require(len(args.baseline)+len(args.candidate)<=a.MAX_RUNS,'suite_bound')
            # Only compact summaries persist between bounded input files.
            summaries=[]
            for kind,paths in [('baseline',args.baseline),('candidate',args.candidate)]:
                for path in paths:summaries.append((kind,a.summarize(load(path))))
            result=a._compare_summaries(summaries)
        # Failed summary analysis has no publishable result. Comparisons may
        # publish complete insufficient reports (e.g. missing suite shapes),
        # but malformed raw records must not create a partial report.
        a.require(not (args.command=='summarize' and result['status']!='PASS'),'unqualified_summary')
        a.require('invalid_run' not in result.get('reasons',[]) and
                  not any('invalid_runtime_evidence' in s.get('reasons',[]) for s in result.get('scenarios',[])), 'invalid_suite_input')
        raw=a.canonical(result)+b'\n'
        if args.output:publish(args.output,raw)
        else:print(raw.decode('ascii'),end='')
        return 0 if result['status']=='PASS' else 2
    except (ValueError,KeyError,TypeError,IndexError,OverflowError,RecursionError,AttributeError,StopIteration,OSError):
        print('{"reasons":["invalid_input_or_publication"],"release_ready":false,"schema":1,"status":"INSUFFICIENT_DATA"}')
        return 2


if __name__=='__main__':raise SystemExit(main())
