"""Read-only inventory of retained producer-placement attempts, on the lab VM."""
import json
import pathlib
import stat
import subprocess

root = pathlib.Path('/var/lib/vprouter-v2-lab')
metadata = root.lstat()
assert stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
assert stat.S_IMODE(metadata.st_mode) == 0o700
rows = []
for directory in sorted(root.iterdir()):
    if not directory.name.startswith('task8b1-') or not directory.is_dir():
        continue
    row = {'directory': str(directory),
           'entries': sorted(item.name for item in directory.iterdir())}
    for path in directory.rglob('*.json'):
        metadata = path.lstat()
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
        assert metadata.st_size < 65536
        if path.name == 'resources.json' or 'records' in path.parts:
            row.setdefault('record_files', {})[str(path.relative_to(directory))] = json.loads(path.read_text())
    resources = directory / 'resources.json'
    if resources.exists():
        container = json.loads(resources.read_text())['container']
        assert len(container) == 64 and all(c in '0123456789abcdef' for c in container)
        result = subprocess.run(['docker', 'inspect', '--format',
                                 '{{.Id}} {{.State.Running}} {{.State.Pid}}', container],
                                capture_output=True, text=True, timeout=5)
        row['container_inspect'] = {'code': result.returncode,
                                    'stdout': result.stdout, 'stderr': result.stderr}
        parent = pathlib.Path('/sys/fs/cgroup/system.slice/docker-' + container + '.scope')
        row['parent_cgroup_exists'] = parent.exists()
        if parent.exists():
            row['cgroup_process_files'] = {
                str(path.relative_to(parent)): path.read_text()
                for path in parent.rglob('cgroup.procs')}
    rows.append(row)
print(json.dumps({'attempt_directories': rows,
                  'approval_marker_retained': (root / 'task8b1-producer-acceptance').exists()}, indent=2))
