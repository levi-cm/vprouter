"""Read-only resource samples for an explicitly identified isolated lab cohort.

This collector neither launches workloads nor establishes acceptance. Supply a
Root-created manifest with the VM boot ID, non-overlapping cgroup-v2 roots and
their native dev/inode identities, plus exact executable hashes for PSS labels.
It never reads process arguments, environment, identity state or configuration.
Short runs are smoke checks only. Retain JSONL, including incomplete runs.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import resource
import stat
import time
import measurement


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def read_at(directory, name, limit=1048576):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
    try:
        chunks = []
        length = 0
        while True:
            data = os.read(fd, min(65536, limit + 1 - length))
            if not data:
                return b"".join(chunks)
            chunks.append(data)
            length += len(data)
            if length > limit:
                raise RuntimeError("bounded_read_exceeded")
    finally:
        os.close(fd)


def pairs(data):
    return {key: int(value) for key, value in (line.split() for line in data.decode().splitlines())}


def open_relative(root, relative):
    pieces = relative.split("/")
    assert pieces and all(piece not in ("", ".", "..") and len(piece) <= 255 for piece in pieces)
    fd = os.dup(root)
    try:
        for piece in pieces:
            new = os.open(piece, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def identity(fd):
    value = os.fstat(fd)
    return [value.st_dev, value.st_ino]


def process_stat(directory):
    raw = read_at(directory, "stat", 16384).decode()
    values = raw[raw.rfind(")") + 2:].split()
    return measurement.parse_process_stat(raw)


def file_signature(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def process_sample(pid, cohort, executable_labels, digest_cache):
    proc = os.open("/proc/" + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        start, ticks, state = process_stat(proc)
        if state in ("Z", "X", "x"):
            return None, "terminal_process_state_" + state
        memberships = read_at(proc, "cgroup", 65536).decode().splitlines()
        assert len(memberships) == 1 and memberships[0].startswith("0::/")
        member = memberships[0][4:]
        if member != cohort and not member.startswith(cohort + "/"):
            return None, "moved_outside_cohort"
        # exe is a kernel magic link in the retained proc directory. Opening it
        # pins the current native file; paths/comm never determine the label.
        executable = os.open("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc)
        try:
            before = os.fstat(executable)
            assert stat.S_ISREG(before.st_mode) and before.st_size <= 134217728
            native = file_signature(before)
            memory = {}
            for line in read_at(proc, "smaps_rollup").decode().splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    if key in ("Rss", "Pss"):
                        count, unit = value.split()
                        assert unit == "kB"
                        memory[key] = int(count) * 1024
            if native not in digest_cache:
                digest = hashlib.sha256()
                while True:
                    block = os.read(executable, 1048576)
                    if not block:
                        break
                    digest.update(block)
                digest_cache[native] = digest.hexdigest()
            digest = digest_cache[native]
            after = os.fstat(executable)
            assert native == file_signature(after)
            final_executable = os.open("exe", os.O_RDONLY | os.O_CLOEXEC, dir_fd=proc)
            try:
                if file_signature(os.fstat(final_executable)) != native:
                    return None, "executable_changed"
            finally:
                os.close(final_executable)
        finally:
            os.close(executable)
        final_start, final_ticks, final_state = process_stat(proc)
        if final_state in ("Z", "X", "x"):
            return None, "terminal_process_state_" + final_state
        assert start == final_start and final_ticks >= ticks
        if read_at(proc, "cgroup", 65536).decode().splitlines() != memberships:
            return None, "cohort_membership_changed"
        return dict(pid=pid, start=start, state=final_state, cgroup=member, cpu_ticks=final_ticks, pss_bytes=memory["Pss"],
                    rss_bytes=memory["Rss"], executable_dev=before.st_dev,
                    executable_ino=before.st_ino, executable_sha256=digest,
                    label=executable_labels.get(digest, "unclassified")), None
    finally:
        os.close(proc)


def collect_pids(group):
    pending = [os.dup(group)]
    pids, groups, vanished = set(), 0, 0
    try:
        while pending:
            directory = pending.pop()
            try:
                groups += 1
                assert groups <= 8192
                pids.update(int(value) for value in read_at(directory, "cgroup.procs").split())
                assert len(pids) <= 32768
                for name in os.listdir(directory):
                    try:
                        entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
                        if stat.S_ISDIR(entry.st_mode):
                            pending.append(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory))
                    except FileNotFoundError:
                        vanished += 1
            except FileNotFoundError:
                vanished += 1
            finally:
                os.close(directory)
    finally:
        for directory in pending:
            os.close(directory)
    return sorted(pids), groups, vanished


def sample_group(group, entry, executable_labels, digest_cache):
    counter_start = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    cpu = pairs(read_at(group, "cpu.stat"))
    memory_current = int(read_at(group, "memory.current"))
    memory_events = pairs(read_at(group, "memory.events"))
    memory_stat = pairs(read_at(group, "memory.stat"))
    counter_end = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    pids, groups, vanished = collect_pids(group)
    processes, churn, invalid = [], 0, []
    for pid in pids:
        try:
            row, reason = process_sample(pid, entry["relative"], executable_labels, digest_cache)
            if reason:
                invalid.append(dict(pid=pid, reason=reason))
            else:
                processes.append(row)
        except (FileNotFoundError, ProcessLookupError):
            churn += 1
    by_label = {}
    for row in processes:
        by_label[row["label"]] = by_label.get(row["label"], 0) + row["pss_bytes"]
    return dict(role=entry["role"], accounting_class=entry["accounting_class"], native_identity=identity(group), cpu=cpu, memory_stat=memory_stat,
                counters_read_started_boottime_ns=counter_start, counters_read_finished_boottime_ns=counter_end,
                memory_current_bytes=memory_current, memory_events=memory_events,
                pss_bytes=sum(row["pss_bytes"] for row in processes), pss_by_label_bytes=by_label,
                processes=processes, descendant_groups=groups, vanished_groups=vanished,
                vanished_processes=churn, invalid_processes=invalid)


def whole_host():
    memory = {}
    for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "Slab", "SReclaimable", "SUnreclaim", "KernelStack", "PageTables", "Percpu"):
            count, unit = value.split()
            assert unit == "kB"
            memory[key + "_bytes"] = int(count) * 1024
    cpu = pathlib.Path("/proc/stat").read_text().splitlines()[0].split()
    assert cpu[0] == "cpu"
    names = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice")
    assert 8 <= len(cpu) - 1 <= len(names)
    return dict(cpu_ticks=dict(zip(names, map(int, cpu[1:]))), memory=memory)


def main():
    if not __debug__:
        raise RuntimeError("optimized_python_disables_required_checks")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest")
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args()
    assert 1 <= args.seconds <= 90000 and 0.25 <= args.interval <= 10
    measurement.number(args.interval, 0.25)
    manifest_path = pathlib.Path(args.manifest)
    fd = os.open(manifest_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= 65536
        assert metadata.st_uid == os.geteuid() and stat.S_IMODE(metadata.st_mode) == 0o600
        data = os.read(fd, 65537)
        assert len(data) == metadata.st_size and file_signature(os.fstat(fd)) == file_signature(metadata)
    finally:
        os.close(fd)
    manifest = measurement.decode_json(data)
    measurement.validate_manifest(manifest)
    boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    assert manifest["boot_id"] == boot
    etc = os.open("/etc", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        host = hashlib.sha256(read_at(etc, "machine-id", 4096).strip()).hexdigest()
    finally:
        os.close(etc)
    assert host == manifest["binding"]["host_id_sha256"]
    labels = manifest["executable_labels"]
    workload = manifest["binding"]["workload_sha256"]
    mount_rows = pathlib.Path("/proc/self/mountinfo").read_text().splitlines()
    assert any(row.split()[4] == "/sys/fs/cgroup" and " - cgroup2 " in row for row in mount_rows)
    root = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    groups = []
    try:
        for entry in manifest["groups"]:
            group = open_relative(root, entry["relative"])
            groups.append((entry, group))
            assert identity(group) == entry["native_identity"]
        emit(dict(kind="begin", utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  manifest_sha256=hashlib.sha256(data).hexdigest(), boot_id=boot,
                  workload_binding_sha256=workload, requested_seconds=args.seconds, interval=args.interval,
                  schema=2, manifest=manifest, evidence_origin=manifest["evidence_origin"],
                  manifest_canonical_sha256=measurement.canonical_digest(manifest),
                  collector_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                  collector_helper_sha256=measurement.file_digest(measurement.__file__),
                  clock="CLOCK_BOOTTIME", clock_ticks=os.sysconf("SC_CLK_TCK"),
                  acceptance="NOT_EVALUATED: requires bound workload, platform/fault and matched-baseline evidence",
                  limitations=["PSS snapshots can miss transient processes; cgroup CPU/memory include them",
                               "bracketed process snapshots are not atomic and cannot rule out exec/membership ABA",
                               "whole-host totals include unrelated VM activity and observer",
                               "unclassified executable PSS is included; no exclusion by process name",
                               "end observer usage includes all prior output; excludes final end-record serialization/flush",
                               "executable hashes cached only for measurement labels by native file identity and metadata"]))
        start = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        deadline = start + args.seconds * 1000000000
        sequence, last, max_gap, digest_cache = 0, start, 0, {}
        while True:
            now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip() == boot
            rows = []
            for entry, group in groups:
                fresh = open_relative(root, entry["relative"])
                try:
                    assert identity(fresh) == entry["native_identity"] == identity(group)
                finally:
                    os.close(fresh)
                rows.append(sample_group(group, entry, labels, digest_cache))
                fresh = open_relative(root, entry["relative"])
                try:
                    assert identity(fresh) == entry["native_identity"] == identity(group)
                finally:
                    os.close(fresh)
            seen, duplicates = set(), []
            for row in rows:
                for process in row["processes"]:
                    key = (process["pid"], process["start"])
                    if key in seen:
                        duplicates.append(dict(pid=key[0], start=key[1]))
                    seen.add(key)
            whole_start = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            host = whole_host()
            whole_end = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            finished = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            usage = resource.getrusage(resource.RUSAGE_SELF)
            max_gap = max(max_gap, now - last)
            pss_valid = not duplicates and all(not row["invalid_processes"] and not row["vanished_processes"] and not row["vanished_groups"] for row in rows)
            emit(dict(kind="sample", sequence=sequence, elapsed_ns=now-start,
                      read_collection_ns=finished-now, gap_ns=now-last, groups=rows,
                      duplicate_process_identities=duplicates, pss_sum_valid=pss_valid,
                      total_cohort_pss_bytes=sum(row["pss_bytes"] for row in rows) if pss_valid else None,
                      whole_host=host, whole_host_read_started_boottime_ns=whole_start,
                      whole_host_read_finished_boottime_ns=whole_end,
                      observer_cpu_seconds=usage.ru_utime+usage.ru_stime, observer_maxrss_bytes=usage.ru_maxrss * 1024))
            flushed = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            usage = resource.getrusage(resource.RUSAGE_SELF)
            emit(dict(kind="sample_complete", sequence=sequence, read_started_boottime_ns=now,
                      read_finished_boottime_ns=finished, sample_flush_finished_boottime_ns=flushed,
                      observer_cpu_seconds_through_sample_flush=usage.ru_utime+usage.ru_stime,
                      observer_maxrss_bytes=usage.ru_maxrss * 1024))
            sequence += 1
            last = now
            if now >= deadline:
                break
            remaining = min(start + int(sequence * args.interval * 1000000000), deadline) - time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            if remaining > 0:
                time.sleep(remaining / 1000000000)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        emit(dict(kind="end", samples=sequence, elapsed_ns=now-start, max_gap_ns=max_gap,
                  observer_cpu_seconds_through_prior_output=usage.ru_utime+usage.ru_stime,
                  observer_maxrss_bytes=usage.ru_maxrss * 1024,
                  ten_minute_duration_met=now-start >= 600000000000,
                  full_day_duration_met=now-start >= 86400000000000,
                  acceptance="NOT_EVALUATED", cleanup="none; read-only collector"))
    finally:
        for _, group in groups:
            os.close(group)
        os.close(root)


if __name__ == "__main__":
    try:
        main()
    except SystemExit as error:
        if error.code:
            emit(dict(kind="incomplete", error_type="invalid_arguments", acceptance="NOT_EVALUATED"))
        raise
    except BaseException as error:
        emit(dict(kind="incomplete", error_type=type(error).__name__, acceptance="NOT_EVALUATED"))
        raise
