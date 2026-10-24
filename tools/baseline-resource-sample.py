#!/usr/bin/env python3
"""Read-only short cgroup-v2/PSS inventory; never reads argv, env or config.

Run with procfs permissions (normally sudo). This is an observational sample,
not the repeated ten-minute controlled-workload performance acceptance.
"""
import datetime
import json
import pathlib
import statistics
import subprocess
import time


def command(*args):
    return subprocess.check_output(args, text=True, timeout=10).strip()


def group_for(pid):
    for line in pathlib.Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        if line.startswith("0::/"):
            return pathlib.Path("/sys/fs/cgroup") / line[4:]
    raise RuntimeError("cgroup v2 required")


def read_group(path):
    cpu = dict(line.split() for line in (path / "cpu.stat").read_text().splitlines())
    pids = set()
    for source in [path / "cgroup.procs", *path.glob("**/cgroup.procs")]:
        pids.update(source.read_text().split())
    processes = []
    for pid in sorted(pids, key=int):
        try:
            proc = pathlib.Path("/proc") / pid
            memory = dict(line.split(":", 1) for line in (proc / "smaps_rollup").read_text().splitlines() if ":" in line)
            processes.append({"pid": int(pid), "comm": (proc / "comm").read_text().strip(),
                              "pss_kib": int(memory["Pss"].split()[0]),
                              "rss_kib": int(memory["Rss"].split()[0])})
        except FileNotFoundError:
            # Short-lived monitoring subprocesses are still included in cpu.stat.
            continue
    return {"cpu_usage_usec": int(cpu["usage_usec"]),
            "memory_current_bytes": int((path / "memory.current").read_text()),
            "pss_kib": sum(p["pss_kib"] for p in processes), "processes": processes,
            "memory_events": dict(line.split() for line in (path / "memory.events").read_text().splitlines())}


def main():
    service = "vprouter@max-vprouter.service"
    paths = {"host_guard": group_for(int(command("systemctl", "show", service, "--property=MainPID", "--value")))}
    for name in ("max-vprouter", "max-vprouter-uplink"):
        pid = int(command("docker", "inspect", "--format", "{{.State.Pid}}", name))
        if pid <= 0:
            raise RuntimeError("container is not running")
        paths[name] = group_for(pid)
    start_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    samples = []
    start = time.monotonic()
    for index in range(21):
        if index:
            time.sleep(max(0, start + index - time.monotonic()))
        samples.append({"elapsed_seconds": time.monotonic() - start,
                        "groups": {name: read_group(path) for name, path in paths.items()}})
    elapsed = samples[-1]["elapsed_seconds"] - samples[0]["elapsed_seconds"]
    summary = {}
    for name in paths:
        rows = [s["groups"][name] for s in samples]
        summary[name] = {"cpu_percent_one_core": 100 * (rows[-1]["cpu_usage_usec"] - rows[0]["cpu_usage_usec"]) / (elapsed * 1e6),
                         "mean_pss_kib": statistics.mean(r["pss_kib"] for r in rows),
                         "max_pss_kib": max(r["pss_kib"] for r in rows),
                         "mean_memory_current_bytes": statistics.mean(r["memory_current_bytes"] for r in rows),
                         "first_memory_events": rows[0]["memory_events"],
                         "last_memory_events": rows[-1]["memory_events"]}
    print(json.dumps({"kind": "observed_short_sample", "start_utc": start_utc,
                      "elapsed_seconds": elapsed, "sample_count": len(samples),
                      "workload": "existing uncontrolled live traffic; no generated workload",
                      "acceptance": "NOT_RUN: repeated ten-minute same-workload one/five/six-exit runs",
                      "excluded": ["Docker daemon/containerd/shared shims", "kernel slab/shared system overhead", "external clients and WAN throughput/latency"],
                      "limitations": ["PSS snapshots may miss transient processes; cgroup CPU includes them", "observer overhead excluded; no causal efficiency claim"],
                      "cgroups": {name: str(path) for name, path in paths.items()},
                      "summary": summary, "samples": samples}, indent=2))


if __name__ == "__main__":
    main()
