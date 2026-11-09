# Leak lab combined adversarial re-review, round 2 (GPT)

Target: `545fb95ad448ca86d5b7514e01f48fc4cbf0ae79`. Initial worktree clean. Review in progress; this report is updated incrementally.

Scope: monitor and VM runner, including rootfs/hostsetup, both docs and prior three combined reports. Offline/source/component evidence only. No privileged tools, network operations, prohibited config/state/archive/key reads, or real VMs. Generated host shell may run only with privileged commands stubbed and scratch cwd. Scratch `/var/tmp/leaklab-crr-gpt` will be deleted. Only this repository file may change.

## Validation and prior Important closure

Pending.

## Findings

Pending.

### Fresh suite results

With `TMPDIR=/var/tmp/leaklab-crr-gpt`, `PYTHONDONTWRITEBYTECODE=1`, warnings treated as errors, and scratch cwd:

- Monitor: `python3 -B -W error -m unittest discover -s /DATA/AppData/vprouter-rust-v2/tools/leak-lab -p test_leak_lab.py`: **246 tests, OK**, 7.427 s.
- VM: `python3 -B -W error -m unittest discover -s /DATA/AppData/vprouter-rust-v2/tools/leak-lab/vm -p test_vm.py`: **133 tests, OK**, 3.772 s.

These are offline component results, not runtime acceptance. Independent cross-component probes follow; the VM suite currently substitutes its own scanner hashes rather than invoking the real scanner.

### I1 — Important: real scanner/runner argv-hash contracts disagree, so clean phases cannot PASS

Locations: `tools/leak-lab/vm/rootfs.py:215`, `tools/leak-lab/vm/run_phase.py:2030`, `:2383`, `:2446`; `tools/leak-lab/pcapscan.py:1447`; fake scanner `tools/leak-lab/vm/test_vm.py:1945`.

`EvidenceDirectory.write_json` writes indented JSON with a trailing newline. The controller hashes those exact file bytes. The real scanner's `capture_argv_sha256` hashes compact canonical JSON without a newline. The controller compares these different values and adds `scan_report_mismatch` on every otherwise clean scan. The passing VM tests instead calculate raw-byte hashes in their fake scanner, so they miss the real contract.

Independent reproducer: write policy/4-record clean pcap/4-4-0 stats and argv with the real `rootfs.write_json_at`, pass the retained directory fd to the actual `pcapscan.py` CLI using its real `/proc/self/fd/N/...` paths. Scanner exits **0/PASS**, invalid reasons `[]`, but argv file SHA-256 is `66d7097515baa3431e1c35f9edae8ea20f106a4de9156aca40edd74c02f407ca`, while the scanner declares `0084942c18bff44b362c141c3383e81463ede7873d45406c6cbbb567278e92cf` (fd number affects these sample hashes). Equality is false. Thus descriptor inheritance itself works; the hash definition fails.

Required: agree on exact-byte versus semantic hashing, retain exact-byte evidence hashes separately if needed, and run the real scanner in an integration regression. This is fail-closed availability failure, not a demonstrated hidden leak.

### I2 — Important: hostsetup creates the state directory that provisioning unconditionally refuses

Locations: `tools/leak-lab/vm/hostsetup.py:433`, `tools/leak-lab/vm/provision.py:269`, `:316`; `docs/rust-v2/leak-lab-vm.md:66`, `:128`.

The new documented host setup creates `/var/lib/vprlab/vm-001` (0700, QEMU-owned). The next documented provisioning command refuses any existing state directory, even an empty directory made by that setup. Its locked implementation also requires exclusive creation. The default setup → provision sequence therefore cannot proceed.

Independent reproducer in scratch: create empty `vm-001` exactly as the plan does, call real `provision.provision(Namespace(index=1,state_root=<scratch>))` with only root admission stubbed. It immediately raises **`state directory already exists: .../vm-001`**, before acquiring admission or invoking any tool.

Required: setup should create only the trusted parent; let provision exclusively create and hand over each VM directory. Adjust the inventory check/docs to the pre-/post-provision lifecycle. Do not silently reuse an existing guest state.

### I3 — Important: hostsetup silently drops required symlinks from the tool/library/firmware tree

Location: `tools/leak-lab/vm/hostsetup.py:284` (`find . -type f`), `:443`; tool definitions `tools/leak-lab/vm/guest.py:34`.

`copy_tools` copies only regular files and generates a manifest containing only that subset. Debian shared-library SONAME entries and firmware aliases are normally symlinks. They disappear, while verification still reports success. Metadata-only inspection of the allowed non-secret staged tools confirms `libpixman-1.so.0 -> libpixman-1.so.0.44.0`, `libslirp.so.0 -> libslirp.so.0.4.0`, `liburing.so.2 -> liburing.so.2.9`, `libglib-2.0.so.0 -> libglib-2.0.so.0.8400.4`, and `libgobject-2.0.so.0 -> libgobject-2.0.so.0.8400.4`. `readelf -d` on the staged QEMU binary names those SONAMEs as DT_NEEDED. No staged executable was run.

Required: validate and faithfully copy the complete required tree, including confined symlinks (or safely materialize their contents); verify links and targets as well as regular files. Missing links can either prevent startup or silently load host fallback libraries, defeating the promised staged-tree fidelity. A pure scratch-copy reproducer is recorded below.
