# Rust v2 local lab controller source archive

This byte-for-byte archive saves the controller and evidence-validation programs
that were developed under ignored `target/` paths. The source manifest records
all 293 original relative paths, sizes and SHA256 hashes. Private keys, profiles,
VM disks, image contexts, raw traces, captures and identity state are excluded.

These are development/test implementations, including historical variants.
Many expect their original `target/` working-directory layout, local ephemeral
VM ports and protected Root-owned lab markers. Do not execute this archive as
an installer or production runtime. Only the root controller may authorize
privileged local VM tests after verifying the exact frozen source and artifacts.

The checkpoint preserves progress; archived scripts are not an approval of
all test procedures or evidence. Source and runtime acceptance remain separate.

`parse-bootstrap-cost-diagnostics.py` is a separate maintained, read-only reader
for failed `secret_bootstrap_success` records with the fixed Deadline diagnostic.
It validates closed boundary fields, all13 wrapper rows, all30 nested rows,
the optional exact24 retained-cost rows and optional exact15 owner-cost rows,
then exclusively creates bounded metadata at its second argument. Nested rows
overlap and are never summed. It does not contact a VM or grant state authority.
This reader is outside the293-file historical archive manifest.

`allocation-comparison-cost.rs` preserves the separate offline pure-comparison
experiment harness. It reads two allocation JSON fixtures supplied as arguments;
private fixture values and binaries are excluded. Its host compiler/dependency
bindings and results are recorded in the allocation-comparison cost report.
This experiment does not measure native VM cost share or release performance.

`digest-hex-cost.rs` preserves the separate actual-library digest experiment.
It uses only synthetic public byte fixtures, with no arguments, files or network.
Compile it in an isolated target-only Cargo project with path dependencies on
`vprouter-worker` and `vprouter-core`, sha2=0.11.1 and serde_json=1.0.150. The
original experiment binds frozen source17c914f4 and its repository lock; a later
changed library is a different oracle and cannot reproduce the original result.
The experiment report records the exact manifest/lock/profile, seven fixed
alternating batches, all samples and limits. Host timings do not establish native
VM savings, Bootstrap acceptance or release performance. This harness is outside
the293-file historical archive manifest.
