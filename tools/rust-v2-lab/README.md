# Rust v2 local lab controller source archive

This byte-for-byte archive saves the controller and evidence-validation programs
that were developed under ignored `target/` paths. The source manifest records
all 289 original relative paths, sizes and SHA256 hashes. Private keys, profiles,
VM disks, image contexts, raw traces, captures and identity state are excluded.

These are development/test implementations, including historical variants.
Many expect their original `target/` working-directory layout, local ephemeral
VM ports and protected Root-owned lab markers. Do not execute this archive as
an installer or production runtime. Only the root controller may authorize
privileged local VM tests after verifying the exact frozen source and artifacts.

The checkpoint preserves progress; archived scripts are not an approval of
all test procedures or evidence. Source and runtime acceptance remain separate.
