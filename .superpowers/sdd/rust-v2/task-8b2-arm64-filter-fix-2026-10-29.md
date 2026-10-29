# Task 8b2 ARM64 filter portability fix — 2026-10-29

The coherent static builder failed on ARM64 with E0425 at `crates/vprouter-native-role/src/filter.rs:146`: `libc::SYS_fstatat` does not exist in the pinned libc 0.2.189. Its aarch64 GNU and musl architecture modules instead export `SYS_newfstatat: c_long = 79`; x86_64 exports `SYS_newfstatat = 262`.

Changed only the source file `crates/vprouter-native-role/src/filter.rs`: the bootstrap ancestry policy and its existing focused test now use `libc::SYS_newfstatat` on both supported architectures. The old ARM-only identifier was removed. The syscall ABI and argument positions are unchanged: the fixed directory FD, exact name pointer, and `AT_SYMLINK_NOFOLLOW` remain required, including both halves of every constrained argument. No syscall or argument authority was added. The x86_64 filter instruction shape and numeric syscall selection are unchanged.

Validation executed from `/DATA/AppData/vprouter-rust-v2`:

- `cargo test --locked -p vprouter-native-role` — PASS, 12 tests, including `bootstrap_ancestry_is_exact_read_only_and_does_not_expand_old_role`; 0 doc tests.
- `cargo fmt --all -- --check` — PASS.
- `cargo check --locked -p vprouter-native-role --target aarch64-unknown-linux-musl --tests` — PASS; checks production code and the formerly broken ARM-specific test path. No custom CC/link environment was needed for this check.

No manifests, builder scripts, other source files, HEAD, or index were changed by this task. No commit, VM, privileged action, or production operation was performed. Full coherent static rebuild and ARM runtime verification remain Root-owned; this check is not runtime or release acceptance.
