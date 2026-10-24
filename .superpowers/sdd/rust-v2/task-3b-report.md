# Task 3b — legacy WireGuard option casing

Implementation commit: 32e9e5f0614f46faa2769742fbb4ab01ec5ed683
Base: ab6a5973a412e5d3a0edc6bf503369490c8a5430
Status: focused and covering offline verification PASS; independent review pending.

Known profile options now match ASCII case insensitively, preserving compatibility
with legacy ConfigParser output. Keys are normalized before duplicate detection;
all eight known options reject case-varied duplicates. Section names, values,
server hints, endpoint restrictions and unknown/command option rejection remain
strict. No profile data or original profile paths are rewritten.

Added two synthetic regression tests. One parses lowercase legacy options through
validated configuration while checking the generic original profile path is
passed to the reader and retained, plus public endpoint/address/server fields.
The second covers mixed casing of every known option, case-varied duplicates for
all eight options, and refusal of lowercase section names, command/Unicode unknown
options, wrong server hints and nonpublic endpoints. Existing Linux migration
path/identity preservation test also passed. No real profile or key was read.

Fresh commands in /DATA/AppData/vprouter-rust-v2 with Rust1.97.0:

- cargo test --locked --offline -p vprouter-core: PASS; 38 runtime tests and
  1 existing compile-fail doctest, zero failures.
- cargo fmt --all -- --check: PASS, exit0.
- cargo test --locked --offline --all-targets: PASS; 58 runtime tests
  (38 core, 16 Linux, 4 CLI), zero failures.
- cargo clippy --locked --offline --all-targets -- -D warnings: PASS, exit0.
- git diff --check and git diff --cached --check: PASS, exit0.

The first focused test invocation encountered lockfile refusal because task4's
uncommitted workspace-member addition was present. That manifest was saved to
/tmp/vprouter-task4-Cargo.toml and the committed manifest restored before all
reported passing checks. Task4 crate files remain preserved and untracked;
task4 work is paused pending controller's review. No task4 file or root's
lab-image.json evidence change was staged in the implementation commit.

No actual protected legacy migration plan or release binary was run/rebuilt by
this agent. Controller owns fresh live read-only validation after independent
review. No production, kernel, namespace, service, allocation or identity changes.
The native CLI continues guard_runtime:false; all task4 and runtime acceptance
gates remain unperformed by this patch.
