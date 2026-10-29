# Bootstrap398 exact selector preservation review

2026-10-29. Read-only review of Root's proposed controller-only archival step.
No VM/SSH/Docker/privilege or credential action, source/Git mutation, profile
content read, archive execution, or subagent work was performed. Only this
report was written.

**Verdict: PASS for Root to archive exactly the six run398 selectors in the
reviewed inspection reference, using the exact reviewed archiver and its live
refusal gates.** This permits only hard-linking those public selector files into
the same original protected synthetic-input directory and unlinking their fixed
selector names. It is not resource cleanup, ownership transfer, runtime reuse
approval, failure localization, or successful native Bootstrap acceptance.

## Exact reviewed inputs

| Input | SHA256 |
| --- | --- |
| target/inspect-secret-bootstrap-failure.py | 64537a9d291d7e4df754e7cd194ac3bd6375f61ed538da0b1d8023e0cd879411 |
| target/archive-secret-bootstrap-selectors.py | e36a8e8c122663d9adc36ab8827f2923bd01147601efd248823f9cff0c62b9c0 |
| target/lab-state/secret-bootstrap-failure-run-398.json | bee34a59788682f87ebded708ea6315d5260f5169651625d13733685355f9dd2 |
| target/lab-state/actual-program-run-398.json | 6fb3bacc8b02f913b8ae2e90f2d8d0ceb3801a7a217b09a88533de2e0f74e34a |

Both new script diffs against their HOST counterparts change only the accepted
mode tuple to the exact seven Bootstrap modes and the output/reference family
names. There is no additional resource enumeration, mutation, subprocess or
privilege authority. I compiled both outer Python ASTs and their embedded guest
program strings without executing either program. All syntax checks pass.

The inspection/archival mode set is exactly success, postbirth-failure,
result-failure, registration-failure, handoff-fence, handoff-partial and
handoff-duplicate under `secret_bootstrap_`. Run398 is secret_bootstrap_success
with exit1. It remains an unexpected failed invocation with no completed
Bootstrap case/witness, not an accepted injected failure case.

## Independent binding and preservation checks

I independently checked the local inspection against the original raw record,
candidate and captured controller directory binding under
`target/continuation-20261029T122356Z/bootstrap-success-20261029/`:

- Record path/hash, complete b51 source binding, source archive digest, amd64
  artifact digest, platform and captured runner/guest/context/WAN-builder hashes
  agree exactly. This remains old frozen
  b51b5d7dd7a127d88a6e770f0b8780951190805b execution, separate from later slice8c.1.
- Inspection nonce equals the original input manifest, descriptor and owner
  probe. Expected owner unit equals the original descriptor/probe, not a
  rediscovered or prefix-selected owner.
- Inspection reports LoadState=not-found, ActiveState=inactive, SubState=dead,
  MainPID=0, empty ControlGroup/InvocationID and no exact owner cgroup. The
  archiver rechecks LoadState and exact cgroup absence immediately before work.
- Original gateway Docker inspection succeeded and reports running=true,
  paused=false with the original PID and StartedAt. Its original manifest is
  inert, mounts=[], provider_state_mounted=false. The archiver freshly pins the
  exact original PID, verifies it has not exited, checks original process start
  time and source network namespace, and rechecks pidfd liveness before moving
  selectors. It neither stops nor recreates the gateway.
- Both synthetic profile metadata records exactly match their original path,
  device, inode, size, uid/gid0 and mode0600, with link count1. This was checked
  from metadata only; private profile contents were never read by the inspector
  or this audit. The profile files are not archive sources.
- The original canonical root remains present with allocations.json and
  namespaces.json. Canonical allocation equals the original descriptor's
  allocation; namespace record allocation and owner epoch retain the original
  owner unit. Neither canonical file is an archive source.

The inspection reference has **exactly these six selector keys**, in this order:

```text
owner-domain-nonce
secret-attachment.json
secret-attachment-spec.json
secret-attachment-staging.json
secret-quarantine-host.json
secret-host-baseline.json
```

Their hashes independently match, respectively, original nonce bytes,
input-manifest configuration digest, original gateway spec digest, original
gateway staging digest, original WAN declaration digest and original authored
baseline declaration digest. WAN/baseline public content equals the exact
recorded declaration; spec container/process start and staging agree with the
original gateway/descriptor. All recorded selector device/inode/size fields are
positive and bounded. The successful inspector's `read` gate requires root-owned
mode0600 single-link regular files and supplies their measured identities/hashes.

Admission markers task8b2-image and task8b2-host-acceptance are not among these
six reference keys. The generic archiver's whitelist also recognizes those two
historical marker names, but this approval is restricted to the exact six-key
reference hash above. Do not expand the dictionary or substitute a different
reference without review.

## Exact allowed action and runtime refusal gates

For each of the six source files directly under `/var/lib/vprouter-v2-lab`, the
destination is `398-failed-<original-name>` in the **same original**
`secret-inputs-<original-nonce>` directory. The reviewed code requires that
destination directory to be a real root:root directory, mode0700. Each source
must still be a root:root mode0600 single-link regular file with the exact
inspected device/inode, size and SHA256. Each destination must be absent;
`os.link(...,follow_symlinks=False)` cannot overwrite an existing destination.

The code hard-links the exact source inode, unlinks only its fixed selector
name, then fsyncs the fixture root and input directory. The file contents and
inode remain retained. No profile, canonical allocation/namespace file, mount,
network endpoint, namespace, container, image or original gateway state is
removed. There is no kill/signal, unmount, network mutation or Docker/systemd
mutation in this action. Only read-only systemctl/Docker/proc checks precede
the six file-name moves. Existing failed stdout/stderr, native resources and
failure record remain preserved.

The loop is sequential, not an atomic six-file transaction. If any check, link,
unlink, fsync, SSH transport or sidecar write fails, stop and inspect the exact
partial state. An interruption can leave an archived prefix, or both links to
one original inode. Do not blindly rerun or delete either copy to force the
script through. This does not block the bounded preservation action because
each operation retains original bytes/inode and refuses replacement; it limits
what a completion claim can say. Root should retain the script output and new
exclusive `secret-bootstrap-selector-archive-run-398.json` result before
claiming all six selectors were archived.

## Scope of approval

The inspection is a Root-collected point-in-time observation, independently
bound and reviewed here. This auditor did not refresh live VM state. Approval
therefore depends on the exact reviewed archiver's own fresh owner/gateway/file
checks still passing; none may be bypassed after drift or collision. A changed
reference/script requires a narrow refresh of this review.

This step frees the six fixed selector names while retaining the complete failed
fixture and private synthetic inputs. It does not repair ownership_mismatch,
authorize an identical-payload retry, adopt a live full-HOST baseline, grant
member/removal ownership, qualify native Bootstrap, or accept the new receipt
runtime. Full8c/native/client/release gates remain open. Root alone executes and
records the permitted archival step.

## Root execution addendum

The exact reviewed archiver completed successfully after its fresh checks, with
six selectors archived, all fixture resources retained, no profile-content
reads and no signals/unmounts. Original exclusive result hash SHA256
`0bb7848181289585b9a1f05f031442c2c83b3aaa284d40f4ecb9e9d308fb1fdb`. This is preservation only;
run398 remains failed/unaccepted.
