# Preserve and localize the first Bootstrap query error

Workdir /DATA/AppData/vprouter-rust-v2, rust/v2. Prior frozen source73a352604303796adbe60e4752b27ec6d60ff9de,
owned local native399FAIL/zero cases/88journalpairs. All earlier diagnosticgroups
complete. Canonical HOST queryIntent present, birth/facts/verification absent;
this does not prove post-ACK Intent verification returned or queryspawn began.
Lab failure handler demonstrably replaces any original pre-policy failure with
Interrupted because n.request is absent. Original398 failure remainsunexplained.

After Root sends checkpoint confirmation, implement ONLY operational/bootstrap.rs:
- cfg(test) fixed begin/ok phase diagnostics around post-ACK QueryIntent success,
  existing docker_query::spawn and existing start_inspection_birth chain.
- lab_run Err branch records fixed Step name, original Error class and only
  request_present/query_child_present booleans before looking up policyrequest.
  When policyrequest is absent, return the original Err(error). Keep request-present
  injected-fault handling unchanged. No arbitrary IDs, descriptors, paths, profile,
  credentials, argv/env, clocks or per-pending-poll log spam.
No production semanticfix, changed ownership/fence/retry/deadline/custody/retention,
extra validation/access calls or new authority. Preserve every existing error.
No subagents, Git/buildmanifest/context/staticbuild/VM/SSH/Docker/profile/identity
operations. Root owns builds and localnative execution. Minimal direct formatting/
diff checks only; no mirrored logger tests. Report exacthash and diagnosticcontract
at task-8c-bootstrap-query-diagnostic-report.md then freeze for scopedreview.
Full8c remainsACTIVE; neither diagnostics nor raw runs qualify nativeBootstrap.
