# Task8c.1 — actual enforced-policy receipts and failure ordering

Parent requirements: task-8c-brief.md and docs/rust-v2/IMPLEMENTATION.md.
Base b678e7bf98e0c311109ce82a3893b40127ef0825 on rust/v2. This is a bounded
slice of active8c, never full operational/client acceptance or task9 authority.

The authenticated operational protocol must distinguish observed health from
actually read-back Offline/Bootstrap/Ready policy. Prepare and Commit replies
carry the complete existing Binding and policy stage; retain existing framed
sequence/nonce/peer/exit/generation/boot/config identity validation and deadlines.
Old health-only acknowledgements, wrong stages and wrong binding must refuse.
Prepare receipt must prove Offline before advertisement withdrawal on failure.
Failure Blocked(reason/no evidence),Stopping,Failed commits remain full Offline.
Healthy Starting/Blocked/Recovering verification may retain producer-only Bootstrap;
Ready still requires the existing private native enforcement proof. PolicyReceipt
is observational wire data, never a constructor for placement/native/Ready authority.

Operational worker returns the original sample failure only after a successful
bounded guard-first withdrawal/commit/publication transaction; an ACK/protocol
failure takes precedence. It must not continue provider checks behind full
quarantine. Independent observation admits only valid evidence-free terminal
Stopping/Failed snapshots, latches terminal state and refuses revival. Preserve
three-success recovery, exact server and bounded transient retry; heartbeat
receipt cannot refresh last complete provider/structure/identity evidence age.
Actual restart/withdrawal/rebootstrap recovery remains8c.2 under new retained
native authority, not an implicit caller-boolean exception in this slice.

Focused tests must use actual framed UnixStreams for wrong/missing stage,
binding/generation and wrong commit health; assert guard-first withdrawal/error
precedence, terminal no-revival and healthy/failure policy distinctions. Preserve
production, secrets/identities/resources/failed evidence, no remote tests or
privileged implementer execution. Root owns VM, Git and coherent artifact builds.
Implementer owns only worker operation.rs/engine.rs/engine/tests.rs and launch
handoff.rs/transport.rs/expiry.rs. Report task-8c-report.md. Independent scoped
spec+quality review and Root checks precede milestone push. Full8c stays ACTIVE.
