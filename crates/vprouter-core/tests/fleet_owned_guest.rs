//! Acceptance specifications only. No native multi-exit harness is admitted
//! while Task8c I9/I10/M2/runtime/ARM/client gates remain open. These deliberately
//! fail if forced: an empty ignored test must never yield fabricated evidence.

#[test]
#[ignore = "NOT_RUN: controller-owned guest required; Task8c acceptance OPEN; harness unavailable"]
fn owned_guest_one_exit_no_absent_allocations() {
    // One gateway/host guard; one synthetic WG exit, distinct packet markers;
    // independent positive capture controls and zero drops at every capture.
    // Assert no absent worker/ns/timer/state and preserve primary base netns.
    panic!("NOT_RUN: no admitted Task9 owned-guest harness; see task-9-report.md");
}
#[test]
#[ignore = "NOT_RUN: controller-owned guest required; Task8c acceptance OPEN; harness unavailable"]
fn owned_guest_five_exits_shared_endpoint_overlapping_inner_ips() {
    // Five distinct synthetic device keys, same UDP endpoint and same inner /32;
    // continuous per-exit markers, independent positive controls, zero cross-exit
    // or plaintext markers, zero capture drops, exact healthy-exit invariance.
    panic!("NOT_RUN: no admitted Task9 owned-guest harness; see task-9-report.md");
}
#[test]
#[ignore = "NOT_RUN: controller-owned adversarial proc/state/socket/FD harness unavailable"]
fn owned_guest_every_exit_private_proc_state_root_socket_and_namespace_fds() {
    // Every ordered pair: reject inspection/open of peer state, proc/root,
    // socket and namespace FDs, both during launch and after exec; distinct
    // positive own-state/socket/proc controls. No real enrolled state.
    panic!("NOT_RUN: no admitted Task9 adversarial harness; see task-9-report.md");
}
#[test]
#[ignore = "NOT_RUN: controller-owned kill/freeze/drift/Docker fault harness unavailable"]
fn owned_guest_faults_quarantine_only_owned_scope_and_retain_ambiguity() {
    // Crash/freeze/restart one worker; stale/wrong handshake/server; mutate
    // interface/route/rule/nft; kill gateway; fail Docker/API. Preserve healthy
    // scopes, exact foreign sentinel, identity state and ambiguous quarantine.
    // Interrupt each configuration/native transaction boundary; no prefix
    // cleanup/adoption. Verify packet captures before/through/after each fault.
    panic!("NOT_RUN: no admitted Task9 fault/cleanup harness; see task-9-report.md");
}
