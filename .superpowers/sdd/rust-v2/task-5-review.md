# Task5 independent review, first pass

Reviewer /root/review_network, read-only diff48293d5..0631fb0.
Spec FAIL; quality Needs fixes. No Critical.

Important: native.rs82-85,560-578 VethPair public members permit recombining
legitimate same-plan tokens from independent H1/T1 and H2/T2 namespace pairs.
With local ifindices2/2, H1/T2 cleanup accepts reciprocal numeric indices and
deletes actual T1 peer before its T2 postcheck detects mismatch. No hostile
concurrent root needed. Require private pair members/borrowed getters and minted
namespace pairing; compile-fail recombination and collision refusal-before-delete.

Minor: socket.rs231-236,309-316 Completion::Single accepts NLM_F_MULTI data+ACK
without DONE. Require rejecting multipart under single-message family contract;
focused framing regression.

Strengths: exclusive DOWN-only operations; bounded native protocols; borrowed
secret access, scrubbed buffers and fixed errors; strict route/rule/source/age
auditing. Unknown runtime/traffic/real Tailscale/namespace authorization/UDP birth
and provider acceptance remain later gates, already documented as NOT_RUN.

Original implementer resumed for fix round1; both findings sent verbatim with
focused covering tests. No source mutation/tests performed by reviewer.

## Fix1 independent re-review

Reviewer /root/review_network scoped0631fb0..d63050e: both findings ADDRESSED, spec PASS, quality Approved for bounded component; no new Critical/Important/Minor. Native.rs92-100 private endpoints/borrowed getters,581-587 namespace-pair+Plan admission before I/O;85-89 compilefail,660-684 collision ordering regression. Socket.rs319-322 rejects Single multipart,399-433 ACK-order/normal/dump regressions. No source mutations/outside checks/test reruns. Runtime/traffic/namespace authorization limits unchanged.
