# Independent task7 fix1 re-review

Reviewer /root/review_native_worker; fix range04ecfc6..0522fa1.
Spec PASS within task7 component; quality Approved; no new breakage.

- Important1 ADDRESSED: client.rs119 bounded typed causes;136 certificate/protocol,
  nonallowlisted I/O and overlong chains permanent; provider.rs129 same TLS mapping.
  Actual EOF/reset negotiation/headers/partialbody one-retry/count/recheck cases
  engine/tests.rs388 and permanent realcert cases461.
- Important2 ADDRESSED: core state.rs142 explicit expiry; engine.rs142/163/182
  checks before sampling/offering/evidence replacement; revocation fail-closed and
  defensive READY transition206. Tests494/522 exact45/longer/mid-provider gaps,
  renewed three-success recovery, actualUnixguard block before withdrawal without
  successheartbeat.
- Newbreakage none. Core expiry extraction preserves prior observe semantics.
  Controller parser driver now propagates harness failure after evidence20.
- Outofscope none new. Actual placement/provider/preferences/approval/guard/client
  acceptance remain separate explicit NOT_RUN gates.

Reviewed packaged fix diff in passes and checked appended redgreen/71test evidence.
No suite rerun, mutations, live/privileged/network operations.
