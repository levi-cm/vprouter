# Independent task7 review

Reviewer /root/review_native_worker; range7bf59fc..04ecfc6.
Spec compliance FAIL; Task quality Needs fixes. No Critical or Minor findings.

## Strengths
Production refuses before runtime creation; placement test-only; fixed provider,
TLS verification, namespace binding, bounded strict parsing and redaction; retry
rechecks before/after delay and after success; real controlled TLS/Unix tests;
functional rule attributes retained without authorizing arbitrary layout.

## Important1 — Real transient transport failures misclassified

crates/vprouter-worker/src/client.rs:119 classifies Hyper I/O/body errors as
Malformed unless incomplete-message/channel/cancellation. Genuine connection
resets can skip retry. provider.rs:129 maps every TLS handshake error to permanent
Tls, including underlying transport failures. Engine retries only HttpTransient,
Transport, Deadline (engine.rs:207). Preserve bounded underlying I/O classification:
eligible transient failures get one retry; certificate/hostname, malformed protocol
and permanent failures remain nonretryable. Controlled transport regressions for
reset/EOF during TLS negotiation and established HTTP I/O, checking request counts
and fresh structural rechecks; retain certificate-refusal no-retry tests.

## Important2 — Expiry after lifecycle decision / missing enforcement

engine.rs:167 advertises based on cached Recovering before HealthMachine::observe
expiry at180. Three successes then pause>=45s then one healthy sample can advertise
using expired streak. READY expiry can enter Blocked then accept fresh sample and
return Ok(Blocked); Engine discards returned state. Runner takes success branch
at350, heartbeats and publishes BLOCKED without guard block or withdrawal. Apply
freshness invalidation before lifecycle writes; revoked readiness must invoke
fail-closed enforcement. Paused-clock regressions for RECOVERING and READY then
>=45s gap: no premature advertisement; guard notification and withdrawal when
readiness expires; renewed three-success gate before offering.

## Cannot verify / cross-task disposition
Actual placed worker/provider, actual prefs/approval transitions, independent guard
enforcement/watchdog, real client traffic and platform acceptance remain NOT_RUN.
Controller confirms these are explicit task8+ integration gates, not authority
to enable production. Parser evidence retains the narrower claim.

Reviewer read packaged diff in passes; focused outside-diff checks: HealthMachine
expiry, native observation deadline and pinned Hyper variants. No changed source
reopening, suite reruns, live/privileged/network actions or mutations.
