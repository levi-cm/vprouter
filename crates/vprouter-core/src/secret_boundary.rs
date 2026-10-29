//! Supplemental process-wide ingress fence. This never grants permission to
//! read a secret or proves memory erasure. Fixed secret roles additionally deny
//! fork/exec in the kernel BEFORE ingress; ordinary parents never read secrets.
use std::sync::atomic::{AtomicBool, Ordering};

static EVER_INGRESSED: AtomicBool = AtomicBool::new(false);

/// Mark BEFORE attempting a protected read/raw secret receive, and at parser
/// entry for supplied bytes. Invalid inputs and errors permanently taint too.
/// No PID reset: a fork copy inherits true. There is deliberately no reset API.
pub fn mark_ingress() {
    EVER_INGRESSED.store(true, Ordering::SeqCst);
}

/// A fork-capable boundary must also establish single-threaded execution; this
/// atomic alone cannot close a concurrent read-versus-fork race.
pub fn pristine() -> bool {
    !EVER_INGRESSED.load(Ordering::SeqCst)
}
