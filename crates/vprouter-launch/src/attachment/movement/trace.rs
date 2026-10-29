//! Lab-only bounded parent timing. Spans are inclusive and may nest; neither
//! their sum nor elapsed time attributes CPU cost. No native state is reread.
//! Each scope emits before its own cancellation. Unwinding may emit inner and
//! outer snapshots after a deeper scope has cancelled/collected; only the first
//! deepest record precedes that scope's cancellation, not every cancellation.
use std::cell::RefCell;
const LIMIT: usize = 32;
#[derive(serde::Serialize)]
struct Row {
    scope: &'static str,
    phase: &'static str,
    calls: u32,
    failed_calls: u32,
    first_at: f64,
    last_at: f64,
    total_seconds: f64,
    max_seconds: f64,
}
struct State {
    creator: u32,
    request: [u8; 32],
    start: f64,
    end: f64,
    rows: Vec<Row>,
    omitted: u32,
}
thread_local! {static STATE:RefCell<Option<State>>=const{RefCell::new(None)};}
pub(super) fn arm(request: [u8; 32], start: f64, end: f64) {
    STATE.with(|slot| {
        *slot.borrow_mut() = Some(State {
            creator: std::process::id(),
            request,
            start,
            end,
            rows: Vec::with_capacity(LIMIT),
            omitted: 0,
        })
    });
}
pub(crate) fn active() -> bool {
    STATE.with(|s| {
        s.borrow()
            .as_ref()
            .is_some_and(|v| v.creator == std::process::id())
    })
}
pub(crate) struct Span {
    creator: u32,
    scope: &'static str,
    phase: &'static str,
    start: Option<f64>,
    ok: bool,
}
impl Span {
    pub(crate) fn new(scope: &'static str, phase: &'static str) -> Self {
        let creator = std::process::id();
        let active = STATE.with(|s| s.borrow().as_ref().is_some_and(|v| v.creator == creator));
        Self {
            creator,
            scope,
            phase,
            start: active.then(vprouter_core::health::boot_seconds),
            ok: false,
        }
    }
    pub(crate) fn finish(mut self) {
        self.ok = true;
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        let Some(start) = self.start else {
            return;
        };
        let end = vprouter_core::health::boot_seconds();
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            let Some(s) = s.as_mut().filter(|s| s.creator == self.creator) else {
                return;
            };
            if let Some(r) = s
                .rows
                .iter_mut()
                .find(|r| r.scope == self.scope && r.phase == self.phase)
            {
                r.calls = r.calls.saturating_add(1);
                r.failed_calls = r.failed_calls.saturating_add(u32::from(!self.ok));
                r.last_at = end;
                r.total_seconds += end - start;
                r.max_seconds = r.max_seconds.max(end - start);
            } else if s.rows.len() < LIMIT {
                s.rows.push(Row {
                    scope: self.scope,
                    phase: self.phase,
                    calls: 1,
                    failed_calls: u32::from(!self.ok),
                    first_at: start,
                    last_at: end,
                    total_seconds: end - start,
                    max_seconds: end - start,
                });
            } else {
                s.omitted = s.omitted.saturating_add(1);
            }
        });
    }
}
pub(crate) fn emit(scope: &'static str, error: super::Error, cached: serde_json::Value) {
    STATE.with(|slot| {
        let s = slot.borrow();
        let Some(s) = s.as_ref().filter(|s|s.creator == std::process::id()) else { return; };
        eprintln!("LAB_MOVEMENT_PROGRESS {}", serde_json::json!({"schema":1,"scope":scope,
            "reason":format!("{error:?}"),"request":s.request,"requested_at":s.start,"deadline":s.end,
            "observed_at":vprouter_core::health::boot_seconds(),"cached":cached,
            "spans":s.rows,"omitted":s.omitted,"inclusive_spans_not_additive":true,"native_reads":false}));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_aggregation_and_foreign_creator_are_inert() {
        STATE.with(|s| *s.borrow_mut() = None);
        Span::new("outer", "entry").finish();
        STATE.with(|s| assert!(s.borrow().is_none()));
        let start = vprouter_core::health::boot_seconds();
        arm([7; 32], start, start + 2.);
        for _ in 0..100 {
            Span::new("outer", "entry").finish();
        }
        drop(Span::new("outer", "entry"));
        STATE.with(|s| {
            let s = s.borrow();
            let s = s.as_ref().unwrap();
            assert_eq!(s.rows.len(), 1);
            assert_eq!(s.rows[0].calls, 101);
            assert_eq!(s.rows[0].failed_calls, 1);
            assert!(s.rows[0].first_at >= start && s.rows[0].last_at >= s.rows[0].first_at);
            assert!(s.rows[0].total_seconds >= s.rows[0].max_seconds);
        });
        // Construct distinct fixed labels without allocating any leaked strings.
        const LABELS: [&str; 33] = [
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
            "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31", "32",
        ];
        for label in LABELS {
            Span::new("test", label).finish();
        }
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            let s = s.as_mut().unwrap();
            assert_eq!(s.rows.len(), LIMIT);
            assert_eq!(s.omitted, 2);
            s.creator = std::process::id().wrapping_add(1);
        });
        Span::new("foreign", "ignored").finish();
        STATE.with(|s| {
            let s = s.borrow();
            let s = s.as_ref().unwrap();
            assert_eq!(s.rows.len(), LIMIT);
            assert_eq!(s.omitted, 2);
        });
        STATE.with(|s| *s.borrow_mut() = None);
    }
}
