//! Test-only inclusive elapsed costs. This module grants no verification authority.
use std::{cell::Cell, io::Write, marker::PhantomData, rc::Rc, time::Instant};

#[derive(Clone, Copy)]
pub(crate) enum Family {
    Query,
    Policy,
    Other,
}
const FAMILIES: [Family; 3] = [Family::Query, Family::Policy, Family::Other];
impl Family {
    fn label(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Policy => "policy",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Key {
    AllocationMemory,
    BindingServiceCustody,
    BindingRetained,
    OwnedProgress,
    TypedBootstrapProgress,
    OriginalProof,
    RecordEncode,
    ExpectedRecordEncode,
    RecordSha256,
    JournalAdvance,
}
const KEYS: [Key; 10] = [
    Key::AllocationMemory,
    Key::BindingServiceCustody,
    Key::BindingRetained,
    Key::OwnedProgress,
    Key::TypedBootstrapProgress,
    Key::OriginalProof,
    Key::RecordEncode,
    Key::ExpectedRecordEncode,
    Key::RecordSha256,
    Key::JournalAdvance,
];
impl Key {
    fn label(self) -> &'static str {
        match self {
            Self::AllocationMemory => "allocation_anchor_memory",
            Self::BindingServiceCustody => "binding_service_custody",
            Self::BindingRetained => "binding_retained",
            Self::OwnedProgress => "owned_progress",
            Self::TypedBootstrapProgress => "typed_bootstrap_progress",
            Self::OriginalProof => "original_proof",
            Self::RecordEncode => "record_json_encode",
            Self::ExpectedRecordEncode => "expected_record_json_encode",
            Self::RecordSha256 => "record_sha256",
            Self::JournalAdvance => "journal_advance",
        }
    }
}

#[derive(Clone, Copy)]
struct Total {
    calls: u64,
    elapsed_ns: u128,
}
const ZERO: Total = Total {
    calls: 0,
    elapsed_ns: 0,
};
const ROWS: usize = FAMILIES.len() * KEYS.len();

#[derive(Clone, Copy)]
struct Token {
    creator: u32,
    epoch: u64,
    family: Family,
}
#[derive(Clone, Copy)]
struct State {
    creator: u32,
    epoch: u64,
    active: bool,
    family: Family,
    totals: [Total; ROWS],
}
impl State {
    const fn inactive() -> Self {
        Self {
            creator: 0,
            epoch: 0,
            active: false,
            family: Family::Other,
            totals: [ZERO; ROWS],
        }
    }
    fn begin(&mut self, creator: u32, family: Family) -> Option<Token> {
        // Epoch exhaustion disables diagnostics rather than reusing an old timer token.
        self.active = false;
        let epoch = self.epoch.checked_add(1)?;
        self.creator = creator;
        self.epoch = epoch;
        self.family = family;
        self.totals = [ZERO; ROWS];
        self.active = true;
        self.token()
    }
    fn token(&self) -> Option<Token> {
        self.active.then_some(Token {
            creator: self.creator,
            epoch: self.epoch,
            family: self.family,
        })
    }
    fn accepts(&self, token: Token) -> bool {
        self.active && self.creator == token.creator && self.epoch == token.epoch
    }
    fn record(&mut self, token: Token, key: Key, elapsed_ns: u128) {
        if !self.accepts(token) {
            return;
        }
        let total = &mut self.totals[token.family as usize * KEYS.len() + key as usize];
        total.calls = total.calls.saturating_add(1);
        total.elapsed_ns = total.elapsed_ns.saturating_add(elapsed_ns);
    }
    fn stop_snapshot(&mut self, creator: u32) -> Option<Snapshot> {
        let permitted = self.active && self.creator == creator;
        self.active = false;
        permitted.then_some(Snapshot {
            totals: self.totals,
        })
    }
}
thread_local! {
    static STATE: Cell<State> = const { Cell::new(State::inactive()) };
}

pub(crate) struct Session {
    token: Option<Token>,
    _thread: PhantomData<Rc<()>>,
}
pub(crate) fn arm(family: Family) -> Session {
    // Only unrestricted lab boundaries observe the process ID, never record/hash timers.
    let creator = std::process::id();
    let token = STATE.with(|cell| {
        let mut state = cell.get();
        let token = state.begin(creator, family);
        cell.set(state);
        token
    });
    Session {
        token,
        _thread: PhantomData,
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Some(token) = self.token {
            let creator = std::process::id();
            STATE.with(|cell| {
                let mut state = cell.get();
                if state.accepts(token) {
                    let _ = state.stop_snapshot(creator);
                    cell.set(state);
                }
            });
        }
    }
}
pub(crate) fn set_family(family: Family) {
    STATE.with(|cell| {
        let mut state = cell.get();
        if state.active {
            state.family = family;
            cell.set(state);
        }
    });
}

pub(crate) struct Timer {
    entry: Option<(Token, Key, Instant)>,
    _thread: PhantomData<Rc<()>>,
}
impl Timer {
    pub(crate) fn new(key: Key) -> Self {
        // Forked children may touch only their COW-private copy. Do not add getpid
        // here: the journal publisher filter has no such syscall permission.
        let token = STATE.with(|cell| cell.get().token());
        Self {
            entry: token.map(|token| (token, key, Instant::now())),
            _thread: PhantomData,
        }
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        if let Some((token, key, started)) = self.entry {
            STATE.with(|cell| {
                let mut state = cell.get();
                if state.accepts(token) {
                    state.record(token, key, started.elapsed().as_nanos());
                    cell.set(state);
                }
            });
        }
    }
}

pub(crate) struct Snapshot {
    totals: [Total; ROWS],
}
pub(crate) fn stop_snapshot() -> Option<Snapshot> {
    let creator = std::process::id();
    STATE.with(|cell| {
        let mut state = cell.get();
        let snapshot = state.stop_snapshot(creator);
        cell.set(state);
        snapshot
    })
}
impl Snapshot {
    pub(crate) fn emit(self, output: &mut impl Write) {
        // Inclusive rows overlap, including expected encoding within record encoding.
        // A poll can transition: family means cached lab-loop-entry Step, not inner phase.
        for family in FAMILIES {
            for key in KEYS {
                let total = self.totals[family as usize * KEYS.len() + key as usize];
                let _ = writeln!(
                    output,
                    "LAB_SECRET_BOOTSTRAP_NESTED_TOTAL family={} category={} calls={} elapsed_ns={} measurement=inclusive_nested_elapsed grouping=lab_loop_entry_step_family",
                    family.label(),
                    key.label(),
                    total.calls,
                    total.elapsed_ns,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested_result(outcome: Result<(), ()>) -> Result<(), ()> {
        let _outer = Timer::new(Key::OwnedProgress);
        let _inner = Timer::new(Key::OriginalProof);
        outcome?;
        Ok(())
    }

    #[test]
    fn inactive_nested_early_return_and_stopped_timers_do_not_escape_session() {
        let _ = stop_snapshot();
        drop(Timer::new(Key::RecordEncode));
        assert!(stop_snapshot().is_none());
        let _session = arm(Family::Query);
        let outcome = nested_result(Err(()));
        assert_eq!(outcome, Err(()));
        let still_live = Timer::new(Key::RecordEncode);
        let snapshot = stop_snapshot().unwrap();
        drop(still_live);
        assert!(stop_snapshot().is_none());
        assert_eq!(snapshot.totals[Key::OwnedProgress as usize].calls, 1);
        assert_eq!(snapshot.totals[Key::OriginalProof as usize].calls, 1);
        assert_eq!(snapshot.totals[Key::RecordEncode as usize].calls, 0);
    }

    #[test]
    fn copied_foreign_creator_cannot_export_or_modify_parent_totals() {
        let mut parent = State::inactive();
        let token = parent.begin(7, Family::Query).unwrap();
        parent.record(token, Key::RecordSha256, 11);
        let mut child = parent;
        child.record(token, Key::RecordSha256, 99);
        assert!(child.stop_snapshot(8).is_none());
        assert!(!child.active);
        let snapshot = parent.stop_snapshot(7).unwrap();
        let total = snapshot.totals[Key::RecordSha256 as usize];
        assert_eq!(total.calls, 1);
        assert_eq!(total.elapsed_ns, 11);
    }

    #[test]
    fn family_is_captured_at_entry_and_totals_saturate_without_stale_epoch_reuse() {
        let mut state = State::inactive();
        let first = state.begin(7, Family::Query).unwrap();
        state.family = Family::Policy;
        state.totals[Key::RecordEncode as usize] = Total {
            calls: u64::MAX,
            elapsed_ns: u128::MAX - 1,
        };
        state.record(first, Key::RecordEncode, 5);
        assert_eq!(state.totals[Key::RecordEncode as usize].calls, u64::MAX);
        assert_eq!(
            state.totals[Key::RecordEncode as usize].elapsed_ns,
            u128::MAX
        );
        let second = state.begin(7, Family::Policy).unwrap();
        state.record(first, Key::RecordEncode, 5);
        state.record(second, Key::RecordEncode, 3);
        assert_eq!(state.totals[Key::RecordEncode as usize].calls, 0);
        let row = Family::Policy as usize * KEYS.len() + Key::RecordEncode as usize;
        assert_eq!(state.totals[row].calls, 1);
        state.epoch = u64::MAX;
        assert!(state.begin(7, Family::Query).is_none());
        assert!(!state.active);
    }

    #[test]
    fn session_drop_stops_collection_and_old_timer_cannot_join_a_new_session() {
        let first = arm(Family::Query);
        let old_timer = Timer::new(Key::RecordEncode);
        let second = arm(Family::Policy);
        drop(first);
        drop(old_timer);
        drop(Timer::new(Key::RecordEncode));
        STATE.with(|cell| {
            let state = cell.get();
            assert!(state.active);
            assert_eq!(state.totals[Key::RecordEncode as usize].calls, 0);
            let row = Family::Policy as usize * KEYS.len() + Key::RecordEncode as usize;
            assert_eq!(state.totals[row].calls, 1);
        });
        drop(second);
        assert!(stop_snapshot().is_none());
        drop(Timer::new(Key::RecordEncode));
        assert!(!STATE.with(|cell| cell.get().active));
    }
}
