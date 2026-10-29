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
pub(crate) enum RetainedKey {
    RetainedTransport,
    RetainedData,
    RetainedOwnerRecord,
    RetainedHistory,
    HistoryAllocationDigest,
    CreatedGroupNative,
    SourceIdentityEntries,
    NativeSourceEntries,
}
const RETAINED_KEYS: [RetainedKey; 8] = [
    RetainedKey::RetainedTransport,
    RetainedKey::RetainedData,
    RetainedKey::RetainedOwnerRecord,
    RetainedKey::RetainedHistory,
    RetainedKey::HistoryAllocationDigest,
    RetainedKey::CreatedGroupNative,
    RetainedKey::SourceIdentityEntries,
    RetainedKey::NativeSourceEntries,
];
impl RetainedKey {
    fn label(self) -> &'static str {
        match self {
            Self::RetainedTransport => "retained_transport",
            Self::RetainedData => "retained_data",
            Self::RetainedOwnerRecord => "retained_owner_record",
            Self::RetainedHistory => "retained_history",
            Self::HistoryAllocationDigest => "history_allocation_digest",
            Self::CreatedGroupNative => "created_group_native",
            Self::SourceIdentityEntries => "source_identity_entries",
            Self::NativeSourceEntries => "native_source_entries",
        }
    }
    fn count_only(self) -> bool {
        matches!(
            self,
            Self::SourceIdentityEntries | Self::NativeSourceEntries
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) enum OwnerKey {
    HostPreflight,
    RecordValidate,
    NamespaceIdentities,
    CurrentIdentityChain,
    RecordClone,
}
const OWNER_KEYS: [OwnerKey; 5] = [
    OwnerKey::HostPreflight,
    OwnerKey::RecordValidate,
    OwnerKey::NamespaceIdentities,
    OwnerKey::CurrentIdentityChain,
    OwnerKey::RecordClone,
];
impl OwnerKey {
    fn label(self) -> &'static str {
        match self {
            Self::HostPreflight => "owner_host_preflight",
            Self::RecordValidate => "owner_record_validate",
            Self::NamespaceIdentities => "owner_namespace_identities",
            Self::CurrentIdentityChain => "owner_current_identity_chain",
            Self::RecordClone => "owner_record_clone",
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
const RETAINED_ROWS: usize = FAMILIES.len() * RETAINED_KEYS.len();
const OWNER_ROWS: usize = FAMILIES.len() * OWNER_KEYS.len();

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
            retained_totals: [ZERO; RETAINED_ROWS],
            owner_totals: [ZERO; OWNER_ROWS],
        })
    }
}
// Separate selected-row cells leave State and every existing timer's table
// copy unchanged. No borrow or lock spans instrumented work.
struct RetainedTotals {
    rows: [Cell<Total>; RETAINED_ROWS],
}
impl RetainedTotals {
    const fn new() -> Self {
        Self {
            rows: [const { Cell::new(ZERO) }; RETAINED_ROWS],
        }
    }
    fn reset(&self) {
        for row in &self.rows {
            row.set(ZERO);
        }
    }
    fn record(&self, state: &State, token: Token, key: RetainedKey, elapsed_ns: u128) {
        if !state.accepts(token) {
            return;
        }
        let row = &self.rows[token.family as usize * RETAINED_KEYS.len() + key as usize];
        let mut total = row.get();
        total.calls = total.calls.saturating_add(1);
        if !key.count_only() {
            total.elapsed_ns = total.elapsed_ns.saturating_add(elapsed_ns);
        }
        row.set(total);
    }
    fn snapshot(&self) -> [Total; RETAINED_ROWS] {
        std::array::from_fn(|index| self.rows[index].get())
    }
}
// Keep owner rows separate from both old tables. Entry/drop touches one row;
// only the stopped parent snapshot copies the full owner table.
struct OwnerTotals {
    rows: [Cell<Total>; OWNER_ROWS],
}
impl OwnerTotals {
    const fn new() -> Self {
        Self {
            rows: [const { Cell::new(ZERO) }; OWNER_ROWS],
        }
    }
    fn reset(&self) {
        for row in &self.rows {
            row.set(ZERO);
        }
    }
    fn record(&self, state: &State, token: Token, key: OwnerKey, elapsed_ns: u128) {
        if !state.accepts(token) {
            return;
        }
        let row = &self.rows[token.family as usize * OWNER_KEYS.len() + key as usize];
        let mut total = row.get();
        total.calls = total.calls.saturating_add(1);
        total.elapsed_ns = total.elapsed_ns.saturating_add(elapsed_ns);
        row.set(total);
    }
    fn snapshot(&self) -> [Total; OWNER_ROWS] {
        std::array::from_fn(|index| self.rows[index].get())
    }
}
thread_local! {
    static STATE: Cell<State> = const { Cell::new(State::inactive()) };
    // Fork copies stay private; no child totals are merged or exported.
    static RETAINED: RetainedTotals = const { RetainedTotals::new() };
    static OWNER: OwnerTotals = const { OwnerTotals::new() };
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
        RETAINED.with(RetainedTotals::reset);
        OWNER.with(OwnerTotals::reset);
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

pub(crate) struct RetainedTimer {
    entry: Option<(Token, RetainedKey, Instant)>,
    _thread: PhantomData<Rc<()>>,
}
impl RetainedTimer {
    pub(crate) fn new(key: RetainedKey) -> Self {
        // No getpid here or in count_entry/drop: restricted child filters remain
        // unchanged, and all writes use their COW-private metadata and rows.
        let token = if key.count_only() {
            None
        } else {
            STATE.with(|cell| cell.get().token())
        };
        Self {
            entry: token.map(|token| (token, key, Instant::now())),
            _thread: PhantomData,
        }
    }
}
impl Drop for RetainedTimer {
    fn drop(&mut self) {
        if let Some((token, key, started)) = self.entry {
            STATE.with(|cell| {
                let state = cell.get();
                if state.accepts(token) {
                    RETAINED.with(|totals| {
                        totals.record(&state, token, key, started.elapsed().as_nanos());
                    });
                }
            });
        }
    }
}
pub(crate) struct OwnerTimer {
    entry: Option<(Token, OwnerKey, Instant)>,
    _thread: PhantomData<Rc<()>>,
}
impl OwnerTimer {
    pub(crate) fn new(key: OwnerKey) -> Self {
        // No getpid, allocation or borrow across measured work. Fork copies
        // remain COW-private and the original stop boundary controls export.
        let token = STATE.with(|cell| cell.get().token());
        Self {
            entry: token.map(|token| (token, key, Instant::now())),
            _thread: PhantomData,
        }
    }
}
impl Drop for OwnerTimer {
    fn drop(&mut self) {
        if let Some((token, key, started)) = self.entry {
            STATE.with(|cell| {
                let state = cell.get();
                if state.accepts(token) {
                    OWNER.with(|totals| {
                        totals.record(&state, token, key, started.elapsed().as_nanos());
                    });
                }
            });
        }
    }
}
pub(crate) fn count_entry(key: RetainedKey) {
    // Count-only entry paths do not observe time, even when active.
    if !key.count_only() {
        return;
    }
    STATE.with(|cell| {
        let state = cell.get();
        if let Some(token) = state.token() {
            RETAINED.with(|totals| totals.record(&state, token, key, 0));
        }
    });
}

pub(crate) struct Snapshot {
    totals: [Total; ROWS],
    retained_totals: [Total; RETAINED_ROWS],
    owner_totals: [Total; OWNER_ROWS],
}
pub(crate) fn stop_snapshot() -> Option<Snapshot> {
    let creator = std::process::id();
    STATE.with(|cell| {
        let mut state = cell.get();
        let snapshot = state.stop_snapshot(creator);
        cell.set(state);
        // Collection is disabled and creator checked before copying added rows.
        snapshot.map(|mut snapshot| {
            snapshot.retained_totals = RETAINED.with(RetainedTotals::snapshot);
            snapshot.owner_totals = OWNER.with(OwnerTotals::snapshot);
            snapshot
        })
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
        for family in FAMILIES {
            for key in RETAINED_KEYS {
                let total =
                    self.retained_totals[family as usize * RETAINED_KEYS.len() + key as usize];
                let _ = writeln!(
                    output,
                    "LAB_SECRET_BOOTSTRAP_RETAINED_TOTAL family={} category={} calls={} elapsed_ns={} measurement=inclusive_retained_elapsed grouping=lab_loop_entry_step_family",
                    family.label(),
                    key.label(),
                    total.calls,
                    total.elapsed_ns,
                );
            }
        }
        // Inclusive owner method rows may include non-Binding callers and early
        // errors. Fixed byte bounds do not bound output blocking time.
        for family in FAMILIES {
            for key in OWNER_KEYS {
                let total = self.owner_totals[family as usize * OWNER_KEYS.len() + key as usize];
                let _ = writeln!(
                    output,
                    "LAB_SECRET_BOOTSTRAP_OWNER_TOTAL family={} category={} calls={} elapsed_ns={} measurement=inclusive_owner_elapsed grouping=lab_loop_entry_step_family",
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

    #[test]
    fn owner_output_appends_only_closed_rows_after_existing_tables() {
        let _session = arm(Family::Query);
        let snapshot = stop_snapshot().unwrap();
        let mut output = Vec::new();
        snapshot.emit(&mut output);
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 69);
        assert!(
            lines[..30]
                .iter()
                .all(|line| line.starts_with("LAB_SECRET_BOOTSTRAP_NESTED_TOTAL "))
        );
        assert!(
            lines[30..54]
                .iter()
                .all(|line| line.starts_with("LAB_SECRET_BOOTSTRAP_RETAINED_TOTAL "))
        );
        let mut rows = lines[54..].iter();
        for family in ["query", "policy", "other"] {
            for category in [
                "owner_host_preflight",
                "owner_record_validate",
                "owner_namespace_identities",
                "owner_current_identity_chain",
                "owner_record_clone",
            ] {
                assert_eq!(
                    *rows.next().unwrap(),
                    format!(
                        "LAB_SECRET_BOOTSTRAP_OWNER_TOTAL family={family} category={category} calls=0 elapsed_ns=0 measurement=inclusive_owner_elapsed grouping=lab_loop_entry_step_family"
                    )
                );
            }
        }
        assert!(rows.next().is_none());
    }

    fn owner_nested_result(outcome: Result<(), ()>) -> Result<(), ()> {
        let _outer = OwnerTimer::new(OwnerKey::HostPreflight);
        let _inner = OwnerTimer::new(OwnerKey::RecordValidate);
        outcome?;
        Ok(())
    }

    fn owner_row(family: Family, key: OwnerKey) -> usize {
        family as usize * OWNER_KEYS.len() + key as usize
    }

    #[test]
    fn owner_nested_error_entries_capture_family_and_stop_before_export() {
        let _ = stop_snapshot();
        drop(OwnerTimer::new(OwnerKey::RecordClone));
        assert!(stop_snapshot().is_none());
        let session = arm(Family::Query);
        assert_eq!(owner_nested_result(Err(())), Err(()));
        let query_timer = OwnerTimer::new(OwnerKey::NamespaceIdentities);
        set_family(Family::Policy);
        drop(query_timer);
        drop(OwnerTimer::new(OwnerKey::RecordClone));
        let stopped = OwnerTimer::new(OwnerKey::CurrentIdentityChain);
        let snapshot = stop_snapshot().unwrap();
        drop(stopped);
        drop(session);
        assert!(stop_snapshot().is_none());
        for key in [
            OwnerKey::HostPreflight,
            OwnerKey::RecordValidate,
            OwnerKey::NamespaceIdentities,
        ] {
            assert_eq!(
                snapshot.owner_totals[owner_row(Family::Query, key)].calls,
                1
            );
        }
        assert_eq!(
            snapshot.owner_totals[owner_row(Family::Policy, OwnerKey::NamespaceIdentities)].calls,
            0
        );
        assert_eq!(
            snapshot.owner_totals[owner_row(Family::Policy, OwnerKey::RecordClone)].calls,
            1
        );
        assert_eq!(
            snapshot.owner_totals[owner_row(Family::Policy, OwnerKey::CurrentIdentityChain)].calls,
            0
        );
    }

    #[test]
    fn owner_reset_stale_sessions_foreign_stop_and_exhausted_epoch_cannot_leak() {
        let first = arm(Family::Query);
        drop(OwnerTimer::new(OwnerKey::RecordValidate));
        let old_timer = OwnerTimer::new(OwnerKey::HostPreflight);
        let second = arm(Family::Policy);
        drop(first);
        drop(old_timer);
        drop(OwnerTimer::new(OwnerKey::RecordClone));
        let snapshot = stop_snapshot().unwrap();
        assert_eq!(
            snapshot.owner_totals[owner_row(Family::Query, OwnerKey::RecordValidate)].calls,
            0
        );
        assert_eq!(
            snapshot.owner_totals[owner_row(Family::Query, OwnerKey::HostPreflight)].calls,
            0
        );
        assert_eq!(
            snapshot.owner_totals[owner_row(Family::Policy, OwnerKey::RecordClone)].calls,
            1
        );
        drop(second);
        let session = arm(Family::Other);
        drop(OwnerTimer::new(OwnerKey::HostPreflight));
        drop(session);
        drop(OwnerTimer::new(OwnerKey::HostPreflight));
        assert!(stop_snapshot().is_none());
        let foreign = arm(Family::Other);
        drop(OwnerTimer::new(OwnerKey::RecordValidate));
        STATE.with(|cell| {
            let mut state = cell.get();
            state.creator = state.creator.wrapping_add(1);
            cell.set(state);
        });
        assert!(stop_snapshot().is_none());
        drop(OwnerTimer::new(OwnerKey::RecordValidate));
        assert!(!STATE.with(|cell| cell.get().active));
        drop(foreign);
        let _fresh = arm(Family::Other);
        assert!(
            stop_snapshot()
                .unwrap()
                .owner_totals
                .iter()
                .all(|total| total.calls == 0 && total.elapsed_ns == 0)
        );
        let exhausted = arm(Family::Query);
        drop(OwnerTimer::new(OwnerKey::RecordClone));
        STATE.with(|cell| {
            let mut state = cell.get();
            state.epoch = u64::MAX;
            cell.set(state);
        });
        let disabled = arm(Family::Query);
        assert!(disabled.token.is_none());
        assert!(stop_snapshot().is_none());
        OWNER.with(|totals| {
            assert!(
                totals
                    .snapshot()
                    .iter()
                    .all(|total| total.calls == 0 && total.elapsed_ns == 0)
            )
        });
        drop(exhausted);
        drop(disabled);
        // Restore this test thread's exhausted diagnostic state for later tests.
        STATE.with(|cell| cell.set(State::inactive()));
    }

    #[test]
    fn owner_selected_rows_saturate_and_copied_child_accounting_stays_private() {
        let mut parent = State::inactive();
        let token = parent.begin(7, Family::Query).unwrap();
        let totals = OwnerTotals::new();
        let row = owner_row(Family::Query, OwnerKey::RecordValidate);
        totals.rows[row].set(Total {
            calls: u64::MAX,
            elapsed_ns: u128::MAX - 1,
        });
        totals.record(&parent, token, OwnerKey::RecordValidate, 5);
        assert_eq!(totals.rows[row].get().calls, u64::MAX);
        assert_eq!(totals.rows[row].get().elapsed_ns, u128::MAX);
        totals.record(&parent, token, OwnerKey::RecordClone, 11);
        let child_totals = OwnerTotals::new();
        for (cell, total) in child_totals.rows.iter().zip(totals.snapshot()) {
            cell.set(total);
        }
        let mut child = parent;
        child_totals.record(&child, token, OwnerKey::RecordClone, 99);
        assert!(child.stop_snapshot(8).is_none());
        child_totals.record(&child, token, OwnerKey::HostPreflight, 13);
        assert_eq!(
            child_totals.rows[owner_row(Family::Query, OwnerKey::RecordClone)]
                .get()
                .calls,
            2
        );
        assert_eq!(
            child_totals.rows[owner_row(Family::Query, OwnerKey::RecordClone)]
                .get()
                .elapsed_ns,
            110
        );
        assert_eq!(
            child_totals.rows[owner_row(Family::Query, OwnerKey::HostPreflight)]
                .get()
                .calls,
            0
        );
        let snapshot = parent.stop_snapshot(7).unwrap();
        assert!(!parent.active);
        assert!(snapshot.owner_totals.iter().all(|total| total.calls == 0));
        assert_eq!(
            totals.rows[owner_row(Family::Query, OwnerKey::RecordClone)]
                .get()
                .calls,
            1
        );
        assert_eq!(
            totals.rows[owner_row(Family::Query, OwnerKey::RecordClone)]
                .get()
                .elapsed_ns,
            11
        );
        totals.record(&parent, token, OwnerKey::RecordClone, 17);
        assert_eq!(
            totals.rows[owner_row(Family::Query, OwnerKey::RecordClone)]
                .get()
                .calls,
            1
        );
        totals.reset();
        assert!(
            totals
                .snapshot()
                .iter()
                .all(|total| total.calls == 0 && total.elapsed_ns == 0)
        );
    }

    #[test]
    fn owner_maximum_output_is_bounded_and_writer_failure_is_ignored() {
        let _session = arm(Family::Other);
        let mut snapshot = stop_snapshot().unwrap();
        snapshot.owner_totals = [Total {
            calls: u64::MAX,
            elapsed_ns: u128::MAX,
        }; OWNER_ROWS];
        let mut output = Vec::new();
        snapshot.emit(&mut output);
        let text = String::from_utf8(output).unwrap();
        let owner_lines: Vec<_> = text.lines().skip(54).collect();
        assert_eq!(owner_lines.len(), 15);
        assert_eq!(
            owner_lines.iter().map(|line| line.len() + 1).sum::<usize>(),
            3434
        );
        assert_eq!(
            owner_lines.iter().map(|line| line.len() + 1).max(),
            Some(235)
        );
        struct Fails;
        impl std::io::Write for Fails {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let _session = arm(Family::Query);
        stop_snapshot().unwrap().emit(&mut Fails);
        assert!(!STATE.with(|cell| cell.get().active));
    }

    fn retained_nested_result(outcome: Result<(), ()>) -> Result<(), ()> {
        let _outer = RetainedTimer::new(RetainedKey::RetainedHistory);
        let _inner = RetainedTimer::new(RetainedKey::HistoryAllocationDigest);
        count_entry(RetainedKey::NativeSourceEntries);
        outcome?;
        Ok(())
    }

    fn retained_row(family: Family, key: RetainedKey) -> usize {
        family as usize * RETAINED_KEYS.len() + key as usize
    }

    #[test]
    fn retained_regions_count_errors_and_capture_family_without_escaping_session() {
        let _ = stop_snapshot();
        drop(RetainedTimer::new(RetainedKey::RetainedHistory));
        count_entry(RetainedKey::NativeSourceEntries);
        assert!(stop_snapshot().is_none());
        let _session = arm(Family::Query);
        assert_eq!(retained_nested_result(Err(())), Err(()));
        count_entry(RetainedKey::SourceIdentityEntries);
        let query_timer = RetainedTimer::new(RetainedKey::RetainedOwnerRecord);
        set_family(Family::Policy);
        count_entry(RetainedKey::SourceIdentityEntries);
        drop(query_timer);
        let stopped = RetainedTimer::new(RetainedKey::RetainedData);
        let snapshot = stop_snapshot().unwrap();
        drop(stopped);
        assert!(stop_snapshot().is_none());
        for key in [
            RetainedKey::RetainedHistory,
            RetainedKey::HistoryAllocationDigest,
            RetainedKey::RetainedOwnerRecord,
            RetainedKey::NativeSourceEntries,
            RetainedKey::SourceIdentityEntries,
        ] {
            assert_eq!(
                snapshot.retained_totals[retained_row(Family::Query, key)].calls,
                1
            );
        }
        for family in FAMILIES {
            for key in [
                RetainedKey::SourceIdentityEntries,
                RetainedKey::NativeSourceEntries,
            ] {
                assert_eq!(
                    snapshot.retained_totals[retained_row(family, key)].elapsed_ns,
                    0
                );
            }
        }
        assert_eq!(
            snapshot.retained_totals
                [retained_row(Family::Policy, RetainedKey::SourceIdentityEntries)]
            .calls,
            1
        );
        assert_eq!(
            snapshot.retained_totals[retained_row(Family::Policy, RetainedKey::RetainedData)].calls,
            0
        );
    }

    #[test]
    fn retained_selected_rows_saturate_and_copied_child_totals_remain_private() {
        let mut parent = State::inactive();
        let token = parent.begin(7, Family::Query).unwrap();
        let totals = RetainedTotals::new();
        let row = retained_row(Family::Query, RetainedKey::RetainedHistory);
        totals.rows[row].set(Total {
            calls: u64::MAX,
            elapsed_ns: u128::MAX - 1,
        });
        totals.record(&parent, token, RetainedKey::RetainedHistory, 5);
        assert_eq!(totals.rows[row].get().calls, u64::MAX);
        assert_eq!(totals.rows[row].get().elapsed_ns, u128::MAX);
        totals.record(&parent, token, RetainedKey::NativeSourceEntries, 99);
        assert_eq!(
            totals.rows[retained_row(Family::Query, RetainedKey::NativeSourceEntries)]
                .get()
                .elapsed_ns,
            0
        );
        let child_totals = RetainedTotals::new();
        for (cell, total) in child_totals.rows.iter().zip(totals.snapshot()) {
            cell.set(total);
        }
        let mut child = parent;
        child_totals.record(&child, token, RetainedKey::NativeSourceEntries, 0);
        assert!(child.stop_snapshot(8).is_none());
        assert_eq!(
            child_totals.rows[retained_row(Family::Query, RetainedKey::NativeSourceEntries)]
                .get()
                .calls,
            2
        );
        assert_eq!(
            totals.rows[retained_row(Family::Query, RetainedKey::NativeSourceEntries)]
                .get()
                .calls,
            1
        );
        let before = child_totals.snapshot();
        child_totals.record(&child, token, RetainedKey::RetainedData, 10);
        assert_eq!(
            child_totals.rows[retained_row(Family::Query, RetainedKey::RetainedData)]
                .get()
                .calls,
            0
        );
        assert_eq!(
            before[retained_row(Family::Query, RetainedKey::NativeSourceEntries)].calls,
            2
        );
        totals.reset();
        assert!(
            totals
                .snapshot()
                .iter()
                .all(|total| total.calls == 0 && total.elapsed_ns == 0)
        );
    }

    #[test]
    fn retained_reset_stale_epochs_and_foreign_stop_cannot_publish_new_rows() {
        let first = arm(Family::Query);
        count_entry(RetainedKey::SourceIdentityEntries);
        let old_timer = RetainedTimer::new(RetainedKey::RetainedTransport);
        let second = arm(Family::Policy);
        drop(first);
        drop(old_timer);
        assert_eq!(retained_nested_result(Ok(())), Ok(()));
        let snapshot = stop_snapshot().unwrap();
        assert_eq!(
            snapshot.retained_totals
                [retained_row(Family::Query, RetainedKey::SourceIdentityEntries)]
            .calls,
            0
        );
        assert_eq!(
            snapshot.retained_totals[retained_row(Family::Query, RetainedKey::RetainedTransport)]
                .calls,
            0
        );
        assert_eq!(
            snapshot.retained_totals[retained_row(Family::Policy, RetainedKey::RetainedHistory)]
                .calls,
            1
        );
        drop(second);
        let _session = arm(Family::Other);
        count_entry(RetainedKey::NativeSourceEntries);
        STATE.with(|cell| {
            let mut state = cell.get();
            state.creator = state.creator.wrapping_add(1);
            cell.set(state);
        });
        assert!(stop_snapshot().is_none());
        count_entry(RetainedKey::NativeSourceEntries);
        assert!(!STATE.with(|cell| cell.get().active));
        let _new = arm(Family::Other);
        let snapshot = stop_snapshot().unwrap();
        assert!(
            snapshot
                .retained_totals
                .iter()
                .all(|total| total.calls == 0 && total.elapsed_ns == 0)
        );
    }

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
