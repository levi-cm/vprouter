//! A separate terminal deny authority; ordinary release never owns this table.
use crate::{
    Error, Policy, Reconciliation, Result,
    actuator::{delete, inspect_table_from},
    codec::Attr,
    policy::Table,
    socket::Socket,
};
use rustix::time::{ClockId, Timespec, clock_gettime};
use std::{
    os::fd::BorrowedFd,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

/// Absolute CLOCK_BOOTTIME boundary. Conversion rounds conservatively down;
/// no operation may restart this budget after a message, syscall or suspend.
#[derive(Clone, Copy, Debug)]
pub struct BootDeadline(Timespec);
impl BootDeadline {
    pub fn at(seconds: f64) -> Result<Self> {
        let duration = Duration::try_from_secs_f64(seconds)
            .map_err(|_| Error::InvalidInput)?
            .checked_sub(Duration::from_nanos(1))
            .ok_or(Error::InvalidInput)?;
        let at = Timespec::try_from(duration).map_err(|_| Error::InvalidInput)?;
        if at.tv_sec == 0 && at.tv_nsec == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self(at))
    }
    pub fn check(self) -> Result<()> {
        self.check_at(clock_gettime(ClockId::Boottime))
    }
    fn check_at(self, now: Timespec) -> Result<()> {
        if (now.tv_sec, now.tv_nsec) < (self.0.tv_sec, self.0.tv_nsec) {
            Ok(())
        } else {
            Err(Error::Deadline)
        }
    }
    pub(crate) fn timespec(self) -> Timespec {
        self.0
    }
}

/// Fixed lifecycle deny policy on a newly opened namespace-bound socket. This
/// authority cannot stage permits, release quarantine, or delete terminal state.
/// Its terminal table is deliberately separate from both ordinary deny tables.
pub struct TerminalQuarantine {
    socket: Socket,
    table: Table,
    namespace: (u64, u64),
    attempted: bool,
}
impl TerminalQuarantine {
    pub fn open(policy: &Policy, lifecycle: &str, namespace: (u64, u64)) -> Result<Self> {
        let table = terminal_table(policy, lifecycle)?;
        let before =
            std::fs::metadata("/proc/thread-self/ns/net").map_err(|_| Error::InvalidInput)?;
        if (before.dev(), before.ino()) != namespace {
            return Err(Error::InvalidInput);
        }
        let socket = Socket::open_terminal()?;
        let after =
            std::fs::metadata("/proc/thread-self/ns/net").map_err(|_| Error::InvalidInput)?;
        if (after.dev(), after.ino()) != namespace {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            socket,
            table,
            namespace,
            attempted: false,
        })
    }
    /// Read-only exact witness used for recovery and disposable native oracles.
    /// It cannot repair an absent/drifted terminal table or mint a Ready lease.
    pub fn verify_existing(policy: &Policy, lifecycle: &str, namespace: (u64, u64)) -> Result<()> {
        let table = terminal_table(policy, lifecycle)?;
        let observed =
            std::fs::metadata("/proc/thread-self/ns/net").map_err(|_| Error::InvalidInput)?;
        if (observed.dev(), observed.ino()) != namespace {
            return Err(Error::InvalidInput);
        }
        let mut socket = Socket::open()?;
        let end = Instant::now() + Duration::from_secs(5);
        let generation = socket.generation(end)?;
        let tables = socket.dump(1, &[], end)?;
        if inspect_table_from(&mut socket, &table, &tables, end)? != Reconciliation::Matching {
            return Err(Error::Drifted);
        }
        if socket.generation(end)? != generation {
            return Err(Error::GenerationChanged);
        }
        Ok(())
    }
    pub fn namespace(&self) -> (u64, u64) {
        self.namespace
    }
    /// Borrowed descriptors only, for the fixed child's exact close/confinement
    /// inventory. No constructor accepts caller-supplied or duplicated sockets.
    pub fn descriptors(&self) -> [BorrowedFd<'_>; 2] {
        self.socket.terminal_descriptors()
    }
    /// One terminal attempt. Even a matching table is atomically re-created to
    /// commit a real generation change; a no-op cannot fence older batches.
    /// A lost ACK or deadline permanently consumes this writer. Its owner must
    /// retain the durable recovery barrier rather than infer successful cleanup.
    pub fn contain(&mut self, deadline: BootDeadline) -> Result<()> {
        if self.attempted {
            return Err(Error::InvalidInput);
        }
        self.attempted = true;
        self.socket.bind_deadline(deadline)?;
        let end = Instant::now() + Duration::from_secs(5);
        let generation = self.socket.generation(end)?;
        let tables = self.socket.dump(1, &[], end)?;
        let state = inspect_table_from(&mut self.socket, &self.table, &tables, end)?;
        if self.socket.generation(end)? != generation {
            return Err(Error::GenerationChanged);
        }
        let ops = terminal_operations(&self.table, state)?;
        self.socket.batch(&ops, generation, end)?;
        let committed = self.socket.generation(end)?;
        if committed == generation {
            return Err(Error::GenerationChanged);
        }
        let tables = self.socket.dump(1, &[], end)?;
        if inspect_table_from(&mut self.socket, &self.table, &tables, end)?
            != Reconciliation::Matching
        {
            return Err(Error::Drifted);
        }
        if self.socket.generation(end)? != committed {
            return Err(Error::GenerationChanged);
        }
        deadline.check()
    }
}
pub(crate) fn terminal_table(policy: &Policy, lifecycle: &str) -> Result<Table> {
    if lifecycle.len() != 64
        || !lifecycle
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::InvalidInput);
    }
    let mut table = policy.table(true);
    table.name.push_str("_terminal_");
    table.name.push_str(lifecycle);
    table.marker.extend_from_slice(b"\0terminal-expiry\0");
    table.marker.extend_from_slice(lifecycle.as_bytes());
    Ok(table)
}
fn terminal_operations(table: &Table, state: Reconciliation) -> Result<Vec<(u16, u16, Vec<Attr>)>> {
    let mut operations = match state {
        Reconciliation::Absent => Vec::new(),
        Reconciliation::Matching => vec![delete(table)],
        Reconciliation::Foreign => return Err(Error::Foreign),
        _ => return Err(Error::Drifted),
    };
    operations.extend(table.operations());
    Ok(operations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Reconciliation, Scope, policy::fixture};
    #[test]
    fn terminal_identity_and_mutation_are_distinct_from_releasable_quarantine() {
        for scope in [Scope::Host, Scope::Transport, Scope::Data] {
            let policy = fixture(scope);
            let a = terminal_table(&policy, &"a".repeat(64)).unwrap();
            let b = terminal_table(&policy, &"b".repeat(64)).unwrap();
            assert_ne!(a.name, b.name);
            assert_ne!(a.marker, b.marker);
            for other in [
                policy.table(true),
                policy.table(false),
                policy.emergency_table(),
            ] {
                assert_ne!(a.name, other.name);
                assert_ne!(a.marker, other.marker);
            }
            assert_eq!(a.chains, policy.table(true).chains);
            let absent = terminal_operations(&a, Reconciliation::Absent).unwrap();
            let matching = terminal_operations(&a, Reconciliation::Matching).unwrap();
            assert!(!absent.is_empty());
            assert_eq!(matching.len(), absent.len() + 1);
            assert_eq!(&matching[1..], absent.as_slice());
            for state in [
                Reconciliation::Foreign,
                Reconciliation::Drifted,
                Reconciliation::Unknown,
                Reconciliation::Owned,
            ] {
                assert!(terminal_operations(&a, state).is_err());
            }
        }
        for bad in ["", "a", &"A".repeat(64), &"g".repeat(64), &"a".repeat(65)] {
            assert!(terminal_table(&fixture(Scope::Host), bad).is_err());
        }
    }
    #[test]
    fn absolute_deadline_is_not_extended_by_conversion_or_clock_resume() {
        let deadline = BootDeadline::at(123.25).unwrap();
        assert!(
            deadline
                .check_at(rustix::time::Timespec {
                    tv_sec: 123,
                    tv_nsec: 249_999_998
                })
                .is_ok()
        );
        for now in [
            rustix::time::Timespec {
                tv_sec: 123,
                tv_nsec: 250_000_000,
            },
            rustix::time::Timespec {
                tv_sec: 999,
                tv_nsec: 0,
            },
        ] {
            assert_eq!(deadline.check_at(now), Err(Error::Deadline));
        }
        for invalid in [f64::NAN, f64::INFINITY, -1., 0., f64::MAX] {
            assert!(BootDeadline::at(invalid).is_err());
        }
    }
}
