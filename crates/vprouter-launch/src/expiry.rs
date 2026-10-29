#![forbid(unsafe_code)]
//! Three independently scheduled terminal writers. Wire data never constitutes
//! Ready authority without the retained child pidfds, durable identities and ACKs.
use super::{
    Error, Result, kernel,
    owned::{ExecutorCompletion, ExecutorIdentity, Identity, TerminalResult, Transaction},
    spec::LaunchSpec,
};
use rustix::{
    event::{PollFd, PollFlags, poll},
    net::{self, RecvFlags, SendFlags},
};
use serde::{Deserialize, Serialize};
use std::{
    os::fd::{AsFd, OwnedFd},
    time::{Duration, Instant},
};
use vprouter_core::health::{Binding, HealthMessage, Session, boot_seconds};
use vprouter_netfilter::{BootDeadline, Policy, TerminalQuarantine};
#[path = "expiry_owner.rs"]
mod owner;
#[cfg(test)]
pub(super) use owner::lab_retained_expiry;
pub(crate) use owner::{FixedCompletion, FixedRegistration, OwnerExecutors};
pub(super) use owner::{poll_retired_owners, retired_owners_drained};
const MARGIN: f64 = 5.;
const MAX_FRAME: usize = 32768;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum Command {
    Health {
        message: Box<HealthMessage>,
    },
    Liveness {
        lifecycle: String,
        sequence: u64,
        sent_at: f64,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
enum Ack {
    Failed {
        reason: String,
    },
    Registered {
        lifecycle: String,
        scope: u8,
        namespace: Identity,
    },
    Lease {
        lifecycle: String,
        scope: u8,
        sequence: u64,
        deadline: f64,
    },
    Liveness {
        lifecycle: String,
        scope: u8,
        sequence: u64,
    },
    Terminal {
        lifecycle: String,
        scope: u8,
        outcome: TerminalResult,
        deadline: f64,
        finished_at: f64,
    },
}
fn observe_original(
    machine: &mut vprouter_core::state::HealthMachine,
    message: &HealthMessage,
    now: f64,
) -> Result<vprouter_core::state::HealthState> {
    use vprouter_core::state::HealthState;
    if machine.expire(now) {
        return Err(Error::Deadline);
    }
    if let Some(snapshot) = &message.snapshot {
        if matches!(machine.state(), HealthState::Stopping | HealthState::Failed)
            && snapshot.state != machine.state()
        {
            return Err(Error::DescriptorPolicy);
        }
        if let Some(evidence) = &snapshot.evidence {
            let observed = machine
                .observe(now, evidence.clone())
                .map_err(|_| Error::DescriptorPolicy)?;
            if observed != snapshot.state {
                return Err(Error::DescriptorPolicy);
            }
        } else if snapshot.state == HealthState::Blocked {
            machine.block(snapshot.reason.ok_or(Error::DescriptorPolicy)?);
        } else if snapshot.state == HealthState::Stopping {
            if snapshot.reason != Some(vprouter_core::reason::Reason::Stopping) {
                return Err(Error::DescriptorPolicy);
            }
            machine.stop();
        } else if snapshot.state == HealthState::Failed {
            machine.fail(snapshot.reason.ok_or(Error::DescriptorPolicy)?);
        } else if snapshot.state != HealthState::Starting
            || machine.state() != HealthState::Starting
        {
            return Err(Error::DescriptorPolicy);
        }
    }
    Ok(machine.state())
}
struct LeaseClock {
    session: Session,
    lifecycle: String,
    deadline: f64,
    liveness_deadline: f64,
    liveness_sequence: u64,
    terminal: bool,
}
impl LeaseClock {
    fn new(binding: Binding, lifecycle: String, now: f64) -> Result<Self> {
        let session =
            Session::new(binding, lifecycle.clone(), now).map_err(|_| Error::DescriptorPolicy)?;
        let deadline = session.expires_at().map_err(|_| Error::Deadline)?;
        Ok(Self {
            session,
            lifecycle,
            deadline,
            liveness_deadline: now + 90.,
            liveness_sequence: 0,
            terminal: false,
        })
    }
    fn check(&mut self, now: f64) -> Result<()> {
        if self.terminal
            || !now.is_finite()
            || now >= self.trigger()
            || self.session.check(now).is_err()
        {
            self.terminal = true;
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn trigger(&self) -> f64 {
        self.deadline.min(self.liveness_deadline) - MARGIN
    }
    fn accept(&mut self, message: &HealthMessage, now: f64) -> Result<f64> {
        let result = (|| {
            self.check(now)?;
            self.session
                .accept(message, now)
                .map_err(|_| Error::DescriptorPolicy)?;
            let deadline = self.session.expires_at().map_err(|_| Error::Deadline)?;
            if deadline - now <= MARGIN {
                return Err(Error::Deadline);
            }
            self.deadline = deadline;
            Ok(deadline)
        })();
        if result.is_err() {
            self.terminal = true;
        }
        result
    }
    fn liveness(&mut self, lifecycle: &str, sequence: u64, sent_at: f64, now: f64) -> Result<()> {
        self.check(now)?;
        if lifecycle != self.lifecycle
            || Some(sequence) != self.liveness_sequence.checked_add(1)
            || !sent_at.is_finite()
            || sent_at > now
            || now - sent_at >= 2.
        {
            self.terminal = true;
            return Err(Error::DescriptorPolicy);
        }
        self.liveness_sequence = sequence;
        self.liveness_deadline = sent_at + 90.;
        Ok(())
    }
}
fn send<T: Serialize>(socket: impl AsFd, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::DescriptorPolicy)?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::TooLarge);
    }
    match net::send(socket, &bytes, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
        Ok(n) if n == bytes.len() => Ok(()),
        _ => Err(Error::DescriptorPolicy),
    }
}
pub(super) fn child_failure(socket: impl AsFd, reason: Error) {
    let _ = send(
        socket,
        &Ack::Failed {
            reason: reason.to_string(),
        },
    );
}
fn receive<T: serde::de::DeserializeOwned>(socket: impl AsFd) -> Result<Option<T>> {
    let mut bytes = vec![0; MAX_FRAME + 1];
    match net::recv(socket, &mut bytes, RecvFlags::DONTWAIT | RecvFlags::TRUNC) {
        Err(rustix::io::Errno::AGAIN) => Ok(None),
        Ok((n, full)) if n > 0 && n == full && n <= MAX_FRAME => {
            serde_json::from_slice(&bytes[..n])
                .map(Some)
                .map_err(|_| Error::DescriptorPolicy)
        }
        _ => Err(Error::DescriptorPolicy),
    }
}
fn wait_ack(socket: impl AsFd, child: &kernel::Survivor, end: Instant) -> Result<Ack> {
    loop {
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        if let Some(ack) = receive(&socket)? {
            if Instant::now() >= end {
                return Err(Error::Deadline);
            }
            if let Ack::Failed { reason } = &ack {
                #[cfg(test)]
                eprintln!("LAB_TERMINAL_CHILD_FAILURE reason={reason}");
                #[cfg(not(test))]
                let _ = reason;
                return Err(Error::ChildFailed);
            }
            child.require_live()?;
            return Ok(ack);
        }
        child.require_live()?;
        let child_fd = child.pidfd();
        let mut fds = [
            PollFd::new(&socket, PollFlags::IN),
            PollFd::new(&child_fd, PollFlags::IN),
        ];
        let left = rustix::event::Timespec::try_from(end.saturating_duration_since(Instant::now()))
            .map_err(|_| Error::Deadline)?;
        poll(&mut fds, Some(&left)).map_err(|_| Error::Deadline)?;
    }
}
// A retained constructor copy of the endpoint must not suppress revocation
// when the guard's owning control wrapper leaves scope on any error path.
struct ExecutorControl {
    creator: u32,
    socket: OwnedFd,
}
impl AsFd for ExecutorControl {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.socket.as_fd()
    }
}
impl Drop for ExecutorControl {
    fn drop(&mut self) {
        if self.creator == std::process::id() {
            let _ = net::shutdown(&self.socket, net::Shutdown::Both);
        }
    }
}
struct Executor {
    child: kernel::Survivor,
    socket: ExecutorControl,
    identity: ExecutorIdentity,
    _inventory: super::inventory::Registration,
    _scope: Option<super::supervision::Scope>,
}
pub(super) struct Executors {
    children: Vec<Executor>,
    clock: LeaseClock,
    authority: vprouter_core::state::HealthMachine,
    lifecycle: String,
    ready_sequence: Option<u64>,
}
/// Borrowed permission cannot outlive its owner. Its constructor is private and
/// it is checked before AND after the native Ready transition by the transport.
pub(super) struct ReadyLease<'a> {
    owner: &'a mut Executors,
    sequence: u64,
}
impl ReadyLease<'_> {
    pub fn expires_at(&self) -> f64 {
        self.owner.clock.trigger()
    }
    pub fn check(&mut self) -> Result<()> {
        let result = (|| {
            self.owner.clock.check(boot_seconds())?;
            if self.owner.ready_sequence != Some(self.sequence)
                || self.owner.authority.state() != vprouter_core::state::HealthState::Ready
            {
                return Err(Error::Interrupted);
            }
            for e in &self.owner.children {
                e.child.require_live()?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.owner.revoke();
        }
        result
    }
}
impl Executors {
    pub fn spawn(
        transaction: &Transaction,
        spec: &LaunchSpec,
        binding: Binding,
        lifecycle: &str,
        scopes: [(Policy, std::os::fd::BorrowedFd<'_>); 3],
    ) -> Result<Self> {
        Self::spawn_inner(transaction, spec, binding, lifecycle, scopes, None, None)
    }
    pub fn spawn_owned(
        transaction: &Transaction,
        spec: &LaunchSpec,
        binding: Binding,
        scopes: [(Policy, std::os::fd::BorrowedFd<'_>); 3],
        domains: &super::supervision::Domains,
    ) -> Result<Self> {
        domains.verify_guard()?;
        Self::spawn_inner(
            transaction,
            spec,
            binding,
            domains.lifecycle(),
            scopes,
            Some(domains),
            None,
        )
    }
    pub fn spawn_remote(
        transaction: &Transaction,
        spec: &LaunchSpec,
        binding: Binding,
        lifecycle: &str,
        scopes: [(Policy, std::os::fd::BorrowedFd<'_>); 3],
        client: &super::owner::HostAuditClient,
    ) -> Result<Self> {
        let domains = client.domains(spec, lifecycle)?;
        Self::spawn_inner(
            transaction,
            spec,
            binding,
            lifecycle,
            scopes,
            Some(domains),
            Some(client),
        )
    }
    fn spawn_inner(
        transaction: &Transaction,
        spec: &LaunchSpec,
        binding: Binding,
        lifecycle: &str,
        scopes: [(Policy, std::os::fd::BorrowedFd<'_>); 3],
        domains: Option<&super::supervision::Domains>,
        remote: Option<&super::owner::HostAuditClient>,
    ) -> Result<Self> {
        if remote.is_some() {
            super::process::guard_preflight()?;
        } else {
            super::process::host_preflight()?;
        }
        let started_at = transaction.begin_terminal_at(spec, binding.clone(), lifecycle)?;
        let mut result = Self {
            children: Vec::new(),
            clock: LeaseClock::new(binding.clone(), lifecycle.into(), started_at)?,
            authority: vprouter_core::state::HealthMachine::new(
                binding.mode,
                binding.expected_server.as_deref(),
                &binding.node_id,
            )
            .map_err(|_| Error::InvalidSpec)?,
            lifecycle: lifecycle.into(),
            ready_sequence: None,
        };
        for (scope, (policy, namespace)) in scopes.into_iter().enumerate() {
            let expected_scope = [
                vprouter_netfilter::Scope::Host,
                vprouter_netfilter::Scope::Transport,
                vprouter_netfilter::Scope::Data,
            ][scope];
            if policy.scope() != expected_scope {
                return Err(Error::DescriptorPolicy);
            }
            let namespace_id = Identity::network(namespace)?;
            let (child, socket, placement) = if let Some(client) = remote {
                let (child, socket) = client.spawn_executor(spec, scope as u8, started_at)?;
                (child, socket, None)
            } else {
                let lock = transaction.retain_executor_lock(spec)?;
                let registration = super::inventory::Registration::owned(&[lock.as_fd()])?;
                let (child, socket) = kernel::spawn_terminal(
                    namespace,
                    &lock,
                    &policy,
                    ChildBinding {
                        binding: &binding,
                        lifecycle,
                        scope: scope as u8,
                        started_at,
                    },
                    domains,
                    None,
                )?;
                drop(registration);
                drop(lock);
                (child, socket, None)
            };
            let socket = ExecutorControl {
                creator: std::process::id(),
                socket,
            };
            let inventory = super::inventory::Registration::owned(&[socket.as_fd()])?;
            let identity = child.identity(scope as u8, namespace_id)?;
            // Durable PID/start intent is recorded BEFORE trusting its ACK.
            if remote.is_none() {
                transaction.register_executor(spec, lifecycle, identity.clone())?;
            }
            match wait_ack(&socket, &child, Instant::now() + Duration::from_secs(2))? {
                Ack::Registered {
                    lifecycle: received,
                    scope: number,
                    namespace: ns,
                } if received == lifecycle && number == scope as u8 && ns == namespace_id => (),
                _ => return Err(Error::DescriptorPolicy),
            }
            transaction.acknowledge_executor(spec, lifecycle, &identity)?;
            result.children.push(Executor {
                child,
                socket,
                identity,
                _inventory: inventory,
                _scope: placement,
            });
        }
        result.verify_journal(transaction, spec)?;
        Ok(result)
    }
    fn identities(&self) -> Vec<ExecutorIdentity> {
        self.children.iter().map(|e| e.identity.clone()).collect()
    }
    fn verify_journal(&self, transaction: &Transaction, spec: &LaunchSpec) -> Result<()> {
        transaction.verify_executors(spec, &self.lifecycle, &self.identities())
    }
    fn revoke(&mut self) {
        self.ready_sequence = None;
        self.clock.terminal = true;
        for e in &self.children {
            let _ = net::shutdown(&e.socket, net::Shutdown::Both);
        }
    }
    pub fn check(&mut self, transaction: &Transaction, spec: &LaunchSpec) -> Result<()> {
        let result = (|| {
            self.clock.check(boot_seconds())?;
            self.verify_journal(transaction, spec)?;
            for child in &self.children {
                child.child.require_live()?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.revoke();
        }
        result
    }
    pub fn stop(&mut self) {
        self.revoke();
    }
    pub fn health(
        &mut self,
        transaction: &Transaction,
        spec: &LaunchSpec,
        message: &HealthMessage,
    ) -> Result<()> {
        let result = self.health_inner(transaction, spec, message);
        if result.is_err() {
            self.revoke();
        }
        result
    }
    fn health_inner(
        &mut self,
        transaction: &Transaction,
        spec: &LaunchSpec,
        message: &HealthMessage,
    ) -> Result<()> {
        self.ready_sequence = None;
        let deadline = self.clock.accept(message, boot_seconds())?;
        let state = observe_original(&mut self.authority, message, boot_seconds())?;
        self.verify_journal(transaction, spec)?;
        let end = Instant::now() + Duration::from_secs(2);
        for e in &self.children {
            e.child.require_live()?;
            send(
                &e.socket,
                &Command::Health {
                    message: Box::new(message.clone()),
                },
            )?;
        }
        for e in &self.children {
            match wait_ack(&e.socket, &e.child, end)? {
                Ack::Lease {
                    lifecycle,
                    scope,
                    sequence,
                    deadline: actual,
                } if lifecycle == self.lifecycle
                    && scope == e.identity.scope
                    && sequence == message.sequence
                    && actual == deadline => {}
                _ => {
                    self.clock.terminal = true;
                    return Err(Error::DescriptorPolicy);
                }
            }
        }
        self.clock.check(boot_seconds())?;
        self.verify_journal(transaction, spec)?;
        if state == vprouter_core::state::HealthState::Ready {
            self.ready_sequence = Some(message.sequence);
        }
        Ok(())
    }
    pub fn ready(
        &mut self,
        transaction: &Transaction,
        spec: &LaunchSpec,
    ) -> Result<ReadyLease<'_>> {
        self.verify_journal(transaction, spec)?;
        let sequence = self.ready_sequence.ok_or(Error::Interrupted)?;
        let mut lease = ReadyLease {
            owner: self,
            sequence,
        };
        lease.check()?;
        Ok(lease)
    }
    pub fn finish_terminal(&mut self, transaction: &Transaction, spec: &LaunchSpec) -> Result<()> {
        self.ready_sequence = None;
        self.clock.terminal = true;
        let end = Instant::now() + Duration::from_secs(2);
        for e in &self.children {
            // A terminated fixed child may have queued its final ACK. Endpoint
            // provenance is retained even after pidfd readability; never bind a
            // replacement process or trust unauthenticated cache contents.
            let ack = loop {
                if Instant::now() >= end {
                    return Err(Error::Deadline);
                }
                if let Some(ack) = receive::<Ack>(&e.socket)? {
                    break ack;
                }
                let mut fds = [PollFd::new(&e.socket, PollFlags::IN)];
                let remaining = rustix::event::Timespec::try_from(
                    end.saturating_duration_since(Instant::now()),
                )
                .map_err(|_| Error::Deadline)?;
                poll(&mut fds, Some(&remaining)).map_err(|_| Error::Deadline)?;
            };
            match ack {
                Ack::Terminal {
                    lifecycle,
                    scope,
                    outcome,
                    deadline,
                    finished_at,
                } if lifecycle == self.lifecycle
                    && scope == e.identity.scope
                    && deadline == self.clock.deadline.min(self.clock.liveness_deadline)
                    && finished_at <= boot_seconds()
                    && Instant::now() < end =>
                {
                    transaction.complete_executor(
                        spec,
                        &lifecycle,
                        ExecutorCompletion {
                            identity: e.identity.clone(),
                            result: outcome,
                            deadline,
                            finished_at,
                        },
                    )?;
                }
                _ => return Err(Error::DescriptorPolicy),
            }
        }
        Ok(())
    }
    pub fn liveness(&mut self) -> Result<()> {
        let result = self.liveness_inner();
        if result.is_err() {
            self.revoke();
        }
        result
    }
    fn liveness_inner(&mut self) -> Result<()> {
        let now = boot_seconds();
        let sequence = self
            .clock
            .liveness_sequence
            .checked_add(1)
            .ok_or(Error::Interrupted)?;
        self.clock.liveness(&self.lifecycle, sequence, now, now)?;
        let end = Instant::now() + Duration::from_secs(2);
        for e in &self.children {
            send(
                &e.socket,
                &Command::Liveness {
                    lifecycle: self.lifecycle.clone(),
                    sequence,
                    sent_at: now,
                },
            )?;
        }
        for e in &self.children {
            match wait_ack(&e.socket, &e.child, end)? {
                Ack::Liveness {
                    lifecycle,
                    scope,
                    sequence: actual,
                } if lifecycle == self.lifecycle
                    && scope == e.identity.scope
                    && actual == sequence => {}
                _ => {
                    self.clock.terminal = true;
                    return Err(Error::DescriptorPolicy);
                }
            }
        }
        self.clock.check(boot_seconds())
    }
}
/// Runs only after fixed child confinement. No caller policy or FD arrives over
/// IPC. Parent death/closed channel/invalid frame and expiry are terminal.
pub(super) struct ChildBinding<'a> {
    pub binding: &'a Binding,
    pub lifecycle: &'a str,
    pub scope: u8,
    pub started_at: f64,
}
#[allow(clippy::too_many_arguments)]
pub(super) fn run_child(
    socket: impl AsFd,
    guard: impl AsFd,
    timer: impl AsFd,
    guard_identity: &kernel::TerminalGuardIdentity,
    completion: Option<std::os::fd::BorrowedFd<'_>>,
    #[cfg(test)] checkpoint: bool,
    mut writer: TerminalQuarantine,
    mut recovery: TerminalQuarantine,
    init: ChildBinding<'_>,
) -> Result<()> {
    let ChildBinding {
        binding,
        lifecycle,
        scope,
        started_at,
    } = init;
    let mut clock = LeaseClock::new(binding.clone(), lifecycle.into(), started_at)?;
    let ns = writer.namespace();
    if let Some(completion) = completion {
        send(
            completion,
            &owner::Notice::Started {
                lifecycle: lifecycle.into(),
                scope,
                namespace: Identity {
                    dev: ns.0,
                    ino: ns.1,
                },
                started_at,
            },
        )?;
    }
    send(
        &socket,
        &Ack::Registered {
            lifecycle: lifecycle.into(),
            scope,
            namespace: Identity {
                dev: ns.0,
                ino: ns.1,
            },
        },
    )?;
    let run = (|| -> Result<()> {
        loop {
            clock.check(boot_seconds())?;
            arm(&timer, clock.trigger())?;
            let mut fds = [
                PollFd::new(&socket, PollFlags::IN),
                PollFd::new(&guard, PollFlags::IN),
                PollFd::new(&timer, PollFlags::IN),
            ];
            poll(&mut fds, None).map_err(|_| Error::Deadline)?;
            clock.check(boot_seconds())?;
            if !fds[1].revents().is_empty() || !fds[2].revents().is_empty() {
                return Err(Error::Deadline);
            }
            let message = receive::<Command>(&socket)?.ok_or(Error::DescriptorPolicy)?;
            match message {
                Command::Health { message } => {
                    let at = boot_seconds();
                    let deadline = clock.accept(&message, at)?;
                    if let Some(completion) = completion {
                        send(
                            completion,
                            &owner::Notice::Health {
                                message: message.clone(),
                                at,
                            },
                        )?;
                    }
                    send(
                        &socket,
                        &Ack::Lease {
                            lifecycle: lifecycle.into(),
                            scope,
                            sequence: message.sequence,
                            deadline,
                        },
                    )?;
                }
                Command::Liveness {
                    lifecycle: received,
                    sequence,
                    sent_at,
                } => {
                    let at = boot_seconds();
                    clock.liveness(&received, sequence, sent_at, at)?;
                    if let Some(completion) = completion {
                        send(
                            completion,
                            &owner::Notice::Liveness {
                                lifecycle: received.clone(),
                                sequence,
                                sent_at,
                                at,
                            },
                        )?;
                    }
                    send(
                        &socket,
                        &Ack::Liveness {
                            lifecycle: lifecycle.into(),
                            scope,
                            sequence,
                        },
                    )?;
                }
            }
        }
    })();
    clock.terminal = true;
    let deadline = clock.deadline.min(clock.liveness_deadline);
    let stopped = kernel::stop_terminal_guard(&guard, guard_identity, deadline).is_ok();
    // Signal delivery is NOT kernel transaction drainage. Only the actual
    // generation-changing commit plus exact read-back can fence stale writers.
    let bounded = BootDeadline::at(deadline).and_then(|d| writer.contain(d));
    let outcome = if bounded.is_ok() && stopped && boot_seconds() < deadline {
        TerminalResult::VerifiedBeforeDeadline
    } else {
        // A distinct pre-opened one-shot socket attempts bounded best effort.
        // It never turns a missed original deadline into a timely success.
        let late = BootDeadline::at(boot_seconds() + MARGIN).and_then(|d| recovery.contain(d));
        if !stopped {
            TerminalResult::StopFailed
        } else if late.is_ok() {
            TerminalResult::LateVerified
        } else {
            TerminalResult::Failed
        }
    };
    let finished_at = boot_seconds();
    if let Some(completion) = completion {
        send(
            completion,
            &owner::Notice::Terminal {
                lifecycle: lifecycle.into(),
                scope,
                outcome: outcome.clone(),
                deadline,
                finished_at,
            },
        )?;
    }
    let _ = send(
        &socket,
        &Ack::Terminal {
            lifecycle: lifecycle.into(),
            scope,
            outcome,
            deadline,
            finished_at,
        },
    );
    #[cfg(test)]
    if checkpoint {
        kernel::terminal_after_containment()?;
    }
    run
}
fn arm(timer: impl AsFd, at: f64) -> Result<()> {
    let value = rustix::time::Timespec::try_from(
        Duration::try_from_secs_f64(at).map_err(|_| Error::Deadline)?,
    )
    .map_err(|_| Error::Deadline)?;
    rustix::time::timerfd_settime(
        timer,
        rustix::time::TimerfdTimerFlags::ABSTIME,
        &rustix::time::Itimerspec {
            it_interval: rustix::time::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: value,
        },
    )
    .map(|_| ())
    .map_err(|_| Error::Deadline)
}
#[cfg(test)]
pub(super) fn lab_run(
    a: &super::Admission,
    mut guard: super::transport::GuardTransport<'_>,
    dir: &std::path::Path,
    store: &vprouter_core::allocation::AllocationStore,
    guard_death: bool,
    inspect_actual: bool,
    authority: &vprouter_network::HostAuthority,
) -> Result<()> {
    use vprouter_core::{health::Snapshot, state::HealthMachine};
    let cfg = super::transport_lab::health_configuration_at(
        &a.spec,
        &guard.lab_plan().endpoint().ip().to_string(),
    )?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::InvalidSpec)?;
    let binding = vprouter_linux::status::expected_binding(&cfg, 0, a.spec.generation, boot.trim())
        .map_err(|_| Error::InvalidSpec)?;
    let bytes = vprouter_linux::storage::read(
        std::path::Path::new("/var/lib/vprouter-v2-lab/owner-domain-nonce"),
        vprouter_linux::storage::Kind::SecretFile,
        64,
    )
    .map_err(|_| Error::LabRequired)?;
    let lifecycle = std::str::from_utf8(&bytes)
        .map_err(|_| Error::LabRequired)?
        .to_owned();
    let domains = super::supervision::Domains::new(&a.spec, &lifecycle)?;
    let mut expiry = guard.owner_expiry(domains.clone(), binding.clone())?;
    if guard_death {
        expiry.stop_host_after_containment();
    }
    let (checkpoint, ready) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let checkpoint_inventory = super::inventory::Registration::owned(&[checkpoint.as_fd()])?;
    let ready_inventory = super::inventory::Registration::owned(&[ready.as_fd()])?;
    let bundle = super::programs::ReviewedBundle::current()?;
    let inspection_policy = if inspect_actual {
        Some(guard.inspection_policy(a, &bundle, kernel::DaemonConfiguration::Unenrolled)?)
    } else {
        None
    };
    let mut inputs = guard.guard_inputs(&domains, inspect_actual.then_some(a))?;
    inputs.lab_checkpoint(&ready_inventory)?;
    let external = super::owner::ExternalOwner::spawn(domains.clone(), inputs, |owner| {
        let scenario_started = boot_seconds();
        eprintln!(
            "LAB_EXPIRY_FIXTURE_PHASE phase=guard_started at={scenario_started} inspect_actual={inspect_actual}"
        );
        guard.bind_remote(owner)?;
        let mut executors = guard.start_expiry(binding.clone(), &lifecycle)?;
        let dead_peer = if inspect_actual {
            Some(super::actual_lab::owner_inspection_component(
                a, &mut guard, &bundle,
            )?)
        } else {
            None
        };
        eprintln!(
            "LAB_EXPIRY_FIXTURE_PHASE phase=actual_inspection_complete at={} elapsed={}",
            boot_seconds(),
            boot_seconds() - scenario_started
        );
        let mut machine = HealthMachine::new(
            binding.mode,
            binding.expected_server.as_deref(),
            &binding.node_id,
        )
        .map_err(|_| Error::InvalidSpec)?;
        let mut sequence = 0;
        for _ in 0..4 {
            lab_sample(
                &mut guard,
                &mut executors,
                &mut machine,
                &binding,
                &lifecycle,
                &mut sequence,
                0.,
            )?;
        }
        guard.ready_with_executors(&mut executors)?;
        let ready_snapshot =
            Snapshot::from_machine(binding.clone(), sequence, boot_seconds(), &machine)
                .map_err(|_| Error::DescriptorPolicy)?;
        guard.lab_operational_ready_publication(&mut executors, &ready_snapshot)?;
        super::lab::case(
            "operational_repeated_ready_revalidates_and_private_publication_proof_binds_exact_snapshot",
        );

        super::lab::case(
            "native_ready_requires_three_executor_leases_and_independent_guard_recovery_streak_synthetic_evidence",
        );
        machine.block(vprouter_core::reason::Reason::ProviderFailure);
        sequence += 1;
        let now = boot_seconds();
        guard.lease_health(
            &mut executors,
            &HealthMessage {
                version: 1,
                lifecycle: lifecycle.clone(),
                sequence,
                sent_at: now,
                snapshot: Some(
                    Snapshot::from_machine(binding.clone(), sequence, now, &machine)
                        .map_err(|_| Error::DescriptorPolicy)?,
                ),
            },
        )?;
        guard.audit()?;
        for _ in 0..4 {
            lab_sample(
                &mut guard,
                &mut executors,
                &mut machine,
                &binding,
                &lifecycle,
                &mut sequence,
                0.,
            )?;
        }
        guard.ready_with_executors(&mut executors)?;
        super::lab::case(
            "ordinary_provider_failure_quarantine_health_bootstrap_four_fresh_samples_restore_native_ready_synthetic_evidence",
        );
        // A fresh original handshake observation with7s remaining selects the
        // independent earliest deadline;44s evidence and5s margin stay unchanged.
        lab_sample(
            &mut guard,
            &mut executors,
            &mut machine,
            &binding,
            &lifecycle,
            &mut sequence,
            173.,
        )?;
        executors.liveness()?;
        eprintln!(
            "LAB_EXPIRY_FIXTURE_PHASE phase=ready_checkpoint at={} elapsed={}",
            boot_seconds(),
            boot_seconds() - scenario_started
        );
        kernel::lab_terminal_checkpoint(&ready)?;
        if let Some(token) = dead_peer {
            // Target was actually stopped and reaped above; the owner must
            // reject fresh native reinspection and freeze this lifecycle.
            let _ = owner
                .journal()
                .inspect(super::inspection::Request::Reinspect { token });
        }
        // The owner freezes/kills this generation; no expired actor is resumed.
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    })?;
    drop(ready_inventory);
    drop(checkpoint_inventory);
    drop(ready);
    let _checkpoint_inventory = super::inventory::Registration::owned(&[checkpoint.as_fd()])?;
    let (tx, namespaces) = guard.lab_journal_parts();
    let mut journals = [super::owned::JournalServer::new(
        tx, &a.spec, namespaces, domains, binding,
    )?];
    let mut owners = [external];
    owners[0].install_expiry(expiry, &mut journals[0]);
    owners[0].install_host_audit(authority, &mut journals[0]);
    if let Some(policy) = inspection_policy {
        owners[0].install_inspection(policy, &mut journals[0]);
    }
    // This test-only envelope covers two workloads when inspect_actual is set:
    // native daemon/sender inspection, then the existing synthetic health cycle.
    // Each contributes the original 30s harness allowance. Establish one fixed
    // aggregate deadline, never renew it or any product/job/lease clock. The
    // original 2s requests and independent expiry actors still enforce failure.
    let scenario_started = boot_seconds();
    let allowance = if inspect_actual { 60. } else { 30. };
    let deadline = scenario_started + allowance;
    eprintln!(
        "LAB_EXPIRY_FIXTURE_WAIT phase=start started_at={scenario_started} deadline={deadline} allowance={allowance} inspect_actual={inspect_actual}"
    );
    loop {
        super::owner::DeploymentOwner::new(&mut owners, &mut journals)?.poll_once()?;
        let mut byte = [0u8; 1];
        match net::recv(&checkpoint, &mut byte, RecvFlags::DONTWAIT) {
            Ok((1, 1)) if byte == [1] => {
                let now = boot_seconds();
                let pending = super::owner::DeploymentOwner::new(&mut owners, &mut journals)?
                    .lab_pending_frame(0);
                eprintln!(
                    "LAB_EXPIRY_FIXTURE_WAIT phase=checkpoint started_at={scenario_started} deadline={deadline} at={now} elapsed={} owner_terminal={:?} last_sequence={} pending={pending:?}",
                    now - scenario_started,
                    owners[0].lab_terminal_reason(),
                    owners[0].lab_last_sequence()
                );
                break;
            }
            Err(rustix::io::Errno::AGAIN) => {}
            _ => return Err(Error::DescriptorPolicy),
        }
        let now = boot_seconds();
        if now >= deadline {
            let pending = super::owner::DeploymentOwner::new(&mut owners, &mut journals)?
                .lab_pending_frame(0);
            eprintln!(
                "LAB_EXPIRY_FIXTURE_WAIT phase=timeout started_at={scenario_started} deadline={deadline} at={now} elapsed={} owner_terminal={:?} last_sequence={} pending={pending:?}",
                now - scenario_started,
                owners[0].lab_terminal_reason(),
                owners[0].lab_last_sequence()
            );
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let identities = owners[0].lab_executor_identities()?;
    let handles = owners[0].lab_executor_native_handles()?;
    let stopped_start = if inspect_actual {
        let start = owners[0].lab_identity()?.1;
        let end = boot_seconds() + 3.;
        while owners[0].lab_terminal_reason().is_none() {
            owners[0].lab_poll_terminal(&mut journals[0])?;
            if boot_seconds() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        owners[0].lab_stopped(start)?;
        start
    } else if guard_death {
        let start = owners[0].lab_identity()?.1;
        owners[0].lab_kill()?;
        start
    } else {
        owners[0].lab_stop()?
    };
    super::lab::case(
        "three_owned_independent_expiry_actors_original_leases_actual_guard_stop_or_death",
    );
    let end = boot_seconds() + 10.;
    loop {
        // The parent remains the sole journal writer after guard T/death.
        // It uses private fixed-executor receipts, never guard completion RPC.
        owners[0].lab_poll_terminal(&mut journals[0])?;
        if guard.lab_verify_terminal(&lifecycle).is_ok()
            && journals[0].lab_terminal_completions() == 3
            && owners[0].lab_executor_drained() == if guard_death { 2 } else { 3 }
        {
            break;
        }
        if boot_seconds() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if !guard_death {
        owners[0].lab_stopped(stopped_start)?;
    }
    if inspect_actual {
        if !owners[0].lab_dead_peer_rejected() {
            return Err(Error::OwnershipMismatch);
        }
        super::lab::case(
            "actual_owner_reinspection_rejects_reaped_peer_revokes_incarnation_and_actually_drains_inspector",
        );
    }
    let bytes =
        std::fs::read(dir.join("records/namespaces.json")).map_err(|_| Error::Interrupted)?;
    let journal: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::Interrupted)?;
    let terminal = &journal["entries"][0]["terminal"];
    if terminal["lifecycle"] != lifecycle
        || terminal["executors"]
            .as_array()
            .is_none_or(|a| a.len() != 3)
        || terminal["completions"].as_array().is_none_or(|a| {
            a.len() != 3 || a.iter().any(|c| c["result"] != "verified_before_deadline")
        })
    {
        return Err(Error::Interrupted);
    }
    let witness = guard.lab_terminal_witness()?;
    witness.verify(&lifecycle)?;
    if guard_death {
        // Scope0 has already contained, emitted its authentic completion, and
        // stopped itself before exit. Other writers must actually be dead.
        let host_start = identities[0].start_time;
        let end = boot_seconds() + 2.;
        loop {
            if handles[0].lab_require_stopped(host_start).is_ok()
                && handles[1].lab_is_dead()?
                && handles[2].lab_is_dead()?
            {
                break;
            }
            if boot_seconds() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(journals);
        drop(owners);
        drop(guard);
        if !store
            .lock()
            .is_err_and(|e| e.reason() == vprouter_core::reason::Reason::LockBusy)
        {
            return Err(Error::LockBusy);
        }
        handles[0].lab_require_stopped(host_start)?;
        handles[0].lab_signal(libc::SIGKILL)?;
        handles[0].lab_wait_killed()?;
        drop(store.lock().map_err(|_| Error::LockBusy)?);
        witness.verify(&lifecycle)?;
        let mut transaction = Transaction::open(
            store,
            &dir.join("records"),
            &a.spec,
            "one",
            a.process.base_network(),
        )?;
        if transaction.acquire(&a.spec, a.process.base_network()).err() != Some(Error::Interrupted)
            || transaction.transport_cleaned(&a.spec) != Err(Error::Interrupted)
        {
            return Err(Error::Interrupted);
        }
        super::lab::write(&dir.join("terminal-guard-death-witness.json"), &serde_json::to_vec(&serde_json::json!({"guard_killed":true,"surviving_executor_lock_verified":true,"other_executor_pidfds_exited_before_lock_assertion":true,"survivor_stop_start_time":host_start,"terminal_host_transport_data_exact":true,"all_executors_exited":true,"reacquire_refused":true,"cleanup_refused":true,"operational_ready":false,"bounded_containment_claim":true,"identities":identities,"completions":terminal["completions"],"post_containment_checkpoint":true,"expired_actor_resumed":false})).map_err(|_| Error::Interrupted)?)?;
        super::lab::case(
            "actual_guard_death_three_scope_containment_parent_durable_completion_sole_survivor_lease_until_killed",
        );
    } else {
        owners[0].lab_kill_stopped(stopped_start)?;
        super::lab::write(&dir.join("terminal-executor-witness.json"), &serde_json::to_vec(&serde_json::json!({"synthetic_evidence":true,"operational_ready":false,"guard_frozen":true,"terminal_host_transport_data_exact":true,"lifecycle":lifecycle,"stopped_start_time":stopped_start,"stop_observed_before_and_after_containment":true,"executors":terminal["executors"],"completions":terminal["completions"],"retained_ownership":true,"expired_actor_resumed":false})).map_err(|_| Error::Interrupted)?)?;
        super::lab::case(
            "independent_frozen_guard_terminal_host_transport_data_exact_parent_durable_completion_without_resume",
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn lab_sample(
    guard: &mut super::transport::GuardTransport<'_>,
    executors: &mut Executors,
    machine: &mut vprouter_core::state::HealthMachine,
    binding: &Binding,
    lifecycle: &str,
    sequence: &mut u64,
    handshake_age: f64,
) -> Result<()> {
    use vprouter_core::{
        health::Snapshot,
        state::{Evidence, VerificationResult},
    };
    let now = boot_seconds();
    *sequence += 1;
    machine
        .observe(
            now,
            Evidence {
                provider_ok: true,
                structural_ok: true,
                provider_at: now,
                structural_at: now,
                heartbeat_at: now,
                handshake_age_seconds: Some(handshake_age),
                online: true,
                policy_approved: true,
                server: binding.expected_server.clone(),
                node_id: Some(binding.node_id.clone()),
                egress: Some("1.1.1.1".parse().map_err(|_| Error::InvalidSpec)?),
                verified_at: Some(now),
                dns: VerificationResult::NotTested,
                ipv6: VerificationResult::NotTested,
            },
        )
        .map_err(|_| Error::DescriptorPolicy)?;
    guard.lease_health(
        executors,
        &HealthMessage {
            version: 1,
            lifecycle: lifecycle.into(),
            sequence: *sequence,
            sent_at: now,
            snapshot: Some(
                Snapshot::from_machine(binding.clone(), *sequence, now, machine)
                    .map_err(|_| Error::DescriptorPolicy)?,
            ),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            deployment_id: "test".into(),
            exit_id: "one".into(),
            mode: vprouter_core::config::ExitMode::Mullvad,
            generation: 1,
            display_name: "test-exit".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "node".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        }
    }
    #[test]
    fn claimed_ready_snapshot_cannot_skip_guards_independent_recovery_streak() {
        use vprouter_core::{
            health::Snapshot,
            state::{Evidence, HealthMachine, VerificationResult},
        };
        let binding = binding();
        let make = || {
            HealthMachine::new(
                binding.mode,
                binding.expected_server.as_deref(),
                &binding.node_id,
            )
            .unwrap()
        };
        let mut producer = make();
        let mut guard = make();
        let mut frames = Vec::new();
        for sequence in 1..=4 {
            let now = 100. + sequence as f64;
            producer
                .observe(
                    now,
                    Evidence {
                        provider_ok: true,
                        structural_ok: true,
                        provider_at: now,
                        structural_at: now,
                        heartbeat_at: now,
                        handshake_age_seconds: Some(0.),
                        online: true,
                        policy_approved: true,
                        server: binding.expected_server.clone(),
                        node_id: Some(binding.node_id.clone()),
                        egress: Some("1.1.1.1".parse().unwrap()),
                        verified_at: Some(now),
                        dns: VerificationResult::NotTested,
                        ipv6: VerificationResult::NotTested,
                    },
                )
                .unwrap();
            frames.push(HealthMessage {
                version: 1,
                lifecycle: "a".repeat(64),
                sequence,
                sent_at: now,
                snapshot: Some(
                    Snapshot::from_machine(binding.clone(), sequence, now, &producer).unwrap(),
                ),
            });
        }
        assert!(observe_original(&mut guard, &frames[3], 104.).is_err());
        let mut guard = make();
        for (i, frame) in frames.iter().enumerate() {
            let state = observe_original(&mut guard, frame, 101. + i as f64).unwrap();
            assert_eq!(state == vprouter_core::state::HealthState::Ready, i == 3);
        }
        producer.block(vprouter_core::reason::Reason::ProviderFailure);
        let failed = HealthMessage {
            version: 1,
            lifecycle: "a".repeat(64),
            sequence: 5,
            sent_at: 105.,
            snapshot: Some(Snapshot::from_machine(binding.clone(), 5, 105., &producer).unwrap()),
        };
        assert_eq!(
            observe_original(&mut guard, &failed, 105.).unwrap(),
            vprouter_core::state::HealthState::Blocked
        );
        let mut evidence = frames[3]
            .snapshot
            .as_ref()
            .unwrap()
            .evidence
            .clone()
            .unwrap();
        for sequence in 6..=9 {
            let now = 100. + sequence as f64;
            evidence.provider_at = now;
            evidence.structural_at = now;
            evidence.heartbeat_at = now;
            evidence.verified_at = Some(now);
            producer.observe(now, evidence.clone()).unwrap();
            let next = HealthMessage {
                version: 1,
                lifecycle: "a".repeat(64),
                sequence,
                sent_at: now,
                snapshot: Some(
                    Snapshot::from_machine(binding.clone(), sequence, now, &producer).unwrap(),
                ),
            };
            let state = observe_original(&mut guard, &next, now).unwrap();
            assert_eq!(
                state == vprouter_core::state::HealthState::Ready,
                sequence == 9
            );
        }
    }
    #[test]
    fn terminal_health_deadline_cannot_be_renewed_by_liveness_or_replayed_health() {
        let mut clock = LeaseClock::new(binding(), "a".repeat(64), 100.).unwrap();
        for sequence in 1..=30 {
            clock
                .liveness(
                    &"a".repeat(64),
                    sequence,
                    100. + sequence as f64,
                    100. + sequence as f64,
                )
                .unwrap();
        }
        assert_eq!(clock.deadline, 144.);
        assert_eq!(clock.trigger(), 139.);
        assert!(clock.check(139.).is_err());
        assert!(clock.liveness(&"a".repeat(64), 31, 130., 130.).is_err());
        let mut clock = LeaseClock::new(binding(), "a".repeat(64), 100.).unwrap();
        let msg = HealthMessage {
            version: 1,
            lifecycle: "a".repeat(64),
            sequence: 1,
            sent_at: 101.,
            snapshot: None,
        };
        assert_eq!(clock.accept(&msg, 101.).unwrap(), 144.);
        assert!(clock.accept(&msg, 101.).is_err());
        let mut next = msg;
        next.sequence = 2;
        assert!(clock.accept(&next, 101.).is_err());
    }
    #[test]
    fn terminal_publication_is_evidence_free_reason_bound_and_cannot_revive_authority() {
        use vprouter_core::{
            health::Snapshot,
            reason::Reason,
            state::{HealthMachine, HealthState},
        };
        for failed in [false, true] {
            let binding = binding();
            let make = || {
                HealthMachine::new(
                    binding.mode,
                    binding.expected_server.as_deref(),
                    &binding.node_id,
                )
                .unwrap()
            };
            let mut worker = make();
            if failed {
                worker.fail(Reason::ProviderFailure);
            } else {
                worker.stop();
            }
            let snapshot = Snapshot::from_machine(binding.clone(), 1, 101., &worker).unwrap();
            let message = HealthMessage {
                version: 1,
                lifecycle: "a".repeat(64),
                sequence: 1,
                sent_at: 101.,
                snapshot: Some(snapshot),
            };
            let mut guard = make();
            assert_eq!(
                observe_original(&mut guard, &message, 101.).unwrap(),
                worker.state()
            );
            for state in [
                HealthState::Starting,
                HealthState::Blocked,
                HealthState::Recovering,
                HealthState::Ready,
            ] {
                let mut changed = message.clone();
                changed.snapshot.as_mut().unwrap().state = state;
                assert!(observe_original(&mut guard, &changed, 101.).is_err());
                assert_eq!(guard.state(), worker.state());
            }
            let mut missing = message.clone();
            missing.snapshot.as_mut().unwrap().reason = None;
            assert!(observe_original(&mut make(), &missing, 101.).is_err());
            if !failed {
                let mut wrong = message;
                wrong.snapshot.as_mut().unwrap().reason = Some(Reason::ProviderFailure);
                assert!(observe_original(&mut make(), &wrong, 101.).is_err());
            }
        }
    }
    #[test]
    fn malformed_channel_data_and_closed_endpoint_are_terminal_errors() {
        let (a, b) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        assert!(receive::<Command>(&a).unwrap().is_none());
        net::send(&b, b"{\"kind\":\"ready\"}", SendFlags::NOSIGNAL).unwrap();
        assert!(receive::<Command>(&a).is_err());
        drop(b);
        assert!(receive::<Command>(&a).is_err());
    }
    #[test]
    fn guard_liveness_is_a_separate_ninety_second_watchdog() {
        let mut clock = LeaseClock::new(binding(), "a".repeat(64), 100.).unwrap();
        assert_eq!(clock.liveness_deadline, 190.);
        clock.liveness(&"a".repeat(64), 1, 101., 101.).unwrap();
        assert_eq!(clock.liveness_deadline, 191.);
        assert_eq!(clock.deadline, 144.);
        assert!(clock.liveness(&"a".repeat(64), 1, 102., 102.).is_err());
    }
}
