#![forbid(unsafe_code)]
//! Fixed native inspection policy and private owner incarnation registry. A
//! receipt never substitutes for a fresh native inspection on the next request.
use super::{
    Admission, Error, Result,
    daemon::{NativeDaemon, Process},
    kernel,
    owned::{OwnedNamespaces, Transaction},
    producer::{NativeSender, ProducerGroup},
    programs::{ReviewedBundle, Role},
};
use serde::{Deserialize, Serialize};
use std::os::fd::{AsFd, BorrowedFd};

const SLOTS: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PeerRole {
    Daemon,
    Observer,
    Monitor,
}
impl PeerRole {
    fn executable(self) -> Role {
        match self {
            Self::Daemon => Role::Tailscaled,
            Self::Observer => Role::WorkerObserver,
            Self::Monitor => Role::WorkerMonitor,
        }
    }
}
/// Fields are private; only a matched authenticated owner reply mints a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Token {
    incarnation: [u8; 32],
    slot: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Container,
    RegisterChild {
        pid: u32,
        role: PeerRole,
    },
    PinDaemon {
        pid: u32,
        child: u32,
        bootstrap: String,
    },
    PinSender {
        pid: u32,
        role: PeerRole,
    },
    Reinspect {
        token: Token,
    },
}
impl Request {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Container | Self::Reinspect { .. } => Ok(()),
            Self::RegisterChild { pid, .. } | Self::PinSender { pid, .. }
                if *pid > 1 && *pid <= i32::MAX as u32 =>
            {
                Ok(())
            }
            Self::PinDaemon {
                pid,
                child,
                bootstrap,
            } if *pid > 1
                && *pid <= i32::MAX as u32
                && *child > 1
                && *child <= i32::MAX as u32
                && super::spec::digest(bootstrap) =>
            {
                Ok(())
            }
            _ => Err(Error::DescriptorPolicy),
        }
    }
    fn pid(&self) -> Option<u32> {
        match self {
            Self::RegisterChild { pid, .. }
            | Self::PinDaemon { pid, .. }
            | Self::PinSender { pid, .. } => Some(*pid),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Job {
    pub sequence: u64,
    pub sent_at: f64,
    pub token: Token,
    pub operation: Request,
    #[cfg(test)]
    pub hold: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FailureKind {
    Rejected,
    DeadPinnedPeer,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Failure {
    pub job: Option<Job>,
    pub stage: u8,
    #[cfg(test)]
    pub substage: u8,
    pub reason: String,
    pub kind: FailureKind,
    pub finished_at: f64,
}
/// Only a fixed actor result over its private endpoint reaches this decoder.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub job: Job,
}
impl Receipt {
    pub(super) fn validate_reply(&self, operation: &Request) -> Result<()> {
        let token = self.job.token;
        if token.incarnation == [0; 32] || self.job.operation != *operation {
            return Err(Error::DescriptorPolicy);
        }
        #[cfg(test)]
        if self.job.hold {
            return Err(Error::DescriptorPolicy);
        }
        match operation {
            Request::Container if token.slot == 0 => Ok(()),
            Request::Reinspect { token: expected }
                if token == *expected && token.slot > 0 && token.slot as usize <= SLOTS =>
            {
                Ok(())
            }
            Request::RegisterChild { .. }
            | Request::PinDaemon { .. }
            | Request::PinSender { .. }
                if token.slot > 0 && token.slot as usize <= SLOTS =>
            {
                Ok(())
            }
            _ => Err(Error::DescriptorPolicy),
        }
    }
}

pub(super) struct Policy<'a> {
    admission: &'a Admission,
    namespaces: OwnedNamespaces,
    producer: ProducerGroup,
    bundle: &'a ReviewedBundle,
    configuration: kernel::DaemonConfiguration,
    #[cfg(test)]
    fail_after_spawn: bool,
}
impl<'a> Policy<'a> {
    /// Parent only, before guard creation. No wire-supplied policy or manifest.
    pub fn new(
        admission: &'a Admission,
        transaction: &Transaction,
        namespaces: &OwnedNamespaces,
        producer: &ProducerGroup,
        bundle: &'a ReviewedBundle,
        configuration: kernel::DaemonConfiguration,
    ) -> Result<Self> {
        transaction.require_local(&admission.spec)?;
        admission
            .process
            .revalidate(&admission.spec, &admission.staging)?;
        namespaces.bind(&admission.spec)?;
        producer.verify(transaction, &admission.spec)?;
        if bundle.digest() != ReviewedBundle::current()?.digest() {
            return Err(Error::ExecutableMismatch);
        }
        Ok(Self {
            admission,
            namespaces: namespaces.inspection_copy(&admission.spec)?,
            producer: producer.inspection_copy()?,
            bundle,
            configuration,
            #[cfg(test)]
            fail_after_spawn: false,
        })
    }
    pub fn fds(&self) -> Vec<BorrowedFd<'_>> {
        let mut fds = self.admission.process.inspection_fds();
        fds.extend(self.producer.inspection_fds());
        fds.extend([
            self.namespaces.data.as_fd(),
            self.namespaces.transport.as_fd(),
        ]);
        fds
    }
    pub fn binds(&self, allocation: &str, exit: &str) -> Result<()> {
        if self.admission.spec.exit.exit_id != exit
            || vprouter_worker::bootstrap::digest(
                &serde_json::to_vec(&self.admission.spec.allocation)
                    .map_err(|_| Error::InvalidSpec)?,
            ) != allocation
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    fn container(&self) -> Result<()> {
        self.admission
            .process
            .revalidate(&self.admission.spec, &self.admission.staging)?;
        self.namespaces.bind(&self.admission.spec)?;
        self.producer.verify_native()
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Reserved,
    Active,
    Revoked,
}
struct Slot {
    token: Token,
    request: Request,
    state: State,
}
struct Registry {
    incarnation: [u8; 32],
    slots: Vec<Slot>,
    revoked: bool,
}
impl Registry {
    fn new(incarnation: [u8; 32]) -> Self {
        Self {
            incarnation,
            slots: Vec::new(),
            revoked: false,
        }
    }
    fn reserve(&mut self, operation: &Request) -> Result<Token> {
        operation.validate()?;
        if self.revoked {
            return Err(Error::Interrupted);
        }
        if let Request::Reinspect { token } = operation {
            if self
                .slots
                .iter()
                .any(|s| s.token == *token && s.state == State::Active)
            {
                return Ok(*token);
            }
            return Err(Error::OwnershipMismatch);
        }
        if matches!(operation, Request::Container) {
            return Ok(Token {
                incarnation: self.incarnation,
                slot: 0,
            });
        }
        if self.slots.len() >= SLOTS
            || self.slots.iter().any(|s| {
                s.request.pid() == operation.pid()
                    || matches!((&s.request, operation),
                    (Request::RegisterChild {role:a,..}, Request::RegisterChild {role:b,..})
                    | (Request::PinSender {role:a,..}, Request::PinSender {role:b,..}) if a == b)
                    || matches!(
                        (&s.request, operation),
                        (Request::PinDaemon { .. }, Request::PinDaemon { .. })
                    )
            })
        {
            return Err(Error::OwnershipMismatch);
        }
        let token = Token {
            incarnation: self.incarnation,
            slot: self.slots.len() as u8 + 1,
        };
        self.slots.push(Slot {
            token,
            request: operation.clone(),
            state: State::Reserved,
        });
        Ok(token)
    }
    fn complete(&mut self, expected: &Job, receipt: &Receipt, now: f64) -> Result<()> {
        deadline(expected.sent_at, now)?;
        if self.revoked || expected != &receipt.job {
            return Err(Error::DescriptorPolicy);
        }
        if expected.token.slot != 0 {
            let slot = self
                .slots
                .iter_mut()
                .find(|s| s.token == expected.token)
                .ok_or(Error::OwnershipMismatch)?;
            if slot.state == State::Revoked {
                return Err(Error::OwnershipMismatch);
            }
            slot.state = State::Active;
        }
        Ok(())
    }
    fn revoke(&mut self) {
        self.revoked = true;
        for slot in &mut self.slots {
            slot.state = State::Revoked;
        }
    }
}
pub(super) fn deadline(sent: f64, now: f64) -> Result<()> {
    if !sent.is_finite() || !now.is_finite() || sent <= 0. || now < sent || now - sent >= 2. {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}
/// Canonical owner state survives actor cancellation until actual native reap.
pub(super) struct Service {
    actor: kernel::inspection::Actor,
    registry: Registry,
    pending: Option<Job>,
    #[cfg(test)]
    pause_next: bool,
    #[cfg(test)]
    completed: u64,
    #[cfg(test)]
    failure_reported: std::cell::Cell<bool>,
}
impl Service {
    #[cfg(test)]
    pub(super) fn lab_require_foreign_inert(&self) -> Result<()> {
        self.actor.lab_require_foreign_inert()
    }
    pub fn new(policy: Policy<'_>, guard: &kernel::Survivor) -> Result<Self> {
        use std::io::Read;
        let mut incarnation = [0; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut incarnation))
            .map_err(|_| Error::DescriptorPolicy)?;
        if incarnation == [0; 32] {
            return Err(Error::DescriptorPolicy);
        }
        #[cfg(test)]
        let fail_after_spawn = policy.fail_after_spawn;
        let actor = kernel::inspection::spawn(policy, guard, incarnation)?;
        #[cfg(test)]
        if fail_after_spawn {
            let identity = actor.lab_identity()?;
            LAB_FAILED_SETUP.with(|slot| slot.set(Some(identity)));
            eprintln!(
                "LAB_INSPECTION_SETUP_FAILURE pid={} start={} stage=post_spawn_native_actor",
                identity.0, identity.1
            );
            // Actor::drop transfers the exact pidfd and channel to early-fork
            // retention; the existing owner is terminalized in place.
            return Err(Error::DescriptorPolicy);
        }
        Ok(Self {
            actor,
            registry: Registry::new(incarnation),
            pending: None,
            #[cfg(test)]
            pause_next: false,
            #[cfg(test)]
            completed: 0,
            #[cfg(test)]
            failure_reported: std::cell::Cell::new(false),
        })
    }
    pub fn start(&mut self, operation: Request, sequence: u64, sent_at: f64) -> Result<()> {
        deadline(sent_at, vprouter_core::health::boot_seconds())?;
        if self.pending.is_some() {
            return Err(Error::Interrupted);
        }
        self.actor.require_quiet()?;
        let token = self.registry.reserve(&operation)?;
        let job = Job {
            sequence,
            sent_at,
            token,
            operation,
            #[cfg(test)]
            hold: std::mem::take(&mut self.pause_next),
        };
        self.actor.send(&job)?;
        self.pending = Some(job);
        Ok(())
    }
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn poll(&mut self) -> Result<Option<Receipt>> {
        let Some(job) = self.pending.as_ref() else {
            self.actor.require_quiet()?;
            return Ok(None);
        };
        deadline(job.sent_at, vprouter_core::health::boot_seconds())?;
        let receipt = match self.actor.receive() {
            Ok(Some(receipt)) => receipt,
            Ok(None) => return Ok(None),
            Err(error) => {
                #[cfg(test)]
                self.lab_report_failure();
                if self
                    .actor
                    .failure()
                    .is_some_and(|failure| dead_failure(job, &failure))
                {
                    deadline(job.sent_at, vprouter_core::health::boot_seconds())?;
                    return Err(Error::ProcessUnavailable);
                }
                return Err(error);
            }
        };
        self.registry
            .complete(job, &receipt, vprouter_core::health::boot_seconds())?;
        self.pending = None;
        #[cfg(test)]
        {
            self.completed += 1;
        }
        Ok(Some(receipt))
    }
    #[cfg(test)]
    fn lab_report_failure(&self) {
        if self.actor.lab_current_creator()
            && let Some(job) = self.pending.as_ref()
            && let Some(failure) = self.actor.failure()
            && !self.failure_reported.replace(true)
        {
            lab_failure_diagnostic(job, &failure);
        }
    }
    pub fn cancel(&mut self) -> Result<()> {
        self.registry.revoke();
        self.actor.cancel()
    }
    pub fn drain(&mut self) -> Result<bool> {
        let cancelled = if self.registry.revoked {
            self.actor.cancel()
        } else {
            Ok(())
        };
        let drained = self.actor.drain()?;
        #[cfg(test)]
        self.lab_report_failure();
        if !drained {
            cancelled?;
        }
        Ok(drained)
    }
    pub fn drained(&self) -> bool {
        self.actor.drained()
    }
    #[cfg(test)]
    pub fn lab_pause(&mut self) {
        self.pause_next = true;
    }
    #[cfg(test)]
    pub fn lab_completed(&self) -> u64 {
        self.completed
    }
    #[cfg(test)]
    pub fn lab_checkpoint(&mut self) -> Result<Option<(u32, u64, f64)>> {
        let Some(job) = &self.pending else {
            return Ok(None);
        };
        self.actor.lab_checkpoint(job)
    }
    #[cfg(test)]
    pub fn lab_revoked(&self) -> bool {
        self.registry.revoked
    }
    #[cfg(test)]
    pub fn lab_dead_peer_rejected(&self) -> bool {
        self.registry.revoked
            && self.actor.drained()
            && self.pending.as_ref().is_some_and(|job| {
                self.actor
                    .failure()
                    .is_some_and(|failure| dead_failure(job, &failure))
            })
    }
}

#[cfg(test)]
thread_local! { static LAB_FAILURE_TIMINGS: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
fn lab_failure_timing(job: &Job, failure: &Failure, now: f64) -> Option<(u64, u64)> {
    if failure.job.as_ref() != Some(job)
        || !job.sent_at.is_finite()
        || job.sent_at <= 0.
        || !failure.finished_at.is_finite()
        || !now.is_finite()
        || failure.finished_at < job.sent_at
        || failure.finished_at > now
    {
        return None;
    }
    let elapsed = (failure.finished_at - job.sent_at) * 1_000_000.;
    if !elapsed.is_finite() || elapsed > u64::MAX as f64 {
        return None;
    }
    Some((
        elapsed as u64,
        ((job.sent_at + 2. - failure.finished_at).max(0.) * 1_000_000.) as u64,
    ))
}
#[cfg(test)]
fn lab_failure_diagnostic(job: &Job, failure: &Failure) {
    let allowed = LAB_FAILURE_TIMINGS.with(|count| {
        let before = count.get();
        count.set(before.saturating_add(1));
        before < 8
    });
    if !allowed {
        return;
    }
    if let Some((elapsed, remaining)) =
        lab_failure_timing(job, failure, vprouter_core::health::boot_seconds())
    {
        eprintln!(
            "LAB_INSPECTION_FAILURE_JOB bound=true stage={} substage={} sequence={} sent_at={} finished_at={} elapsed_us={} original_rpc_remaining_us={}",
            failure.stage,
            failure.substage,
            job.sequence,
            job.sent_at,
            failure.finished_at,
            elapsed,
            remaining
        );
    } else {
        eprintln!(
            "LAB_INSPECTION_FAILURE_JOB bound=false stage={} substage={}",
            failure.stage, failure.substage
        );
    }
}
fn dead_failure(job: &Job, failure: &Failure) -> bool {
    failure.kind == FailureKind::DeadPinnedPeer
        && failure.reason == "process_unavailable"
        && failure.job.as_ref() == Some(job)
        && matches!(job.operation, Request::Reinspect { .. })
        && deadline(job.sent_at, failure.finished_at).is_ok()
}

enum Peer {
    Child {
        process: Process,
        role: PeerRole,
    },
    Daemon(NativeDaemon),
    Sender {
        native: NativeSender,
        chain: Vec<Process>,
    },
}
struct NativeSlot {
    token: Token,
    peer: Peer,
}
pub(super) struct Inspector<'a> {
    policy: Policy<'a>,
    guard: Process,
    incarnation: [u8; 32],
    slots: Vec<NativeSlot>,
    sequence: u64,
}
impl<'a> Inspector<'a> {
    pub fn new(policy: Policy<'a>, guard: Process, incarnation: [u8; 32]) -> Self {
        Self {
            policy,
            guard,
            incarnation,
            slots: Vec::new(),
            sequence: 0,
        }
    }
    fn root(&self, role: PeerRole, pid: Option<u32>) -> Result<&Process> {
        let mut roots = self.slots.iter().filter_map(|s| match &s.peer {
            Peer::Child {
                process,
                role: expected,
            } if *expected == role && pid.is_none_or(|p| process.pid() == p) => Some(process),
            _ => None,
        });
        let root = roots.next().ok_or(Error::PlacementFailed)?;
        if roots.next().is_some() {
            return Err(Error::PlacementFailed);
        }
        root.verify()?;
        self.guard.verify()?;
        if root.parent() != self.guard.pid() {
            return Err(Error::PlacementFailed);
        }
        Ok(root)
    }
    pub fn execute(
        &mut self,
        job: Job,
        stage: &std::cell::Cell<u8>,
        failure: &std::cell::Cell<FailureKind>,
        #[cfg(test)] substage: &std::cell::Cell<u8>,
    ) -> Result<Receipt> {
        stage.set(20);
        deadline(job.sent_at, vprouter_core::health::boot_seconds())?;
        job.operation.validate()?;
        if job.sequence <= self.sequence || job.token.incarnation != self.incarnation {
            return Err(Error::DescriptorPolicy);
        }
        self.sequence = job.sequence;
        stage.set(21);
        self.guard.verify()?;
        stage.set(22);
        self.policy.container()?;
        let p = &self.policy;
        let peer = match &job.operation {
            Request::Container => {
                if job.token.slot != 0 {
                    return Err(Error::DescriptorPolicy);
                }
                None
            }
            Request::RegisterChild { pid, role } => {
                stage.set(30);
                let child = Process::open(*pid)?;
                if child.parent() != self.guard.pid() {
                    return Err(Error::PlacementFailed);
                }
                p.producer
                    .membership(*pid, child.proc(), &p.admission.spec)?;
                child.verify()?;
                self.guard.verify()?;
                Some(Peer::Child {
                    process: child,
                    role: *role,
                })
            }
            Request::PinDaemon {
                pid,
                child,
                bootstrap,
            } => {
                stage.set(40);
                let root = self.root(PeerRole::Daemon, Some(*child))?;
                Some(Peer::Daemon(NativeDaemon::pin(
                    p.admission,
                    &p.namespaces,
                    &p.producer,
                    p.bundle,
                    root,
                    &self.guard,
                    *pid,
                    bootstrap,
                    p.configuration,
                )?))
            }
            Request::PinSender { pid, role } => {
                stage.set(50);
                if *role == PeerRole::Daemon {
                    return Err(Error::DescriptorPolicy);
                }
                let root = self.root(*role, None)?;
                let mut chain = vec![Process::open(*pid)?];
                for _ in 0..3 {
                    chain.push(Process::open(
                        chain.last().ok_or(Error::PlacementFailed)?.parent(),
                    )?);
                }
                chain[3].same(root)?;
                for process in &chain {
                    p.producer
                        .membership(process.pid(), process.proc(), &p.admission.spec)?;
                }
                let native = NativeSender::pin(
                    *pid,
                    &p.producer,
                    &p.admission.spec,
                    &p.namespaces,
                    p.bundle,
                    role.executable(),
                )?;
                if native.start() != chain[0].start() {
                    return Err(Error::ProcessChanged);
                }
                for process in &chain {
                    process.verify()?;
                    p.producer
                        .membership(process.pid(), process.proc(), &p.admission.spec)?;
                }
                self.guard.verify()?;
                Some(Peer::Sender { native, chain })
            }
            Request::Reinspect { token } => {
                stage.set(60);
                #[cfg(test)]
                substage.set(1);
                if token != &job.token {
                    return Err(Error::DescriptorPolicy);
                }
                let slot = self
                    .slots
                    .iter()
                    .find(|s| s.token == *token)
                    .ok_or(Error::OwnershipMismatch)?;
                #[cfg(test)]
                substage.set(2);
                let dead = match &slot.peer {
                    Peer::Child { process, .. } => process.exited()?,
                    Peer::Daemon(daemon) => daemon.target_exited()?,
                    Peer::Sender { native, .. } => native.target_exited()?,
                };
                if dead {
                    deadline(job.sent_at, vprouter_core::health::boot_seconds())?;
                    failure.set(FailureKind::DeadPinnedPeer);
                    return Err(Error::ProcessUnavailable);
                }
                match &slot.peer {
                    Peer::Child { process, .. } => {
                        process.verify()?;
                        p.producer
                            .membership(process.pid(), process.proc(), &p.admission.spec)?;
                    }
                    Peer::Daemon(daemon) => daemon.verify(
                        p.admission,
                        &p.namespaces,
                        &p.producer,
                        p.bundle,
                        daemon.bootstrap_digest(),
                        &self.guard,
                    )?,
                    Peer::Sender { native, chain } => {
                        #[cfg(test)]
                        native.verify_diagnostic(
                            &p.producer,
                            &p.admission.spec,
                            &p.namespaces,
                            p.bundle,
                            substage,
                        )?;
                        #[cfg(not(test))]
                        native.verify(&p.producer, &p.admission.spec, &p.namespaces, p.bundle)?;
                        for (index, process) in chain.iter().enumerate() {
                            #[cfg(test)]
                            substage.set(40 + index as u8 * 2);
                            #[cfg(not(test))]
                            let _ = index;
                            process.verify()?;
                            #[cfg(test)]
                            substage.set(41 + index as u8 * 2);
                            p.producer.membership(
                                process.pid(),
                                process.proc(),
                                &p.admission.spec,
                            )?;
                        }
                        #[cfg(test)]
                        substage.set(49);
                        if chain[3].parent() != self.guard.pid() {
                            return Err(Error::PlacementFailed);
                        }
                    }
                }
                None
            }
        };
        stage.set(70);
        self.guard.verify()?;
        deadline(job.sent_at, vprouter_core::health::boot_seconds())?;
        if let Some(peer) = peer {
            if self.slots.len() >= SLOTS || job.token.slot as usize != self.slots.len() + 1 {
                return Err(Error::DescriptorPolicy);
            }
            self.slots.push(NativeSlot {
                token: job.token,
                peer,
            });
        }
        Ok(Receipt { job })
    }
}

#[cfg(test)]
pub(super) fn lab_receipt(sequence: u64) -> Receipt {
    Receipt {
        job: Job {
            sequence,
            sent_at: vprouter_core::health::boot_seconds(),
            token: Token {
                incarnation: [7; 32],
                slot: 0,
            },
            operation: Request::Container,
            hold: false,
        },
    }
}

#[cfg(test)]
pub(super) fn lab_token(slot: u8) -> Token {
    Token {
        incarnation: [7; 32],
        slot,
    }
}

#[cfg(test)]
thread_local! {
    static LAB_FAILED_SETUP: std::cell::Cell<Option<(u32, u64)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn lab_held<'a>(
    first: &Admission,
    second: &Admission,
    a: &mut super::transport::GuardTransport<'a>,
    b: &mut super::transport::GuardTransport<'a>,
    cfg: &vprouter_core::config::ValidatedConfiguration,
    nonce: &str,
    authority: &vprouter_network::HostAuthority,
    directory: &std::path::Path,
    setup_failure: bool,
    owner_domain: &super::supervision::OwnerDomain,
    admission_stop: bool,
) -> Result<()> {
    use std::time::Duration;
    let domains_a = super::supervision::Domains::new(&first.spec, nonce)?;
    let domains_b = super::supervision::Domains::new(
        &second.spec,
        &vprouter_worker::bootstrap::digest(format!("inspector-neighbor:{nonce}").as_bytes()),
    )?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::InvalidSpec)?;
    let binding_a =
        vprouter_linux::status::expected_binding(cfg, 0, first.spec.generation, boot.trim())
            .map_err(|_| Error::InvalidSpec)?;
    let binding_b =
        vprouter_linux::status::expected_binding(cfg, 1, second.spec.generation, boot.trim())
            .map_err(|_| Error::InvalidSpec)?;
    let bundle = ReviewedBundle::current()?;
    let mut policy_a =
        a.inspection_policy(first, &bundle, kernel::DaemonConfiguration::Unenrolled)?;
    policy_a.fail_after_spawn = setup_failure;
    let expiry_a = if setup_failure {
        Some(a.owner_expiry(domains_a.clone(), binding_a.clone())?)
    } else {
        None
    };
    let policy_b = b.inspection_policy(second, &bundle, kernel::DaemonConfiguration::Unenrolled)?;
    let mut owner_a = super::owner::ExternalOwner::spawn(
        domains_a.clone(),
        a.guard_inputs(&domains_a, None)?,
        |owner| {
            a.bind_remote(owner)?;
            loop {
                if owner.journal().inspect(Request::Container).is_err() {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        },
    )?;
    // Hot-add boundary: A's canonical journal, host factory, optional expiry
    // factory and real private inspector are LIVE before B's actual guard fork.
    let (tx_a, ns_a) = a.lab_journal_parts();
    let mut journal_a =
        super::owned::JournalServer::new(tx_a, &first.spec, ns_a, domains_a, binding_a)?;
    owner_a.install_host_audit(authority, &mut journal_a);
    if let Some(expiry) = expiry_a {
        owner_a.install_expiry(expiry, &mut journal_a);
    }
    owner_a.install_inspection(policy_a, &mut journal_a);
    if admission_stop {
        journal_a.lab_hold_next_read()?;
    }
    let (tx_b, ns_b) = b.lab_journal_parts();
    let mut journal_b = super::owned::JournalServer::new_owned(
        tx_b,
        &second.spec,
        ns_b,
        domains_b.clone(),
        binding_b,
        owner_domain,
    )?;
    let inputs_b = b.guard_inputs_owned(&domains_b, owner_domain, None)?;
    journal_b.start_attempt(owner_domain)?;
    let mut held_read = None;
    let mut plan = None;
    loop {
        super::owner::DeploymentOwner::new(
            std::slice::from_mut(&mut owner_a),
            std::slice::from_mut(&mut journal_a),
        )?
        .poll_once()?;
        if admission_stop && held_read.is_none() {
            held_read = journal_a.lab_checkpoint()?;
        }
        if plan.is_none() {
            plan = journal_b.poll_attempt()?;
        }
        if plan.is_some() && (!admission_stop || held_read.is_some()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let plan = plan.ok_or(Error::OwnershipMismatch)?;
    let wrong_member = super::supervision::Domains::new(&first.spec, domains_b.lifecycle())?;
    plan.lab_reject_other_member(
        &wrong_member,
        owner_domain,
        a.guard_inputs_owned(&wrong_member, owner_domain, None)?,
    )?;
    let mut pending_b = super::owner::PendingOwner::fork(
        domains_b.clone(),
        owner_domain,
        plan,
        inputs_b,
        &mut journal_b,
        |owner| {
            owner_a.lab_require_foreign_inert_and_drop_inspector()?;
            if journal_a.fence() != Err(Error::OwnershipMismatch) {
                return Err(Error::OwnershipMismatch);
            }
            super::inventory::verify()?;
            eprintln!(
                "LAB_GUARD_HOT_ADD private_native_excluded=true foreign_actor_drop_inert=true foreign_journal_fence_refused=true"
            );
            b.bind_remote(owner)?;
            loop {
                if owner.journal().inspect(Request::Container).is_err() {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        },
    )?;
    if admission_stop {
        let birth = pending_b.lab_birth()?;
        let a_identity = owner_a.lab_identity()?;
        let before = std::fs::read(directory.join("records/namespaces.json"))
            .map_err(|_| Error::Interrupted)?;
        let held_read = held_read.ok_or(Error::OwnershipMismatch)?;
        if journal_a.lab_stopped_read()? != held_read
            || journal_a.native_drained()
            || owner_a.lab_terminal_reason().is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        eprintln!(
            "LAB_ADMISSION_HELD_READ {}",
            serde_json::json!({"pid":held_read.0,
            "start":held_read.1,"original_deadline":held_read.2,"native_stopped":true,"never_resume":true})
        );
        let native_births = kernel::lab_native_births();
        kernel::lab_queue_owner_stop()?;
        let result = super::owner::DeploymentOwner::new(
            std::slice::from_mut(&mut owner_a),
            std::slice::from_mut(&mut journal_a),
        )?
        .poll_admission(&mut pending_b, &mut journal_b);
        if !matches!(result, Err(Error::Interrupted))
            || kernel::lab_native_births() != native_births
        {
            return Err(Error::ChildFailed);
        }
        let end = vprouter_core::health::boot_seconds() + 10.;
        loop {
            let drained = super::owner::DeploymentOwner::new(
                std::slice::from_mut(&mut owner_a),
                std::slice::from_mut(&mut journal_a),
            )?
            .poll_once()?;
            if drained
                && (!journal_a.native_drained()
                    || !journal_b.native_drained()
                    || !owner_a.lab_terminal_native_drained())
            {
                return Err(Error::OwnershipMismatch);
            }
            if drained
                && kernel::early_forks_drained()
                && journal_a.drain()?
                && journal_b.drain()?
            {
                break;
            }
            if vprouter_core::health::boot_seconds() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if Process::open(birth.pid).is_ok_and(|process| process.start() == birth.start)
            || std::fs::read(directory.join("records/namespaces.json"))
                .map_err(|_| Error::Interrupted)?
                != before
            || owner_a.lab_terminal_reason() != Some(Error::Interrupted)
            || Process::open(held_read.0).is_ok_and(|process| process.start() == held_read.1)
            || journal_a.lab_retired_read() != Some(held_read.2)
            || owner_a.lab_abandoned_read() != Some(held_read.2)
        {
            return Err(Error::OwnershipMismatch);
        }
        owner_a.lab_kill_stopped(a_identity.1)?;
        println!(
            "{}",
            serde_json::json!({"case":"actual_owner_stop_latched_across_existing_and_pending_member_before_release",
            "pending_pid":birth.pid,"pending_start":birth.start,"original_gate_deadline":birth.gate_deadline,
            "native_births_unchanged_after_stop":true,"pending_actual_reaped":true,
            "held_read_pid":held_read.0,"held_read_start":held_read.1,"held_read_original_deadline":held_read.2,
            "held_read_native_stopped_before_signal":true,"held_read_actual_reaped":true,
            "held_read_never_resumed":true,"held_read_progress_retained_without_ack":true,
            "a_journal_actual_drained":true,"b_journal_actual_drained":true,"host_audit_actual_drained":true,
            "planned_record_retained_without_birth_receipt":true,"no_guard_release":true,"component_only":true})
        );
        super::lab::case(
            "actual_owner_stop_latched_across_existing_and_pending_member_before_release",
        );
        return Ok(());
    }
    let owner_b = loop {
        let mut deployment = super::owner::DeploymentOwner::new(
            std::slice::from_mut(&mut owner_a),
            std::slice::from_mut(&mut journal_a),
        )?;
        if let Some(owner) = deployment.poll_admission(&mut pending_b, &mut journal_b)? {
            break owner;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let setup_reaped_before_admission_complete = if setup_failure {
        let actor = LAB_FAILED_SETUP
            .with(|slot| slot.get())
            .ok_or(Error::OwnershipMismatch)?;
        kernel::lab_early_reap(actor)?.is_some()
    } else {
        false
    };
    let (pid, start, born, gate) = journal_b.lab_attempt_released()?;
    if owner_b.lab_identity()? != (pid, start) {
        return Err(Error::OwnershipMismatch);
    }
    eprintln!(
        "LAB_GUARD_ATTEMPT {}",
        serde_json::json!({"phase":"released",
        "owner_epoch_precedes_resources":true,"planned_before_clone":true,
        "birth_durable_before_placement":true,"release_durable_before_gate":true,
        "pid":pid,"start":start,"born_at":born,"gate_deadline":gate,
        "a_inspections_during_admission":owner_a.lab_inspection_completed()})
    );
    let mut journals = [journal_a, journal_b];
    let mut owners = [owner_a, owner_b];
    owners[1].install_host_audit(authority, &mut journals[1]);
    owners[1].install_inspection(policy_b, &mut journals[1]);
    let identities = [owners[0].lab_identity()?, owners[1].lab_identity()?];
    let before =
        std::fs::read(directory.join("records/namespaces.json")).map_err(|_| Error::Interrupted)?;
    if setup_failure {
        return lab_setup_failure(
            &mut owners,
            &mut journals,
            identities,
            directory,
            &before,
            setup_reaped_before_admission_complete,
        );
    }
    let mut held = None;
    let mut pause = false;
    let mut terminal_at = None;
    let mut b_at_hold = 0;
    let mut b_at_terminal = 0;
    let mut b_final = 0;
    let mut a_before_hold = 0;
    let end = vprouter_core::health::boot_seconds() + 15.;
    {
        let mut deployment = super::owner::DeploymentOwner::new(&mut owners, &mut journals)?;
        loop {
            let done = deployment.poll_once()?;
            if !pause
                && deployment.lab_inspection_completed(0) >= 2
                && deployment.lab_inspection_completed(1) >= 2
            {
                deployment.lab_pause_inspection(0)?;
                pause = true;
            }
            if pause && held.is_none() {
                held = deployment.lab_inspection_checkpoint(0)?;
                if held.is_some() {
                    b_at_hold = deployment.lab_inspection_completed(1);
                    a_before_hold = deployment.lab_inspection_completed(0);
                }
            }
            if terminal_at.is_none() && deployment.lab_terminal(0).is_some() {
                let (_, _, deadline) = held.ok_or(Error::OwnershipMismatch)?;
                let now = vprouter_core::health::boot_seconds();
                if deployment.lab_terminal(0) != Some(Error::Deadline)
                    || now < deadline
                    || now - deadline > 0.5
                {
                    return Err(Error::Deadline);
                }
                terminal_at = Some(now);
                b_at_terminal = deployment.lab_inspection_completed(1);
                if b_at_terminal < b_at_hold + 2 {
                    return Err(Error::Deadline);
                }
            }
            if terminal_at.is_some()
                && deployment.lab_inspection_completed(1) >= b_at_terminal + 2
                && deployment.lab_inspection_drained_revoked(0)
                && deployment.lab_terminal(1).is_none()
            {
                b_final = deployment.lab_inspection_completed(1);
                if deployment.lab_inspection_completed(0) != a_before_hold {
                    return Err(Error::DescriptorPolicy);
                }
                deployment.lab_terminate(1);
            }
            if done {
                if b_final == 0
                    || !deployment.lab_inspection_drained_revoked(0)
                    || !deployment.lab_inspection_drained_revoked(1)
                    || !deployment.lab_guard_stopped(0, identities[0].1)?
                    || !deployment.lab_guard_stopped(1, identities[1].1)?
                {
                    return Err(Error::OwnershipMismatch);
                }
                break;
            }
            if vprouter_core::health::boot_seconds() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    for (owner, (_, start)) in owners.iter().zip(identities) {
        owner.lab_kill_stopped(start)?;
    }
    for journal in &mut journals {
        if !journal.drain()? {
            return Err(Error::OwnershipMismatch);
        }
    }
    let after =
        std::fs::read(directory.join("records/namespaces.json")).map_err(|_| Error::Interrupted)?;
    if before != after {
        return Err(Error::OwnershipMismatch);
    }
    let (pid, start, deadline) = held.ok_or(Error::OwnershipMismatch)?;
    println!(
        "{}",
        serde_json::json!({"case":"actual_owner_held_inspection_original_deadline_neighbor_fresh_inspections_actual_drain",
        "inspector_pid":pid,"inspector_start":start,"original_deadline":deadline,"terminal_at":terminal_at,
        "guard_identities":identities,"b_at_hold":b_at_hold,"b_at_terminal":b_at_terminal,"b_final":b_final,
        "registry_revoked":true,"actual_reaped":true,"held_request_acknowledged":false,"expired_actor_resumed":false,
        "disk_sha256":vprouter_linux::sha256(&after),"component_only":true})
    );
    super::lab::case(
        "actual_owner_held_inspection_original_deadline_neighbor_fresh_inspections_actual_drain",
    );
    Ok(())
}

#[cfg(test)]
fn lab_setup_failure(
    owners: &mut [super::owner::ExternalOwner; 2],
    journals: &mut [super::owned::JournalServer; 2],
    identities: [(u32, u64); 2],
    directory: &std::path::Path,
    before: &[u8],
    reaped_before_admission_complete: bool,
) -> Result<()> {
    let actor = LAB_FAILED_SETUP
        .with(|slot| slot.get())
        .ok_or(Error::OwnershipMismatch)?;
    let reaped_at_entry = kernel::lab_early_reap(actor)?.is_some();
    eprintln!(
        "LAB_SETUP_DRAIN_ENTRY {}",
        serde_json::json!({"pid":actor.0,"start":actor.1,
            "actual_reaped_before_admission_complete":reaped_before_admission_complete,
            "actual_reaped_at_entry":reaped_at_entry,
            "collectors_drained":kernel::early_forks_drained(),
            "original_terminal_reason_preserved":owners[0].lab_terminal_reason() == Some(Error::DescriptorPolicy),
            "prepared_expiry_retained":owners[0].lab_retained_expiry()})
    );
    if (reaped_before_admission_complete && !reaped_at_entry)
        || owners[0].lab_terminal_reason() != Some(Error::DescriptorPolicy)
        || !owners[0].lab_retained_expiry()
        || owners[0].lab_identity()? != identities[0]
    {
        return Err(Error::OwnershipMismatch);
    }
    let end = vprouter_core::health::boot_seconds() + 10.;
    let mut b_at_drain = None;
    let mut b_final = 0;
    {
        let mut deployment = super::owner::DeploymentOwner::new(owners, journals)?;
        loop {
            let done = deployment.poll_once()?;
            if done && !kernel::early_forks_drained() {
                return Err(Error::OwnershipMismatch);
            }
            if kernel::early_forks_drained()
                && kernel::lab_early_reap(actor)?.is_some()
                && b_at_drain.is_none()
            {
                b_at_drain = Some(deployment.lab_inspection_completed(1));
            }
            if b_at_drain.is_some_and(|at| deployment.lab_inspection_completed(1) >= at + 3)
                && deployment.lab_terminal(1).is_none()
            {
                b_final = deployment.lab_inspection_completed(1);
                deployment.lab_terminate(1);
            }
            if done {
                if b_final < 3
                    || deployment.lab_terminal(0) != Some(Error::DescriptorPolicy)
                    || !deployment.lab_guard_stopped(0, identities[0].1)?
                    || !deployment.lab_guard_stopped(1, identities[1].1)?
                    || !deployment.lab_inspection_drained_revoked(1)
                {
                    return Err(Error::OwnershipMismatch);
                }
                break;
            }
            if vprouter_core::health::boot_seconds() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    let reap_status = kernel::lab_early_reap(actor)?.ok_or(Error::OwnershipMismatch)?;
    if !libc::WIFSIGNALED(reap_status)
        || libc::WTERMSIG(reap_status) != libc::SIGKILL
        || Process::open(actor.0).is_ok_and(|p| p.start() == actor.1)
    {
        return Err(Error::OwnershipMismatch);
    }
    for (owner, (_, start)) in owners.iter().zip(identities) {
        owner.lab_kill_stopped(start)?;
    }
    for journal in journals {
        if !journal.drain()? {
            return Err(Error::OwnershipMismatch);
        }
    }
    let after =
        std::fs::read(directory.join("records/namespaces.json")).map_err(|_| Error::Interrupted)?;
    if before != after {
        return Err(Error::OwnershipMismatch);
    }
    println!(
        "{}",
        serde_json::json!({"case":"actual_owner_inspection_post_spawn_setup_failure_retains_guard_expiry_and_early_fork_neighbor_progress",
        "inspector_pid":actor.0,"inspector_start":actor.1,"guard_identities":identities,
        "b_at_actual_drain":b_at_drain,"b_final":b_final,"original_terminal_reason_preserved":true,
        "early_fork_actual_reaped":true,"prepared_expiry_retained":true,"active_expiry_actors":0,
        "early_fork_waitpid_status":reap_status,
        "actual_reaped_before_admission_complete":reaped_before_admission_complete,
        "component_only":true})
    );
    super::lab::case(
        "actual_owner_inspection_post_spawn_setup_failure_retains_guard_expiry_and_early_fork_neighbor_progress",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dead_peer_failure_requires_exact_job_native_reason_and_original_deadline() {
        let token = lab_token(1);
        let job = Job {
            sequence: 9,
            sent_at: 10.,
            token,
            operation: Request::Reinspect { token },
            hold: false,
        };
        let failure = Failure {
            job: Some(job.clone()),
            stage: 60,
            substage: 0,
            reason: "process_unavailable".into(),
            kind: FailureKind::DeadPinnedPeer,
            finished_at: 10.1,
        };
        assert!(dead_failure(&job, &failure));
        for alteration in 0..8 {
            let mut forged = failure.clone();
            match alteration {
                0 => forged.kind = FailureKind::Rejected,
                1 => forged.reason = "deadline".into(),
                2 => forged.finished_at = 12.,
                3 => forged.finished_at = 9.9,
                4 => forged.job.as_mut().unwrap().sequence += 1,
                5 => forged.job.as_mut().unwrap().operation = Request::Container,
                6 => forged.job.as_mut().unwrap().token.slot += 1,
                _ => forged.job = None,
            }
            assert!(!dead_failure(&job, &forged));
        }
    }
    #[test]
    fn diagnostic_failure_timing_requires_exact_pending_job_and_ordered_native_times() {
        let token = lab_token(1);
        let job = Job {
            sequence: 9,
            sent_at: 10.,
            token,
            operation: Request::Reinspect { token },
            hold: false,
        };
        let failure = Failure {
            job: Some(job.clone()),
            stage: 60,
            substage: 23,
            reason: "placement_failed".into(),
            kind: FailureKind::Rejected,
            finished_at: 10.5,
        };
        assert_eq!(
            lab_failure_timing(&job, &failure, 11.),
            Some((500000, 1500000))
        );
        let mut late = failure.clone();
        late.finished_at = 12.5;
        assert_eq!(lab_failure_timing(&job, &late, 13.), Some((2500000, 0)));
        for change in 0..6 {
            let mut bad = failure.clone();
            match change {
                0 => bad.job.as_mut().unwrap().sequence += 1,
                1 => bad.job.as_mut().unwrap().token.slot += 1,
                2 => bad.finished_at = f64::NAN,
                3 => bad.finished_at = 9.,
                4 => bad.finished_at = 12.,
                _ => bad.job = None,
            }
            assert!(lab_failure_timing(&job, &bad, 11.).is_none());
        }
    }
    #[test]
    fn diagnostic_failure_maximum_fixed_payload_stays_within_original_private_frame() {
        let token = Token {
            incarnation: [255; 32],
            slot: 255,
        };
        let operations = [
            Request::Container,
            Request::RegisterChild {
                pid: i32::MAX as u32,
                role: PeerRole::Observer,
            },
            Request::PinDaemon {
                pid: i32::MAX as u32,
                child: i32::MAX as u32,
                bootstrap: "f".repeat(64),
            },
            Request::PinSender {
                pid: i32::MAX as u32,
                role: PeerRole::Observer,
            },
            Request::Reinspect { token },
        ];
        for operation in operations {
            operation.validate().unwrap();
            let failure = Failure {
                job: Some(Job {
                    sequence: u64::MAX,
                    sent_at: f64::MIN_POSITIVE,
                    token,
                    operation,
                    hold: false,
                }),
                stage: u8::MAX,
                substage: u8::MAX,
                reason: "a".repeat(64),
                kind: FailureKind::DeadPinnedPeer,
                finished_at: f64::MAX,
            };
            assert!(kernel::inspection::lab_failure_fits_frame(&failure));
        }
    }
    #[test]
    fn cancelled_slot_cannot_be_completed_replayed_or_reminted() {
        let mut registry = Registry::new([7; 32]);
        let operation = Request::PinSender {
            pid: 123,
            role: PeerRole::Observer,
        };
        let token = registry.reserve(&operation).unwrap();
        let job = Job {
            sequence: 1,
            sent_at: 10.,
            token,
            operation: operation.clone(),
            hold: false,
        };
        registry.revoke();
        assert!(
            registry
                .complete(&job, &Receipt { job: job.clone() }, 10.1)
                .is_err()
        );
        assert!(registry.reserve(&Request::Reinspect { token }).is_err());
        assert!(registry.reserve(&operation).is_err());
    }
    #[test]
    fn receipt_binds_operation_sequence_original_time_and_incarnation() {
        let mut registry = Registry::new([7; 32]);
        let operation = Request::PinSender {
            pid: 123,
            role: PeerRole::Observer,
        };
        let token = registry.reserve(&operation).unwrap();
        let job = Job {
            sequence: 1,
            sent_at: 10.,
            token,
            operation: operation.clone(),
            hold: false,
        };
        for change in 0..5 {
            let mut forged = job.clone();
            match change {
                0 => forged.sequence += 1,
                1 => forged.sent_at += 0.01,
                2 => forged.token.incarnation[0] ^= 1,
                3 => forged.token.slot += 1,
                _ => forged.operation = Request::Container,
            }
            assert!(
                registry
                    .complete(&job, &Receipt { job: forged }, 10.1)
                    .is_err()
            );
        }
        assert!(
            registry
                .complete(&job, &Receipt { job: job.clone() }, 12.)
                .is_err()
        );
        registry
            .complete(&job, &Receipt { job: job.clone() }, 10.1)
            .unwrap();
        assert_eq!(
            registry.reserve(&Request::Reinspect { token }).unwrap(),
            token
        );
        assert!(registry.reserve(&operation).is_err());
        assert!(
            registry
                .reserve(&Request::Reinspect {
                    token: Token {
                        incarnation: [8; 32],
                        slot: token.slot
                    }
                })
                .is_err()
        );
    }
}
