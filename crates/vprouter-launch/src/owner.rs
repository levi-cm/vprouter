#![forbid(unsafe_code)]
//! External host owner. Its independent deadline never resumes a stopped guard.
use super::{Error, Result};
use rustix::{
    event::{PollFd, PollFlags, poll},
    net::{self, RecvFlags, SendFlags},
};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    lifecycle: String,
    sequence: u64,
    sent_at: f64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    allocation: String,
    exit_id: String,
    progress: Progress,
    operation: Operation,
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Operation {
    Progress,
    HostAudit,
    Inspect(super::inspection::Request),
    SpawnExecutor { scope: u8, started_at: f64 },
    Journal(Box<super::owned::JournalRequest>),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    allocation: String,
    exit_id: String,
    progress: Progress,
    executor: Option<super::owned::ExecutorIdentity>,
    inspection: Option<super::inspection::Receipt>,
}
struct Packet {
    progress: Progress,
    executor: Option<super::owned::ExecutorIdentity>,
    inspection: Option<super::inspection::Receipt>,
    descriptors: Vec<OwnedFd>,
}
/// A private endpoint minted only in the exact gated guard, shared by its
/// heartbeat and journal clients. One sequence space prevents reply confusion.
struct Client {
    channel: OwnedFd,
    allocation: String,
    exit_id: String,
    lifecycle: String,
    sequence: Cell<u64>,
    failed: Cell<bool>,
    _inventory: super::inventory::Registration,
}
impl Client {
    fn exchange(&self, operation: Operation) -> Result<()> {
        self.exchange_ack(operation).map(|_| ())
    }
    fn exchange_ack(&self, operation: Operation) -> Result<Progress> {
        let Packet {
            progress,
            executor: identity,
            inspection,
            descriptors,
        } = self.exchange_packet(operation)?;
        if identity.is_some() || inspection.is_some() || !descriptors.is_empty() {
            self.failed.set(true);
            return Err(Error::DescriptorPolicy);
        }
        Ok(progress)
    }
    fn exchange_packet(&self, operation: Operation) -> Result<Packet> {
        if self.failed.replace(true) {
            return Err(Error::Interrupted);
        }
        let sequence = self.sequence.get().checked_add(1).ok_or(Error::Deadline)?;
        let sent_at = vprouter_core::health::boot_seconds();
        let request = Request {
            allocation: self.allocation.clone(),
            exit_id: self.exit_id.clone(),
            progress: Progress {
                lifecycle: self.lifecycle.clone(),
                sequence,
                sent_at,
            },
            operation,
        };
        let end = Instant::now() + Duration::from_secs(2);
        #[cfg(test)]
        let profile = super::handoff::lab_profile::Span::new(
            match &request.operation {
                Operation::Progress => "rpc_progress",
                Operation::HostAudit => "rpc_host_audit",
                Operation::SpawnExecutor { .. } => "rpc_spawn_executor",
                Operation::Journal(operation) => match operation.as_ref() {
                    super::owned::JournalRequest::Revalidate => "rpc_journal_revalidate",
                    super::owned::JournalRequest::VerifyProducer { .. } => "rpc_journal_producer",
                    _ => "rpc_journal_other",
                },
                Operation::Inspect(operation) => match operation {
                    super::inspection::Request::Container => "rpc_inspect_container",
                    super::inspection::Request::RegisterChild { .. } => {
                        "rpc_inspect_register_child"
                    }
                    super::inspection::Request::PinDaemon { .. } => "rpc_inspect_pin_daemon",
                    super::inspection::Request::PinSender { .. } => "rpc_inspect_pin_sender",
                    super::inspection::Request::Reinspect { .. } => "rpc_inspect_reinspect",
                },
            },
            sequence,
        );
        send(&self.channel, &request)?;
        let (reply, descriptors): (Reply, Vec<OwnedFd>) = loop {
            let now = vprouter_core::health::boot_seconds();
            if Instant::now() >= end || now < sent_at || now - sent_at >= 2. {
                return Err(Error::Deadline);
            }
            if let Some(reply) = receive_descriptors(&self.channel)? {
                break reply;
            }
            let mut fds = [PollFd::new(&self.channel, PollFlags::IN)];
            poll(
                &mut fds,
                Some(
                    &rustix::event::Timespec::try_from(
                        end.saturating_duration_since(Instant::now()),
                    )
                    .map_err(|_| Error::Deadline)?,
                ),
            )
            .map_err(|_| Error::Deadline)?;
        };
        let now = vprouter_core::health::boot_seconds();
        if Instant::now() >= end
            || now < sent_at
            || now - sent_at >= 2.
            || reply.allocation != request.allocation
            || reply.exit_id != self.exit_id
            || reply.progress.lifecycle != self.lifecycle
            || reply.progress.sequence != sequence
            || reply.progress.sent_at != sent_at
        {
            return Err(Error::Deadline);
        }
        self.sequence.set(sequence);
        self.failed.set(false);
        #[cfg(test)]
        profile.success();
        Ok(Packet {
            progress: reply.progress,
            executor: reply.executor,
            inspection: reply.inspection,
            descriptors,
        })
    }
}
#[derive(Clone)]
pub(super) struct JournalClient(Rc<Client>);
impl JournalClient {
    pub fn begin_terminal(
        &self,
        binding: vprouter_core::health::Binding,
        lifecycle: &str,
    ) -> Result<f64> {
        Ok(self
            .0
            .exchange_ack(Operation::Journal(Box::new(
                super::owned::JournalRequest::BeginTerminal {
                    binding,
                    lifecycle: lifecycle.into(),
                },
            )))?
            .sent_at)
    }
    pub(super) fn inspect(
        &self,
        operation: super::inspection::Request,
    ) -> Result<super::inspection::Token> {
        let result = (|| {
            let Packet {
                progress,
                executor,
                inspection: receipt,
                descriptors: fds,
            } = self
                .0
                .exchange_packet(Operation::Inspect(operation.clone()))?;
            let receipt = receipt.ok_or(Error::DescriptorPolicy)?;
            receipt.validate_reply(&operation)?;
            if executor.is_some()
                || !fds.is_empty()
                || receipt.job.operation != operation
                || receipt.job.sequence != progress.sequence
                || receipt.job.sent_at != progress.sent_at
            {
                return Err(Error::DescriptorPolicy);
            }
            super::inspection::deadline(progress.sent_at, vprouter_core::health::boot_seconds())?;
            Ok(receipt.job.token)
        })();
        if result.is_err() {
            self.0.failed.set(true);
        }
        result
    }
    pub fn request(&self, request: super::owned::JournalRequest) -> Result<()> {
        self.0.exchange(Operation::Journal(Box::new(request)))
    }
    pub fn lifecycle(&self) -> &str {
        &self.0.lifecycle
    }
    pub fn binds(&self, spec: &super::LaunchSpec) -> Result<()> {
        if self.0.exit_id != spec.exit.exit_id
            || self.0.allocation
                != vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(&spec.allocation).map_err(|_| Error::InvalidSpec)?,
                )
        {
            return Err(Error::AllocationMismatch);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct HostAuditClient {
    journal: JournalClient,
    domains: super::supervision::Domains,
}

/// Only a matched HostAudit Progress ACK can mint this private evidence. It
/// proves host structure, never Ready; original request time is the age anchor.
#[derive(Clone)]
pub(super) struct HostAuditReceipt {
    allocation: String,
    exit_id: String,
    lifecycle: String,
    checked_at: f64,
}
impl HostAuditReceipt {
    pub fn check(&self, spec: &super::LaunchSpec, lifecycle: &str) -> Result<()> {
        if self.exit_id != spec.exit.exit_id
            || self.lifecycle != lifecycle
            || self.allocation
                != vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(&spec.allocation).map_err(|_| Error::InvalidSpec)?,
                )
        {
            return Err(Error::AllocationMismatch);
        }
        original_audit_time(self.checked_at, vprouter_core::health::boot_seconds())
    }
    pub fn checked_at(&self) -> f64 {
        self.checked_at
    }
    pub fn expires_at(&self) -> f64 {
        self.checked_at + 2.
    }
}
fn original_audit_time(sent_at: f64, now: f64) -> Result<()> {
    if !sent_at.is_finite()
        || !now.is_finite()
        || sent_at < 0.
        || now < sent_at
        || now - sent_at >= 2.
    {
        return Err(Error::Deadline);
    }
    Ok(())
}
impl HostAuditClient {
    pub fn domains(
        &self,
        spec: &super::LaunchSpec,
        lifecycle: &str,
    ) -> Result<&super::supervision::Domains> {
        self.journal.binds(spec)?;
        self.domains.verify_guard()?;
        if lifecycle != self.domains.lifecycle() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(&self.domains)
    }
    pub fn spawn_executor(
        &self,
        spec: &super::LaunchSpec,
        scope: u8,
        started_at: f64,
    ) -> Result<(super::kernel::Survivor, OwnedFd)> {
        let result = (|| {
            self.domains(spec, self.journal.lifecycle())?;
            let Packet {
                progress,
                executor: identity,
                inspection,
                mut descriptors,
            } = self
                .journal
                .0
                .exchange_packet(Operation::SpawnExecutor { scope, started_at })?;
            let identity = identity.ok_or(Error::OwnershipMismatch)?;
            if inspection.is_some() || identity.scope != scope || descriptors.len() != 2 {
                return Err(Error::DescriptorPolicy);
            }
            let pinned = descriptors.pop().ok_or(Error::DescriptorPolicy)?;
            let socket = descriptors.pop().ok_or(Error::DescriptorPolicy)?;
            if net::sockopt::socket_type(&socket).map_err(|_| Error::DescriptorPolicy)?
                != net::SocketType::SEQPACKET
            {
                return Err(Error::DescriptorPolicy);
            }
            let child = super::kernel::received_executor(pinned, &identity)?;
            #[cfg(test)]
            super::kernel::executor_private_boundary(&child)?;
            original_audit_time(progress.sent_at, vprouter_core::health::boot_seconds())?;
            Ok((child, socket))
        })();
        if result.is_err() {
            self.journal.0.failed.set(true);
        }
        result
    }
    pub fn audit(&self, spec: &super::LaunchSpec) -> Result<HostAuditReceipt> {
        self.journal.binds(spec)?;
        let progress = self.journal.0.exchange_ack(Operation::HostAudit)?;
        let receipt = HostAuditReceipt {
            allocation: self.journal.0.allocation.clone(),
            exit_id: self.journal.0.exit_id.clone(),
            lifecycle: progress.lifecycle,
            checked_at: progress.sent_at,
        };
        receipt.check(spec, self.journal.lifecycle())?;
        Ok(receipt)
    }
    pub fn check(&self, spec: &super::LaunchSpec, receipt: &HostAuditReceipt) -> Result<()> {
        receipt.check(spec, self.journal.lifecycle())
    }
}
/// Minted only in the fixed, gated guard closure; no received PID/path or flag.
pub(super) struct GuardOwner {
    client: Rc<Client>,
    domains: super::supervision::Domains,
}
impl GuardOwner {
    pub fn domains(&self) -> &super::supervision::Domains {
        &self.domains
    }
    pub fn heartbeat(&self) -> Result<()> {
        self.client.exchange(Operation::Progress)
    }
    pub fn host_audit(&self, spec: &super::LaunchSpec) -> Result<HostAuditClient> {
        self.domains.verify_guard()?;
        let journal = self.journal();
        journal.binds(spec)?;
        Ok(HostAuditClient {
            journal,
            domains: self.domains.clone(),
        })
    }
    pub fn journal(&self) -> JournalClient {
        JournalClient(self.client.clone())
    }
    fn from_gate(channel: BorrowedFd<'_>, domains: super::supervision::Domains) -> Result<Self> {
        domains.verify_guard()?;
        let channel =
            rustix::io::fcntl_dupfd_cloexec(channel, 3).map_err(|_| Error::DescriptorDuplicate)?;
        let inventory = super::inventory::Registration::owned(&[channel.as_fd()])?;
        Ok(Self {
            client: Rc::new(Client {
                channel,
                allocation: domains.allocation().into(),
                exit_id: domains.exit_id().into(),
                lifecycle: domains.lifecycle().into(),
                sequence: Cell::new(0),
                failed: Cell::new(false),
                _inventory: inventory,
            }),
            domains,
        })
    }
}
fn send<T: Serialize>(socket: impl AsFd, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::DescriptorPolicy)?;
    if bytes.len() > 16384 {
        return Err(Error::TooLarge);
    }
    match net::send(socket, &bytes, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
        Ok(n) if n == bytes.len() => Ok(()),
        _ => Err(Error::DescriptorPolicy),
    }
}
fn receive<T: serde::de::DeserializeOwned>(socket: impl AsFd) -> Result<Option<T>> {
    let mut bytes = [0; 16385];
    match net::recv(socket, &mut bytes, RecvFlags::DONTWAIT | RecvFlags::TRUNC) {
        Err(rustix::io::Errno::AGAIN) => Ok(None),
        Ok((length, full)) if length > 0 && length == full && length <= 16384 => {
            serde_json::from_slice(&bytes[..length])
                .map(Some)
                .map_err(|_| Error::DescriptorPolicy)
        }
        _ => Err(Error::DescriptorPolicy),
    }
}

fn receive_descriptors<T: serde::de::DeserializeOwned>(
    socket: impl AsFd,
) -> Result<Option<(T, Vec<OwnedFd>)>> {
    let mut bytes = [0; 16385];
    let mut buffer = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = net::RecvAncillaryBuffer::new(&mut buffer);
    let msg = match net::recvmsg(
        socket,
        &mut [std::io::IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    ) {
        Err(rustix::io::Errno::AGAIN) => return Ok(None),
        Ok(msg) => msg,
        _ => return Err(Error::DescriptorPolicy),
    };
    let mut fds = vec![];
    for item in ancillary.drain() {
        match item {
            net::RecvAncillaryMessage::ScmRights(rights) if fds.is_empty() => fds.extend(rights),
            _ => return Err(Error::DescriptorPolicy),
        }
    }
    if msg.bytes == 0
        || msg.bytes > 16384
        || msg
            .flags
            .intersects(net::ReturnFlags::TRUNC | net::ReturnFlags::CTRUNC)
        || fds.len() > 2
    {
        return Err(Error::DescriptorPolicy);
    }
    let value = serde_json::from_slice(&bytes[..msg.bytes]).map_err(|_| Error::DescriptorPolicy)?;
    Ok(Some((value, fds)))
}
fn send_descriptors(socket: impl AsFd, value: &Reply, fds: &[BorrowedFd<'_>]) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::DescriptorPolicy)?;
    if bytes.len() > 16384 || fds.len() != 2 {
        return Err(Error::DescriptorPolicy);
    }
    let mut buffer = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = net::SendAncillaryBuffer::new(&mut buffer);
    if !ancillary.push(net::SendAncillaryMessage::ScmRights(fds)) {
        return Err(Error::DescriptorPolicy);
    }
    let n = net::sendmsg(
        socket,
        &[std::io::IoSlice::new(&bytes)],
        &mut ancillary,
        SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    if n != bytes.len() {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ConstructionStage {
    Birth,
    Placement,
    Placed,
    Release,
    Finished,
}
/// One retained member construction slot. Each poll performs at most one
/// nonblocking stage; callers service established slots before polling it.
pub(super) struct PendingOwner {
    creator: u32,
    domains: super::supervision::Domains,
    guard: Option<super::kernel::PendingGuard>,
    guard_drain: super::kernel::GuardDrain,
    clock: Option<Watchdog>,
    signals: Option<super::kernel::OwnerSignals>,
    stage: ConstructionStage,
    failure: Option<Error>,
    drain_error: Option<Error>,
    #[cfg(test)]
    birth: super::owned::GuardBirth,
}
impl PendingOwner {
    #[cfg(test)]
    pub(super) fn lab_birth(&self) -> Result<super::owned::GuardBirth> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(self.birth.clone())
    }
    #[cfg(test)]
    pub(super) fn lab_failure_status(&self) -> Result<(Option<Error>, Option<i32>)> {
        Ok((self.failure, self.guard_drain.lab_status()?))
    }
    pub(super) fn fork(
        domains: super::supervision::Domains,
        owner: &super::supervision::OwnerDomain,
        plan: super::owned::PlannedAttempt,
        inputs: super::inventory::GuardInputs,
        journal: &mut super::owned::JournalServer,
        run: impl FnOnce(&GuardOwner) -> Result<()>,
    ) -> Result<Self> {
        if journal.allocation() != domains.allocation()
            || journal.exit_id() != domains.exit_id()
            || journal.lifecycle() != domains.lifecycle()
        {
            return Err(Error::OwnershipMismatch);
        }
        let clock = Watchdog::new(
            domains.lifecycle().into(),
            vprouter_core::health::boot_seconds(),
        )?;
        let signals = super::kernel::OwnerSignals::new()?;
        let guard_domains = domains.clone();
        let guard = super::kernel::PendingGuard::spawn(&domains, owner, inputs, plan, |channel| {
            let owner = GuardOwner::from_gate(channel, guard_domains)?;
            owner.heartbeat()?;
            run(&owner)
        })?;
        let mut pending = Self {
            creator: std::process::id(),
            domains,
            guard_drain: guard.drain_receipt()?,
            #[cfg(test)]
            birth: guard.birth()?,
            guard: Some(guard),
            clock: Some(clock),
            signals: Some(signals),
            stage: ConstructionStage::Birth,
            failure: None,
            drain_error: None,
        };
        if let Err(error) = journal.start_birth(pending.guard.as_ref().ok_or(Error::Interrupted)?) {
            pending.fail(journal, error)?;
        }
        Ok(pending)
    }
    fn require_journal(&self, journal: &super::owned::JournalServer) -> Result<()> {
        if self.creator != std::process::id()
            || journal.allocation() != self.domains.allocation()
            || journal.exit_id() != self.domains.exit_id()
            || journal.lifecycle() != self.domains.lifecycle()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    fn fail(&mut self, journal: &mut super::owned::JournalServer, reason: Error) -> Result<()> {
        // A caller supplying another member's journal cannot cancel its work.
        self.require_journal(journal)?;
        self.failure.get_or_insert(reason);
        if let Err(error) = journal.fence() {
            self.drain_error.get_or_insert(error);
        }
        // Transfer the complete unreleased native bundle immediately, including
        // when starting the first durable birth write fails.
        drop(self.guard.take());
        Ok(())
    }
    /// Native drainage only; this never clears mutation uncertainty or permits
    /// cleanup/reuse. Keep the canonical journal view until retirement proves it.
    pub(super) fn poll_failure(
        &mut self,
        journal: &mut super::owned::JournalServer,
    ) -> Result<bool> {
        self.require_journal(journal)?;
        if self.failure.is_none() {
            return Err(Error::Interrupted);
        }
        if let Err(error) = super::kernel::poll_early_forks() {
            self.drain_error.get_or_insert(error);
            self.signals
                .as_ref()
                .ok_or(Error::Interrupted)?
                .fence(error)?;
        }
        if let Err(error) = journal.poll_terminal_io() {
            self.drain_error.get_or_insert(error);
        }
        Ok(self.guard_drain.drained()? && journal.native_drained())
    }
    pub(super) fn poll(
        &mut self,
        journal: &mut super::owned::JournalServer,
    ) -> Result<Option<ExternalOwner>> {
        self.require_journal(journal)?;
        if let Some(error) = self.failure {
            self.poll_failure(journal)?;
            return Err(error);
        }
        let result = match self
            .signals
            .as_ref()
            .ok_or(Error::Interrupted)?
            .stop_requested()
        {
            Ok(false) => self.advance(journal),
            Ok(true) => Err(Error::Interrupted),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            self.fail(journal, error)?;
        }
        result
    }
    fn advance(
        &mut self,
        journal: &mut super::owned::JournalServer,
    ) -> Result<Option<ExternalOwner>> {
        self.require_journal(journal)?;
        let guard = self.guard.as_mut().ok_or(Error::Interrupted)?;
        match self.stage {
            ConstructionStage::Birth => {
                if let Some(receipt) = journal.poll_birth(guard)? {
                    guard.start_placement(&receipt)?;
                    self.stage = ConstructionStage::Placement;
                }
            }
            ConstructionStage::Placement => {
                if guard.poll_placement()? {
                    journal.start_placed(guard)?;
                    self.stage = ConstructionStage::Placed;
                }
            }
            ConstructionStage::Placed => {
                if journal.poll_placed(guard)? {
                    journal.start_release(guard)?;
                    self.stage = ConstructionStage::Release;
                }
            }
            ConstructionStage::Release => {
                if let Some(receipt) = journal.poll_release(guard)? {
                    let guard = self
                        .guard
                        .take()
                        .ok_or(Error::Interrupted)?
                        .release(receipt)?;
                    self.stage = ConstructionStage::Finished;
                    return Ok(Some(ExternalOwner::from_guard(
                        &self.domains,
                        guard,
                        self.clock.take().ok_or(Error::Interrupted)?,
                        self.signals.take().ok_or(Error::Interrupted)?,
                    )));
                }
            }
            ConstructionStage::Finished => return Err(Error::Interrupted),
        }
        Ok(None)
    }
}
pub(super) struct ExternalOwner {
    allocation: String,
    exit_id: String,
    guard: super::kernel::ManagedGuard,
    clock: Watchdog,
    signals: super::kernel::OwnerSignals,
    pending: Option<Progress>,
    terminal: Option<Error>,
    host: Option<HostService>,
    inspection: Option<super::inspection::Service>,
    inspection_drain_error: Option<Error>,
    journal_drain_error: Option<Error>,
    abandoned_read: Option<Progress>,
    expiry: Option<super::expiry::OwnerExecutors>,
    // Fixed internal setup calls exactly once per owner (expiry/placement labs);
    // no wire operation or service loop can append attachments.
    rejected_expiry: Vec<RejectedExpiry>,
    spawning: Option<Progress>,
    completions: std::collections::VecDeque<super::expiry::FixedCompletion>,
    completion_error: Option<Error>,
}
/// Consuming retirement never relinquishes its canonical service on Err/Drop.
/// Beginning is borrowed: mismatched or busy inputs stay untouched in their slots.
pub(super) struct Retirement {
    native: Option<NativeRetirement>,
}
#[cfg(test)]
#[derive(Default)]
struct LabLinksWriter {
    pending_polls: u8,
    witness: Option<super::kernel::Survivor>,
    original: Option<(u32, u64, f64)>,
    started_at: Option<f64>,
    verified_at: Option<f64>,
    prequeue_refused: bool,
    released: bool,
}
struct NativeRetirement {
    #[cfg(test)]
    lab_links_writer: Option<LabLinksWriter>,
    #[cfg(test)]
    lab_fault: u8,
    creator: u32,
    owner: ExternalOwner,
    journal: super::owned::JournalServer,
    transport: std::rc::Rc<std::cell::RefCell<super::transport::RetirementTransport>>,
    binding: super::owned::RetirementBinding,
    phase: RetirementPhase,
    failure: Option<Error>,
    completed_links: Option<(
        Box<vprouter_network::HostRemovalPlan>,
        std::rc::Rc<super::kernel::cleanup::CleanupReceipt>,
    )>,
    _ticket: RetirementTicket,
}
struct RetirementTicket {
    creator: u32,
    #[cfg(test)]
    anchor: std::rc::Rc<()>,
}
impl RetirementTicket {
    fn issue() -> Result<Self> {
        RETIREMENT_COUNT.with(|count| {
            let before = count.get();
            if before >= 64 {
                return Err(Error::LockBusy);
            }
            count.set(before + 1);
            Ok(Self {
                creator: std::process::id(),
                #[cfg(test)]
                anchor: std::rc::Rc::new(()),
            })
        })
    }
}
impl Drop for RetirementTicket {
    fn drop(&mut self) {
        if self.creator == std::process::id() {
            RETIREMENT_COUNT.with(|count| {
                count.set(count.get().checked_sub(1).expect("owned retirement count"))
            });
        }
    }
}
enum RetirementPhase {
    Revoking,
    Containment,
    Retiring {
        started_at: f64,
        queued: bool,
    },
    StopAuthorized(Box<super::owned::RetiringPermit>),
    Stopping {
        permit: Box<super::owned::RetiringPermit>,
        child: Box<super::kernel::retirement::StopChild>,
    },
    Stopped {
        permit: Box<super::owned::RetiringPermit>,
        receipt: Box<super::kernel::retirement::StopReceipt>,
        started_at: f64,
    },
    QuiescenceWriting {
        started_at: f64,
    },
    Quiescent(Box<super::owned::QuiescentPermit>),
    LinksIntent {
        permit: Box<super::owned::QuiescentPermit>,
        plan: Box<vprouter_network::HostRemovalPlan>,
        started_at: f64,
        queued: bool,
    },
    LinksAuthorized {
        permit: Box<super::owned::CleanupPermit>,
        plan: Box<vprouter_network::HostRemovalPlan>,
        activated: bool,
    },
    LinksCleaning {
        permit: Box<super::owned::CleanupPermit>,
        plan: Box<vprouter_network::HostRemovalPlan>,
        child: Box<super::kernel::cleanup::CleanupChild>,
    },
    LinksCleaned {
        permit: Box<super::owned::CleanupPermit>,
        plan: Box<vprouter_network::HostRemovalPlan>,
        receipt: std::rc::Rc<super::kernel::cleanup::CleanupReceipt>,
        started_at: f64,
        model_finished: bool,
        queued: bool,
    },
    ProducerIntent {
        permit: Box<super::owned::CleanupPermit>,
        started_at: f64,
        queued: bool,
    },
    ProducerAuthorized(Box<super::owned::CleanupPermit>),
    ProducerRemoving {
        permit: Box<super::owned::CleanupPermit>,
        child: Box<super::kernel::cleanup::CleanupChild>,
    },
    ProducerRemoved {
        permit: Box<super::owned::CleanupPermit>,
        receipt: std::rc::Rc<super::kernel::cleanup::CleanupReceipt>,
        started_at: f64,
        queued: bool,
    },
    FinalWriting {
        permit: Box<super::owned::CleanupPermit>,
        receipt: std::rc::Rc<super::kernel::cleanup::CleanupReceipt>,
        started_at: f64,
        queued: bool,
    },
    FinalCollection(Box<super::owned::RetiredPermit>),
    Complete,
}
thread_local! {
    static RETAINED_RETIREMENTS: std::cell::RefCell<Vec<NativeRetirement>> = const { std::cell::RefCell::new(Vec::new()) };
    static RETIREMENT_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
impl Retirement {
    pub(super) fn try_begin(
        owner: &mut Option<ExternalOwner>,
        journal: &mut Option<super::owned::JournalServer>,
        transport: &mut Option<super::transport::GuardTransport<'_>>,
    ) -> Result<Option<Self>> {
        let current_owner = owner.as_ref().ok_or(Error::OwnershipMismatch)?;
        let current_journal = journal.as_ref().ok_or(Error::OwnershipMismatch)?;
        let current_transport = transport.as_ref().ok_or(Error::OwnershipMismatch)?;
        if current_owner.guard.original_creator() != std::process::id()
            || current_owner.allocation != current_journal.allocation()
            || current_owner.exit_id != current_journal.exit_id()
            || current_owner.clock.lifecycle != current_journal.lifecycle()
            || !current_owner.rejected_expiry.is_empty()
        {
            return Err(Error::OwnershipMismatch);
        }
        // The existing deployment loop must finish already accepted normal jobs
        // within THEIR original deadlines. No pending read is discarded or ACKed
        // by this retirement API, and a healthy completion writer is preserved.
        if current_owner.pending.is_some()
            || current_owner.spawning.is_some()
            || (!current_journal.idle() && !current_journal.completing())
        {
            return Ok(None);
        }
        let expiry = current_owner
            .expiry
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        expiry.binds(
            &current_owner.allocation,
            &current_owner.exit_id,
            &current_owner.clock.lifecycle,
        )?;
        expiry.require_registered_retirement()?;
        let binding =
            current_transport.retirement_binding(current_journal, &current_owner.guard)?;
        let creator = current_owner.guard.original_creator();
        let ticket = RetirementTicket::issue()?;
        // No fallible operation follows the first take. Every original field is
        // immediately owned by the retained driver, including canonical service.
        Ok(Some(Self {
            native: Some(NativeRetirement {
                #[cfg(test)]
                lab_links_writer: None,
                #[cfg(test)]
                lab_fault: 0,
                creator,
                owner: owner.take().expect("validated owner slot"),
                journal: journal.take().expect("validated journal slot"),
                transport: std::rc::Rc::new(std::cell::RefCell::new(
                    transport
                        .take()
                        .expect("validated transport slot")
                        .into_retirement(),
                )),
                binding,
                phase: RetirementPhase::Revoking,
                failure: None,
                completed_links: None,
                _ticket: ticket,
            }),
        }))
    }
    #[cfg(test)]
    pub(super) fn lab_hold_links_writer(&mut self) -> Result<()> {
        let native = self.native.as_mut().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id()
            || native.lab_links_writer.is_some()
            || !matches!(native.phase, RetirementPhase::Revoking)
        {
            return Err(Error::OwnershipMismatch);
        }
        native.lab_links_writer = Some(LabLinksWriter::default());
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn lab_links_writer_receipt(&self) -> Result<serde_json::Value> {
        if !self.is_complete()? {
            return Err(Error::OwnershipMismatch);
        }
        let proof = self
            .native
            .as_ref()
            .and_then(|n| n.lab_links_writer.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        let status = proof
            .witness
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .lab_terminal_status()?;
        if proof.pending_polls < 2
            || !proof.prequeue_refused
            || !proof.released
            || status != Some(0)
        {
            return Err(Error::OwnershipMismatch);
        }
        let (pid, start, deadline) = proof.original.ok_or(Error::OwnershipMismatch)?;
        let started_at = proof.started_at.ok_or(Error::OwnershipMismatch)?;
        let verified_at = proof.verified_at.ok_or(Error::OwnershipMismatch)?;
        if !started_at.is_finite()
            || !verified_at.is_finite()
            || deadline != started_at + 2.
            || verified_at <= started_at
            || verified_at >= deadline
        {
            return Err(Error::Deadline);
        }
        Ok(
            serde_json::json!({"pid":pid,"start":start,"original_deadline":deadline,"original_started_at":started_at,"verified_at":verified_at,
            "pending_parent_polls":proof.pending_polls,"prequeue_prepared_member_job_refused":true,
            "actual_wait_status":status,"original_deadline_unchanged":true,"ack_readback_and_actual_reap":true}),
        )
    }
    #[cfg(test)]
    pub(super) fn lab_unconsumed_stop_record(&self) -> Result<(Vec<u8>, Option<Error>)> {
        self.native
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .lab_unconsumed_stop_record()
    }
    #[cfg(test)]
    pub(super) fn lab_retained_unconsumed_stop_record(
        anchor: &std::rc::Weak<()>,
    ) -> Result<(Vec<u8>, Option<Error>)> {
        RETAINED_RETIREMENTS.with(|owners| {
            let owners = owners.borrow();
            let mut matches = owners.iter().filter(|owner| {
                std::rc::Weak::ptr_eq(anchor, &std::rc::Rc::downgrade(&owner._ticket.anchor))
            });
            let owner = matches.next().ok_or(Error::OwnershipMismatch)?;
            if matches.next().is_some() {
                return Err(Error::OwnershipMismatch);
            }
            owner.lab_unconsumed_stop_record()
        })
    }
    #[cfg(test)]
    pub(super) fn lab_retention_observer(&self) -> Result<std::rc::Weak<()>> {
        let native = self.native.as_ref().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(std::rc::Rc::downgrade(&native._ticket.anchor))
    }
    #[cfg(test)]
    pub(super) fn lab_inject_failure(&mut self, fault: u8) -> Result<()> {
        let native = self.native.as_mut().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id()
            || fault > 2
            || !matches!(native.phase, RetirementPhase::Revoking)
        {
            return Err(Error::OwnershipMismatch);
        }
        native.lab_fault = fault;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn lab_failure_snapshot(&self) -> Result<serde_json::Value> {
        let native = self.native.as_ref().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id()
            || native.failure.is_none()
            || !matches!(native.phase, RetirementPhase::Retiring { .. })
        {
            return Err(Error::OwnershipMismatch);
        }
        native.journal.lab_retirement_failure()
    }
    #[cfg(test)]
    pub(super) fn lab_cleanup_checkpoint(&mut self) -> Result<bool> {
        let native = self.native.as_mut().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        match &mut native.phase {
            RetirementPhase::LinksCleaning { child, .. } => child.lab_checkpoint(),
            _ => Ok(false),
        }
    }
    #[cfg(test)]
    pub(super) fn lab_cleanup_snapshot(&self) -> Result<Option<serde_json::Value>> {
        let native = self.native.as_ref().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        match &native.phase {
            RetirementPhase::LinksCleaning { child, .. } => child.lab_snapshot().map(Some),
            _ => Ok(None),
        }
    }
    #[cfg(test)]
    pub(super) fn lab_release_cleanup(&mut self) -> Result<()> {
        let native = self.native.as_mut().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        match &mut native.phase {
            RetirementPhase::LinksCleaning { child, .. } => child.lab_release(),
            _ => Err(Error::OwnershipMismatch),
        }
    }
    #[cfg(test)]
    pub(super) fn lab_phase(&self) -> Result<&'static str> {
        let native = self.native.as_ref().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(match native.phase {
            RetirementPhase::Revoking => "revoking",
            RetirementPhase::Containment => "containment",
            RetirementPhase::Retiring { .. } => "retiring",
            RetirementPhase::StopAuthorized(_) => "stop_authorized",
            RetirementPhase::Stopping { .. } => "stopping",
            RetirementPhase::Stopped { .. } => "stopped",
            RetirementPhase::QuiescenceWriting { .. } => "quiescence_writing",
            RetirementPhase::Quiescent(_) => "quiescent",
            RetirementPhase::LinksIntent { .. } => "links_intent",
            RetirementPhase::LinksAuthorized { .. } => "links_authorized",
            RetirementPhase::LinksCleaning { .. } => "links_cleaning",
            RetirementPhase::LinksCleaned { .. } => "links_cleaned",
            RetirementPhase::ProducerIntent { .. } => "producer_intent",
            RetirementPhase::ProducerAuthorized(_) => "producer_authorized",
            RetirementPhase::ProducerRemoving { .. } => "producer_removing",
            RetirementPhase::ProducerRemoved { .. } => "producer_removed",
            RetirementPhase::FinalWriting { .. } => "final_writing",
            RetirementPhase::FinalCollection(_) => "final_collection",
            RetirementPhase::Complete => "complete",
        })
    }
    #[cfg(test)]
    pub(super) fn lab_links_pending(&self) -> Result<bool> {
        Ok(matches!(
            self.lab_phase()?,
            "links_authorized" | "links_cleaning"
        ))
    }
    #[cfg(test)]
    pub(super) fn lab_links_finished(&self) -> Result<bool> {
        Ok(matches!(
            self.lab_phase()?,
            "links_cleaned"
                | "producer_intent"
                | "producer_authorized"
                | "producer_removing"
                | "producer_removed"
                | "final_writing"
                | "final_collection"
                | "complete"
        ))
    }
    #[cfg(test)]
    pub(super) fn lab_completed_record(&self) -> Result<serde_json::Value> {
        if !self.is_complete()? {
            return Err(Error::OwnershipMismatch);
        }
        self.native
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .journal
            .lab_retirement_record()
    }
    pub(super) fn is_complete(&self) -> Result<bool> {
        let native = self.native.as_ref().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(matches!(native.phase, RetirementPhase::Complete))
    }
    pub(super) fn poll(&mut self) -> Result<()> {
        let native = self.native.as_mut().ok_or(Error::OwnershipMismatch)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Err(error) = super::kernel::poll_early_forks() {
            native.failure.get_or_insert(error);
            let _ = native.owner.signals.fence(error);
        }
        native.poll()
    }
}
impl Drop for Retirement {
    fn drop(&mut self) {
        if let Some(native) = self.native.take()
            && native.creator == std::process::id()
            && !matches!(native.phase, RetirementPhase::Complete)
        {
            RETAINED_RETIREMENTS.with(|owners| owners.borrow_mut().push(native));
        }
    }
}
impl NativeRetirement {
    #[cfg(test)]
    fn lab_unconsumed_stop_record(&self) -> Result<(Vec<u8>, Option<Error>)> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let RetirementPhase::StopAuthorized(permit) = &self.phase else {
            return Err(Error::OwnershipMismatch);
        };
        Ok((
            self.journal.lab_unconsumed_stop_record(permit)?,
            self.failure,
        ))
    }

    fn revoke(&mut self) {
        let mut first = None;
        if let Err(error) = self.owner.guard.revoke_owner_channel() {
            first.get_or_insert(error);
        }
        if let Some(inspection) = &mut self.owner.inspection
            && let Err(error) = inspection.cancel()
        {
            first.get_or_insert(error);
        }
        if let Some(host) = &mut self.owner.host
            && let Err(error) = host.cancel()
        {
            host.drain_error.get_or_insert(error);
            first.get_or_insert(error);
        }
        if let Some(expiry) = &mut self.owner.expiry
            && let Err(error) = expiry.revoke_for_retirement()
        {
            first.get_or_insert(error);
        }
        if let Err(error) = self.owner.guard.freeze() {
            first.get_or_insert(error);
        }
        self.owner.clock.terminal = true;
        self.owner.terminal.get_or_insert(Error::Interrupted);
        if let Some(error) = first {
            self.failure.get_or_insert(error);
        }
        self.phase = RetirementPhase::Containment;
    }
    fn collect(&mut self) {
        if let Err(error) = self.owner.service_completions(&mut self.journal) {
            self.owner.completion_error.get_or_insert(error);
            self.failure.get_or_insert(error);
        }
        if let Some(host) = &mut self.owner.host {
            host.drain();
        }
        if let Err(error) = self.journal.poll_terminal_io() {
            self.owner.journal_drain_error.get_or_insert(error);
            self.failure.get_or_insert(error);
        }
        if let Some(error) = self
            .owner
            .inspection_drain_error
            .or(self.owner.journal_drain_error)
            .or(self.owner.completion_error)
            .or(self.owner.host.as_ref().and_then(|host| host.drain_error))
        {
            self.failure.get_or_insert(error);
        }
    }
    fn poll(&mut self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if matches!(self.phase, RetirementPhase::Complete) {
            return Ok(());
        }
        // The permanent deployment latch is independent of this member's
        // deliberate local terminal state. It also gates dropped/TLS drivers.
        match self.owner.signals.stop_requested() {
            Ok(false) => {}
            Ok(true) => {
                self.failure.get_or_insert(Error::Interrupted);
            }
            Err(error) => {
                self.failure.get_or_insert(error);
            }
        }
        if matches!(self.phase, RetirementPhase::Revoking) {
            self.revoke();
        }
        // Errors stop authority progression, never collection of other exact
        // original roles or completion receipts. No new ACK is sent to guard.
        self.collect();
        if let Some(error) = self.failure {
            let _ = self.journal.fail_retirement(&self.binding);
            if let RetirementPhase::Stopping { child, .. } = &mut self.phase {
                let _ = child.cancel();
                let _ = child.drain();
            }
            if let RetirementPhase::LinksCleaning { child, .. }
            | RetirementPhase::ProducerRemoving { child, .. } = &mut self.phase
            {
                let _ = child.cancel();
                let _ = child.drain();
            }
            return Err(error);
        }
        let result = self.advance();
        if let Err(error) = result {
            self.failure.get_or_insert(error);
            let _ = self.journal.fail_retirement(&self.binding);
        }
        result
    }
    fn advance(&mut self) -> Result<()> {
        match &mut self.phase {
            RetirementPhase::Revoking => return Err(Error::OwnershipMismatch),
            RetirementPhase::Containment => {
                let expiry = self.owner.expiry.as_ref().ok_or(Error::OwnershipMismatch)?;
                if !expiry.finished()
                    || !self.owner.completions.is_empty()
                    || !self.journal.idle()
                    || !self.journal.native_drained()
                    || self
                        .owner
                        .host
                        .as_ref()
                        .is_some_and(|h| !h.native_drained())
                    || self.owner.inspection.as_ref().is_some_and(|i| !i.drained())
                {
                    return Ok(());
                }
                expiry.retirement_reaps()?;
                self.phase = RetirementPhase::Retiring {
                    started_at: vprouter_core::health::boot_seconds(),
                    queued: false,
                };
            }
            RetirementPhase::Retiring { started_at, queued } => {
                if !*queued {
                    let reaps = self
                        .owner
                        .expiry
                        .as_ref()
                        .ok_or(Error::OwnershipMismatch)?
                        .retirement_reaps()?;
                    #[cfg(test)]
                    if self.lab_fault == 2 {
                        self.journal.lab_hold_retirement_write();
                    }
                    match self
                        .journal
                        .start_retirement(&self.binding, reaps, *started_at)
                    {
                        Ok(()) => *queued = true,
                        Err(Error::LockBusy) => {
                            original_audit_time(
                                *started_at,
                                vprouter_core::health::boot_seconds(),
                            )?;
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    }
                }
                #[cfg(test)]
                if self.lab_fault == 1 && vprouter_core::health::boot_seconds() < *started_at + 2. {
                    return Ok(());
                }
                #[cfg(test)]
                if self.lab_fault == 2 && self.journal.lab_write_checkpoint()? {
                    self.journal.lab_fail_retirement_poll();
                }
                if let Some(permit) = self.journal.poll_retirement(&self.binding, *started_at)? {
                    self.phase = RetirementPhase::StopAuthorized(Box::new(permit));
                }
            }
            RetirementPhase::StopAuthorized(permit) => {
                let child = self
                    .transport
                    .try_borrow()
                    .map_err(|_| Error::LockBusy)?
                    .stop(permit, &self.journal, &self.owner.guard)?;
                let previous = std::mem::replace(&mut self.phase, RetirementPhase::Containment);
                let RetirementPhase::StopAuthorized(permit) = previous else {
                    unreachable!("matched phase")
                };
                self.phase = RetirementPhase::Stopping {
                    permit,
                    child: Box::new(child),
                };
            }
            RetirementPhase::Stopping { child, .. } => {
                if let Some(receipt) = child.poll()? {
                    let previous = std::mem::replace(&mut self.phase, RetirementPhase::Containment);
                    let RetirementPhase::Stopping { permit, child } = previous else {
                        unreachable!("matched phase")
                    };
                    // Full successful wrapper collection releases the job ticket;
                    // actual reap alone never changes the member-drained count.
                    drop(child);
                    self.phase = RetirementPhase::Stopped {
                        permit,
                        receipt: Box::new(receipt),
                        started_at: vprouter_core::health::boot_seconds(),
                    };
                }
            }
            RetirementPhase::Stopped {
                permit,
                receipt,
                started_at,
            } => {
                original_audit_time(*started_at, vprouter_core::health::boot_seconds())?;
                if self
                    .owner
                    .host
                    .as_ref()
                    .is_some_and(|h| !h.native_drained())
                    || self.owner.inspection.as_ref().is_some_and(|i| !i.drained())
                    || !self.owner.completions.is_empty()
                {
                    return Ok(());
                }
                if let Some(request) = self
                    .transport
                    .try_borrow()
                    .map_err(|_| Error::LockBusy)?
                    .quiescence(
                        permit,
                        &self.journal,
                        &self.owner.guard,
                        receipt,
                        self.owner.expiry.as_ref().ok_or(Error::OwnershipMismatch)?,
                        *started_at,
                    )?
                {
                    match self.journal.start_quiescence(request) {
                        Ok(()) => {
                            self.phase = RetirementPhase::QuiescenceWriting {
                                started_at: *started_at,
                            }
                        }
                        Err(Error::LockBusy) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            RetirementPhase::QuiescenceWriting { started_at } => {
                if let Some(permit) = self.journal.poll_quiescence(&self.binding, *started_at)? {
                    self.phase = RetirementPhase::Quiescent(Box::new(permit));
                }
            }
            RetirementPhase::Quiescent(permit) => {
                if !self.owner.guard.retirement_removed()? {
                    return Ok(());
                }
                self.owner
                    .expiry
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .retirement_reaps()?;
                self.owner.guard.retire_bookkeeping(permit, &self.journal)?;
                self.journal.retire_service_bookkeeping(permit)?;
                let plan = Box::new(
                    self.transport
                        .try_borrow()
                        .map_err(|_| Error::LockBusy)?
                        .prepare_host_removal()?,
                );
                let previous = std::mem::replace(&mut self.phase, RetirementPhase::Containment);
                let RetirementPhase::Quiescent(permit) = previous else {
                    unreachable!("matched phase")
                };
                self.phase = RetirementPhase::LinksIntent {
                    permit,
                    plan,
                    started_at: vprouter_core::health::boot_seconds(),
                    queued: false,
                };
            }
            RetirementPhase::LinksIntent {
                permit,
                plan,
                started_at,
                queued,
            } => {
                original_audit_time(*started_at, vprouter_core::health::boot_seconds())?;
                if !*queued {
                    match self.journal.start_links_intent(permit, plan, *started_at) {
                        Ok(()) => *queued = true,
                        Err(Error::LockBusy) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
                if let Some(permit) = self.journal.poll_links_intent(&self.binding, plan)? {
                    let previous = std::mem::replace(&mut self.phase, RetirementPhase::Containment);
                    let RetirementPhase::LinksIntent { plan, .. } = previous else {
                        unreachable!("matched phase")
                    };
                    self.phase = RetirementPhase::LinksAuthorized {
                        permit: Box::new(permit),
                        plan,
                        activated: false,
                    };
                }
            }
            RetirementPhase::LinksAuthorized {
                permit,
                plan,
                activated,
            } => {
                if !*activated {
                    *activated = permit.activate(
                        &self.journal,
                        &self.owner.guard,
                        self.owner.expiry.as_ref().ok_or(Error::OwnershipMismatch)?,
                        plan,
                    )?;
                }
                if *activated {
                    let child = permit.launch_links(
                        &self.journal,
                        &self.owner.guard,
                        self.owner.expiry.as_ref().ok_or(Error::OwnershipMismatch)?,
                        plan,
                        self.transport.clone(),
                    )?;
                    let previous = std::mem::replace(&mut self.phase, RetirementPhase::Containment);
                    let RetirementPhase::LinksAuthorized { permit, plan, .. } = previous else {
                        unreachable!("matched phase")
                    };
                    self.phase = RetirementPhase::LinksCleaning {
                        permit,
                        plan,
                        child: Box::new(child),
                    };
                }
            }
            RetirementPhase::LinksCleaning { child, .. } => {
                if let Some(receipt) = child.poll()? {
                    let previous = std::mem::replace(&mut self.phase, RetirementPhase::Containment);
                    let RetirementPhase::LinksCleaning {
                        permit,
                        plan,
                        child,
                    } = previous
                    else {
                        unreachable!("matched phase")
                    };
                    drop(child);
                    self.phase = RetirementPhase::LinksCleaned {
                        permit,
                        plan,
                        receipt: std::rc::Rc::new(receipt),
                        started_at: vprouter_core::health::boot_seconds(),
                        model_finished: false,
                        queued: false,
                    };
                }
            }
            RetirementPhase::LinksCleaned {
                permit,
                plan,
                receipt,
                started_at,
                model_finished,
                queued,
            } => {
                original_audit_time(*started_at, vprouter_core::health::boot_seconds())?;
                if !self.owner.guard.retirement_removed()? {
                    return Err(Error::OwnershipMismatch);
                }
                // Quiet is an admission condition. Once this phase queues its
                // own exact writer, poll that retained operation to actual reap;
                // it is expected to occupy the member's native job registry.
                if !*queued && !self.journal.native_drained() {
                    return Err(Error::OwnershipMismatch);
                }
                self.owner
                    .expiry
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .retirement_reaps()?;
                if !*model_finished {
                    plan.finish(receipt.verify(permit)?)
                        .map_err(|_| Error::OwnershipMismatch)?;
                    *model_finished = true;
                }
                if !*queued {
                    #[cfg(test)]
                    if let Some(proof) = &mut self.lab_links_writer {
                        if !proof.prequeue_refused {
                            self.journal.lab_refuse_prequeue_cleanup(
                                permit,
                                receipt.clone(),
                                *started_at,
                            )?;
                            proof.prequeue_refused = true;
                        }
                        self.journal.lab_hold_retirement_write();
                    }
                    match self.journal.start_cleanup_progress(
                        permit,
                        super::owned::CleanupStage::LinksRemoved,
                        Some(receipt.clone()),
                        *started_at,
                    ) {
                        Ok(()) => *queued = true,
                        Err(Error::LockBusy) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
                #[cfg(test)]
                if let Some(proof) = &mut self.lab_links_writer
                    && !proof.released
                    && self.journal.lab_write_checkpoint()?
                {
                    let (witness, original) = self.journal.lab_original_writer()?;
                    if original.2 != *started_at + 2.
                        || proof.original.is_some_and(|before| before != original)
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                    if proof.witness.is_none() {
                        proof.witness = Some(witness);
                        proof.original = Some(original);
                        proof.started_at = Some(*started_at);
                    }
                    if proof.pending_polls >= 2 {
                        self.journal.lab_release_write()?;
                        proof.released = true;
                    }
                }
                let next = self
                    .journal
                    .poll_cleanup_progress(permit, super::owned::CleanupStage::LinksRemoved)?;
                #[cfg(test)]
                if next.is_none()
                    && let Some(proof) = &mut self.lab_links_writer
                    && proof.witness.is_some()
                    && !proof.released
                {
                    proof.pending_polls =
                        proof.pending_polls.checked_add(1).ok_or(Error::TooLarge)?;
                }
                if let Some(next) = next {
                    #[cfg(test)]
                    if let Some(proof) = &mut self.lab_links_writer {
                        proof.verified_at = Some(vprouter_core::health::boot_seconds());
                    }
                    let previous = std::mem::replace(&mut self.phase, RetirementPhase::Containment);
                    let RetirementPhase::LinksCleaned { plan, receipt, .. } = previous else {
                        unreachable!("matched phase")
                    };
                    self.completed_links = Some((plan, receipt));
                    self.phase = RetirementPhase::ProducerIntent {
                        permit: Box::new(next),
                        started_at: vprouter_core::health::boot_seconds(),
                        queued: false,
                    };
                }
            }
            RetirementPhase::ProducerIntent {
                permit,
                started_at,
                queued,
            } => {
                original_audit_time(*started_at, vprouter_core::health::boot_seconds())?;
                if !self.owner.guard.retirement_removed()? {
                    return Err(Error::OwnershipMismatch);
                }
                self.owner
                    .expiry
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .retirement_reaps()?;
                if !*queued {
                    match self.journal.start_cleanup_progress(
                        permit,
                        super::owned::CleanupStage::ProducerIntent,
                        None,
                        *started_at,
                    ) {
                        Ok(()) => *queued = true,
                        Err(Error::LockBusy) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
                if let Some(next) = self
                    .journal
                    .poll_cleanup_progress(permit, super::owned::CleanupStage::ProducerIntent)?
                {
                    self.phase = RetirementPhase::ProducerAuthorized(Box::new(next));
                }
            }
            RetirementPhase::ProducerAuthorized(permit) => {
                let plan = &mut self
                    .completed_links
                    .as_mut()
                    .ok_or(Error::OwnershipMismatch)?
                    .0;
                let child = permit.launch_producer(
                    &self.journal,
                    &self.owner.guard,
                    self.owner.expiry.as_ref().ok_or(Error::OwnershipMismatch)?,
                    plan,
                    self.transport.clone(),
                )?;
                let previous = std::mem::replace(&mut self.phase, RetirementPhase::Containment);
                let RetirementPhase::ProducerAuthorized(permit) = previous else {
                    unreachable!("matched phase")
                };
                self.phase = RetirementPhase::ProducerRemoving {
                    permit,
                    child: Box::new(child),
                };
            }
            RetirementPhase::ProducerRemoving { child, .. } => {
                if let Some(receipt) = child.poll()? {
                    let previous = std::mem::replace(&mut self.phase, RetirementPhase::Containment);
                    let RetirementPhase::ProducerRemoving { permit, child } = previous else {
                        unreachable!("matched phase")
                    };
                    drop(child);
                    self.phase = RetirementPhase::ProducerRemoved {
                        permit,
                        receipt: std::rc::Rc::new(receipt),
                        started_at: vprouter_core::health::boot_seconds(),
                        queued: false,
                    };
                }
            }
            RetirementPhase::ProducerRemoved {
                permit,
                receipt,
                started_at,
                queued,
            } => {
                original_audit_time(*started_at, vprouter_core::health::boot_seconds())?;
                if !self.owner.guard.retirement_root_removed()? {
                    return Err(Error::OwnershipMismatch);
                }
                self.owner
                    .expiry
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .retirement_reaps()?;
                if !*queued {
                    match self.journal.start_cleanup_progress(
                        permit,
                        super::owned::CleanupStage::ProducerRemoved,
                        Some(receipt.clone()),
                        *started_at,
                    ) {
                        Ok(()) => *queued = true,
                        Err(Error::LockBusy) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
                if let Some(next) = self
                    .journal
                    .poll_cleanup_progress(permit, super::owned::CleanupStage::ProducerRemoved)?
                {
                    self.phase = RetirementPhase::FinalWriting {
                        permit: Box::new(next),
                        receipt: receipt.clone(),
                        started_at: vprouter_core::health::boot_seconds(),
                        queued: false,
                    };
                }
            }
            RetirementPhase::FinalWriting {
                permit,
                receipt,
                started_at,
                queued,
            } => {
                original_audit_time(*started_at, vprouter_core::health::boot_seconds())?;
                if !*queued {
                    match self.journal.start_final_retirement(
                        permit,
                        &self.owner.guard,
                        self.owner.expiry.as_ref().ok_or(Error::OwnershipMismatch)?,
                        receipt.clone(),
                        *started_at,
                    ) {
                        Ok(()) => *queued = true,
                        Err(Error::LockBusy) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
                if let Some(retired) =
                    self.journal
                        .poll_final_retirement(permit, receipt.clone(), *started_at)?
                {
                    self.phase = RetirementPhase::FinalCollection(Box::new(retired));
                }
            }
            RetirementPhase::FinalCollection(permit) => {
                permit.verify(&self.journal)?;
                if std::rc::Rc::strong_count(&self.transport) != 1
                    || !self.owner.completions.is_empty()
                    || self
                        .owner
                        .host
                        .as_ref()
                        .is_some_and(|h| !h.native_drained())
                    || self.owner.inspection.as_ref().is_some_and(|i| !i.drained())
                {
                    return Err(Error::OwnershipMismatch);
                }
                // Validate every native bundle before taking any original owner.
                permit.verify_guard_release(&self.journal, &self.owner.guard)?;
                permit.verify_expiry_release(
                    &self.journal,
                    self.owner.expiry.as_ref().ok_or(Error::OwnershipMismatch)?,
                )?;
                self.transport
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?
                    .release_retired(permit, &self.journal)?;
                self.owner
                    .expiry
                    .as_mut()
                    .ok_or(Error::OwnershipMismatch)?
                    .release_retired(permit, &self.journal)?;
                self.owner.expiry.take();
                self.owner.guard.release_retired(permit, &self.journal)?;
                self.owner.inspection.take();
                self.phase = RetirementPhase::Complete;
            }
            RetirementPhase::Complete => {}
        }
        Ok(())
    }
}
fn poll_retained_retirements() {
    RETAINED_RETIREMENTS.with(|owners| {
        owners.borrow_mut().retain_mut(|owner| {
            if owner.creator == std::process::id() {
                let _ = owner.poll();
                !matches!(owner.phase, RetirementPhase::Complete)
            } else {
                true
            }
        });
    });
}
fn retirements_drained() -> bool {
    RETIREMENT_COUNT.with(|count| count.get() == 0)
}
// A rejected attachment can already own native children. Keep its collectors and
// receipts separate from this member's journal until actual drainage is proven.
struct RejectedExpiry {
    owner: super::expiry::OwnerExecutors,
    receipts: Vec<super::expiry::FixedCompletion>,
    error: Option<Error>,
}

fn independent_collection<T>(
    drain: Result<bool>,
    failure: &mut Option<Error>,
    collect: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if let Err(error) = drain {
        failure.get_or_insert(error);
    }
    collect()
}
fn start_retained<T>(
    queue: &mut std::collections::VecDeque<T>,
    start: impl FnOnce(&T) -> Result<()>,
) -> Result<()> {
    if let Some(receipt) = queue.front() {
        start(receipt)?;
        queue.pop_front();
    }
    Ok(())
}
#[cfg(test)]
pub(super) struct LabHostObservation {
    pub sequence: u64,
    pub sent_at: f64,
    pub verified_at: f64,
    pub bytes: Vec<u8>,
}
type HostWindow = std::rc::Rc<std::cell::RefCell<vprouter_network::HostAuditTicket>>;
struct HostService {
    allocation: String,
    lifecycle: String,
    authority: vprouter_network::HostAuthority,
    record: vprouter_core::allocation::AllocationRecord,
    exit: String,
    directory: OwnedFd,
    _inventory: super::inventory::Registration,
    drain_error: Option<Error>,
    abandoned: Option<(HostWindow, Progress)>,
    pending: Option<(
        HostWindow,
        super::kernel::host_audit::HostAuditChild,
        Progress,
    )>,
    #[cfg(test)]
    pause_next: bool,
    #[cfg(test)]
    pause_next_links: bool,
    #[cfg(test)]
    last_observation: Option<(Progress, Vec<u8>, f64)>,
    #[cfg(test)]
    capture_observations: bool,
    #[cfg(test)]
    completed: u64,
}
impl HostService {
    fn start(&mut self, progress: Progress, journal: &super::owned::JournalServer) -> Result<()> {
        original_audit_time(progress.sent_at, vprouter_core::health::boot_seconds())?;
        if self.pending.is_some()
            || self.abandoned.is_some()
            || !self._inventory.contains(self.directory.as_fd())
        {
            return Err(Error::Interrupted);
        }
        let lease = journal.host_job_lease(&self.allocation, &self.exit, &self.lifecycle)?;
        let directory = self
            .directory
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let ticket = self
            .authority
            .begin_audit_at(&self.record, &self.exit, progress.sent_at)
            .map_err(|_| Error::OwnershipMismatch)?;
        let ticket = std::rc::Rc::new(std::cell::RefCell::new(ticket));
        let job = super::kernel::host_audit::spawn(
            directory,
            lease,
            Some(ticket.clone()),
            progress.sent_at + 2.,
            #[cfg(test)]
            std::mem::take(&mut self.pause_next),
            #[cfg(test)]
            false,
            #[cfg(test)]
            std::mem::take(&mut self.pause_next_links),
        )?;
        self.pending = Some((ticket, job, progress));
        Ok(())
    }
    fn poll(&mut self) -> Result<Option<Progress>> {
        let Some((ticket, child, progress)) = &mut self.pending else {
            return Ok(None);
        };
        original_audit_time(progress.sent_at, vprouter_core::health::boot_seconds())?;
        let Some(observation) = child.poll()? else {
            return Ok(None);
        };
        self.authority
            .complete_audit(
                &*ticket.try_borrow().map_err(|_| Error::LockBusy)?,
                &observation,
            )
            .map_err(|error| {
                #[cfg(test)]
                eprintln!("LAB_HOST_CANONICAL_REJECTION reason={error}");
                #[cfg(not(test))]
                let _ = error;
                Error::NetworkPolicy
            })?;
        original_audit_time(progress.sent_at, vprouter_core::health::boot_seconds())?;
        let progress = progress.clone();
        #[cfg(test)]
        if self.capture_observations {
            self.last_observation = Some((
                progress.clone(),
                observation.encode().map_err(|_| Error::TooLarge)?,
                vprouter_core::health::boot_seconds(),
            ));
        }
        self.pending.take();
        #[cfg(test)]
        {
            self.completed += 1;
        }
        Ok(Some(progress))
    }
    fn cancel(&mut self) -> Result<()> {
        if let Some((_, child, _)) = &mut self.pending {
            child.cancel()?;
        }
        Ok(())
    }
    fn native_drained(&self) -> bool {
        self.pending.is_none()
    }
    fn drain(&mut self) -> bool {
        if let Some((_, child, _)) = &mut self.pending {
            if !child.drained()
                && let Err(error) = child.poll()
            {
                self.drain_error.get_or_insert(error);
            }
            if !child.drained() {
                return false;
            }
        }
        if let Some((ticket, child, progress)) = self.pending.take() {
            // Only actual native reap permits collection. Preserve the exact
            // abandoned request/ticket without ACK or deadline reset, while the
            // complete job Drop releases its per-member native receipt/lease.
            if self.abandoned.is_some() {
                self.pending = Some((ticket, child, progress));
                self.drain_error.get_or_insert(Error::OwnershipMismatch);
                return false;
            }
            if ticket
                .try_borrow_mut()
                .map_err(|_| Error::LockBusy)
                .and_then(|mut ticket| ticket.retire().map_err(|_| Error::OwnershipMismatch))
                .is_err()
            {
                self.pending = Some((ticket, child, progress));
                self.drain_error.get_or_insert(Error::OwnershipMismatch);
                return false;
            }
            self.abandoned = Some((ticket, progress));
            drop(child);
        }
        true
    }
}
/// A terminal return does not authorize cleanup. The caller must retain this
/// owner and all pins/locks until every old writer/mutator is proven dead and
/// replacement Offline has been installed/read back by retirement authority.
pub(super) struct TerminalGuard {
    pub owner: ExternalOwner,
    pub reason: Error,
}
#[cfg(test)]
impl TerminalGuard {
    pub fn lab_reap_exited(&self) -> Result<()> {
        self.owner.guard.child.lab_wait_dead()
    }
}
impl ExternalOwner {
    #[cfg(test)]
    pub(super) fn lab_hold_next_host_links(&mut self) -> Result<()> {
        let host = self.host.as_mut().ok_or(Error::OwnershipMismatch)?;
        if host.pause_next_links {
            return Err(Error::Interrupted);
        }
        host.pause_next_links = true;
        host.capture_observations = true;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn lab_host_links_checkpoint(&self) -> Result<Option<(u32, u64, u64, f64)>> {
        let Some((_, child, progress)) = self.host.as_ref().and_then(|host| host.pending.as_ref())
        else {
            return Ok(None);
        };
        let Some((pid, start, deadline)) = child.lab_links_checkpoint()? else {
            return Ok(None);
        };
        if deadline != progress.sent_at + 2. {
            return Err(Error::OwnershipMismatch);
        }
        Ok(Some((pid, start, progress.sequence, progress.sent_at)))
    }
    #[cfg(test)]
    pub(super) fn lab_release_host_links(&mut self, exact: (u32, u64, u64, f64)) -> Result<()> {
        if self.lab_host_links_checkpoint()? != Some(exact) {
            return Err(Error::OwnershipMismatch);
        }
        self.host
            .as_mut()
            .and_then(|host| host.pending.as_mut())
            .ok_or(Error::OwnershipMismatch)?
            .1
            .lab_release_links()
    }
    #[cfg(test)]
    pub(super) fn lab_host_observation(&self, sequence: u64) -> Result<Option<LabHostObservation>> {
        let host = self.host.as_ref().ok_or(Error::OwnershipMismatch)?;
        Ok(host
            .last_observation
            .as_ref()
            .filter(|(progress, _, _)| progress.sequence >= sequence)
            .map(|(progress, bytes, verified_at)| LabHostObservation {
                sequence: progress.sequence,
                sent_at: progress.sent_at,
                verified_at: *verified_at,
                bytes: bytes.clone(),
            }))
    }
    #[cfg(test)]
    pub(super) fn lab_reject_mixed_replay(&self, bytes: &[u8]) -> Result<()> {
        let host = self.host.as_ref().ok_or(Error::OwnershipMismatch)?;
        let ticket = host
            .authority
            .begin_audit(&host.record, &host.exit)
            .map_err(|_| Error::OwnershipMismatch)?;
        let replay = vprouter_network::HostObservation::decode(bytes)
            .map_err(|_| Error::OwnershipMismatch)?;
        if host.authority.complete_audit(&ticket, &replay)
            != Err(vprouter_network::Error::HostDrift)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn lab_host_window(
        &self,
    ) -> Result<std::rc::Weak<std::cell::RefCell<vprouter_network::HostAuditTicket>>> {
        let ticket = &self
            .host
            .as_ref()
            .and_then(|host| host.pending.as_ref())
            .ok_or(Error::OwnershipMismatch)?
            .0;
        Ok(std::rc::Rc::downgrade(ticket))
    }
    #[cfg(test)]
    pub(super) fn lab_native_drop_witness(
        &self,
    ) -> Result<(
        super::kernel::GuardDrain,
        super::kernel::Survivor,
        super::kernel::Survivor,
        u64,
        f64,
    )> {
        let (_, host, progress) = self
            .host
            .as_ref()
            .and_then(|host| host.pending.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        Ok((
            self.guard.lab_drain_receipt()?,
            self.guard.lab_native_handle()?,
            host.lab_native_handle()?,
            progress.sequence,
            progress.sent_at + 2.,
        ))
    }
    #[cfg(test)]
    pub(super) fn lab_require_foreign_inert_and_drop_inspector(&mut self) -> Result<()> {
        self.guard.lab_require_foreign_inert()?;
        if let Some(host) = &self.host {
            host._inventory.lab_require_inert()?;
        }
        if let Some(inspection) = &self.inspection {
            inspection.lab_require_foreign_inert()?;
        }
        if let Some(expiry) = &self.expiry {
            expiry.lab_require_inert()?;
        }
        drop(self.inspection.take());
        if !super::kernel::early_forks_drained() {
            return Err(Error::ChildFailed);
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn spawn(
        domains: super::supervision::Domains,
        inputs: super::inventory::GuardInputs,
        run: impl FnOnce(&GuardOwner) -> Result<()>,
    ) -> Result<Self> {
        domains.verify_owner()?;
        let signals = super::kernel::OwnerSignals::new()?;
        let lifecycle = domains.lifecycle().to_owned();
        let guard_domains = domains.clone();
        // Validate all fallible scalar setup before creating a native guard.
        let clock = Watchdog::new(lifecycle, vprouter_core::health::boot_seconds())?;
        let guard = super::kernel::spawn_owned_guard(&domains, inputs, |channel| {
            let owner = GuardOwner::from_gate(channel, guard_domains)?;
            owner.heartbeat()?;
            run(&owner)
        })?;
        Ok(Self::from_guard(&domains, guard, clock, signals))
    }
    fn from_guard(
        domains: &super::supervision::Domains,
        guard: super::kernel::ManagedGuard,
        clock: Watchdog,
        signals: super::kernel::OwnerSignals,
    ) -> Self {
        Self {
            allocation: domains.allocation().into(),
            exit_id: domains.exit_id().into(),
            guard,
            clock,
            signals,
            pending: None,
            terminal: None,
            host: None,
            inspection: None,
            inspection_drain_error: None,
            journal_drain_error: None,
            abandoned_read: None,
            expiry: None,
            rejected_expiry: Vec::new(),
            spawning: None,
            completions: std::collections::VecDeque::new(),
            completion_error: None,
        }
    }
    /// Setup errors terminalize in place. The caller retains this same owner,
    /// guard, scopes and expiry actors and continues the deployment drain loop.
    pub fn install_inspection(
        &mut self,
        policy: super::inspection::Policy<'_>,
        journal: &mut super::owned::JournalServer,
    ) {
        if self.terminal.is_some() {
            return;
        }
        let result = (|| {
            if self.inspection.is_some() {
                return Err(Error::OwnershipMismatch);
            }
            policy.binds(&self.allocation, &self.exit_id)?;
            super::inspection::Service::new(policy, &self.guard.child)
        })();
        match result {
            Ok(service) => self.inspection = Some(service),
            Err(error) => self.terminate(Some(journal), error),
        }
    }
    pub fn install_expiry(
        &mut self,
        mut expiry: super::expiry::OwnerExecutors,
        journal: &mut super::owned::JournalServer,
    ) {
        let binding = expiry.binds(&self.allocation, &self.exit_id, &self.clock.lifecycle);
        if binding.is_ok() && self.expiry.is_none() && self.terminal.is_none() {
            self.expiry = Some(expiry);
            return;
        }
        let error = expiry.cancel_spawn().err();
        self.rejected_expiry.push(RejectedExpiry {
            owner: expiry,
            receipts: Vec::new(),
            error,
        });
        self.terminate(
            Some(journal),
            binding.err().unwrap_or(Error::OwnershipMismatch),
        );
    }
    fn service_completions(&mut self, journal: &mut super::owned::JournalServer) -> Result<()> {
        // Each collector gets a turn even if another retained role failed.
        for rejected in &mut self.rejected_expiry {
            match rejected.owner.poll() {
                Ok(receipts) => rejected.receipts.extend(receipts),
                Err(error) => {
                    rejected.error.get_or_insert(error);
                }
            }
        }
        let drain = if self.terminal.is_some() {
            self.inspection
                .as_mut()
                .map_or(Ok(true), |inspection| inspection.drain())
        } else {
            Ok(true)
        };
        if let Some(expiry) = &mut self.expiry {
            for completion in
                independent_collection(drain, &mut self.inspection_drain_error, || expiry.poll())?
            {
                if self.completions.len() >= 3 {
                    return Err(Error::TooLarge);
                }
                self.completions.push_back(completion);
            }
        } else {
            independent_collection(drain, &mut self.inspection_drain_error, || Ok(()))?;
        }
        // Persistence failure disables new writes, never independent actor
        // collection or actual reap. Queued receipts retain original timestamps.
        if self.completion_error.is_some() {
            return Ok(());
        }
        if journal.completing() {
            journal.poll_completion()?;
        } else if self.pending.is_none() && journal.idle() {
            start_retained(&mut self.completions, |completion| {
                journal.start_completion(completion)
            })?;
        }
        Ok(())
    }
    pub fn install_host_audit(
        &mut self,
        authority: &vprouter_network::HostAuthority,
        journal: &mut super::owned::JournalServer,
    ) {
        if self.terminal.is_some() {
            return;
        }
        let result = (|| {
            if self.host.is_some()
                || self.allocation != journal.allocation()
                || self.exit_id != journal.exit_id()
                || self.clock.lifecycle != journal.lifecycle()
            {
                return Err(Error::OwnershipMismatch);
            }
            let record = journal.host_allocation();
            authority
                .begin_audit(&record, &self.exit_id)
                .map_err(|_| Error::OwnershipMismatch)?;
            let directory = journal.host_directory()?;
            let inventory = super::inventory::Registration::owned(&[directory.as_fd()])?;
            Ok(HostService {
                allocation: self.allocation.clone(),
                lifecycle: self.clock.lifecycle.clone(),
                authority: authority.clone(),
                record,
                exit: self.exit_id.clone(),
                directory,
                _inventory: inventory,
                drain_error: None,
                abandoned: None,
                pending: None,
                #[cfg(test)]
                pause_next: false,
                #[cfg(test)]
                pause_next_links: false,
                #[cfg(test)]
                last_observation: None,
                #[cfg(test)]
                capture_observations: false,
                #[cfg(test)]
                completed: 0,
            })
        })();
        match result {
            Ok(host) => self.host = Some(host),
            Err(error) => self.terminate(Some(journal), error),
        }
    }
    pub fn supervise(self) -> Result<TerminalGuard> {
        self.supervise_inner(None)
    }
    pub fn supervise_journal(
        self,
        journal: &mut super::owned::JournalServer,
    ) -> Result<TerminalGuard> {
        if journal.exit_id() != self.exit_id
            || journal.allocation() != self.allocation
            || journal.lifecycle() != self.clock.lifecycle
        {
            return Err(Error::OwnershipMismatch);
        }
        self.supervise_inner(Some(journal))
    }
    fn acknowledge(&self, progress: Progress) -> Result<()> {
        let now = vprouter_core::health::boot_seconds();
        if now < progress.sent_at || now - progress.sent_at >= 2. {
            return Err(Error::Deadline);
        }
        self.guard.child.require_live()?;
        send(
            &self.guard.channel,
            &Reply {
                allocation: self.allocation.clone(),
                exit_id: self.exit_id.clone(),
                progress,
                inspection: None,
                executor: None,
            },
        )
    }
    fn service_once(
        &mut self,
        mut journal: Option<&mut super::owned::JournalServer>,
    ) -> Result<()> {
        self.clock.check(vprouter_core::health::boot_seconds())?;
        self.guard.child.require_live()?;
        if let Some(reason) = self.expiry.as_ref().and_then(|e| e.failure()) {
            return Err(reason);
        }
        if let Some(inspection) = &mut self.inspection {
            if let Some(receipt) = inspection.poll()? {
                let progress = Progress {
                    lifecycle: self.clock.lifecycle.clone(),
                    sequence: receipt.job.sequence,
                    sent_at: receipt.job.sent_at,
                };
                original_audit_time(progress.sent_at, vprouter_core::health::boot_seconds())?;
                self.guard.child.require_live()?;
                send(
                    &self.guard.channel,
                    &Reply {
                        allocation: self.allocation.clone(),
                        exit_id: self.exit_id.clone(),
                        progress,
                        executor: None,
                        inspection: Some(receipt),
                    },
                )?;
                return Ok(());
            }
            if inspection.pending() {
                return Ok(());
            }
        }
        if let Some(progress) = self.spawning.clone() {
            original_audit_time(progress.sent_at, vprouter_core::health::boot_seconds())?;
            let expiry = self.expiry.as_mut().ok_or(Error::OwnershipMismatch)?;
            let journal = journal.as_deref_mut().ok_or(Error::OwnershipMismatch)?;
            if journal.registering() {
                if journal.poll_registration(&self.guard.child)? {
                    expiry.release_registered()?;
                }
                return Ok(());
            }
            if !expiry.released() {
                if let Some(receipt) = expiry.poll_placement()? {
                    journal.start_registration(receipt, progress.sent_at)?;
                }
                return Ok(());
            }
            if let Some((identity, control, pidfd)) = expiry.poll_spawn()? {
                original_audit_time(progress.sent_at, vprouter_core::health::boot_seconds())?;
                send_descriptors(
                    &self.guard.channel,
                    &Reply {
                        allocation: self.allocation.clone(),
                        exit_id: self.exit_id.clone(),
                        progress,
                        inspection: None,
                        executor: Some(identity),
                    },
                    &[control, pidfd],
                )?;
                expiry.transferred()?;
                self.spawning = None;
            }
            return Ok(());
        }
        if journal.as_ref().is_some_and(|j| j.completing()) {
            return Ok(());
        }
        if self.host.as_ref().is_some_and(|h| h.pending.is_some()) {
            if let Some(progress) = self.host.as_mut().ok_or(Error::Interrupted)?.poll()? {
                self.acknowledge(progress)?;
            }
            return Ok(());
        }
        if self.pending.is_some() {
            if journal
                .as_deref_mut()
                .ok_or(Error::Interrupted)?
                .poll(&self.guard.child)?
            {
                let progress = self.pending.take().ok_or(Error::Interrupted)?;
                self.acknowledge(progress)?;
            }
            return Ok(());
        }
        if let Some(request) = receive::<Request>(&self.guard.channel)? {
            #[cfg(test)]
            eprintln!(
                "LAB_OWNER_REQUEST sequence={} kind={}",
                request.progress.sequence,
                match &request.operation {
                    Operation::Progress => "progress",
                    Operation::HostAudit => "host_audit",
                    Operation::SpawnExecutor { .. } => "spawn_executor",
                    Operation::Journal(_) => "journal",
                    Operation::Inspect(operation) => match operation {
                        super::inspection::Request::Container => "inspect_container",
                        super::inspection::Request::RegisterChild { .. } =>
                            "inspect_register_child",
                        super::inspection::Request::PinDaemon { .. } => "inspect_pin_daemon",
                        super::inspection::Request::PinSender { .. } => "inspect_pin_sender",
                        super::inspection::Request::Reinspect { .. } => "inspect_reinspect",
                    },
                }
            );
            if request.allocation != self.allocation || request.exit_id != self.exit_id {
                return Err(Error::AllocationMismatch);
            }
            self.clock.progress(
                request.progress.clone(),
                vprouter_core::health::boot_seconds(),
            )?;
            match request.operation {
                Operation::Progress => self.acknowledge(request.progress)?,
                Operation::Inspect(operation) => {
                    self.inspection
                        .as_mut()
                        .ok_or(Error::OwnershipMismatch)?
                        .start(
                            operation,
                            request.progress.sequence,
                            request.progress.sent_at,
                        )?;
                }
                Operation::SpawnExecutor { scope, started_at } => {
                    journal
                        .as_ref()
                        .ok_or(Error::OwnershipMismatch)?
                        .authorize_spawn()?;
                    self.expiry
                        .as_mut()
                        .ok_or(Error::OwnershipMismatch)?
                        .spawn(
                            &self.guard.child,
                            scope,
                            started_at,
                            request.progress.sent_at,
                        )?;
                    self.spawning = Some(request.progress);
                }
                Operation::HostAudit => self.host.as_mut().ok_or(Error::OwnershipMismatch)?.start(
                    request.progress,
                    journal.as_ref().ok_or(Error::OwnershipMismatch)?,
                )?,
                Operation::Journal(operation) => {
                    match operation.as_ref() {
                        super::owned::JournalRequest::BeginTerminal { .. } => {
                            if let Some(expiry) = &mut self.expiry {
                                expiry.begin(request.progress.sent_at)?;
                            }
                        }
                        super::owned::JournalRequest::RegisterExecutor { identity, .. }
                        | super::owned::JournalRequest::AcknowledgeExecutor { identity, .. } => {
                            self.expiry
                                .as_ref()
                                .ok_or(Error::OwnershipMismatch)?
                                .registered_identity(identity)?
                        }
                        super::owned::JournalRequest::VerifyExecutors { children, .. } => {
                            for identity in children {
                                self.expiry
                                    .as_ref()
                                    .ok_or(Error::OwnershipMismatch)?
                                    .registered_identity(identity)?;
                            }
                        }
                        super::owned::JournalRequest::CompleteExecutor { .. } => {
                            return Err(Error::OwnershipMismatch);
                        }
                        _ => {}
                    }
                    journal.ok_or(Error::OwnershipMismatch)?.start(
                        *operation,
                        &self.guard.child,
                        request.progress.sent_at,
                    )?;
                    self.pending = Some(request.progress);
                }
            }
        }
        Ok(())
    }
    fn terminate(&mut self, journal: Option<&mut super::owned::JournalServer>, reason: Error) {
        if self.terminal.is_some() {
            return;
        }
        // Retain every handle even if fencing itself fails. A terminal return
        // never grants retirement; the caller must prove actual drainage.
        let inspection_error = self
            .inspection
            .as_mut()
            .and_then(|inspection| inspection.cancel().err());
        let host_error = self.host.as_mut().and_then(|host| host.cancel().err());
        let journal_error = journal.and_then(|journal| {
            if journal.completing() {
                None
            } else {
                journal.fence().err()
            }
        });
        let expiry_error = self
            .expiry
            .as_mut()
            .and_then(|expiry| expiry.cancel_spawn().err());
        let guard_error = self.guard.freeze().err();
        let reason = inspection_error
            .or(host_error)
            .or(journal_error)
            .or(expiry_error)
            .or(guard_error)
            .unwrap_or(reason);
        self.clock.terminal = true;
        self.terminal = Some(reason);
        #[cfg(test)]
        eprintln!("LAB_OWNER_TERMINAL reason={reason}");
    }
    fn supervise_inner(
        mut self,
        mut journal: Option<&mut super::owned::JournalServer>,
    ) -> Result<TerminalGuard> {
        loop {
            if let Err(reason) = super::kernel::poll_early_forks() {
                self.terminate(journal.as_deref_mut(), reason);
                return Ok(TerminalGuard {
                    reason,
                    owner: self,
                });
            }
            if let Some(journal) = journal.as_deref_mut()
                && let Err(reason) = self.service_completions(journal)
            {
                self.completion_error = Some(reason);
                self.terminate(Some(journal), reason);
                return Ok(TerminalGuard {
                    reason,
                    owner: self,
                });
            }
            let result = match self.signals.stop_requested() {
                Ok(true) => Err(Error::Interrupted),
                Ok(false) => self.service_once(journal.as_deref_mut()),
                Err(error) => Err(error),
            };
            if let Err(reason) = result {
                self.terminate(journal.as_deref_mut(), reason);
                return Ok(TerminalGuard {
                    reason: self.terminal.ok_or(Error::Interrupted)?,
                    owner: self,
                });
            }
            if let Err(error) = owner_wait(std::slice::from_ref(&self)) {
                self.terminate(journal.as_deref_mut(), error);
                return Ok(TerminalGuard {
                    reason: self.terminal.ok_or(Error::Interrupted)?,
                    owner: self,
                });
            }
        }
    }
}
/// One canonical deployment loop. Slots retain failed members and IO actors;
/// one exit's deadline, disconnect or IO failure never stops another slot.
/// Construction/placement happens before attaching this loop; live dynamic
/// admission must use an independent bounded actor before adding a new slot.
pub(super) struct DeploymentOwner<'r> {
    owners: &'r mut [ExternalOwner],
    journals: &'r mut [super::owned::JournalServer],
    signals: super::kernel::OwnerSignals,
}
impl<'r> DeploymentOwner<'r> {
    pub fn new(
        owners: &'r mut [ExternalOwner],
        journals: &'r mut [super::owned::JournalServer],
    ) -> Result<Self> {
        if owners.is_empty()
            || owners.len() != journals.len()
            || owners.len() > vprouter_core::config::MAX_EXITS
        {
            return Err(Error::AllocationMismatch);
        }
        let allocation = &owners[0].allocation;
        let mut exits = std::collections::HashSet::new();
        let mut lifecycles = std::collections::HashSet::new();
        for (owner, journal) in owners.iter().zip(journals.iter()) {
            if &owner.allocation != allocation
                || owner.allocation != journal.allocation()
                || owner.exit_id != journal.exit_id()
                || owner.clock.lifecycle != journal.lifecycle()
                || !exits.insert(&owner.exit_id)
                || !lifecycles.insert(&owner.clock.lifecycle)
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        Ok(Self {
            owners,
            journals,
            signals: super::kernel::OwnerSignals::new()?,
        })
    }
    pub fn poll_once(&mut self) -> Result<bool> {
        if let Err(reason) = super::kernel::poll_early_forks() {
            self.signals.fence(reason)?;
            // A failed native early-fork reap cannot discard the deployment or
            // its actors. Retain/fence all affected ownership, then keep polling.
            for (owner, journal) in self.owners.iter_mut().zip(self.journals.iter_mut()) {
                owner.terminate(Some(journal), reason);
            }
        }
        poll_retained_retirements();
        let stop = match self.signals.stop_requested() {
            Ok(false) => None,
            Ok(true) => Some(Error::Interrupted),
            Err(error) => Some(error),
        };
        for (owner, journal) in self.owners.iter_mut().zip(self.journals.iter_mut()) {
            if let Err(reason) = owner.service_completions(journal) {
                owner.completion_error = Some(reason);
                owner.terminate(Some(journal), reason);
                // A terminal member retains all actor/IO authority. Its failure
                // must never prevent another member receiving its next turn.
            }
            if owner.terminal.is_some() {
                if let Some(host) = &mut owner.host {
                    host.drain();
                }
                match journal.poll_terminal_io() {
                    Ok(super::owned::TerminalIo::ReadReaped { deadline }) => {
                        if owner
                            .pending
                            .as_ref()
                            .is_some_and(|p| p.sent_at + 2. == deadline)
                            && owner.abandoned_read.is_none()
                        {
                            owner.abandoned_read = owner.pending.take();
                        } else {
                            owner
                                .journal_drain_error
                                .get_or_insert(Error::OwnershipMismatch);
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        owner.journal_drain_error.get_or_insert(error);
                    }
                }
                continue;
            }
            let result = stop.map_or_else(|| owner.service_once(Some(journal)), Err);
            if let Err(reason) = result {
                owner.terminate(Some(journal), reason);
            }
        }
        Ok(super::kernel::early_forks_drained()
            && retirements_drained()
            && self
                .owners
                .iter()
                .zip(self.journals.iter())
                .all(|(owner, journal)| {
                    owner.terminal.is_some()
                        && owner.completions.is_empty()
                        && !journal.completing()
                        && journal.native_drained()
                        && owner.host.as_ref().is_none_or(HostService::native_drained)
                        && owner.journal_drain_error.is_none()
                        && owner.expiry.as_ref().is_none_or(|e| e.finished())
                        && owner
                            .rejected_expiry
                            .iter()
                            .all(|e| e.owner.finished() && e.receipts.is_empty())
                        && owner.inspection.as_ref().is_none_or(|i| i.drained())
                }))
    }
    pub(super) fn poll_admission(
        &mut self,
        pending: &mut PendingOwner,
        journal: &mut super::owned::JournalServer,
    ) -> Result<Option<ExternalOwner>> {
        self.poll_once()?;
        pending.poll(journal)
    }
    pub fn run(&mut self) -> Result<()> {
        while !self.poll_once()? {
            if let Err(error) = owner_wait(self.owners) {
                for (owner, journal) in self.owners.iter_mut().zip(self.journals.iter_mut()) {
                    owner.terminate(Some(journal), error);
                }
            }
        }
        Ok(())
    }
}
#[cfg(test)]
impl DeploymentOwner<'_> {
    pub fn lab_guard_stopped(&self, index: usize, start: u64) -> Result<bool> {
        let child = &self.owners[index].guard.child;
        child.require_live()?;
        if child.start_time()? != start {
            return Err(Error::ProcessChanged);
        }
        Ok(child.lab_require_stopped(start).is_ok())
    }
    pub fn lab_placement_checkpoint(&mut self, index: usize) -> Result<Option<(u32, u64, f64)>> {
        self.owners[index]
            .expiry
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .lab_placement_checkpoint()
    }
    pub fn lab_placement_drained_without_grant(&self, index: usize) -> Result<bool> {
        self.owners[index]
            .expiry
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .lab_placement_drained_without_grant()
    }
    pub fn lab_terminate(&mut self, index: usize) {
        self.owners[index].terminate(Some(&mut self.journals[index]), Error::Interrupted);
    }
    pub fn lab_inspection_completed(&self, index: usize) -> u64 {
        self.owners[index]
            .inspection
            .as_ref()
            .map_or(0, |i| i.lab_completed())
    }
    pub fn lab_pause_inspection(&mut self, index: usize) -> Result<()> {
        self.owners[index]
            .inspection
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .lab_pause();
        Ok(())
    }
    pub fn lab_inspection_checkpoint(&mut self, index: usize) -> Result<Option<(u32, u64, f64)>> {
        self.owners[index]
            .inspection
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .lab_checkpoint()
    }
    pub fn lab_inspection_drained_revoked(&self, index: usize) -> bool {
        self.owners[index]
            .inspection
            .as_ref()
            .is_some_and(|i| i.drained() && i.lab_revoked())
    }
    pub fn lab_host_completed(&self, index: usize) -> u64 {
        self.owners[index].host.as_ref().map_or(0, |h| h.completed)
    }
    pub fn lab_pause_host(&mut self, index: usize) -> Result<()> {
        self.owners[index]
            .host
            .as_mut()
            .ok_or(Error::OwnershipMismatch)?
            .pause_next = true;
        Ok(())
    }
    pub fn lab_host_checkpoint(&mut self, index: usize) -> Result<Option<(u32, u64, f64)>> {
        if let Some((_, child, _)) = self.owners[index]
            .host
            .as_mut()
            .and_then(|h| h.pending.as_mut())
        {
            child.lab_checkpoint()
        } else {
            Ok(None)
        }
    }
    pub fn lab_host_drained(&mut self, index: usize) -> bool {
        self.owners[index].host.as_mut().is_none_or(|h| h.drain())
    }
    pub fn lab_queued(&self, index: usize) -> bool {
        self.journals[index].lab_queued()
    }
    pub fn lab_write_checkpoint(&mut self, index: usize) -> Result<bool> {
        self.journals[index].lab_write_checkpoint()
    }
    pub fn lab_release_write(&mut self, index: usize) -> Result<()> {
        self.journals[index].lab_release_write()
    }
    pub fn lab_pending_frame(&self, index: usize) -> Option<(u64, f64)> {
        self.owners[index]
            .pending
            .as_ref()
            .map(|p| (p.sequence, p.sent_at))
    }
    pub fn lab_checkpoint(&mut self, index: usize) -> Result<Option<(u32, u64, f64)>> {
        self.journals
            .get_mut(index)
            .ok_or(Error::InvalidSpec)?
            .lab_checkpoint()
    }
    pub fn lab_completed(&self, index: usize) -> u64 {
        self.journals[index].lab_completed()
    }
    pub fn lab_terminal(&self, index: usize) -> Option<Error> {
        self.owners[index].terminal
    }
}
#[cfg(test)]
impl ExternalOwner {
    pub fn lab_guard_removed_scope_witness(
        &mut self,
    ) -> Result<(
        super::kernel::GuardDrain,
        std::rc::Rc<std::cell::Cell<bool>>,
    )> {
        Ok((
            self.guard.lab_drain_receipt()?,
            self.guard.lab_require_removed_scope()?,
        ))
    }
    pub fn lab_expiry_all_transferred(&self) -> bool {
        self.expiry
            .as_ref()
            .is_some_and(|expiry| expiry.lab_all_transferred())
    }
    pub fn lab_guard_native_handle(&self) -> Result<super::kernel::Survivor> {
        self.guard.child.lab_clone_native()
    }
    pub fn lab_retained_expiry(&self) -> bool {
        self.expiry.is_some()
    }
    pub fn lab_last_sequence(&self) -> u64 {
        self.clock.sequence
    }
    pub(super) fn lab_normal_idle(&self) -> bool {
        self.pending.is_none()
            && self.spawning.is_none()
            && self.host.as_ref().is_none_or(|h| h.pending.is_none())
    }
    pub fn lab_terminal_reason(&self) -> Option<Error> {
        self.terminal
    }
    pub fn lab_dead_peer_rejected(&self) -> bool {
        self.terminal == Some(Error::ProcessUnavailable)
            && self
                .inspection
                .as_ref()
                .is_some_and(|i| i.lab_dead_peer_rejected())
    }
    pub fn lab_poll_terminal(&mut self, journal: &mut super::owned::JournalServer) -> Result<()> {
        self.service_completions(journal)?;
        if self.terminal.is_none()
            && let Err(reason) = self.service_once(Some(journal))
        {
            self.terminate(Some(journal), reason);
        }
        Ok(())
    }
    pub fn lab_stop(&self) -> Result<u64> {
        self.guard.child.lab_stop_and_witness()
    }
    pub fn lab_stopped(&self, start: u64) -> Result<()> {
        self.guard.child.lab_require_stopped(start)
    }
    pub fn lab_kill(&self) -> Result<()> {
        self.guard.child.lab_signal(libc::SIGKILL)?;
        self.guard.child.lab_wait_killed()
    }
    pub fn lab_executor_drained(&self) -> usize {
        self.expiry.as_ref().map_or(0, |e| e.drained())
    }
    pub(super) fn lab_executor_native_handles(&self) -> Result<Vec<super::kernel::Survivor>> {
        self.expiry
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .native_handles()
    }
    pub fn lab_executor_identities(&self) -> Result<Vec<super::owned::ExecutorIdentity>> {
        Ok(self
            .expiry
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .identities())
    }
    pub(super) fn lab_terminal_native_drained(&self) -> bool {
        self.host.as_ref().is_none_or(HostService::native_drained)
            && self.journal_drain_error.is_none()
    }
    pub(super) fn lab_abandoned_read(&self) -> Option<f64> {
        self.abandoned_read
            .as_ref()
            .map(|progress| progress.sent_at + 2.)
    }
    pub(super) fn lab_inspection_completed(&self) -> u64 {
        self.inspection
            .as_ref()
            .map_or(0, |service| service.lab_completed())
    }
    pub fn lab_identity(&self) -> Result<(u32, u64)> {
        Ok((self.guard.child.pid(), self.guard.child.start_time()?))
    }
    pub fn lab_kill_stopped(&self, start: u64) -> Result<()> {
        self.guard.child.lab_require_stopped(start)?;
        self.guard.child.lab_signal(libc::SIGKILL)?;
        self.guard.child.lab_wait_killed()
    }
    pub fn lab_reap_success(&self) -> Result<()> {
        self.guard.child.lab_wait_dead()
    }
}
fn owner_wait(owners: &[ExternalOwner]) -> Result<()> {
    let mut fds = Vec::new();
    for owner in owners.iter().filter(|owner| owner.terminal.is_none()) {
        if owner.pending.is_none() && !owner.host.as_ref().is_some_and(|h| h.pending.is_some()) {
            fds.push(PollFd::new(&owner.guard.channel, PollFlags::IN));
        }
        fds.push(PollFd::from_borrowed_fd(
            owner.guard.child.pidfd(),
            PollFlags::IN,
        ));
    }
    // Short bounded wait covers IO completion and blocked termination signals.
    // Every turn checks the unchanged absolute BOOTTIME deadlines after wake.
    let interval =
        rustix::event::Timespec::try_from(Duration::from_millis(5)).map_err(|_| Error::Deadline)?;
    poll(&mut fds, Some(&interval)).map_err(|_| Error::Deadline)?;
    Ok(())
}

struct Watchdog {
    lifecycle: String,
    sequence: u64,
    deadline: f64,
    terminal: bool,
}
impl Watchdog {
    fn new(lifecycle: String, now: f64) -> Result<Self> {
        if !super::spec::digest(&lifecycle) || !now.is_finite() || now < 0. {
            return Err(Error::InvalidSpec);
        }
        Ok(Self {
            lifecycle,
            sequence: 0,
            deadline: now + 90.,
            terminal: false,
        })
    }
    fn check(&mut self, now: f64) -> Result<()> {
        if self.terminal || !now.is_finite() || now < 0. || now >= self.deadline {
            self.terminal = true;
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn progress(&mut self, message: Progress, now: f64) -> Result<()> {
        self.check(now)?;
        if message.lifecycle != self.lifecycle
            || Some(message.sequence) != self.sequence.checked_add(1)
            || !message.sent_at.is_finite()
            || message.sent_at < 0.
            || message.sent_at > now
            || now - message.sent_at >= 2.
        {
            self.terminal = true;
            return Err(Error::DescriptorPolicy);
        }
        self.sequence = message.sequence;
        self.deadline = message.sent_at + 90.;
        self.check(now)
    }
}
#[cfg(test)]
pub(super) fn lab_watchdog() -> Result<()> {
    let bytes = vprouter_linux::storage::read(
        std::path::Path::new("/var/lib/vprouter-v2-lab/owner-domain-nonce"),
        vprouter_linux::storage::Kind::SecretFile,
        64,
    )
    .map_err(|_| Error::LabRequired)?;
    let lifecycle = std::str::from_utf8(&bytes).map_err(|_| Error::LabRequired)?;
    let (spec, _) = super::tests::fixture();
    let domains = super::supervision::Domains::new(&spec, lifecycle)?;
    let owner = ExternalOwner::spawn(
        domains.clone(),
        super::inventory::GuardInputs::for_domains(&domains)?,
        |_guard| {
            // Initial real progress is ACKed by the external owner. Then no more
            // progress: the product90s timer must stop this exact still-live guard.
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        },
    )?;
    let pid = owner.guard.child.pid();
    let start = owner.guard.child.start_time()?;
    println!(
        "{}",
        serde_json::json!({"stage":"owner_watchdog_started", "guard_pid":pid,"guard_start":start})
    );
    let terminal = owner.supervise()?;
    if terminal.reason != Error::Deadline {
        return Err(Error::DescriptorPolicy);
    }
    // The product timer already requested the terminal stop at its ORIGINAL
    // 90s deadline. Delivery is asynchronous: wait only for the exact retained
    // pidfd/start to exhibit T, bounded by the preexisting deadline+2s oracle
    // allowance. This neither rearms the watchdog nor resumes the old guard.
    loop {
        terminal.owner.guard.child.require_live()?;
        if terminal.owner.guard.child.start_time()? != start {
            return Err(Error::ProcessChanged);
        }
        if terminal
            .owner
            .guard
            .child
            .lab_require_stopped(start)
            .is_ok()
        {
            break;
        }
        if vprouter_core::health::boot_seconds() >= terminal.owner.clock.deadline + 2. {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let finished = vprouter_core::health::boot_seconds();
    if finished < terminal.owner.clock.deadline || finished >= terminal.owner.clock.deadline + 2. {
        return Err(Error::Deadline);
    }
    println!(
        "{}",
        serde_json::json!({"case":"actual_external_owner_original90s_no_progress_guard_stopped_no_rearm", "guard_pid":pid,"guard_start":start,"original_deadline":terminal.owner.clock.deadline,"stopped_at":finished,"component_only":true})
    );
    terminal.owner.guard.child.lab_signal(libc::SIGKILL)?;
    terminal.owner.guard.child.lab_wait_killed()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn client_pair() -> (Client, OwnedFd) {
        let (channel, server) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        let inventory = super::super::inventory::Registration::owned(&[channel.as_fd()]).unwrap();
        (
            Client {
                channel,
                allocation: "a".repeat(64),
                exit_id: "one".into(),
                lifecycle: "b".repeat(64),
                sequence: Cell::new(0),
                failed: Cell::new(false),
                _inventory: inventory,
            },
            server,
        )
    }
    fn request(socket: &OwnedFd) -> Request {
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(request) = receive(socket).unwrap() {
                return request;
            }
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    #[test]
    fn matched_reinspect_reply_with_changed_token_permanently_poisons_client() {
        let (client, server) = client_pair();
        let token = super::super::inspection::lab_token(1);
        let operation = super::super::inspection::Request::Reinspect { token };
        let forged_operation = operation.clone();
        let peer = std::thread::spawn(move || {
            let request = request(&server);
            let mut receipt = super::super::inspection::lab_receipt(request.progress.sequence);
            receipt.job.sent_at = request.progress.sent_at;
            receipt.job.operation = forged_operation;
            receipt.job.token = super::super::inspection::lab_token(2);
            send(
                &server,
                &Reply {
                    allocation: request.allocation,
                    exit_id: request.exit_id,
                    progress: request.progress,
                    executor: None,
                    inspection: Some(receipt),
                },
            )
            .unwrap();
        });
        let client = JournalClient(Rc::new(client));
        assert_eq!(client.inspect(operation), Err(Error::DescriptorPolicy));
        assert_eq!(
            client.0.exchange(Operation::Progress),
            Err(Error::Interrupted)
        );
        peer.join().unwrap();
    }
    #[test]
    fn inspector_reap_error_never_suppresses_valid_neighbor_actor_receipts() {
        let mut failure = None;
        let original_receipt = (2u8, 100.25f64, 102.0f64);
        let mut retained = Vec::new();
        for _ in 0..2 {
            let receipts = independent_collection(Err(Error::ChildFailed), &mut failure, || {
                Ok(vec![original_receipt])
            })
            .unwrap();
            retained.extend(receipts);
        }
        assert_eq!(failure, Some(Error::ChildFailed));
        assert_eq!(retained, vec![original_receipt, original_receipt]);
    }
    #[test]
    fn failed_durable_enqueue_retains_original_receipt_for_reconciliation() {
        let mut receipts = std::collections::VecDeque::from([(17u64, 123f64), (18, 124.)]);
        assert_eq!(
            start_retained(&mut receipts, |_| Err(Error::LockBusy)),
            Err(Error::LockBusy)
        );
        assert_eq!(receipts.front(), Some(&(17, 123.)));
        assert_eq!(receipts.len(), 2);
        start_retained(&mut receipts, |value| {
            assert_eq!(*value, (17, 123.));
            Ok(())
        })
        .unwrap();
        assert_eq!(receipts.front(), Some(&(18, 124.)));
    }
    #[test]
    fn matched_plain_reply_with_unexpected_rights_poison_client() {
        let (client, server) = client_pair();
        let peer = std::thread::spawn(move || {
            let request = request(&server);
            let (one, two) = net::socketpair(
                net::AddressFamily::UNIX,
                net::SocketType::SEQPACKET,
                net::SocketFlags::CLOEXEC,
                None,
            )
            .unwrap();
            send_descriptors(
                &server,
                &Reply {
                    allocation: request.allocation,
                    exit_id: request.exit_id,
                    progress: request.progress,
                    inspection: None,
                    executor: None,
                },
                &[one.as_fd(), two.as_fd()],
            )
            .unwrap();
        });
        assert_eq!(
            client.exchange(Operation::HostAudit),
            Err(Error::DescriptorPolicy)
        );
        assert_eq!(
            client.exchange(Operation::Progress),
            Err(Error::Interrupted)
        );
        peer.join().unwrap();
    }
    #[test]
    fn matched_plain_reply_with_executor_metadata_poison_client() {
        let (client, server) = client_pair();
        let peer = std::thread::spawn(move || {
            let request = request(&server);
            send(
                &server,
                &Reply {
                    allocation: request.allocation,
                    exit_id: request.exit_id,
                    progress: request.progress,
                    inspection: None,
                    executor: Some(super::super::owned::ExecutorIdentity {
                        scope: 0,
                        pid: 42,
                        start_time: 1,
                        namespace: super::super::owned::Identity { dev: 1, ino: 2 },
                    }),
                },
            )
            .unwrap();
        });
        assert_eq!(
            client.exchange(Operation::HostAudit),
            Err(Error::DescriptorPolicy)
        );
        assert_eq!(
            client.exchange(Operation::Progress),
            Err(Error::Interrupted)
        );
        peer.join().unwrap();
    }
    #[test]
    fn three_successful_framed_reads_then_eof_have_expected_terminal_category() {
        let (client, server) = client_pair();
        let peer = std::thread::spawn(move || {
            for sequence in 1..=3 {
                let request = request(&server);
                assert_eq!(request.progress.sequence, sequence);
                send(
                    &server,
                    &Reply {
                        allocation: request.allocation,
                        exit_id: request.exit_id,
                        progress: request.progress,
                        inspection: None,
                        executor: None,
                    },
                )
                .unwrap();
            }
            let end = Instant::now() + Duration::from_secs(1);
            let reason = loop {
                match receive::<Request>(&server) {
                    Err(error) => break error,
                    Ok(None) => (),
                    Ok(Some(_)) => panic!("unexpected extra request"),
                }
                assert!(Instant::now() < end);
                std::thread::sleep(Duration::from_millis(1));
            };
            assert_eq!(reason, Error::DescriptorPolicy);
            // The native fixture additionally requires exact pidfd waitpid
            // EXITED(0); neither this EOF nor this category check proves exit.
            super::super::owned::lab_expected_journal_end(reason, 3).unwrap();
            assert!(super::super::owned::lab_expected_journal_end(reason, 2).is_err());
            assert!(super::super::owned::lab_expected_journal_end(Error::Deadline, 3).is_err());
        });
        for _ in 0..3 {
            client
                .exchange(Operation::Journal(Box::new(
                    super::super::owned::JournalRequest::Revalidate,
                )))
                .unwrap();
        }
        drop(client);
        peer.join().unwrap();
    }
    #[test]
    fn host_receipt_original_budget_rejects_invalid_future_and_strict_expiry() {
        for (sent, now) in [
            (f64::NAN, 1.),
            (1., f64::NAN),
            (-1., 1.),
            (2., 1.),
            (1., 3.),
            (1., 3.1),
        ] {
            assert!(original_audit_time(sent, now).is_err());
        }
        assert!(original_audit_time(1., 2.999).is_ok());
    }
    #[test]
    fn framed_owner_journal_and_progress_share_exact_sequence_and_binding() {
        let (client, server) = client_pair();
        let peer = std::thread::spawn(move || {
            for sequence in [1, 2, 3] {
                let request = request(&server);
                assert_eq!(request.progress.sequence, sequence);
                assert_eq!(request.allocation, "a".repeat(64));
                assert_eq!(request.progress.lifecycle, "b".repeat(64));
                match (&request.operation, sequence) {
                    (Operation::Journal(operation), 1) => assert!(matches!(
                        **operation,
                        super::super::owned::JournalRequest::Revalidate
                    )),
                    (Operation::Progress, 2) => (),
                    (Operation::HostAudit, 3) => (),
                    _ => panic!("wrong owner operation"),
                }
                send(
                    &server,
                    &Reply {
                        allocation: request.allocation,
                        exit_id: request.exit_id,
                        progress: request.progress,
                        inspection: None,
                        executor: None,
                    },
                )
                .unwrap();
            }
        });
        client
            .exchange(Operation::Journal(Box::new(
                super::super::owned::JournalRequest::Revalidate,
            )))
            .unwrap();
        client.exchange(Operation::Progress).unwrap();
        let ack = client.exchange_ack(Operation::HostAudit).unwrap();
        assert_eq!(ack.sequence, 3);
        assert!(ack.sent_at <= vprouter_core::health::boot_seconds());
        peer.join().unwrap();
        assert_eq!(client.sequence.get(), 3);
    }
    #[test]
    fn framed_owner_reply_rejects_cross_allocation_lifecycle_replay_and_changed_original_time() {
        for fault in 0..5 {
            let (client, server) = client_pair();
            let peer = std::thread::spawn(move || {
                let request = request(&server);
                let mut reply = Reply {
                    allocation: request.allocation,
                    exit_id: request.exit_id,
                    progress: request.progress,
                    inspection: None,
                    executor: None,
                };
                match fault {
                    0 => reply.allocation = "c".repeat(64),
                    1 => reply.progress.lifecycle = "c".repeat(64),
                    2 => reply.progress.sequence = 0,
                    3 => reply.progress.sent_at -= 1.,
                    _ => reply.exit_id = "other".into(),
                }
                send(&server, &reply).unwrap();
            });
            assert!(client.exchange(Operation::Progress).is_err());
            assert_eq!(
                client.exchange(Operation::Progress),
                Err(Error::Interrupted)
            );
            peer.join().unwrap();
        }
    }
    #[test]
    fn framed_owner_late_durable_reply_does_not_extend_original_two_seconds() {
        let (client, server) = client_pair();
        let peer = std::thread::spawn(move || {
            let request = request(&server);
            std::thread::sleep(Duration::from_millis(2100));
            send(
                &server,
                &Reply {
                    allocation: request.allocation,
                    exit_id: request.exit_id,
                    progress: request.progress,
                    inspection: None,
                    executor: None,
                },
            )
            .unwrap();
        });
        let start = Instant::now();
        assert_eq!(
            client.exchange(Operation::Journal(Box::new(
                super::super::owned::JournalRequest::Revalidate
            ))),
            Err(Error::Deadline)
        );
        assert!(start.elapsed() >= Duration::from_secs(2));
        assert!(start.elapsed() < Duration::from_millis(2500));
        assert_eq!(
            client.exchange(Operation::Progress),
            Err(Error::Interrupted)
        );
        peer.join().unwrap();
    }
    #[test]
    fn external_watchdog_uses_original_ninety_second_deadline_and_never_rearms() {
        let mut watchdog = Watchdog::new("a".repeat(64), 10.).unwrap();
        watchdog
            .progress(
                Progress {
                    lifecycle: "a".repeat(64),
                    sequence: 1,
                    sent_at: 20.,
                },
                21.,
            )
            .unwrap();
        watchdog.check(109.999).unwrap();
        assert_eq!(watchdog.check(110.), Err(Error::Deadline));
        assert_eq!(
            watchdog.progress(
                Progress {
                    lifecycle: "a".repeat(64),
                    sequence: 2,
                    sent_at: 110.
                },
                110.
            ),
            Err(Error::Deadline)
        );
        for (lifecycle, sequence, sent_at, now) in [
            ("b".repeat(64), 1, 20., 20.),
            ("a".repeat(64), 2, 20., 20.),
            ("a".repeat(64), 1, 20., 22.),
            ("a".repeat(64), 1, 21., 20.),
            ("a".repeat(64), 1, f64::NAN, 20.),
        ] {
            let mut watchdog = Watchdog::new("a".repeat(64), 10.).unwrap();
            assert!(
                watchdog
                    .progress(
                        Progress {
                            lifecycle,
                            sequence,
                            sent_at
                        },
                        now
                    )
                    .is_err()
            );
            assert_eq!(watchdog.check(20.), Err(Error::Deadline));
        }
    }
}
