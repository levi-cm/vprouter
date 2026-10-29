#![forbid(unsafe_code)]
//! Locked generation-bound ownership. Failed creation is deliberately retained.
use super::{Error, Result, kernel, process, spec::LaunchSpec};
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsFd, OwnedFd},
    path::Path,
};
use vprouter_core::allocation::{
    AllocationRecord, AllocationStore, AllocationTransaction, ExitAllocation,
};
pub(super) mod preparation;
const RD: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub dev: u64,
    pub ino: u64,
}
impl Identity {
    pub fn of(fd: impl AsFd) -> Result<Self> {
        let s = fs::fstat(fd).map_err(|_| Error::OwnershipMismatch)?;
        Ok(Self {
            dev: s.st_dev,
            ino: s.st_ino,
        })
    }
    pub fn network(fd: impl AsFd) -> Result<Self> {
        if fs::fstatfs(&fd)
            .map_err(|_| Error::NamespaceMismatch)?
            .f_type as u64
            != 0x6e736673
        {
            return Err(Error::NamespaceMismatch);
        }
        Self::of(fd)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Creating,
    Offline,
    Activating,
    Bootstrap,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    exit_id: String,
    data_name: String,
    transport_name: String,
    phase: Phase,
    data: Option<Identity>,
    transport: Option<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    links: Option<LinkOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    producer: Option<ProducerOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal: Option<TerminalOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt: Option<AttemptOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    preparation: Option<preparation::History>,
}
/// A stage is durable history, never a native liveness or emptiness verdict.
/// In particular Placed may already be running after a crash before Released ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AttemptStage {
    Planned,
    Born,
    Placed,
    Released,
    Retiring,
    Quiescent,
    Retired,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GuardBirth {
    pub(super) pid: u32,
    pub(super) start: u64,
    pub(super) born_at: f64,
    pub(super) gate_deadline: f64,
}
impl GuardBirth {
    fn validate(&self) -> Result<()> {
        if self.pid <= 1
            || self.start == 0
            || !self.born_at.is_finite()
            || self.born_at <= 0.
            || self.gate_deadline != self.born_at + 3.
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptOwnership {
    exit_id: String,
    lifecycle: String,
    allocation: String,
    launch: String,
    resources: String,
    owner: super::supervision::OwnerDomainRecord,
    scopes: [String; 4],
    planned_at: f64,
    stage: AttemptStage,
    birth: Option<GuardBirth>,
    guard_group: Option<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retirement: Option<RetirementHistory>,
}
/// Immutable original object identities survive live resource removal. These
/// values are historical evidence, never native authority recovered by parsing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementResources {
    exit_id: String,
    data_name: String,
    transport_name: String,
    data: Option<Identity>,
    transport: Option<Identity>,
    links: Option<LinkOwnership>,
    producer: Option<ProducerOwnership>,
}
impl RetirementResources {
    fn capture(entry: &Entry) -> Self {
        Self {
            exit_id: entry.exit_id.clone(),
            data_name: entry.data_name.clone(),
            transport_name: entry.transport_name.clone(),
            data: entry.data,
            transport: entry.transport,
            links: entry.links.clone(),
            producer: entry.producer.clone(),
        }
    }
    fn digest(&self) -> Result<String> {
        Ok(vprouter_worker::bootstrap::digest(
            &serde_json::to_vec(&(
                &self.exit_id,
                &self.data_name,
                &self.transport_name,
                self.data,
                self.transport,
                &self.links,
                &self.producer,
            ))
            .map_err(|_| Error::OwnershipMismatch)?,
        ))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CleanupStage {
    NotStarted,
    LinksIntent,
    LinksRemoved,
    ProducerIntent,
    ProducerRemoved,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementHistory {
    original: RetirementResources,
    terminal_digest: String,
    started_at: f64,
    quiescent_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_transition: Option<String>,
    cleanup: CleanupStage,
    retired_at: Option<f64>,
}
impl RetirementHistory {
    fn validate(&self, entry: &Entry, attempt: &AttemptOwnership) -> Result<()> {
        if self.original.digest()? != attempt.resources
            || self.original.exit_id != entry.exit_id
            || self.original.data_name != entry.data_name
            || self.original.transport_name != entry.transport_name
            || self.original.data != entry.data
            || self.original.transport != entry.transport
            || self.original.links.is_none()
            || self.original.producer.is_none()
            || !self.started_at.is_finite()
            || self.started_at < attempt.planned_at
            || !super::spec::digest(&self.terminal_digest)
        {
            return Err(Error::OwnershipMismatch);
        }
        let terminal = entry.terminal.as_ref().ok_or(Error::OwnershipMismatch)?;
        if vprouter_worker::bootstrap::digest(
            &serde_json::to_vec(terminal).map_err(|_| Error::OwnershipMismatch)?,
        ) != self.terminal_digest
            || terminal.lifecycle != attempt.lifecycle
            || terminal.executors.len() != 3
            || terminal.completions.len() != 3
            || terminal
                .completions
                .iter()
                .any(|c| c.result != TerminalResult::VerifiedBeforeDeadline)
        {
            return Err(Error::OwnershipMismatch);
        }
        if (self.cleanup == CleanupStage::NotStarted && self.host_transition.is_some())
            || (self.cleanup != CleanupStage::NotStarted
                && self
                    .host_transition
                    .as_ref()
                    .is_none_or(|v| !super::spec::digest(v)))
        {
            return Err(Error::OwnershipMismatch);
        }
        match attempt.stage {
            AttemptStage::Retiring
                if self.quiescent_at.is_none()
                    && self.retired_at.is_none()
                    && self.cleanup == CleanupStage::NotStarted => {}
            AttemptStage::Quiescent | AttemptStage::Retired => {
                let at = self.quiescent_at.ok_or(Error::OwnershipMismatch)?;
                if !at.is_finite() || at < self.started_at {
                    return Err(Error::OwnershipMismatch);
                }
                if attempt.stage == AttemptStage::Retired {
                    let retired = self.retired_at.ok_or(Error::OwnershipMismatch)?;
                    if !retired.is_finite()
                        || retired < at
                        || self.cleanup != CleanupStage::ProducerRemoved
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                } else if self.retired_at.is_some() {
                    return Err(Error::OwnershipMismatch);
                }
            }
            _ => return Err(Error::OwnershipMismatch),
        }
        if self.cleanup == CleanupStage::ProducerRemoved {
            if entry.phase != Phase::Offline || entry.links.is_some() || entry.producer.is_some() {
                return Err(Error::OwnershipMismatch);
            }
        } else if entry.phase != Phase::Bootstrap || attempt_resources(entry)? != attempt.resources
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
impl AttemptOwnership {
    fn validate(&self, record: &Record, entry: &Entry) -> Result<()> {
        let domains = super::supervision::Domains::from_record(
            &record.allocation,
            &entry.exit_id,
            &self.lifecycle,
        )?;
        self.owner.validate(&domains)?;
        if record.owner_epoch.as_ref() != Some(&self.owner) {
            return Err(Error::OwnershipMismatch);
        }
        if self.exit_id != entry.exit_id
            || self.allocation != domains.allocation()
            || !super::spec::digest(&self.launch)
            || !super::spec::digest(&self.resources)
            || !self.planned_at.is_finite()
            || self.planned_at <= 0.
            || self.scopes != attempt_scopes(&domains)
            || (self.stage == AttemptStage::Planned
                && (self.birth.is_some() || self.guard_group.is_some()))
            || (matches!(
                self.stage,
                AttemptStage::Born
                    | AttemptStage::Placed
                    | AttemptStage::Released
                    | AttemptStage::Retiring
                    | AttemptStage::Quiescent
                    | AttemptStage::Retired
            ) && self.birth.is_none())
            || (matches!(
                self.stage,
                AttemptStage::Placed
                    | AttemptStage::Released
                    | AttemptStage::Retiring
                    | AttemptStage::Quiescent
                    | AttemptStage::Retired
            ) && self.guard_group.is_none())
            || self.guard_group.is_some_and(|group| group.ino == 0)
            || (self.guard_group.is_some() && self.birth.is_none())
        {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(birth) = &self.birth {
            birth.validate()?;
            if birth.born_at < self.planned_at || birth.pid == self.owner.pid {
                return Err(Error::OwnershipMismatch);
            }
            if entry.terminal.as_ref().is_some_and(|terminal| {
                terminal.lifecycle != self.lifecycle
                    || terminal.binding.boot_id != self.owner.boot
                    || (terminal.guard_pid, terminal.guard_start) != (birth.pid, birth.start)
            }) {
                return Err(Error::OwnershipMismatch);
            }
        } else if entry.terminal.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        if matches!(
            self.stage,
            AttemptStage::Retiring | AttemptStage::Quiescent | AttemptStage::Retired
        ) {
            self.retirement
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .validate(entry, self)?;
        } else if self.retirement.is_some() || self.resources != attempt_resources(entry)? {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
fn attempt_scopes(domains: &super::supervision::Domains) -> [String; 4] {
    use super::supervision::Role;
    [
        Role::Guard,
        Role::ExpiryHost,
        Role::ExpiryTransport,
        Role::ExpiryData,
    ]
    .map(|role| domains.unit(role))
}
fn attempt_resources(entry: &Entry) -> Result<String> {
    Ok(vprouter_worker::bootstrap::digest(
        &serde_json::to_vec(&(
            &entry.exit_id,
            &entry.data_name,
            &entry.transport_name,
            entry.data,
            entry.transport,
            &entry.links,
            &entry.producer,
        ))
        .map_err(|_| Error::OwnershipMismatch)?,
    ))
}
/// Owner-only intent, minted using a retained authenticated original service
/// domain. No variant of the guard's JournalRequest wire protocol carries it.
pub(super) struct AttemptBinding {
    exit_id: String,
    launch: String,
    resources: String,
}
impl AttemptBinding {
    fn binds(
        &self,
        attempt: &AttemptOwnership,
        domains: &super::supervision::Domains,
    ) -> Result<()> {
        if self.exit_id != attempt.exit_id
            || self.exit_id != domains.exit_id()
            || self.launch != attempt.launch
            || self.resources != attempt.resources
            || domains.allocation() != attempt.allocation
            || domains.lifecycle() != attempt.lifecycle
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
pub(super) struct AttemptPlan {
    creator: u32,
    value: AttemptOwnership,
}
/// Issued once, only after the fixed IO actor's durable ACK and actual reap.
/// Retains the allocation OFD and same-process exit reservation through birth.
pub(super) struct PlannedAttempt {
    creator: u32,
    value: AttemptOwnership,
    lease: MutatorLease,
}
impl PlannedAttempt {
    #[cfg(test)]
    pub(super) fn lab_reject_other_member(
        &self,
        domains: &super::supervision::Domains,
        owner: &super::supervision::OwnerDomain,
        inputs: super::inventory::GuardInputs,
    ) -> Result<()> {
        if self.creator != std::process::id()
            || domains.exit_id() == self.value.exit_id
            || domains.lifecycle() != self.value.lifecycle
        {
            return Err(Error::OwnershipMismatch);
        }
        let copy = Self {
            creator: self.creator,
            value: self.value.clone(),
            lease: self.lease.retain()?,
        };
        let before = kernel::lab_native_births();
        let rejected =
            kernel::PendingGuard::spawn(domains, owner, inputs, copy, |_| Err(Error::ChildFailed));
        if !matches!(rejected, Err(Error::OwnershipMismatch))
            || kernel::lab_native_births() != before
        {
            return Err(Error::ChildFailed);
        }
        eprintln!(
            "LAB_GUARD_ATTEMPT cross_member_same_lifecycle_rejected_before_clone=true native_births_unchanged=true"
        );
        Ok(())
    }
    pub(super) fn verify(
        &self,
        domains: &super::supervision::Domains,
        owner: &super::supervision::OwnerDomain,
        inputs: &super::inventory::GuardInputs,
    ) -> Result<()> {
        inputs.attempt_binding()?.binds(&self.value, domains)?;
        if self.creator != std::process::id()
            || !self.lease.counted
            || self.value.stage != AttemptStage::Planned
            || self.value.lifecycle != domains.lifecycle()
            || self.value.allocation != domains.allocation()
            || owner.record(domains)? != self.value.owner
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn lease(&self) -> std::os::fd::BorrowedFd<'_> {
        self.lease.fd.as_fd()
    }
}
pub(super) struct BornAttempt {
    creator: u32,
    allocation: String,
    lifecycle: String,
    exit_id: String,
    birth: GuardBirth,
}
impl BornAttempt {
    pub(super) fn verify(&self, guard: &kernel::PendingGuard) -> Result<()> {
        let domains = guard.domains()?;
        if self.creator != std::process::id()
            || domains.allocation() != self.allocation
            || domains.lifecycle() != self.lifecycle
            || domains.exit_id() != self.exit_id
            || guard.birth()? != self.birth
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
pub(super) struct ReleaseAttempt {
    born: BornAttempt,
    group: Identity,
}
impl ReleaseAttempt {
    pub(super) fn verify(&self, guard: &kernel::PendingGuard) -> Result<()> {
        self.born.verify(guard)?;
        if guard.group_identity()? != self.group {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutorIdentity {
    pub scope: u8,
    pub pid: u32,
    pub start_time: u64,
    pub namespace: Identity,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TerminalResult {
    VerifiedBeforeDeadline,
    LateVerified,
    Failed,
    StopFailed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutorCompletion {
    pub identity: ExecutorIdentity,
    pub result: TerminalResult,
    pub deadline: f64,
    pub finished_at: f64,
}
impl ExecutorCompletion {
    pub(crate) fn validate(&self) -> Result<()> {
        if !self.deadline.is_finite()
            || !self.finished_at.is_finite()
            || self.deadline <= 0.
            || self.finished_at <= 0.
            || self.result == TerminalResult::VerifiedBeforeDeadline
                && self.finished_at >= self.deadline
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalOwnership {
    lifecycle: String,
    binding: vprouter_core::health::Binding,
    executors: Vec<ExecutorIdentity>,
    acknowledged: Vec<u8>,
    guard_pid: u32,
    guard_start: u64,
    completions: Vec<ExecutorCompletion>,
}
impl TerminalOwnership {
    fn validate(&self, record: &Record, entry: &Entry) -> Result<()> {
        self.binding
            .validate()
            .map_err(|_| Error::OwnershipMismatch)?;
        if self.lifecycle.len() != 64
            || !self
                .lifecycle
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || self.binding.deployment_id != record.allocation.deployment_id
            || self.binding.generation != record.allocation.generation
            || self.binding.exit_id != entry.exit_id
            || record
                .allocation
                .exits
                .iter()
                .find(|e| e.exit_id == entry.exit_id)
                .is_none_or(|e| e.mode != self.binding.mode)
            || (entry.phase != Phase::Bootstrap
                && !entry.attempt.as_ref().is_some_and(|a| {
                    matches!(a.stage, AttemptStage::Quiescent | AttemptStage::Retired)
                        && a.retirement
                            .as_ref()
                            .is_some_and(|h| h.cleanup == CleanupStage::ProducerRemoved)
                }))
            || self.executors.len() > 3
            || self.guard_pid <= 1
            || self.guard_start == 0
        {
            return Err(Error::OwnershipMismatch);
        }
        let mut scopes = std::collections::HashSet::new();
        let mut pids = std::collections::HashSet::new();
        for child in &self.executors {
            let expected = match child.scope {
                0 => entry
                    .links
                    .as_ref()
                    .or_else(|| {
                        entry
                            .attempt
                            .as_ref()
                            .and_then(|a| a.retirement.as_ref())
                            .and_then(|h| h.original.links.as_ref())
                    })
                    .map(|l| l.host_namespace),
                1 => entry.transport,
                2 => entry.data,
                _ => None,
            };
            if expected != Some(child.namespace)
                || child.pid <= 1
                || child.start_time == 0
                || !scopes.insert(child.scope)
                || !pids.insert(child.pid)
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        let mut seen = std::collections::HashSet::new();
        if self
            .acknowledged
            .iter()
            .any(|s| !scopes.contains(s) || !seen.insert(*s))
        {
            return Err(Error::OwnershipMismatch);
        }
        let mut completed = std::collections::HashSet::new();
        for completion in &self.completions {
            completion.validate()?;
            if !self.executors.contains(&completion.identity)
                || !self.acknowledged.contains(&completion.identity.scope)
                || !completed.insert(completion.identity.scope)
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        Ok(())
    }
}
impl Entry {
    fn preparation_bound_producer(&self) -> bool {
        self.preparation
            .as_ref()
            .is_some_and(|p| p.matches_producer_publication(self))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerOwnership {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<[u8; 32]>,
    parent: Identity,
    group: Identity,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkOwnership {
    host_namespace: Identity,
    host_index: u32,
    transport_index: u32,
    wireguard_index: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_epoch: Option<super::supervision::OwnerDomainRecord>,
    allocation: AllocationRecord,
    primary_exit_id: String,
    // None is an explicit prebirth state, never a host namespace pretending to
    // be the primary data namespace. Existing records deserialize as Some.
    base_network: Option<Identity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_network: Option<Identity>,
    entries: Vec<Entry>,
}
fn same_allocation(a: &AllocationRecord, b: &AllocationRecord) -> Result<bool> {
    let AllocationRecord {
        schema_version: a_schema,
        deployment_id: a_deployment,
        generation: a_generation,
        exits: a_exits,
    } = a;
    let AllocationRecord {
        schema_version: b_schema,
        deployment_id: b_deployment,
        generation: b_generation,
        exits: b_exits,
    } = b;
    // serde_core 1.0.228 ser/impls.rs: PathBuf delegates to Path::to_str.
    // Preserve both serialization errors, in A-then-B order, before mismatches.
    for exits in [a_exits, b_exits] {
        for exit in exits {
            exit.state_dir.to_str().ok_or(Error::OwnershipMismatch)?;
        }
    }
    // allocation.rs derives serialization for these fields; integer, String,
    // ordered Vec, ExitMode and Option<String> encodings are injective here.
    Ok(a_schema == b_schema
        && a_deployment == b_deployment
        && a_generation == b_generation
        && a_exits.len() == b_exits.len()
        && a_exits
            .iter()
            .zip(b_exits)
            .all(|(a, b)| same_exit_allocation(a, b)))
}
fn same_exit_allocation(a: &ExitAllocation, b: &ExitAllocation) -> bool {
    let ExitAllocation {
        exit_id: a_id,
        mode: a_mode,
        state_dir: a_path,
        data_namespace: a_data,
        transport_namespace: a_transport,
        nft_table: a_nft,
        host_interface: a_host,
        data_interface: a_interface,
        wireguard_interface: a_wireguard,
        transport_subnet: a_subnet,
    } = a;
    let ExitAllocation {
        exit_id: b_id,
        mode: b_mode,
        state_dir: b_path,
        data_namespace: b_data,
        transport_namespace: b_transport,
        nft_table: b_nft,
        host_interface: b_host,
        data_interface: b_interface,
        wireguard_interface: b_wireguard,
        transport_subnet: b_subnet,
    } = b;
    a_id == b_id
        && a_mode == b_mode
        // Path equality normalizes components; serialization preserves spelling.
        && a_path.as_os_str() == b_path.as_os_str()
        && a_data == b_data
        && a_transport == b_transport
        && a_nft == b_nft
        && a_host == b_host
        && a_interface == b_interface
        && a_wireguard == b_wireguard
        && a_subnet == b_subnet
}
impl Record {
    fn new(s: &LaunchSpec, primary: &str, base: Identity) -> Result<Self> {
        s.validate()?;
        Self::new_allocation(&s.allocation, primary, base)
    }
    fn new_allocation(a: &AllocationRecord, primary: &str, base: Identity) -> Result<Self> {
        a.validate(&a.deployment_id, &[])
            .map_err(|_| Error::AllocationMismatch)?;
        if base.ino == 0 || !a.exits.iter().any(|e| e.exit_id == primary) {
            return Err(Error::AllocationMismatch);
        }
        let allocation = a.clone();
        Ok(Self {
            schema_version: 1,
            owner_epoch: None,
            allocation,
            primary_exit_id: primary.into(),
            base_network: Some(base),
            owner_network: None,
            entries: Vec::new(),
        })
    }
    fn plan_attempt(&mut self, exit: &str, attempt: AttemptOwnership) -> Result<()> {
        if attempt.stage != AttemptStage::Planned || attempt.exit_id != exit {
            return Err(Error::OwnershipMismatch);
        }
        if self.entries.iter().any(|entry| {
            entry
                .attempt
                .as_ref()
                .is_some_and(|a| a.lifecycle == attempt.lifecycle || a.scopes == attempt.scopes)
                || entry
                    .terminal
                    .as_ref()
                    .is_some_and(|t| t.lifecycle == attempt.lifecycle)
        }) {
            return Err(Error::LockBusy);
        }
        let index = self
            .entries
            .iter()
            .position(|entry| entry.exit_id == exit)
            .ok_or(Error::OwnershipMismatch)?;
        let entry = &self.entries[index];
        if entry.attempt.is_some() || entry.terminal.is_some() || entry.phase != Phase::Bootstrap {
            return Err(Error::Interrupted);
        }
        attempt.validate(self, entry)?;
        self.entries[index].attempt = Some(attempt);
        Ok(())
    }
    fn begin_terminal(
        &mut self,
        exit_id: &str,
        binding: vprouter_core::health::Binding,
        lifecycle: &str,
        guard: (u32, u64),
    ) -> Result<()> {
        let index = self
            .entries
            .iter()
            .position(|e| e.exit_id == exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let entry = &self.entries[index];
        if entry.terminal.is_some() || entry.phase != Phase::Bootstrap {
            return Err(Error::Interrupted);
        }
        let (guard_pid, guard_start) = guard;
        if let Some(attempt) = &entry.attempt {
            attempt.validate(self, entry)?;
            if attempt.stage != AttemptStage::Released
                || attempt.lifecycle != lifecycle
                || attempt
                    .birth
                    .as_ref()
                    .is_none_or(|birth| (birth.pid, birth.start) != (guard_pid, guard_start))
            {
                return Err(Error::Interrupted);
            }
        }
        let terminal = TerminalOwnership {
            lifecycle: lifecycle.into(),
            binding,
            executors: Vec::new(),
            acknowledged: Vec::new(),
            guard_pid,
            guard_start,
            completions: Vec::new(),
        };
        terminal.validate(self, entry)?;
        self.entries[index].terminal = Some(terminal);
        Ok(())
    }
    fn bind(&self, s: &LaunchSpec, primary: &str, base: Identity) -> Result<()> {
        s.validate()?;
        self.bind_allocation(&s.allocation, primary, base)
    }
    fn bind_allocation(
        &self,
        allocation: &AllocationRecord,
        primary: &str,
        base: Identity,
    ) -> Result<()> {
        self.bind_anchor(allocation, primary, Some(base), self.owner_network)
    }
    fn primary_network(&self) -> Result<Identity> {
        self.base_network.ok_or(Error::OwnershipMismatch)
    }
    fn new_preparing(
        allocation: &AllocationRecord,
        primary: &str,
        owner_network: Identity,
        owner_epoch: super::supervision::OwnerDomainRecord,
    ) -> Result<Self> {
        allocation
            .validate(&allocation.deployment_id, &[])
            .map_err(|_| Error::AllocationMismatch)?;
        let record = Self {
            schema_version: 1,
            owner_epoch: Some(owner_epoch),
            allocation: allocation.clone(),
            primary_exit_id: primary.into(),
            base_network: None,
            owner_network: Some(owner_network),
            entries: Vec::new(),
        };
        record.bind_anchor(allocation, primary, None, Some(owner_network))?;
        Ok(record)
    }
    fn bind_anchor(
        &self,
        allocation: &AllocationRecord,
        primary: &str,
        base: Option<Identity>,
        owner_network: Option<Identity>,
    ) -> Result<()> {
        allocation
            .validate(&allocation.deployment_id, &[])
            .map_err(|_| Error::AllocationMismatch)?;
        if self.schema_version != 1
            || !same_allocation(&self.allocation, allocation)?
            || self.primary_exit_id != primary
            || self.base_network != base
            || self.owner_network != owner_network
            || base.is_none() && (owner_network.is_none() || self.owner_epoch.is_none())
            || base.is_some_and(|identity| identity.ino == 0)
            || owner_network.is_some_and(|identity| identity.ino == 0)
            || !self.allocation.exits.iter().any(|e| e.exit_id == primary)
        {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(owner) = &self.owner_epoch {
            owner.validate(&super::supervision::Domains::from_record(
                &self.allocation,
                primary,
                &"0".repeat(64),
            )?)?;
        }
        let mut seen = std::collections::HashSet::new();
        let mut identities = std::collections::HashSet::new();
        for e in &self.entries {
            if base.is_none()
                && (e.phase != Phase::Creating
                    || e.data.is_some()
                    || e.transport.is_some()
                    || e.links.is_some()
                    || e.producer.is_some()
                    || e.terminal.is_some()
                    || e.attempt.is_some())
            {
                return Err(Error::OwnershipMismatch);
            }
            let a = self
                .allocation
                .exits
                .iter()
                .find(|a| a.exit_id == e.exit_id)
                .ok_or(Error::OwnershipMismatch)?;
            if !seen.insert(&e.exit_id)
                || a.data_namespace != e.data_name
                || a.transport_namespace != e.transport_name
            {
                return Err(Error::OwnershipMismatch);
            }
            if e.phase != Phase::Creating && (e.data.is_none() || e.transport.is_none()) {
                return Err(Error::OwnershipMismatch);
            }
            if let Some(p) = &e.producer {
                if (if p.binding.is_some() {
                    !e.preparation_bound_producer()
                } else {
                    !matches!(e.phase, Phase::Activating | Phase::Bootstrap)
                }) || p.parent.dev != p.group.dev
                    || p.parent == p.group
                    || p.parent.ino == 0
                    || p.group.ino == 0
                {
                    return Err(Error::OwnershipMismatch);
                }
            } else if e.phase == Phase::Bootstrap {
                return Err(Error::OwnershipMismatch);
            }
            if let Some(l) = &e.links {
                if !matches!(e.phase, Phase::Activating | Phase::Bootstrap)
                    || l.host_namespace.ino == 0
                    || l.host_namespace == e.data.unwrap_or(l.host_namespace)
                    || l.host_namespace == e.transport.unwrap_or(l.host_namespace)
                    || [l.host_index, l.transport_index, l.wireguard_index].contains(&0)
                {
                    return Err(Error::OwnershipMismatch);
                }
            } else if e.phase == Phase::Bootstrap {
                return Err(Error::OwnershipMismatch);
            }
            if let Some(terminal) = &e.terminal {
                terminal.validate(self, e)?;
            }
            if let Some(attempt) = &e.attempt {
                attempt.validate(self, e)?;
            }
            if let Some(preparation) = &e.preparation {
                preparation.validate(self, e)?;
            }
            for id in [e.data, e.transport].into_iter().flatten() {
                if id.ino == 0 || !identities.insert((id.dev, id.ino)) {
                    return Err(Error::OwnershipMismatch);
                }
            }
            if e.exit_id == primary && e.data.is_some_and(|id| Some(id) != base) {
                return Err(Error::OwnershipMismatch);
            }
            if base.is_some() && (e.exit_id != primary && e.data == base || e.transport == base) {
                return Err(Error::OwnershipMismatch);
            }
        }
        Ok(())
    }
}
pub(super) struct OwnedNamespaces {
    pub data: OwnedFd,
    pub transport: OwnedFd,
    exit_id: String,
    allocation_digest: String,
    data_identity: Identity,
    transport_identity: Identity,
    _inventory: super::inventory::Registration,
}
impl OwnedNamespaces {
    pub(super) fn select_guard(&self, inputs: &mut super::inventory::GuardInputs) -> Result<()> {
        inputs.include(
            &self._inventory,
            super::inventory::GuardAuthority::SelectedMember,
        )
    }
    fn new(s: &LaunchSpec, data: OwnedFd, transport: OwnedFd) -> Result<Self> {
        let data_identity = Identity::network(&data)?;
        let transport_identity = Identity::network(&transport)?;
        let inventory = super::inventory::Registration::owned(&[data.as_fd(), transport.as_fd()])?;
        Ok(Self {
            data,
            transport,
            exit_id: s.exit.exit_id.clone(),
            allocation_digest: vprouter_linux::sha256(
                &serde_json::to_vec(&s.allocation).map_err(|_| Error::AllocationMismatch)?,
            ),
            data_identity,
            transport_identity,
            _inventory: inventory,
        })
    }
    pub(super) fn inspection_copy(&self, s: &LaunchSpec) -> Result<Self> {
        self.bind(s)?;
        Self::new(
            s,
            self.data
                .try_clone()
                .map_err(|_| Error::DescriptorDuplicate)?,
            self.transport
                .try_clone()
                .map_err(|_| Error::DescriptorDuplicate)?,
        )
    }
    pub fn bind(&self, s: &LaunchSpec) -> Result<()> {
        if self.exit_id != s.exit.exit_id
            || self.allocation_digest
                != vprouter_linux::sha256(
                    &serde_json::to_vec(&s.allocation).map_err(|_| Error::AllocationMismatch)?,
                )
            || Identity::network(&self.data)? != self.data_identity
            || Identity::network(&self.transport)? != self.transport_identity
        {
            return Err(Error::NamespaceMismatch);
        }
        Ok(())
    }
}
/// Allocation lock is shared with AllocationStore; it remains held through
/// namespace acquisition and execution admission. No caller evidence booleans.
struct Journal {
    owner_pid: u32,
    staging: std::cell::Cell<bool>,
    async_only: std::cell::Cell<bool>,
    dir: OwnedFd,
    allocation: AllocationTransaction,
    record: Record,
    _inventory: super::inventory::Registration,
}
/// Fixed post-bootstrap operations. Namespace creation, shared-host mutation,
/// cleanup and lease creation remain exclusively in the external owner.
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "operation",
    content = "arguments",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum JournalRequest {
    Revalidate,
    VerifyProducer {
        parent: Identity,
        group: Identity,
    },
    VerifyLinks {
        host: Identity,
        indices: (u32, u32, u32),
        data: Identity,
        transport: Identity,
    },
    BeginTerminal {
        binding: vprouter_core::health::Binding,
        lifecycle: String,
    },
    RegisterExecutor {
        lifecycle: String,
        identity: ExecutorIdentity,
    },
    AcknowledgeExecutor {
        lifecycle: String,
        identity: ExecutorIdentity,
    },
    VerifyExecutors {
        lifecycle: String,
        children: Vec<ExecutorIdentity>,
    },
    CompleteExecutor {
        lifecycle: String,
        completion: ExecutorCompletion,
    },
    RequireNoExecutors,
}
/// Fixed child IO payload, created only by the single authoritative journal.
/// Read-only jobs run beside a pending mutation; neither can authorize a fresh
/// lifecycle or overwrite uncertain state after an original deadline expires.
pub(super) struct JournalIo {
    allocation: AllocationRecord,
    before: Vec<u8>,
    after: Option<Vec<u8>>,
    deadline: f64,
    #[cfg(test)]
    pause_before_sync: bool,
    #[cfg(test)]
    pause_before_read: bool,
    #[cfg(test)]
    pub(super) lab_stage: std::cell::Cell<u8>,
}
impl JournalIo {
    pub(super) fn constructor_binding(&self) -> ([u8; 32], Option<[u8; 32]>, f64) {
        (
            record_digest(&self.before),
            self.after.as_ref().map(|b| record_digest(b)),
            self.deadline,
        )
    }
    fn check(&self) -> Result<()> {
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub fn run(&self, directory: impl AsFd) -> Result<[u8; 32]> {
        #[cfg(test)]
        self.lab_stage.set(20);
        self.check()?;
        #[cfg(test)]
        if self.pause_before_read {
            kernel::lab_journal_pause()?;
        }
        let read = |name: &str| -> Result<Vec<u8>> {
            #[cfg(test)]
            let stage = self.lab_stage.get();
            let fd = fs::openat(&directory, name, RD, Mode::empty())
                .map_err(|_| Error::OwnershipMismatch)?;
            #[cfg(test)]
            self.lab_stage.set(stage + 10);
            file_check(&fd)?;
            #[cfg(test)]
            self.lab_stage.set(stage + 20);
            let mut bytes = Vec::new();
            File::from(fd)
                .take(262145)
                .read_to_end(&mut bytes)
                .map_err(|_| Error::Interrupted)?;
            if bytes.len() > 262144 {
                return Err(Error::TooLarge);
            }
            Ok(bytes)
        };
        #[cfg(test)]
        self.lab_stage.set(21);
        let allocation_bytes = read("allocations.json")?;
        #[cfg(test)]
        self.lab_stage.set(22);
        let allocation =
            AllocationRecord::parse(&allocation_bytes, &self.allocation.deployment_id, &[])
                .map_err(|_| Error::AllocationMismatch)?;
        if !same_allocation(&allocation, &self.allocation)? {
            return Err(Error::AllocationMismatch);
        }
        #[cfg(test)]
        self.lab_stage.set(23);
        let current = read("namespaces.json")?;
        #[cfg(test)]
        self.lab_stage.set(24);
        if self.after.is_some() && current != self.before {
            return Err(Error::OwnershipMismatch);
        }
        self.check()?;
        if let Some(bytes) = &self.after {
            // The single outstanding writer owns this fixed name. Interrupted
            // temp files remain and prevent subsequent writers from overwriting.
            #[cfg(test)]
            self.lab_stage.set(25);
            let fd = fs::openat(
                &directory,
                ".owner-journal.pending",
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| Error::Interrupted)?;
            let mut file = File::from(fd);
            file.write_all(bytes).map_err(|_| Error::Interrupted)?;
            #[cfg(test)]
            self.lab_stage.set(26);
            #[cfg(test)]
            if self.pause_before_sync {
                kernel::lab_journal_pause()?;
            }
            file.sync_all().map_err(|_| Error::Interrupted)?;
            #[cfg(test)]
            self.lab_stage.set(27);
            self.check()?;
            fs::renameat(
                &directory,
                ".owner-journal.pending",
                &directory,
                "namespaces.json",
            )
            .map_err(|_| Error::Interrupted)?;
            #[cfg(test)]
            self.lab_stage.set(28);
            fs::fsync(&directory).map_err(|_| Error::Interrupted)?;
        }
        #[cfg(test)]
        self.lab_stage.set(29);
        self.check()?;
        Ok(record_digest(self.after.as_deref().unwrap_or(&current)))
    }
}
/// One lease per active exit, sharing one deployment flock and durable journal.
/// Rc deliberately confines journal mutation to the host guard thread. The
/// flock survives until the final lease drops; no second per-exit flock exists.
pub(super) struct Transaction {
    remote: Option<super::owner::JournalClient>,
    owner_service: bool,
    retirement_bookkeeping: bool,
    shared: std::rc::Rc<SharedJournal>,
    exit_id: String,
}
struct SharedJournal {
    native_jobs: std::rc::Rc<std::cell::RefCell<NativeJobs>>,
    services: std::cell::RefCell<std::collections::HashSet<String>>,
    pending: std::cell::RefCell<Option<Record>>,
    queue: std::cell::RefCell<MutationQueue>,
    reads: std::cell::RefCell<ReadWindows>,
    fenced: std::cell::Cell<bool>,
    journal: std::cell::RefCell<Journal>,
    leases: std::rc::Rc<std::cell::RefCell<ExitLeases>>,
}
/// Outstanding exact fixed-role constructor receipts, independent of service
/// pending/queued fields. Completed slots are pruned only after full collection.
pub(super) struct NativeJobs {
    creator: u32,
    next: u64,
    pending: std::collections::BTreeMap<u64, (String, kernel::NativeJobDrain)>,
    transferring: std::collections::HashSet<String>,
}
impl NativeJobs {
    fn new() -> Self {
        Self {
            creator: std::process::id(),
            next: 0,
            pending: Default::default(),
            transferring: Default::default(),
        }
    }
    fn prune(&mut self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let mut completed = Vec::new();
        for (id, (_, receipt)) in &self.pending {
            if receipt.complete()? {
                completed.push(*id);
            }
        }
        for id in completed {
            self.pending.remove(&id);
        }
        Ok(())
    }
    fn issue(
        &mut self,
        exit: &str,
        kind: kernel::NativeJobKind,
    ) -> Result<kernel::NativeJobTicket> {
        self.prune()?;
        if self.transferring.contains(exit) {
            return Err(Error::LockBusy);
        }
        let mut active = 0usize;
        for (_, receipt) in self.pending.values() {
            if !receipt.resources_transferred()? {
                active += 1;
            }
        }
        if active >= 64 {
            return Err(Error::LockBusy);
        }
        self.next = self.next.checked_add(1).ok_or(Error::LockBusy)?;
        let (ticket, receipt) = kernel::NativeJobTicket::prepare(kind);
        self.pending.insert(self.next, (exit.to_owned(), receipt));
        Ok(ticket)
    }
    fn drained(&mut self, exit: &str) -> Result<bool> {
        self.prune()?;
        Ok(!self.pending.values().any(|(member, _)| member == exit))
    }
}
#[derive(Default)]
struct ExitLeases(std::collections::HashMap<String, usize>);
impl ExitLeases {
    fn acquire(&mut self, exit: &str) -> Result<()> {
        if self.0.contains_key(exit) {
            return Err(Error::LockBusy);
        }
        self.0.insert(exit.to_owned(), 1);
        Ok(())
    }
    fn hold(&mut self, exit: &str) -> Result<()> {
        let count = self.0.get_mut(exit).ok_or(Error::OwnershipMismatch)?;
        *count = count.checked_add(1).ok_or(Error::LockBusy)?;
        Ok(())
    }
    fn release(&mut self, exit: &str) {
        if let Some(count) = self.0.get_mut(exit) {
            *count -= 1;
            if *count == 0 {
                self.0.remove(exit);
            }
        }
    }
}
/// Parent-created hold only: no journal methods, mutation permission or authority
/// can be recovered from this object. Both OFD and in-process reservation survive
/// a dropped transaction until every native mutator's drain owner releases them.
pub(super) struct MutatorLease {
    native_jobs: std::rc::Rc<std::cell::RefCell<NativeJobs>>,
    native_job: Option<kernel::NativeJobTicket>,
    host_window: Option<std::rc::Rc<std::cell::RefCell<vprouter_network::HostAuditTicket>>>,
    counted: bool,
    _inventory: super::inventory::Registration,
    fd: OwnedFd,
    reservations: std::rc::Rc<std::cell::RefCell<ExitLeases>>,
    exit: String,
}
impl MutatorLease {
    pub(super) fn matches_writer_owner(
        &self,
        jobs: &std::rc::Rc<std::cell::RefCell<NativeJobs>>,
        member: &str,
    ) -> Result<bool> {
        if !self.counted
            || !self._inventory.contains(self.fd.as_fd())
            || !std::rc::Rc::ptr_eq(jobs, &self.native_jobs)
            || self.exit != member
        {
            return Ok(false);
        }
        let ticket = self.native_job.as_ref().ok_or(Error::OwnershipMismatch)?;
        let jobs = jobs.try_borrow().map_err(|_| Error::LockBusy)?;
        Ok(jobs.creator == std::process::id()
            && jobs.pending.values().any(|(owner, original)| {
                owner == member && original.matches_original_writer(ticket)
            }))
    }
    pub(super) fn retain_host_window(
        &mut self,
        window: std::rc::Rc<std::cell::RefCell<vprouter_network::HostAuditTicket>>,
    ) -> Result<()> {
        if self.native_job.is_some()
            || self.host_window.is_some()
            || !self.counted
            || !self._inventory.contains(self.fd.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        self.host_window = Some(window);
        Ok(())
    }

    pub(super) fn prepare_native_job(&mut self, kind: kernel::NativeJobKind) -> Result<()> {
        if !self.counted || self.native_job.is_some() || !self._inventory.contains(self.fd.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        self.native_job = Some(
            self.native_jobs
                .try_borrow_mut()
                .map_err(|_| Error::LockBusy)?
                .issue(&self.exit, kind)?,
        );
        Ok(())
    }
    pub(crate) fn transfer_ticket(&self) -> Result<&kernel::NativeJobTicket> {
        if !self.counted || !self._inventory.contains(self.fd.as_fd()) {
            return Err(Error::OwnershipMismatch);
        }
        self.native_job.as_ref().ok_or(Error::OwnershipMismatch)
    }
    pub(super) fn native_job_mut(&mut self) -> &mut kernel::NativeJobTicket {
        self.native_job
            .as_mut()
            .expect("fixed constructor prepared job before clone")
    }

    #[cfg(test)]
    pub(super) fn lab_count(&self) -> Result<usize> {
        if !self._inventory.contains(self.fd.as_fd()) {
            return Err(Error::OwnershipMismatch);
        }
        self.reservations
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .0
            .get(&self.exit)
            .copied()
            .ok_or(Error::OwnershipMismatch)
    }
    pub(super) fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }
    pub(super) fn select_guard(&self, inputs: &mut super::inventory::GuardInputs) -> Result<()> {
        if !self.counted {
            return Err(Error::OwnershipMismatch);
        }
        inputs.include(
            &self._inventory,
            super::inventory::GuardAuthority::DeploymentHold,
        )
    }
    pub(super) fn sole_producer(&self) -> Result<bool> {
        // Transaction plus canonical producer; a live/retired same-process
        // child has an additional hold. This is only an admission fence, never
        // a cross-process or native death witness.
        Ok(self
            .reservations
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .0
            .get(&self.exit)
            == Some(&2))
    }
    pub(super) fn retain(&self) -> Result<Self> {
        if !self.counted {
            return Err(Error::OwnershipMismatch);
        }
        let fd = self
            .fd
            .try_clone()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let inventory = super::inventory::Registration::owned(&[fd.as_fd()])?;
        self.reservations
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .hold(&self.exit)?;
        Ok(Self {
            native_jobs: self.native_jobs.clone(),
            native_job: None,
            host_window: None,
            counted: true,
            _inventory: inventory,
            fd,
            reservations: self.reservations.clone(),
            exit: self.exit.clone(),
        })
    }
}
impl Drop for MutatorLease {
    fn drop(&mut self) {
        if self.counted {
            self.reservations.borrow_mut().release(&self.exit);
        }
    }
}
impl Drop for Transaction {
    fn drop(&mut self) {
        if self.owner_service {
            self.shared.services.borrow_mut().remove(&self.exit_id);
        }
        if !self.retirement_bookkeeping {
            self.shared.leases.borrow_mut().release(&self.exit_id);
        }
    }
}
impl Transaction {
    pub(super) fn attempt_binding(&self, spec: &LaunchSpec) -> Result<AttemptBinding> {
        self.require_local(spec)?;
        self.pending_binding(spec)
    }
    pub(super) fn pending_binding(&self, spec: &LaunchSpec) -> Result<AttemptBinding> {
        self.require_owner_memory(spec)?;
        let journal = self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == spec.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if entry.phase != Phase::Bootstrap {
            return Err(Error::OwnershipMismatch);
        }
        Ok(AttemptBinding {
            exit_id: spec.exit.exit_id.clone(),
            launch: vprouter_worker::bootstrap::digest(
                &serde_json::to_vec(spec).map_err(|_| Error::OwnershipMismatch)?,
            ),
            resources: attempt_resources(entry)?,
        })
    }
    /// A creator-local service view of this existing reservation. This cannot
    /// admit a second member or create a new journal/lock; it keeps the canonical
    /// journal alive while its transport is moved into pending construction.
    fn retain_owner_view(&self, spec: &LaunchSpec) -> Result<Self> {
        self.require_owner_memory(spec)?;
        if !self
            .shared
            .native_jobs
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .drained(&self.exit_id)?
        {
            return Err(Error::LockBusy);
        }
        let mut services = self
            .shared
            .services
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        if services.contains(&self.exit_id) {
            return Err(Error::LockBusy);
        }
        self.shared
            .leases
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .hold(&self.exit_id)?;
        services.insert(self.exit_id.clone());
        Ok(Self {
            remote: None,
            owner_service: true,
            retirement_bookkeeping: false,
            shared: self.shared.clone(),
            exit_id: self.exit_id.clone(),
        })
    }
    pub(super) fn retain_mutator_lease(&self, spec: &LaunchSpec) -> Result<MutatorLease> {
        self.require_local(spec)?;
        self.retain_service_lease(spec)
    }
    fn require_owner_memory(&self, spec: &LaunchSpec) -> Result<()> {
        self.bound(spec)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        journal.record.bind(
            spec,
            &journal.record.primary_exit_id,
            journal.record.primary_network()?,
        )
    }
    fn retain_service_lease(&self, spec: &LaunchSpec) -> Result<MutatorLease> {
        self.require_owner_memory(spec)?;
        self.retain_allocation_lease()
    }
    fn retain_allocation_lease(&self) -> Result<MutatorLease> {
        self.require_allocation_memory()?;
        let journal = self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let fd = journal
            .allocation
            .retain_executor_lock()
            .map_err(|_| Error::LockBusy)?;
        let inventory = super::inventory::Registration::owned(&[fd.as_fd()])?;
        self.shared
            .leases
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .hold(&self.exit_id)?;
        Ok(MutatorLease {
            native_jobs: self.shared.native_jobs.clone(),
            native_job: None,
            host_window: None,
            counted: true,
            _inventory: inventory,
            fd,
            reservations: self.shared.leases.clone(),
            exit: self.exit_id.clone(),
        })
    }
    pub fn open(
        store: &AllocationStore,
        path: &Path,
        s: &LaunchSpec,
        primary: &str,
        base: impl AsFd,
    ) -> Result<Self> {
        let journal = Journal::open(store, path, s, primary, base)?;
        Self::from_journal(journal, s)
    }
    /// Operational initial acquisition. The authenticated preplacement domain
    /// is durably bound before any namespace/link/producer constructor can run.
    /// Unknown old epochs are retained verbatim and refused, not rewritten.
    pub(super) fn open_owned(
        store: &AllocationStore,
        path: &Path,
        s: &LaunchSpec,
        primary: &str,
        base: impl AsFd,
        domains: &super::supervision::Domains,
        owner: &super::supervision::OwnerDomain,
    ) -> Result<Self> {
        let epoch = owner.record(domains)?;
        if domains.exit_id() != s.exit.exit_id
            || domains.allocation()
                != vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(&s.allocation).map_err(|_| Error::OwnershipMismatch)?,
                )
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = Journal::open_inner(store, path, s, primary, base, Some(epoch))?;
        Self::from_journal(journal, s)
    }
    fn from_journal(journal: Journal, s: &LaunchSpec) -> Result<Self> {
        Self::from_journal_member(journal, &s.exit.exit_id)
    }
    fn from_journal_member(journal: Journal, exit: &str) -> Result<Self> {
        if !journal
            .record
            .allocation
            .exits
            .iter()
            .any(|entry| entry.exit_id == exit)
        {
            return Err(Error::AllocationMismatch);
        }
        let mut leases = ExitLeases::default();
        leases.acquire(exit)?;
        Ok(Self {
            remote: None,
            owner_service: false,
            retirement_bookkeeping: false,
            shared: std::rc::Rc::new(SharedJournal {
                native_jobs: std::rc::Rc::new(std::cell::RefCell::new(NativeJobs::new())),
                services: std::cell::RefCell::new(std::collections::HashSet::new()),
                pending: std::cell::RefCell::new(None),
                queue: std::cell::RefCell::new(MutationQueue::default()),
                reads: std::cell::RefCell::new(ReadWindows::default()),
                fenced: std::cell::Cell::new(false),
                journal: std::cell::RefCell::new(journal),
                leases: std::rc::Rc::new(std::cell::RefCell::new(leases)),
            }),
            exit_id: exit.into(),
        })
    }
    fn require_allocation_memory(&self) -> Result<()> {
        #[cfg(test)]
        let _cost = preparation::lab_cost::Timer::new(preparation::lab_cost::Key::AllocationMemory);
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        if journal.owner_pid != std::process::id()
            || !journal
                .record
                .allocation
                .exits
                .iter()
                .any(|entry| entry.exit_id == self.exit_id)
        {
            return Err(Error::OwnershipMismatch);
        }
        journal.record.bind_anchor(
            &journal.record.allocation,
            &journal.record.primary_exit_id,
            journal.record.base_network,
            journal.record.owner_network,
        )
    }
    /// Additional member of this exact allocation generation. Revalidates the
    /// retained allocation under its existing flock before issuing a unique lease.
    pub fn for_exit(&self, s: &LaunchSpec) -> Result<Self> {
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        if self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .owner_pid
            != std::process::id()
        {
            return Err(Error::OwnershipMismatch);
        }
        process::single_threaded()?;
        self.shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .revalidate(s)?;
        self.shared
            .leases
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .acquire(&s.exit.exit_id)?;
        Ok(Self {
            remote: None,
            owner_service: false,
            retirement_bookkeeping: false,
            shared: self.shared.clone(),
            exit_id: s.exit.exit_id.clone(),
        })
    }
    fn bound(&self, s: &LaunchSpec) -> Result<()> {
        if self.exit_id != s.exit.exit_id {
            return Err(Error::OwnershipMismatch);
        }
        if self.remote.is_none()
            && self
                .shared
                .journal
                .try_borrow()
                .map_err(|_| Error::LockBusy)?
                .owner_pid
                != std::process::id()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    /// The only post-fork conversion, requiring a capability minted by the
    /// actual gated owner/guard path. The inherited Journal can no longer persist.
    fn mutation_allowed(&self) -> Result<()> {
        let journal = self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        if journal.owner_pid != std::process::id()
            || journal.async_only.get() && !journal.staging.get()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub fn fork_remote(&self, s: &LaunchSpec, owner: &super::owner::GuardOwner) -> Result<Self> {
        if self.remote.is_some()
            || self.exit_id != s.exit.exit_id
            || self
                .shared
                .journal
                .try_borrow()
                .map_err(|_| Error::LockBusy)?
                .owner_pid
                == std::process::id()
        {
            return Err(Error::OwnershipMismatch);
        }
        owner.domains().verify_guard()?;
        let client = owner.journal();
        client.binds(s)?;
        client.request(JournalRequest::Revalidate)?;
        // The caller replaces its inherited Transaction with this remote view.
        // Hold the existing reservation before the old view's Drop releases it;
        // this does not grant any fork-copied Journal mutation authority.
        self.shared
            .leases
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .hold(&self.exit_id)?;
        Ok(Self {
            shared: self.shared.clone(),
            exit_id: self.exit_id.clone(),
            remote: Some(client),
            owner_service: false,
            retirement_bookkeeping: false,
        })
    }
    pub(super) fn inspection_client(
        &self,
        s: &LaunchSpec,
    ) -> Result<Option<super::owner::JournalClient>> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            client.binds(s)?;
        }
        Ok(self.remote.clone())
    }
    pub(super) fn inspect_container(&self, admission: &super::Admission) -> Result<()> {
        match self.inspection_client(&admission.spec)? {
            Some(client) => client
                .inspect(super::inspection::Request::Container)
                .map(|_| ()),
            None => admission
                .process
                .revalidate(&admission.spec, &admission.staging),
        }
    }
    pub(super) fn require_local(&self, s: &LaunchSpec) -> Result<()> {
        self.bound(s)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.revalidate(s)
    }
    pub fn revalidate(&self, s: &LaunchSpec) -> Result<()> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            return client.request(JournalRequest::Revalidate);
        }
        self.shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .revalidate(s)
    }
    pub fn acquire(&mut self, s: &LaunchSpec, base: impl AsFd) -> Result<OwnedNamespaces> {
        self.bound(s)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.mutation_allowed()?;
        self.shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .acquire(s, base)
    }
    pub fn begin_transport(&mut self, s: &LaunchSpec, ns: &OwnedNamespaces) -> Result<()> {
        self.bound(s)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.mutation_allowed()?;
        self.shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .begin_transport(s, ns)
    }
    pub fn bind_producer(
        &mut self,
        s: &LaunchSpec,
        parent: Identity,
        group: Identity,
    ) -> Result<()> {
        self.bound(s)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.mutation_allowed()?;
        self.shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .bind_producer(s, parent, group)
    }
    pub fn verify_producer(&self, s: &LaunchSpec, parent: Identity, group: Identity) -> Result<()> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            return client.request(JournalRequest::VerifyProducer { parent, group });
        }
        self.shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .verify_producer(s, parent, group)
    }
    pub fn bind_links(
        &mut self,
        s: &LaunchSpec,
        ns: &OwnedNamespaces,
        host: Identity,
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.bound(s)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.mutation_allowed()?;
        self.shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .bind_links(s, ns, host, indices)
    }
    pub fn bootstrap(
        &mut self,
        s: &LaunchSpec,
        ns: &OwnedNamespaces,
        host: Identity,
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.bound(s)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.mutation_allowed()?;
        self.shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .bootstrap(s, ns, host, indices)
    }
    pub fn verify_links(
        &self,
        s: &LaunchSpec,
        ns: &OwnedNamespaces,
        host: Identity,
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            return client.request(JournalRequest::VerifyLinks {
                host,
                indices,
                data: Identity::network(&ns.data)?,
                transport: Identity::network(&ns.transport)?,
            });
        }
        self.shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .verify_links(s, ns, host, indices)
    }
    pub fn transport_cleaned(&mut self, s: &LaunchSpec) -> Result<()> {
        self.bound(s)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.mutation_allowed()?;
        self.shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?
            .transport_cleaned(s)
    }
    pub fn retain_executor_lock(&self, s: &LaunchSpec) -> Result<OwnedFd> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            client.request(JournalRequest::Revalidate)?;
        }

        let journal = self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        // Remote ACK authorizes only the inherited native OFD, never copied records.
        if self.remote.is_none() {
            journal.revalidate(s)?;
        }
        journal
            .allocation
            .retain_executor_lock()
            .map_err(|_| Error::LockBusy)
    }
    pub fn begin_terminal(
        &self,
        s: &LaunchSpec,
        binding: vprouter_core::health::Binding,
        lifecycle: &str,
    ) -> Result<()> {
        self.begin_terminal_at(s, binding, lifecycle).map(|_| ())
    }
    pub fn begin_terminal_at(
        &self,
        s: &LaunchSpec,
        binding: vprouter_core::health::Binding,
        lifecycle: &str,
    ) -> Result<f64> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            return client.begin_terminal(binding, lifecycle);
        }
        let started_at = vprouter_core::health::boot_seconds();
        self.begin_terminal_for(s, binding, lifecycle, kernel::current_process_identity()?)?;
        Ok(started_at)
    }
    fn begin_terminal_for(
        &self,
        s: &LaunchSpec,
        binding: vprouter_core::health::Binding,
        lifecycle: &str,
        guard: (u32, u64),
    ) -> Result<()> {
        self.bound(s)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.mutation_allowed()?;
        let mut journal = self
            .shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        journal.revalidate(s)?;
        journal
            .record
            .begin_terminal(&s.exit.exit_id, binding, lifecycle, guard)?;
        journal.persist()
    }
    pub fn register_executor(
        &self,
        s: &LaunchSpec,
        lifecycle: &str,
        identity: ExecutorIdentity,
    ) -> Result<()> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            return client.request(JournalRequest::RegisterExecutor {
                lifecycle: lifecycle.into(),
                identity,
            });
        }
        self.mutation_allowed()?;
        let mut journal = self
            .shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        journal.revalidate(s)?;
        let index = journal
            .record
            .entries
            .iter()
            .position(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let mut terminal = journal.record.entries[index]
            .terminal
            .clone()
            .ok_or(Error::Interrupted)?;
        if terminal.lifecycle != lifecycle {
            return Err(Error::OwnershipMismatch);
        }
        terminal.executors.push(identity);
        terminal.validate(&journal.record, &journal.record.entries[index])?;
        journal.record.entries[index].terminal = Some(terminal);
        journal.persist()
    }
    pub fn acknowledge_executor(
        &self,
        s: &LaunchSpec,
        lifecycle: &str,
        identity: &ExecutorIdentity,
    ) -> Result<()> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            return client.request(JournalRequest::AcknowledgeExecutor {
                lifecycle: lifecycle.into(),
                identity: identity.clone(),
            });
        }
        self.mutation_allowed()?;
        let mut journal = self
            .shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        journal.revalidate(s)?;
        let entry = journal
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let terminal = entry.terminal.as_mut().ok_or(Error::Interrupted)?;
        if terminal.lifecycle != lifecycle
            || !terminal.executors.contains(identity)
            || terminal.acknowledged.contains(&identity.scope)
        {
            return Err(Error::OwnershipMismatch);
        }
        terminal.acknowledged.push(identity.scope);
        journal.persist()
    }
    pub fn verify_executors(
        &self,
        s: &LaunchSpec,
        lifecycle: &str,
        children: &[ExecutorIdentity],
    ) -> Result<()> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            return client.request(JournalRequest::VerifyExecutors {
                lifecycle: lifecycle.into(),
                children: children.to_vec(),
            });
        }
        let journal = self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        journal.revalidate(s)?;
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let terminal = entry.terminal.as_ref().ok_or(Error::Interrupted)?;
        terminal.validate(&journal.record, entry)?;
        if terminal.lifecycle != lifecycle
            || terminal.executors.len() != 3
            || terminal.acknowledged != [0, 1, 2]
            || terminal.executors != children
            || !terminal.completions.is_empty()
        {
            return Err(Error::Interrupted);
        }
        Ok(())
    }
    pub fn complete_executor(
        &self,
        s: &LaunchSpec,
        lifecycle: &str,
        completion: ExecutorCompletion,
    ) -> Result<()> {
        self.bound(s)?;
        if self.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        self.mutation_allowed()?;
        let mut journal = self
            .shared
            .journal
            .try_borrow_mut()
            .map_err(|_| Error::LockBusy)?;
        journal.revalidate(s)?;
        completion.validate()?;
        let index = journal
            .record
            .entries
            .iter()
            .position(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let mut terminal = journal.record.entries[index]
            .terminal
            .clone()
            .ok_or(Error::Interrupted)?;
        if terminal.lifecycle != lifecycle {
            return Err(Error::OwnershipMismatch);
        }
        terminal.completions.push(completion);
        terminal.validate(&journal.record, &journal.record.entries[index])?;
        journal.record.entries[index].terminal = Some(terminal);
        journal.persist()
    }
    pub fn require_no_executors(&self, s: &LaunchSpec) -> Result<()> {
        self.bound(s)?;
        if let Some(client) = &self.remote {
            return client.request(JournalRequest::RequireNoExecutors);
        }
        let journal = self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        journal.revalidate(s)?;
        if journal
            .record
            .entries
            .iter()
            .any(|e| e.exit_id == s.exit.exit_id && e.terminal.is_some())
        {
            return Err(Error::Interrupted);
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn lab_unpin(&self) -> Result<()> {
        if self.shared.leases.borrow().0.len() != 1 {
            return Err(Error::LockBusy);
        }
        self.shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .lab_unpin()
    }
}
fn original_frame(sent_at: f64, now: f64) -> Result<()> {
    if !now.is_finite()
        || !sent_at.is_finite()
        || sent_at < 0.
        || now < sent_at
        || now >= sent_at + 2.
    {
        return Err(Error::Deadline);
    }
    Ok(())
}
fn mutation_slot_available(pending: bool, fenced: bool) -> Result<bool> {
    if fenced {
        return Err(Error::LockBusy);
    }
    Ok(!pending)
}
fn unchanged_selected_entry(committed: &Record, alternate: &Record, exit_id: &str) -> Result<()> {
    // Read predicates are evaluated on the committed entry. An atomic alternate
    // may therefore change other exits only, never the selected authority.
    if committed.schema_version != alternate.schema_version
        || committed.primary_exit_id != alternate.primary_exit_id
        || committed.base_network != alternate.base_network
        || committed.owner_network != alternate.owner_network
        || committed.owner_epoch != alternate.owner_epoch
        || !same_allocation(&committed.allocation, &alternate.allocation)?
    {
        return Err(Error::OwnershipMismatch);
    }
    let selected = |record: &Record| -> Result<Vec<u8>> {
        let mut entries = record
            .entries
            .iter()
            .filter(|entry| entry.exit_id == exit_id);
        let entry = entries.next().ok_or(Error::OwnershipMismatch)?;
        if entries.next().is_some() {
            return Err(Error::OwnershipMismatch);
        }
        serde_json::to_vec(entry).map_err(|_| Error::OwnershipMismatch)
    };
    if selected(committed)? != selected(alternate)? {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}
// One in-flight authenticated frame per exit. Queue ordering never refreshes
// that frame's Progress sequence or sent_at; ExternalOwner retains the original.
const MAX_JOURNAL_MEMBERS: usize = 256;
const MAX_READ_GENERATIONS: usize = 64;
#[derive(Default)]
struct MutationQueue(std::collections::VecDeque<String>);
impl MutationQueue {
    fn push(&mut self, exit: &str) -> Result<()> {
        if self.0.len() >= MAX_JOURNAL_MEMBERS || self.0.iter().any(|e| e == exit) {
            return Err(Error::LockBusy);
        }
        self.0.push_back(exit.into());
        Ok(())
    }
    fn first(&self, exit: &str) -> bool {
        self.0.front().is_some_and(|e| e == exit)
    }
    fn remove(&mut self, exit: &str) {
        self.0.retain(|e| e != exit);
    }
}
fn encode_record(record: &Record) -> Result<Vec<u8>> {
    #[cfg(test)]
    let _cost = preparation::lab_cost::Timer::new(preparation::lab_cost::Key::RecordEncode);
    let bytes = serde_json::to_vec(record).map_err(|_| Error::OwnershipMismatch)?;
    if bytes.len() > 262144 {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}
fn record_digest(bytes: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    let _cost = preparation::lab_cost::Timer::new(preparation::lab_cost::Key::RecordSha256);
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}
fn selected_authority(record: &Record, exit: &str) -> Result<[u8; 32]> {
    let mut entries = record.entries.iter().filter(|entry| entry.exit_id == exit);
    let selected = entries.next().ok_or(Error::OwnershipMismatch)?;
    if entries.next().is_some() {
        return Err(Error::OwnershipMismatch);
    }
    Ok(record_digest(
        &serde_json::to_vec(&(
            "vprouter-journal-read-authority-v1",
            record.schema_version,
            &record.allocation,
            &record.primary_exit_id,
            record.base_network,
            record.owner_network,
            &record.owner_epoch,
            selected,
        ))
        .map_err(|_| Error::OwnershipMismatch)?,
    ))
}
struct ReadWindow {
    authority: [u8; 32],
    generations: std::collections::HashSet<[u8; 32]>,
}
/// Only the authoritative owner inserts digests. An IO child observes bytes but
/// cannot introduce an accepted generation. Bound: 256 * 64 digests (512 KiB
/// payload), plus one authority per active read; no retained record history.
#[derive(Default)]
struct ReadWindows(std::collections::HashMap<String, ReadWindow>);
impl ReadWindows {
    fn reserve(&mut self, before: &Record, pending: Option<&Record>, exit: &str) -> Result<()> {
        if self.0.len() >= MAX_JOURNAL_MEMBERS || self.0.contains_key(exit) {
            return Err(Error::LockBusy);
        }
        let authority = selected_authority(before, exit)?;
        let mut generations = std::collections::HashSet::new();
        generations.insert(record_digest(&encode_record(before)?));
        if let Some(pending) = pending {
            unchanged_selected_entry(before, pending, exit)?;
            generations.insert(record_digest(&encode_record(pending)?));
        }
        self.0.insert(
            exit.into(),
            ReadWindow {
                authority,
                generations,
            },
        );
        Ok(())
    }
    fn can_publish(&self, record: &Record) -> Result<bool> {
        let digest = record_digest(&encode_record(record)?);
        for (exit, read) in &self.0 {
            if selected_authority(record, exit)? == read.authority
                && !read.generations.contains(&digest)
                && read.generations.len() >= MAX_READ_GENERATIONS
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn publish(&mut self, record: &Record) -> Result<()> {
        if !self.can_publish(record)? {
            return Err(Error::LockBusy);
        }
        let digest = record_digest(&encode_record(record)?);
        for (exit, read) in &mut self.0 {
            if selected_authority(record, exit)? == read.authority {
                read.generations.insert(digest);
            }
        }
        Ok(())
    }
    fn verify(
        &self,
        exit: &str,
        observed: [u8; 32],
        current: &Record,
        pending: Option<&Record>,
    ) -> Result<()> {
        let read = self.0.get(exit).ok_or(Error::OwnershipMismatch)?;
        if !read.generations.contains(&observed)
            || selected_authority(current, exit)? != read.authority
            || pending
                .map(|p| selected_authority(p, exit))
                .transpose()?
                .is_some_and(|a| a != read.authority)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    fn remove(&mut self, exit: &str) {
        self.0.remove(exit);
    }
}
/// Bound by the original constructor and the SAME in-process canonical journal.
/// This is retained ownership only, never a stop/cleanup permission.
#[derive(Clone)]
pub(super) struct RetirementBinding {
    creator: u32,
    shared: std::rc::Rc<SharedJournal>,
    exit: String,
    lifecycle: String,
    birth: GuardBirth,
    group: Identity,
    launch: String,
    resources: RetirementResources,
}
struct RetirementStart {
    binding: RetirementBinding,
    reaps: [kernel::NativeReapProof; 3],
    started_at: f64,
}
/// One-shot permission can only be returned after the original Retiring writer
/// durably acknowledges/readbacks and actually reaps. No Deserialize or Clone.
pub(super) struct RetiringPermit {
    binding: RetirementBinding,
    authority: [u8; 32],
    started_at: f64,
    stop_started: Option<f64>,
    stop_consumed: bool,
}
/// Sealed native job input: no caller-supplied fd, name or parsed record can
/// construct the authorization accepted by the fixed stop-role constructor.
pub(super) struct StopAuthorization {
    context: StopContext,
    target: super::producer::StopTarget,
    guard: OwnedFd,
    inventory: super::inventory::Registration,
    lease: MutatorLease,
}
#[derive(Clone)]
pub(super) struct StopContext {
    binding: RetirementBinding,
    authority: [u8; 32],
    started_at: f64,
}
impl StopContext {
    pub(super) fn deadline(&self) -> f64 {
        self.started_at + 2.
    }
    pub(super) fn verify(&self, binding: &RetirementBinding, authority: [u8; 32]) -> Result<()> {
        if self.binding.creator != std::process::id()
            || binding.creator != self.binding.creator
            || !std::rc::Rc::ptr_eq(&self.binding.shared, &binding.shared)
            || self.binding.exit != binding.exit
            || self.binding.lifecycle != binding.lifecycle
            || self.binding.birth != binding.birth
            || self.binding.group != binding.group
            || self.authority != authority
            || !self.started_at.is_finite()
            || self.started_at <= 0.
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
impl StopAuthorization {
    pub(super) fn into_native(
        self,
    ) -> (
        StopContext,
        super::producer::StopTarget,
        OwnedFd,
        super::inventory::Registration,
        MutatorLease,
    ) {
        (
            self.context,
            self.target,
            self.guard,
            self.inventory,
            self.lease,
        )
    }
}
impl RetiringPermit {
    pub(super) fn verify_stop(
        &self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
        producer: (Identity, Identity),
    ) -> Result<()> {
        if self.stop_consumed {
            return Err(Error::OwnershipMismatch);
        }
        self.verify_current(service, guard, producer)
    }
    fn verify_current(
        &self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
        producer: (Identity, Identity),
    ) -> Result<()> {
        self.binding.verify(service, AttemptStage::Retiring)?;
        if guard.original_birth()? != self.binding.birth
            || guard.retirement_group()? != self.binding.group
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self
            .binding
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.binding.exit)
            .ok_or(Error::OwnershipMismatch)?;
        if selected_authority(&journal.record, &self.binding.exit)? != self.authority
            || entry
                .producer
                .as_ref()
                .is_none_or(|p| (p.parent, p.group) != producer)
            || entry
                .attempt
                .as_ref()
                .and_then(|a| a.retirement.as_ref())
                .is_none_or(|r| r.started_at != self.started_at)
            || self.binding.shared.fenced.get()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn launch_stop(
        &mut self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
        producer: &super::producer::ProducerGroup,
    ) -> Result<kernel::retirement::StopChild> {
        kernel::owner_admission_permitted()?;
        let started = *self
            .stop_started
            .get_or_insert_with(vprouter_core::health::boot_seconds);
        original_frame(started, vprouter_core::health::boot_seconds())?;
        self.verify_stop(service, guard, producer.original_identities()?)?;
        let target = producer.stop_target(self, service, guard)?;
        let (pidfd, inventory) = guard.retirement_pidfd()?;
        let lease = service.transaction.retain_service_lease(&service.spec)?;
        self.verify_stop(service, guard, producer.original_identities()?)?;
        self.stop_consumed = true;
        kernel::retirement::spawn(StopAuthorization {
            context: StopContext {
                binding: self.binding.clone(),
                authority: self.authority,
                started_at: started,
            },
            target,
            guard: pidfd,
            inventory,
            lease,
        })
    }
}
pub(super) struct QuiescenceRequest {
    binding: RetirementBinding,
    authority: [u8; 32],
    guard: kernel::GuardQuiescence,
    reaps: [kernel::NativeReapProof; 3],
    stop: kernel::retirement::StopReceipt,
    producer: super::producer::Drain,
    started_at: f64,
}
pub(super) struct QuiescentPermit {
    binding: RetirementBinding,
    authority: [u8; 32],
    quiescent_at: f64,
}
impl QuiescentPermit {
    pub(super) fn verify(&self, service: &JournalServer) -> Result<()> {
        self.binding.verify(service, AttemptStage::Quiescent)?;
        let journal = self
            .binding
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.binding.exit)
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if self.binding.shared.fenced.get()
            || selected_authority(&journal.record, &self.binding.exit)? != self.authority
            || history.quiescent_at != Some(self.quiescent_at)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn verify_guard(
        &self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
    ) -> Result<()> {
        self.verify(service)?;
        if guard.original_birth() != Ok(self.binding.birth.clone())
            || guard.retirement_group() != Ok(self.binding.group)
            || !guard.retirement_drained()?
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn retire_bookkeeping(
        &self,
        service: &JournalServer,
        lease: &mut MutatorLease,
    ) -> Result<()> {
        self.verify(service)?;
        if !service.idle()
            || !service.native_drained()
            || lease.native_job.is_some()
            || lease.exit != self.binding.exit
            || !std::rc::Rc::ptr_eq(&lease.reservations, &self.binding.shared.leases)
            || !lease._inventory.contains(lease.fd.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        if lease.counted {
            lease
                .reservations
                .try_borrow_mut()
                .map_err(|_| Error::LockBusy)?
                .release(&lease.exit);
            lease.counted = false;
        }
        Ok(())
    }
}
impl PlannedAttempt {
    pub(super) fn retire_bookkeeping(
        &mut self,
        permit: &QuiescentPermit,
        service: &JournalServer,
    ) -> Result<()> {
        if self.creator != std::process::id()
            || self.value.exit_id != permit.binding.exit
            || self.value.lifecycle != permit.binding.lifecycle
        {
            return Err(Error::OwnershipMismatch);
        }
        permit.retire_bookkeeping(service, &mut self.lease)
    }
}
struct CleanupIntent {
    binding: RetirementBinding,
    authority: [u8; 32],
    transition: String,
    started_at: f64,
}
impl CleanupIntent {
    fn verify(&self, service: &JournalServer) -> Result<()> {
        self.binding.verify(service, AttemptStage::Quiescent)?;
        original_frame(self.started_at, vprouter_core::health::boot_seconds())?;
        let journal = self
            .binding
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.binding.exit)
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if self.binding.shared.fenced.get()
            || selected_authority(&journal.record, &self.binding.exit)? != self.authority
            || history.cleanup != CleanupStage::NotStarted
            || history.host_transition.is_some()
            || !super::spec::digest(&self.transition)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
/// Current opaque cleanup intent, minted only after its writer ACK/readback and
/// actual reap. The original live native fence remains separately mandatory.
pub(super) struct CleanupPermit {
    binding: RetirementBinding,
    authority: [u8; 32],
    transition: String,
    stage: CleanupStage,
    started_at: Option<f64>,
    consumed: bool,
}
#[derive(Clone)]
pub(super) struct CleanupContext {
    binding: RetirementBinding,
    authority: [u8; 32],
    transition: String,
    stage: CleanupStage,
    started_at: f64,
}
impl CleanupContext {
    pub(super) fn verify_authority(
        &self,
        binding: &RetirementBinding,
        authority: [u8; 32],
        transition: &str,
        stage: CleanupStage,
    ) -> Result<()> {
        if self.binding.creator != std::process::id()
            || !std::rc::Rc::ptr_eq(&self.binding.shared, &binding.shared)
            || self.binding.exit != binding.exit
            || self.binding.lifecycle != binding.lifecycle
            || self.binding.birth != binding.birth
            || self.authority != authority
            || self.transition != transition
            || self.stage != stage
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn verify_unlinked(
        &self,
        binding: &RetirementBinding,
        transition: &str,
    ) -> Result<()> {
        self.verify_authority(
            binding,
            self.authority,
            transition,
            CleanupStage::ProducerIntent,
        )
    }
    pub(super) fn producer_operation(&self) -> bool {
        self.stage == CleanupStage::ProducerIntent
    }
    pub(super) fn deadline(&self) -> f64 {
        self.started_at + 2.
    }
    pub(super) fn verify(&self, permit: &CleanupPermit) -> Result<()> {
        if self.binding.creator != std::process::id()
            || !std::rc::Rc::ptr_eq(&self.binding.shared, &permit.binding.shared)
            || self.binding.exit != permit.binding.exit
            || self.binding.lifecycle != permit.binding.lifecycle
            || self.binding.birth != permit.binding.birth
            || self.authority != permit.authority
            || self.transition != permit.transition
            || self.stage != permit.stage
            || permit.started_at != Some(self.started_at)
            || !permit.consumed
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
pub(super) struct CleanupAuthorization {
    context: CleanupContext,
    target: super::producer::CleanupTarget,
    transport: std::rc::Rc<std::cell::RefCell<super::transport::RetirementTransport>>,
    plan: Option<vprouter_network::NativeRemovalPlan>,
    lease: MutatorLease,
}
impl CleanupAuthorization {
    pub(super) fn into_native(
        self,
    ) -> (
        CleanupContext,
        super::producer::CleanupTarget,
        std::rc::Rc<std::cell::RefCell<super::transport::RetirementTransport>>,
        Option<vprouter_network::NativeRemovalPlan>,
        MutatorLease,
    ) {
        (
            self.context,
            self.target,
            self.transport,
            self.plan,
            self.lease,
        )
    }
}
impl CleanupPermit {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify_transport(
        &self,
        service: &JournalServer,
        transaction: &Transaction,
        spec: &LaunchSpec,
        namespaces: &OwnedNamespaces,
        guard: &kernel::ManagedGuard,
        producer: (Identity, Identity),
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.binding.verify(service, AttemptStage::Quiescent)?;
        if !std::rc::Rc::ptr_eq(&transaction.shared, &self.binding.shared)
            || transaction.exit_id != self.binding.exit
            || transaction.retirement_bookkeeping
            || guard.original_birth()? != self.binding.birth
            || guard.retirement_group()? != self.binding.group
        {
            return Err(Error::OwnershipMismatch);
        }
        transaction.require_owner_memory(spec)?;
        namespaces.bind(spec)?;
        if vprouter_worker::bootstrap::digest(
            &serde_json::to_vec(spec).map_err(|_| Error::OwnershipMismatch)?,
        ) != self.binding.launch
            || self
                .binding
                .resources
                .links
                .as_ref()
                .is_none_or(|l| (l.host_index, l.transport_index, l.wireguard_index) != indices)
            || self.binding.resources.data != Some(Identity::network(&namespaces.data)?)
            || self.binding.resources.transport != Some(Identity::network(&namespaces.transport)?)
        {
            return Err(Error::OwnershipMismatch);
        }
        self.verify_producer_target(producer)
    }
    pub(super) fn verify_producer_target(&self, identities: (Identity, Identity)) -> Result<()> {
        let journal = self
            .binding
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.binding.exit)
            .ok_or(Error::OwnershipMismatch)?;
        if self.binding.creator != std::process::id()
            || self.binding.shared.fenced.get()
            || selected_authority(&journal.record, &self.binding.exit)? != self.authority
            || entry
                .producer
                .as_ref()
                .is_none_or(|p| (p.parent, p.group) != identities)
            || entry.attempt.as_ref().is_none_or(|a| {
                a.stage != AttemptStage::Quiescent
                    || a.retirement.as_ref().is_none_or(|r| {
                        r.cleanup != self.stage
                            || r.host_transition.as_ref() != Some(&self.transition)
                    })
            })
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }

    fn eligible(
        &self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
        expiry: &super::expiry::OwnerExecutors,
        plan: &mut vprouter_network::HostRemovalPlan,
    ) -> Result<bool> {
        self.binding.verify(service, AttemptStage::Quiescent)?;
        if !service.idle() || !service.native_drained() || !guard.retirement_removed()? {
            return Ok(false);
        }
        let birth = guard.original_birth()?;
        if birth != self.binding.birth || guard.retirement_group()? != self.binding.group {
            return Err(Error::OwnershipMismatch);
        }
        expiry.retirement_reaps()?;
        let journal = self
            .binding
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.binding.exit)
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if self.binding.shared.fenced.get()
            || selected_authority(&journal.record, &self.binding.exit)? != self.authority
            || history.cleanup != self.stage
            || history.host_transition.as_ref() != Some(&self.transition)
            || vprouter_worker::bootstrap::digest(
                plan.intent_bytes().map_err(|_| Error::OwnershipMismatch)?,
            ) != self.transition
        {
            return Err(Error::OwnershipMismatch);
        }
        let host = self
            .binding
            .resources
            .links
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .host_namespace;
        plan.bind(
            &service.spec.allocation,
            service.exit_id(),
            (host.dev, host.ino),
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        drop(journal);
        Ok(true)
    }
    pub(super) fn activate(
        &self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
        expiry: &super::expiry::OwnerExecutors,
        plan: &mut vprouter_network::HostRemovalPlan,
    ) -> Result<bool> {
        if self.stage != CleanupStage::LinksIntent
            || !self.eligible(service, guard, expiry, plan)?
        {
            return Ok(false);
        }
        plan.activate().map_err(|_| Error::OwnershipMismatch)?;
        Ok(true)
    }
    pub(super) fn launch_links(
        &mut self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
        expiry: &super::expiry::OwnerExecutors,
        plan: &mut vprouter_network::HostRemovalPlan,
        transport: std::rc::Rc<std::cell::RefCell<super::transport::RetirementTransport>>,
    ) -> Result<kernel::cleanup::CleanupChild> {
        kernel::owner_admission_permitted()?;
        let started = *self
            .started_at
            .get_or_insert_with(vprouter_core::health::boot_seconds);
        original_frame(started, vprouter_core::health::boot_seconds())?;
        if self.stage != CleanupStage::LinksIntent
            || self.consumed
            || !self.eligible(service, guard, expiry, plan)?
        {
            return Err(Error::OwnershipMismatch);
        }
        let target = transport
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .cleanup_target(self)?;
        let native_plan = plan.native_plan().map_err(|_| Error::OwnershipMismatch)?;
        let lease = service.transaction.retain_service_lease(&service.spec)?;
        transport
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .verify_cleanup_binding(self, service, guard)?;
        self.consumed = true;
        kernel::cleanup::spawn(CleanupAuthorization {
            context: CleanupContext {
                binding: self.binding.clone(),
                authority: self.authority,
                transition: self.transition.clone(),
                stage: self.stage,
                started_at: started,
            },
            target,
            transport,
            plan: Some(native_plan),
            lease,
        })
    }
    pub(super) fn launch_producer(
        &mut self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
        expiry: &super::expiry::OwnerExecutors,
        plan: &mut vprouter_network::HostRemovalPlan,
        transport: std::rc::Rc<std::cell::RefCell<super::transport::RetirementTransport>>,
    ) -> Result<kernel::cleanup::CleanupChild> {
        kernel::owner_admission_permitted()?;
        let started = *self
            .started_at
            .get_or_insert_with(vprouter_core::health::boot_seconds);
        original_frame(started, vprouter_core::health::boot_seconds())?;
        if self.stage != CleanupStage::ProducerIntent
            || self.consumed
            || !self.eligible(service, guard, expiry, plan)?
        {
            return Err(Error::OwnershipMismatch);
        }
        let target = transport
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .cleanup_target(self)?;
        transport
            .try_borrow()
            .map_err(|_| Error::LockBusy)?
            .verify_cleanup_binding(self, service, guard)?;
        let lease = service.transaction.retain_service_lease(&service.spec)?;
        self.consumed = true;
        kernel::cleanup::spawn(CleanupAuthorization {
            context: CleanupContext {
                binding: self.binding.clone(),
                authority: self.authority,
                transition: self.transition.clone(),
                stage: self.stage,
                started_at: started,
            },
            target,
            transport,
            plan: None,
            lease,
        })
    }
}
struct FinalRetirement {
    binding: RetirementBinding,
    authority: [u8; 32],
    transition: String,
    producer: std::rc::Rc<kernel::cleanup::CleanupReceipt>,
    root: kernel::RemovedGuard,
    reaps: [kernel::NativeReapProof; 3],
    started_at: f64,
}
impl FinalRetirement {
    fn verify(&self, service: &JournalServer) -> Result<()> {
        self.binding.verify(service, AttemptStage::Quiescent)?;
        original_frame(self.started_at, vprouter_core::health::boot_seconds())?;
        self.root.verify(&self.binding.birth, self.binding.group)?;
        self.producer
            .verify_unlinked(&self.binding, &self.transition)?;
        verify_terminal_reaps(&self.binding, &self.reaps, self.started_at)?;
        let journal = self
            .binding
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.binding.exit)
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if self.binding.shared.fenced.get()
            || selected_authority(&journal.record, &self.binding.exit)? != self.authority
            || history.cleanup != CleanupStage::ProducerRemoved
            || history.host_transition.as_ref() != Some(&self.transition)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
pub(super) struct RetiredPermit {
    binding: RetirementBinding,
    authority: [u8; 32],
    retired_at: f64,
    transition: String,
    producer: std::rc::Rc<kernel::cleanup::CleanupReceipt>,
}
impl RetiredPermit {
    pub(super) fn verify(&self, service: &JournalServer) -> Result<()> {
        self.binding.verify(service, AttemptStage::Retired)?;
        if !service.idle() || !service.native_drained() || self.binding.shared.fenced.get() {
            return Err(Error::OwnershipMismatch);
        }
        self.producer
            .verify_unlinked(&self.binding, &self.transition)?;
        let journal = self
            .binding
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.binding.exit)
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if selected_authority(&journal.record, &self.binding.exit)? != self.authority
            || history.cleanup != CleanupStage::ProducerRemoved
            || history.retired_at != Some(self.retired_at)
            || history.host_transition.as_ref() != Some(&self.transition)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn verify_guard_release(
        &self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
    ) -> Result<()> {
        self.verify(service)?;
        if guard.original_birth()? != self.binding.birth
            || guard.retirement_group()? != self.binding.group
            || !guard.retirement_root_removed()?
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn verify_expiry_release(
        &self,
        service: &JournalServer,
        expiry: &super::expiry::OwnerExecutors,
    ) -> Result<()> {
        self.verify(service)?;
        expiry.binds(
            service.allocation(),
            &self.binding.exit,
            &self.binding.lifecycle,
        )?;
        verify_terminal_reaps(&self.binding, &expiry.retirement_reaps()?, self.retired_at)
    }
    pub(super) fn verify_producer_release(
        &self,
        service: &JournalServer,
        parent: Identity,
        group: Identity,
    ) -> Result<()> {
        self.verify(service)?;
        if self
            .binding
            .resources
            .producer
            .as_ref()
            .is_none_or(|p| (p.parent, p.group) != (parent, group))
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
struct CleanupProgress {
    binding: RetirementBinding,
    authority: [u8; 32],
    transition: String,
    previous: CleanupStage,
    next: CleanupStage,
    started_at: f64,
    receipt: Option<std::rc::Rc<kernel::cleanup::CleanupReceipt>>,
}
impl CleanupProgress {
    fn verify(&self, service: &JournalServer) -> Result<()> {
        self.binding.verify(service, AttemptStage::Quiescent)?;
        original_frame(self.started_at, vprouter_core::health::boot_seconds())?;
        let journal = self
            .binding
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.binding.exit)
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if self.binding.shared.fenced.get()
            || selected_authority(&journal.record, &self.binding.exit)? != self.authority
            || history.cleanup != self.previous
            || history.host_transition.as_ref() != Some(&self.transition)
        {
            return Err(Error::OwnershipMismatch);
        }
        match (self.previous, self.next) {
            (CleanupStage::LinksIntent, CleanupStage::LinksRemoved)
            | (CleanupStage::ProducerIntent, CleanupStage::ProducerRemoved) => {
                self.receipt
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .verify_authority(
                        &self.binding,
                        self.authority,
                        &self.transition,
                        self.previous,
                    )?;
            }
            (CleanupStage::LinksRemoved, CleanupStage::ProducerIntent)
                if self.receipt.is_none() => {}
            _ => return Err(Error::OwnershipMismatch),
        }
        Ok(())
    }
}
impl QuiescenceRequest {
    fn verify(&self, service: &JournalServer) -> Result<()> {
        self.binding.verify(service, AttemptStage::Retiring)?;
        original_frame(self.started_at, vprouter_core::health::boot_seconds())?;
        self.guard.verify(&self.binding.birth, self.binding.group)?;
        self.stop.verify(&self.binding, self.authority)?;
        if !self.producer.empty()?
            || selected_authority(
                &self.binding.shared.journal.borrow().record,
                &self.binding.exit,
            )? != self.authority
        {
            return Err(Error::OwnershipMismatch);
        }
        verify_terminal_reaps(&self.binding, &self.reaps, self.started_at)
    }
}
impl RetiringPermit {
    pub(super) fn quiescence(
        &self,
        service: &JournalServer,
        guard: &kernel::ManagedGuard,
        producer: &super::producer::ProducerGroup,
        stop: &kernel::retirement::StopReceipt,
        expiry: &super::expiry::OwnerExecutors,
        started_at: f64,
    ) -> Result<Option<QuiescenceRequest>> {
        if !self.stop_consumed {
            return Err(Error::OwnershipMismatch);
        }
        self.verify_current(service, guard, producer.original_identities()?)?;
        stop.verify(&self.binding, self.authority)?;
        if !service.idle() || !service.native_drained() {
            return Ok(None);
        }
        let Some(guard) = guard.retirement_quiescence()? else {
            return Ok(None);
        };
        let producer = producer.retain_drain()?;
        if !producer.empty()? {
            return Ok(None);
        }
        let reaps = expiry.retirement_reaps()?;
        let result = QuiescenceRequest {
            binding: self.binding.clone(),
            authority: self.authority,
            guard,
            reaps,
            stop: stop.clone(),
            producer,
            started_at,
        };
        result.verify(service)?;
        Ok(Some(result))
    }
}
fn verify_terminal_reaps(
    binding: &RetirementBinding,
    reaps: &[kernel::NativeReapProof; 3],
    observed_at: f64,
) -> Result<()> {
    let journal = binding
        .shared
        .journal
        .try_borrow()
        .map_err(|_| Error::LockBusy)?;
    let terminal = journal
        .record
        .entries
        .iter()
        .find(|e| e.exit_id == binding.exit)
        .and_then(|e| e.terminal.as_ref())
        .ok_or(Error::OwnershipMismatch)?;
    if terminal.lifecycle != binding.lifecycle
        || terminal.executors.len() != 3
        || terminal.acknowledged != [0, 1, 2]
        || terminal.completions.len() != 3
    {
        return Err(Error::OwnershipMismatch);
    }
    for (scope, reap) in reaps.iter().enumerate() {
        let identity = terminal
            .executors
            .iter()
            .find(|e| e.scope as usize == scope)
            .ok_or(Error::OwnershipMismatch)?;
        let completion = terminal
            .completions
            .iter()
            .find(|c| &c.identity == identity)
            .ok_or(Error::OwnershipMismatch)?;
        if reap.identity()? != (identity.pid, identity.start_time, 122 << 8)
            || completion.result != TerminalResult::VerifiedBeforeDeadline
            || completion.finished_at > observed_at
            || completion.finished_at >= completion.deadline
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    Ok(())
}
impl RetirementBinding {
    fn verify(&self, service: &JournalServer, stage: AttemptStage) -> Result<()> {
        if self.creator != std::process::id()
            || self.creator != service.creator
            || !std::rc::Rc::ptr_eq(&self.shared, &service.transaction.shared)
            || self.exit != service.exit_id()
            || self.lifecycle != service.lifecycle()
        {
            return Err(Error::OwnershipMismatch);
        }
        service.transaction.require_owner_memory(&service.spec)?;
        let journal = self
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.exit)
            .ok_or(Error::OwnershipMismatch)?;
        let attempt = entry.attempt.as_ref().ok_or(Error::OwnershipMismatch)?;
        attempt.validate(&journal.record, entry)?;
        if attempt.stage != stage
            || attempt.lifecycle != self.lifecycle
            || attempt.birth.as_ref() != Some(&self.birth)
            || attempt.guard_group != Some(self.group)
            || attempt.launch != self.launch
            || attempt.resources != self.resources.digest()?
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
impl RetirementStart {
    fn verify(&self, service: &JournalServer) -> Result<()> {
        self.binding.verify(service, AttemptStage::Released)?;
        original_frame(self.started_at, vprouter_core::health::boot_seconds())?;
        let journal = self
            .binding
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let terminal = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.binding.exit)
            .and_then(|e| e.terminal.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if terminal.lifecycle != self.binding.lifecycle
            || terminal.executors.len() != 3
            || terminal.acknowledged != [0, 1, 2]
            || terminal.completions.len() != 3
        {
            return Err(Error::OwnershipMismatch);
        }
        for (scope, reap) in self.reaps.iter().enumerate() {
            let identity = terminal
                .executors
                .iter()
                .find(|e| e.scope as usize == scope)
                .ok_or(Error::OwnershipMismatch)?;
            let completion = terminal
                .completions
                .iter()
                .find(|c| &c.identity == identity)
                .ok_or(Error::OwnershipMismatch)?;
            if reap.identity()? != (identity.pid, identity.start_time, 122 << 8)
                || completion.result != TerminalResult::VerifiedBeforeDeadline
                || completion.finished_at > self.started_at
                || completion.finished_at >= completion.deadline
            {
                return Err(Error::OwnershipMismatch);
            }
        }
        Ok(())
    }
}
enum OwnerMutation {
    Retire(Box<RetirementStart>),
    Quiescent(Box<QuiescenceRequest>),
    LinksIntent(Box<CleanupIntent>),
    CleanupProgress(Box<CleanupProgress>),
    FinalRetirement(Box<FinalRetirement>),
    Plan(Box<AttemptPlan>),
    Birth(GuardBirth),
    Place(GuardBirth, Identity),
    Release(GuardBirth, Identity),
}
enum JournalOperation {
    Guard(JournalRequest),
    Owner(OwnerMutation),
}
impl From<JournalRequest> for JournalOperation {
    fn from(value: JournalRequest) -> Self {
        Self::Guard(value)
    }
}
struct QueuedRequest {
    request: JournalOperation,
    sent_at: f64,
}
/// The owner keeps this service alive through fencing/drain. It never executes
/// filesystem reads/fsync in its poll loop; fixed children do that bounded work.
pub(super) enum TerminalIo {
    Busy,
    Drained,
    ReadReaped { deadline: f64 },
}
pub(super) struct JournalServer {
    creator: u32,
    transaction: Transaction,
    spec: LaunchSpec,
    namespaces: OwnedNamespaces,
    domains: super::supervision::Domains,
    binding: vprouter_core::health::Binding,
    pending: Option<JournalJob>,
    queued: Option<QueuedRequest>,
    completing: bool,
    registering: bool,
    owner_stage: Option<AttemptStage>,
    plan_issued: bool,
    retired_read_deadline: Option<f64>,
    #[cfg(test)]
    completed: u64,
    #[cfg(test)]
    pause_next_read: bool,
    #[cfg(test)]
    pause_next_write: bool,
    #[cfg(test)]
    retirement_poll_error: bool,
    #[cfg(test)]
    mutation_completion: Option<(f64, f64)>,
    #[cfg(test)]
    refuse_next_birth: bool,
}
struct JournalJob {
    child: kernel::JournalChild,
    mutation: bool,
    deadline: f64,
    failed: bool,
}
impl JournalServer {
    #[cfg(test)]
    pub fn new(
        transaction: &Transaction,
        spec: &LaunchSpec,
        namespaces: &OwnedNamespaces,
        domains: super::supervision::Domains,
        binding: vprouter_core::health::Binding,
    ) -> Result<Self> {
        transaction.revalidate(spec)?;
        domains.verify_owner()?;
        Self::new_inner(transaction, spec, namespaces, domains, binding)
    }
    pub(super) fn new_owned(
        transaction: &Transaction,
        spec: &LaunchSpec,
        namespaces: &OwnedNamespaces,
        domains: super::supervision::Domains,
        binding: vprouter_core::health::Binding,
        owner: &super::supervision::OwnerDomain,
    ) -> Result<Self> {
        let epoch = owner.record(&domains)?;
        if binding.boot_id != epoch.boot {
            return Err(Error::OwnershipMismatch);
        }
        transaction.require_owner_memory(spec)?;
        if transaction
            .shared
            .journal
            .borrow()
            .record
            .owner_epoch
            .as_ref()
            != Some(&epoch)
        {
            return Err(Error::OwnershipMismatch);
        }
        Self::new_inner(transaction, spec, namespaces, domains, binding)
    }
    fn new_inner(
        transaction: &Transaction,
        spec: &LaunchSpec,
        namespaces: &OwnedNamespaces,
        domains: super::supervision::Domains,
        binding: vprouter_core::health::Binding,
    ) -> Result<Self> {
        if transaction.remote.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        namespaces.bind(spec)?;
        binding.validate().map_err(|_| Error::InvalidSpec)?;
        if domains.allocation()
            != vprouter_worker::bootstrap::digest(
                &serde_json::to_vec(&spec.allocation).map_err(|_| Error::InvalidSpec)?,
            )
            || binding.deployment_id != spec.allocation.deployment_id
            || binding.generation != spec.generation
            || domains.exit_id() != spec.exit.exit_id
            || binding.exit_id != spec.exit.exit_id
            || binding.mode != spec.exit.mode
        {
            return Err(Error::AllocationMismatch);
        }
        let namespaces = namespaces.inspection_copy(spec)?;
        let spec = LaunchSpec::parse(&serde_json::to_vec(spec).map_err(|_| Error::InvalidSpec)?)?;
        let transaction = transaction.retain_owner_view(&spec)?;
        transaction.shared.journal.borrow().async_only.set(true);
        Ok(Self {
            creator: std::process::id(),
            transaction,
            spec,
            namespaces,
            domains,
            binding,
            pending: None,
            queued: None,
            completing: false,
            registering: false,
            owner_stage: None,
            plan_issued: false,
            retired_read_deadline: None,
            #[cfg(test)]
            completed: 0,
            #[cfg(test)]
            pause_next_read: false,
            #[cfg(test)]
            pause_next_write: false,
            #[cfg(test)]
            retirement_poll_error: false,
            #[cfg(test)]
            mutation_completion: None,
            #[cfg(test)]
            refuse_next_birth: false,
        })
    }
    pub(super) fn bind_retirement(
        &self,
        transaction: &Transaction,
        spec: &LaunchSpec,
        namespaces: &OwnedNamespaces,
        guard: &kernel::ManagedGuard,
        producer: (Identity, Identity),
    ) -> Result<RetirementBinding> {
        if self.creator != std::process::id()
            || !std::rc::Rc::ptr_eq(&self.transaction.shared, &transaction.shared)
            || transaction.exit_id != self.exit_id()
        {
            return Err(Error::OwnershipMismatch);
        }
        transaction.require_owner_memory(spec)?;
        namespaces.bind(spec)?;
        let birth = guard.original_birth()?;
        let group = guard.retirement_group()?;
        let launch = vprouter_worker::bootstrap::digest(
            &serde_json::to_vec(spec).map_err(|_| Error::OwnershipMismatch)?,
        );
        let journal = self
            .transaction
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let entry = journal
            .record
            .entries
            .iter()
            .find(|entry| entry.exit_id == self.exit_id())
            .ok_or(Error::OwnershipMismatch)?;
        let attempt = entry.attempt.as_ref().ok_or(Error::OwnershipMismatch)?;
        attempt.validate(&journal.record, entry)?;
        if attempt.stage != AttemptStage::Released
            || attempt.lifecycle != self.lifecycle()
            || attempt.birth.as_ref() != Some(&birth)
            || attempt.guard_group != Some(group)
            || attempt.launch != launch
            || entry
                .producer
                .as_ref()
                .is_none_or(|p| (p.parent, p.group) != producer)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(RetirementBinding {
            creator: self.creator,
            shared: self.transaction.shared.clone(),
            exit: self.exit_id().into(),
            lifecycle: self.lifecycle().into(),
            birth,
            group,
            launch,
            resources: RetirementResources::capture(entry),
        })
    }
    pub(super) fn fail_retirement(&mut self, binding: &RetirementBinding) -> Result<()> {
        if self.creator != std::process::id()
            || binding.creator != self.creator
            || !std::rc::Rc::ptr_eq(&binding.shared, &self.transaction.shared)
            || binding.exit != self.exit_id()
            || binding.lifecycle != self.lifecycle()
        {
            return Err(Error::OwnershipMismatch);
        }
        if matches!(
            self.owner_stage,
            Some(AttemptStage::Retiring | AttemptStage::Quiescent | AttemptStage::Retired)
        ) {
            self.fence()?;
        }
        Ok(())
    }
    pub(super) fn start_retirement(
        &mut self,
        binding: &RetirementBinding,
        reaps: [kernel::NativeReapProof; 3],
        started_at: f64,
    ) -> Result<()> {
        if !self.idle() || !self.native_drained() {
            return Err(Error::LockBusy);
        }
        let request = RetirementStart {
            binding: binding.clone(),
            reaps,
            started_at,
        };
        request.verify(self)?;
        let shared = &self.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        shared.queue.borrow_mut().push(self.exit_id())?;
        self.queued = Some(QueuedRequest {
            request: JournalOperation::Owner(OwnerMutation::Retire(Box::new(request))),
            sent_at: started_at,
        });
        self.owner_stage = Some(AttemptStage::Retiring);
        Ok(())
    }
    pub(super) fn poll_retirement(
        &mut self,
        binding: &RetirementBinding,
        started_at: f64,
    ) -> Result<Option<RetiringPermit>> {
        if self.owner_stage != Some(AttemptStage::Retiring)
            || binding.creator != self.creator
            || !std::rc::Rc::ptr_eq(&binding.shared, &self.transaction.shared)
            || binding.exit != self.exit_id()
            || binding.lifecycle != self.lifecycle()
        {
            return Err(Error::OwnershipMismatch);
        }
        if !self.poll_inner(None)? {
            return Ok(None);
        }
        binding.verify(self, AttemptStage::Retiring)?;
        let journal = self
            .transaction
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.exit_id())
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if history.started_at != started_at {
            return Err(Error::OwnershipMismatch);
        }
        let authority = selected_authority(&journal.record, self.exit_id())?;
        drop(journal);
        self.owner_stage = None;
        Ok(Some(RetiringPermit {
            binding: binding.clone(),
            authority,
            started_at,
            stop_started: None,
            stop_consumed: false,
        }))
    }
    pub(super) fn start_links_intent(
        &mut self,
        permit: &QuiescentPermit,
        plan: &vprouter_network::HostRemovalPlan,
        started_at: f64,
    ) -> Result<()> {
        permit.verify(self)?;
        if !self.idle() || !self.native_drained() || !self.transaction.retirement_bookkeeping {
            return Err(Error::LockBusy);
        }
        let host = permit
            .binding
            .resources
            .links
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .host_namespace;
        plan.bind(&self.spec.allocation, self.exit_id(), (host.dev, host.ino))
            .map_err(|_| Error::OwnershipMismatch)?;
        let transition = vprouter_worker::bootstrap::digest(
            plan.intent_bytes().map_err(|_| Error::OwnershipMismatch)?,
        );
        let request = CleanupIntent {
            binding: permit.binding.clone(),
            authority: permit.authority,
            transition,
            started_at,
        };
        request.verify(self)?;
        let shared = &self.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        shared.queue.borrow_mut().push(self.exit_id())?;
        self.queued = Some(QueuedRequest {
            request: JournalOperation::Owner(OwnerMutation::LinksIntent(Box::new(request))),
            sent_at: started_at,
        });
        self.owner_stage = Some(AttemptStage::Quiescent);
        Ok(())
    }
    pub(super) fn poll_links_intent(
        &mut self,
        binding: &RetirementBinding,
        plan: &vprouter_network::HostRemovalPlan,
    ) -> Result<Option<CleanupPermit>> {
        if self.owner_stage != Some(AttemptStage::Quiescent)
            || binding.creator != self.creator
            || !std::rc::Rc::ptr_eq(&binding.shared, &self.transaction.shared)
            || binding.exit != self.exit_id()
            || binding.lifecycle != self.lifecycle()
        {
            return Err(Error::OwnershipMismatch);
        }
        if !self.poll_inner(None)? {
            return Ok(None);
        }
        binding.verify(self, AttemptStage::Quiescent)?;
        let transition = vprouter_worker::bootstrap::digest(
            plan.intent_bytes().map_err(|_| Error::OwnershipMismatch)?,
        );
        let journal = self
            .transaction
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.exit_id())
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if history.cleanup != CleanupStage::LinksIntent
            || history.host_transition.as_ref() != Some(&transition)
        {
            return Err(Error::OwnershipMismatch);
        }
        let authority = selected_authority(&journal.record, self.exit_id())?;
        drop(journal);
        self.owner_stage = None;
        Ok(Some(CleanupPermit {
            binding: binding.clone(),
            authority,
            transition,
            stage: CleanupStage::LinksIntent,
            started_at: None,
            consumed: false,
        }))
    }
    pub(super) fn start_cleanup_progress(
        &mut self,
        permit: &CleanupPermit,
        next: CleanupStage,
        receipt: Option<std::rc::Rc<kernel::cleanup::CleanupReceipt>>,
        started_at: f64,
    ) -> Result<()> {
        if !self.idle() || !self.native_drained() || !self.transaction.retirement_bookkeeping {
            return Err(Error::LockBusy);
        }
        let request = CleanupProgress {
            binding: permit.binding.clone(),
            authority: permit.authority,
            transition: permit.transition.clone(),
            previous: permit.stage,
            next,
            receipt,
            started_at,
        };
        request.verify(self)?;
        let shared = &self.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        shared.queue.borrow_mut().push(self.exit_id())?;
        self.queued = Some(QueuedRequest {
            request: JournalOperation::Owner(OwnerMutation::CleanupProgress(Box::new(request))),
            sent_at: started_at,
        });
        self.owner_stage = Some(AttemptStage::Quiescent);
        Ok(())
    }
    pub(super) fn poll_cleanup_progress(
        &mut self,
        permit: &CleanupPermit,
        next: CleanupStage,
    ) -> Result<Option<CleanupPermit>> {
        if self.owner_stage != Some(AttemptStage::Quiescent)
            || permit.binding.creator != self.creator
            || !std::rc::Rc::ptr_eq(&permit.binding.shared, &self.transaction.shared)
            || permit.binding.exit != self.exit_id()
            || permit.binding.lifecycle != self.lifecycle()
        {
            return Err(Error::OwnershipMismatch);
        }
        if !self.poll_inner(None)? {
            return Ok(None);
        }
        permit.binding.verify(self, AttemptStage::Quiescent)?;
        let journal = self
            .transaction
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.exit_id())
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if history.cleanup != next || history.host_transition.as_ref() != Some(&permit.transition) {
            return Err(Error::OwnershipMismatch);
        }
        let authority = selected_authority(&journal.record, self.exit_id())?;
        drop(journal);
        self.owner_stage = None;
        Ok(Some(CleanupPermit {
            binding: permit.binding.clone(),
            authority,
            transition: permit.transition.clone(),
            stage: next,
            started_at: None,
            consumed: false,
        }))
    }
    pub(super) fn start_final_retirement(
        &mut self,
        permit: &CleanupPermit,
        guard: &kernel::ManagedGuard,
        expiry: &super::expiry::OwnerExecutors,
        producer: std::rc::Rc<kernel::cleanup::CleanupReceipt>,
        started_at: f64,
    ) -> Result<()> {
        if !self.idle() || !self.native_drained() || !self.transaction.retirement_bookkeeping {
            return Err(Error::LockBusy);
        }
        if permit.stage != CleanupStage::ProducerRemoved {
            return Err(Error::OwnershipMismatch);
        }
        let request = FinalRetirement {
            binding: permit.binding.clone(),
            authority: permit.authority,
            transition: permit.transition.clone(),
            root: guard.removed_root_proof()?,
            reaps: expiry.retirement_reaps()?,
            producer,
            started_at,
        };
        request.verify(self)?;
        let shared = &self.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        shared.queue.borrow_mut().push(self.exit_id())?;
        self.queued = Some(QueuedRequest {
            request: JournalOperation::Owner(OwnerMutation::FinalRetirement(Box::new(request))),
            sent_at: started_at,
        });
        self.owner_stage = Some(AttemptStage::Retired);
        Ok(())
    }
    pub(super) fn poll_final_retirement(
        &mut self,
        permit: &CleanupPermit,
        producer: std::rc::Rc<kernel::cleanup::CleanupReceipt>,
        started_at: f64,
    ) -> Result<Option<RetiredPermit>> {
        if self.owner_stage != Some(AttemptStage::Retired)
            || permit.binding.creator != self.creator
            || !std::rc::Rc::ptr_eq(&permit.binding.shared, &self.transaction.shared)
            || permit.binding.exit != self.exit_id()
            || permit.binding.lifecycle != self.lifecycle()
        {
            return Err(Error::OwnershipMismatch);
        }
        if !self.poll_inner(None)? {
            return Ok(None);
        }
        permit.binding.verify(self, AttemptStage::Retired)?;
        producer.verify_unlinked(&permit.binding, &permit.transition)?;
        let authority = selected_authority(
            &self.transaction.shared.journal.borrow().record,
            self.exit_id(),
        )?;
        self.owner_stage = None;
        let retired = RetiredPermit {
            binding: permit.binding.clone(),
            authority,
            retired_at: started_at,
            transition: permit.transition.clone(),
            producer,
        };
        retired.verify(self)?;
        Ok(Some(retired))
    }
    pub(super) fn retire_service_bookkeeping(&mut self, permit: &QuiescentPermit) -> Result<()> {
        permit.verify(self)?;
        if !self.idle()
            || !self.native_drained()
            || !self.transaction.owner_service
            || !self
                .transaction
                .shared
                .services
                .borrow()
                .contains(self.exit_id())
        {
            return Err(Error::OwnershipMismatch);
        }
        if !self.transaction.retirement_bookkeeping {
            self.transaction
                .shared
                .leases
                .try_borrow_mut()
                .map_err(|_| Error::LockBusy)?
                .release(self.exit_id());
            self.transaction.retirement_bookkeeping = true;
        }
        // Keep the unique services reservation, canonical Rc and original native
        // allocation registration. Final writers still issue counted job leases.
        Ok(())
    }
    pub(super) fn start_quiescence(&mut self, request: QuiescenceRequest) -> Result<()> {
        if !self.idle() || !self.native_drained() {
            return Err(Error::LockBusy);
        }
        request.verify(self)?;
        let shared = &self.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        shared.queue.borrow_mut().push(self.exit_id())?;
        let sent_at = request.started_at;
        self.queued = Some(QueuedRequest {
            request: JournalOperation::Owner(OwnerMutation::Quiescent(Box::new(request))),
            sent_at,
        });
        self.owner_stage = Some(AttemptStage::Quiescent);
        Ok(())
    }
    pub(super) fn poll_quiescence(
        &mut self,
        binding: &RetirementBinding,
        started_at: f64,
    ) -> Result<Option<QuiescentPermit>> {
        if self.owner_stage != Some(AttemptStage::Quiescent)
            || binding.creator != self.creator
            || !std::rc::Rc::ptr_eq(&binding.shared, &self.transaction.shared)
            || binding.exit != self.exit_id()
            || binding.lifecycle != self.lifecycle()
        {
            return Err(Error::OwnershipMismatch);
        }
        if !self.poll_inner(None)? {
            return Ok(None);
        }
        binding.verify(self, AttemptStage::Quiescent)?;
        let journal = self
            .transaction
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        let history = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.exit_id())
            .and_then(|e| e.attempt.as_ref())
            .and_then(|a| a.retirement.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if history.quiescent_at != Some(started_at) {
            return Err(Error::OwnershipMismatch);
        }
        let authority = selected_authority(&journal.record, self.exit_id())?;
        drop(journal);
        self.owner_stage = None;
        Ok(Some(QuiescentPermit {
            binding: binding.clone(),
            authority,
            quiescent_at: started_at,
        }))
    }
    pub(super) fn start_attempt(&mut self, owner: &super::supervision::OwnerDomain) -> Result<()> {
        kernel::owner_admission_permitted()?;
        if !self.idle() || self.plan_issued {
            return Err(Error::Interrupted);
        }
        self.transaction.require_owner_memory(&self.spec)?;
        self.namespaces.bind(&self.spec)?;
        let owner = owner.record(&self.domains)?;
        let now = vprouter_core::health::boot_seconds();
        let shared = &self.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        let journal = shared.journal.borrow();
        if journal.record.owner_epoch.as_ref() != Some(&owner) {
            return Err(Error::OwnershipMismatch);
        }
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.exit_id())
            .ok_or(Error::OwnershipMismatch)?;
        if entry.attempt.is_some() || entry.terminal.is_some() || entry.phase != Phase::Bootstrap {
            return Err(Error::Interrupted);
        }
        let plan = AttemptPlan {
            creator: self.creator,
            value: AttemptOwnership {
                exit_id: self.exit_id().into(),
                lifecycle: self.domains.lifecycle().into(),
                allocation: self.domains.allocation().into(),
                launch: vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(&self.spec).map_err(|_| Error::OwnershipMismatch)?,
                ),
                resources: attempt_resources(entry)?,
                owner,
                scopes: attempt_scopes(&self.domains),
                planned_at: now,
                stage: AttemptStage::Planned,
                birth: None,
                guard_group: None,
                retirement: None,
            },
        };
        plan.value.validate(&journal.record, entry)?;
        shared.queue.borrow_mut().push(self.exit_id())?;
        self.queued = Some(QueuedRequest {
            request: JournalOperation::Owner(OwnerMutation::Plan(Box::new(plan))),
            sent_at: now,
        });
        self.owner_stage = Some(AttemptStage::Planned);
        Ok(())
    }
    pub(super) fn poll_attempt(&mut self) -> Result<Option<PlannedAttempt>> {
        if let Err(error) = kernel::owner_admission_permitted() {
            self.fence()?;
            return Err(error);
        }
        if self.owner_stage != Some(AttemptStage::Planned) || self.plan_issued {
            return Err(Error::OwnershipMismatch);
        }
        if !self.poll_inner(None)? {
            return Ok(None);
        }
        let journal = self.transaction.shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.exit_id())
            .ok_or(Error::OwnershipMismatch)?;
        let value = entry.attempt.as_ref().ok_or(Error::OwnershipMismatch)?;
        if value.stage != AttemptStage::Planned || value.lifecycle != self.domains.lifecycle() {
            return Err(Error::OwnershipMismatch);
        }
        let value = value.clone();
        drop(journal);
        let lease = self.transaction.retain_service_lease(&self.spec)?;
        self.owner_stage = None;
        self.plan_issued = true;
        Ok(Some(PlannedAttempt {
            creator: self.creator,
            value,
            lease,
        }))
    }
    fn start_owner_stage(&mut self, stage: AttemptStage, operation: OwnerMutation) -> Result<()> {
        if !self.idle() || !self.plan_issued || self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let shared = &self.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        shared.queue.borrow_mut().push(self.exit_id())?;
        self.queued = Some(QueuedRequest {
            request: JournalOperation::Owner(operation),
            sent_at: vprouter_core::health::boot_seconds(),
        });
        self.owner_stage = Some(stage);
        Ok(())
    }
    pub(super) fn start_birth(&mut self, guard: &kernel::PendingGuard) -> Result<()> {
        self.bind_pending(guard)?;
        #[cfg(test)]
        if std::mem::take(&mut self.refuse_next_birth) {
            return Err(Error::Interrupted);
        }
        self.start_owner_stage(AttemptStage::Born, OwnerMutation::Birth(guard.birth()?))
    }
    pub(super) fn poll_birth(
        &mut self,
        guard: &kernel::PendingGuard,
    ) -> Result<Option<BornAttempt>> {
        if !self.poll_owner_stage(AttemptStage::Born, guard)? {
            return Ok(None);
        }
        Ok(Some(BornAttempt {
            creator: self.creator,
            lifecycle: self.domains.lifecycle().into(),
            allocation: self.domains.allocation().into(),
            exit_id: self.exit_id().into(),
            birth: guard.birth()?,
        }))
    }
    pub(super) fn start_placed(&mut self, guard: &kernel::PendingGuard) -> Result<()> {
        self.bind_pending(guard)?;
        self.start_owner_stage(
            AttemptStage::Placed,
            OwnerMutation::Place(guard.birth()?, guard.group_identity()?),
        )
    }
    pub(super) fn poll_placed(&mut self, guard: &kernel::PendingGuard) -> Result<bool> {
        self.poll_owner_stage(AttemptStage::Placed, guard)
    }
    pub(super) fn start_release(&mut self, guard: &kernel::PendingGuard) -> Result<()> {
        self.bind_pending(guard)?;
        self.start_owner_stage(
            AttemptStage::Released,
            OwnerMutation::Release(guard.birth()?, guard.group_identity()?),
        )
    }
    pub(super) fn poll_release(
        &mut self,
        guard: &kernel::PendingGuard,
    ) -> Result<Option<ReleaseAttempt>> {
        if !self.poll_owner_stage(AttemptStage::Released, guard)? {
            return Ok(None);
        }
        Ok(Some(ReleaseAttempt {
            born: BornAttempt {
                creator: self.creator,
                lifecycle: self.domains.lifecycle().into(),
                allocation: self.domains.allocation().into(),
                exit_id: self.exit_id().into(),
                birth: guard.birth()?,
            },
            group: guard.group_identity()?,
        }))
    }
    fn bind_pending(&self, guard: &kernel::PendingGuard) -> Result<()> {
        let domains = guard.domains()?;
        if domains.lifecycle() != self.domains.lifecycle()
            || domains.allocation() != self.domains.allocation()
            || domains.exit_id() != self.domains.exit_id()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    fn poll_owner_stage(
        &mut self,
        stage: AttemptStage,
        guard: &kernel::PendingGuard,
    ) -> Result<bool> {
        self.bind_pending(guard)?;
        if self.owner_stage != Some(stage) {
            return Err(Error::OwnershipMismatch);
        }
        if !self.poll_inner(None)? {
            return Ok(false);
        }
        let journal = self.transaction.shared.journal.borrow();
        let attempt = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.exit_id())
            .and_then(|entry| entry.attempt.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if attempt.stage != stage
            || attempt.birth.as_ref() != Some(&guard.birth()?)
            || (matches!(stage, AttemptStage::Placed | AttemptStage::Released)
                && attempt.guard_group != Some(guard.group_identity()?))
        {
            return Err(Error::OwnershipMismatch);
        }
        self.owner_stage = None;
        Ok(true)
    }
    pub fn host_allocation(&self) -> vprouter_core::allocation::AllocationRecord {
        self.spec.allocation.clone()
    }
    pub fn host_directory(&self) -> Result<OwnedFd> {
        let journal = self
            .transaction
            .shared
            .journal
            .try_borrow()
            .map_err(|_| Error::LockBusy)?;
        if journal.owner_pid != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        rustix::io::fcntl_dupfd_cloexec(&journal.dir, 3).map_err(|_| Error::DescriptorDuplicate)
    }
    pub fn exit_id(&self) -> &str {
        &self.spec.exit.exit_id
    }
    pub fn allocation(&self) -> &str {
        self.domains.allocation()
    }
    pub fn lifecycle(&self) -> &str {
        self.domains.lifecycle()
    }
    pub fn authorize_spawn(&self) -> Result<()> {
        self.transaction.bound(&self.spec)?;
        if self.transaction.shared.fenced.get()
            || self.transaction.shared.pending.borrow().is_some()
            || !self.idle()
        {
            return Err(Error::Interrupted);
        }
        let journal = self.transaction.shared.journal.borrow();
        let terminal = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.spec.exit.exit_id)
            .and_then(|e| e.terminal.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if terminal.lifecycle != self.domains.lifecycle() || !terminal.completions.is_empty() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub fn idle(&self) -> bool {
        self.pending.is_none()
            && self.queued.is_none()
            && !self.completing
            && !self.registering
            && self.owner_stage.is_none()
    }
    pub fn completing(&self) -> bool {
        self.completing
    }
    pub fn registering(&self) -> bool {
        self.registering
    }
    pub fn start_registration(
        &mut self,
        receipt: super::expiry::FixedRegistration,
        sent_at: f64,
    ) -> Result<()> {
        if !self.idle() {
            return Err(Error::Interrupted);
        }
        self.transaction.bound(&self.spec)?;
        original_frame(sent_at, vprouter_core::health::boot_seconds())?;
        let identity = receipt.into_bound(
            self.domains.allocation(),
            self.domains.exit_id(),
            self.domains.lifecycle(),
        )?;
        let shared = &self.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        shared.queue.borrow_mut().push(self.exit_id())?;
        self.queued = Some(QueuedRequest {
            request: JournalRequest::RegisterExecutor {
                lifecycle: self.domains.lifecycle().into(),
                identity,
            }
            .into(),
            sent_at,
        });
        self.registering = true;
        Ok(())
    }
    pub fn poll_registration(&mut self, guard: &kernel::Survivor) -> Result<bool> {
        if !self.registering {
            return Err(Error::OwnershipMismatch);
        }
        let done = self.poll(guard)?;
        if done {
            self.registering = false;
        }
        Ok(done)
    }
    pub fn start_completion(&mut self, receipt: &super::expiry::FixedCompletion) -> Result<()> {
        if self.transaction.retirement_bookkeeping {
            return Err(Error::OwnershipMismatch);
        }
        if !self.idle() {
            return Err(Error::Interrupted);
        }
        self.transaction.bound(&self.spec)?;
        let completion = receipt.bound_completion(
            self.domains.allocation(),
            self.domains.exit_id(),
            self.domains.lifecycle(),
        )?;
        original_frame(
            completion.finished_at,
            vprouter_core::health::boot_seconds(),
        )?;
        let shared = &self.transaction.shared;
        mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
        shared.queue.borrow_mut().push(self.exit_id())?;
        let sent_at = completion.finished_at;
        self.queued = Some(QueuedRequest {
            request: JournalRequest::CompleteExecutor {
                lifecycle: self.domains.lifecycle().into(),
                completion,
            }
            .into(),
            sent_at,
        });
        self.completing = true;
        Ok(())
    }
    pub fn poll_completion(&mut self) -> Result<bool> {
        if !self.completing {
            return Err(Error::OwnershipMismatch);
        }
        let done = self.poll_inner(None)?;
        if done {
            self.completing = false;
        }
        Ok(done)
    }
    pub fn start(
        &mut self,
        request: JournalRequest,
        guard: &kernel::Survivor,
        sent_at: f64,
    ) -> Result<()> {
        original_frame(sent_at, vprouter_core::health::boot_seconds())?;
        if self.transaction.retirement_bookkeeping {
            return Err(Error::OwnershipMismatch);
        }
        if self.pending.is_some() || self.queued.is_some() || self.completing {
            return Err(Error::Deadline);
        }
        if matches!(
            request,
            JournalRequest::CompleteExecutor { .. } | JournalRequest::RegisterExecutor { .. }
        ) {
            return Err(Error::OwnershipMismatch);
        }
        let mutation = matches!(
            request,
            JournalRequest::BeginTerminal { .. }
                | JournalRequest::RegisterExecutor { .. }
                | JournalRequest::AcknowledgeExecutor { .. }
                | JournalRequest::CompleteExecutor { .. }
        );
        self.transaction.bound(&self.spec)?;
        guard.require_live()?;
        if mutation {
            let shared = &self.transaction.shared;
            mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?;
            shared.queue.borrow_mut().push(self.exit_id())?;
            self.queued = Some(QueuedRequest {
                request: request.into(),
                sent_at,
            });
            return Ok(());
        }
        self.launch(request.into(), Some(guard), sent_at, false)
    }
    fn launch(
        &mut self,
        request: JournalOperation,
        guard: Option<&kernel::Survivor>,
        sent_at: f64,
        mutation: bool,
    ) -> Result<()> {
        let shared = &self.transaction.shared;
        let before = shared.journal.borrow().record.clone();
        shared.journal.borrow().staging.set(true);
        let result = self.apply(request, guard);
        let proposed = shared.journal.borrow().record.clone();
        shared.journal.borrow_mut().record = before.clone();
        shared.journal.borrow().staging.set(false);
        result?;
        if mutation {
            if !shared.reads.borrow().can_publish(&proposed)? {
                return Err(Error::LockBusy);
            }
        } else {
            shared.reads.borrow_mut().reserve(
                &before,
                shared.pending.borrow().as_ref(),
                self.exit_id(),
            )?;
        }
        let job = JournalIo {
            allocation: before.allocation.clone(),
            before: encode_record(&before)?,
            after: mutation.then(|| encode_record(&proposed)).transpose()?,
            deadline: sent_at + 2.,
            #[cfg(test)]
            pause_before_sync: mutation && std::mem::take(&mut self.pause_next_write),
            #[cfg(test)]
            pause_before_read: !mutation && std::mem::take(&mut self.pause_next_read),
            #[cfg(test)]
            lab_stage: std::cell::Cell::new(0),
        };
        let journal = shared.journal.borrow();
        let directory = rustix::io::fcntl_dupfd_cloexec(&journal.dir, 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let lease = self.transaction.retain_service_lease(&self.spec)?;
        #[cfg(test)]
        eprintln!("LAB_JOURNAL_STAGE stage=spawn_io mutation={mutation}");
        original_frame(sent_at, vprouter_core::health::boot_seconds())?;
        let child = kernel::spawn_journal_io(directory, lease, &job)?;
        #[cfg(test)]
        eprintln!("LAB_JOURNAL_STAGE stage=io_spawned");
        drop(journal);
        if mutation {
            shared.reads.borrow_mut().publish(&proposed)?;
            *shared.pending.borrow_mut() = Some(proposed);
        }
        self.pending = Some(JournalJob {
            child,
            mutation,
            deadline: sent_at + 2.,
            failed: false,
        });
        if let Err(error) = self
            .pending
            .as_mut()
            .ok_or(Error::Interrupted)?
            .child
            .start()
        {
            self.fence()?;
            return Err(error);
        }
        Ok(())
    }
    fn apply(&self, request: JournalOperation, guard: Option<&kernel::Survivor>) -> Result<()> {
        let request = match request {
            JournalOperation::Guard(request) => request,
            JournalOperation::Owner(OwnerMutation::Plan(plan)) => {
                if guard.is_some()
                    || self.owner_stage != Some(AttemptStage::Planned)
                    || plan.creator != self.creator
                {
                    return Err(Error::OwnershipMismatch);
                }
                let mut journal = self
                    .transaction
                    .shared
                    .journal
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?;
                journal.record.plan_attempt(self.exit_id(), plan.value)?;
                return journal.persist();
            }
            JournalOperation::Owner(OwnerMutation::LinksIntent(request)) => {
                if guard.is_some() || self.owner_stage != Some(AttemptStage::Quiescent) {
                    return Err(Error::OwnershipMismatch);
                }
                request.verify(self)?;
                let mut journal = self
                    .transaction
                    .shared
                    .journal
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?;
                let history = journal
                    .record
                    .entries
                    .iter_mut()
                    .find(|e| e.exit_id == self.exit_id())
                    .and_then(|e| e.attempt.as_mut())
                    .and_then(|a| a.retirement.as_mut())
                    .ok_or(Error::OwnershipMismatch)?;
                history.cleanup = CleanupStage::LinksIntent;
                history.host_transition = Some(request.transition);
                journal.record.bind(
                    &self.spec,
                    &journal.record.primary_exit_id,
                    journal.record.primary_network()?,
                )?;
                return journal.persist();
            }
            JournalOperation::Owner(OwnerMutation::CleanupProgress(request)) => {
                if guard.is_some() || self.owner_stage != Some(AttemptStage::Quiescent) {
                    return Err(Error::OwnershipMismatch);
                }
                request.verify(self)?;
                let mut journal = self
                    .transaction
                    .shared
                    .journal
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?;
                let entry = journal
                    .record
                    .entries
                    .iter_mut()
                    .find(|e| e.exit_id == self.exit_id())
                    .ok_or(Error::OwnershipMismatch)?;
                entry
                    .attempt
                    .as_mut()
                    .and_then(|a| a.retirement.as_mut())
                    .ok_or(Error::OwnershipMismatch)?
                    .cleanup = request.next;
                if request.next == CleanupStage::ProducerRemoved {
                    entry.phase = Phase::Offline;
                    entry.links = None;
                    entry.producer = None;
                }
                journal.record.bind(
                    &self.spec,
                    &journal.record.primary_exit_id,
                    journal.record.primary_network()?,
                )?;
                return journal.persist();
            }
            JournalOperation::Owner(OwnerMutation::FinalRetirement(request)) => {
                if guard.is_some() || self.owner_stage != Some(AttemptStage::Retired) {
                    return Err(Error::OwnershipMismatch);
                }
                request.verify(self)?;
                let mut journal = self
                    .transaction
                    .shared
                    .journal
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?;
                let attempt = journal
                    .record
                    .entries
                    .iter_mut()
                    .find(|e| e.exit_id == self.exit_id())
                    .and_then(|e| e.attempt.as_mut())
                    .ok_or(Error::OwnershipMismatch)?;
                attempt.stage = AttemptStage::Retired;
                attempt
                    .retirement
                    .as_mut()
                    .ok_or(Error::OwnershipMismatch)?
                    .retired_at = Some(request.started_at);
                journal.record.bind(
                    &self.spec,
                    &journal.record.primary_exit_id,
                    journal.record.primary_network()?,
                )?;
                return journal.persist();
            }
            JournalOperation::Owner(OwnerMutation::Quiescent(request)) => {
                if guard.is_some() || self.owner_stage != Some(AttemptStage::Quiescent) {
                    return Err(Error::OwnershipMismatch);
                }
                request.verify(self)?;
                let mut journal = self
                    .transaction
                    .shared
                    .journal
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?;
                let attempt = journal
                    .record
                    .entries
                    .iter_mut()
                    .find(|e| e.exit_id == self.exit_id())
                    .and_then(|e| e.attempt.as_mut())
                    .ok_or(Error::OwnershipMismatch)?;
                attempt.stage = AttemptStage::Quiescent;
                attempt
                    .retirement
                    .as_mut()
                    .ok_or(Error::OwnershipMismatch)?
                    .quiescent_at = Some(request.started_at);
                journal.record.bind(
                    &self.spec,
                    &journal.record.primary_exit_id,
                    journal.record.primary_network()?,
                )?;
                return journal.persist();
            }
            JournalOperation::Owner(OwnerMutation::Retire(request)) => {
                if guard.is_some() || self.owner_stage != Some(AttemptStage::Retiring) {
                    return Err(Error::OwnershipMismatch);
                }
                request.verify(self)?;
                let mut journal = self
                    .transaction
                    .shared
                    .journal
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?;
                let entry = journal
                    .record
                    .entries
                    .iter_mut()
                    .find(|e| e.exit_id == self.exit_id())
                    .ok_or(Error::OwnershipMismatch)?;
                let terminal_digest = vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(entry.terminal.as_ref().ok_or(Error::OwnershipMismatch)?)
                        .map_err(|_| Error::OwnershipMismatch)?,
                );
                let history = RetirementHistory {
                    original: request.binding.resources.clone(),
                    terminal_digest,
                    started_at: request.started_at,
                    quiescent_at: None,
                    host_transition: None,
                    cleanup: CleanupStage::NotStarted,
                    retired_at: None,
                };
                let attempt = entry.attempt.as_mut().ok_or(Error::OwnershipMismatch)?;
                attempt.stage = AttemptStage::Retiring;
                attempt.retirement = Some(history);
                journal.record.bind(
                    &self.spec,
                    &journal.record.primary_exit_id,
                    journal.record.primary_network()?,
                )?;
                return journal.persist();
            }
            JournalOperation::Owner(operation) => {
                if guard.is_some() {
                    return Err(Error::OwnershipMismatch);
                }
                let (expected, next, birth, group) = match operation {
                    OwnerMutation::Birth(birth) => {
                        (AttemptStage::Planned, AttemptStage::Born, birth, None)
                    }
                    OwnerMutation::Place(birth, group) => {
                        (AttemptStage::Born, AttemptStage::Placed, birth, Some(group))
                    }
                    OwnerMutation::Release(birth, group) => (
                        AttemptStage::Placed,
                        AttemptStage::Released,
                        birth,
                        Some(group),
                    ),
                    OwnerMutation::Plan(_)
                    | OwnerMutation::Retire(_)
                    | OwnerMutation::Quiescent(_)
                    | OwnerMutation::LinksIntent(_)
                    | OwnerMutation::CleanupProgress(_)
                    | OwnerMutation::FinalRetirement(_) => {
                        return Err(Error::OwnershipMismatch);
                    }
                };
                if self.owner_stage != Some(next) {
                    return Err(Error::OwnershipMismatch);
                }
                birth.validate()?;
                let mut journal = self
                    .transaction
                    .shared
                    .journal
                    .try_borrow_mut()
                    .map_err(|_| Error::LockBusy)?;
                let entry = journal
                    .record
                    .entries
                    .iter_mut()
                    .find(|e| e.exit_id == self.exit_id())
                    .ok_or(Error::OwnershipMismatch)?;
                let attempt = entry.attempt.as_mut().ok_or(Error::OwnershipMismatch)?;
                if attempt.stage != expected
                    || attempt.lifecycle != self.domains.lifecycle()
                    || attempt.birth.as_ref().is_some_and(|old| old != &birth)
                    || (expected == AttemptStage::Placed && attempt.guard_group != group)
                    || vprouter_core::health::boot_seconds() >= birth.gate_deadline
                {
                    return Err(Error::OwnershipMismatch);
                }
                attempt.birth = Some(birth);
                attempt.guard_group = group;
                attempt.stage = next;
                journal.persist()?;
                return Ok(());
            }
        };
        let tx = &self.transaction;
        let s = &self.spec;
        let lifecycle = |value: &str| {
            if value == self.domains.lifecycle() {
                Ok(())
            } else {
                Err(Error::OwnershipMismatch)
            }
        };
        match request {
            JournalRequest::Revalidate => tx.revalidate(s),
            JournalRequest::VerifyProducer { parent, group } => {
                tx.verify_producer(s, parent, group)
            }
            JournalRequest::VerifyLinks {
                host,
                indices,
                data,
                transport,
            } => {
                if data != Identity::network(&self.namespaces.data)?
                    || transport != Identity::network(&self.namespaces.transport)?
                {
                    return Err(Error::NamespaceMismatch);
                }
                tx.verify_links(s, &self.namespaces, host, indices)
            }
            JournalRequest::BeginTerminal {
                binding,
                lifecycle: value,
            } => {
                lifecycle(&value)?;
                if serde_json::to_vec(&binding).map_err(|_| Error::InvalidSpec)?
                    != serde_json::to_vec(&self.binding).map_err(|_| Error::InvalidSpec)?
                {
                    return Err(Error::OwnershipMismatch);
                }
                tx.begin_terminal_for(s, binding, &value, {
                    let guard = guard.ok_or(Error::OwnershipMismatch)?;
                    (guard.pid(), guard.start_time()?)
                })
            }
            JournalRequest::RegisterExecutor {
                lifecycle: value,
                identity,
            } => {
                lifecycle(&value)?;
                if !self.registering {
                    return Err(Error::OwnershipMismatch);
                }
                // Registration is independently tied to the actual sibling
                // cgroup and network namespace, never a caller PID assertion.
                super::supervision::verify_executor(&self.domains, &identity)?;
                tx.register_executor(s, &value, identity)
            }
            JournalRequest::AcknowledgeExecutor {
                lifecycle: value,
                identity,
            } => {
                lifecycle(&value)?;
                super::supervision::verify_executor(&self.domains, &identity)?;
                tx.acknowledge_executor(s, &value, &identity)
            }
            JournalRequest::VerifyExecutors {
                lifecycle: value,
                children,
            } => {
                lifecycle(&value)?;
                for identity in &children {
                    super::supervision::verify_executor(&self.domains, identity)?;
                }
                tx.verify_executors(s, &value, &children)
            }
            JournalRequest::CompleteExecutor {
                lifecycle: value,
                completion,
            } => {
                lifecycle(&value)?;
                if guard.is_some() || !self.completing {
                    return Err(Error::OwnershipMismatch);
                }
                tx.complete_executor(s, &value, completion)
            }
            JournalRequest::RequireNoExecutors => tx.require_no_executors(s),
        }
    }
    pub fn poll(&mut self, guard: &kernel::Survivor) -> Result<bool> {
        guard.require_live()?;
        if self.completing {
            return Err(Error::OwnershipMismatch);
        }
        self.poll_inner(Some(guard))
    }
    fn poll_inner(&mut self, guard: Option<&kernel::Survivor>) -> Result<bool> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let result = self.poll_inner_active(guard);
        if result.is_err() {
            // Only this failed operation is cancelled. Unstarted queue entries
            // are removed so siblings can progress; launched mutations set the
            // permanent uncertainty fence BEFORE any fallible cancellation.
            // The original error wins, and every native field stays retained.
            let _ = self.fence();
        }
        result
    }
    fn poll_inner_active(&mut self, guard: Option<&kernel::Survivor>) -> Result<bool> {
        #[cfg(test)]
        if std::mem::take(&mut self.retirement_poll_error) {
            return Err(Error::ChildFailed);
        }
        if let Some(queued) = &self.queued {
            original_frame(queued.sent_at, vprouter_core::health::boot_seconds())?;
            let shared = &self.transaction.shared;
            if !mutation_slot_available(shared.pending.borrow().is_some(), shared.fenced.get())?
                || !shared.queue.borrow().first(self.exit_id())
            {
                return Ok(false);
            }
            // A bounded generation window can delay a writer, never reset its
            // original deadline. Reads continue independently while it waits.
            // Conservatively reserve one digest slot in every active window.
            if shared
                .reads
                .borrow()
                .0
                .values()
                .any(|r| r.generations.len() >= MAX_READ_GENERATIONS)
            {
                return Ok(false);
            }
            let queued = self.queued.take().ok_or(Error::Interrupted)?;
            shared.queue.borrow_mut().remove(self.exit_id());
            self.launch(queued.request, guard, queued.sent_at, true)?;
        }
        let Some(job) = &mut self.pending else {
            return Err(Error::Interrupted);
        };
        if job.failed || vprouter_core::health::boot_seconds() >= job.deadline {
            job.failed = true;
            if job.mutation {
                self.transaction.shared.fenced.set(true);
            }
            job.child.cancel()?;
            // Keep the exact child handle, pending record and allocation lease
            // until drain observes actual death, even for an uninterruptible IO.
            return Err(Error::Deadline);
        }
        match job.child.poll()? {
            None => Ok(false),
            Some(true) => {
                if vprouter_core::health::boot_seconds() >= job.deadline {
                    job.failed = true;
                    if job.mutation {
                        self.transaction.shared.fenced.set(true);
                    }
                    return Err(Error::Deadline);
                }
                if !job.mutation {
                    let shared = &self.transaction.shared;
                    shared.reads.borrow().verify(
                        &self.spec.exit.exit_id,
                        job.child.observed()?,
                        &shared.journal.borrow().record,
                        shared.pending.borrow().as_ref(),
                    )?;
                    shared.reads.borrow_mut().remove(&self.spec.exit.exit_id);
                }
                if job.mutation {
                    let committed = self
                        .transaction
                        .shared
                        .pending
                        .borrow_mut()
                        .take()
                        .ok_or(Error::Interrupted)?;
                    if job.child.observed()? != record_digest(&encode_record(&committed)?) {
                        self.transaction.shared.fenced.set(true);
                        *self.transaction.shared.pending.borrow_mut() = Some(committed);
                        return Err(Error::OwnershipMismatch);
                    }
                    self.transaction.shared.journal.borrow_mut().record = committed;
                }
                #[cfg(test)]
                if job.mutation {
                    self.mutation_completion =
                        Some((job.deadline, vprouter_core::health::boot_seconds()));
                }
                self.pending = None;
                #[cfg(test)]
                {
                    self.completed += 1;
                }
                Ok(true)
            }
            Some(false) => {
                job.failed = true;
                if job.mutation {
                    self.transaction.shared.fenced.set(true);
                }
                Err(Error::Interrupted)
            }
        }
    }
    pub(super) fn native_drained(&self) -> bool {
        self.queued.is_none()
            && self.pending.as_ref().is_none_or(|job| job.child.drained())
            && self
                .transaction
                .shared
                .native_jobs
                .try_borrow_mut()
                .is_ok_and(|mut jobs| jobs.drained(self.exit_id()) == Ok(true))
    }
    pub(super) fn host_job_lease(
        &self,
        allocation: &str,
        exit: &str,
        lifecycle: &str,
    ) -> Result<MutatorLease> {
        if self.creator != std::process::id()
            || self.transaction.retirement_bookkeeping
            || self.allocation() != allocation
            || self.exit_id() != exit
            || self.lifecycle() != lifecycle
        {
            return Err(Error::OwnershipMismatch);
        }
        self.transaction.retain_service_lease(&self.spec)
    }
    /// Collect failed IO independently of healthy original-deadline completion
    /// writes. Only a read's actual reap releases its abandoned read bookkeeping;
    /// uncertain mutations and their canonical pending/fence remain retained.
    pub(super) fn poll_terminal_io(&mut self) -> Result<TerminalIo> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let Some(job) = self.pending.as_mut() else {
            return Ok(if self.queued.is_none() {
                TerminalIo::Drained
            } else {
                TerminalIo::Busy
            });
        };
        if !job.failed {
            return Ok(TerminalIo::Busy);
        }
        if !job.child.drained() {
            job.child.poll()?;
        }
        if !job.child.drained() {
            return Ok(TerminalIo::Busy);
        }
        if job.mutation {
            return Ok(TerminalIo::Drained);
        }
        let deadline = job.deadline;
        self.transaction
            .shared
            .reads
            .borrow_mut()
            .remove(self.exit_id());
        self.retired_read_deadline = Some(deadline);
        self.pending = None;
        Ok(TerminalIo::ReadReaped { deadline })
    }
    pub fn drain(&mut self) -> Result<bool> {
        let Some(job) = &mut self.pending else {
            return Ok(true);
        };
        if !job.failed {
            return Err(Error::Interrupted);
        }
        if job.child.drained() {
            return Ok(true);
        }
        Ok(job.child.poll()?.is_some())
    }
    pub fn fence(&mut self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        self.queued = None;
        self.transaction
            .shared
            .queue
            .borrow_mut()
            .remove(self.exit_id());
        self.transaction
            .shared
            .reads
            .borrow_mut()
            .remove(self.exit_id());
        if let Some(job) = &mut self.pending {
            job.failed = true;
            if job.mutation {
                self.transaction.shared.fenced.set(true);
            }
            job.child.cancel()?;
        }
        Ok(())
    }
}
#[cfg(test)]
impl JournalServer {
    pub(super) fn lab_refuse_next_birth(&mut self) -> Result<()> {
        if !self.idle() || !self.plan_issued || self.refuse_next_birth {
            return Err(Error::OwnershipMismatch);
        }
        self.refuse_next_birth = true;
        Ok(())
    }
    pub(super) fn lab_hold_next_read(&mut self) -> Result<()> {
        if !self.idle() || self.pause_next_read {
            return Err(Error::Interrupted);
        }
        self.pause_next_read = true;
        Ok(())
    }
    pub(super) fn lab_stopped_read(&self) -> Result<(u32, u64, f64)> {
        let job = self.pending.as_ref().ok_or(Error::Interrupted)?;
        if job.mutation || job.failed {
            return Err(Error::OwnershipMismatch);
        }
        let (pid, start) = job.child.lab_require_stopped()?;
        Ok((pid, start, job.deadline))
    }
    pub(super) fn lab_retired_read(&self) -> Option<f64> {
        self.retired_read_deadline
    }
    pub(super) fn lab_attempt_released(&self) -> Result<(u32, u64, f64, f64)> {
        let journal = self.transaction.shared.journal.borrow();
        let attempt = journal
            .record
            .entries
            .iter()
            .find(|entry| entry.exit_id == self.exit_id())
            .and_then(|entry| entry.attempt.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if attempt.stage != AttemptStage::Released
            || journal.record.owner_epoch.as_ref() != Some(&attempt.owner)
        {
            return Err(Error::OwnershipMismatch);
        }
        let birth = attempt.birth.as_ref().ok_or(Error::OwnershipMismatch)?;
        Ok((birth.pid, birth.start, birth.born_at, birth.gate_deadline))
    }
    pub(super) fn lab_refuse_prequeue_cleanup(
        &mut self,
        permit: &CleanupPermit,
        receipt: std::rc::Rc<kernel::cleanup::CleanupReceipt>,
        started_at: f64,
    ) -> Result<()> {
        if !self.idle() || !self.native_drained() {
            return Err(Error::OwnershipMismatch);
        }
        let ticket = self
            .transaction
            .shared
            .native_jobs
            .borrow_mut()
            .issue(self.exit_id(), kernel::NativeJobKind::Journal)?;
        let result = self.start_cleanup_progress(
            permit,
            CleanupStage::LinksRemoved,
            Some(receipt),
            started_at,
        );
        if result != Err(Error::LockBusy) || !self.idle() || self.native_drained() {
            return Err(Error::OwnershipMismatch);
        }
        drop(ticket); // Exact NoBirth receipt; no native task or fake reap is claimed.
        if !self.native_drained() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn lab_original_writer(&self) -> Result<(kernel::Survivor, (u32, u64, f64))> {
        let job = self.pending.as_ref().ok_or(Error::OwnershipMismatch)?;
        if !job.mutation || job.failed || job.child.drained() {
            return Err(Error::OwnershipMismatch);
        }
        let witness = job.child.lab_native_reap_handle()?;
        let start = witness.start_time()?;
        let (pid, stored_start) = witness.lab_birth_identity()?;
        if stored_start != start {
            return Err(Error::ProcessChanged);
        }
        Ok((witness, (pid, start, job.deadline)))
    }
    pub(super) fn lab_hold_retirement_write(&mut self) {
        self.pause_next_write = true;
    }
    pub(super) fn lab_fail_retirement_poll(&mut self) {
        self.retirement_poll_error = true;
    }
    pub(super) fn lab_retirement_failure(&self) -> Result<serde_json::Value> {
        if self.creator != std::process::id()
            || self.queued.is_some()
            || self
                .transaction
                .shared
                .queue
                .borrow()
                .0
                .iter()
                .any(|exit| exit == self.exit_id())
        {
            return Err(Error::OwnershipMismatch);
        }
        let status = if let Some(job) = &self.pending {
            if !job.failed || !job.child.drained() {
                return Err(Error::Interrupted);
            }
            job.child.lab_native_reap_handle()?.lab_terminal_status()?
        } else {
            None
        };
        Ok(
            serde_json::json!({"queue_removed":true,"native_actual_drained":self.native_drained(),"writer_actual_wait_status":status,
            "uncertain_mutation_fence":self.transaction.shared.fenced.get(),"canonical_pending_retained":self.transaction.shared.pending.borrow().is_some(),
            "service_reserved":self.transaction.shared.services.borrow().contains(self.exit_id())}),
        )
    }
    pub(super) fn lab_unconsumed_stop_record(&self, permit: &RetiringPermit) -> Result<Vec<u8>> {
        if self.creator != std::process::id()
            || permit.binding.creator != self.creator
            || !std::rc::Rc::ptr_eq(&permit.binding.shared, &self.transaction.shared)
            || permit.binding.exit != self.exit_id()
            || permit.binding.lifecycle != self.lifecycle()
            || permit.stop_consumed
            || permit.stop_started.is_some()
            || !self.idle()
            || !self.native_drained()
            || !self
                .transaction
                .shared
                .services
                .borrow()
                .contains(self.exit_id())
        {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self.transaction.shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|entry| entry.exit_id == self.exit_id())
            .ok_or(Error::OwnershipMismatch)?;
        if entry.attempt.as_ref().is_none_or(|attempt| {
            attempt.stage != AttemptStage::Retiring
                || attempt
                    .retirement
                    .as_ref()
                    .is_none_or(|history| history.cleanup != CleanupStage::NotStarted)
        }) || entry
            .terminal
            .as_ref()
            .is_none_or(|terminal| terminal.completions.len() != 3)
        {
            return Err(Error::OwnershipMismatch);
        }
        serde_json::to_vec(entry).map_err(|_| Error::OwnershipMismatch)
    }
    pub(super) fn lab_retirement_record(&self) -> Result<serde_json::Value> {
        if self.transaction.shared.journal.borrow().owner_pid != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if !self.idle() || !self.native_drained() {
            return Err(Error::OwnershipMismatch);
        }
        let journal = self.transaction.shared.journal.borrow();
        let entry = journal
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.exit_id())
            .ok_or(Error::OwnershipMismatch)?;
        if entry
            .attempt
            .as_ref()
            .is_none_or(|a| a.stage != AttemptStage::Retired)
            || entry
                .terminal
                .as_ref()
                .is_none_or(|t| t.completions.len() != 3)
            || entry.links.is_some()
            || entry.producer.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        serde_json::to_value(entry).map_err(|_| Error::InvalidSpec)
    }
    pub(super) fn lab_expiry_registered(&self) -> Result<Vec<ExecutorIdentity>> {
        let journal = self.transaction.shared.journal.borrow();
        let terminal = journal
            .record
            .entries
            .iter()
            .find(|entry| entry.exit_id == self.exit_id())
            .and_then(|entry| entry.terminal.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if terminal.lifecycle != self.lifecycle()
            || terminal.executors.len() != 3
            || terminal.acknowledged != [0, 1, 2]
        {
            return Err(Error::Interrupted);
        }
        Ok(terminal.executors.clone())
    }
    pub fn lab_terminal_completions(&self) -> usize {
        self.transaction
            .shared
            .journal
            .borrow()
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == self.spec.exit.exit_id)
            .and_then(|e| e.terminal.as_ref())
            .map_or(0, |t| t.completions.len())
    }
    pub fn lab_queued(&self) -> bool {
        self.queued.is_some()
    }
    pub fn lab_write_checkpoint(&mut self) -> Result<bool> {
        match self.pending.as_mut() {
            Some(job) if job.mutation && !job.failed => job.child.lab_waiting_checkpoint(),
            _ => Ok(false),
        }
    }
    pub fn lab_release_write(&mut self) -> Result<()> {
        let job = self.pending.as_mut().ok_or(Error::Interrupted)?;
        if !job.mutation || job.failed {
            return Err(Error::Interrupted);
        }
        job.child.lab_release_checkpoint()
    }
    pub fn lab_checkpoint(&mut self) -> Result<Option<(u32, u64, f64)>> {
        let Some(job) = self.pending.as_mut() else {
            return Ok(None);
        };
        Ok(job
            .child
            .lab_stop_at_checkpoint()?
            .map(|(pid, start)| (pid, start, job.deadline)))
    }
    pub fn lab_completed(&self) -> u64 {
        self.completed
    }
}
impl Drop for JournalServer {
    fn drop(&mut self) {
        let _ = self.fence();
    }
}
fn file_check(fd: impl AsFd) -> Result<()> {
    let s = fs::fstat(fd).map_err(|_| Error::OwnershipMismatch)?;
    if s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o7777 != 0o600
        || s.st_nlink != 1
        || FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}
enum JournalOrigin {
    Primary,
    OwnerHost,
}
pub(super) fn directory(path: &Path) -> Result<OwnedFd> {
    if !super::spec::safe_absolute(path) {
        return Err(Error::UnsafeInput);
    }
    let mut d =
        fs::open("/", RD | OFlags::DIRECTORY, Mode::empty()).map_err(|_| Error::UnsafeInput)?;
    for p in path.components().skip(1) {
        let s = fs::fstat(&d).map_err(|_| Error::UnsafeInput)?;
        if s.st_uid != 0 || s.st_gid != 0 || s.st_mode & 0o022 != 0 {
            return Err(Error::UnsafeInput);
        }
        d = fs::openat(&d, p.as_os_str(), RD | OFlags::DIRECTORY, Mode::empty())
            .map_err(|_| Error::UnsafeInput)?;
    }
    let s = fs::fstat(&d).map_err(|_| Error::UnsafeInput)?;
    if s.st_uid != 0 || s.st_gid != 0 || s.st_mode & 0o7777 != 0o700 {
        return Err(Error::UnsafeInput);
    }
    Ok(d)
}
impl Journal {
    pub fn open(
        store: &AllocationStore,
        path: &Path,
        s: &LaunchSpec,
        primary: &str,
        base: impl AsFd,
    ) -> Result<Self> {
        Self::open_inner(store, path, s, primary, base, None)
    }
    fn open_inner(
        store: &AllocationStore,
        path: &Path,
        s: &LaunchSpec,
        primary: &str,
        base: impl AsFd,
        owner_epoch: Option<super::supervision::OwnerDomainRecord>,
    ) -> Result<Self> {
        s.validate()?;
        Self::open_allocation(
            store,
            path,
            &s.allocation,
            &s.exit.exit_id,
            primary,
            base,
            owner_epoch,
        )
    }
    /// Original owner epoch can precede container/profile/native resource birth.
    /// A full launched-container spec is still required by every later launch
    /// and inspection path; no synthetic container identity is introduced here.
    #[allow(clippy::too_many_arguments)]
    fn open_allocation(
        store: &AllocationStore,
        path: &Path,
        expected: &AllocationRecord,
        exit: &str,
        primary: &str,
        base: impl AsFd,
        owner_epoch: Option<super::supervision::OwnerDomainRecord>,
    ) -> Result<Self> {
        Self::open_context(
            store,
            path,
            expected,
            exit,
            primary,
            base,
            owner_epoch,
            JournalOrigin::Primary,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn open_context(
        store: &AllocationStore,
        path: &Path,
        expected: &AllocationRecord,
        exit: &str,
        primary: &str,
        base: impl AsFd,
        owner_epoch: Option<super::supervision::OwnerDomainRecord>,
        origin: JournalOrigin,
    ) -> Result<Self> {
        process::single_threaded()?;
        expected
            .validate(&expected.deployment_id, &[])
            .map_err(|_| Error::AllocationMismatch)?;
        if !expected.exits.iter().any(|e| e.exit_id == exit) {
            return Err(Error::AllocationMismatch);
        }
        let allocation = store.lock().map_err(|_| Error::LockBusy)?;
        let a = allocation
            .read()
            .map_err(|_| Error::AllocationMismatch)?
            .ok_or(Error::AllocationMismatch)?;
        if !same_allocation(&a, expected)? {
            return Err(Error::AllocationMismatch);
        }
        let dir = directory(path)?;
        allocation
            .verify_directory(dir.as_fd())
            .map_err(|_| Error::OwnershipMismatch)?;
        let inventory = super::inventory::Registration::allocation(dir.as_fd())?;
        let base = Identity::network(base)?;
        let mut created = false;
        let mut record: Record = match fs::openat(&dir, "namespaces.json", RD, Mode::empty()) {
            Ok(fd) => {
                file_check(&fd)?;
                let mut b = Vec::new();
                File::from(fd)
                    .take(262145)
                    .read_to_end(&mut b)
                    .map_err(|_| Error::OwnershipMismatch)?;
                if b.len() > 262144 {
                    return Err(Error::TooLarge);
                }
                serde_json::from_slice(&b).map_err(|_| Error::OwnershipMismatch)?
            }
            Err(rustix::io::Errno::NOENT) => {
                created = true;
                match origin {
                    JournalOrigin::Primary => Record::new_allocation(expected, primary, base)?,
                    JournalOrigin::OwnerHost => Record::new_preparing(
                        expected,
                        primary,
                        base,
                        owner_epoch.clone().ok_or(Error::OwnershipMismatch)?,
                    )?,
                }
            }
            Err(_) => return Err(Error::OwnershipMismatch),
        };
        match origin {
            JournalOrigin::Primary => record.bind_allocation(expected, primary, base)?,
            JournalOrigin::OwnerHost => record.bind_anchor(expected, primary, None, Some(base))?,
        }
        if let Some(epoch) = owner_epoch {
            epoch.validate(&super::supervision::Domains::from_record(
                expected,
                exit,
                &"0".repeat(64),
            )?)?;
            if created {
                record.owner_epoch = Some(epoch);
            } else if record.owner_epoch.as_ref() != Some(&epoch) {
                // No persist, adoption, native mutation or cleanup on this path.
                return Err(Error::Interrupted);
            }
        }
        let tx = Self {
            owner_pid: std::process::id(),
            staging: std::cell::Cell::new(false),
            async_only: std::cell::Cell::new(false),
            dir,
            allocation,
            record,
            _inventory: inventory,
        };
        tx.persist()?;
        Ok(tx)
    }
    fn persist(&self) -> Result<()> {
        if self.owner_pid != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if self.staging.get() {
            return Ok(());
        }
        if self.async_only.get() {
            return Err(Error::OwnershipMismatch);
        }
        let bytes = serde_json::to_vec(&self.record).map_err(|_| Error::OwnershipMismatch)?;
        if bytes.len() > 262144 {
            return Err(Error::TooLarge);
        }
        let name = format!(".namespaces-{}", std::process::id());
        // An interrupted temp is never overwritten or silently deleted.
        let fd = fs::openat(
            &self.dir,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Error::Interrupted)?;
        let mut f = File::from(fd);
        f.write_all(&bytes)
            .and_then(|()| f.sync_all())
            .map_err(|_| Error::Interrupted)?;
        fs::renameat(&self.dir, &name, &self.dir, "namespaces.json")
            .map_err(|_| Error::Interrupted)?;
        fs::fsync(&self.dir).map_err(|_| Error::Interrupted)
    }
    pub fn revalidate(&self, s: &LaunchSpec) -> Result<()> {
        if self.record.entries.iter().any(|e| {
            e.exit_id == s.exit.exit_id && e.producer.as_ref().is_some_and(|p| p.binding.is_some())
        }) {
            return Err(Error::OwnershipMismatch);
        }
        if self.staging.get() {
            return self.record.bind(
                s,
                &self.record.primary_exit_id,
                self.record.primary_network()?,
            );
        }
        let current = self
            .allocation
            .read()
            .map_err(|_| Error::AllocationMismatch)?
            .ok_or(Error::AllocationMismatch)?;
        if !same_allocation(&current, &s.allocation)? {
            return Err(Error::AllocationMismatch);
        }
        self.record.bind(
            s,
            &self.record.primary_exit_id,
            self.record.primary_network()?,
        )
    }
    pub fn acquire(&mut self, s: &LaunchSpec, base: impl AsFd) -> Result<OwnedNamespaces> {
        self.revalidate(s)?;
        if Some(Identity::network(&base)?) != self.record.base_network {
            return Err(Error::NamespaceMismatch);
        }
        if let Some(e) = self
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == s.exit.exit_id)
        {
            if e.phase != Phase::Offline || e.terminal.is_some() {
                return Err(Error::Interrupted);
            }
            return OwnedNamespaces::new(
                s,
                self.reopen(&e.data_name, e.data.ok_or(Error::Interrupted)?)?,
                self.reopen(&e.transport_name, e.transport.ok_or(Error::Interrupted)?)?,
            );
        }
        // Exclusivity checked before durable intent, but O_EXCL below remains
        // decisive. Foreign paths and ambiguous partial entries are never adopted.
        for name in [&s.exit.data_namespace, &s.exit.transport_namespace] {
            match fs::statat(&self.dir, name, fs::AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                _ => return Err(Error::OwnershipMismatch),
            }
        }
        self.record.entries.push(Entry {
            exit_id: s.exit.exit_id.clone(),
            data_name: s.exit.data_namespace.clone(),
            transport_name: s.exit.transport_namespace.clone(),
            phase: Phase::Creating,
            data: None,
            transport: None,
            links: None,
            producer: None,
            terminal: None,
            attempt: None,
            preparation: None,
        });
        self.persist()?;
        let data = self.create(
            &s.exit.data_namespace,
            if s.exit.exit_id == self.record.primary_exit_id {
                Some(base.as_fd())
            } else {
                None
            },
        )?;
        let id = Identity::network(&data)?;
        self.record
            .entries
            .last_mut()
            .ok_or(Error::Interrupted)?
            .data = Some(id);
        self.persist()?;
        let transport = self.create(&s.exit.transport_namespace, None)?;
        let id = Identity::network(&transport)?;
        let e = self.record.entries.last_mut().ok_or(Error::Interrupted)?;
        e.transport = Some(id);
        e.phase = Phase::Offline;
        self.record.bind(
            s,
            &self.record.primary_exit_id,
            self.record.primary_network()?,
        )?;
        self.persist()?;
        OwnedNamespaces::new(s, data, transport)
    }
    /// Persist activation intent before any link creation/UP operation. A crash
    /// in this phase is never silently adopted by acquire().
    pub fn begin_transport(&mut self, s: &LaunchSpec, ns: &OwnedNamespaces) -> Result<()> {
        self.revalidate(s)?;
        ns.bind(s)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if e.phase != Phase::Offline
            || e.links.is_some()
            || e.terminal.is_some()
            || e.preparation.is_some()
            || e.producer.is_some()
        {
            return Err(Error::Interrupted);
        }
        e.phase = Phase::Activating;
        self.persist()
    }
    pub fn bind_producer(
        &mut self,
        s: &LaunchSpec,
        parent: Identity,
        group: Identity,
    ) -> Result<()> {
        self.revalidate(s)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if e.phase != Phase::Activating
            || e.producer.is_some()
            || parent.dev != group.dev
            || parent == group
            || parent.ino == 0
            || group.ino == 0
        {
            return Err(Error::OwnershipMismatch);
        }
        e.producer = Some(ProducerOwnership {
            parent,
            group,
            binding: None,
        });
        self.persist()
    }
    pub fn verify_producer(&self, s: &LaunchSpec, parent: Identity, group: Identity) -> Result<()> {
        self.revalidate(s)?;
        let e = self
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let p = e.producer.as_ref().ok_or(Error::OwnershipMismatch)?;
        if p.binding.is_some() || e.preparation.is_some() || p.parent != parent || p.group != group
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub fn bind_links(
        &mut self,
        s: &LaunchSpec,
        ns: &OwnedNamespaces,
        host: Identity,
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.revalidate(s)?;
        ns.bind(s)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if e.phase != Phase::Activating
            || e.links.is_some()
            || [indices.0, indices.1, indices.2].contains(&0)
            || host.ino == 0
            || Some(host) == e.data
            || Some(host) == e.transport
        {
            return Err(Error::OwnershipMismatch);
        }
        e.links = Some(LinkOwnership {
            host_namespace: host,
            host_index: indices.0,
            transport_index: indices.1,
            wireguard_index: indices.2,
        });
        self.persist()
    }
    pub fn bootstrap(
        &mut self,
        s: &LaunchSpec,
        ns: &OwnedNamespaces,
        host: Identity,
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.verify_links(s, ns, host, indices)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if e.phase != Phase::Activating {
            return Err(Error::Interrupted);
        }
        e.phase = Phase::Bootstrap;
        self.persist()
    }
    pub fn verify_links(
        &self,
        s: &LaunchSpec,
        ns: &OwnedNamespaces,
        host: Identity,
        indices: (u32, u32, u32),
    ) -> Result<()> {
        self.revalidate(s)?;
        ns.bind(s)?;
        let e = self
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let l = e.links.as_ref().ok_or(Error::OwnershipMismatch)?;
        if !matches!(e.phase, Phase::Activating | Phase::Bootstrap)
            || l.host_namespace != host
            || (l.host_index, l.transport_index, l.wireguard_index) != indices
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub fn transport_cleaned(&mut self, s: &LaunchSpec) -> Result<()> {
        self.revalidate(s)?;
        let e = self
            .record
            .entries
            .iter_mut()
            .find(|e| e.exit_id == s.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        if !matches!(e.phase, Phase::Activating | Phase::Bootstrap) || e.terminal.is_some() {
            return Err(Error::Interrupted);
        }
        e.phase = Phase::Offline;
        e.links = None;
        e.producer = None;
        self.persist()
    }
    fn create(&self, name: &str, source: Option<std::os::fd::BorrowedFd<'_>>) -> Result<OwnedFd> {
        let placeholder = fs::openat(
            &self.dir,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        file_check(&placeholder)?;
        fs::fsync(&self.dir).map_err(|_| Error::Interrupted)?;
        kernel::pin_network(&placeholder, source)?;
        let handle = fs::openat2(
            &self.dir,
            name,
            RD,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        let id = Identity::network(&handle)?;
        self.reopen(name, id)
    }
    #[cfg(test)]
    pub fn lab_unpin(&self) -> Result<()> {
        for (index, e) in self.record.entries.iter().enumerate() {
            if e.phase != Phase::Offline || e.terminal.is_some() {
                return Err(Error::Interrupted);
            }
            eprintln!("LAB_UNPIN_RECORD exit_index={index} kind=data");
            kernel::lab_unpin(
                self.dir.as_fd(),
                &e.data_name,
                e.data.ok_or(Error::Interrupted)?,
            )?;
            eprintln!("LAB_UNPIN_RECORD exit_index={index} kind=transport");
            kernel::lab_unpin(
                self.dir.as_fd(),
                &e.transport_name,
                e.transport.ok_or(Error::Interrupted)?,
            )?;
        }
        fs::fsync(&self.dir).map_err(|_| Error::Interrupted)
    }
    fn reopen(&self, name: &str, expected: Identity) -> Result<OwnedFd> {
        let handle = fs::openat2(
            &self.dir,
            name,
            RD,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        if Identity::network(&handle)? != expected {
            return Err(Error::NamespaceMismatch);
        }
        // setns+direct proc reopening is mandatory for native NamespaceTarget.
        kernel::direct_network(&handle)
    }
}
#[cfg(test)]
fn lab_deployment_fixture() -> Result<(
    LaunchSpec,
    LaunchSpec,
    vprouter_core::config::ValidatedConfiguration,
)> {
    let (mut first, _) = super::tests::fixture();
    let cfg = super::transport_lab::health_configuration(&first)?;
    let mut config = serde_json::to_value(cfg.configuration()).map_err(|_| Error::InvalidSpec)?;
    let mut other = config["exits"][0].clone();
    other["id"] = serde_json::json!("other");
    other["state_dir"] = serde_json::json!("/var/lib/launchlab/other");
    config["exits"]
        .as_array_mut()
        .ok_or(Error::InvalidSpec)?
        .push(other);
    let mut policy = config["client_policies"][0].clone();
    policy["id"] = serde_json::json!("neighbor-fixture");
    policy["exit_id"] = serde_json::json!("other");
    policy["selected_node_id"] = serde_json::json!("fixture-neighbor");
    config["client_policies"]
        .as_array_mut()
        .ok_or(Error::InvalidSpec)?
        .push(policy);
    let cfg = vprouter_core::config::Configuration::parse(
        &serde_json::to_vec(&config).map_err(|_| Error::InvalidSpec)?,
    )
    .map_err(|_| Error::InvalidSpec)?
    .validate_with(|_, _| unreachable!("Direct fixture has no profile"))
    .map_err(|_| Error::InvalidSpec)?;
    first.allocation = AllocationRecord::from_configuration(&cfg, first.generation)
        .map_err(|_| Error::InvalidSpec)?;
    let mut second =
        super::LaunchSpec::parse(&serde_json::to_vec(&first).map_err(|_| Error::InvalidSpec)?)?;
    second.exit = first.allocation.exits[1].clone();
    second.validate()?;
    Ok((first, second, cfg))
}
/// Real confined IO crossing a legal neighboring activation intent. This gate
/// proves journal read generation handling, NOT Bootstrap/routed activation.
#[cfg(test)]
fn lab_crossing_neighbor_intent(
    tx: &mut Transaction,
    spec: &LaunchSpec,
    ns: &OwnedNamespaces,
) -> Result<()> {
    let before = tx.shared.journal.borrow().record.clone();
    let sent_at = vprouter_core::health::boot_seconds();
    tx.shared
        .reads
        .borrow_mut()
        .reserve(&before, None, "other")?;
    let reader_job = JournalIo {
        allocation: spec.allocation.clone(),
        before: encode_record(&before)?,
        after: None,
        deadline: sent_at + 2.,
        pause_before_read: true,
        pause_before_sync: false,
        lab_stage: std::cell::Cell::new(0),
    };
    let launch = |job: &JournalIo| -> Result<kernel::JournalChild> {
        let journal = tx.shared.journal.borrow();
        let directory = rustix::io::fcntl_dupfd_cloexec(&journal.dir, 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let lease = tx.retain_mutator_lease(spec)?;
        kernel::spawn_journal_io(directory, lease, job)
    };
    let mut reader = launch(&reader_job)?;
    reader.start()?;
    while !reader.lab_waiting_checkpoint()? {
        original_frame(sent_at, vprouter_core::health::boot_seconds())?;
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    // Existing legal owner-side Offline -> Activating intent, evaluated against
    // actual acquired namespaces. No schema-only Bootstrap or noop RPC is used.
    tx.shared.journal.borrow().staging.set(true);
    let intent = tx.shared.journal.borrow_mut().begin_transport(spec, ns);
    let proposed = tx.shared.journal.borrow().record.clone();
    tx.shared.journal.borrow_mut().record = before.clone();
    tx.shared.journal.borrow().staging.set(false);
    intent?;
    unchanged_selected_entry(&before, &proposed, "other")?;
    let writer_job = JournalIo {
        after: Some(encode_record(&proposed)?),
        pause_before_read: false,
        ..reader_job
    };
    let mut writer = launch(&writer_job)?;
    tx.shared.reads.borrow_mut().publish(&proposed)?;
    *tx.shared.pending.borrow_mut() = Some(proposed.clone());
    writer.start()?;
    loop {
        original_frame(sent_at, vprouter_core::health::boot_seconds())?;
        match writer.poll()? {
            Some(true) => break,
            Some(false) => return Err(Error::ChildFailed),
            None => std::thread::sleep(std::time::Duration::from_millis(1)),
        }
    }
    if writer.observed()? != record_digest(&encode_record(&proposed)?) {
        return Err(Error::OwnershipMismatch);
    }
    tx.shared.journal.borrow_mut().record = tx
        .shared
        .pending
        .borrow_mut()
        .take()
        .ok_or(Error::Interrupted)?;
    reader.lab_release_checkpoint()?;
    loop {
        original_frame(sent_at, vprouter_core::health::boot_seconds())?;
        match reader.poll()? {
            Some(true) => break,
            Some(false) => return Err(Error::ChildFailed),
            None => std::thread::sleep(std::time::Duration::from_millis(1)),
        }
    }
    let observed = reader.observed()?;
    if observed == record_digest(&encode_record(&before)?) || observed != writer.observed()? {
        return Err(Error::OwnershipMismatch);
    }
    tx.shared
        .reads
        .borrow()
        .verify("other", observed, &tx.shared.journal.borrow().record, None)?;
    tx.shared.reads.borrow_mut().remove("other");
    original_frame(sent_at, vprouter_core::health::boot_seconds())?;
    println!(
        "{}",
        serde_json::json!({"case":"actual_confined_reader_crosses_neighbor_atomic_activation_intent_commit_exact_owner_generation", "original_deadline":sent_at+2.,"finished_at":vprouter_core::health::boot_seconds(),"component_only":true,"bootstrap_activation_acceptance":false})
    );
    Ok(())
}
#[cfg(test)]
pub(super) fn lab_owner_deployment() -> Result<()> {
    use std::{os::unix::fs::DirBuilderExt, time::Duration};
    let nonce = vprouter_linux::storage::read(
        Path::new("/var/lib/vprouter-v2-lab/owner-domain-nonce"),
        vprouter_linux::storage::Kind::SecretFile,
        64,
    )
    .map_err(|_| Error::LabRequired)?;
    let lifecycle = std::str::from_utf8(&nonce).map_err(|_| Error::LabRequired)?;
    let (first, second, cfg) = lab_deployment_fixture()?;
    let domains_a = super::supervision::Domains::new(&first, lifecycle)?;
    let domains_b = super::supervision::Domains::new(
        &second,
        &vprouter_worker::bootstrap::digest(format!("neighbor:{lifecycle}").as_bytes()),
    )?;
    domains_a.verify_owner()?;
    let path = Path::new("/var/lib/vprouter-v2-lab").join(format!("owner-deployment-{lifecycle}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| Error::OwnershipMismatch)?;
    let store = AllocationStore::open(&path, &first.allocation.deployment_id)
        .map_err(|_| Error::OwnershipMismatch)?;
    store
        .lock()
        .map_err(|_| Error::LockBusy)?
        .commit(None, &first.allocation)
        .map_err(|_| Error::OwnershipMismatch)?;
    let base = fs::open(
        "/proc/self/ns/net",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::NamespaceMismatch)?;
    let _base = super::inventory::Registration::owned(&[base.as_fd()])?;
    let mut tx_a = Transaction::open(&store, &path, &first, "one", &base)?;
    let mut tx_b = tx_a.for_exit(&second)?;
    let ns_a = tx_a.acquire(&first, &base)?;
    let ns_b = tx_b.acquire(&second, &base)?;
    lab_crossing_neighbor_intent(&mut tx_a, &first, &ns_a)?;
    let before = std::fs::read(path.join("namespaces.json")).map_err(|_| Error::Interrupted)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::InvalidSpec)?;
    let binding_a =
        vprouter_linux::status::expected_binding(&cfg, 0, first.generation, boot.trim())
            .map_err(|_| Error::InvalidSpec)?;
    let binding_b =
        vprouter_linux::status::expected_binding(&cfg, 1, second.generation, boot.trim())
            .map_err(|_| Error::InvalidSpec)?;
    let mut journals = [
        JournalServer::new(&tx_a, &first, &ns_a, domains_a.clone(), binding_a)?,
        JournalServer::new(&tx_b, &second, &ns_b, domains_b.clone(), binding_b)?,
    ];
    journals[0].pause_next_read = true;
    let owner_a = super::owner::ExternalOwner::spawn(
        domains_a.clone(),
        super::inventory::GuardInputs::for_domains(&domains_a)?,
        |owner| {
            if tx_a.fork_remote(&first, owner).err() != Some(Error::Deadline) {
                return Err(Error::DescriptorPolicy);
            }
            // Failed RPC does not self-exit; external owner must actually freeze it.
            loop {
                std::thread::sleep(Duration::from_millis(50));
            }
        },
    )?;
    let owner_b = super::owner::ExternalOwner::spawn(
        domains_b.clone(),
        super::inventory::GuardInputs::for_domains(&domains_b)?,
        |owner| {
            let remote = tx_b.fork_remote(&second, owner)?;
            let end = vprouter_core::health::boot_seconds() + 4.;
            while vprouter_core::health::boot_seconds() < end {
                remote.require_no_executors(&second)?;
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(())
        },
    )?;
    let a = owner_a.lab_identity()?;
    let b = owner_b.lab_identity()?;
    let mut owners = [owner_a, owner_b];
    let mut checkpoint = None;
    let mut b_at_a_terminal = None;
    let mut a_terminal_at = None;
    {
        let mut deployment = super::owner::DeploymentOwner::new(&mut owners, &mut journals)?;
        let end = vprouter_core::health::boot_seconds() + 8.;
        loop {
            let finished = deployment.poll_once()?;
            if checkpoint.is_none() {
                checkpoint = deployment.lab_checkpoint(0)?;
            }
            if b_at_a_terminal.is_none() && deployment.lab_terminal(0).is_some() {
                if deployment.lab_terminal(0) != Some(Error::Deadline) {
                    return Err(Error::DescriptorPolicy);
                }
                b_at_a_terminal = Some(deployment.lab_completed(1));
                a_terminal_at = Some(vprouter_core::health::boot_seconds());
            }
            if finished {
                break;
            }
            if vprouter_core::health::boot_seconds() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let (io_pid, io_start, deadline) = checkpoint.ok_or(Error::DescriptorPolicy)?;
    let b_before = b_at_a_terminal.ok_or(Error::DescriptorPolicy)?;
    let stopped_at = a_terminal_at.ok_or(Error::DescriptorPolicy)?;
    if journals[0].completed != 0
        || journals[1].completed < b_before + 5
        || stopped_at < deadline
        || stopped_at >= deadline + 1.
    {
        return Err(Error::Deadline);
    }
    owners[0].lab_kill_stopped(a.1)?;
    owners[1].lab_reap_success()?;
    let end = vprouter_core::health::boot_seconds() + 2.;
    while !journals[0].drain()? {
        if vprouter_core::health::boot_seconds() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if !journals[1].drain()?
        || std::fs::read(path.join("namespaces.json")).map_err(|_| Error::Interrupted)? != before
    {
        return Err(Error::OwnershipMismatch);
    }
    println!(
        "{}",
        serde_json::json!({"case":"actual_two_guard_owner_loop_stalled_a_original_deadline_scoped_freeze_b_continues_fresh_journal_reads", "guard_a_pid":a.0,"guard_a_start":a.1,"guard_b_pid":b.0,"guard_b_start":b.1,"stopped_io_pid":io_pid,"stopped_io_start":io_start,"original_deadline":deadline,"a_terminal_at":stopped_at,"b_reads_before_a_terminal":b_before,"b_reads_total":journals[1].completed,"component_only":true,"routed_neighbor_acceptance":false})
    );
    Ok(())
}
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn lab_expiry_placement<'a>(
    first: &LaunchSpec,
    second: &LaunchSpec,
    a: &mut super::transport::GuardTransport<'a>,
    b: &mut super::transport::GuardTransport<'a>,
    cfg: &vprouter_core::config::ValidatedConfiguration,
    nonce: &str,
    authority: &vprouter_network::HostAuthority,
    store: &AllocationStore,
) -> Result<()> {
    use std::time::Duration;
    let domains_a = super::supervision::Domains::new(first, nonce)?;
    let domains_b = super::supervision::Domains::new(
        second,
        &vprouter_worker::bootstrap::digest(format!("placement-neighbor:{nonce}").as_bytes()),
    )?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::InvalidSpec)?;
    let binding_a = vprouter_linux::status::expected_binding(cfg, 0, first.generation, boot.trim())
        .map_err(|_| Error::InvalidSpec)?;
    let binding_b =
        vprouter_linux::status::expected_binding(cfg, 1, second.generation, boot.trim())
            .map_err(|_| Error::InvalidSpec)?;
    let mut expiry = a.owner_expiry(domains_a.clone(), binding_a.clone())?;
    expiry.lab_pause_placement();
    let owner_a = super::owner::ExternalOwner::spawn(
        domains_a.clone(),
        a.guard_inputs(&domains_a, None)?,
        |owner| {
            a.bind_remote(owner)?;
            let result = a.start_expiry(binding_a.clone(), owner.domains().lifecycle());
            if result.is_ok() {
                return Err(Error::OwnershipMismatch);
            }
            // Keep the exact guard available for independent scoped T observation.
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        },
    )?;
    let owner_b = super::owner::ExternalOwner::spawn(
        domains_b.clone(),
        b.guard_inputs(&domains_b, None)?,
        |owner| {
            b.bind_remote(owner)?;
            loop {
                if b.audit().is_err() {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        },
    )?;
    let (tx_a, ns_a) = a.lab_journal_parts();
    let (tx_b, ns_b) = b.lab_journal_parts();
    let mut journals = [
        JournalServer::new(tx_a, first, ns_a, domains_a, binding_a)?,
        JournalServer::new(tx_b, second, ns_b, domains_b, binding_b)?,
    ];
    let mut owners = [owner_a, owner_b];
    owners[0].install_expiry(expiry, &mut journals[0]);
    for (owner, journal) in owners.iter_mut().zip(journals.iter_mut()) {
        owner.install_host_audit(authority, journal);
    }
    let guards = [owners[0].lab_identity()?, owners[1].lab_identity()?];
    let mut held = None;
    let mut b_at_hold = 0;
    let mut a_terminal_at = None;
    let mut b_at_terminal = 0;
    let mut b_final = 0;
    let mut stopping_b = false;
    {
        let mut deployment = super::owner::DeploymentOwner::new(&mut owners, &mut journals)?;
        let end = vprouter_core::health::boot_seconds() + 12.;
        loop {
            let done = deployment.poll_once()?;
            if held.is_none() {
                held = deployment.lab_placement_checkpoint(0)?;
                if held.is_some() {
                    b_at_hold = deployment.lab_host_completed(1);
                    // Shared deployment lock: B and parent also retain copies.
                    // This is not the independent sole-survivor claim of109.
                    if !store
                        .lock()
                        .is_err_and(|e| e.reason() == vprouter_core::reason::Reason::LockBusy)
                    {
                        return Err(Error::LockBusy);
                    }
                }
            }
            if a_terminal_at.is_none() && deployment.lab_terminal(0).is_some() {
                let (_, _, deadline) = held.ok_or(Error::OwnershipMismatch)?;
                let now = vprouter_core::health::boot_seconds();
                if deployment.lab_terminal(0) != Some(Error::Deadline)
                    || now < deadline
                    || now - deadline > 0.5
                {
                    return Err(Error::Deadline);
                }
                a_terminal_at = Some(now);
                b_at_terminal = deployment.lab_host_completed(1);
                if b_at_terminal < b_at_hold + 2 {
                    return Err(Error::Interrupted);
                }
            }
            if a_terminal_at.is_some()
                && !stopping_b
                && deployment.lab_host_completed(1) >= b_at_terminal + 2
                && deployment.lab_placement_drained_without_grant(0)?
                && deployment.lab_guard_stopped(0, guards[0].1)?
            {
                b_final = deployment.lab_host_completed(1);
                deployment.lab_terminate(1);
                stopping_b = true;
            }
            if done
                && stopping_b
                && deployment.lab_host_drained(1)
                && deployment.lab_guard_stopped(0, guards[0].1)?
                && deployment.lab_guard_stopped(1, guards[1].1)?
            {
                break;
            }
            if vprouter_core::health::boot_seconds() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let targets = owners[0].lab_executor_identities()?;
    if targets.len() != 1 {
        return Err(Error::OwnershipMismatch);
    }
    for (owner, (_, start)) in owners.iter().zip(guards) {
        owner.lab_kill_stopped(start)?;
    }
    for journal in &mut journals {
        if !journal.drain()? {
            return Err(Error::OwnershipMismatch);
        }
    }
    let disk_digest = {
        let journal = tx_a.shared.journal.borrow();
        let fd = fs::openat(&journal.dir, "namespaces.json", RD, Mode::empty())
            .map_err(|_| Error::OwnershipMismatch)?;
        file_check(&fd)?;
        let mut bytes = Vec::new();
        File::from(fd)
            .take(262145)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Interrupted)?;
        if bytes.len() > 262144 || bytes != encode_record(&journal.record)? {
            return Err(Error::OwnershipMismatch);
        }
        let disk: Record = serde_json::from_slice(&bytes).map_err(|_| Error::OwnershipMismatch)?;
        disk.bind(
            first,
            &journal.record.primary_exit_id,
            journal.record.primary_network()?,
        )?;
        let entry = disk
            .entries
            .iter()
            .find(|e| e.exit_id == first.exit.exit_id)
            .ok_or(Error::OwnershipMismatch)?;
        let terminal = entry.terminal.as_ref().ok_or(Error::OwnershipMismatch)?;
        terminal.validate(&disk, entry)?;
        if (terminal.guard_pid, terminal.guard_start) != guards[0]
            || !terminal.executors.is_empty()
            || !terminal.acknowledged.is_empty()
            || !terminal.completions.is_empty()
        {
            return Err(Error::OwnershipMismatch);
        }
        vprouter_linux::sha256(&bytes)
    };
    if !store
        .lock()
        .is_err_and(|e| e.reason() == vprouter_core::reason::Reason::LockBusy)
    {
        return Err(Error::LockBusy);
    }
    let (helper_pid, helper_start, deadline) = held.ok_or(Error::OwnershipMismatch)?;
    println!(
        "{}",
        serde_json::json!({"case":"actual_owner_held_expiry_placement_original_deadline_neighbor_progress_no_control_or_registration_actual_drain", "helper_pid":helper_pid,"helper_start":helper_start,"target":targets[0],"original_deadline":deadline,"a_terminal_at":a_terminal_at,"b_audits_at_hold":b_at_hold,"b_audits_at_terminal":b_at_terminal,"b_audits_final":b_final,"guard_identities":guards,"disk_sha256":disk_digest,"before_pid1_send":true,"helper_and_gated_target_actually_reaped":true,"control_granted":false,"executor_registered":false,"shared_deployment_ofd_busy":true,"sole_survivor_claim":false,"expired_actor_resumed":false,"component_only":true})
    );
    super::lab::case(
        "actual_owner_held_expiry_placement_original_deadline_neighbor_progress_no_control_or_registration_actual_drain",
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn lab_host_audits<'a>(
    first: &LaunchSpec,
    second: &LaunchSpec,
    a: &mut super::transport::GuardTransport<'a>,
    b: &mut super::transport::GuardTransport<'a>,
    cfg: &vprouter_core::config::ValidatedConfiguration,
    nonce: &str,
    authority: &vprouter_network::HostAuthority,
) -> Result<()> {
    use std::time::Duration;
    let domains_a = super::supervision::Domains::new(first, nonce)?;
    let domains_b = super::supervision::Domains::new(
        second,
        &vprouter_worker::bootstrap::digest(format!("host-audit-neighbor:{nonce}").as_bytes()),
    )?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::InvalidSpec)?;
    let binding_a = vprouter_linux::status::expected_binding(cfg, 0, first.generation, boot.trim())
        .map_err(|_| Error::InvalidSpec)?;
    let binding_b =
        vprouter_linux::status::expected_binding(cfg, 1, second.generation, boot.trim())
            .map_err(|_| Error::InvalidSpec)?;
    let owned_host_index = a.lab_host_index()?;
    // Spawn before borrowing parent journal parts: only the fork child converts
    // its entire transport, while the parent retains canonical local authority.
    let owner_a = super::owner::ExternalOwner::spawn(
        domains_a.clone(),
        a.guard_inputs(&domains_a, None)?,
        |owner| {
            a.bind_remote(owner)?;
            loop {
                if a.audit().is_err() {
                    // Never resume an expired lifecycle or exit before the owner can
                    // prove scoped freeze; parent will exact-kill and reap this guard.
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        },
    )?;
    let owner_b = super::owner::ExternalOwner::spawn(
        domains_b.clone(),
        b.guard_inputs(&domains_b, None)?,
        |owner| {
            b.bind_remote(owner)?;
            loop {
                if b.audit().is_err() {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        },
    )?;
    let (tx_a, ns_a) = a.lab_journal_parts();
    let (tx_b, ns_b) = b.lab_journal_parts();
    let mut journals = [
        JournalServer::new(tx_a, first, ns_a, domains_a, binding_a)?,
        JournalServer::new(tx_b, second, ns_b, domains_b, binding_b)?,
    ];
    let mut owners = [owner_a, owner_b];
    for (owner, journal) in owners.iter_mut().zip(journals.iter_mut()) {
        owner.install_host_audit(authority, journal);
    }
    let identities = [owners[0].lab_identity()?, owners[1].lab_identity()?];
    let mut held = None;
    let mut pause_requested = false;
    let mut a_terminal = None;
    let mut b_at_terminal = 0;
    let mut drift_at = None;
    let mut b_before_drift = 0;
    {
        let mut deployment = super::owner::DeploymentOwner::new(&mut owners, &mut journals)?;
        let end = vprouter_core::health::boot_seconds() + 12.;
        loop {
            let done = deployment.poll_once()?;
            if !pause_requested
                && deployment.lab_host_completed(0) >= 2
                && deployment.lab_host_completed(1) >= 2
            {
                deployment.lab_pause_host(0)?;
                pause_requested = true;
            }
            if pause_requested && held.is_none() {
                held = deployment.lab_host_checkpoint(0)?;
            }
            if a_terminal.is_none() && deployment.lab_terminal(0).is_some() {
                let (_, _, deadline) = held.ok_or(Error::OwnershipMismatch)?;
                let now = vprouter_core::health::boot_seconds();
                if now < deadline
                    || now - deadline > 0.5
                    || deployment.lab_terminal(0) != Some(Error::Deadline)
                {
                    return Err(Error::Deadline);
                }
                a_terminal = Some(now);
                b_at_terminal = deployment.lab_host_completed(1);
            }
            if a_terminal.is_some()
                && drift_at.is_none()
                && deployment.lab_host_completed(1) >= b_at_terminal + 2
                && deployment.lab_host_drained(0)
            {
                b_before_drift = deployment.lab_host_completed(1);
                kernel::host_audit::lab_owned_link_drift(owned_host_index)?;
                drift_at = Some(vprouter_core::health::boot_seconds());
            }
            if done {
                if drift_at.is_none() || deployment.lab_terminal(1) != Some(Error::NetworkPolicy) {
                    return Err(Error::OwnershipMismatch);
                }
                while !deployment.lab_host_drained(0)
                    || !deployment.lab_host_drained(1)
                    || !deployment.lab_guard_stopped(0, identities[0].1)?
                    || !deployment.lab_guard_stopped(1, identities[1].1)?
                {
                    if vprouter_core::health::boot_seconds() >= end {
                        return Err(Error::Deadline);
                    }
                    std::thread::sleep(Duration::from_millis(1));
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
    let (pid, start, deadline) = held.ok_or(Error::OwnershipMismatch)?;
    println!(
        "{}",
        serde_json::json!({"case":"actual_owner_route_only_host_audit_caps0_negative_stalled_a_original_deadline_b_healthy_owned_host_drift", "held_audit_pid":pid,"held_audit_start":start,"original_deadline":deadline,"a_terminal_at":a_terminal,"b_audits_at_a_terminal":b_at_terminal,"b_audits_before_drift":b_before_drift,"drift_at":drift_at,"guard_a_pid":identities[0].0,"guard_a_start":identities[0].1,"guard_b_pid":identities[1].0,"guard_b_start":identities[1].1,"component_only":true,"ready_or_provider_acceptance":false})
    );
    super::lab::case(
        "actual_owner_route_only_host_audit_original_deadline_neighbor_and_owned_drift",
    );
    Ok(())
}

#[cfg(test)]
fn lab_host_shape_presence(
    bytes: &[u8],
    index: u32,
    alias: &str,
    link_present: bool,
) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Error::OwnershipMismatch)?;
    let links = value["links"].as_array().ok_or(Error::OwnershipMismatch)?;
    let owned: Vec<_> = links
        .iter()
        .filter(|link| link["index"] == index || link["alias"] == alias)
        .collect();
    if owned.len() != usize::from(link_present)
        || owned
            .first()
            .is_some_and(|link| link["index"] != index || link["alias"] != alias)
        || value["addresses"]
            .as_array()
            .ok_or(Error::OwnershipMismatch)?
            .iter()
            .any(|a| a["index"] == index)
        || value["routes"]
            .as_array()
            .ok_or(Error::OwnershipMismatch)?
            .iter()
            .any(|r| r["output"] == index)
    {
        return Err(Error::OwnershipMismatch);
    }
    Ok(())
}
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum RetainedCase {
    Drop,
    BirthFailure,
    ExpiryDrop { partial: bool },
    Retirement { fault: u8 },
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn lab_retained_owners<'a>(
    first: &LaunchSpec,
    second: &LaunchSpec,
    a: &mut super::transport::GuardTransport<'a>,
    mut b: super::transport::GuardTransport<'a>,
    cfg: &vprouter_core::config::ValidatedConfiguration,
    nonce: &str,
    authority: &vprouter_network::HostAuthority,
    owner_domain: &super::supervision::OwnerDomain,
    directory: &std::path::Path,
    case: RetainedCase,
) -> Result<()> {
    use super::owner::{DeploymentOwner, ExternalOwner, PendingOwner};
    use std::time::Duration;
    fn tick(owner: &mut ExternalOwner, journal: &mut JournalServer) -> Result<u64> {
        let mut deployment =
            DeploymentOwner::new(std::slice::from_mut(owner), std::slice::from_mut(journal))?;
        deployment.poll_once()?;
        if deployment.lab_terminal(0).is_some() {
            return Err(Error::ChildFailed);
        }
        Ok(deployment.lab_host_completed(0))
    }
    let domains_a = super::supervision::Domains::new(first, nonce)?;
    let domains_b = super::supervision::Domains::new(
        second,
        &vprouter_worker::bootstrap::digest(format!("retained-neighbor:{nonce}").as_bytes()),
    )?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::InvalidSpec)?;
    let binding_a = vprouter_linux::status::expected_binding(cfg, 0, first.generation, boot.trim())
        .map_err(|_| Error::InvalidSpec)?;
    let binding_b =
        vprouter_linux::status::expected_binding(cfg, 1, second.generation, boot.trim())
            .map_err(|_| Error::InvalidSpec)?;
    let mut prepared_expiry = if matches!(
        case,
        RetainedCase::ExpiryDrop { .. } | RetainedCase::Retirement { .. }
    ) {
        Some(b.owner_expiry(domains_b.clone(), binding_b.clone())?)
    } else {
        None
    };
    let mut owner_a = ExternalOwner::spawn(
        domains_a.clone(),
        a.guard_inputs_owned(&domains_a, owner_domain, None)?,
        |owner| {
            a.bind_remote(owner)?;
            loop {
                if a.audit().is_err() {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        },
    )?;
    let (tx_a, ns_a) = a.lab_journal_parts();
    let mut journal_a =
        JournalServer::new_owned(tx_a, first, ns_a, domains_a, binding_a, owner_domain)?;
    owner_a.install_host_audit(authority, &mut journal_a);
    let (tx_b, ns_b) = b.lab_journal_parts();
    let mut journal_b = JournalServer::new_owned(
        tx_b,
        second,
        ns_b,
        domains_b.clone(),
        binding_b.clone(),
        owner_domain,
    )?;
    let inputs_b = b.guard_inputs_owned(&domains_b, owner_domain, None)?;
    journal_b.start_attempt(owner_domain)?;
    let end = vprouter_core::health::boot_seconds()
        + if matches!(case, RetainedCase::Retirement { .. }) {
            30.
        } else {
            12.
        };
    let mut plan = None;
    loop {
        let completed = tick(&mut owner_a, &mut journal_a)?;
        if plan.is_none() {
            plan = journal_b.poll_attempt()?;
        }
        if completed >= 2 && plan.is_some() {
            break;
        }
        if vprouter_core::health::boot_seconds() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let planned =
        std::fs::read(directory.join("records/namespaces.json")).map_err(|_| Error::Interrupted)?;
    if matches!(case, RetainedCase::BirthFailure) {
        journal_b.lab_refuse_next_birth()?;
    }
    let mut pending = PendingOwner::fork(
        domains_b.clone(),
        owner_domain,
        plan.ok_or(Error::OwnershipMismatch)?,
        inputs_b,
        &mut journal_b,
        |owner| {
            b.bind_remote(owner)?;
            let _expiry = if matches!(
                case,
                RetainedCase::ExpiryDrop { .. } | RetainedCase::Retirement { .. }
            ) {
                match b.start_expiry(binding_b.clone(), owner.domains().lifecycle()) {
                    Ok(expiry) => Some(expiry),
                    Err(_) => loop {
                        std::thread::sleep(Duration::from_secs(1));
                    },
                }
            } else {
                None
            };
            loop {
                if b.audit().is_err() {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        },
    )?;
    let birth = pending.lab_birth()?;
    // A wrong supplied service must not fence A, cancel B or advance B's gate.
    if !matches!(pending.poll(&mut journal_a), Err(Error::OwnershipMismatch)) {
        return Err(Error::OwnershipMismatch);
    }
    let mut witness;
    let label;
    match case {
        RetainedCase::BirthFailure => {
            label = "actual_owner_failed_initial_birth_write_retained_plan_actual_guard_reap_neighbor_progress";
            if pending.lab_failure_status()?.0 != Some(Error::Interrupted) {
                return Err(Error::OwnershipMismatch);
            }
            let mut baseline = None;
            let final_count = loop {
                let count = tick(&mut owner_a, &mut journal_a)?;
                if pending.poll_failure(&mut journal_b)? && baseline.is_none() {
                    baseline = Some(count);
                }
                if baseline.is_some_and(|baseline| count >= baseline + 3) {
                    break count;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let status = pending.lab_failure_status()?.1.ok_or(Error::ChildFailed)?;
            if !libc::WIFSIGNALED(status)
                || libc::WTERMSIG(status) != libc::SIGKILL
                || std::fs::read(directory.join("records/namespaces.json"))
                    .map_err(|_| Error::Interrupted)?
                    != planned
                || journal_b.lab_attempt_released().is_ok()
            {
                return Err(Error::OwnershipMismatch);
            }
            witness = serde_json::json!({"case":label,"guard_pid":birth.pid,"guard_start":birth.start,
                "original_born_at":birth.born_at,"original_gate_deadline":birth.gate_deadline,
                "initial_birth_write_failed":true,"planned_bytes_unchanged":true,"guard_actual_wait_status":status,
                "guard_actual_reaped":true,"pending_native_drained":true,"journal_actual_drained":journal_b.native_drained(),
                "released":false,"wrong_member_journal_refused":true,"a_completed_at_drain":baseline,
                "a_completed_after_drain":final_count,"resumed":false,"component_only":true});
        }
        RetainedCase::Retirement { fault } => {
            label = match fault {
                0 => {
                    "actual_owner_consuming_retirement_original_native_cleanup_final_durable_reap_neighbor_progress"
                }
                1 => {
                    "actual_owner_retirement_queued_deadline_releases_only_own_slot_neighbor_mutation"
                }
                2 => {
                    "actual_owner_retirement_writer_poll_failure_actual_reap_retains_global_uncertainty"
                }
                3 => {
                    "actual_owner_retirement_original_a_dump_spans_b_removal_and_fresh_ticket_rejects_replay"
                }
                4 => {
                    "actual_owner_dropped_retirement_global_stop_retains_unconsumed_durable_authority"
                }
                _ => return Err(Error::InvalidSpec),
            };
            let mut owner_b = loop {
                if let Some(owner) = DeploymentOwner::new(
                    std::slice::from_mut(&mut owner_a),
                    std::slice::from_mut(&mut journal_a),
                )?
                .poll_admission(&mut pending, &mut journal_b)?
                {
                    break owner;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            if journal_b.lab_attempt_released()?
                != (birth.pid, birth.start, birth.born_at, birth.gate_deadline)
            {
                return Err(Error::OwnershipMismatch);
            }
            owner_b.install_expiry(
                prepared_expiry.take().ok_or(Error::OwnershipMismatch)?,
                &mut journal_b,
            );
            owner_b.install_host_audit(authority, &mut journal_b);
            loop {
                tick(&mut owner_a, &mut journal_a)?;
                DeploymentOwner::new(
                    std::slice::from_mut(&mut owner_b),
                    std::slice::from_mut(&mut journal_b),
                )?
                .poll_once()?;
                if owner_b.lab_expiry_all_transferred()
                    && journal_b.idle()
                    && journal_b.lab_expiry_registered().is_ok()
                {
                    break;
                }
                if let Some(reason) = owner_b.lab_terminal_reason() {
                    return Err(reason);
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let guard = owner_b.lab_guard_native_handle()?;
            let handles = owner_b.lab_executor_native_handles()?;
            let identities = journal_b.lab_expiry_registered()?;
            if handles.len() != 3 || owner_b.lab_executor_identities()? != identities {
                return Err(Error::OwnershipMismatch);
            }
            let b_host_index = b.lab_host_index()?;
            let b_host_alias = b.lab_host_alias();
            let mut owner_slot = Some(owner_b);
            let mut journal_slot = Some(journal_b);
            let mut transport_slot = Some(b);
            let mut retirement = loop {
                tick(&mut owner_a, &mut journal_a)?;
                if let Some(retirement) = super::owner::Retirement::try_begin(
                    &mut owner_slot,
                    &mut journal_slot,
                    &mut transport_slot,
                )? {
                    break retirement;
                }
                DeploymentOwner::new(
                    std::slice::from_mut(owner_slot.as_mut().ok_or(Error::OwnershipMismatch)?),
                    std::slice::from_mut(journal_slot.as_mut().ok_or(Error::OwnershipMismatch)?),
                )?
                .poll_once()?;
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            retirement.lab_inject_failure(if matches!(fault, 3 | 4) { 0 } else { fault })?;
            if fault == 4 {
                loop {
                    tick(&mut owner_a, &mut journal_a)?;
                    if retirement.lab_phase()? != "stop_authorized" {
                        retirement.poll()?;
                    }
                    if retirement.lab_phase()? == "stop_authorized"
                        && owner_a.lab_normal_idle()
                        && journal_a.idle()
                    {
                        break;
                    }
                    if vprouter_core::health::boot_seconds() >= end {
                        return Err(Error::Deadline);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                let (before, failure) = retirement.lab_unconsumed_stop_record()?;
                if failure.is_some() {
                    return Err(Error::OwnershipMismatch);
                }
                let retained = retirement.lab_retention_observer()?;
                let births = kernel::lab_native_births();
                drop(retirement);
                kernel::lab_queue_owner_stop()?;
                for _ in 0..3 {
                    DeploymentOwner::new(
                        std::slice::from_mut(&mut owner_a),
                        std::slice::from_mut(&mut journal_a),
                    )?
                    .poll_once()?;
                    let (after, failure) =
                        super::owner::Retirement::lab_retained_unconsumed_stop_record(&retained)?;
                    if before != after
                        || failure != Some(Error::Interrupted)
                        || kernel::lab_native_births() != births
                        || owner_a.lab_terminal_reason() != Some(Error::Interrupted)
                        || retained.upgrade().is_none()
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                }
                guard.lab_require_stopped(birth.start)?;
                // Explicit fixture containment of this original handle, AFTER
                // proving the dropped driver did not consume the stop permit.
                guard.lab_signal(libc::SIGKILL)?;
                guard.lab_wait_killed()?;
                let status = guard.lab_terminal_status()?.ok_or(Error::ChildFailed)?;
                if status != libc::SIGKILL {
                    return Err(Error::ChildFailed);
                }
                let mut expiry_statuses = Vec::new();
                for (handle, identity) in handles.iter().zip(&identities) {
                    if handle.lab_birth_identity()? != (identity.pid, identity.start_time)
                        || handle.lab_terminal_status()? != Some(122 << 8)
                    {
                        return Err(Error::ChildFailed);
                    }
                    expiry_statuses.push(122 << 8);
                }
                let (after, failure) =
                    super::owner::Retirement::lab_retained_unconsumed_stop_record(&retained)?;
                if before != after || failure != Some(Error::Interrupted) {
                    return Err(Error::OwnershipMismatch);
                }
                witness = serde_json::json!({"case":label,"guard_pid":birth.pid,"guard_start":birth.start,
                    "original_born_at":birth.born_at,"original_gate_deadline":birth.gate_deadline,
                    "guard_actual_wait_status":status,"expiry_identities":identities,"expiry_actual_wait_statuses":expiry_statuses,
                    "durable_retiring_before_drop":true,"real_sigterm_queued_after_drop":true,"retained_driver_polls":3,
                    "unconsumed_stop_permit_retained":true,"canonical_retiring_bytes_unchanged":true,
                    "canonical_service_reserved":true,"whole_failed_retirement_retained_after_drop":true,
                    "native_births_before_stop":births,"native_births_after_stop":kernel::lab_native_births(),
                    "existing_a_terminal_interrupted":true,"cleanup_or_reuse_authorized":false,
                    "inventory_corruption_tested":false,"expiry_signalled":false,"resumed":false,"component_only":true});
            } else if matches!(fault, 1 | 2) {
                let baseline = tick(&mut owner_a, &mut journal_a)?;
                let expected = if fault == 1 {
                    Error::Deadline
                } else {
                    Error::ChildFailed
                };
                let mut failed_at = None;
                let (snapshot, after_failure) = loop {
                    let count = tick(&mut owner_a, &mut journal_a)?;
                    match retirement.poll() {
                        Err(error) if error == expected => {
                            failed_at.get_or_insert(count);
                        }
                        Err(error) => return Err(error),
                        Ok(()) => {}
                    }
                    if failed_at.is_some_and(|at| count >= at + 3)
                        && owner_a.lab_normal_idle()
                        && journal_a.idle()
                        && let Ok(snapshot) = retirement.lab_failure_snapshot()
                    {
                        break (snapshot, count);
                    }
                    if vprouter_core::health::boot_seconds() >= end {
                        return Err(Error::Deadline);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                };
                if snapshot["queue_removed"] != true
                    || snapshot["service_reserved"] != true
                    || snapshot["uncertain_mutation_fence"] != (fault == 2)
                    || snapshot["canonical_pending_retained"] != (fault == 2)
                    || (fault == 2 && snapshot["writer_actual_wait_status"] != libc::SIGKILL)
                    || retirement.is_complete()?
                {
                    return Err(Error::OwnershipMismatch);
                }
                let a_start = owner_a.lab_stop()?;
                let a_guard = owner_a.lab_guard_native_handle()?;
                let mutation_at = vprouter_core::health::boot_seconds();
                let result = journal_a.start(
                    JournalRequest::BeginTerminal {
                        binding: journal_a.binding.clone(),
                        lifecycle: journal_a.lifecycle().into(),
                    },
                    &a_guard,
                    mutation_at,
                );
                let a_mutation = if fault == 1 {
                    result?;
                    loop {
                        if journal_a.poll(&a_guard)? {
                            break;
                        }
                        if vprouter_core::health::boot_seconds() >= mutation_at + 2. {
                            return Err(Error::Deadline);
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    if !journal_a.idle() || !journal_a.native_drained() {
                        return Err(Error::OwnershipMismatch);
                    }
                    true
                } else {
                    if result != Err(Error::LockBusy) {
                        return Err(Error::OwnershipMismatch);
                    }
                    false
                };
                owner_a.lab_stopped(a_start)?;
                guard.lab_signal(libc::SIGKILL)?;
                guard.lab_wait_killed()?;
                if guard.lab_terminal_status()? != Some(libc::SIGKILL) {
                    return Err(Error::ChildFailed);
                }
                let retained_driver = retirement.lab_retention_observer()?;
                drop(retirement);
                if retained_driver.upgrade().is_none()
                    || !journal_a
                        .transaction
                        .shared
                        .services
                        .borrow()
                        .contains(&second.exit.exit_id)
                {
                    return Err(Error::OwnershipMismatch);
                }
                witness = serde_json::json!({"case":label,"failure_kind":fault,"original_born_at":birth.born_at,"original_gate_deadline":birth.gate_deadline,
                    "guard_pid":birth.pid,"guard_start":birth.start,"guard_actual_wait_status":libc::SIGKILL,
                    "failure":snapshot,"whole_failed_retirement_retained_after_drop":true,
                    "a_completed_before_failure":baseline,"a_completed_at_failure":failed_at,"a_completed_after_failure":after_failure,
                    "a_next_mutation_actual_durable_reaped":a_mutation,"a_next_mutation_refused_by_uncertainty":!a_mutation,
                    "retirement_complete":false,"cleanup_or_reuse_authorized":false,"expiry_signalled":false,"resumed":false,"component_only":true});
            } else {
                retirement.lab_hold_links_writer()?;
                kernel::cleanup::lab_hold_next_links();
                let baseline = tick(&mut owner_a, &mut journal_a)?;
                let mut held_at = None;
                let mut released_at = None;
                let mut cleanup_start = None;
                let mut cleanup_end = None;
                let mut span_armed = false;
                let mut span = None;
                let mut span_released = false;
                let mut span_checkpoint_at = None;
                let mut span_released_at = None;
                let mut span_verified_at = None;
                let mut mixed_observation = None;
                let mut cleanup_native = None;
                let mut checkpoint_at = None;
                let mut checkpoint_released_at = None;
                let mut last_a_count = baseline;
                let run = (|| -> Result<()> {
                    loop {
                        let count = tick(&mut owner_a, &mut journal_a)?;
                        last_a_count = count;
                        if cleanup_native.is_none()
                            && let Some(snapshot) = retirement.lab_cleanup_snapshot()?
                        {
                            eprintln!(
                                "LAB_RETIREMENT_CLEANUP_TIMING {}",
                                serde_json::json!({
                                    "event":"launched", "observed_at":vprouter_core::health::boot_seconds(),
                                    "native":snapshot, "a_completed":count,
                                })
                            );
                            cleanup_native = Some(snapshot);
                        }
                        if retirement.lab_cleanup_checkpoint()? {
                            if checkpoint_at.is_none() {
                                checkpoint_at = Some(vprouter_core::health::boot_seconds());
                                eprintln!(
                                    "LAB_RETIREMENT_CLEANUP_TIMING {}",
                                    serde_json::json!({
                                        "event":"checkpoint", "observed_at":checkpoint_at,
                                        "native":cleanup_native, "a_completed":count,
                                    })
                                );
                            }
                            let at = *held_at.get_or_insert(count);
                            if fault == 3 {
                                if !span_armed {
                                    owner_a.lab_hold_next_host_links()?;
                                    span_armed = true;
                                }
                                if span.is_none() {
                                    span = owner_a.lab_host_links_checkpoint()?;
                                    if span.is_some() {
                                        span_checkpoint_at =
                                            Some(vprouter_core::health::boot_seconds());
                                    }
                                }
                                if span.is_some() && released_at.is_none() {
                                    retirement.lab_release_cleanup()?;
                                    released_at = Some(count);
                                    checkpoint_released_at =
                                        Some(vprouter_core::health::boot_seconds());
                                }
                            } else if released_at.is_none() && count >= at + 3 {
                                retirement.lab_release_cleanup()?;
                                released_at = Some(count);
                                checkpoint_released_at =
                                    Some(vprouter_core::health::boot_seconds());
                            }
                        }
                        if retirement.lab_links_pending()? && cleanup_start.is_none() {
                            cleanup_start = Some(count);
                        }
                        retirement.poll()?;
                        if cleanup_start.is_some()
                            && retirement.lab_links_finished()?
                            && cleanup_end.is_none()
                        {
                            cleanup_end = Some(count);
                        }
                        if fault == 3 && retirement.lab_links_finished()? && !span_released {
                            owner_a
                                .lab_release_host_links(span.ok_or(Error::OwnershipMismatch)?)?;
                            span_released = true;
                            span_released_at = Some(vprouter_core::health::boot_seconds());
                        }
                        if let Some((_, _, sequence, _)) = span
                            && mixed_observation.is_none()
                            && let Some(observation) = owner_a.lab_host_observation(sequence)?
                        {
                            if observation.sequence != sequence
                                || span.is_none_or(|original| original.3 != observation.sent_at)
                                || !observation.verified_at.is_finite()
                                || observation.verified_at < observation.sent_at
                                || observation.verified_at >= observation.sent_at + 2.
                            {
                                return Err(Error::OwnershipMismatch);
                            }
                            span_verified_at = Some(observation.verified_at);
                            mixed_observation = Some(observation.bytes);
                        }
                        if retirement.is_complete()? && (fault != 3 || mixed_observation.is_some())
                        {
                            break;
                        }
                        if vprouter_core::health::boot_seconds() >= end {
                            eprintln!(
                                "LAB_RETIREMENT_FAILURE phase={} reason=fixture_deadline",
                                retirement.lab_phase()?
                            );
                            return Err(Error::Deadline);
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Ok(())
                })();
                if let Err(error) = run {
                    // At most one failure record. No re-poll/reap or extra native
                    // probe: retain the exact operation's existing cached facts.
                    eprintln!(
                        "LAB_RETIREMENT_CLEANUP_TIMING {}",
                        serde_json::json!({
                            "event":"failure", "phase":retirement.lab_phase()?, "reason":error.to_string(),
                            "observed_at":vprouter_core::health::boot_seconds(),
                            "native":retirement.lab_cleanup_snapshot()?.or(cleanup_native),
                            "checkpoint_at":checkpoint_at, "checkpoint_released_at":checkpoint_released_at,
                            "a_at_checkpoint":held_at, "a_at_release":released_at, "a_last_completed":last_a_count,
                        })
                    );
                    return Err(error);
                }
                eprintln!(
                    "LAB_RETIREMENT_CLEANUP_TIMING {}",
                    serde_json::json!({
                        "event":"completed", "observed_at":vprouter_core::health::boot_seconds(),
                        "native":cleanup_native, "checkpoint_at":checkpoint_at,
                        "checkpoint_released_at":checkpoint_released_at,
                        "a_at_checkpoint":held_at, "a_at_release":released_at,
                    })
                );
                if held_at.is_none()
                    || (fault != 3
                        && released_at.is_none_or(|count| {
                            count < held_at.unwrap_or(u64::MAX).saturating_add(3)
                        }))
                {
                    return Err(Error::OwnershipMismatch);
                }
                if fault == 3 {
                    let (_, _, _, sent) = span.ok_or(Error::OwnershipMismatch)?;
                    let checkpoint = span_checkpoint_at.ok_or(Error::OwnershipMismatch)?;
                    let released = span_released_at.ok_or(Error::OwnershipMismatch)?;
                    let verified = span_verified_at.ok_or(Error::OwnershipMismatch)?;
                    if !checkpoint.is_finite()
                        || !released.is_finite()
                        || !verified.is_finite()
                        || checkpoint < sent
                        || released < checkpoint
                        || verified < released
                        || verified >= sent + 2.
                    {
                        return Err(Error::Deadline);
                    }
                    let bytes = mixed_observation.as_ref().ok_or(Error::OwnershipMismatch)?;
                    lab_host_shape_presence(bytes, b_host_index, &b_host_alias, true)?;
                    owner_a.lab_reject_mixed_replay(bytes)?;
                }
                let final_record = retirement.lab_completed_record()?;
                let links_writer = retirement.lab_links_writer_receipt()?;
                let guard_status = guard.lab_terminal_status()?.ok_or(Error::ChildFailed)?;
                let mut expiry_statuses = Vec::new();
                for (handle, identity) in handles.iter().zip(&identities) {
                    if handle.lab_birth_identity()? != (identity.pid, identity.start_time) {
                        return Err(Error::OwnershipMismatch);
                    }
                    let status = handle.lab_terminal_status()?.ok_or(Error::ChildFailed)?;
                    if status != 122 << 8 {
                        return Err(Error::ChildFailed);
                    }
                    expiry_statuses.push(status);
                }
                if guard_status != libc::SIGKILL
                    || owner_slot.is_some()
                    || journal_slot.is_some()
                    || transport_slot.is_some()
                {
                    return Err(Error::OwnershipMismatch);
                }
                drop(retirement);
                let after_retired = tick(&mut owner_a, &mut journal_a)?;
                let final_count = loop {
                    let count = tick(&mut owner_a, &mut journal_a)?;
                    if count >= after_retired + 3 {
                        break count;
                    }
                    if vprouter_core::health::boot_seconds() >= end {
                        return Err(Error::Deadline);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                };
                let mut fresh_span_job = None;
                if let Some((_, _, sequence, _)) = span {
                    let fresh = owner_a
                        .lab_host_observation(sequence + 1)?
                        .ok_or(Error::OwnershipMismatch)?;
                    if fresh.sequence <= sequence
                        || !fresh.sent_at.is_finite()
                        || !fresh.verified_at.is_finite()
                        || fresh.verified_at < fresh.sent_at
                        || fresh.verified_at >= fresh.sent_at + 2.
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                    lab_host_shape_presence(&fresh.bytes, b_host_index, &b_host_alias, false)?;
                    fresh_span_job = Some((fresh.sequence, fresh.sent_at, fresh.verified_at));
                }
                witness = serde_json::json!({"case":label,"guard_pid":birth.pid,"guard_start":birth.start,
                "original_born_at":birth.born_at,"original_gate_deadline":birth.gate_deadline,
                "guard_actual_wait_status":guard_status,"expiry_identities":identities,"expiry_actual_wait_statuses":expiry_statuses,
                "final_record":final_record,"links_removed_writer":links_writer,"final_writer_actual_reaped":true,"canonical_service_retained_through_final_reap":true,
                "original_producer_unlinked_by_bound_helper":true,"original_guard_scope_removed":true,
                "a_completed_before_retirement":baseline,"a_completed_at_native_cleanup_hold":held_at,"a_completed_before_native_cleanup_release":released_at,"a_completed_at_cleanup_start":cleanup_start,"a_completed_at_cleanup_end":cleanup_end,
                "a_completed_after_retirement":after_retired,"a_completed_after_final_reap":final_count,
                "namespaces_and_quarantine_retained":true,"operational_reuse_authorized":false,"producer_live_stop_proven":false,
                "a_dump_spans_host_removal_proven":fault == 3,"a_span_original_job":span,
                "a_span_checkpoint_at":span_checkpoint_at,"a_span_released_at":span_released_at,"a_span_verified_at":span_verified_at,"fresh_a_job":fresh_span_job,"b_original_host_index":b_host_index,"b_original_host_alias":b_host_alias,
                "a_mixed_observation_verified":mixed_observation.is_some(),"fresh_a_replay_refused":fault == 3,"expiry_signalled":false,"resumed":false,"component_only":true});
            }
        }
        RetainedCase::ExpiryDrop { partial } => {
            label = if partial {
                "actual_owner_partial_expiry_birth_drop_retains_original_native_context_without_signal"
            } else {
                "actual_owner_registered_expiry_drop_retains_three_original_completions_and_native_reaps"
            };
            let mut owner_b = loop {
                if let Some(owner) = DeploymentOwner::new(
                    std::slice::from_mut(&mut owner_a),
                    std::slice::from_mut(&mut journal_a),
                )?
                .poll_admission(&mut pending, &mut journal_b)?
                {
                    break owner;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            if journal_b.lab_attempt_released()?
                != (birth.pid, birth.start, birth.born_at, birth.gate_deadline)
            {
                return Err(Error::OwnershipMismatch);
            }
            owner_b.install_expiry(
                prepared_expiry.take().ok_or(Error::OwnershipMismatch)?,
                &mut journal_b,
            );
            // bind_remote performs the same fresh host audit as other owner
            // paths before it can request any independent expiry actor.
            owner_b.install_host_audit(authority, &mut journal_b);
            if partial {
                kernel::lab_fail_next_terminal_parent();
            }
            let mut partial_actor = None;
            loop {
                tick(&mut owner_a, &mut journal_a)?;
                DeploymentOwner::new(
                    std::slice::from_mut(&mut owner_b),
                    std::slice::from_mut(&mut journal_b),
                )?
                .poll_once()?;
                if partial {
                    if let Ok(actor) = kernel::lab_terminal_birth(&domains_b, 0) {
                        if !actor.2 {
                            return Err(Error::OwnershipMismatch);
                        }
                        partial_actor = Some(actor);
                        break;
                    }
                } else if owner_b.lab_expiry_all_transferred()
                    && journal_b.idle()
                    && journal_b.lab_expiry_registered().is_ok()
                {
                    break;
                }
                // The intended partial-constructor receipt is recognized above
                // first. Any other terminal outcome must retain its first cause.
                if let Some(reason) = owner_b.lab_terminal_reason() {
                    eprintln!(
                        "LAB_EXPIRY_DROP_FAILURE phase=registration partial={partial} reason={reason}"
                    );
                    return Err(reason);
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let guard = owner_b.lab_guard_native_handle()?;
            let (guard_drain, removed_scope) = owner_b.lab_guard_removed_scope_witness()?;
            if guard.lab_birth_identity()? != (birth.pid, birth.start) {
                return Err(Error::OwnershipMismatch);
            }
            let identities = owner_b.lab_executor_identities()?;
            let handles = if partial {
                Vec::new()
            } else {
                owner_b.lab_executor_native_handles()?
            };
            if !partial
                && (handles.len() != 3
                    || identities.len() != 3
                    || journal_b.lab_expiry_registered()? != identities)
            {
                return Err(Error::OwnershipMismatch);
            }
            for (handle, identity) in handles.iter().zip(&identities) {
                handle.require_live()?;
                if handle.lab_birth_identity()? != (identity.pid, identity.start_time) {
                    return Err(Error::OwnershipMismatch);
                }
            }
            let baseline = tick(&mut owner_a, &mut journal_a)?;
            eprintln!("LAB_EXPIRY_DROP_PHASE phase=before_drop partial={partial}");
            drop(owner_b);
            journal_b.fence()?;
            eprintln!("LAB_EXPIRY_DROP_PHASE phase=initial_retained_snapshot partial={partial}");
            let after_drop = if partial {
                serde_json::Value::Null
            } else {
                super::expiry::lab_retained_expiry(&domains_b)?
            };
            let mut final_expiry = serde_json::Value::Null;
            let mut actor_status = None;
            eprintln!("LAB_EXPIRY_DROP_PHASE phase=polling_retained_snapshot partial={partial}");
            let final_count = loop {
                let count = tick(&mut owner_a, &mut journal_a)?;
                journal_b.poll_terminal_io()?;
                let drained = if let Some((actor, _, _)) = &partial_actor {
                    let complete = actor.reap_exited()?;
                    if complete {
                        actor_status = actor.lab_terminal_status()?;
                    }
                    complete
                } else {
                    final_expiry = super::expiry::lab_retained_expiry(&domains_b)?;
                    final_expiry["all_actual_reaped"] == true
                };
                if drained && journal_b.native_drained() && count >= baseline + 3 {
                    break count;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let partial_identity;
            let original_started_at;
            if let Some((actor, started_at, failed)) = &partial_actor {
                partial_identity = Some(actor.lab_birth_identity()?);
                original_started_at = *started_at;
                let retained = kernel::lab_terminal_birth(&domains_b, 0)?;
                if !*failed
                    || !retained.2
                    || retained.0.lab_birth_identity()? != actor.lab_birth_identity()?
                    || actor_status != Some(122 << 8)
                    || kernel::terminal_births_drained(
                        domains_b.allocation(),
                        domains_b.exit_id(),
                        domains_b.lifecycle(),
                    )
                {
                    return Err(Error::OwnershipMismatch);
                }
            } else {
                partial_identity = None;
                original_started_at = final_expiry["original_started_at"]
                    .as_f64()
                    .ok_or(Error::OwnershipMismatch)?;
                if final_expiry["failure"] != serde_json::Value::Null
                    || final_expiry["completions"]
                        .as_array()
                        .is_none_or(|receipts| receipts.len() != 3)
                {
                    return Err(Error::OwnershipMismatch);
                }
                for actor in final_expiry["actors"]
                    .as_array()
                    .ok_or(Error::OwnershipMismatch)?
                {
                    if actor["actual_wait_status"] != 122 << 8 || actor["no_live_tasks"] != true {
                        return Err(Error::OwnershipMismatch);
                    }
                }
                for receipt in final_expiry["completions"]
                    .as_array()
                    .ok_or(Error::OwnershipMismatch)?
                {
                    let receipt: ExecutorCompletion = serde_json::from_value(receipt.clone())
                        .map_err(|_| Error::OwnershipMismatch)?;
                    if receipt.result != TerminalResult::VerifiedBeforeDeadline
                        || !identities.contains(&receipt.identity)
                    {
                        return Err(Error::OwnershipMismatch);
                    }
                }
            }
            // Only the original stopped guard is explicitly killed for fixture
            // shutdown. No signal has been sent to any independent expiry actor.
            let stop_end = vprouter_core::health::boot_seconds() + 2.;
            while guard.lab_require_stopped(birth.start).is_err() {
                tick(&mut owner_a, &mut journal_a)?;
                if vprouter_core::health::boot_seconds() >= stop_end {
                    return Err(Error::Deadline);
                }
            }
            guard.lab_signal(libc::SIGKILL)?;
            guard.lab_wait_killed()?;
            loop {
                tick(&mut owner_a, &mut journal_a)?;
                if guard_drain.drained()? {
                    break;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if !removed_scope.get()
                || journal_b.lab_terminal_completions() != 0
                || !journal_b.native_drained()
            {
                return Err(Error::OwnershipMismatch);
            }
            witness = serde_json::json!({"case":label,"partial":partial,"guard_pid":birth.pid,"guard_start":birth.start,
                "original_born_at":birth.born_at,"original_gate_deadline":birth.gate_deadline,"durable_released_before_drop":true,
                "original_expiry_started_at":original_started_at,"partial_actor_identity":partial_identity,"partial_actor_wait_status":actor_status,
                "registered_identities":identities,"retained_after_drop":after_drop,"retained_after_reap":final_expiry,
                "original_native_context_retained":true,"b_journal_native_drained":true,"canonical_completion_count":0,
                "canonical_registered_acknowledged_before_drop":!partial,"partial_birth_failed_before_return":partial,
                "guard_removed_original_scope_observed":true,"guard_bundle_drained":true,"expiry_signal_sent":false,"resumed":false,"canonical_completion_claimed":false,
                "guard_actual_wait_status":guard.lab_terminal_status()?,"guard_actual_reaped":true,
                "a_completed_before_drop":baseline,"a_completed_after_drop":final_count,"cleanup_or_reuse_authorized":false,"component_only":true});
        }
        RetainedCase::Drop => {
            label = "actual_owner_retained_host_audit_and_managed_guard_drop_original_receipts_neighbor_progress";
            if pending.lab_failure_status()?.0.is_some() {
                return Err(Error::OwnershipMismatch);
            }
            let mut owner_b = loop {
                if let Some(owner) = DeploymentOwner::new(
                    std::slice::from_mut(&mut owner_a),
                    std::slice::from_mut(&mut journal_a),
                )?
                .poll_admission(&mut pending, &mut journal_b)?
                {
                    break owner;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            if journal_b.lab_attempt_released()?
                != (birth.pid, birth.start, birth.born_at, birth.gate_deadline)
            {
                return Err(Error::OwnershipMismatch);
            }
            owner_b.install_host_audit(authority, &mut journal_b);
            let mut pause = false;
            let held = loop {
                tick(&mut owner_a, &mut journal_a)?;
                let mut deployment = DeploymentOwner::new(
                    std::slice::from_mut(&mut owner_b),
                    std::slice::from_mut(&mut journal_b),
                )?;
                deployment.poll_once()?;
                if deployment.lab_terminal(0).is_some() {
                    return Err(Error::ChildFailed);
                }
                if !pause && deployment.lab_host_completed(0) >= 2 {
                    deployment.lab_pause_host(0)?;
                    pause = true;
                }
                if pause && let Some(held) = deployment.lab_host_checkpoint(0)? {
                    break held;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            let window = owner_b.lab_host_window()?;
            let (guard_drain, guard, audit, sequence, deadline) =
                owner_b.lab_native_drop_witness()?;
            if held != (audit.pid(), audit.start_time()?, deadline) {
                return Err(Error::OwnershipMismatch);
            }
            audit.lab_require_stopped(held.1)?;
            let guard_start = guard.start_time()?;
            if (guard.pid(), guard_start) != (birth.pid, birth.start) {
                return Err(Error::OwnershipMismatch);
            }
            let baseline = tick(&mut owner_a, &mut journal_a)?;
            drop(owner_b);
            // Before any collector turn all original descriptors, context and
            // counted holds must still be owned by the retired native bundles.
            let (retained_deadline, hold_count) = kernel::host_audit::lab_retained(&audit)?;
            if retained_deadline != deadline || hold_count == 0 || window.upgrade().is_none() {
                return Err(Error::OwnershipMismatch);
            }
            kernel::lab_retained_guard(&guard)?;
            audit.lab_wait_killed()?;
            if kernel::host_audit::lab_retained(&audit)? != (deadline, hold_count)
                || window.upgrade().is_none()
            {
                return Err(Error::OwnershipMismatch);
            }
            let final_count = loop {
                let count = tick(&mut owner_a, &mut journal_a)?;
                journal_b.poll_terminal_io()?;
                if count >= baseline + 3 && kernel::host_audit::retired_drained() {
                    break count;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            if window.upgrade().is_some() {
                return Err(Error::OwnershipMismatch);
            }
            // A real postclone failure has no returned HostAuditChild. Its native
            // constructor collector must still own the exact accepted model window.
            let sent = vprouter_core::health::boot_seconds();
            let ticket = authority
                .begin_audit_at(&journal_b.host_allocation(), journal_b.exit_id(), sent)
                .map_err(|_| Error::OwnershipMismatch)?;
            let ticket = std::rc::Rc::new(std::cell::RefCell::new(ticket));
            let weak = std::rc::Rc::downgrade(&ticket);
            let lease = journal_b.host_job_lease(
                journal_b.allocation(),
                journal_b.exit_id(),
                journal_b.lifecycle(),
            )?;
            let before_job = journal_b.transaction.shared.native_jobs.borrow().next;
            kernel::host_audit::lab_fail_next_parent()?;
            if !matches!(
                kernel::host_audit::spawn(
                    journal_b.host_directory()?,
                    lease,
                    Some(ticket),
                    sent + 2.,
                    false,
                    true,
                    false
                ),
                Err(Error::DescriptorInventory)
            ) {
                return Err(Error::OwnershipMismatch);
            }
            let receipt = {
                let jobs = journal_b.transaction.shared.native_jobs.borrow();
                if jobs.next != before_job + 1 {
                    return Err(Error::OwnershipMismatch);
                }
                jobs.pending
                    .get(&jobs.next)
                    .ok_or(Error::OwnershipMismatch)?
                    .1
                    .clone()
            };
            if weak.upgrade().is_none() || receipt.complete()? || journal_b.native_drained() {
                return Err(Error::OwnershipMismatch);
            }
            loop {
                tick(&mut owner_a, &mut journal_a)?;
                if receipt.lab_collected()? {
                    break;
                }
                if vprouter_core::health::boot_seconds() >= sent + 2. {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            if weak.upgrade().is_some() || !journal_b.native_drained() {
                return Err(Error::OwnershipMismatch);
            }
            guard.lab_require_stopped(guard_start)?;
            kernel::lab_retained_guard(&guard)?;
            // Explicit test shutdown, never a ManagedGuard Drop kill/resume.
            guard.lab_signal(libc::SIGKILL)?;
            guard.lab_wait_killed()?;
            kernel::poll_early_forks()?;
            let guard_bundle_drained = guard_drain.drained()?;
            if !guard_bundle_drained {
                kernel::lab_retained_guard(&guard)?;
            }
            let guard_status = guard.lab_terminal_status()?.ok_or(Error::ChildFailed)?;
            let audit_status = audit.lab_terminal_status()?.ok_or(Error::ChildFailed)?;
            witness = serde_json::json!({"case":label,"guard_pid":guard.pid(),"guard_start":guard_start,
                "original_born_at":birth.born_at,"original_gate_deadline":birth.gate_deadline,"durable_released_before_drop":true,
                "audit_pid":held.0,"audit_start":held.1,"audit_native_stopped":true,
                "original_sequence":sequence,"original_deadline":deadline,"audit_actual_wait_status":audit_status,
                "guard_actual_wait_status":guard_status,"audit_actual_reaped":true,"guard_actual_reaped":true,
                "audit_hold_count_after_drop_and_reap":hold_count,"audit_bundle_collected":true,
                "host_window_retained_after_drop_and_reap":true,"host_window_released_only_after_collection":true,
                "host_window_postclone_failure_retained":true,"host_window_postclone_actual_collection_released":true,
                "guard_bundle_drained":guard_bundle_drained,"uncertain_scope_bundle_retained":!guard_bundle_drained,
                "private_owner_ipc_revoked":true,"ack_sent":false,"resumed":false,
                "wrong_member_journal_refused":true,"a_completed_before_drop":baseline,
                "a_completed_after_drop":final_count,"cleanup_or_reuse_authorized":false,"component_only":true});
        }
    }
    let start = owner_a.lab_stop()?;
    owner_a.lab_kill_stopped(start)?;
    loop {
        DeploymentOwner::new(
            std::slice::from_mut(&mut owner_a),
            std::slice::from_mut(&mut journal_a),
        )?
        .poll_once()?;
        if owner_a.lab_terminal_native_drained() && journal_a.native_drained() {
            break;
        }
        if vprouter_core::health::boot_seconds() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    witness["a_native_io_drained"] = serde_json::json!(true);
    println!("{witness}");
    super::lab::case(label);
    Ok(())
}

#[cfg(test)]
pub(super) fn lab_bootstrap_mutations<'a>(
    first: &LaunchSpec,
    second: &LaunchSpec,
    a: &super::transport::GuardTransport<'a>,
    b: &super::transport::GuardTransport<'a>,
    cfg: &vprouter_core::config::ValidatedConfiguration,
    nonce: &str,
) -> Result<()> {
    let (tx_a, ns_a) = a.lab_journal_parts();
    let (tx_b, ns_b) = b.lab_journal_parts();
    let domains_a = super::supervision::Domains::new(first, nonce)?;
    let domains_b = super::supervision::Domains::new(
        second,
        &vprouter_worker::bootstrap::digest(format!("bootstrap-neighbor:{nonce}").as_bytes()),
    )?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::InvalidSpec)?;
    let binding_a = vprouter_linux::status::expected_binding(cfg, 0, first.generation, boot.trim())
        .map_err(|_| Error::InvalidSpec)?;
    let binding_b =
        vprouter_linux::status::expected_binding(cfg, 1, second.generation, boot.trim())
            .map_err(|_| Error::InvalidSpec)?;
    let mut journals = [
        JournalServer::new(tx_a, first, ns_a, domains_a.clone(), binding_a.clone())?,
        JournalServer::new(tx_b, second, ns_b, domains_b.clone(), binding_b.clone())?,
    ];
    for journal in &mut journals {
        journal.pause_next_write = true;
    }
    let owner_a = super::owner::ExternalOwner::spawn(
        domains_a.clone(),
        super::inventory::GuardInputs::for_domains(&domains_a)?,
        |owner| {
            let remote = tx_a.fork_remote(first, owner)?;
            remote.begin_terminal(first, binding_a.clone(), owner.domains().lifecycle())?;
            remote.revalidate(first)?;
            remote.revalidate(first)
        },
    )?;
    let owner_b = super::owner::ExternalOwner::spawn(
        domains_b.clone(),
        super::inventory::GuardInputs::for_domains(&domains_b)?,
        |owner| {
            let remote = tx_b.fork_remote(second, owner)?;
            remote.begin_terminal(second, binding_b.clone(), owner.domains().lifecycle())?;
            remote.revalidate(second)?;
            remote.revalidate(second)
        },
    )?;
    let identities = [owner_a.lab_identity()?, owner_b.lab_identity()?];
    let mut owners = [owner_a, owner_b];
    let mut frames = [None, None];
    let mut releases = [None, None];
    let mut order = Vec::new();
    {
        let mut deployment = super::owner::DeploymentOwner::new(&mut owners, &mut journals)?;
        let end = vprouter_core::health::boot_seconds() + 6.;
        loop {
            let done = deployment.poll_once()?;
            for index in 0..2 {
                if releases[index].is_none() && deployment.lab_write_checkpoint(index)? {
                    let other = 1 - index;
                    if order.is_empty() {
                        if !deployment.lab_queued(other) {
                            continue;
                        }
                        frames[index] = deployment.lab_pending_frame(index);
                        frames[other] = deployment.lab_pending_frame(other);
                    } else if deployment.lab_pending_frame(index) != frames[index] {
                        return Err(Error::DescriptorPolicy);
                    }
                    let frame = frames[index].ok_or(Error::DescriptorPolicy)?;
                    if frame.0 != 3 {
                        return Err(Error::DescriptorPolicy);
                    }
                    original_frame(frame.1, vprouter_core::health::boot_seconds())?;
                    deployment.lab_release_write(index)?;
                    releases[index] = Some(vprouter_core::health::boot_seconds());
                    order.push(index);
                }
            }
            if done {
                break;
            }
            if vprouter_core::health::boot_seconds() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    if order.len() != 2
        || tx_a.shared.fenced.get()
        || tx_a.shared.pending.borrow().is_some()
        || !tx_a.shared.queue.borrow().0.is_empty()
        || !tx_a.shared.reads.borrow().0.is_empty()
    {
        return Err(Error::OwnershipMismatch);
    }
    for (index, (owner, journal)) in owners.iter().zip(journals.iter_mut()).enumerate() {
        owner.lab_reap_success()?;
        if journal.completed != 4 || !journal.drain()? {
            return Err(Error::OwnershipMismatch);
        }
        let record = &tx_a.shared.journal.borrow().record;
        let entry = record
            .entries
            .iter()
            .find(|e| e.exit_id == journal.exit_id())
            .ok_or(Error::OwnershipMismatch)?;
        let terminal = entry.terminal.as_ref().ok_or(Error::OwnershipMismatch)?;
        terminal.validate(record, entry)?;
        if (terminal.guard_pid, terminal.guard_start) != identities[index]
            || !terminal.executors.is_empty()
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    // Independent final strict disk readback, after both durable child ACKs and
    // guard EXIT0/reaps. RAM inspection alone cannot establish persistence.
    let disk_digest = {
        let journal = tx_a.shared.journal.borrow();
        let fd = fs::openat(&journal.dir, "namespaces.json", RD, Mode::empty())
            .map_err(|_| Error::OwnershipMismatch)?;
        file_check(&fd)?;
        let mut bytes = Vec::new();
        File::from(fd)
            .take(262145)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Interrupted)?;
        if bytes.len() > 262144 || bytes != encode_record(&journal.record)? {
            return Err(Error::OwnershipMismatch);
        }
        let disk: Record = serde_json::from_slice(&bytes).map_err(|_| Error::OwnershipMismatch)?;
        disk.bind(
            first,
            &journal.record.primary_exit_id,
            journal.record.primary_network()?,
        )?;
        disk.bind(
            second,
            &journal.record.primary_exit_id,
            journal.record.primary_network()?,
        )?;
        for (spec, identity) in [first, second].into_iter().zip(identities) {
            let entry = disk
                .entries
                .iter()
                .find(|e| e.exit_id == spec.exit.exit_id)
                .ok_or(Error::OwnershipMismatch)?;
            let terminal = entry.terminal.as_ref().ok_or(Error::OwnershipMismatch)?;
            terminal.validate(&disk, entry)?;
            if (terminal.guard_pid, terminal.guard_start) != identity {
                return Err(Error::OwnershipMismatch);
            }
        }
        vprouter_linux::sha256(&bytes)
    };
    let completions = [
        journals[0].mutation_completion,
        journals[1].mutation_completion,
    ];
    for index in 0..2 {
        let (deadline, finished) = completions[index].ok_or(Error::Interrupted)?;
        let (_, sent_at) = frames[index].ok_or(Error::Interrupted)?;
        if deadline != sent_at + 2. || finished >= deadline {
            return Err(Error::Deadline);
        }
    }
    println!(
        "{}",
        serde_json::json!({"case":"actual_two_bootstrap_guards_overlapping_legal_begin_terminal_fifo_original_frames_durable_ack_and_exit0", "guard_identities":identities, "original_frames":frames,"durable_completions":completions,"strict_disk_sha256":disk_digest,"writer_release_times":releases,"fifo_order":order,"component_only":true,"provider_acceptance":false,"routed_neighbor_acceptance":false})
    );
    Ok(())
}
#[cfg(test)]
pub(super) fn lab_expected_journal_end(reason: Error, completed: u64) -> Result<()> {
    if !matches!(reason, Error::ChildFailed | Error::DescriptorPolicy) || completed != 3 {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn lab_owner_journal() -> Result<()> {
    use std::{
        os::unix::fs::DirBuilderExt,
        time::{Duration, Instant},
    };
    let bytes = vprouter_linux::storage::read(
        Path::new("/var/lib/vprouter-v2-lab/owner-domain-nonce"),
        vprouter_linux::storage::Kind::SecretFile,
        64,
    )
    .map_err(|_| Error::LabRequired)?;
    let lifecycle = std::str::from_utf8(&bytes).map_err(|_| Error::LabRequired)?;
    let (spec, _) = super::tests::fixture();
    let domains = super::supervision::Domains::new(&spec, lifecycle)?;
    domains.verify_owner()?;
    let path = Path::new("/var/lib/vprouter-v2-lab").join(format!("owner-journal-{lifecycle}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| Error::OwnershipMismatch)?;
    let store = AllocationStore::open(&path, &spec.allocation.deployment_id)
        .map_err(|_| Error::OwnershipMismatch)?;
    store
        .lock()
        .map_err(|_| Error::LockBusy)?
        .commit(None, &spec.allocation)
        .map_err(|_| Error::OwnershipMismatch)?;
    let base = fs::open(
        "/proc/self/ns/net",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::NamespaceMismatch)?;
    let _base = super::inventory::Registration::owned(&[base.as_fd()])?;
    let mut transaction = Transaction::open(&store, &path, &spec, "one", &base)?;
    let namespaces = transaction.acquire(&spec, &base)?;
    let before = std::fs::read(path.join("namespaces.json")).map_err(|_| Error::Interrupted)?;
    let copy = kernel::lab_terminal_guard(|ready| {
        if transaction.shared.journal.borrow().persist().err() != Some(Error::OwnershipMismatch)
            || transaction.revalidate(&spec).err() != Some(Error::OwnershipMismatch)
            || transaction.for_exit(&spec).err() != Some(Error::OwnershipMismatch)
        {
            return Err(Error::OwnershipMismatch);
        }
        kernel::lab_terminal_checkpoint(ready)?;
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    })?;
    if std::fs::read(path.join("namespaces.json")).map_err(|_| Error::Interrupted)? != before {
        return Err(Error::OwnershipMismatch);
    }
    copy.lab_signal(libc::SIGKILL)?;
    copy.lab_wait_killed()?;
    drop(copy);
    super::lab::case("actual_fork_copied_journal_creator_pid_refuses_write_lease_and_revalidate");
    let cfg = super::transport_lab::health_configuration(&spec)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::InvalidSpec)?;
    let binding = vprouter_linux::status::expected_binding(&cfg, 0, spec.generation, boot.trim())
        .map_err(|_| Error::InvalidSpec)?;
    let mut service =
        JournalServer::new(&transaction, &spec, &namespaces, domains.clone(), binding)?;
    let owner = super::owner::ExternalOwner::spawn(
        domains.clone(),
        super::inventory::GuardInputs::for_domains(&domains)?,
        |owner| {
            let remote = transaction.fork_remote(&spec, owner)?;
            remote.revalidate(&spec)?;
            remote.require_no_executors(&spec)
        },
    )?;
    let terminal = owner.supervise_journal(&mut service)?;
    eprintln!(
        "LAB_JOURNAL_TERMINAL reason={} completed={}",
        terminal.reason, service.completed
    );
    if !service.drain()? {
        return Err(Error::DescriptorPolicy);
    }
    // Independent retained pidfd + waitpid EXITED(0), never terminal reason alone.
    terminal.lab_reap_exited()?;
    lab_expected_journal_end(terminal.reason, service.completed)?;
    drop(terminal);
    drop(service);
    super::lab::case(
        "actual_gated_guard_owner_journal_rpc_three_fresh_isolated_read_jobs_no_stale_rc_write",
    );
    let make = |pause, after, end| JournalIo {
        allocation: spec.allocation.clone(),
        before: before.clone(),
        after,
        deadline: end,
        pause_before_sync: pause,
        pause_before_read: false,
        lab_stage: std::cell::Cell::new(0),
    };
    let launch = |job: &JournalIo| -> Result<kernel::JournalChild> {
        let journal = transaction.shared.journal.borrow();
        let directory = rustix::io::fcntl_dupfd_cloexec(&journal.dir, 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let lease = transaction.retain_mutator_lease(&spec)?;
        kernel::spawn_journal_io(directory, lease, job)
    };
    // Positive durability path, separate from the never-resumed stall. The
    // canonical record is identical; inode replacement proves actual rename.
    {
        use std::os::unix::fs::MetadataExt;
        let old = std::fs::metadata(path.join("namespaces.json"))
            .map_err(|_| Error::OwnershipMismatch)?;
        let end = vprouter_core::health::boot_seconds() + 2.;
        let mut positive = launch(&make(false, Some(before.clone()), end))?;
        positive.start()?;
        loop {
            if vprouter_core::health::boot_seconds() >= end {
                positive.cancel()?;
                return Err(Error::Deadline);
            }
            match positive.poll()? {
                Some(true) => break,
                Some(false) => return Err(Error::ChildFailed),
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        let record = fs::open(path.join("namespaces.json"), RD, Mode::empty())
            .map_err(|_| Error::OwnershipMismatch)?;
        file_check(&record)?;
        let new = Identity::of(&record)?;
        if !positive.drained()
            || new.dev != old.dev()
            || new.ino == old.ino()
            || std::fs::read(path.join("namespaces.json")).map_err(|_| Error::Interrupted)?
                != before
            || path
                .join(".owner-journal.pending")
                .try_exists()
                .map_err(|_| Error::Interrupted)?
            || vprouter_core::health::boot_seconds() >= end
        {
            return Err(Error::OwnershipMismatch);
        }
        println!(
            "{}",
            serde_json::json!({"case":"actual_confined_journal_write_fsync_atomic_rename_directory_fsync_ack_exit0_exact_readback", "old_inode":old.ino(), "new_inode":new.ino, "original_deadline":end, "finished_at":vprouter_core::health::boot_seconds(), "component_only":true})
        );
    }
    let original_end = vprouter_core::health::boot_seconds() + 2.;
    let mut writer = launch(&make(true, Some(before.clone()), original_end))?;
    writer.start()?;
    let until = Instant::now() + Duration::from_secs(1);
    let (pid, start) = loop {
        if let Some(identity) = writer.lab_stop_at_checkpoint()? {
            break identity;
        }
        if Instant::now() >= until {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    {
        use std::os::unix::fs::MetadataExt;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|_| Error::ProcessUnavailable)?;
        for (field, expected) in [
            ("Uid:", "0 0 0 0"),
            ("Gid:", "0 0 0 0"),
            ("Groups:", ""),
            ("NoNewPrivs:", "1"),
            ("Seccomp:", "2"),
            ("CapInh:", "0000000000000000"),
            ("CapPrm:", "0000000000000000"),
            ("CapEff:", "0000000000000000"),
            ("CapBnd:", "0000000000000000"),
            ("CapAmb:", "0000000000000000"),
        ] {
            let values: Vec<_> = status
                .lines()
                .filter_map(|line| line.strip_prefix(field))
                .collect();
            if values.len() != 1
                || values[0].split_whitespace().collect::<Vec<_>>()
                    != expected.split_whitespace().collect::<Vec<_>>()
            {
                return Err(Error::ConfinementPolicy);
            }
        }
        let mut fds: Vec<u32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .map_err(|_| Error::DescriptorPolicy)?
            .map(|entry| {
                entry
                    .map_err(|_| Error::DescriptorPolicy)
                    .and_then(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .parse()
                            .map_err(|_| Error::DescriptorPolicy)
                    })
            })
            .collect::<Result<_>>()?;
        fds.sort_unstable();
        if fds != [0, 1, 2, 3, 4, 5, 6] {
            return Err(Error::DescriptorPolicy);
        }
        for (inside, outside) in [
            (format!("/proc/{pid}/root"), path.clone()),
            (format!("/proc/{pid}/fd/5"), path.join(".allocations.lock")),
            (
                format!("/proc/{pid}/fd/6"),
                path.join(".owner-journal.pending"),
            ),
        ] {
            let a = std::fs::metadata(inside).map_err(|_| Error::OwnershipMismatch)?;
            let b = std::fs::metadata(outside).map_err(|_| Error::OwnershipMismatch)?;
            if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                return Err(Error::OwnershipMismatch);
            }
        }
        super::lab::case(
            "actual_journal_writer_root_confined_caps0_nnp_seccomp_exact_ack_dir_lease_temp_fds",
        );
    }
    let mut reader = launch(&make(
        false,
        None,
        vprouter_core::health::boot_seconds() + 2.,
    ))?;
    reader.start()?;
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match reader.poll()? {
            Some(true) => break,
            Some(false) => return Err(Error::Interrupted),
            None => (),
        }
        if Instant::now() >= until {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(reader);
    super::lab::case("actual_stopped_writer_after_temp_write_does_not_block_independent_read_job");
    let reservations = transaction.shared.leases.clone();
    drop(transaction);
    if store.lock().is_ok() {
        return Err(Error::OwnershipMismatch);
    }
    while vprouter_core::health::boot_seconds() < original_end {
        std::thread::sleep(Duration::from_millis(2));
    }
    writer.lab_require_stopped()?;
    writer.cancel()?;
    let until = Instant::now() + Duration::from_secs(2);
    while writer.poll()?.is_none() {
        if Instant::now() >= until {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    if !writer.drained() {
        return Err(Error::ChildFailed);
    }
    // Actual native reap does not drop the retained parent owner. Its complete
    // bundle deliberately still owns the OFD and same-process exit reservation.
    if !store
        .lock()
        .is_err_and(|error| error.reason() == vprouter_core::reason::Reason::LockBusy)
        || reservations.borrow().0.get("one") != Some(&1)
    {
        return Err(Error::OwnershipMismatch);
    }
    eprintln!(
        "LAB_JOURNAL_LEASE pid={pid} start={start} actual_reaped=true parent_owner_retained=true independent_ofd_busy=true exit_reservation_count=1"
    );
    drop(writer);
    if reservations.borrow().0.contains_key("one") {
        return Err(Error::OwnershipMismatch);
    }
    let recovered = store.lock().map_err(|_| Error::LockBusy)?;
    if recovered
        .read()
        .map_err(|_| Error::OwnershipMismatch)?
        .is_none()
        || std::fs::read(path.join("namespaces.json")).map_err(|_| Error::Interrupted)? != before
        || !path.join(".owner-journal.pending").exists()
    {
        return Err(Error::OwnershipMismatch);
    }
    println!(
        "{}",
        serde_json::json!({"case":"actual_expired_writer_never_resumed_lease_busy_until_actual_death_late_temp_retained","writer_pid":pid,"writer_start":start,"original_deadline":original_end,
        "actual_reaped_before_parent_owner_drop":true,"parent_retained_independent_ofd_busy":true,
        "parent_retained_exit_reservation_count":1,"parent_writer_owner_dropped":true,
        "after_drop_independent_ofd_acquired":true,"after_drop_exit_reservation_absent":true,
        "component_only":true})
    );
    Ok(())
}

/// Rootless native ownership regression: do not release the IO child into its
/// privileged fixed role. Dropping its parent wrapper must retain every FD and
/// the OFD/reservation until the independent collector actually reaps it.
#[cfg(test)]
pub(super) fn lab_journal_drop_retention() -> Result<()> {
    lab_native_job_drop_retention(false, false)?;
    lab_native_job_drop_retention(true, false)?;
    lab_native_job_drop_retention(false, true)
}
#[cfg(test)]
fn lab_native_job_drop_retention(host: bool, fail_parent: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    let fd = fs::memfd_create(c"vprouter-journal-drop", fs::MemfdFlags::CLOEXEC)
        .map_err(|_| Error::DescriptorPolicy)?;
    fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::LockBusy)?;
    let observer = fs::open(
        format!("/proc/self/fd/{}", fd.as_raw_fd()),
        OFlags::RDWR | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let _observer_inventory = super::inventory::Registration::owned(&[observer.as_fd()])?;
    let reservations = std::rc::Rc::new(std::cell::RefCell::new(ExitLeases::default()));
    reservations.borrow_mut().acquire("one")?;
    reservations.borrow_mut().hold("one")?;
    let native_jobs = std::rc::Rc::new(std::cell::RefCell::new(NativeJobs::new()));
    let lease = MutatorLease {
        native_jobs: native_jobs.clone(),
        native_job: None,
        host_window: None,
        counted: true,
        _inventory: super::inventory::Registration::owned(&[fd.as_fd()])?,
        fd,
        reservations: reservations.clone(),
        exit: "one".into(),
    };
    let directory = fs::open(
        "/tmp",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::OwnershipMismatch)?;
    let (spec, _) = super::tests::fixture();
    let record = Record::new(&spec, "one", Identity { dev: 1, ino: 2 })?;
    let mut job = JournalIo {
        allocation: spec.allocation.clone(),
        before: encode_record(&record)?,
        after: Some(encode_record(&record)?),
        deadline: vprouter_core::health::boot_seconds() + 2.,
        pause_before_sync: false,
        pause_before_read: false,
        lab_stage: std::cell::Cell::new(0),
    };
    let witness = if fail_parent {
        kernel::lab_fail_next_journal_parent()?;
        if !matches!(
            kernel::spawn_journal_io(directory, lease, &job),
            Err(Error::DescriptorInventory)
        ) {
            return Err(Error::OwnershipMismatch);
        }
        None
    } else if host {
        let child =
            kernel::host_audit::spawn(directory, lease, None, job.deadline, false, true, false)?;
        let witness = child.lab_pre_isolation_handle()?;
        drop(child);
        Some(witness)
    } else {
        let child = kernel::spawn_journal_io(directory, lease, &job)?;
        let (before, after, end) = job.constructor_binding();
        let after = after.ok_or(Error::OwnershipMismatch)?;
        preparation::lab_pending_write_core(&child, &native_jobs, before, after, end)?;
        if child.drained()
            || !child.matches_owned_mutation_io(&native_jobs, "one", before, after, end)?
        {
            eprintln!("LAB_PENDING_WRITE_REGRESSION exact_original_writer_refused=true");
            return Err(Error::OwnershipMismatch);
        }
        let foreign_jobs = std::rc::Rc::new(std::cell::RefCell::new(NativeJobs::new()));
        for refused in [
            child.matches_owned_mutation_io(&foreign_jobs, "one", before, after, end)?,
            child.matches_owned_mutation_io(&native_jobs, "other", before, after, end)?,
            child.matches_owned_mutation_io(&native_jobs, "one", [0; 32], after, end)?,
            child.matches_owned_mutation_io(&native_jobs, "one", before, [0; 32], end)?,
            child.matches_owned_mutation_io(&native_jobs, "one", before, after, end + 1.)?,
        ] {
            if refused {
                return Err(Error::OwnershipMismatch);
            }
        }
        if !child.matches_mutation_io(before, after, end)?
            || child.matches_mutation_io([0; 32], after, end)?
            || child.matches_mutation_io(before, [0; 32], end)?
            || child.matches_mutation_io(before, after, end + 1.)?
        {
            return Err(Error::OwnershipMismatch);
        }
        // Mutating the caller's former input cannot alter the original child
        // binding. This child stays gated and is actually collected below.
        job.before[0] ^= 1;
        job.after = None;
        job.deadline += 1.;
        if !child.matches_mutation_io(before, after, end)? {
            return Err(Error::OwnershipMismatch);
        }
        let witness = child.lab_native_reap_handle()?;
        drop(child);
        Some(witness)
    };
    let job_receipt = native_jobs
        .borrow()
        .pending
        .values()
        .next()
        .ok_or(Error::OwnershipMismatch)?
        .1
        .clone();
    reservations.borrow_mut().release("one");
    if kernel::early_forks_drained()
        || native_jobs.borrow_mut().drained("one")?
        || !native_jobs.borrow_mut().drained("other")?
        || reservations.borrow_mut().acquire("one") != Err(Error::LockBusy)
        || fs::flock(&observer, fs::FlockOperation::NonBlockingLockExclusive)
            != Err(rustix::io::Errno::WOULDBLOCK)
    {
        return Err(Error::OwnershipMismatch);
    }
    super::inventory::verify()?;
    // Original native capability reaps before the independent collector runs.
    // The wrapper's retained context must still own the OFD and reservation.
    if let Some(witness) = &witness {
        witness.lab_wait_killed()?;
    }
    if reservations.borrow().0.get("one") != Some(&1)
        || native_jobs.borrow_mut().drained("one")?
        || fs::flock(&observer, fs::FlockOperation::NonBlockingLockExclusive)
            != Err(rustix::io::Errno::WOULDBLOCK)
    {
        return Err(Error::OwnershipMismatch);
    }
    let end = vprouter_core::health::boot_seconds() + 2.;
    while !kernel::early_forks_drained() {
        kernel::poll_early_forks()?;
        if vprouter_core::health::boot_seconds() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    if !job_receipt.lab_collected()? || !native_jobs.borrow_mut().drained("one")? {
        return Err(Error::OwnershipMismatch);
    }
    reservations.borrow_mut().acquire("one")?;
    fs::flock(&observer, fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| Error::LockBusy)?;
    drop(witness);
    super::inventory::verify()?;
    if fail_parent {
        eprintln!(
            "LAB_JOURNAL_POSTCLONE_RECEIPT pending_job_absent=true native_born=true actual_waitpid=true full_bundle_collected=true member_receipt_complete=true"
        );
    }
    if host {
        eprintln!(
            "LAB_HOST_AUDIT_RETENTION rootless_before_isolation=true actual_waitpid=true ofd_busy_after_reap=true reservation_retained_until_collection=true"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Catch omitted fields, vector normalization, path normalization and premature
    // mismatch returns using the former implementation as an independent oracle.
    fn assert_allocation_comparison(
        a: &AllocationRecord,
        b: &AllocationRecord,
        expected: Result<bool>,
    ) {
        let serialized = (|| {
            Ok(serde_json::to_vec(a).map_err(|_| Error::OwnershipMismatch)?
                == serde_json::to_vec(b).map_err(|_| Error::OwnershipMismatch)?)
        })();
        assert_eq!(serialized, expected, "hand-checked serializer result");
        assert_eq!(same_allocation(a, b), serialized, "differential result");
    }

    #[test]
    fn allocation_comparison_includes_every_scalar_field_and_option() {
        use vprouter_core::config::ExitMode;
        let mut base = super::super::tests::record();
        base.exits[0].mode = ExitMode::Mullvad;
        base.exits[0].wireguard_interface = Some("wg-fixture".into());
        assert_allocation_comparison(&base, &base.clone(), Ok(true));
        let changes: [fn(&mut AllocationRecord); 13] = [
            |a| a.schema_version += 1,
            |a| a.deployment_id.push('x'),
            |a| a.generation += 1,
            |a| a.exits[0].exit_id.push('x'),
            |a| a.exits[0].mode = ExitMode::Direct,
            |a| a.exits[0].state_dir.push("different"),
            |a| a.exits[0].data_namespace.push('x'),
            |a| a.exits[0].transport_namespace.push('x'),
            |a| a.exits[0].nft_table.push('x'),
            |a| a.exits[0].host_interface.push('x'),
            |a| a.exits[0].data_interface.push('x'),
            |a| a.exits[0].wireguard_interface = None,
            |a| a.exits[0].transport_subnet.push('x'),
        ];
        for change in changes {
            let mut changed = base.clone();
            change(&mut changed);
            assert_allocation_comparison(&base, &changed, Ok(false));
            assert_allocation_comparison(&changed, &changed.clone(), Ok(true));
        }
        let mut empty_option = base.clone();
        empty_option.exits[0].wireguard_interface = Some(String::new());
        let mut absent_option = empty_option.clone();
        absent_option.exits[0].wireguard_interface = None;
        assert_allocation_comparison(&empty_option, &empty_option.clone(), Ok(true));
        assert_allocation_comparison(&empty_option, &absent_option, Ok(false));
        let mut boundaries = base.clone();
        boundaries.schema_version = u32::MAX;
        boundaries.generation = u64::MAX;
        assert_allocation_comparison(&boundaries, &boundaries.clone(), Ok(true));
        boundaries.generation = 0;
        assert_allocation_comparison(&base, &boundaries, Ok(false));
    }

    #[test]
    fn allocation_comparison_preserves_exit_order_duplicates_and_length() {
        let base = super::super::tests::record();
        let mut empty = base.clone();
        empty.exits.clear();
        assert_allocation_comparison(&empty, &empty.clone(), Ok(true));
        assert_allocation_comparison(&base, &empty, Ok(false));
        let mut duplicate = base.clone();
        duplicate.exits.push(duplicate.exits[0].clone());
        assert_allocation_comparison(&duplicate, &duplicate.clone(), Ok(true));
        assert_allocation_comparison(&base, &duplicate, Ok(false));
        let mut ordered = duplicate.clone();
        ordered.exits[1].exit_id.push('x');
        let mut reversed = ordered.clone();
        reversed.exits.reverse();
        assert_allocation_comparison(&ordered, &ordered.clone(), Ok(true));
        assert_allocation_comparison(&ordered, &reversed, Ok(false));
        assert_allocation_comparison(&duplicate, &ordered, Ok(false));
    }

    #[test]
    fn allocation_comparison_preserves_exact_path_and_string_spelling() {
        let mut base = super::super::tests::record();
        base.exits[0].state_dir = "/fixture/a".into();
        for path in [
            "",
            "/fixture/a",
            "/fixture//a",
            "/fixture/./a",
            "/fixture/a/",
            "/fixture/é",
            "/fixture/e\u{301}",
            "/fixture/a\0b",
        ] {
            let mut changed = base.clone();
            changed.exits[0].state_dir = path.into();
            assert_allocation_comparison(&changed, &changed.clone(), Ok(true));
            assert_allocation_comparison(&base, &changed, Ok(path == "/fixture/a"));
        }
        for text in ["", "\0", "\n\"\\", "é", "e\u{301}"] {
            let mut changed = base.clone();
            changed.deployment_id = text.into();
            changed.exits[0].exit_id = text.into();
            assert_allocation_comparison(&changed, &changed.clone(), Ok(true));
            assert_allocation_comparison(&base, &changed, Ok(false));
        }
        let mut composed = base.clone();
        composed.exits[0].exit_id = "é".into();
        let mut decomposed = composed.clone();
        decomposed.exits[0].exit_id = "e\u{301}".into();
        assert_allocation_comparison(&composed, &decomposed, Ok(false));
    }

    #[test]
    fn allocation_comparison_reports_invalid_paths_before_any_mismatch() {
        use std::os::unix::ffi::OsStringExt;
        let base = super::super::tests::record();
        let mut malformed = base.clone();
        malformed.exits[0].state_dir = std::ffi::OsString::from_vec(vec![b'/', 0xff]).into();
        let error = Err(Error::OwnershipMismatch);
        assert_allocation_comparison(&malformed, &base, error);
        assert_allocation_comparison(&base, &malformed, error);
        assert_allocation_comparison(&malformed, &malformed.clone(), error);
        let mut late = base.clone();
        late.exits.push(malformed.exits[0].clone());
        for invalid in [&malformed, &late] {
            let mut scalar_mismatch = base.clone();
            scalar_mismatch.schema_version += 1;
            let mut length_mismatch = base.clone();
            length_mismatch.exits.clear();
            let mut entry_mismatch = base.clone();
            entry_mismatch.exits[0].exit_id.push('x');
            for other in [&scalar_mismatch, &length_mismatch, &entry_mismatch] {
                assert_allocation_comparison(invalid, other, error);
                assert_allocation_comparison(other, invalid, error);
            }
        }
    }
    #[test]
    fn pre_container_record_binds_exact_allocation_without_inventing_launch_identity() {
        let allocation = super::super::tests::record();
        let base = Identity { dev: 4, ino: 10 };
        let record = Record::new_allocation(&allocation, "one", base).unwrap();
        record.bind_allocation(&allocation, "one", base).unwrap();
        let (spec, _) = super::super::tests::fixture();
        assert_eq!(
            encode_record(&record).unwrap(),
            encode_record(&Record::new(&spec, "one", base).unwrap()).unwrap()
        );
        let mut changed = allocation.clone();
        changed.generation += 1;
        assert!(record.bind_allocation(&changed, "one", base).is_err());
        assert!(record.bind_allocation(&allocation, "other", base).is_err());
        assert!(
            record
                .bind_allocation(&allocation, "one", Identity { dev: 4, ino: 11 })
                .is_err()
        );
        let mut invalid = allocation;
        invalid.exits[0].host_interface = "foreign".into();
        assert!(Record::new_allocation(&invalid, "one", base).is_err());
    }
    #[test]
    fn prebirth_host_anchor_never_substitutes_for_primary_data_namespace() {
        let (spec, _) = super::super::tests::fixture();
        let domains = super::super::supervision::Domains::new(&spec, &"a".repeat(64)).unwrap();
        let owner = super::super::supervision::OwnerDomainRecord {
            boot: "12345678-1234-1234-1234-123456789abc".into(),
            unit: domains.owner_unit(),
            invocation: "b".repeat(32),
            pid: 42,
            start: 100,
            cgroup: Identity { dev: 7, ino: 9 },
        };
        let host = Identity { dev: 4, ino: 10 };
        let mut record = Record::new_preparing(&spec.allocation, "one", host, owner).unwrap();
        assert_eq!(record.primary_network(), Err(Error::OwnershipMismatch));
        assert!(record.bind(&spec, "one", host).is_err());
        record
            .bind_anchor(&spec.allocation, "one", None, Some(host))
            .unwrap();
        let restored: Record = serde_json::from_slice(&encode_record(&record).unwrap()).unwrap();
        assert!(restored.base_network.is_none());
        assert_eq!(restored.owner_network, Some(host));
        record.owner_epoch = None;
        assert!(
            record
                .bind_anchor(&spec.allocation, "one", None, Some(host))
                .is_err()
        );
    }
    #[test]
    fn native_member_jobs_are_bound_bounded_and_prebirth_failure_does_not_block_a_neighbor() {
        let mut jobs = NativeJobs::new();
        let mut tickets = Vec::new();
        for _ in 0..64 {
            tickets.push(jobs.issue("one", kernel::NativeJobKind::Journal).unwrap());
        }
        assert!(!jobs.drained("one").unwrap());
        assert!(jobs.drained("two").unwrap());
        assert!(matches!(
            jobs.issue("two", kernel::NativeJobKind::HostAudit),
            Err(Error::LockBusy)
        ));
        drop(tickets.pop());
        let other = jobs.issue("two", kernel::NativeJobKind::HostAudit).unwrap();
        drop(tickets);
        assert!(jobs.drained("one").unwrap());
        assert!(!jobs.drained("two").unwrap());
        drop(other);
        assert!(jobs.drained("two").unwrap());
        jobs.next = u64::MAX;
        assert!(matches!(
            jobs.issue("one", kernel::NativeJobKind::Journal),
            Err(Error::LockBusy)
        ));
    }
    // A second exit must share the live journal; duplicate exit leases must not
    // create two actuators, and an allocation generation cannot be rebound.
    fn two_bootstrap_records() -> (LaunchSpec, Record, Record) {
        let (s, _, cfg) = lab_deployment_fixture().unwrap();
        let base = Identity { dev: 4, ino: 10 };
        let mut before = Record::new(&s, "one", base).unwrap();
        for (i, exit) in s.allocation.exits.iter().enumerate() {
            before.entries.push(Entry {
                exit_id: exit.exit_id.clone(),
                data_name: exit.data_namespace.clone(),
                transport_name: exit.transport_namespace.clone(),
                phase: Phase::Bootstrap,
                data: Some(Identity {
                    dev: 4,
                    ino: 10 + i as u64 * 2,
                }),
                transport: Some(Identity {
                    dev: 4,
                    ino: 11 + i as u64 * 2,
                }),
                producer: Some(ProducerOwnership {
                    binding: None,
                    parent: Identity { dev: 5, ino: 20 },
                    group: Identity {
                        dev: 5,
                        ino: 21 + i as u64,
                    },
                }),
                links: Some(LinkOwnership {
                    host_namespace: Identity { dev: 4, ino: 100 },
                    host_index: 2 + i as u32 * 3,
                    transport_index: 3 + i as u32 * 3,
                    wireguard_index: 4 + i as u32 * 3,
                }),
                terminal: None,
                attempt: None,
                preparation: None,
            });
        }
        before.bind(&s, "one", base).unwrap();
        let mut after = before.clone();
        after.entries[0].terminal = Some(TerminalOwnership {
            lifecycle: "a".repeat(64),
            binding: vprouter_linux::status::expected_binding(
                &cfg,
                0,
                s.generation,
                "01234567-1234-1234-1234-0123456789ab",
            )
            .unwrap(),
            executors: vec![],
            acknowledged: vec![],
            guard_pid: 42,
            guard_start: 100,
            completions: vec![],
        });
        after.bind(&s, "one", base).unwrap();
        (s, before, after)
    }
    #[test]
    fn crossing_neighbor_commit_uses_only_exact_owner_authorized_generations() {
        let (_, before, after) = two_bootstrap_records();
        let observed = record_digest(&encode_record(&after).unwrap());
        let mut reads = ReadWindows::default();
        reads.reserve(&before, None, "other").unwrap();
        // Child has not read yet, and cannot introduce this future record itself.
        assert_eq!(
            reads.verify("other", observed, &before, None),
            Err(Error::OwnershipMismatch)
        );
        // Owner registers legal A proposal before releasing the atomic writer.
        reads.publish(&after).unwrap();
        reads
            .verify("other", observed, &before, Some(&after))
            .unwrap();
        reads.verify("other", observed, &after, None).unwrap();
        // It may have opened the previous inode before the commit, too.
        reads
            .verify(
                "other",
                record_digest(&encode_record(&before).unwrap()),
                &after,
                None,
            )
            .unwrap();
        assert_eq!(
            reads.verify("other", [0; 32], &after, None),
            Err(Error::OwnershipMismatch)
        );
        reads.remove("other");
        assert!(reads.verify("other", observed, &after, None).is_err());
    }
    #[test]
    fn read_completion_rejects_selected_changes_pending_changes_and_shared_rebinding() {
        let (_, before, after) = two_bootstrap_records();
        let mut reads = ReadWindows::default();
        reads.reserve(&before, None, "one").unwrap();
        let old = record_digest(&encode_record(&before).unwrap());
        reads.publish(&after).unwrap();
        assert_eq!(
            reads.verify("one", old, &after, None),
            Err(Error::OwnershipMismatch)
        );
        assert_eq!(
            reads.verify("one", old, &before, Some(&after)),
            Err(Error::OwnershipMismatch)
        );
        assert_eq!(
            reads.verify(
                "one",
                record_digest(&encode_record(&after).unwrap()),
                &after,
                None
            ),
            Err(Error::OwnershipMismatch)
        );
        for field in 0..5 {
            let mut changed = before.clone();
            match field {
                0 => changed.base_network.as_mut().unwrap().ino += 1,
                1 => changed.primary_exit_id = "other".into(),
                2 => changed.schema_version += 1,
                3 => changed.allocation.generation += 1,
                _ => changed.allocation.exits.swap(0, 1),
            }
            assert_eq!(
                reads.verify("one", old, &changed, None),
                Err(Error::OwnershipMismatch)
            );
        }
        let mut fresh = ReadWindows::default();
        assert_eq!(
            fresh.reserve(&before, Some(&after), "one"),
            Err(Error::OwnershipMismatch)
        );
        fresh.reserve(&before, Some(&after), "other").unwrap();
        fresh
            .verify(
                "other",
                record_digest(&encode_record(&after).unwrap()),
                &before,
                Some(&after),
            )
            .unwrap();
    }
    #[test]
    fn read_history_is_bounded_and_released_without_waiting_on_unrelated_reads() {
        let (spec, before, mut candidate) = two_bootstrap_records();
        let mut reads = ReadWindows::default();
        reads.reserve(&before, None, "other").unwrap();
        assert_eq!(reads.reserve(&before, None, "other"), Err(Error::LockBusy));
        // Successive canonical neighbor states leave the selected entry intact.
        // Schema-valid owner records here exercise capacity, not native lifecycles.
        for i in 1..MAX_READ_GENERATIONS {
            candidate.entries[0].terminal.as_mut().unwrap().guard_start = i as u64;
            candidate
                .bind(&spec, "one", before.primary_network().unwrap())
                .unwrap();
            assert!(reads.can_publish(&candidate).unwrap());
            reads.publish(&candidate).unwrap();
        }
        candidate.entries[0].terminal.as_mut().unwrap().guard_start = 1000;
        assert!(!reads.can_publish(&candidate).unwrap());
        assert_eq!(reads.publish(&candidate), Err(Error::LockBusy));
        assert_eq!(reads.0["other"].generations.len(), MAX_READ_GENERATIONS);
        reads.reserve(&before, None, "one").unwrap();
        reads
            .verify(
                "one",
                record_digest(&encode_record(&before).unwrap()),
                &before,
                None,
            )
            .unwrap();
        reads.remove("other");
        assert!(reads.can_publish(&candidate).unwrap());
    }
    #[test]
    fn overlapping_legal_member_terminal_mutations_commit_in_fifo_order() {
        let (spec, mut canonical, _) = two_bootstrap_records();
        let (_, _, cfg) = lab_deployment_fixture().unwrap();
        let mut queue = MutationQueue::default();
        let request = |index| JournalRequest::BeginTerminal {
            binding: vprouter_linux::status::expected_binding(
                &cfg,
                index,
                spec.generation,
                "01234567-1234-1234-1234-0123456789ab",
            )
            .unwrap(),
            lifecycle: if index == 0 {
                "a".repeat(64)
            } else {
                "b".repeat(64)
            },
        };
        let a = QueuedRequest {
            request: request(0).into(),
            sent_at: 100.,
        };
        let b = QueuedRequest {
            request: request(1).into(),
            sent_at: 100.1,
        };
        queue.push("one").unwrap();
        queue.push("other").unwrap();
        for (i, (exit, queued)) in [("one", a), ("other", b)].into_iter().enumerate() {
            assert!(queue.first(exit));
            assert!(!mutation_slot_available(true, false).unwrap());
            original_frame(queued.sent_at, 100.5 + i as f64 * 0.1).unwrap();
            assert!(mutation_slot_available(false, false).unwrap());
            let JournalOperation::Guard(JournalRequest::BeginTerminal { binding, lifecycle }) =
                queued.request
            else {
                panic!("fixed mutation");
            };
            let previous = canonical.clone();
            canonical
                .begin_terminal(exit, binding, &lifecycle, (42 + i as u32, 100))
                .unwrap();
            canonical
                .bind(&spec, "one", previous.primary_network().unwrap())
                .unwrap();
            unchanged_selected_entry(&previous, &canonical, if i == 0 { "other" } else { "one" })
                .unwrap();
            queue.remove(exit);
        }
        assert!(queue.0.is_empty());
        assert_eq!(
            canonical.entries[0].terminal.as_ref().unwrap().guard_pid,
            42
        );
        assert_eq!(
            canonical.entries[1].terminal.as_ref().unwrap().guard_pid,
            43
        );
        assert_eq!(
            canonical.begin_terminal(
                "one",
                canonical.entries[0]
                    .terminal
                    .as_ref()
                    .unwrap()
                    .binding
                    .clone(),
                &"a".repeat(64),
                (42, 100)
            ),
            Err(Error::Interrupted)
        );
        assert_eq!(mutation_slot_available(true, true), Err(Error::LockBusy));
        assert_eq!(mutation_slot_available(false, true), Err(Error::LockBusy));
    }
    #[test]
    fn mutation_fifo_preserves_order_bound_and_cancelled_member_removal() {
        let mut queue = MutationQueue::default();
        queue.push("a").unwrap();
        queue.push("b").unwrap();
        assert!(queue.first("a"));
        assert!(!queue.first("b"));
        assert_eq!(queue.push("a"), Err(Error::LockBusy));
        queue.remove("a");
        assert!(queue.first("b"));
        queue.push("a").unwrap();
        assert!(queue.first("b"));
        queue.remove("a");
        for i in 1..MAX_JOURNAL_MEMBERS {
            queue.push(&format!("member{i}")).unwrap();
        }
        assert_eq!(queue.push("overflow"), Err(Error::LockBusy));
        queue.remove("b");
        assert!(queue.first("member1"));
        queue.push("after_cancel").unwrap();
        assert!(queue.first("member1"));
    }
    #[test]
    fn queued_original_frame_never_gets_a_new_deadline() {
        let sent = 100.;
        assert_eq!(original_frame(sent, 101.999), Ok(()));
        assert_eq!(original_frame(sent, 102.), Err(Error::Deadline));
        assert_eq!(original_frame(sent, 105.), Err(Error::Deadline));
        for bad in [f64::NAN, f64::INFINITY, -1., 106.] {
            assert_eq!(original_frame(bad, 105.), Err(Error::Deadline));
        }
        assert_eq!(original_frame(sent, f64::NAN), Err(Error::Deadline));
    }
    #[test]
    fn ordinary_neighbor_writer_is_waiting_not_terminal_failure() {
        assert_eq!(mutation_slot_available(true, false), Ok(false));
        assert_eq!(mutation_slot_available(false, false), Ok(true));
        assert_eq!(mutation_slot_available(true, true), Err(Error::LockBusy));
        assert_eq!(mutation_slot_available(false, true), Err(Error::LockBusy));
    }
    #[test]
    fn deployment_lab_binds_both_actual_member_policies_before_native_actions() {
        let (a, b, cfg) = lab_deployment_fixture().unwrap();
        for (index, spec) in [&a, &b].into_iter().enumerate() {
            spec.validate().unwrap();
            spec.allocation.matches_configuration(&cfg).unwrap();
            let binding = vprouter_linux::status::expected_binding(
                &cfg,
                index,
                spec.generation,
                "01234567-1234-1234-1234-0123456789ab",
            )
            .unwrap();
            binding.validate().unwrap();
            assert_eq!(binding.exit_id, spec.exit.exit_id);
        }
    }
    #[test]
    fn pending_journal_terminal_update_cannot_authorize_old_selected_entry_reads() {
        let (mut s, _) = super::super::tests::fixture();
        let cfg = super::super::transport_lab::health_configuration(&s).unwrap();
        let mut config = serde_json::to_value(cfg.configuration()).unwrap();
        let mut second = config["exits"][0].clone();
        second["id"] = serde_json::json!("other");
        second["state_dir"] = serde_json::json!("/var/lib/launchlab/other");
        config["exits"].as_array_mut().unwrap().push(second);
        let config =
            vprouter_core::config::Configuration::parse(&serde_json::to_vec(&config).unwrap())
                .unwrap()
                .validate_with(|_, _| panic!("direct fixture"))
                .unwrap();
        s.allocation = AllocationRecord::from_configuration(&config, s.generation).unwrap();
        let base = Identity { dev: 4, ino: 10 };
        let mut committed = Record::new(&s, "one", base).unwrap();
        committed.entries.push(Entry {
            exit_id: "one".into(),
            data_name: s.exit.data_namespace.clone(),
            transport_name: s.exit.transport_namespace.clone(),
            phase: Phase::Bootstrap,
            data: Some(base),
            transport: Some(Identity { dev: 4, ino: 11 }),
            producer: Some(ProducerOwnership {
                binding: None,
                parent: Identity { dev: 5, ino: 20 },
                group: Identity { dev: 5, ino: 21 },
            }),
            links: Some(LinkOwnership {
                host_namespace: Identity { dev: 4, ino: 12 },
                host_index: 2,
                transport_index: 3,
                wireguard_index: 4,
            }),
            terminal: None,
            attempt: None,
            preparation: None,
        });
        let other = &s.allocation.exits[1];
        committed.entries.push(Entry {
            exit_id: other.exit_id.clone(),
            data_name: other.data_namespace.clone(),
            transport_name: other.transport_namespace.clone(),
            phase: Phase::Creating,
            data: None,
            transport: None,
            producer: None,
            links: None,
            terminal: None,
            attempt: None,
            preparation: None,
        });
        committed.bind(&s, "one", base).unwrap();
        let cfg = super::super::transport_lab::health_configuration(&s).unwrap();
        let binding = vprouter_linux::status::expected_binding(
            &cfg,
            0,
            s.generation,
            "01234567-1234-1234-1234-0123456789ab",
        )
        .unwrap();
        let mut pending = committed.clone();
        pending.entries[0].terminal = Some(TerminalOwnership {
            lifecycle: "a".repeat(64),
            binding,
            executors: vec![],
            acknowledged: vec![],
            guard_pid: 42,
            guard_start: 100,
            completions: vec![],
        });
        pending.bind(&s, "one", base).unwrap();
        assert!(committed.entries[0].terminal.is_none());
        assert!(pending.entries[0].terminal.is_some());
        assert_eq!(
            unchanged_selected_entry(&committed, &pending, "one"),
            Err(Error::OwnershipMismatch)
        );
        // A distinct unchanged member may read either exact atomic snapshot.
        assert_eq!(
            unchanged_selected_entry(&committed, &pending, "other"),
            Ok(())
        );
        assert_eq!(
            unchanged_selected_entry(&committed, &committed, "one"),
            Ok(())
        );
        assert_eq!(
            unchanged_selected_entry(&committed, &pending, "missing"),
            Err(Error::OwnershipMismatch)
        );
        let mut changed_base = pending.clone();
        changed_base.base_network.as_mut().unwrap().ino += 1;
        assert_eq!(
            unchanged_selected_entry(&committed, &changed_base, "other"),
            Err(Error::OwnershipMismatch)
        );
    }
    fn planned_record() -> (LaunchSpec, Record, TerminalOwnership) {
        let (spec, mut record, after) = two_bootstrap_records();
        let terminal = after.entries[0].terminal.as_ref().unwrap().clone();
        let domains = super::super::supervision::Domains::new(&spec, &terminal.lifecycle).unwrap();
        record.entries[0].attempt = Some(AttemptOwnership {
            exit_id: "one".into(),
            lifecycle: terminal.lifecycle.clone(),
            allocation: domains.allocation().into(),
            launch: "a".repeat(64),
            resources: attempt_resources(&record.entries[0]).unwrap(),
            owner: super::super::supervision::OwnerDomainRecord {
                boot: "12345678-1234-1234-1234-123456789abc".into(),
                unit: domains.owner_unit(),
                invocation: "b".repeat(32),
                pid: 42,
                start: 500,
                cgroup: Identity { dev: 7, ino: 9 },
            },
            scopes: attempt_scopes(&domains),
            planned_at: 100.,
            stage: AttemptStage::Planned,
            birth: None,
            guard_group: None,
            retirement: None,
        });
        record.owner_epoch = Some(record.entries[0].attempt.as_ref().unwrap().owner.clone());
        (spec, record, terminal)
    }
    #[test]
    fn retired_attempt_requires_immutable_terminal_and_resource_provenance() {
        let (spec, mut record, mut terminal) = planned_record();
        // A parsed stage name is not sufficient history, even before native
        // retirement capability checks (which parsing can never manufacture).
        record.entries[0].attempt.as_mut().unwrap().stage = AttemptStage::Retired;
        assert!(
            record
                .bind(&spec, "one", record.primary_network().unwrap())
                .is_err()
        );
        let original = RetirementResources::capture(&record.entries[0]);
        terminal.executors = [
            original.links.as_ref().unwrap().host_namespace,
            original.transport.unwrap(),
            original.data.unwrap(),
        ]
        .into_iter()
        .enumerate()
        .map(|(scope, namespace)| ExecutorIdentity {
            scope: scope as u8,
            pid: 100 + scope as u32,
            start_time: 1000 + scope as u64,
            namespace,
        })
        .collect();
        terminal.acknowledged = vec![0, 1, 2];
        terminal.completions = terminal
            .executors
            .iter()
            .cloned()
            .map(|identity| ExecutorCompletion {
                identity,
                result: TerminalResult::VerifiedBeforeDeadline,
                deadline: 150.,
                finished_at: 149.,
            })
            .collect();
        let terminal_digest =
            vprouter_worker::bootstrap::digest(&serde_json::to_vec(&terminal).unwrap());
        let attempt = record.entries[0].attempt.as_mut().unwrap();
        attempt.owner.pid = 99;
        attempt.owner.boot = terminal.binding.boot_id.clone();
        attempt.birth = Some(GuardBirth {
            pid: terminal.guard_pid,
            start: terminal.guard_start,
            born_at: 101.,
            gate_deadline: 104.,
        });
        attempt.guard_group = Some(Identity { dev: 7, ino: 10 });
        attempt.stage = AttemptStage::Retiring;
        attempt.retirement = Some(RetirementHistory {
            original,
            terminal_digest,
            started_at: 200.,
            quiescent_at: None,
            host_transition: None,
            cleanup: CleanupStage::NotStarted,
            retired_at: None,
        });
        record.owner_epoch = Some(attempt.owner.clone());
        record.entries[0].terminal = Some(terminal);
        record
            .bind(&spec, "one", record.primary_network().unwrap())
            .unwrap();
        let before = record.clone();
        let entry = &mut record.entries[0];
        let attempt = entry.attempt.as_mut().unwrap();
        attempt.stage = AttemptStage::Retired;
        let history = attempt.retirement.as_mut().unwrap();
        history.quiescent_at = Some(201.);
        history.cleanup = CleanupStage::ProducerRemoved;
        history.host_transition = Some("e".repeat(64));
        history.retired_at = Some(202.);
        entry.phase = Phase::Offline;
        entry.links = None;
        entry.producer = None;
        record
            .bind(&spec, "one", record.primary_network().unwrap())
            .unwrap();
        let encoded = encode_record(&record).unwrap();
        let restored: Record = serde_json::from_slice(&encoded).unwrap();
        restored
            .bind(&spec, "one", record.primary_network().unwrap())
            .unwrap();
        let mut reads = ReadWindows::default();
        reads.reserve(&before, None, "other").unwrap();
        reads.publish(&record).unwrap();
        reads
            .verify("other", record_digest(&encoded), &record, None)
            .unwrap();
        for change in 0..6 {
            let mut forged = restored.clone();
            let entry = &mut forged.entries[0];
            match change {
                0 => entry.attempt.as_mut().unwrap().retirement = None,
                1 => {
                    entry
                        .attempt
                        .as_mut()
                        .unwrap()
                        .retirement
                        .as_mut()
                        .unwrap()
                        .original
                        .links
                        .as_mut()
                        .unwrap()
                        .host_index += 1
                }
                2 => entry.terminal.as_mut().unwrap().completions[0].finished_at -= 1.,
                3 => entry.attempt.as_mut().unwrap().birth = None,
                4 => {
                    entry
                        .attempt
                        .as_mut()
                        .unwrap()
                        .retirement
                        .as_mut()
                        .unwrap()
                        .cleanup = CleanupStage::LinksIntent
                }
                _ => {
                    entry
                        .attempt
                        .as_mut()
                        .unwrap()
                        .retirement
                        .as_mut()
                        .unwrap()
                        .quiescent_at = Some(203.)
                }
            }
            assert!(
                forged
                    .bind(&spec, "one", forged.primary_network().unwrap())
                    .is_err(),
                "mutation {change}"
            );
        }
    }
    #[test]
    fn planned_attempt_cannot_gain_terminal_authority_before_native_birth() {
        let (_, mut record, terminal) = planned_record();
        assert_eq!(
            record.begin_terminal(
                "one",
                terminal.binding.clone(),
                &terminal.lifecycle,
                (terminal.guard_pid, terminal.guard_start)
            ),
            Err(Error::Interrupted)
        );
        assert!(record.entries[0].terminal.is_none());
    }
    #[test]
    fn guard_plan_binding_rejects_other_member_same_lifecycle_and_changed_native_context() {
        let (spec, record, _) = planned_record();
        let attempt = record.entries[0].attempt.as_ref().unwrap();
        let domains = super::super::supervision::Domains::new(&spec, &attempt.lifecycle).unwrap();
        let mut binding = AttemptBinding {
            exit_id: attempt.exit_id.clone(),
            launch: attempt.launch.clone(),
            resources: attempt.resources.clone(),
        };
        assert_eq!(binding.binds(attempt, &domains), Ok(()));
        let other = super::super::supervision::Domains::from_record(
            &spec.allocation,
            &record.entries[1].exit_id,
            &attempt.lifecycle,
        )
        .unwrap();
        assert_eq!(
            binding.binds(attempt, &other),
            Err(Error::OwnershipMismatch)
        );
        binding.launch = "c".repeat(64);
        assert_eq!(
            binding.binds(attempt, &domains),
            Err(Error::OwnershipMismatch)
        );
        binding.launch = attempt.launch.clone();
        binding.resources = "d".repeat(64);
        assert_eq!(
            binding.binds(attempt, &domains),
            Err(Error::OwnershipMismatch)
        );
    }
    #[test]
    fn planned_scope_collision_and_unknown_owner_epoch_fail_before_birth() {
        let (_, mut record, _) = planned_record();
        let first = record.entries[0].attempt.as_ref().unwrap().clone();
        let mut second = first.clone();
        second.exit_id = record.entries[1].exit_id.clone();
        second.resources = attempt_resources(&record.entries[1]).unwrap();
        let exit = second.exit_id.clone();
        assert_eq!(record.plan_attempt(&exit, second), Err(Error::LockBusy));
        assert!(record.entries[1].attempt.is_none());
        record.entries[0].attempt = None;
        record.owner_epoch = None;
        assert_eq!(
            record.plan_attempt("one", first.clone()),
            Err(Error::OwnershipMismatch)
        );
        assert!(record.entries[0].attempt.is_none());
        record.owner_epoch = Some(first.owner.clone());
        record.plan_attempt("one", first).unwrap();
    }
    #[test]
    fn shared_exit_leases_reject_duplicates_and_generation_rebinding() {
        let (s, _) = super::super::tests::fixture();
        let mut leases = ExitLeases::default();
        leases.acquire(&s.exit.exit_id).unwrap();
        assert_eq!(leases.acquire("one"), Err(Error::LockBusy));
        leases.acquire("two").unwrap();
        leases.release("two");
        assert_eq!(leases.acquire("one"), Err(Error::LockBusy));
        leases.acquire("two").unwrap();
        let base = Identity { dev: 4, ino: 10 };
        let record = Record::new(&s, "one", base).unwrap();
        let (mut changed, _) = super::super::tests::fixture();
        changed.generation += 1;
        changed.allocation.generation += 1;
        assert!(record.bind(&changed, "one", base).is_err());
    }
    #[test]
    fn mutator_hold_keeps_native_ofd_and_same_journal_reservation_after_transaction_drop() {
        let fd = fs::memfd_create(c"vprouter-mutator-hold", fs::MemfdFlags::CLOEXEC).unwrap();
        fs::flock(&fd, fs::FlockOperation::NonBlockingLockExclusive).unwrap();
        use std::os::fd::AsRawFd;
        let independent = fs::openat(
            fs::CWD,
            format!("/proc/self/fd/{}", fd.as_raw_fd()),
            OFlags::RDWR | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let reservations = std::rc::Rc::new(std::cell::RefCell::new(ExitLeases::default()));
        reservations.borrow_mut().acquire("one").unwrap();
        // Transaction's reservation plus the initially parent-created hold.
        reservations.borrow_mut().hold("one").unwrap();
        let original = MutatorLease {
            native_jobs: std::rc::Rc::new(std::cell::RefCell::new(NativeJobs::new())),
            native_job: None,
            host_window: None,
            counted: true,
            _inventory: super::super::inventory::Registration::owned(&[fd.as_fd()]).unwrap(),
            fd,
            reservations: reservations.clone(),
            exit: "one".into(),
        };
        let retained = original.retain().unwrap();
        reservations.borrow_mut().release("one");
        drop(original);
        assert_eq!(
            reservations.borrow_mut().acquire("one"),
            Err(Error::LockBusy)
        );
        assert_eq!(
            fs::flock(&independent, fs::FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
        drop(retained);
        reservations.borrow_mut().acquire("one").unwrap();
        fs::flock(&independent, fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    }
    #[test]
    fn producer_binding_discriminator_preserves_legacy_bytes_and_refuses_orphan_grants() {
        #[derive(Serialize)]
        struct LegacyProducer {
            parent: Identity,
            group: Identity,
        }
        let parent = Identity { dev: 5, ino: 20 };
        let group = Identity { dev: 5, ino: 21 };
        let p = ProducerOwnership {
            binding: None,
            parent,
            group,
        };
        assert_eq!(
            serde_json::to_vec(&p).unwrap(),
            serde_json::to_vec(&LegacyProducer { parent, group }).unwrap()
        );
        let (spec, _) = super::super::tests::fixture();
        let base = Identity { dev: 4, ino: 10 };
        let mut record = Record::new(&spec, "one", base).unwrap();
        let entry = Entry {
            exit_id: "one".into(),
            data_name: spec.exit.data_namespace.clone(),
            transport_name: spec.exit.transport_namespace.clone(),
            phase: Phase::Activating,
            data: Some(base),
            transport: Some(Identity { dev: 4, ino: 11 }),
            producer: Some(p),
            links: None,
            terminal: None,
            attempt: None,
            preparation: None,
        };
        let legacy = serde_json::to_vec(&(
            &entry.exit_id,
            &entry.data_name,
            &entry.transport_name,
            entry.data,
            entry.transport,
            &entry.links,
            Some(LegacyProducer { parent, group }),
        ))
        .unwrap();
        assert_eq!(
            attempt_resources(&entry).unwrap(),
            vprouter_worker::bootstrap::digest(&legacy)
        );
        record.entries.push(entry);
        assert!(record.bind(&spec, "one", base).is_ok());
        record.entries[0].producer.as_mut().unwrap().binding = Some([7; 32]);
        assert_ne!(
            attempt_resources(&record.entries[0]).unwrap(),
            vprouter_worker::bootstrap::digest(&legacy)
        );
        for phase in [Phase::Creating, Phase::Activating, Phase::Bootstrap] {
            record.entries[0].phase = phase;
            assert_eq!(
                record.bind(&spec, "one", base),
                Err(Error::OwnershipMismatch)
            );
        }
    }
    #[test]
    fn durable_activation_and_bootstrap_require_exact_live_authorities() {
        let (s, _) = super::super::tests::fixture();
        let base = Identity { dev: 4, ino: 10 };
        let mut r = Record::new(&s, "one", base).unwrap();
        r.entries.push(Entry {
            exit_id: "one".into(),
            data_name: s.exit.data_namespace.clone(),
            transport_name: s.exit.transport_namespace.clone(),
            phase: Phase::Activating,
            data: Some(base),
            transport: Some(Identity { dev: 4, ino: 11 }),
            producer: None,
            terminal: None,
            attempt: None,
            preparation: None,
            links: None,
        });
        // Partial intent remains readable, but acquire refuses this phase.
        assert!(r.bind(&s, "one", base).is_ok());
        r.entries[0].phase = Phase::Bootstrap;
        assert!(r.bind(&s, "one", base).is_err());
        r.entries[0].producer = Some(ProducerOwnership {
            binding: None,
            parent: Identity { dev: 5, ino: 20 },
            group: Identity { dev: 5, ino: 21 },
        });
        r.entries[0].links = Some(LinkOwnership {
            host_namespace: Identity { dev: 4, ino: 12 },
            host_index: 2,
            transport_index: 3,
            wireguard_index: 4,
        });
        assert!(r.bind(&s, "one", base).is_ok());
        r.entries[0].links.as_mut().unwrap().host_namespace = base;
        assert!(r.bind(&s, "one", base).is_err());
        r.entries[0].links.as_mut().unwrap().host_namespace = Identity { dev: 4, ino: 12 };
        r.entries[0].producer.as_mut().unwrap().group.dev = 6;
        assert!(r.bind(&s, "one", base).is_err());
    }
    #[test]
    fn exact_members_generation_primary_and_interruption_are_bound() {
        let (mut s, _) = super::super::tests::fixture();
        let base = Identity { dev: 4, ino: 10 };
        let mut r = Record::new(&s, "one", base).unwrap();
        assert!(r.bind(&s, "one", base).is_ok());
        assert!(r.bind(&s, "wrong", base).is_err());
        assert!(r.bind(&s, "one", Identity { dev: 4, ino: 11 }).is_err());
        s.generation += 1;
        assert!(r.bind(&s, "one", base).is_err());
        s.generation -= 1;
        r.entries.push(Entry {
            exit_id: "one".into(),
            data_name: s.exit.data_namespace.clone(),
            transport_name: s.exit.transport_namespace.clone(),
            phase: Phase::Creating,
            data: None,
            transport: None,
            links: None,
            producer: None,
            terminal: None,
            attempt: None,
            preparation: None,
        });
        assert!(r.bind(&s, "one", base).is_ok());
        r.entries[0].phase = Phase::Offline;
        assert!(r.bind(&s, "one", base).is_err());
        r.entries[0].data = Some(base);
        r.entries[0].transport = Some(base);
        assert!(r.bind(&s, "one", base).is_err());
        r.entries[0].transport = Some(Identity { dev: 4, ino: 12 });
        assert!(r.bind(&s, "one", base).is_ok());
        r.entries[0].transport_name = "foreign".into();
        assert!(r.bind(&s, "one", base).is_err());
    }
    #[test]
    fn terminal_completion_never_promotes_late_or_nonfinite_evidence() {
        let identity = ExecutorIdentity {
            scope: 0,
            pid: 2,
            start_time: 3,
            namespace: Identity { dev: 4, ino: 5 },
        };
        let good = ExecutorCompletion {
            identity,
            result: TerminalResult::VerifiedBeforeDeadline,
            deadline: 144.,
            finished_at: 143.,
        };
        good.validate().unwrap();
        for at in [144., 145., f64::NAN, f64::INFINITY, -1.] {
            let mut bad = good.clone();
            bad.finished_at = at;
            assert!(bad.validate().is_err());
        }
        let mut late = good;
        late.result = TerminalResult::LateVerified;
        late.finished_at = 145.;
        late.validate().unwrap();
        assert_ne!(late.result, TerminalResult::VerifiedBeforeDeadline);
    }
}
