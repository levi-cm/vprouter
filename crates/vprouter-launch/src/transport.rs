#![forbid(unsafe_code)]
//! Independent host-owned transport. Private until real daemon placement,
//! watchdog/control protocol and release gates are independently approved.
use super::{
    Admission, Error, LaunchSpec, Result, kernel,
    owned::{Identity, OwnedNamespaces, Transaction},
    process,
};
use std::{net::Ipv4Addr, os::fd::AsFd};
use vprouter_core::profile::Profile;
use vprouter_netfilter::{Actuator, Endpoint, Enforcement, Policy, Scope, Stage};
use vprouter_network::{ActiveLinks, NamespaceTarget, NativeNetwork, Plan};

// Explicit ignored-harness crash checkpoint. Absent from production builds.
#[cfg(test)]
static INTERRUPT_ACTIVATION: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

enum AuditAuthority {
    Local,
    Remote(super::owner::HostAuditClient),
}
#[derive(Clone)]
enum HostEvidence {
    Local(f64),
    Remote(super::owner::HostAuditReceipt),
}
impl HostEvidence {
    fn checked_at(&self) -> f64 {
        match self {
            Self::Local(at) => *at,
            Self::Remote(receipt) => receipt.checked_at(),
        }
    }
    fn expires_at(&self) -> f64 {
        match self {
            Self::Local(at) => *at + 2.,
            Self::Remote(receipt) => receipt.expires_at(),
        }
    }
}
impl AuditAuthority {
    fn expiry(
        &self,
        transaction: &Transaction,
        spec: &LaunchSpec,
        binding: vprouter_core::health::Binding,
        lifecycle: &str,
        scopes: [(Policy, std::os::fd::BorrowedFd<'_>); 3],
    ) -> Result<super::expiry::Executors> {
        match self {
            Self::Local => {
                super::expiry::Executors::spawn(transaction, spec, binding, lifecycle, scopes)
            }
            Self::Remote(client) => super::expiry::Executors::spawn_remote(
                transaction,
                spec,
                binding,
                lifecycle,
                scopes,
                client,
            ),
        }
    }
    fn begin(&self, spec: &LaunchSpec) -> Result<HostEvidence> {
        match self {
            Self::Local => Ok(HostEvidence::Local(vprouter_core::health::boot_seconds())),
            Self::Remote(client) => Ok(HostEvidence::Remote(client.audit(spec)?)),
        }
    }
    fn check(&self, evidence: &HostEvidence, spec: &LaunchSpec) -> Result<()> {
        match (self, evidence) {
            (Self::Remote(client), HostEvidence::Remote(receipt)) => client.check(spec, receipt),
            (Self::Local, HostEvidence::Local(at)) => {
                let now = vprouter_core::health::boot_seconds();
                if !at.is_finite() || !now.is_finite() || *at < 0. || now < *at || now >= *at + 2. {
                    Err(Error::Deadline)
                } else {
                    Ok(())
                }
            }
            _ => Err(Error::OwnershipMismatch),
        }
    }
}

pub(super) struct GuardTransport<'a> {
    authority: AuditAuthority,
    _inventory: Vec<super::inventory::Registration>,
    producer: super::producer::ProducerGroup,
    transaction: Transaction,
    namespaces: OwnedNamespaces,
    spec: &'a LaunchSpec,
    host: NativeNetwork,
    transport: NativeNetwork,
    data: NativeNetwork,
    enforcement: Enforcement,
    active: Option<ActiveLinks>,
    resolvers: Vec<Ipv4Addr>,
    plan: Plan,
}
/// Consuming retirement keeps every original native resource, canonical view
/// and registration. An owned public spec copy is not a new admission capability;
/// normal GuardTransport continues to require its original Admission pointer.
pub(super) struct RetirementTransport {
    authority: AuditAuthority,
    _inventory: Vec<super::inventory::Registration>,
    producer: super::producer::ProducerGroup,
    transaction: Transaction,
    namespaces: OwnedNamespaces,
    spec: LaunchSpec,
    host: NativeNetwork,
    transport: NativeNetwork,
    data: NativeNetwork,
    enforcement: Enforcement,
    active: Option<ActiveLinks>,
    resolvers: Vec<Ipv4Addr>,
    plan: Plan,
}
#[cfg(test)]
pub(super) struct TerminalWitness {
    policies: [Policy; 3],
    namespaces: [std::os::fd::OwnedFd; 3],
}
#[cfg(test)]
impl TerminalWitness {
    pub fn verify(&self, lifecycle: &str) -> Result<()> {
        for (policy, namespace) in self.policies.iter().zip(&self.namespaces) {
            let identity = Identity::network(namespace)?;
            kernel::network_scope(namespace, || {
                vprouter_netfilter::TerminalQuarantine::verify_existing(
                    policy,
                    lifecycle,
                    (identity.dev, identity.ino),
                )
                .map_err(|_| Error::NetworkPolicy)
            })?;
        }
        Ok(())
    }
}
/// Private proof minted only AFTER native Ready and independent lease readback.
/// It binds exact snapshot bytes and the original executor deadline.
#[derive(Clone)]
pub(super) struct ReadyPublication {
    digest: String,
    expires_at: f64,
}
impl ReadyPublication {
    pub(super) fn expires_at(&self) -> f64 {
        self.expires_at
    }
    pub(super) fn check_time(&self) -> Result<()> {
        let now = vprouter_core::health::boot_seconds();
        if !self.expires_at.is_finite() || !now.is_finite() || now >= self.expires_at {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
    pub(super) fn check(&self, snapshot: &vprouter_core::health::Snapshot) -> Result<()> {
        self.check_time()?;
        if snapshot.state != vprouter_core::state::HealthState::Ready
            || vprouter_core::health::boot_seconds() >= self.expires_at
            || vprouter_worker::bootstrap::digest(
                &serde_json::to_vec(snapshot).map_err(|_| Error::DescriptorPolicy)?,
            ) != self.digest
        {
            return Err(Error::DescriptorPolicy);
        }
        Ok(())
    }
}
pub(super) struct ObservationAudit<'g> {
    authority: &'g AuditAuthority,
    spec: &'g LaunchSpec,
    structural_host: Option<HostEvidence>,
    host: &'g mut NativeNetwork,
    transport: &'g mut NativeNetwork,
    data: &'g mut NativeNetwork,
    enforcement: &'g mut Enforcement,
    active: &'g ActiveLinks,
    plan: &'g Plan,
    stage: Stage,
}
impl ObservationAudit<'_> {
    fn host_evidence(&self) -> Result<&HostEvidence> {
        let evidence = self
            .structural_host
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?;
        self.authority.check(evidence, self.spec)?;
        Ok(evidence)
    }

    fn policy(&mut self) -> Result<()> {
        self.enforcement
            .verify(
                self.plan.ownership_alias(),
                self.plan.endpoint(),
                self.host.namespace_identity(),
                self.transport.namespace_identity(),
                self.data.namespace_identity(),
                self.stage,
            )
            .map_err(|_| Error::NetworkPolicy)
    }
    #[cfg(test)]
    pub(super) fn assert_offline(&mut self) -> Result<()> {
        self.enforcement
            .verify(
                self.plan.ownership_alias(),
                self.plan.endpoint(),
                self.host.namespace_identity(),
                self.transport.namespace_identity(),
                self.data.namespace_identity(),
                Stage::Offline,
            )
            .map_err(|_| Error::NetworkPolicy)
    }
    pub(super) fn offline(&mut self) -> Result<()> {
        self.enforcement
            .offline()
            .map_err(|_| Error::NetworkPolicy)?;
        self.stage = Stage::Offline;
        self.policy()
    }
    /// Report only the policy read back through retained namespace sockets.
    /// The serializable receipt itself grants no policy transition authority.
    pub(super) fn policy_receipt(
        &mut self,
        binding: &vprouter_core::health::Binding,
    ) -> Result<vprouter_worker::operation::PolicyReceipt> {
        self.policy()?;
        use vprouter_worker::operation::{PolicyReceipt, PolicyState};
        let state = match self.stage {
            Stage::Offline => PolicyState::Offline,
            Stage::Bootstrap => PolicyState::Bootstrap,
            Stage::Ready => PolicyState::Ready,
        };
        Ok(PolicyReceipt {
            binding: binding.clone(),
            state,
        })
    }
    pub(super) fn expiry(
        &self,
        transaction: &Transaction,
        spec: &LaunchSpec,
        namespaces: &OwnedNamespaces,
        binding: vprouter_core::health::Binding,
        lifecycle: &str,
    ) -> Result<super::expiry::Executors> {
        let host = kernel::network()?;
        let _inventory = super::inventory::Registration::owned(&[host.as_fd()])?;
        let [h, t, d] = self.enforcement.terminal_policies();
        self.authority.expiry(
            transaction,
            spec,
            binding,
            lifecycle,
            [
                (h, host.as_fd()),
                (t, namespaces.transport.as_fd()),
                (d, namespaces.data.as_fd()),
            ],
        )
    }
    pub(super) fn apply_health(
        &mut self,
        executors: &mut super::expiry::Executors,
        transaction: &Transaction,
        spec: &LaunchSpec,
        snapshot: &vprouter_core::health::Snapshot,
    ) -> Result<()> {
        use vprouter_worker::operation::PolicyState;
        let state = PolicyState::publication(snapshot);
        let result = (|| {
            executors.check(transaction, spec)?;
            if state == PolicyState::Ready {
                self.host_evidence()?;
                let mut lease = executors.ready(transaction, spec)?;
                lease.check()?;
                self.host_evidence()?;
                if self.stage != Stage::Ready {
                    self.enforcement.ready().map_err(|_| Error::NetworkPolicy)?;
                    self.stage = Stage::Ready;
                }
                self.policy()?;
                self.host_evidence()?;
                lease.check()?;
            } else if state == PolicyState::Bootstrap {
                self.enforcement
                    .bootstrap()
                    .map_err(|_| Error::NetworkPolicy)?;
                self.stage = Stage::Bootstrap;
                self.policy()?;
            } else {
                self.offline()?;
            }
            executors.check(transaction, spec)?;
            if state == PolicyState::Ready {
                self.host_evidence()?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.offline()?;
        }
        result
    }
    pub(super) fn ready_publication(
        &mut self,
        executors: &mut super::expiry::Executors,
        transaction: &Transaction,
        spec: &LaunchSpec,
        snapshot: &vprouter_core::health::Snapshot,
    ) -> Result<ReadyPublication> {
        if snapshot.state != vprouter_core::state::HealthState::Ready {
            return Err(Error::DescriptorPolicy);
        }
        self.apply_health(executors, transaction, spec, snapshot)?;
        let mut lease = executors.ready(transaction, spec)?;
        lease.check()?;
        let proof = ReadyPublication {
            digest: vprouter_worker::bootstrap::digest(
                &serde_json::to_vec(snapshot).map_err(|_| Error::DescriptorPolicy)?,
            ),
            expires_at: lease.expires_at().min(self.host_evidence()?.expires_at()),
        };
        proof.check(snapshot)?;
        lease.check()?;
        Ok(proof)
    }
    pub(super) fn pin(&mut self) -> Result<vprouter_network::DaemonLinks> {
        let result = (|| {
            let host_evidence = self.authority.begin(self.spec)?;
            self.policy()?;
            let metadata = network(
                "pin_actual_daemon_shape",
                match self.authority {
                    AuditAuthority::Local => {
                        self.active
                            .pin_daemon_metadata(self.host, self.transport, self.data)
                    }
                    AuditAuthority::Remote(_) => self.active.pin_daemon_namespaces(
                        self.host,
                        self.transport,
                        self.data,
                        None,
                    ),
                },
            )?;
            self.policy()?;
            self.authority.check(&host_evidence, self.spec)?;
            Ok(metadata)
        })();
        if result.is_err() {
            self.offline()?;
        }
        result
    }
    pub(super) fn pin_operational(
        &mut self,
        declaration: vprouter_network::DaemonDeclaration,
    ) -> Result<vprouter_network::DaemonLinks> {
        let result = (|| {
            let host_evidence = self.authority.begin(self.spec)?;
            self.policy()?;
            let metadata = network(
                "pin_operational_daemon",
                match self.authority {
                    AuditAuthority::Local => self.active.pin_operational_metadata(
                        self.host,
                        self.transport,
                        self.data,
                        declaration,
                    ),
                    AuditAuthority::Remote(_) => self.active.pin_daemon_namespaces(
                        self.host,
                        self.transport,
                        self.data,
                        Some(declaration),
                    ),
                },
            )?;
            self.policy()?;
            self.authority.check(&host_evidence, self.spec)?;
            Ok(metadata)
        })();
        if result.is_err() {
            self.offline()?;
        }
        result
    }
    pub(super) fn structural(
        &mut self,
        daemon: &vprouter_network::DaemonLinks,
    ) -> Result<vprouter_worker::operation::StructuralEvidence> {
        let result = (|| {
            let host_evidence = self.authority.begin(self.spec)?;
            self.policy()?;
            let (checked_at, handshake_age) = network(
                "operational_structure",
                match self.authority {
                    AuditAuthority::Local => self.active.audit_daemon_health(
                        self.host,
                        self.transport,
                        self.data,
                        daemon,
                    ),
                    AuditAuthority::Remote(_) => self.active.audit_daemon_namespace_health(
                        self.host,
                        self.transport,
                        self.data,
                        daemon,
                    ),
                },
            )?;
            self.policy()?;
            self.authority.check(&host_evidence, self.spec)?;
            let checked_at = checked_at.min(host_evidence.checked_at());
            self.structural_host = Some(host_evidence);
            Ok(vprouter_worker::operation::StructuralEvidence {
                checked_at,
                handshake_age,
            })
        })();
        if result.is_err() {
            self.offline()?;
        }
        result
    }
    pub(super) fn verify(&mut self, daemon: &vprouter_network::DaemonLinks) -> Result<()> {
        let result = (|| {
            let host_evidence = self.authority.begin(self.spec)?;
            self.policy()?;
            self.authority.check(&host_evidence, self.spec)?;
            network(
                "audit_actual_daemon_shape",
                match self.authority {
                    AuditAuthority::Local => self.active.audit_daemon_metadata(
                        self.host,
                        self.transport,
                        self.data,
                        daemon,
                    ),
                    AuditAuthority::Remote(_) => self.active.audit_daemon_namespaces(
                        self.host,
                        self.transport,
                        self.data,
                        daemon,
                    ),
                },
            )?;
            self.policy()?;
            self.authority.check(&host_evidence, self.spec)
        })();
        if result.is_err() {
            self.offline()?;
        }
        result
    }
}
fn network<T>(stage: &'static str, result: vprouter_network::Result<T>) -> Result<T> {
    result.map_err(|e| {
        #[cfg(test)]
        eprintln!("LAB_NATIVE_FAILURE stage={stage} reason={e}");
        #[cfg(not(test))]
        let _ = (stage, e);
        Error::NetworkOperation
    })
}
fn firewall<T>(stage: &'static str, result: vprouter_netfilter::Result<T>) -> Result<T> {
    result.map_err(|e| {
        #[cfg(test)]
        eprintln!("LAB_NFT_FAILURE stage={stage} reason={e}");
        #[cfg(not(test))]
        let _ = (stage, e);
        Error::NetworkPolicy
    })
}
fn policy(spec: &LaunchSpec, profile: &Profile, scope: Scope, wan: &str) -> Result<Policy> {
    Policy::new(
        &spec.allocation,
        &spec.allocation.deployment_id,
        &spec.exit,
        Endpoint::new(profile.endpoint()).map_err(|_| Error::NetworkPolicy)?,
        scope,
        wan,
        "wireguard",
    )
    .map_err(|_| Error::NetworkPolicy)
}
impl RetirementTransport {
    pub(super) fn release_retired(
        &mut self,
        permit: &super::owned::RetiredPermit,
        service: &super::owned::JournalServer,
    ) -> Result<()> {
        self.namespaces.bind(&self.spec)?;
        self.cleanup_descriptors()?;
        self.producer.release_retired(permit, service)
    }
    pub(super) fn verify_cleanup_binding(
        &self,
        permit: &super::owned::CleanupPermit,
        journal: &super::owned::JournalServer,
        guard: &kernel::ManagedGuard,
    ) -> Result<()> {
        if !matches!(self.authority, AuditAuthority::Local) {
            return Err(Error::OwnershipMismatch);
        }
        permit.verify_transport(
            journal,
            &self.transaction,
            &self.spec,
            &self.namespaces,
            guard,
            self.producer.original_identities()?,
            self.active
                .as_ref()
                .ok_or(Error::OwnershipMismatch)?
                .indices(),
        )
    }
    pub(super) fn cleanup_descriptors(&self) -> Result<Vec<std::os::fd::BorrowedFd<'_>>> {
        let mut fds = Vec::new();
        for network in [&self.host, &self.transport, &self.data] {
            fds.extend(network.descriptors());
        }
        fds.extend(self.enforcement.descriptors());
        if fds.len() != 12
            || !fds
                .iter()
                .all(|fd| self._inventory.iter().any(|r| r.contains(*fd)))
        {
            return Err(Error::DescriptorInventory);
        }
        Ok(fds)
    }
    pub(super) fn cleanup_target(
        &self,
        permit: &super::owned::CleanupPermit,
    ) -> Result<super::producer::CleanupTarget> {
        self.producer.cleanup_target(permit)
    }
    pub(super) fn bind_cleanup_deadline(
        &mut self,
        end: f64,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        let deadline = vprouter_netfilter::BootDeadline::at(end).map_err(|_| Error::Deadline)?;
        for network in [&mut self.host, &mut self.transport, &mut self.data] {
            network
                .bind_cleanup_deadline(deadline, timer.clone())
                .map_err(|_| Error::Deadline)?;
        }
        self.enforcement
            .bind_cleanup_deadline(deadline, timer)
            .map_err(|_| Error::Deadline)
    }
    pub(super) fn cleanup_links_native(
        &mut self,
        plan: &vprouter_network::NativeRemovalPlan,
        target: &super::producer::CleanupTarget,
        deadline: f64,
    ) -> Result<vprouter_network::HostObservation> {
        let active = self.active.as_ref().ok_or(Error::OwnershipMismatch)?;
        let fence = || {
            #[cfg(test)]
            super::kernel::cleanup::lab_native_fence()
                .map_err(|_| vprouter_network::Error::Deadline)?;
            let now = vprouter_core::health::boot_seconds();
            if !now.is_finite() || now >= deadline || deadline - now > 2. {
                return Err(vprouter_network::Error::Deadline);
            }
            target
                .verify_empty_native()
                .map_err(|_| vprouter_network::Error::Foreign)
        };
        #[cfg(test)]
        let observed = active.cleanup_native_profiled(
            plan,
            &mut self.host,
            &mut self.transport,
            &mut self.data,
            &mut self.enforcement,
            fence,
            super::kernel::cleanup::lab_native_subphase,
        );
        #[cfg(not(test))]
        let observed = active.cleanup_native(
            plan,
            &mut self.host,
            &mut self.transport,
            &mut self.data,
            &mut self.enforcement,
            fence,
        );
        observed.map_err(|_| Error::NetworkOperation)
    }

    pub(super) fn prepare_host_removal(&self) -> Result<vprouter_network::HostRemovalPlan> {
        self.active
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .prepare_host_removal()
            .map_err(|_| Error::OwnershipMismatch)
    }
    pub(super) fn quiescence(
        &self,
        permit: &super::owned::RetiringPermit,
        journal: &super::owned::JournalServer,
        guard: &kernel::ManagedGuard,
        receipt: &kernel::retirement::StopReceipt,
        expiry: &super::expiry::OwnerExecutors,
        started_at: f64,
    ) -> Result<Option<super::owned::QuiescenceRequest>> {
        permit.quiescence(journal, guard, &self.producer, receipt, expiry, started_at)
    }
    pub(super) fn stop(
        &self,
        permit: &mut super::owned::RetiringPermit,
        journal: &super::owned::JournalServer,
        guard: &kernel::ManagedGuard,
    ) -> Result<kernel::retirement::StopChild> {
        permit.launch_stop(journal, guard, &self.producer)
    }

    pub(super) fn bind(
        &self,
        journal: &super::owned::JournalServer,
        guard: &kernel::ManagedGuard,
    ) -> Result<super::owned::RetirementBinding> {
        if !matches!(self.authority, AuditAuthority::Local) {
            return Err(Error::OwnershipMismatch);
        }
        journal.bind_retirement(
            &self.transaction,
            &self.spec,
            &self.namespaces,
            guard,
            self.producer.original_identities()?,
        )
    }
}
impl<'a> GuardTransport<'a> {
    pub(super) fn retirement_binding(
        &self,
        journal: &super::owned::JournalServer,
        guard: &kernel::ManagedGuard,
    ) -> Result<super::owned::RetirementBinding> {
        if !matches!(self.authority, AuditAuthority::Local) {
            return Err(Error::OwnershipMismatch);
        }
        journal.bind_retirement(
            &self.transaction,
            self.spec,
            &self.namespaces,
            guard,
            self.producer.original_identities()?,
        )
    }
    pub(super) fn into_retirement(self) -> RetirementTransport {
        RetirementTransport {
            authority: self.authority,
            _inventory: self._inventory,
            producer: self.producer,
            transaction: self.transaction,
            namespaces: self.namespaces,
            spec: self.spec.clone(),
            host: self.host,
            transport: self.transport,
            data: self.data,
            enforcement: self.enforcement,
            active: self.active,
            resolvers: self.resolvers,
            plan: self.plan,
        }
    }
    pub fn activate(
        mut transaction: Transaction,
        namespaces: OwnedNamespaces,
        admission: &'a Admission,
        profile: &Profile,
        wan: &str,
        host_authority: &vprouter_network::HostAuthority,
    ) -> Result<Self> {
        let spec = &admission.spec;
        process::host_preflight()?;
        // This preflight precedes durable intent, nft/socket and native changes.
        if profile.resolvers().is_empty() {
            return Err(Error::ResolverUnavailable);
        }
        transaction.revalidate(spec)?;
        namespaces.bind(spec)?;
        let plan = Plan::new(
            &spec.allocation,
            &spec.allocation.deployment_id,
            &spec.exit,
            profile,
        )
        .map_err(|_| Error::AllocationMismatch)?;
        Actuator::preflight_socket_cgroup(&policy(spec, profile, Scope::Data, wan)?)
            .map_err(|_| Error::UnsupportedPlatform)?;
        {
            let (mut check, _inventory) = super::inventory::Registration::network(plan.clone())?;
            network(
                "shared_host_preflight",
                host_authority.verify_current(&mut check),
            )?;
        }
        transaction.begin_transport(spec, &namespaces)?;
        let producer =
            super::producer::ProducerGroup::create(admission, &namespaces, &mut transaction)?;
        let ((mut host, host_policy), host_inventory) =
            super::inventory::Registration::control(|| {
                Ok((
                    NativeNetwork::open(plan.clone()).map_err(|_| Error::NetworkOperation)?,
                    Actuator::open(policy(spec, profile, Scope::Host, wan)?)
                        .map_err(|_| Error::NetworkPolicy)?,
                ))
            })?;
        let ((mut transport, transport_policy), transport_inventory) =
            kernel::network_scope(&namespaces.transport, || {
                super::inventory::Registration::control(|| {
                    Ok((
                        NativeNetwork::open(plan.clone()).map_err(|_| Error::NetworkOperation)?,
                        Actuator::open(policy(spec, profile, Scope::Transport, wan)?)
                            .map_err(|_| Error::NetworkPolicy)?,
                    ))
                })
            })?;
        let ((mut data, data_policy), data_inventory) =
            kernel::network_scope(&namespaces.data, || {
                super::inventory::Registration::control(|| {
                    Ok((
                        NativeNetwork::open(plan.clone()).map_err(|_| Error::NetworkOperation)?,
                        Actuator::open(
                            policy(spec, profile, Scope::Data, wan)?
                                .with_producer(producer.authority())
                                .map_err(|_| Error::NetworkPolicy)?,
                        )
                        .map_err(|_| Error::NetworkPolicy)?,
                    ))
                })
            })?;
        let mut enforcement = firewall(
            "initial_quarantine",
            Enforcement::quarantine(host_policy, transport_policy, data_policy),
        )?;
        let result = (|| {
            // Namespace ownership/allocation lock is retained for this lifetime.
            producer.verify(&transaction, spec)?;
            namespaces.bind(spec)?;
            transaction.revalidate(spec)?;
            firewall(
                "pre_baseline_ipv6_quarantine",
                enforcement.verify(
                    plan.ownership_alias(),
                    plan.endpoint(),
                    host.namespace_identity(),
                    transport.namespace_identity(),
                    data.namespace_identity(),
                    Stage::Offline,
                ),
            )?;
            kernel::prepare_owned_data_ipv6(&namespaces, spec)?;
            firewall(
                "post_ipv6_quarantine",
                enforcement.verify(
                    plan.ownership_alias(),
                    plan.endpoint(),
                    host.namespace_identity(),
                    transport.namespace_identity(),
                    data.namespace_identity(),
                    Stage::Offline,
                ),
            )?;
            let target_t =
                NamespaceTarget::from_trusted_network_namespace(namespaces.transport.as_fd())
                    .map_err(|_| Error::NamespaceMismatch)?;
            let target_d = NamespaceTarget::from_trusted_network_namespace(namespaces.data.as_fd())
                .map_err(|_| Error::NamespaceMismatch)?;
            let pair = network(
                "create_veth_down",
                host.create_veth_pair_down(&mut transport, &target_t),
            )?;
            let wg = network(
                "create_wireguard_birth_down",
                transport.create_wireguard_down(profile),
            )?;
            let wg = network(
                "move_wireguard_data_down",
                transport.move_wireguard_down(&mut data, &target_d, wg),
            )?;
            // Persist actual assigned indices and exact host ns before any UP.
            let hi = host.namespace_identity();
            transaction.bind_links(
                spec,
                &namespaces,
                Identity {
                    dev: hi.0,
                    ino: hi.1,
                },
                (pair.host().index(), pair.transport().index(), wg.index()),
            )?;
            let active = network(
                "activate_quarantined",
                NativeNetwork::activate_quarantined(
                    &mut host,
                    &mut transport,
                    &mut data,
                    pair,
                    wg,
                    &mut enforcement,
                    host_authority,
                ),
            )?;
            network(
                "post_activation_audit",
                active.audit(&mut host, &mut transport, &mut data),
            )?;
            firewall("bootstrap", enforcement.bootstrap())?;
            #[cfg(test)]
            let commit = !INTERRUPT_ACTIVATION.swap(false, std::sync::atomic::Ordering::SeqCst);
            #[cfg(not(test))]
            let commit = true;
            if commit {
                transaction.bootstrap(
                    spec,
                    &namespaces,
                    Identity {
                        dev: hi.0,
                        ino: hi.1,
                    },
                    active.indices(),
                )?;
            }
            Ok(active)
        })();
        if result.is_err() {
            enforcement.offline().map_err(|_| Error::NetworkPolicy)?;
        }
        Ok(Self {
            authority: AuditAuthority::Local,
            _inventory: vec![host_inventory, transport_inventory, data_inventory],
            producer,
            transaction,
            namespaces,
            spec,
            host,
            transport,
            data,
            enforcement,
            active: Some(result?),
            resolvers: profile.resolvers().to_vec(),
            plan,
        })
    }
    /// Exact selected member authority; canonical journals and owner factories
    /// are deliberately absent. Only the independent retained deployment OFD is
    /// shared with this guard. All other inherited registrations are private.
    pub(super) fn guard_inputs(
        &self,
        domains: &super::supervision::Domains,
        admission: Option<&Admission>,
    ) -> Result<super::inventory::GuardInputs> {
        if !matches!(self.authority, AuditAuthority::Local)
            || domains.exit_id() != self.spec.exit.exit_id
            || domains.allocation()
                != vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(&self.spec.allocation).map_err(|_| Error::InvalidSpec)?,
                )
        {
            return Err(Error::OwnershipMismatch);
        }
        self.transaction.revalidate(self.spec)?;
        self.namespaces.bind(self.spec)?;
        self.producer.verify(&self.transaction, self.spec)?;
        let mut inputs = super::inventory::GuardInputs::for_domains(domains)?;
        inputs.bind_attempt(self.transaction.attempt_binding(self.spec)?)?;
        self.select_guard_inputs(inputs, admission)
    }
    pub(super) fn guard_inputs_owned(
        &self,
        domains: &super::supervision::Domains,
        owner: &super::supervision::OwnerDomain,
        admission: Option<&Admission>,
    ) -> Result<super::inventory::GuardInputs> {
        if !matches!(self.authority, AuditAuthority::Local)
            || domains.exit_id() != self.spec.exit.exit_id
        {
            return Err(Error::OwnershipMismatch);
        }
        self.namespaces.bind(self.spec)?;
        self.producer.verify_native()?;
        let mut inputs = super::inventory::GuardInputs::for_owner(domains, owner)?;
        inputs.bind_attempt(self.transaction.pending_binding(self.spec)?)?;
        self.select_guard_inputs(inputs, admission)
    }
    fn select_guard_inputs(
        &self,
        mut inputs: super::inventory::GuardInputs,
        admission: Option<&Admission>,
    ) -> Result<super::inventory::GuardInputs> {
        for registration in &self._inventory {
            inputs.include(
                registration,
                super::inventory::GuardAuthority::SelectedMember,
            )?;
        }
        self.namespaces.select_guard(&mut inputs)?;
        self.producer.select_guard(&mut inputs)?;
        if let Some(admission) = admission {
            if serde_json::to_vec(&admission.spec).map_err(|_| Error::InvalidSpec)?
                != serde_json::to_vec(self.spec).map_err(|_| Error::InvalidSpec)?
            {
                return Err(Error::OwnershipMismatch);
            }
            admission
                .process
                .revalidate(&admission.spec, &admission.staging)?;
            admission.process.select_guard(&mut inputs)?;
        }
        Ok(inputs)
    }
    pub fn owner_expiry(
        &self,
        domains: super::supervision::Domains,
        binding: vprouter_core::health::Binding,
    ) -> Result<super::expiry::OwnerExecutors> {
        if !matches!(self.authority, AuditAuthority::Local)
            || domains.exit_id() != self.spec.exit.exit_id
            || domains.allocation()
                != vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(&self.spec.allocation).map_err(|_| Error::InvalidSpec)?,
                )
        {
            return Err(Error::OwnershipMismatch);
        }
        self.transaction.revalidate(self.spec)?;
        let host = kernel::network()?;
        let transport = rustix::io::fcntl_dupfd_cloexec(&self.namespaces.transport, 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let data = rustix::io::fcntl_dupfd_cloexec(&self.namespaces.data, 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let lease = self.transaction.retain_executor_lock(self.spec)?;
        super::expiry::OwnerExecutors::new(
            domains,
            binding,
            self.enforcement.terminal_policies(),
            [host, transport, data],
            lease,
        )
    }
    pub fn start_expiry(
        &self,
        binding: vprouter_core::health::Binding,
        lifecycle: &str,
    ) -> Result<super::expiry::Executors> {
        let host = kernel::network()?;
        let _inventory = super::inventory::Registration::owned(&[host.as_fd()])?;
        let [h, t, d] = self.enforcement.terminal_policies();
        self.authority.expiry(
            &self.transaction,
            self.spec,
            binding,
            lifecycle,
            [
                (h, host.as_fd()),
                (t, self.namespaces.transport.as_fd()),
                (d, self.namespaces.data.as_fd()),
            ],
        )
    }
    pub fn lease_health(
        &mut self,
        executors: &mut super::expiry::Executors,
        message: &vprouter_core::health::HealthMessage,
    ) -> Result<()> {
        let blocked = message
            .snapshot
            .as_ref()
            .is_some_and(|s| s.state == vprouter_core::state::HealthState::Blocked);
        if blocked {
            // Ordinary provider failure is recoverable within the ORIGINAL
            // lifetime. Quarantine first; restore only health/control bootstrap.
            self.enforcement
                .offline()
                .map_err(|_| Error::NetworkPolicy)?;
        }
        let result = executors.health(&self.transaction, self.spec, message);
        if result.is_err() {
            self.enforcement
                .offline()
                .map_err(|_| Error::NetworkPolicy)?;
        } else if blocked {
            self.producer.verify(&self.transaction, self.spec)?;
            self.enforcement
                .bootstrap()
                .map_err(|_| Error::NetworkPolicy)?;
        }
        result
    }
    pub fn finish_terminal(&self, executors: &mut super::expiry::Executors) -> Result<()> {
        executors.finish_terminal(&self.transaction, self.spec)
    }
    pub fn ready_with_executors(&mut self, executors: &mut super::expiry::Executors) -> Result<()> {
        let result = (|| {
            let evidence = self.authority.begin(self.spec)?;
            self.audit()?;
            self.authority.check(&evidence, self.spec)?;
            let mut lease = executors.ready(&self.transaction, self.spec)?;
            lease.check()?;
            self.authority.check(&evidence, self.spec)?;
            self.enforcement.ready().map_err(|_| Error::NetworkPolicy)?;
            lease.check()?;
            self.audit_stage(Stage::Ready)?;
            lease.check()?;
            self.authority.check(&evidence, self.spec)
        })();
        if result.is_err() {
            self.enforcement
                .offline()
                .map_err(|_| Error::NetworkPolicy)?;
        }
        result
    }
    #[cfg(test)]
    pub fn lab_operational_ready_publication(
        &mut self,
        executors: &mut super::expiry::Executors,
        snapshot: &vprouter_core::health::Snapshot,
    ) -> Result<()> {
        self.audit_stage(Stage::Ready)?;
        let evidence = self.authority.begin(self.spec)?;
        let mut audit = ObservationAudit {
            authority: &self.authority,
            spec: self.spec,
            structural_host: Some(evidence),
            host: &mut self.host,
            transport: &mut self.transport,
            data: &mut self.data,
            enforcement: &mut self.enforcement,
            active: self.active.as_ref().ok_or(Error::Interrupted)?,
            plan: &self.plan,
            stage: Stage::Ready,
        };
        for _ in 0..2 {
            let proof =
                audit.ready_publication(executors, &self.transaction, self.spec, snapshot)?;
            proof.check(snapshot)?;
            let mut substituted = snapshot.clone();
            substituted.sequence += 1;
            if proof.check(&substituted).is_ok() {
                return Err(Error::DescriptorPolicy);
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub fn lab_terminal_witness(&self) -> Result<TerminalWitness> {
        Ok(TerminalWitness {
            policies: self.enforcement.terminal_policies(),
            namespaces: [
                kernel::network()?,
                self.namespaces
                    .transport
                    .try_clone()
                    .map_err(|_| Error::DescriptorDuplicate)?,
                self.namespaces
                    .data
                    .try_clone()
                    .map_err(|_| Error::DescriptorDuplicate)?,
            ],
        })
    }
    #[cfg(test)]
    pub fn lab_verify_terminal(&self, lifecycle: &str) -> Result<()> {
        let [h, t, d] = self.enforcement.terminal_policies();
        vprouter_netfilter::TerminalQuarantine::verify_existing(
            &h,
            lifecycle,
            self.host.namespace_identity(),
        )
        .map_err(|_| Error::NetworkPolicy)?;
        kernel::network_scope(&self.namespaces.transport, || {
            vprouter_netfilter::TerminalQuarantine::verify_existing(
                &t,
                lifecycle,
                self.transport.namespace_identity(),
            )
            .map_err(|_| Error::NetworkPolicy)
        })?;
        kernel::network_scope(&self.namespaces.data, || {
            vprouter_netfilter::TerminalQuarantine::verify_existing(
                &d,
                lifecycle,
                self.data.namespace_identity(),
            )
            .map_err(|_| Error::NetworkPolicy)
        })
    }
    /// Observation handoff is available only while exact bootstrap enforcement
    /// and retained producer/allocation/namespace authority freshly verify.
    pub(super) fn inspection_policy<'p>(
        &self,
        admission: &'p Admission,
        bundle: &'p super::programs::ReviewedBundle,
        configuration: super::kernel::DaemonConfiguration,
    ) -> Result<super::inspection::Policy<'p>> {
        super::inspection::Policy::new(
            admission,
            &self.transaction,
            &self.namespaces,
            &self.producer,
            bundle,
            configuration,
        )
    }
    pub fn prepare_observation<'g>(
        &'g mut self,
        admission: &'g Admission,
        bundle: &super::programs::ReviewedBundle,
    ) -> Result<super::handoff::Handoff<'g>> {
        self.prepare_handoff(admission, bundle, None, None)
    }
    pub fn prepare_monitor<'g>(
        &'g mut self,
        admission: &'g Admission,
        bundle: &super::programs::ReviewedBundle,
        binding: vprouter_core::health::Binding,
    ) -> Result<super::handoff::Handoff<'g>> {
        self.prepare_handoff(admission, bundle, Some(binding), None)
    }
    pub fn prepare_operational<'g>(
        &'g mut self,
        admission: &'g Admission,
        bundle: &super::programs::ReviewedBundle,
        binding: vprouter_core::health::Binding,
    ) -> Result<super::handoff::Handoff<'g>> {
        let enrollment =
            super::enrollment::AuthorizedEnrollment::load(self.spec, bundle, &binding)?;
        self.prepare_handoff(admission, bundle, Some(binding), Some(enrollment))
    }
    fn prepare_handoff<'g>(
        &'g mut self,
        admission: &'g Admission,
        bundle: &super::programs::ReviewedBundle,
        binding: Option<vprouter_core::health::Binding>,
        enrollment: Option<super::enrollment::AuthorizedEnrollment>,
    ) -> Result<super::handoff::Handoff<'g>> {
        self.audit()?;
        if !std::ptr::eq(self.spec, &admission.spec) {
            return Err(Error::AllocationMismatch);
        }
        let resolver = *self.resolvers.first().ok_or(Error::ResolverUnavailable)?;
        super::handoff::Handoff::prepare(
            admission,
            &self.producer,
            &self.transaction,
            &self.namespaces,
            &self.plan,
            resolver,
            bundle,
            ObservationAudit {
                authority: &self.authority,
                spec: self.spec,
                structural_host: None,
                host: &mut self.host,
                transport: &mut self.transport,
                data: &mut self.data,
                enforcement: &mut self.enforcement,
                active: self.active.as_ref().ok_or(Error::Interrupted)?,
                plan: &self.plan,
                stage: Stage::Bootstrap,
            },
            binding,
            enrollment,
        )
    }
    pub fn bind_remote(&mut self, owner: &super::owner::GuardOwner) -> Result<()> {
        if !matches!(self.authority, AuditAuthority::Local) {
            return Err(Error::OwnershipMismatch);
        }
        let client = owner.host_audit(self.spec)?;
        self.transaction = self.transaction.fork_remote(self.spec, owner)?;
        self.authority = AuditAuthority::Remote(client);
        self.audit()
    }
    pub fn audit(&mut self) -> Result<()> {
        self.audit_stage(Stage::Bootstrap)
    }
    #[cfg(test)]
    pub(super) fn lab_audit_offline(&mut self) -> Result<()> {
        self.audit_stage(Stage::Offline)
    }
    fn audit_stage(&mut self, stage: Stage) -> Result<()> {
        let result = (|| {
            let evidence = self.authority.begin(self.spec)?;
            let active = self.active.as_ref().ok_or(Error::Interrupted)?;
            let h = self.host.namespace_identity();
            self.producer.verify(&self.transaction, self.spec)?;
            self.transaction.verify_links(
                self.spec,
                &self.namespaces,
                Identity { dev: h.0, ino: h.1 },
                active.indices(),
            )?;
            match self.authority {
                AuditAuthority::Local => {
                    active.audit(&mut self.host, &mut self.transport, &mut self.data)
                }
                AuditAuthority::Remote(_) => {
                    active.audit_namespaces(&mut self.host, &mut self.transport, &mut self.data)
                }
            }
            .map_err(|_| Error::NetworkOperation)?;
            self.enforcement
                .verify(
                    self.plan.ownership_alias(),
                    self.plan.endpoint(),
                    self.host.namespace_identity(),
                    self.transport.namespace_identity(),
                    self.data.namespace_identity(),
                    stage,
                )
                .map_err(|_| Error::NetworkPolicy)?;
            self.authority.check(&evidence, self.spec)
        })();
        if result.is_err() {
            self.enforcement
                .offline()
                .map_err(|_| Error::NetworkPolicy)?;
        }
        result
    }
    #[cfg(test)]
    pub(super) fn lab_ready(&mut self) -> Result<()> {
        self.audit()?;
        self.enforcement.ready().map_err(|_| Error::NetworkPolicy)?;
        self.audit_stage(Stage::Ready)
    }
    #[cfg(test)]
    pub(super) fn lab_begin_offline(&mut self) -> Result<()> {
        self.enforcement.offline().map_err(|_| Error::NetworkPolicy)
    }
    #[cfg(test)]
    pub(super) fn lab_interrupt_activation_commit() {
        INTERRUPT_ACTIVATION.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(test)]
    pub(super) fn lab_interrupt_cleanup(mut self) -> Result<()> {
        self.enforcement
            .offline()
            .map_err(|_| Error::NetworkPolicy)?;
        self.lab_offline()?;
        // Deliberately leave the durable live record and every owned resource.
        // Returning drops descriptors only, as a stopped guard would do.
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn lab_host_alias(&self) -> String {
        self.plan.ownership_alias().to_owned()
    }
    #[cfg(test)]
    pub(super) fn lab_host_index(&self) -> Result<u32> {
        Ok(self.active.as_ref().ok_or(Error::Interrupted)?.indices().0)
    }
    #[cfg(test)]
    pub(super) fn lab_journal_parts(&self) -> (&Transaction, &OwnedNamespaces) {
        (&self.transaction, &self.namespaces)
    }
    #[cfg(test)]
    pub(super) fn lab_namespaces(&self) -> (&OwnedNamespaces, &super::producer::ProducerGroup) {
        (&self.namespaces, &self.producer)
    }
    #[cfg(test)]
    pub(super) fn lab_offline(&mut self) -> Result<()> {
        self.enforcement
            .verify(
                self.plan.ownership_alias(),
                self.plan.endpoint(),
                self.host.namespace_identity(),
                self.transport.namespace_identity(),
                self.data.namespace_identity(),
                Stage::Offline,
            )
            .map_err(|_| Error::NetworkPolicy)
    }
    #[cfg(test)]
    pub(super) fn lab_resume_bootstrap(&mut self) -> Result<()> {
        // Fixed fixture restoration still uses the exact owner capability. A
        // forked guard must never consult its copied parent HostAuthority model.
        self.enforcement
            .offline()
            .map_err(|_| Error::NetworkPolicy)?;
        let result = (|| {
            let evidence = self.authority.begin(self.spec)?;
            self.producer.verify(&self.transaction, self.spec)?;
            let active = self.active.as_ref().ok_or(Error::Interrupted)?;
            let h = self.host.namespace_identity();
            self.transaction.verify_links(
                self.spec,
                &self.namespaces,
                Identity { dev: h.0, ino: h.1 },
                active.indices(),
            )?;
            for stage in [Stage::Offline, Stage::Bootstrap] {
                self.authority.check(&evidence, self.spec)?;
                if stage == Stage::Bootstrap {
                    self.enforcement
                        .bootstrap()
                        .map_err(|_| Error::NetworkPolicy)?;
                }
                network(
                    "lab_restore_audit",
                    match self.authority {
                        AuditAuthority::Local => {
                            active.audit(&mut self.host, &mut self.transport, &mut self.data)
                        }
                        AuditAuthority::Remote(_) => active.audit_namespaces(
                            &mut self.host,
                            &mut self.transport,
                            &mut self.data,
                        ),
                    },
                )?;
                self.enforcement
                    .verify(
                        self.plan.ownership_alias(),
                        self.plan.endpoint(),
                        self.host.namespace_identity(),
                        self.transport.namespace_identity(),
                        self.data.namespace_identity(),
                        stage,
                    )
                    .map_err(|_| Error::NetworkPolicy)?;
                // Preserve the SAME original host receipt across restoration,
                // both native reads and final policy verification.
                self.authority.check(&evidence, self.spec)?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.enforcement
                .offline()
                .map_err(|_| Error::NetworkPolicy)?;
        }
        result
    }
    #[cfg(test)]
    pub(super) fn lab_plan(&self) -> &Plan {
        &self.plan
    }
    #[cfg(test)]
    pub(super) fn lab_data_tables(&self) -> (String, String) {
        (
            format!("{}_dq", self.spec.exit.nft_table),
            format!("{}_dp", self.spec.exit.nft_table),
        )
    }
    pub fn cleanup(mut self) -> Result<()> {
        self.transaction.require_no_executors(self.spec)?;
        self.enforcement
            .offline()
            .map_err(|_| Error::NetworkPolicy)?;
        self.producer.verify(&self.transaction, self.spec)?;
        self.enforcement
            .verify_cooperation()
            .map_err(|_| Error::NetworkPolicy)?;
        self.producer
            .require_cleanup(&self.transaction, self.spec)?;
        let active = self.active.take().ok_or(Error::Interrupted)?;
        active
            .cleanup(
                &mut self.host,
                &mut self.transport,
                &mut self.data,
                &mut self.enforcement,
            )
            .map_err(|_| Error::NetworkOperation)?;
        self.producer.cleanup(&self.transaction, self.spec)?;
        self.transaction.transport_cleaned(self.spec)
        // Quarantine remains deliberately installed until namespace deletion has
        // independent exact provenance. No cleanup-by-name or automatic Drop.
    }
}
