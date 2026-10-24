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

pub(super) struct GuardTransport<'a> {
    producer: super::producer::ProducerGroup,
    transaction: Transaction<'a>,
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
impl<'a> GuardTransport<'a> {
    pub fn activate(
        mut transaction: Transaction<'a>,
        namespaces: OwnedNamespaces,
        admission: &'a Admission,
        profile: &Profile,
        wan: &str,
    ) -> Result<Self> {
        let spec = &admission.spec;
        process::single_threaded()?;
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
        transaction.begin_transport(spec, &namespaces)?;
        let producer =
            super::producer::ProducerGroup::create(admission, &namespaces, &mut transaction)?;
        let mut host = NativeNetwork::open(plan.clone()).map_err(|_| Error::NetworkOperation)?;
        let host_policy = Actuator::open(policy(spec, profile, Scope::Host, wan)?)
            .map_err(|_| Error::NetworkPolicy)?;
        let (mut transport, transport_policy) =
            kernel::network_scope(&namespaces.transport, || {
                Ok((
                    NativeNetwork::open(plan.clone()).map_err(|_| Error::NetworkOperation)?,
                    Actuator::open(policy(spec, profile, Scope::Transport, wan)?)
                        .map_err(|_| Error::NetworkPolicy)?,
                ))
            })?;
        let (mut data, data_policy) = kernel::network_scope(&namespaces.data, || {
            Ok((
                NativeNetwork::open(plan.clone()).map_err(|_| Error::NetworkOperation)?,
                Actuator::open(
                    policy(spec, profile, Scope::Data, wan)?
                        .with_producer(producer.authority())
                        .map_err(|_| Error::NetworkPolicy)?,
                )
                .map_err(|_| Error::NetworkPolicy)?,
            ))
        })?;
        let mut enforcement = firewall(
            "initial_quarantine",
            Enforcement::quarantine(host_policy, transport_policy, data_policy),
        )?;
        let result = (|| {
            // Namespace ownership/allocation lock is retained for this lifetime.
            producer.verify(&transaction, spec)?;
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
    pub fn audit(&mut self) -> Result<()> {
        let result = (|| {
            let active = self.active.as_ref().ok_or(Error::Interrupted)?;
            let h = self.host.namespace_identity();
            self.producer.verify(&self.transaction, self.spec)?;
            self.transaction.verify_links(
                self.spec,
                &self.namespaces,
                Identity { dev: h.0, ino: h.1 },
                active.indices(),
            )?;
            active
                .audit(&mut self.host, &mut self.transport, &mut self.data)
                .map_err(|_| Error::NetworkOperation)?;
            self.enforcement
                .verify(
                    self.plan.ownership_alias(),
                    self.plan.endpoint(),
                    self.host.namespace_identity(),
                    self.transport.namespace_identity(),
                    self.data.namespace_identity(),
                    Stage::Bootstrap,
                )
                .map_err(|_| Error::NetworkPolicy)?;
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
        self.producer.verify(&self.transaction, self.spec)?;
        network(
            "lab_restore_audit",
            self.active.as_ref().ok_or(Error::Interrupted)?.audit(
                &mut self.host,
                &mut self.transport,
                &mut self.data,
            ),
        )?;
        self.enforcement
            .offline()
            .map_err(|_| Error::NetworkPolicy)?;
        self.enforcement
            .bootstrap()
            .map_err(|_| Error::NetworkPolicy)
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
        self.enforcement
            .offline()
            .map_err(|_| Error::NetworkPolicy)?;
        self.producer.verify(&self.transaction, self.spec)?;
        self.enforcement
            .verify_cooperation()
            .map_err(|_| Error::NetworkPolicy)?;
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
