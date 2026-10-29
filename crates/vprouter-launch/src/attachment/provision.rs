//! Original transport-bound network operations. Durable authority remains in
//! the canonical owner; the network and lower crates cannot release its gate.
use super::super::{inventory, kernel, secret::InputIdentity};
use super::{Error, Result, transport::MountedTransport};
use serde::{Deserialize, Serialize};
use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    rc::Rc,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Sockets,
    Provision,
    Query,
    DataSockets,
    Move,
}
struct Input {
    member: String,
    identity: InputIdentity,
    fd: OwnedFd,
    token: inventory::Registration,
}
pub(crate) struct Request {
    creator: u32,
    kind: Kind,
    mounted: Rc<kernel::fresh_transport_mount::Mounted>,
    configuration: vprouter_core::config::PublicConfiguration,
    configuration_digest: [u8; 32],
    inputs: Vec<Input>,
    member: String,
    plan: vprouter_network::Plan,
    requested_at: f64,
    digest: [u8; 32],
    movement: Option<Rc<kernel::docker_query::Accepted>>,
}
impl Request {
    pub(super) fn new(owner: &MountedTransport, kind: Kind) -> Result<Rc<Self>> {
        kernel::secret::seal_parent()?;
        kernel::owner_admission_permitted()?;
        let requested_at = vprouter_core::health::boot_seconds();
        if kind == Kind::Move {
            return Err(Error::OwnershipMismatch);
        }
        Self::at(owner, kind, requested_at, None)
    }
    fn at(
        owner: &MountedTransport,
        kind: Kind,
        requested_at: f64,
        movement: Option<Rc<kernel::docker_query::Accepted>>,
    ) -> Result<Rc<Self>> {
        let mounted = owner.mounted()?;
        let configuration = owner.configuration()?.clone();
        let spec = mounted
            .request()
            .original()
            .request()
            .data()
            .request()
            .spec();
        let member = spec.exit.exit_id.clone();
        let public = configuration
            .exits()
            .iter()
            .find(|e| e.exit().id == member)
            .and_then(|e| e.profile())
            .ok_or(Error::InvalidSpec)?;
        let plan = vprouter_network::Plan::from_public(
            &spec.allocation,
            &spec.allocation.deployment_id,
            &spec.exit,
            public,
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        let configuration_digest = configuration
            .configuration()
            .clone()
            .validate_structure()
            .and_then(|c| c.digest())
            .map_err(|_| Error::InvalidSpec)?;
        let mut inputs = Vec::new();
        for (member, original) in owner.provision_descriptors()? {
            let identity = InputIdentity::capture(original, 0)?;
            let fd = rustix::io::fcntl_dupfd_cloexec(original, 3)
                .map_err(|_| Error::DescriptorDuplicate)?;
            let token = inventory::Registration::owned(&[fd.as_fd()])?;
            identity.verify(&fd)?;
            inputs.push(Input {
                member,
                identity,
                fd,
                token,
            });
        }
        let identities: Vec<_> = inputs.iter().map(|i| (&i.member, &i.identity)).collect();
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                "original_wireguard_v1",
                kind,
                mounted.request().digest(),
                mounted.birth()?,
                mounted.request().source_identity(),
                configuration_digest,
                &member,
                identities,
                requested_at,
                movement.as_ref().map(|m| (m.request().digest(), m.facts())),
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let request = Rc::new(Self {
            creator: std::process::id(),
            kind,
            mounted,
            configuration,
            configuration_digest,
            inputs,
            member,
            plan,
            requested_at,
            digest,
            movement,
        });
        request.verify()?;
        Ok(request)
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.check()?;
        self.verify_retained()?;
        if let Some(movement) = &self.movement {
            movement.request().revalidate_movement_process_pins()?;
        }
        self.check()
    }
    pub(crate) fn verify_retained(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::OwnershipMismatch);
        }
        self.mounted.verify_retained()?;
        for i in &self.inputs {
            if !i.token.contains(i.fd.as_fd()) {
                return Err(Error::DescriptorInventory);
            }
            i.identity.verify(&i.fd)?;
        }
        Ok(())
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::OwnershipMismatch);
        }
        kernel::owner_admission_permitted()?;
        match (&self.movement, self.kind) {
            (Some(m), Kind::Move) if m.request().requested_at() == self.requested_at => {
                m.require()?
            }
            (None, kind) if kind != Kind::Move => (),
            _ => return Err(Error::OwnershipMismatch),
        }
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite()
            || !self.requested_at.is_finite()
            || now < self.requested_at
            || now >= self.deadline()
        {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(crate) fn kind(&self) -> Kind {
        self.kind
    }
    pub(crate) fn mounted(&self) -> &kernel::fresh_transport_mount::Mounted {
        &self.mounted
    }
    pub(crate) fn source(&self) -> BorrowedFd<'_> {
        if self.kind == Kind::DataSockets {
            self.mounted
                .request()
                .original()
                .request()
                .data()
                .request()
                .source()
        } else {
            self.mounted.request().source()
        }
    }
    pub(crate) fn source_identity(&self) -> super::super::owned::Identity {
        if self.kind == Kind::DataSockets {
            self.mounted
                .request()
                .original()
                .request()
                .data()
                .request()
                .source_identity()
        } else {
            self.mounted.request().source_identity()
        }
    }
    pub(crate) fn movement_digest(&self) -> Option<[u8; 32]> {
        self.movement.as_ref().map(|m| m.request().digest())
    }
    pub(crate) fn target(&self) -> BorrowedFd<'_> {
        self.mounted
            .request()
            .original()
            .request()
            .data()
            .request()
            .source()
    }
    pub(crate) fn target_identity(&self) -> super::super::owned::Identity {
        self.mounted
            .request()
            .original()
            .request()
            .data()
            .request()
            .source_identity()
    }
    pub(crate) fn verify_movement_service(&self, service: &Server) -> Result<()> {
        if self.kind != Kind::Move {
            return Ok(());
        }
        self.movement
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .verify_movement_service(service)
    }
    pub(crate) fn member(&self) -> &str {
        &self.member
    }
    pub(crate) fn configuration(&self) -> &vprouter_core::config::PublicConfiguration {
        &self.configuration
    }
    pub(crate) fn configuration_digest(&self) -> [u8; 32] {
        self.configuration_digest
    }
    pub(crate) fn identities(&self) -> Vec<(String, InputIdentity)> {
        self.inputs
            .iter()
            .map(|i| (i.member.clone(), i.identity.clone()))
            .collect()
    }
    pub(crate) fn descriptors(&self) -> Vec<(String, BorrowedFd<'_>)> {
        self.inputs
            .iter()
            .map(|i| (i.member.clone(), i.fd.as_fd()))
            .collect()
    }
    pub(crate) fn plan(&self) -> &vprouter_network::Plan {
        &self.plan
    }
    pub(crate) fn requested_at(&self) -> f64 {
        self.requested_at
    }
    pub(crate) fn deadline(&self) -> f64 {
        self.requested_at + 2.
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

use super::super::{
    kernel::wireguard_role::{Child, Verified},
    owned::preparation::Server,
};
use std::cell::RefCell;

/// The canonical service, all earlier original native receipts and the sole
/// release gate remain in one owner throughout the three fixed operations.
pub(super) struct PendingProvision {
    native: Option<Box<Native>>,
}
pub(super) struct ProvisionedTransport {
    native: Option<Box<Native>>,
}
impl ProvisionedTransport {
    pub(super) fn assembly_operations(&self) -> Result<&[Verified]> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.previous.len() != 5
            || n.child.is_some()
            || n.verified.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(&n.previous)
    }

    pub(super) fn move_down(
        slot: &mut Option<Self>,
        accepted: Rc<kernel::docker_query::Accepted>,
    ) -> Result<PendingProvision> {
        let value = slot.as_ref().ok_or(Error::Interrupted)?;
        let n = value.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.previous.len() != 4
        {
            return Err(Error::OwnershipMismatch);
        }
        accepted.verify_movement_service(n.input.service_ref()?)?;
        let request = Request::at(
            &n.input,
            Kind::Move,
            accepted.request().requested_at(),
            Some(accepted),
        )?;
        let mut old = slot.take().ok_or(Error::Interrupted)?;
        let mut value = PendingProvision {
            native: old.native.take(),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        n.request = request;
        n.step = Step::Intent;
        n.input
            .service()?
            .start_wireguard(&n.request, &n.previous)?;
        Ok(value)
    }
    /// Create only unicast route/generic sockets in the retained original DATA
    /// namespace. No netlink transactions or DATA configuration mutation.
    pub(super) fn data_sockets(slot: &mut Option<Self>) -> Result<PendingProvision> {
        let value = slot.as_ref().ok_or(Error::Interrupted)?;
        let n = value.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.previous.len() != 3
        {
            return Err(Error::OwnershipMismatch);
        }
        let request = Request::new(&n.input, Kind::DataSockets)?;
        let mut old = slot.take().ok_or(Error::Interrupted)?;
        let mut value = PendingProvision {
            native: old.native.take(),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        n.request = request;
        n.step = Step::Intent;
        n.input
            .service()?
            .start_wireguard(&n.request, &n.previous)?;
        Ok(value)
    }
    pub(super) fn movement_binding(
        &self,
    ) -> Result<Rc<super::super::owned::preparation::movement::Binding>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.child.is_some()
            || n.verified.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .service_ref()?
            .bind_movement(n.input.mounted()?, &n.previous)
    }
    pub(super) fn verify_netfilter_prefix(
        &self,
        binding: &Rc<super::super::owned::preparation::quarantine::Binding>,
        previous: &[kernel::netfilter_role::Verified],
    ) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .service_ref()?
            .verify_netfilter_prefix(binding, &n.previous, previous)
    }
    pub(super) fn start_netfilter(
        &mut self,
        request: &Rc<super::quarantine::Request>,
        previous: &[kernel::netfilter_role::Verified],
    ) -> Result<()> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.previous.len() != 5
            || n.child.is_some()
            || n.verified.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .service()?
            .start_netfilter(request, &n.previous, previous)
    }
    pub(super) fn quarantine_binding(
        &self,
    ) -> Result<Rc<super::super::owned::preparation::quarantine::Binding>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
            || n.previous.len() != 5
            || n.child.is_some()
            || n.verified.is_some()
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input
            .service_ref()?
            .bind_quarantine(n.input.mounted()?, &n.previous)
    }
    pub(super) fn service(&mut self) -> Result<&mut Server> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input.service()
    }
    pub(super) fn service_ref(&self) -> Result<&Server> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        n.input.service_ref()
    }
}
struct Native {
    #[cfg(test)]
    lab_anchor: Rc<()>,
    creator: u32,
    input: MountedTransport,
    request: Rc<Request>,
    previous: Vec<Verified>,
    child: Option<Child>,
    verified: Option<Verified>,
    step: Step,
    failure: Option<Error>,
}
#[derive(Clone, Copy)]
enum Step {
    Intent,
    Preparing,
    Birth,
    Executing,
    Result,
    Complete,
}
// Keep the same heap-owned bundle on retention; never move its pointee onto the stack.
thread_local! { #[allow(clippy::vec_box)] static RETAINED: RefCell<Vec<Box<Native>>> = const { RefCell::new(Vec::new()) }; }
impl Native {
    fn fail(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(error);
        if let Ok(service) = self.input.service() {
            service.fail(error);
        }
        if let Some(child) = &mut self.child {
            child.cancel(error);
        }
    }
    fn collect(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        if let Ok(service) = self.input.service() {
            service.collect();
        }
        if let Some(child) = &mut self.child {
            child.collect();
        }
    }
    fn reaped(&self) -> bool {
        self.input.service_ref().is_ok_and(Server::children_reaped)
            && self.child.as_ref().is_none_or(Child::reaped)
    }
    fn advance(&mut self) -> Result<()> {
        #[cfg(test)]
        let span = super::movement::trace::Span::new("inner", "entry_check");
        self.request.check()?;
        #[cfg(test)]
        span.finish();
        match self.step {
            Step::Intent => {
                if let Some(intent) = self.input.service()?.poll_wireguard_intent(&self.request)? {
                    self.child = Some(Child::spawn(
                        self.request.clone(),
                        intent,
                        &mut self.previous,
                    )?);
                    self.step = Step::Preparing;
                }
            }
            Step::Preparing => {
                if self
                    .child
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .poll_prepared()?
                {
                    self.input
                        .service()?
                        .start_wireguard_birth(self.child.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::Birth;
                }
            }
            Step::Birth => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(gate) = self.input.service()?.poll_wireguard_birth(child)? {
                    child.release(gate)?;
                    self.step = Step::Executing;
                }
            }
            Step::Executing => {
                if let Some(verified) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? {
                    self.verified = Some(verified);
                    self.input.service()?.start_wireguard_result(
                        self.verified.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::Result;
                }
            }
            Step::Result => {
                let verified = self.verified.as_mut().ok_or(Error::Interrupted)?;
                #[cfg(test)]
                let span = super::movement::trace::Span::new("inner", "result_poll");
                let receipt = self.input.service()?.poll_wireguard_result(verified)?;
                #[cfg(test)]
                span.finish();
                if let Some(receipt) = receipt {
                    #[cfg(test)]
                    let span = super::movement::trace::Span::new("inner", "verified_accept");
                    verified.accept(receipt)?;
                    #[cfg(test)]
                    span.finish();
                    self.previous
                        .push(self.verified.take().ok_or(Error::Interrupted)?);
                    self.child.take();
                    if (3..=5).contains(&self.previous.len()) {
                        self.step = Step::Complete;
                    } else {
                        let kind =
                            [Kind::Sockets, Kind::Provision, Kind::Query][self.previous.len()];
                        let request = Request::new(&self.input, kind)?;
                        self.input
                            .service()?
                            .start_wireguard(&request, &self.previous)?;
                        self.request = request;
                        self.step = Step::Intent;
                    }
                }
            }
            Step::Complete => (),
        }
        #[cfg(test)]
        let span = super::movement::trace::Span::new("inner", "final_check");
        self.request.check()?;
        #[cfg(test)]
        span.finish();
        Ok(())
    }
}
fn retain(mut native: Box<Native>) {
    if native.creator != std::process::id() {
        std::mem::forget(native);
        return;
    }
    native.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(native));
}
impl Drop for PendingProvision {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for ProvisionedTransport {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl PendingProvision {
    pub(super) fn fail(&mut self, error: Error) {
        if let Some(n) = &mut self.native {
            n.fail(error);
        }
    }
    pub(super) fn collect(&mut self) {
        if let Some(n) = &mut self.native {
            n.collect();
        }
    }
    pub(super) fn reaped(&self) -> bool {
        self.native
            .as_ref()
            .is_none_or(|n| n.creator == std::process::id() && n.reaped())
    }
    pub(super) fn new(slot: &mut Option<MountedTransport>) -> Result<Self> {
        if RETAINED.with(|r| {
            r.borrow()
                .iter()
                .filter(|n| n.creator == std::process::id())
                .count()
        }) >= 64
        {
            return Err(Error::OwnershipMismatch);
        }
        let request = Request::new(slot.as_ref().ok_or(Error::Interrupted)?, Kind::Sockets)?;
        let mut pending = Self {
            native: Some(Box::new(Native {
                #[cfg(test)]
                lab_anchor: Rc::new(()),
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                request,
                previous: Vec::with_capacity(3),
                child: None,
                verified: None,
                step: Step::Intent,
                failure: None,
            })),
        };
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        n.input
            .service()?
            .start_wireguard(&n.request, &n.previous)?;
        Ok(pending)
    }
    pub(super) fn poll(&mut self) -> Result<Option<ProvisionedTransport>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = n.failure {
            n.collect();
            return Err(error);
        }
        if let Err(error) = n.advance() {
            #[cfg(test)]
            if n.request.kind() == Kind::Move && super::movement::trace::active() {
                eprintln!("LAB_MOVEMENT_PRIMARY_FAILURE scope=inner reason={error:?}");
                super::movement::trace::emit(
                    "inner",
                    error,
                    n.lab_cached_progress().unwrap_or(serde_json::Value::Null),
                );
            }
            n.fail(error);
            n.collect();
            return Err(error);
        }
        if matches!(n.step, Step::Complete) {
            Ok(Some(ProvisionedTransport {
                native: self.native.take(),
            }))
        } else {
            Ok(None)
        }
    }
}
pub(super) fn poll_retained() {
    RETAINED.with(|r| {
        for n in r.borrow_mut().iter_mut() {
            n.collect();
        }
    });
}
pub(super) fn children_reaped() -> bool {
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reaped())
    })
}

#[cfg(test)]
pub(crate) fn lab_run(fault: u8) -> Result<()> {
    lab_build(fault, false).map(|_| ())
}
#[cfg(test)]
pub(super) fn lab_provisioned() -> Result<(ProvisionedTransport, serde_json::Value)> {
    lab_build(0, true)?.ok_or(Error::OwnershipMismatch)
}
#[cfg(test)]
fn lab_build(
    fault: u8,
    continuing: bool,
) -> Result<Option<(ProvisionedTransport, serde_json::Value)>> {
    use super::transport::{PendingTransport, PendingTransportMount};
    use std::time::Duration;
    let label = match fault {
        0 => "actual_secret_free_parent_fresh_transport_down_wireguard_provision_query",
        1 => "actual_wireguard_postbirth_failure_retains_original_constructor",
        2 => "actual_wireguard_result_writer_failure_retains_original_network",
        3 => "actual_wireguard_partial_registration_failure_retains_prepared_context",
        _ => return Err(Error::InvalidSpec),
    };
    let (attached, attachment) = super::mount::lab_attached()?;
    let mut attached = Some(attached);
    let mut source = PendingTransport::new(&mut attached)?;
    let created = loop {
        match source.poll() {
            Ok(Some(v)) => break v,
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => {
                eprintln!("LAB_SECRET_PROVISION_FAILURE phase=transport_creation reason={e:?}");
                return Err(e);
            }
        }
    };
    let mut created = Some(created);
    let mut mount = PendingTransportMount::new(&mut created)?;
    let mounted = loop {
        match mount.poll() {
            Ok(Some(v)) => break v,
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => {
                eprintln!("LAB_SECRET_PROVISION_FAILURE phase=transport_mount reason={e:?}");
                return Err(e);
            }
        }
    };
    let original_mount = mounted.mounted()?;
    let transport_creation = original_mount.request().original().lab_evidence()?;
    let transport_mount = original_mount.lab_evidence()?;
    let mut mounted = Some(mounted);
    let mut pending = PendingProvision::new(&mut mounted)?;
    let native = pending.native.as_ref().ok_or(Error::Interrupted)?;
    let weak = Rc::downgrade(&native.lab_anchor);
    if fault == 1 || fault == 3 {
        kernel::wireguard_role::lab_arm_fault(&native.request, fault)?;
    }
    let mut held = false;
    let mut hold_armed = false;
    let result = loop {
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        if fault == 2
            && !hold_armed
            && n.request.kind() == Kind::Provision
            && matches!(n.step, Step::Executing)
        {
            n.input.service()?.lab_hold_provision_result()?;
            hold_armed = true;
        }
        match pending.poll() {
            Ok(Some(value)) => break Ok(value),
            Err(error) => break Err(error),
            Ok(None) => (),
        }
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        // Never consume a checkpoint/ACK outside this exact held writer phase.
        if fault == 2
            && n.request.kind() == Kind::Provision
            && matches!(n.step, Step::Result)
            && n.input.service()?.lab_checkpoint()?
        {
            if n.input.service_ref()?.children_reaped() {
                return Err(Error::OwnershipMismatch);
            }
            held = true;
            n.fail(Error::ChildFailed);
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let mut complete = None;
    let mut failed_constructor = None;
    match result {
        Ok(value) if fault == 0 => complete = Some(value),
        Ok(_) => return Err(Error::OwnershipMismatch),
        Err(error) => {
            let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
            eprintln!(
                "LAB_SECRET_PROVISION_FAILURE kind={:?} phase={} reason={error:?} requested_at={} deadline={} now={}",
                n.request.kind(),
                match n.step {
                    Step::Intent => "intent",
                    Step::Preparing => "preparing",
                    Step::Birth => "birth",
                    Step::Executing => "executing",
                    Step::Result => "result",
                    Step::Complete => "complete",
                },
                n.request.requested_at(),
                n.request.deadline(),
                vprouter_core::health::boot_seconds()
            );
            if !(fault == 2 && held && error == Error::ChildFailed
                || [1, 3].contains(&fault) && error == Error::DescriptorInventory)
            {
                return Err(error);
            }
            let drain_end = vprouter_core::health::boot_seconds() + 2.;
            loop {
                n.collect();
                if [1, 3].contains(&fault) {
                    failed_constructor = kernel::wireguard_role::lab_failed_context(&n.request)?;
                }
                if n.reaped() && (!matches!(fault, 1 | 3) || failed_constructor.is_some()) {
                    break;
                }
                if vprouter_core::health::boot_seconds() >= drain_end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    let n = if let Some(c) = &mut complete {
        c.native.as_mut()
    } else {
        pending.native.as_mut()
    }
    .ok_or(Error::Interrupted)?;
    let preparation = n.input.service()?.lab_evidence()?;
    let mut operations = Vec::new();
    let mut borrowed = true;
    for i in 1..n.previous.len() {
        borrowed &= n.previous[i].lab_borrowed_from(&n.previous[i - 1])?;
    }
    if let Some(v) = &n.verified {
        borrowed &= v.lab_borrowed_from(n.previous.last().ok_or(Error::OwnershipMismatch)?)?;
    }
    for v in &mut n.previous {
        operations.push(v.lab_evidence()?);
    }
    if let Some(v) = &mut n.verified {
        operations.push(v.lab_evidence()?);
    }
    let expected_count = match fault {
        0 => 33,
        1 | 3 => 25,
        2 => 30,
        _ => unreachable!(),
    };
    let writers = preparation["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let old = attachment["preparation"]["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    if writers.len() != expected_count
        || writers.get(..17) != Some(old.as_slice())
        || preparation["canonical_owner_epoch"]
            != attachment["preparation"]["canonical_owner_epoch"]
        || preparation["member"] != attachment["preparation"]["member"]
        || preparation["base_network"] != attachment["preparation"]["base_network"]
        || preparation["data_network"] != attachment["preparation"]["data_network"]
        || preparation["inspection"] != attachment["preparation"]["inspection"]
        || preparation["attachment"] != attachment["preparation"]["attachment"]
        || preparation["service_reserved"] != true
        || preparation["native_children_reaped"] != true
        || preparation["member_native_jobs_collected"] != false
        || preparation["canonical_pending"] != (fault == 2)
        || preparation["mutation_fenced"] != (fault == 2)
        || transport_creation["actual_wait_status"] != 0
        || transport_creation["eof"] != true
        || transport_creation["source"] == transport_creation["host"]
        || transport_creation["source"] == transport_creation["data"]
        || transport_mount["actual_wait_status"] != 0
        || transport_mount["eof"] != true
        || transport_mount["original_source"] != transport_creation["source"]
        || preparation["transport_network"] != transport_creation["source"]
        || !borrowed
        || !vprouter_core::secret_boundary::pristine()
    {
        return Err(Error::OwnershipMismatch);
    }
    let appended = [
        "transport_intent",
        "transport_birth",
        "transport_source",
        "transport_mount_intent",
        "transport_mount_birth",
        "transport_mount_placeholder",
        "transport_mount_publication",
        "wireguard_intent",
        "wireguard_birth",
        "wireguard_result",
        "wireguard_intent",
        "wireguard_birth",
        "wireguard_result",
        "wireguard_intent",
        "wireguard_birth",
        "wireguard_result",
    ];
    let histories = preparation["wireguard"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    for (index, w) in writers.iter().enumerate().skip(17) {
        let end = if index < 20 {
            transport_creation["deadline"].as_f64()
        } else if index < 24 {
            transport_mount["deadline"].as_f64()
        } else {
            histories
                .get((index - 24) / 3)
                .and_then(|h| h["deadline"].as_f64())
        }
        .ok_or(Error::OwnershipMismatch)?;
        let queued = w["queued_at"].as_f64().ok_or(Error::OwnershipMismatch)?;
        let failed_last = fault == 2 && index + 1 == writers.len();
        if w["phase"] != appended[index - 17]
            || !end.is_finite()
            || !queued.is_finite()
            || queued < end - 2.
            || queued >= end
            || w["io_deadline"] != end
            || w["parent_deadline"] != end
            || w["actual_wait_status"] != if failed_last { 9 } else { 0 }
            || if failed_last {
                !w["verified_at"].is_null()
            } else {
                w["verified_at"]
                    .as_f64()
                    .is_none_or(|at| !at.is_finite() || at < queued || at >= end)
            }
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    let expected_operations = if fault == 0 {
        3
    } else if fault == 2 {
        2
    } else {
        0
    };
    if operations.len() != expected_operations
        || histories.len()
            != if fault == 0 {
                3
            } else if fault == 2 {
                2
            } else {
                1
            }
    {
        return Err(Error::OwnershipMismatch);
    }
    for (i, op) in operations.iter().enumerate() {
        let h = &histories[i];
        let unacknowledged = fault == 2 && i == 1;
        let result_history = if unacknowledged {
            if !h["result"].is_null() || !h["verified_at"].is_null() {
                return Err(Error::OwnershipMismatch);
            }
            let proposed = preparation["pending_wireguard"]
                .as_array()
                .and_then(|h| h.get(i))
                .ok_or(Error::OwnershipMismatch)?;
            if proposed["birth"] != h["birth"]
                || proposed["request"] != h["request"]
                || proposed["requested_at"] != h["requested_at"]
                || proposed["deadline"] != h["deadline"]
            {
                return Err(Error::OwnershipMismatch);
            }
            proposed
        } else {
            h
        };

        if op["actual_wait_status"] != 0
            || op["native_born"] != true
            || op["native_job_state"] != "born"
            || op["full_descriptor_registration"] != true
            || op["context_retained"] != true
            || op["borrowed_registration_count"] != if i == 0 { 0 } else { 2 }
            || op["birth"] != h["birth"]
            || op["request"] != h["request"]
            || op["deadline"] != h["deadline"]
            || op["requested_at"] != h["requested_at"]
            || op["result"] != result_history["result"]
            || op["accepted_at"] != result_history["verified_at"]
            || op["acknowledged"] != !(fault == 2 && i == 1)
        {
            return Err(Error::OwnershipMismatch);
        }
        if i > 0
            && (op["result"]["link"]["up"] != false || op["result"]["link"]["kind"] != "wireguard")
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    if let Some(f) = &failed_constructor
        && (f["request"] != histories[0]["request"]
            || f["kind"] != "sockets"
            || f["full_descriptor_registration"] != true
            || f["native_born"] != (fault == 1)
            || f["native_job_state"] != if fault == 1 { "born" } else { "prepared" }
            || f["acknowledged"] != false
            || !f["birth"].is_null()
            || !f["accepted_at"].is_null()
            || !f["original_start"].is_null()
            || !histories[0]["birth"].is_null()
            || if fault == 1 {
                f["actual_wait_status"] != 9 || f["original_pid"].as_u64().is_none_or(|p| p <= 1)
            } else {
                !f["actual_wait_status"].is_null() || !f["original_pid"].is_null()
            })
    {
        return Err(Error::OwnershipMismatch);
    }
    let mut witness = serde_json::json!({"schema":1,"fault":fault,"attachment":attachment,"preparation":preparation,
        "transport_creation":transport_creation,"transport_mount":transport_mount,"operations":operations,
        "failed_constructor":failed_constructor,"held_real_result_writer":held,"unacknowledged_native_result_retained":fault==2,"parent_pristine":true,
        "same_service_retained":true,"whole_context_retained_after_drop":true,"transport_distinct_from_host_and_data":true,
        "original_socket_registrations_borrowed":borrowed,"wireguard_down_only":!matches!(fault,1|3),
        "host_resources_created":false,"operational_reuse_authorized":false,"requirement8_complete":false});
    if continuing {
        if fault != 0 || weak.upgrade().is_none() {
            return Err(Error::OwnershipMismatch);
        }
        witness["whole_context_retained_after_drop"] = false.into();
        witness["continued_original_context"] = true.into();
        return Ok(Some((
            complete.take().ok_or(Error::OwnershipMismatch)?,
            witness,
        )));
    }
    drop(complete);
    drop(pending);
    if weak.upgrade().is_none() {
        return Err(Error::OwnershipMismatch);
    }
    println!("{}", serde_json::json!({"case":label,"result":"PASS"}));
    println!("LAB_SECRET_PROVISION {witness}");
    Ok(None)
}

#[cfg(test)]
impl Native {
    fn lab_movement_evidence(&mut self) -> Result<serde_json::Value> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let move_proof = self.verified.as_ref().or_else(|| self.previous.get(4));
        let borrowed = if let Some(v) = move_proof {
            v.lab_move_borrowed_from(
                self.previous.get(2).ok_or(Error::OwnershipMismatch)?,
                self.previous.get(3).ok_or(Error::OwnershipMismatch)?,
            )?
        } else {
            false
        };
        let mut operations = Vec::new();
        for v in &mut self.previous {
            operations.push(v.lab_evidence()?);
        }
        if let Some(v) = &mut self.verified {
            operations.push(v.lab_evidence()?);
        }
        Ok(
            serde_json::json!({"preparation":self.input.service()?.lab_evidence()?,
            "operations":operations,"move_borrows_both_original_pairs":borrowed}),
        )
    }
}
#[cfg(test)]
impl ProvisionedTransport {
    pub(super) fn lab_movement_evidence(&mut self) -> Result<serde_json::Value> {
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .lab_movement_evidence()
    }
    pub(super) fn lab_weak(&self) -> Result<std::rc::Weak<()>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(Rc::downgrade(&n.lab_anchor))
    }
}
#[cfg(test)]
impl PendingProvision {
    pub(super) fn lab_move_injection(&mut self, fault: u8, armed: &mut bool) -> Result<bool> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() || n.request.kind() != Kind::Move {
            return Err(Error::OwnershipMismatch);
        }
        if !*armed {
            if [1, 3].contains(&fault) && matches!(n.step, Step::Intent) {
                kernel::wireguard_role::lab_arm_fault(&n.request, fault)?;
                *armed = true;
            } else if fault == 2 && matches!(n.step, Step::Executing) {
                n.input.service()?.lab_hold_provision_result()?;
                *armed = true;
            }
        }
        if fault == 2
            && *armed
            && matches!(n.step, Step::Result)
            && n.input.service()?.lab_checkpoint()?
        {
            if n.input.service_ref()?.children_reaped() {
                return Err(Error::OwnershipMismatch);
            }
            n.fail(Error::ChildFailed);
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn lab_failed_move(&mut self) -> Result<Option<serde_json::Value>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() || n.request.kind() != Kind::Move {
            return Err(Error::OwnershipMismatch);
        }
        kernel::wireguard_role::lab_failed_context(&n.request)
    }
    pub(super) fn lab_movement_evidence(&mut self) -> Result<serde_json::Value> {
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .lab_movement_evidence()
    }
}

#[cfg(test)]
impl Native {
    fn lab_cached_progress(&self) -> Option<serde_json::Value> {
        if self.creator != std::process::id() {
            return None;
        }
        Some(
            serde_json::json!({"step":match self.step {Step::Intent=>"intent",Step::Preparing=>"preparing",Step::Birth=>"birth",Step::Executing=>"executing",Step::Result=>"result",Step::Complete=>"complete"},
            "request":self.request.digest(),"requested_at":self.request.requested_at(),"deadline":self.request.deadline(),
            "child":self.child.as_ref().and_then(Child::lab_cached_progress),
            "verified":self.verified.as_ref().and_then(Verified::lab_cached_progress),
            "last_history":self.previous.last().and_then(Verified::lab_cached_progress),
            "preparation":self.input.service_ref().ok().and_then(Server::lab_cached_quarantine_progress)}),
        )
    }
}
#[cfg(test)]
impl PendingProvision {
    pub(super) fn lab_cached_progress(&self) -> Option<serde_json::Value> {
        self.native.as_ref()?.lab_cached_progress()
    }
}
#[cfg(test)]
impl ProvisionedTransport {
    pub(super) fn lab_cached_progress(&self) -> Option<serde_json::Value> {
        self.native.as_ref()?.lab_cached_progress()
    }
}
