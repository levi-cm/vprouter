//! Sole canonical-owner release gate for original fixed nft operations.
//! Parsed history and matching tables cannot instantiate this adapter.
use super::super::{
    attachment::quarantine::{Kind, Request},
    owned::{
        Identity,
        preparation::{
            Server, ValidationBirth,
            quarantine::{Gate, Intent, PublicResult, Receipt},
        },
    },
};
use super::*;
use std::{cell::RefCell, rc::Rc};
use vprouter_native_role::{ReapWitness, WireguardReleaseGate};
use vprouter_netfilter::{
    PendingInitialQuarantine, PendingNetfilterSockets, VerifiedInitialQuarantine,
    VerifiedNetfilterSockets,
};
// Bounded three-operation custody stays inline: no allocation during transfer.
#[allow(clippy::large_enum_variant)]
enum Pending {
    Sockets(PendingNetfilterSockets),
    Initial(PendingInitialQuarantine),
    Empty,
}
#[allow(clippy::large_enum_variant)]
enum Complete {
    Sockets(Option<VerifiedNetfilterSockets>),
    Initial(Option<VerifiedInitialQuarantine>),
}
struct Native {
    creator: u32,
    request: Rc<Request>,
    intent: Intent,
    gate: WireguardReleaseGate,
    _gate_token: super::super::inventory::Registration,
    stable_token: Option<super::super::inventory::Registration>,
    child_tokens: Option<super::super::inventory::Registration>,
    pid_token: Option<super::super::inventory::Registration>,
    received_tokens: Vec<Rc<super::super::inventory::Registration>>,
    borrowed_tokens: Vec<Rc<super::super::inventory::Registration>>,
    pending: Pending,
    complete: Option<Complete>,
    _capacity: Option<ChildCapacity>,
    born: bool,
    original: Option<ReapWitness>,
    birth: Option<ValidationBirth>,
    result: Option<PublicResult>,
    accepted_at: Option<f64>,
    acknowledged: bool,
    failure: Option<Error>,
}
pub(crate) struct Child {
    native: Option<Native>,
}
pub(crate) struct Verified {
    native: Option<Native>,
}
#[cfg(test)]
impl Child {
    // Cached constructor context only. No descriptor checks, receive or reap.
    pub(crate) fn lab_cached_failure_context(&self) -> Option<serde_json::Value> {
        let n = self.native.as_ref()?;
        if n.creator != std::process::id() {
            return None;
        }
        let identity = n.original.as_ref().and_then(|r| r.original().ok());
        Some(serde_json::json!({
            "pid":identity.map(|v|v.0),"start":identity.and_then(|v|v.1),
            "actual_wait_status":n.original.as_ref().and_then(|r|r.actual_status().ok().flatten()),
            "born":n.born,"birth":n.birth,"accepted_at":n.accepted_at,
        }))
    }
}
fn map(_: vprouter_netfilter::Error) -> Error {
    Error::NetworkOperation
}
fn raw(_: vprouter_native_role::Error) -> Error {
    Error::DescriptorPolicy
}
impl Pending {
    fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        match self {
            Self::Sockets(p) => p.descriptors().map_err(map),
            Self::Initial(p) => p.descriptors().map_err(map),
            Self::Empty => Ok(vec![]),
        }
    }
    fn endpoints(&self) -> Result<[BorrowedFd<'_>; 2]> {
        match self {
            Self::Sockets(p) => p.child_endpoints_before_birth().map_err(map),
            Self::Initial(p) => p.child_endpoints_before_birth().map_err(map),
            Self::Empty => Err(Error::Interrupted),
        }
    }
    fn validate_prepared(&mut self) -> Result<()> {
        match self {
            Self::Sockets(_) => Ok(()),
            Self::Initial(p) => p.validate_prepared().map_err(map),
            Self::Empty => Err(Error::Interrupted),
        }
    }
    fn birth(&mut self) -> Result<ReapWitness> {
        match self {
            Self::Sockets(p) => p.birth().map_err(map),
            Self::Initial(p) => p.birth().map_err(map),
            Self::Empty => Err(Error::Interrupted),
        }
    }
    fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        match self {
            Self::Sockets(p) => p.pidfd().map_err(map),
            Self::Initial(p) => p.pidfd().map_err(map),
            Self::Empty => Err(Error::Interrupted),
        }
    }
    fn identify(&mut self) -> Result<ValidationBirth> {
        let b = match self {
            Self::Sockets(p) => p.identify().map_err(map)?,
            Self::Initial(p) => p.identify().map_err(map)?,
            Self::Empty => return Err(Error::Interrupted),
        };
        Ok(ValidationBirth {
            pid: b.pid,
            start: b.start,
            born_at: b.born_at,
            deadline: b.deadline,
        })
    }
    fn cancel(&mut self) {
        match self {
            Self::Sockets(p) => p.cancel(),
            Self::Initial(p) => p.cancel(vprouter_netfilter::Error::Interrupted),
            Self::Empty => (),
        }
    }
    fn collect(&mut self) {
        match self {
            Self::Sockets(p) => p.collect(),
            Self::Initial(p) => p.collect(),
            Self::Empty => (),
        }
    }
}
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            Err(Error::OwnershipMismatch)
        } else {
            Ok(())
        }
    }
    fn fail(&mut self, e: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(e);
        self.gate.cancel();
        self.pending.cancel();
    }
    fn register_received(&mut self) -> Result<()> {
        self.creator()?;
        for fd in self.pending.descriptors()? {
            if self.stable_token.as_ref().is_some_and(|t| t.contains(fd))
                || self.pid_token.as_ref().is_some_and(|t| t.contains(fd))
                || self.child_tokens.as_ref().is_some_and(|t| t.contains(fd))
                || self.received_tokens.iter().any(|t| t.contains(fd))
                || self.borrowed_tokens.iter().any(|t| t.contains(fd))
            {
                continue;
            }
            self.received_tokens
                .push(Rc::new(super::super::inventory::Registration::owned(&[
                    fd,
                ])?));
        }
        Ok(())
    }
    fn collect(&mut self) {
        if self.creator != std::process::id() {
            return;
        }
        let _ = self.register_received();
        self.pending.collect();
    }
    fn reaped(&self) -> bool {
        !self.born
            || self
                .original
                .as_ref()
                .is_some_and(|r| r.actual_status().is_ok_and(|s| s.is_some()))
    }
    fn original(&self) -> Result<&ReapWitness> {
        self.creator()?;
        self.original.as_ref().ok_or(Error::OwnershipMismatch)
    }
}
thread_local! {static RETAINED:RefCell<Vec<Native>>=const{RefCell::new(Vec::new())};}
fn retain(mut n: Native) {
    if n.creator != std::process::id() {
        std::mem::forget(n);
        return;
    }
    n.fail(Error::Interrupted);
    RETAINED.with(|r| r.borrow_mut().push(n));
}
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for Verified {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
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
impl Child {
    pub(crate) fn original_request(&self) -> Result<&Rc<Request>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(&n.request)
    }
    pub(crate) fn require_request(&self, request: &Rc<Request>) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        if !Rc::ptr_eq(&n.request, request) {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn spawn(
        request: Rc<Request>,
        mut intent: Intent,
        previous: &mut [Verified],
    ) -> Result<Self> {
        process::single_threaded()?;
        secret::seal_parent()?;
        owner_admission_permitted()?;
        intent.prepare(&request)?;
        let (gate, child_gate) =
            vprouter_native_role::prepare_wireguard_gate(request.digest(), request.deadline())
                .map_err(raw)?;
        let gate_token =
            super::super::inventory::Registration::owned(&[gate.descriptor().map_err(raw)?])?;
        let mut borrowed_tokens = Vec::new();
        let pending = match request.kind() {
            Kind::Sockets => Pending::Sockets(
                PendingNetfilterSockets::prepare(
                    request.policy().clone(),
                    request.source(),
                    request.digest(),
                    request.deadline(),
                    child_gate,
                )
                .map_err(map)?,
            ),
            Kind::InitialQuarantine => {
                let prior = previous.last_mut().ok_or(Error::OwnershipMismatch)?;
                prior.require_acknowledged()?;
                let n = prior.native.as_mut().ok_or(Error::Interrupted)?;
                intent.verify_previous(&n.intent)?;
                borrowed_tokens.extend(n.received_tokens.iter().cloned());
                let Some(Complete::Sockets(slot)) = &mut n.complete else {
                    return Err(Error::OwnershipMismatch);
                };
                Pending::Initial(
                    PendingInitialQuarantine::prepare(
                        slot,
                        request.digest(),
                        request.deadline(),
                        child_gate,
                    )
                    .map_err(map)?,
                )
            }
        };
        // Store all original custody before endpoint/registration or any other
        // fallible post-preparation work, including the NoBirth error paths.
        let mut value = Self {
            native: Some(Native {
                creator: std::process::id(),
                request,
                intent,
                gate,
                _gate_token: gate_token,
                stable_token: None,
                child_tokens: None,
                pid_token: None,
                received_tokens: Vec::new(),
                borrowed_tokens,
                pending,
                complete: None,
                _capacity: None,
                born: false,
                original: None,
                birth: None,
                result: None,
                accepted_at: None,
                acknowledged: false,
                failure: None,
            }),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        let result = (|| {
            let endpoints = n.pending.endpoints()?;
            let raw_endpoints = [endpoints[0].as_raw_fd(), endpoints[1].as_raw_fd()];
            n.child_tokens = Some(super::super::inventory::Registration::owned(&endpoints)?);
            let stable: Vec<_> = n
                .pending
                .descriptors()?
                .into_iter()
                .filter(|f| !raw_endpoints.contains(&f.as_raw_fd()))
                .filter(|f| !n.borrowed_tokens.iter().any(|t| t.contains(*f)))
                .collect();
            n.stable_token = Some(super::super::inventory::Registration::owned(&stable)?);
            super::super::inventory::verify()?;
            n.pending.validate_prepared()?;
            n.request.verify()?;
            owner_admission_permitted()?;
            require_child_capacity()?;
            let original = n.pending.birth()?;
            n._capacity = Some(ChildCapacity::created());
            n.born = true;
            n.intent
                .lease()
                .native_job_mut()
                .born_netfilter(original.clone());
            n.original = Some(original);
            n.child_tokens.take();
            n.pid_token = Some(super::super::inventory::Registration::owned(&[n
                .pending
                .pidfd()?])?);
            n.birth = Some(n.pending.identify()?);
            n.request.check()
        })();
        if let Err(e) = result {
            n.fail(e);
            return Err(e);
        }
        Ok(value)
    }
    pub(crate) fn bind_service(&self, s: &Server) -> Result<()> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .intent
            .same_service(s)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.birth.clone().ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn verify_birth_slot(
        &self,
        index: usize,
        h: &super::super::owned::preparation::quarantine::Operation,
    ) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.intent.verify_binding(&n.request)?;
        n.request.verify()?;
        n.intent.verify_birth_slot(index, h)
    }
    pub(crate) fn verify_gate(&self, g: &Gate) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.intent.verify_binding(&n.request)?;
        g.verify(&n.intent, &self.birth()?)
    }
    pub(crate) fn release(&mut self, g: Gate) -> Result<()> {
        self.verify_gate(&g)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let result = (|| {
            n.request.verify()?;
            if n.failure.is_some() {
                return Err(Error::Interrupted);
            }
            owner_admission_permitted()?;
            let original = n.original()?.clone();
            if !n.gate.matches(&original).map_err(raw)? {
                return Err(Error::OwnershipMismatch);
            }
            n.gate.release(&original).map_err(raw)?;
            n.request.check()
        })();
        if let Err(e) = result {
            n.fail(e);
        }
        result
    }
    pub(crate) fn poll(&mut self) -> Result<Option<Verified>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = (|| {
            n.request.verify()?;
            if let Some(e) = n.failure {
                return Err(e);
            }
            if let Pending::Sockets(p) = &mut n.pending {
                p.receive_native().map_err(map)?;
            }
            n.register_received()?;
            match &mut n.pending {
                Pending::Sockets(p) => {
                    let Some(v) = p.poll().map_err(map)? else {
                        return Ok(false);
                    };
                    // Store before any fallible result extraction.
                    n.complete = Some(Complete::Sockets(Some(v)));
                }
                Pending::Initial(p) => {
                    let Some(v) = p.poll().map_err(map)? else {
                        return Ok(false);
                    };
                    n.complete = Some(Complete::Initial(Some(v)));
                }
                Pending::Empty => return Err(Error::OwnershipMismatch),
            }
            n.pending = Pending::Empty;
            let (identity, policy, observed_at, at) =
                match n.complete.as_ref().ok_or(Error::Interrupted)? {
                    Complete::Sockets(Some(v)) => (
                        v.namespace_identity().map_err(map)?,
                        n.request.policy_digest(),
                        None,
                        v.accepted_at().map_err(map)?,
                    ),
                    Complete::Initial(Some(v)) => (
                        v.namespace_identity().map_err(map)?,
                        v.policy_digest().map_err(map)?,
                        Some(v.observed_at().map_err(map)?),
                        v.accepted_at().map_err(map)?,
                    ),
                    _ => return Err(Error::OwnershipMismatch),
                };
            n.result = Some(PublicResult {
                namespace: Identity {
                    dev: identity.0,
                    ino: identity.1,
                },
                policy,
                observed_at,
            });
            n.accepted_at = Some(at);
            if n.original()?.actual_status().map_err(raw)? != Some(0) {
                return Err(Error::ChildFailed);
            }
            n.request.verify()?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(Verified {
                native: self.native.take(),
            })),
            Err(e) => {
                n.fail(e);
                n.collect();
                Err(e)
            }
        }
    }
    pub(crate) fn cancel(&mut self, e: Error) {
        if let Some(n) = &mut self.native {
            n.fail(e);
        }
    }
    pub(crate) fn collect(&mut self) {
        if let Some(n) = &mut self.native {
            n.collect();
        }
    }
    pub(crate) fn reaped(&self) -> bool {
        self.native
            .as_ref()
            .is_none_or(|n| n.creator == std::process::id() && n.reaped())
    }
}
impl Verified {
    pub(crate) fn prepare_producer_observation(
        &mut self,
        descriptors: vprouter_native_role::ProducerDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        child_gate: vprouter_native_role::WireguardChildGate,
    ) -> Result<(
        vprouter_netfilter::PendingProducerObservation,
        Vec<Rc<super::super::inventory::Registration>>,
    )> {
        self.require_acknowledged()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.request.kind() != Kind::InitialQuarantine
            || n.request.scope() != super::super::attachment::quarantine::Scope::Data
        {
            return Err(Error::OwnershipMismatch);
        }
        for token in n.borrowed_tokens.iter().chain(&n.received_tokens) {
            token.retained_slots()?;
        }
        let borrowed = n.borrowed_tokens.clone();
        if borrowed.len() != 2 {
            return Err(Error::DescriptorInventory);
        }
        let Some(Complete::Initial(slot)) = &mut n.complete else {
            return Err(Error::OwnershipMismatch);
        };
        let pending = vprouter_netfilter::PendingProducerObservation::prepare(
            slot,
            descriptors,
            digest,
            end,
            child_gate,
        )
        .map_err(map)?;
        // No fallible work after the original actor is transferred. The caller
        // stores this entire pending + original token links before validation.
        Ok((pending, borrowed))
    }
    pub(crate) fn prepare_bootstrap(
        &mut self,
        request: &super::super::attachment::operational::bootstrap::Request,
        child_gate: vprouter_native_role::WireguardChildGate,
    ) -> Result<(
        vprouter_netfilter::PendingBootstrap,
        Vec<Rc<super::super::inventory::Registration>>,
    )> {
        self.require_acknowledged()?;
        request.verify()?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.request.kind() != Kind::InitialQuarantine
            || n.request.scope() != request.scope()
            || request.scope() == super::super::attachment::quarantine::Scope::Data
            || !Rc::ptr_eq(n.request.binding(), request.binding())
            || n.request.policy_digest() != request.policy_digest()
        {
            return Err(Error::OwnershipMismatch);
        }
        for token in n.borrowed_tokens.iter().chain(&n.received_tokens) {
            token.retained_slots()?;
        }
        let borrowed = n.borrowed_tokens.clone();
        if borrowed.len() != 2 {
            return Err(Error::DescriptorInventory);
        }
        let Some(Complete::Initial(slot)) = &mut n.complete else {
            return Err(Error::OwnershipMismatch);
        };
        let pending = vprouter_netfilter::PendingBootstrap::prepare_initial(
            slot,
            request.descriptors()?,
            request.ancestry()?,
            request.digest(),
            request.deadline(),
            child_gate,
        )
        .map_err(map)?;
        Ok((pending, borrowed))
    }
    pub(crate) fn resource_transfer(&self) -> Result<ResourceTransfer> {
        self.require_acknowledged()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        // The historical acceptance remains immutable. Recheck custody of
        // every original registration before releasing its child charge.
        n._gate_token.retained_slots()?;
        n.stable_token
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .retained_slots()?;
        n.pid_token
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .retained_slots()?;
        if n.child_tokens.is_some() {
            return Err(Error::DescriptorInventory);
        }
        for token in n.received_tokens.iter().chain(&n.borrowed_tokens) {
            token.retained_slots()?;
        }
        ResourceTransfer::lower(
            n.intent.transfer_ticket()?,
            NativeJobKind::FixedNetfilter,
            n.original()?,
            n._capacity.as_ref().ok_or(Error::OwnershipMismatch)?,
        )
    }
    pub(crate) fn historical_accepted_at(&self) -> Result<f64> {
        self.require_acknowledged()?;
        self.native
            .as_ref()
            .and_then(|n| n.accepted_at)
            .ok_or(Error::OwnershipMismatch)
    }

    pub(crate) fn verify(&self) -> Result<()> {
        self.verify_history()?;
        self.request().verify()
    }
    fn verify_history(&self) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.request.verify_retained()?;
        if n.failure.is_some()
            || n.original()?.actual_status().map_err(raw)? != Some(0)
            || n.result.is_none()
            || n.complete.is_none()
            || n.accepted_at.is_none_or(|at| {
                !at.is_finite()
                    || at >= n.request.deadline()
                    || n.birth.as_ref().is_none_or(|b| at < b.born_at)
            })
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn require_acknowledged(&self) -> Result<()> {
        self.verify_history()?;
        if !self.native.as_ref().ok_or(Error::Interrupted)?.acknowledged {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn accept(&mut self, receipt: Receipt) -> Result<()> {
        self.verify()?;
        receipt.verify(self)?;
        self.native.as_mut().ok_or(Error::Interrupted)?.acknowledged = true;
        Ok(())
    }
    pub(crate) fn bind_service(&self, s: &Server) -> Result<()> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .intent
            .same_service(s)
    }
    pub(crate) fn intent(&self) -> Result<&Intent> {
        self.native.as_ref().ok_or(Error::Interrupted)?.creator()?;
        Ok(&self.native.as_ref().ok_or(Error::Interrupted)?.intent)
    }
    pub(crate) fn request(&self) -> &Rc<Request> {
        &self
            .native
            .as_ref()
            .expect("original network receipt")
            .request
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.birth.clone().ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn historical_result(&self) -> Result<&PublicResult> {
        self.require_acknowledged()?;
        self.native
            .as_ref()
            .and_then(|n| n.result.as_ref())
            .ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn result(&self) -> Result<&PublicResult> {
        self.verify()?;
        self.native
            .as_ref()
            .and_then(|n| n.result.as_ref())
            .ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn accepted_at(&self) -> Result<f64> {
        self.verify()?;
        self.native
            .as_ref()
            .and_then(|n| n.accepted_at)
            .ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn matches_job(&self, r: &NativeJobDrain) -> Result<bool> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.intent.matches_job(r)
    }
}

#[cfg(test)]
impl Native {
    fn lab_evidence(&mut self) -> Result<serde_json::Value> {
        self.creator()?;
        let original = self
            .original
            .as_ref()
            .map(ReapWitness::original)
            .transpose()
            .map_err(raw)?;
        let status = self
            .original
            .as_ref()
            .map(ReapWitness::actual_status)
            .transpose()
            .map_err(raw)?
            .flatten();
        let state = self.intent.lease().native_job_mut().state.get();
        let mut registered_slots = self._gate_token.lab_live_slots()?;
        for token in self
            .stable_token
            .iter()
            .chain(self.child_tokens.iter())
            .chain(self.pid_token.iter())
        {
            registered_slots += token.lab_live_slots()?;
        }
        for token in self.received_tokens.iter().chain(&self.borrowed_tokens) {
            registered_slots += token.lab_live_slots()?;
        }
        if registered_slots < 3 {
            return Err(Error::DescriptorInventory);
        }
        let all_registered = self
            ._gate_token
            .contains(self.gate.descriptor().map_err(raw)?)
            && self.pending.descriptors()?.iter().all(|fd| {
                self.stable_token.as_ref().is_some_and(|t| t.contains(*fd))
                    || self.child_tokens.as_ref().is_some_and(|t| t.contains(*fd))
                    || self.pid_token.as_ref().is_some_and(|t| t.contains(*fd))
                    || self.received_tokens.iter().any(|t| t.contains(*fd))
                    || self.borrowed_tokens.iter().any(|t| t.contains(*fd))
            });
        Ok(
            serde_json::json!({"kind":self.request.kind(),"scope":self.request.scope(),"request":self.request.digest(),
            "requested_at":self.request.requested_at(),"deadline":self.request.deadline(),"birth":self.birth,
            "original_pid":original.map(|v|v.0),"original_start":original.and_then(|v|v.1),
            "actual_wait_status":status,"native_born":self.born,
            "native_job_state":match state { NativeJobState::Prepared=>"prepared",NativeJobState::Born=>"born",NativeJobState::NoBirth=>"no_birth",NativeJobState::Collected=>"collected",NativeJobState::TransferredResources=>"transferred_resources" },
            "full_descriptor_registration":all_registered,"registered_native_slots":registered_slots,"borrowed_registration_count":self.borrowed_tokens.len(),
            "accepted_at":self.accepted_at,"acknowledged":self.acknowledged,"result":self.result,
            "context_retained":true}),
        )
    }
}

#[cfg(test)]
impl Verified {
    pub(crate) fn lab_evidence(&mut self) -> Result<serde_json::Value> {
        self.verify_history()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .lab_evidence()
    }
}
