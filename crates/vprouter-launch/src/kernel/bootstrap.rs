//! Sole durable release gate for the three original Bootstrap scope operations.
use super::super::{
    attachment::operational::bootstrap::Request,
    inventory::Registration,
    owned::{
        Identity,
        preparation::{
            Server, ValidationBirth,
            bootstrap::{Gate, Intent, PublicResult, Receipt},
        },
    },
};
use super::*;
use std::{cell::RefCell, rc::Rc};
use vprouter_native_role::{ReapWitness, WireguardReleaseGate};
use vprouter_netfilter::{PendingBootstrap, VerifiedBootstrap};
fn map(_: vprouter_netfilter::Error) -> Error {
    Error::NetworkOperation
}
fn raw(_: vprouter_native_role::Error) -> Error {
    Error::DescriptorPolicy
}
pub(crate) enum Previous<'a> {
    Initial(&'a mut netfilter_role::Verified),
    Observed(&'a mut producer_binding::Verified),
}
struct Native {
    creator: u32,
    request: Rc<Request>,
    intent: Intent,
    gate: WireguardReleaseGate,
    gate_token: Registration,
    stable: Option<Registration>,
    endpoints: Option<Registration>,
    pid_token: Option<Registration>,
    borrowed: Vec<Rc<Registration>>,
    pending: PendingBootstrap,
    completed: Option<VerifiedBootstrap>,
    capacity: Option<ChildCapacity>,
    original: Option<ReapWitness>,
    birth: Option<ValidationBirth>,
    result: Option<PublicResult>,
    accepted_at: Option<f64>,
    acknowledged: bool,
    failure: Option<Error>,
    #[cfg(test)]
    released: bool,
}
pub(crate) struct Child {
    native: Option<Native>,
}
pub(crate) struct Verified {
    native: Option<Native>,
}
thread_local! {static RETAINED:RefCell<Vec<Native>>=const{RefCell::new(Vec::new())};}
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            Err(Error::OwnershipMismatch)
        } else {
            Ok(())
        }
    }
    fn original(&self) -> Result<&ReapWitness> {
        self.creator()?;
        self.original.as_ref().ok_or(Error::OwnershipMismatch)
    }
    fn fail(&mut self, e: Error) {
        if self.creator == std::process::id() {
            self.failure.get_or_insert(e);
            self.gate.cancel();
            self.pending.cancel(vprouter_netfilter::Error::Interrupted);
        }
    }
    fn collect(&mut self) {
        if self.creator == std::process::id() {
            self.pending.collect();
        }
    }
    fn reaped(&self) -> bool {
        self.original
            .as_ref()
            .is_none_or(|r| r.actual_status().is_ok_and(|s| s.is_some()))
    }
    fn inventory(&self) -> Result<()> {
        self.creator()?;
        self.gate_token.retained_slots()?;
        self.stable
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .retained_slots()?;
        if let Some(t) = &self.pid_token {
            t.retained_slots()?;
        }
        for t in &self.borrowed {
            t.retained_slots()?;
        }
        for fd in self.pending.descriptors().map_err(map)? {
            if !self.stable.as_ref().is_some_and(|t| t.contains(fd))
                && !self.pid_token.as_ref().is_some_and(|t| t.contains(fd))
                && !self.endpoints.as_ref().is_some_and(|t| t.contains(fd))
                && !self.borrowed.iter().any(|t| t.contains(fd))
            {
                return Err(Error::DescriptorInventory);
            }
        }
        Ok(())
    }
}
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
pub(crate) fn spawn(
    request: Rc<Request>,
    mut intent: Intent,
    previous: Previous<'_>,
) -> Result<Child> {
    secret::seal_parent()?;
    owner_admission_permitted()?;
    intent.prepare(&request)?;
    intent.verify_previous(&previous)?;
    let (gate, child_gate) =
        vprouter_native_role::prepare_wireguard_gate(request.digest(), request.deadline())
            .map_err(raw)?;
    let gate_token = Registration::owned(&[gate.descriptor().map_err(raw)?])?;
    let (pending, borrowed) = match previous {
        Previous::Initial(v) => v.prepare_bootstrap(&request, child_gate)?,
        Previous::Observed(v) => v.prepare_bootstrap(&request, child_gate)?,
    };
    // Store every prior owner, gate and successful registration before fallible
    // preparation, including before any new socket timer is attached.
    let mut value = Child {
        native: Some(Native {
            creator: std::process::id(),
            request,
            intent,
            gate,
            gate_token,
            stable: None,
            endpoints: None,
            pid_token: None,
            borrowed,
            pending,
            completed: None,
            capacity: None,
            original: None,
            birth: None,
            result: None,
            accepted_at: None,
            acknowledged: false,
            failure: None,
            #[cfg(test)]
            released: false,
        }),
    };
    let n = value.native.as_mut().ok_or(Error::Interrupted)?;
    let outcome = (|| {
        let endpoints = n.pending.child_endpoints_before_birth().map_err(map)?;
        let numbers = [endpoints[0].as_raw_fd(), endpoints[1].as_raw_fd()];
        n.endpoints = Some(Registration::owned(&endpoints)?);
        #[cfg(test)]
        lab_fault(&n.request, 3)?;
        let stable: Vec<_> = n
            .pending
            .descriptors()
            .map_err(map)?
            .into_iter()
            .filter(|fd| {
                !numbers.contains(&fd.as_raw_fd()) && !n.borrowed.iter().any(|t| t.contains(*fd))
            })
            .collect();
        n.stable = Some(Registration::owned(&stable)?);
        n.inventory()?;
        super::super::inventory::verify()?;
        n.pending.validate_prepared().map_err(map)?;
        n.request.verify()?;
        owner_admission_permitted()?;
        require_child_capacity()?;
        let original = n.pending.birth().map_err(map)?;
        n.capacity = Some(ChildCapacity::created());
        n.intent
            .lease()
            .native_job_mut()
            .born_netfilter(original.clone());
        n.original = Some(original);
        n.endpoints.take();
        #[cfg(test)]
        lab_fault(&n.request, 1)?;
        n.pid_token = Some(Registration::owned(&[n.pending.pidfd().map_err(map)?])?);
        let b = n.pending.identify().map_err(map)?;
        n.birth = Some(ValidationBirth {
            pid: b.pid,
            start: b.start,
            born_at: b.born_at,
            deadline: b.deadline,
        });
        n.request.check()
    })();
    if let Err(e) = outcome {
        n.fail(e);
        return Err(e);
    }
    Ok(value)
}
impl Child {
    pub(crate) fn request(&self) -> &Rc<Request> {
        &self
            .native
            .as_ref()
            .expect("original producer binding")
            .request
    }
    pub(crate) fn request_digest(&self) -> Result<[u8; 32]> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(n.request.digest())
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
    pub(crate) fn verify_gate(&self, g: &Gate) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.request.verify()?;
        g.verify(&n.intent, &self.birth()?)
    }
    pub(crate) fn release(&mut self, g: Gate) -> Result<()> {
        self.verify_gate(&g)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let result = (|| {
            n.inventory()?;
            n.request.verify()?;
            if n.failure.is_some() {
                return Err(Error::Interrupted);
            }
            let r = n.original()?.clone();
            if !n.gate.matches(&r).map_err(raw)? {
                return Err(Error::OwnershipMismatch);
            }
            n.gate.release(&r).map_err(raw)?;
            #[cfg(test)]
            {
                n.released = true;
            }
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
            n.inventory()?;
            let Some(v) = n.pending.poll().map_err(map)? else {
                return Ok(false);
            };
            n.completed = Some(v);
            let v = n.completed.as_ref().ok_or(Error::Interrupted)?;
            let actual = v.original_child().map_err(map)?;
            if !actual.same_constructor(n.original()?).map_err(raw)?
                || actual.actual_status().map_err(raw)? != Some(0)
                || v.identities().map_err(map)?
                    != std::array::from_fn(|i| {
                        let p = n.request.identities()[i];
                        (p.0, p.1)
                    })
            {
                return Err(Error::OwnershipMismatch);
            }
            let (dev, ino) = v.namespace_identity().map_err(map)?;
            let r = PublicResult {
                namespace: Identity { dev, ino },
                group: n.request.group(),
                policy: v.policy_digest().map_err(map)?,
                pins: n.request.identities(),
                observed_at: v.observed_at().map_err(map)?,
            };
            if r.namespace != n.request.namespace() || r.policy != n.request.policy_digest() {
                return Err(Error::OwnershipMismatch);
            }
            n.result = Some(r);
            n.accepted_at = Some(v.accepted_at().map_err(map)?);
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
    /// Retire only the completed original child charges. All group, table,
    /// socket and canonical owners remain in this same retained receipt.
    pub(crate) fn resource_transfer(&self) -> Result<ResourceTransfer> {
        self.require_acknowledged_history()?;
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.endpoints.is_some() {
            return Err(Error::DescriptorInventory);
        }
        ResourceTransfer::lower(
            n.intent.transfer_ticket()?,
            NativeJobKind::FixedNetfilter,
            n.original()?,
            n.capacity.as_ref().ok_or(Error::OwnershipMismatch)?,
        )
    }

    /// Original accepted history plus current custody of the same retained
    /// descriptors. It grants neither current group/table truth nor a new end.
    pub(crate) fn require_acknowledged_history(&self) -> Result<()> {
        self.verify_retained()?;
        if !self.native.as_ref().ok_or(Error::Interrupted)?.acknowledged {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn historical_result(&self) -> Result<&PublicResult> {
        self.verify_retained()?;
        self.native
            .as_ref()
            .and_then(|n| n.result.as_ref())
            .ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn historical_accepted_at(&self) -> Result<f64> {
        self.verify_retained()?;
        self.native
            .as_ref()
            .and_then(|n| n.accepted_at)
            .ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn verify_retained(&self) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.request.verify_retained()?;
        n.gate_token.retained_slots()?;
        n.stable
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .retained_slots()?;
        n.pid_token
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .retained_slots()?;
        for t in &n.borrowed {
            t.retained_slots()?;
        }
        if n.failure.is_some()
            || n.completed.is_none()
            || n.original()?.actual_status().map_err(raw)? != Some(0)
            || n.result.is_none()
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
    pub(crate) fn verify(&self) -> Result<()> {
        self.verify_retained()?;
        self.request().verify()
    }
    pub(crate) fn accept(&mut self, r: Receipt) -> Result<()> {
        self.verify()?;
        r.verify(self)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.acknowledged {
            return Err(Error::OwnershipMismatch);
        }
        n.acknowledged = true;
        Ok(())
    }
    pub(crate) fn request(&self) -> &Rc<Request> {
        &self
            .native
            .as_ref()
            .expect("original producer binding result")
            .request
    }
    pub(crate) fn intent(&self) -> Result<&Intent> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(&n.intent)
    }
    pub(crate) fn bind_service(&self, s: &Server) -> Result<()> {
        self.intent()?.same_service(s)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.birth.clone().ok_or(Error::OwnershipMismatch)
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
thread_local! {static FAULT:std::cell::Cell<Option<(u32,[u8;32],u8)>>=const{std::cell::Cell::new(None)};}
#[cfg(test)]
pub(crate) fn lab_arm(r: &Request, stage: u8) {
    FAULT.with(|f| f.set(Some((std::process::id(), r.digest(), stage))));
}
#[cfg(test)]
fn lab_fault(r: &Request, stage: u8) -> Result<()> {
    if FAULT.with(|f| {
        if f.get() == Some((std::process::id(), r.digest(), stage)) {
            f.set(None);
            true
        } else {
            false
        }
    }) {
        Err(Error::DescriptorInventory)
    } else {
        Ok(())
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
        let mut slots = self.request.lab_registered_slots()? + self.gate_token.lab_live_slots()?;
        for token in self
            .stable
            .iter()
            .chain(self.endpoints.iter())
            .chain(self.pid_token.iter())
        {
            slots += token.lab_live_slots()?;
        }
        for token in &self.borrowed {
            slots += token.lab_live_slots()?;
        }
        let state = self.intent.lease().native_job_mut().state.get();
        Ok(
            serde_json::json!({"request":self.request.digest(),"query":self.request.query_digest(),"requested_at":self.request.requested_at(),"deadline":self.request.deadline(),
            "parent":self.request.source().request().parent_identity(),"group":self.request.group(),"name":self.request.source().request().name(),"scope":self.request.scope(),"namespace":self.request.namespace(),"policy":self.request.policy_digest(),"pins":self.request.identities(),
            "original_pid":original.map(|v|v.0),"original_start":original.and_then(|v|v.1),"actual_wait_status":status,"birth":self.birth,"native_born":original.is_some(),
            "native_job_state":match state{NativeJobState::Prepared=>"prepared",NativeJobState::Born=>"born",NativeJobState::NoBirth=>"no_birth",NativeJobState::Collected=>"collected",NativeJobState::TransferredResources=>"transferred_resources"},
            "registered_native_slots":slots,"original_registration_slots_verified":slots>=9,"borrowed_registration_count":self.borrowed.len(),"complete_native_registration":self.stable.is_some()&&self.pid_token.is_some(),
            "durable_birth_released":self.released,"result":self.result,"accepted_at":self.accepted_at,"acknowledged":self.acknowledged,
            "eof":self.completed.is_some(),"context_retained":true,"bootstrap_installation_observed":self.result.is_some(),"placement_authorized":false,"up_authorized":false}),
        )
    }
}
#[cfg(test)]
impl Verified {
    pub(crate) fn lab_evidence(&mut self) -> Result<serde_json::Value> {
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .lab_evidence()
    }
}
#[cfg(test)]
pub(crate) fn lab_failed_context(r: &Rc<Request>) -> Result<Option<serde_json::Value>> {
    RETAINED.with(|list| {
        let mut list = list.borrow_mut();
        let Some(n) = list
            .iter_mut()
            .find(|n| n.creator == std::process::id() && Rc::ptr_eq(&n.request, r))
        else {
            return Ok(None);
        };
        n.collect();
        if !n.reaped() {
            return Ok(None);
        }
        n.lab_evidence().map(Some)
    })
}
