//! Sole canonical release gate for the closed original HOST link sequence.
use super::super::{
    attachment::host_addition::{Kind, Request},
    inventory::Registration,
    owned::{
        Identity,
        preparation::{
            Server, ValidationBirth,
            host_link::{Gate, Intent, Receipt},
        },
    },
};
use super::*;
use std::{cell::RefCell, rc::Rc};
use vprouter_native_role::{ReapWitness, WireguardReleaseGate};
use vprouter_network::{
    HostAdditionPlan, PendingSocketPreparation, PendingVethCreation, PendingVethHostMove,
    VerifiedSocketPreparation, VerifiedVethCreation, VerifiedVethHostMove,
};
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicResult {
    pub(crate) namespace: Identity,
    pub(crate) host: Option<vprouter_network::Link>,
    pub(crate) peer: Option<vprouter_network::Link>,
}
impl PublicResult {
    pub(crate) fn pair(&self) -> Result<(&vprouter_network::Link, &vprouter_network::Link)> {
        Ok((
            self.host.as_ref().ok_or(Error::OwnershipMismatch)?,
            self.peer.as_ref().ok_or(Error::OwnershipMismatch)?,
        ))
    }
}
#[allow(clippy::large_enum_variant)]
enum Pending {
    Sockets(PendingSocketPreparation),
    Pair(PendingVethCreation),
    Move(PendingVethHostMove),
    Empty,
}
#[allow(clippy::large_enum_variant)]
enum Complete {
    Sockets(Option<VerifiedSocketPreparation>),
    Pair(Option<VerifiedVethCreation>),
    Move(VerifiedVethHostMove),
}
fn map(_: vprouter_network::Error) -> Error {
    Error::NetworkOperation
}
fn raw(_: vprouter_native_role::Error) -> Error {
    Error::DescriptorPolicy
}
impl Pending {
    fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        match self {
            Self::Sockets(p) => p.descriptors().map_err(map),
            Self::Pair(p) => p.descriptors().map_err(map),
            Self::Move(p) => p.descriptors().map_err(map),
            Self::Empty => Ok(vec![]),
        }
    }
    fn endpoints(&self) -> Result<[BorrowedFd<'_>; 2]> {
        match self {
            Self::Sockets(p) => p.child_endpoints_before_birth().map_err(map),
            Self::Pair(p) => p.child_endpoints_before_birth().map_err(map),
            Self::Move(p) => p.child_endpoints_before_birth().map_err(map),
            Self::Empty => Err(Error::OwnershipMismatch),
        }
    }
    fn validate(&mut self) -> Result<bool> {
        match self {
            Self::Sockets(_) => Ok(true),
            Self::Pair(p) => p.validate_prepared().map_err(map),
            Self::Move(p) => p.validate_prepared().map_err(map),
            Self::Empty => Err(Error::OwnershipMismatch),
        }
    }
    fn birth(&mut self) -> Result<ReapWitness> {
        match self {
            Self::Sockets(p) => p.birth().map_err(map),
            Self::Pair(p) => p.birth().map_err(map),
            Self::Move(p) => p.birth().map_err(map),
            Self::Empty => Err(Error::OwnershipMismatch),
        }
    }
    fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        match self {
            Self::Sockets(p) => p.pidfd().map_err(map),
            Self::Pair(p) => p.pidfd().map_err(map),
            Self::Move(p) => p.pidfd().map_err(map),
            Self::Empty => Err(Error::OwnershipMismatch),
        }
    }
    fn identify(&mut self) -> Result<ValidationBirth> {
        let b = match self {
            Self::Sockets(p) => p.identify().map_err(map)?,
            Self::Pair(p) => p.identify().map_err(map)?,
            Self::Move(p) => p.identify().map_err(map)?,
            Self::Empty => return Err(Error::OwnershipMismatch),
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
            Self::Pair(p) => p.cancel(vprouter_network::Error::Interrupted),
            Self::Move(p) => p.cancel(vprouter_network::Error::Interrupted),
            Self::Empty => (),
        }
    }
    fn collect(&mut self) {
        match self {
            Self::Sockets(p) => p.collect(),
            Self::Pair(p) => p.collect(),
            Self::Move(p) => p.collect(),
            Self::Empty => (),
        }
    }
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
    received: Vec<Rc<Registration>>,
    borrowed: Vec<Rc<Registration>>,
    pending: Pending,
    complete: Option<Complete>,
    capacity: Option<ChildCapacity>,
    original: Option<ReapWitness>,
    birth: Option<ValidationBirth>,
    result: Option<PublicResult>,
    accepted_at: Option<f64>,
    acknowledged: bool,
    failure: Option<Error>,
    #[cfg(test)]
    released: bool,
    #[cfg(test)]
    lab_running_inventory: Option<Vec<i32>>,
    #[cfg(test)]
    lab_postcompletion_inventory_polls: u32,
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
    fn fail(&mut self, e: Error) {
        if self.creator == std::process::id() {
            self.failure.get_or_insert(e);
            self.gate.cancel();
            self.pending.cancel();
        }
    }
    fn inventory(&mut self) -> Result<()> {
        self.creator()?;
        self.gate_token.retained_slots()?;
        if let Some(t) = &self.stable {
            t.retained_slots()?;
        }
        if let Some(t) = &self.pid_token {
            t.retained_slots()?;
        }
        for t in self.received.iter().chain(&self.borrowed) {
            t.retained_slots()?;
        }
        let descriptors = self.pending.descriptors()?;
        #[cfg(test)]
        if self.original.is_some() && matches!(self.pending, Pending::Pair(_) | Pending::Move(_)) {
            let mut numbers: Vec<_> = descriptors.iter().map(AsRawFd::as_raw_fd).collect();
            numbers.sort_unstable();
            numbers.dedup();
            let completed = match &self.pending {
                Pending::Pair(p) => p.lab_parent_readback_pending().map_err(map)?,
                Pending::Move(p) => p.lab_parent_readback_pending().map_err(map)?,
                _ => false,
            };
            if completed {
                if self.lab_running_inventory.as_ref() != Some(&numbers)
                    || self
                        .original
                        .as_ref()
                        .ok_or(Error::Interrupted)?
                        .actual_status()
                        .map_err(raw)?
                        != Some(0)
                    || !descriptors.iter().all(|fd| {
                        self.stable.as_ref().is_some_and(|t| t.contains(*fd))
                            || self.pid_token.as_ref().is_some_and(|t| t.contains(*fd))
                            || self
                                .received
                                .iter()
                                .chain(&self.borrowed)
                                .any(|t| t.contains(*fd))
                    })
                {
                    return Err(Error::DescriptorInventory);
                }
                self.lab_postcompletion_inventory_polls = self
                    .lab_postcompletion_inventory_polls
                    .checked_add(1)
                    .ok_or(Error::TooLarge)?;
            } else if let Some(old) = &self.lab_running_inventory {
                if old != &numbers {
                    return Err(Error::DescriptorInventory);
                }
            } else {
                self.lab_running_inventory = Some(numbers);
            }
        }
        for fd in descriptors {
            if self.stable.as_ref().is_some_and(|t| t.contains(fd))
                || self.pid_token.as_ref().is_some_and(|t| t.contains(fd))
                || self.endpoints.as_ref().is_some_and(|t| t.contains(fd))
                || self
                    .received
                    .iter()
                    .chain(&self.borrowed)
                    .any(|t| t.contains(fd))
            {
                continue;
            }
            if !matches!(self.pending, Pending::Sockets(_)) {
                return Err(Error::DescriptorInventory);
            }
            self.received.push(Rc::new(Registration::owned(&[fd])?));
        }
        Ok(())
    }
    fn collect(&mut self) {
        if self.creator == std::process::id() {
            let _ = self.inventory();
            self.pending.collect();
        }
    }
    fn reaped(&self) -> bool {
        self.original
            .as_ref()
            .is_none_or(|r| r.actual_status().is_ok_and(|s| s.is_some()))
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
impl Child {
    pub(crate) fn spawn(
        request: Rc<Request>,
        mut intent: Intent,
        previous: &mut [Verified],
        addition: &mut Option<HostAdditionPlan>,
    ) -> Result<Self> {
        secret::seal_parent()?;
        owner_admission_permitted()?;
        intent.prepare(&request)?;
        let (gate, child_gate) =
            vprouter_native_role::prepare_wireguard_gate(request.digest(), request.deadline())
                .map_err(raw)?;
        let gate_token = Registration::owned(&[gate.descriptor().map_err(raw)?])?;
        if previous.len() != request.index() {
            return Err(Error::OwnershipMismatch);
        }
        let mut borrowed = Vec::new();
        let pending = match request.kind() {
            Kind::TransportSockets | Kind::HostSockets => Pending::Sockets(
                PendingSocketPreparation::prepare(
                    request.plan().clone(),
                    request.source(),
                    request.digest(),
                    request.deadline(),
                    child_gate,
                )
                .map_err(map)?,
            ),
            Kind::Pair => {
                let p = &mut previous[0];
                p.require_acknowledged()?;
                let n = p.native.as_mut().ok_or(Error::Interrupted)?;
                intent.verify_previous(&n.intent, 0)?;
                borrowed.extend(n.received.iter().chain(&n.borrowed).cloned());
                let Some(Complete::Sockets(sockets)) = &mut n.complete else {
                    return Err(Error::OwnershipMismatch);
                };
                Pending::Pair(
                    PendingVethCreation::prepare(
                        sockets,
                        request.source(),
                        request.digest(),
                        request.deadline(),
                        child_gate,
                    )
                    .map_err(map)?,
                )
            }
            Kind::Move => {
                let (source, target) = previous.split_at_mut(2);
                source[1].require_acknowledged()?;
                target[0].require_acknowledged()?;
                let s = source[1].native.as_mut().ok_or(Error::Interrupted)?;
                let t = target[0].native.as_mut().ok_or(Error::Interrupted)?;
                intent.verify_previous(&s.intent, 1)?;
                intent.verify_previous(&t.intent, 2)?;
                borrowed.extend(
                    s.received
                        .iter()
                        .chain(&s.borrowed)
                        .chain(t.received.iter())
                        .chain(&t.borrowed)
                        .cloned(),
                );
                let Some(Complete::Pair(pair)) = &mut s.complete else {
                    return Err(Error::OwnershipMismatch);
                };
                let Some(Complete::Sockets(sockets)) = &mut t.complete else {
                    return Err(Error::OwnershipMismatch);
                };
                let plan = addition.as_ref().ok_or(Error::OwnershipMismatch)?;
                let spec = request.binding().data().request().spec();
                plan.bind(
                    &spec.allocation,
                    &spec.exit.exit_id,
                    (request.binding().host().dev, request.binding().host().ino),
                    pair.as_ref().ok_or(Error::OwnershipMismatch)?,
                )
                .map_err(map)?;
                use sha2::Digest;
                let hash: [u8; 32] = sha2::Sha256::digest(plan.intent_bytes().map_err(map)?).into();
                if request.addition() != Some((hash, plan.planned_index().map_err(map)?)) {
                    return Err(Error::OwnershipMismatch);
                }
                Pending::Move(
                    PendingVethHostMove::prepare(
                        pair,
                        sockets,
                        addition,
                        request.source(),
                        request.target(),
                        request.digest(),
                        request.deadline(),
                        child_gate,
                    )
                    .map_err(map)?,
                )
            }
        };
        let mut value = Self {
            native: Some(Native {
                creator: std::process::id(),
                request,
                intent,
                gate,
                gate_token,
                stable: None,
                endpoints: None,
                pid_token: None,
                received: Vec::new(),
                borrowed,
                pending,
                complete: None,
                capacity: None,
                original: None,
                birth: None,
                result: None,
                accepted_at: None,
                acknowledged: false,
                failure: None,
                #[cfg(test)]
                released: false,
                #[cfg(test)]
                lab_running_inventory: None,
                #[cfg(test)]
                lab_postcompletion_inventory_polls: 0,
            }),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        let result = (|| {
            let endpoints = n.pending.endpoints()?;
            let numbers = [endpoints[0].as_raw_fd(), endpoints[1].as_raw_fd()];
            n.endpoints = Some(Registration::owned(&endpoints)?);
            #[cfg(test)]
            lab_fault(&n.request, 3)?;
            let stable: Vec<_> = n
                .pending
                .descriptors()?
                .into_iter()
                .filter(|fd| {
                    !numbers.contains(&fd.as_raw_fd())
                        && !n.borrowed.iter().any(|t| t.contains(*fd))
                })
                .collect();
            n.stable = Some(Registration::owned(&stable)?);
            n.inventory()?;
            super::super::inventory::verify()?;
            n.request.verify()
        })();
        if let Err(e) = result {
            n.fail(e);
            return Err(e);
        }
        Ok(value)
    }
    pub(crate) fn poll_prepared(&mut self) -> Result<bool> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = (|| {
            if n.original.is_some() || n.failure.is_some() {
                return Err(Error::Interrupted);
            }
            n.request.verify()?;
            n.inventory()?;
            if !n.pending.validate()? {
                return Ok(false);
            }
            n.request.verify()?;
            owner_admission_permitted()?;
            require_child_capacity()?;
            let original = n.pending.birth()?;
            n.capacity = Some(ChildCapacity::created());
            n.intent
                .lease()
                .native_job_mut()
                .born_veth(original.clone());
            n.original = Some(original);
            n.endpoints.take();
            #[cfg(test)]
            lab_fault(&n.request, 1)?;
            n.pid_token = Some(Registration::owned(&[n.pending.pidfd()?])?);
            n.birth = Some(n.pending.identify()?);
            n.request.check()?;
            Ok(true)
        })();
        if let Err(e) = result {
            n.fail(e);
        }
        result
    }
    pub(crate) fn request(&self) -> &Rc<Request> {
        &self.native.as_ref().expect("original host child").request
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
        g.verify(&n.intent, &self.birth()?)
    }
    pub(crate) fn release(&mut self, g: Gate) -> Result<()> {
        self.verify_gate(&g)?;
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        let result = (|| {
            n.request.verify()?;
            n.inventory()?;
            if n.failure.is_some() {
                return Err(Error::Interrupted);
            }
            let original = n.original.as_ref().ok_or(Error::OwnershipMismatch)?;
            if !n.gate.matches(original).map_err(raw)? {
                return Err(Error::OwnershipMismatch);
            }
            n.gate.release(original).map_err(raw)?;
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
            if let Some(e) = n.failure {
                return Err(e);
            }
            n.request.verify()?;
            if let Pending::Sockets(p) = &mut n.pending {
                p.receive_native().map_err(map)?;
            }
            n.inventory()?;
            n.complete = Some(match &mut n.pending {
                Pending::Sockets(p) => {
                    let Some(v) = p.poll().map_err(map)? else {
                        return Ok(false);
                    };
                    Complete::Sockets(Some(v))
                }
                Pending::Pair(p) => {
                    let Some(v) = p.poll().map_err(map)? else {
                        return Ok(false);
                    };
                    Complete::Pair(Some(v))
                }
                Pending::Move(p) => {
                    let Some(v) = p.poll().map_err(map)? else {
                        return Ok(false);
                    };
                    Complete::Move(v)
                }
                Pending::Empty => return Err(Error::Interrupted),
            });
            // Preserve the entire completed context before any fallible result
            // extraction or final acceptance check.
            match n.complete.as_ref().ok_or(Error::Interrupted)? {
                Complete::Sockets(Some(v)) => {
                    let (dev, ino) = v.namespace_identity().map_err(map)?;
                    n.result = Some(PublicResult {
                        namespace: Identity { dev, ino },
                        host: None,
                        peer: None,
                    });
                    n.accepted_at = Some(v.accepted_at().map_err(map)?);
                }
                Complete::Pair(Some(v)) => {
                    let (h, t) = v.observation().map_err(map)?;
                    n.result = Some(PublicResult {
                        namespace: n.request.namespace(),
                        host: Some(h.clone()),
                        peer: Some(t.clone()),
                    });
                    n.accepted_at = Some(v.accepted_at().map_err(map)?);
                }
                Complete::Move(v) => {
                    let (h, t) = v.observation().map_err(map)?;
                    n.result = Some(PublicResult {
                        namespace: n.request.binding().host(),
                        host: Some(h.clone()),
                        peer: Some(t.clone()),
                    });
                    n.accepted_at = Some(v.accepted_at().map_err(map)?);
                }
                _ => return Err(Error::OwnershipMismatch),
            }
            #[cfg(test)]
            if matches!(n.request.kind(), Kind::Pair | Kind::Move)
                && n.lab_postcompletion_inventory_polls < 2
            {
                return Err(Error::DescriptorInventory);
            }
            n.pending = Pending::Empty;
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
        self.native.as_ref().is_none_or(Native::reaped)
    }
}
impl Verified {
    /// Historical child completion and current custody of its original slots;
    /// no socket/resource collection or renewed network observation.
    pub(crate) fn resource_transfer(&self) -> Result<ResourceTransfer> {
        self.require_acknowledged()?;
        let n = self.history()?;
        if n.endpoints.is_some() {
            return Err(Error::DescriptorInventory);
        }
        ResourceTransfer::lower(
            n.intent.transfer_ticket()?,
            NativeJobKind::FixedVeth,
            n.original.as_ref().ok_or(Error::OwnershipMismatch)?,
            n.capacity.as_ref().ok_or(Error::OwnershipMismatch)?,
        )
    }

    fn history(&self) -> Result<&Native> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        n.request.verify_retained()?;
        if n.failure.is_some()
            || n.original
                .as_ref()
                .is_none_or(|r| r.actual_status() != Ok(Some(0)))
            || n.complete.is_none()
            || n.result.is_none()
            || n.accepted_at.is_none_or(|at| {
                !at.is_finite()
                    || at >= n.request.deadline()
                    || n.birth.as_ref().is_none_or(|b| at < b.born_at)
            })
        {
            return Err(Error::OwnershipMismatch);
        }
        n.gate_token.retained_slots()?;
        n.stable
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .retained_slots()?;
        n.pid_token
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .retained_slots()?;
        for t in n.received.iter().chain(&n.borrowed) {
            t.retained_slots()?;
        }
        Ok(n)
    }
    pub(crate) fn verify(&self) -> Result<()> {
        self.history()?.request.verify()
    }
    pub(crate) fn require_acknowledged(&self) -> Result<()> {
        if !self.history()?.acknowledged {
            Err(Error::OwnershipMismatch)
        } else {
            Ok(())
        }
    }
    pub(crate) fn accept(&mut self, r: Receipt) -> Result<()> {
        r.verify(self)?;
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
        Ok(&self.history()?.intent)
    }
    pub(crate) fn request(&self) -> &Rc<Request> {
        &self.native.as_ref().expect("original host receipt").request
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        self.history()?
            .birth
            .clone()
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
        self.history()?.accepted_at.ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn historical_result(&self) -> Result<&PublicResult> {
        self.require_acknowledged()?;
        self.history()?
            .result
            .as_ref()
            .ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn historical_accepted_at(&self) -> Result<f64> {
        self.require_acknowledged()?;
        self.history()?.accepted_at.ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn prepare_addition(
        &self,
        authority: &vprouter_network::HostAuthority,
    ) -> Result<HostAdditionPlan> {
        self.require_acknowledged()?;
        let n = self.history()?;
        let Some(Complete::Pair(Some(pair))) = &n.complete else {
            return Err(Error::OwnershipMismatch);
        };
        let spec = n.request.binding().data().request().spec();
        authority
            .prepare_addition(&spec.allocation, &spec.exit.exit_id, pair)
            .map_err(map)
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
pub(crate) fn lab_arm(r: &Request, stage: u8) -> Result<()> {
    r.verify()?;
    if r.kind() != Kind::Move || ![1, 3].contains(&stage) || FAULT.with(|f| f.get().is_some()) {
        return Err(Error::OwnershipMismatch);
    }
    FAULT.with(|f| f.set(Some((std::process::id(), r.digest(), stage))));
    Ok(())
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
        let mut slots = self.gate_token.lab_live_slots()?;
        for t in self
            .stable
            .iter()
            .chain(&self.endpoints)
            .chain(&self.pid_token)
        {
            slots += t.lab_live_slots()?;
        }
        for t in self.received.iter().chain(&self.borrowed) {
            slots += t.lab_live_slots()?;
        }
        let host_observation = match self.complete.as_ref() {
            Some(Complete::Move(v)) => Some(v.host_observation().map_err(map)?),
            _ => None,
        };
        let state = self.intent.lease().native_job_mut().state.get();
        Ok(
            serde_json::json!({"kind":self.request.kind(),"request":self.request.digest(),"namespace":self.request.namespace(),"host":self.request.binding().host(),
            "declaration":self.request.declaration_digest(),"admission":self.request.admission_window(),"addition":self.request.addition(),
            "requested_at":self.request.requested_at(),"deadline":self.request.deadline(),"original_pid":original.map(|v|v.0),"original_start":original.and_then(|v|v.1),
            "actual_wait_status":status,"birth":self.birth,"native_born":original.is_some(),"native_job_state":match state {NativeJobState::Prepared=>"prepared",NativeJobState::Born=>"born",NativeJobState::NoBirth=>"no_birth",NativeJobState::Collected=>"collected",NativeJobState::TransferredResources=>"transferred_resources"},
            "registered_native_slots":slots,"original_registration_slots_verified":slots>=3,"borrowed_registration_count":self.borrowed.len(),
            "complete_native_registration":self.stable.is_some()&&self.pid_token.is_some(),"durable_birth_released":self.released,
            "result":self.result,"accepted_at":self.accepted_at,"acknowledged":self.acknowledged,"eof":self.complete.is_some(),"context_retained":true,
            "postcompletion_inventory_polls":self.lab_postcompletion_inventory_polls,
            "postcompletion_inventory_preserved":if matches!(self.request.kind(),Kind::Pair|Kind::Move){Some(self.lab_postcompletion_inventory_polls>=2)}else{None},
            "host_observation":host_observation,"up_authorized":false,"placement_authorized":false}),
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
impl Child {
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
