//! Sole launch-owned parent release gate for fixed socket/provision/query jobs.
//! Network owns fixed execution/results; only canonical durable Birth releases.
use super::super::{
    attachment::provision::{Kind, Request},
    owned::{
        Identity,
        preparation::{
            Server, ValidationBirth,
            wireguard::{Gate, Intent, Receipt},
        },
    },
};
use super::*;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, rc::Rc};
use vprouter_native_role::{ReapWitness, WireguardReleaseGate};
use vprouter_network::{
    PendingSocketPreparation, PendingWireguardMove, PendingWireguardProvision,
    PendingWireguardQuery, VerifiedSocketPreparation, VerifiedWireguardMove,
    VerifiedWireguardProvision, VerifiedWireguardQuery,
};
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicResult {
    pub(crate) namespace: Identity,
    pub(crate) link: Option<vprouter_network::Link>,
    pub(crate) wireguard: Option<vprouter_network::Wireguard>,
}
// Bounded three-operation custody stays inline: no allocation during transfer.
#[allow(clippy::large_enum_variant)]
enum Pending {
    Sockets(PendingSocketPreparation),
    Provision(PendingWireguardProvision),
    Query(PendingWireguardQuery),
    Move(PendingWireguardMove),
    Empty,
}
#[allow(clippy::large_enum_variant)]
enum Complete {
    Sockets(Option<VerifiedSocketPreparation>),
    Provision(Option<VerifiedWireguardProvision>),
    Query(Option<VerifiedWireguardQuery>),
    Move(VerifiedWireguardMove),
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
    #[cfg(test)]
    lab_query_sequences: Option<[[u32; 2]; 2]>,
    #[cfg(test)]
    lab_running_inventory: Option<Vec<i32>>,
    #[cfg(test)]
    lab_postcompletion_inventory_polls: u32,
    failure: Option<Error>,
}
pub(crate) struct Child {
    native: Option<Native>,
}
pub(crate) struct Verified {
    native: Option<Native>,
}
fn map(_: vprouter_network::Error) -> Error {
    Error::NetworkOperation
}
fn raw(_: vprouter_native_role::Error) -> Error {
    Error::DescriptorPolicy
}
impl Pending {
    #[cfg(test)]
    fn lab_parent_readback_pending(&self) -> Result<bool> {
        match self {
            Self::Provision(p) => p.lab_parent_readback_pending().map_err(map),
            Self::Query(p) => p.lab_parent_readback_pending().map_err(map),
            Self::Move(p) => p.lab_parent_readback_pending().map_err(map),
            _ => Ok(false),
        }
    }
    fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        match self {
            Self::Sockets(p) => p.descriptors().map_err(map),
            Self::Provision(p) => p.descriptors().map_err(map),
            Self::Query(p) => p.descriptors().map_err(map),
            Self::Move(p) => p.descriptors().map_err(map),
            Self::Empty => Ok(vec![]),
        }
    }
    fn endpoints(&self) -> Result<[BorrowedFd<'_>; 2]> {
        match self {
            Self::Sockets(p) => p.child_endpoints_before_birth().map_err(map),
            Self::Provision(p) => p.child_endpoints_before_birth().map_err(map),
            Self::Query(p) => p.child_endpoints_before_birth().map_err(map),
            Self::Move(p) => Ok([
                p.child_channel_before_birth().map_err(map)?,
                p.child_gate_before_birth().map_err(map)?,
            ]),
            Self::Empty => Err(Error::OwnershipMismatch),
        }
    }
    fn validate_prepared(&mut self) -> Result<bool> {
        match self {
            Self::Sockets(_) => Ok(true),
            Self::Provision(p) => p.validate_prepared().map_err(map),
            Self::Query(p) => p.validate_prepared().map_err(map),
            Self::Move(p) => p.validate_prepared().map_err(map),
            Self::Empty => Err(Error::OwnershipMismatch),
        }
    }
    fn birth(&mut self) -> Result<ReapWitness> {
        match self {
            Self::Sockets(p) => p.birth().map_err(map),
            Self::Provision(p) => p.birth().map_err(map),
            Self::Query(p) => p.birth().map_err(map),
            Self::Move(p) => p.birth().map_err(map),
            Self::Empty => Err(Error::OwnershipMismatch),
        }
    }
    fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        match self {
            Self::Sockets(p) => p.pidfd().map_err(map),
            Self::Provision(p) => p.pidfd().map_err(map),
            Self::Query(p) => p.pidfd().map_err(map),
            Self::Move(p) => p.pidfd().map_err(map),
            Self::Empty => Err(Error::OwnershipMismatch),
        }
    }
    fn identify(&mut self) -> Result<ValidationBirth> {
        let b = match self {
            Self::Sockets(p) => p.identify().map_err(map)?,
            Self::Provision(p) => p.identify().map_err(map)?,
            Self::Query(p) => p.identify().map_err(map)?,
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
            Self::Provision(p) => p.cancel(vprouter_network::Error::Interrupted),
            Self::Query(p) => p.cancel(vprouter_network::Error::Interrupted),
            Self::Move(p) => p.cancel(vprouter_network::Error::Interrupted),
            Self::Empty => (),
        }
    }
    fn collect(&mut self) {
        match self {
            Self::Sockets(p) => p.collect(),
            Self::Provision(p) => p.collect(),
            Self::Query(p) => p.collect(),
            Self::Move(p) => p.collect(),
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
        let descriptors = self.pending.descriptors()?;
        #[cfg(test)]
        if self.born && !matches!(self.pending, Pending::Sockets(_) | Pending::Empty) {
            let mut numbers: Vec<_> = descriptors.iter().map(AsRawFd::as_raw_fd).collect();
            numbers.sort_unstable();
            numbers.dedup();
            if self.pending.lab_parent_readback_pending()? {
                if self.lab_running_inventory.as_ref() != Some(&numbers)
                    || self.original()?.actual_status().map_err(raw)? != Some(0)
                    || !descriptors.iter().all(|fd| {
                        self.stable_token.as_ref().is_some_and(|t| t.contains(*fd))
                            || self.pid_token.as_ref().is_some_and(|t| t.contains(*fd))
                            || self.received_tokens.iter().any(|t| t.contains(*fd))
                            || self.borrowed_tokens.iter().any(|t| t.contains(*fd))
                    })
                {
                    return Err(Error::DescriptorInventory);
                }
                self.lab_postcompletion_inventory_polls = self
                    .lab_postcompletion_inventory_polls
                    .checked_add(1)
                    .ok_or(Error::TooLarge)?;
            } else if let Some(original) = &self.lab_running_inventory {
                if original != &numbers {
                    return Err(Error::DescriptorInventory);
                }
            } else {
                self.lab_running_inventory = Some(numbers);
            }
        }
        for fd in descriptors {
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
            Kind::Sockets | Kind::DataSockets => Pending::Sockets(
                PendingSocketPreparation::prepare(
                    request.plan().clone(),
                    request.source(),
                    request.digest(),
                    request.deadline(),
                    child_gate,
                )
                .map_err(map)?,
            ),
            Kind::Provision => {
                let previous = previous.last_mut().ok_or(Error::OwnershipMismatch)?;
                previous.require_acknowledged()?;
                let n = previous.native.as_mut().ok_or(Error::Interrupted)?;
                intent.verify_previous(&n.intent)?;
                borrowed_tokens.extend(n.received_tokens.iter().cloned());
                borrowed_tokens.extend(n.borrowed_tokens.iter().cloned());
                let Some(Complete::Sockets(sockets)) = &mut n.complete else {
                    return Err(Error::OwnershipMismatch);
                };
                let p = PendingWireguardProvision::prepare_from_original_sockets(
                    sockets,
                    request.source(),
                    request.configuration(),
                    request.member(),
                    &request.descriptors(),
                    request.digest(),
                    request.deadline(),
                    child_gate,
                )
                .map_err(map)?;
                Pending::Provision(p)
            }
            Kind::Query => {
                let previous = previous.last_mut().ok_or(Error::OwnershipMismatch)?;
                previous.require_acknowledged()?;
                let n = previous.native.as_mut().ok_or(Error::Interrupted)?;
                intent.verify_previous(&n.intent)?;
                borrowed_tokens.extend(n.received_tokens.iter().cloned());
                borrowed_tokens.extend(n.borrowed_tokens.iter().cloned());
                let Some(Complete::Provision(provision)) = &mut n.complete else {
                    return Err(Error::OwnershipMismatch);
                };
                Pending::Query(
                    PendingWireguardQuery::prepare_from_original_provision(
                        provision,
                        request.source(),
                        request.digest(),
                        request.deadline(),
                        child_gate,
                    )
                    .map_err(map)?,
                )
            }
            Kind::Move => {
                if previous.len() != 4 {
                    return Err(Error::OwnershipMismatch);
                }
                let (source_set, target_set) = previous.split_at_mut(3);
                let source = &mut source_set[2];
                let target = &mut target_set[0];
                source.require_acknowledged()?;
                target.require_acknowledged()?;
                let s = source.native.as_mut().ok_or(Error::Interrupted)?;
                let t = target.native.as_mut().ok_or(Error::Interrupted)?;
                intent.verify_move_source(&s.intent, false)?;
                intent.verify_move_source(&t.intent, true)?;
                borrowed_tokens.extend(s.received_tokens.iter().chain(&s.borrowed_tokens).cloned());
                borrowed_tokens.extend(t.received_tokens.iter().chain(&t.borrowed_tokens).cloned());
                let Some(Complete::Query(query)) = &mut s.complete else {
                    return Err(Error::OwnershipMismatch);
                };
                let Some(Complete::Sockets(sockets)) = &mut t.complete else {
                    return Err(Error::OwnershipMismatch);
                };
                Pending::Move(
                    PendingWireguardMove::prepare(
                        query,
                        sockets,
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
                #[cfg(test)]
                lab_query_sequences: None,
                #[cfg(test)]
                lab_running_inventory: None,
                #[cfg(test)]
                lab_postcompletion_inventory_polls: 0,
                failure: None,
            }),
        };
        let n = value.native.as_mut().ok_or(Error::Interrupted)?;
        let result = (|| {
            let endpoints = n.pending.endpoints()?;
            let raw_endpoints = [endpoints[0].as_raw_fd(), endpoints[1].as_raw_fd()];
            n.child_tokens = Some(super::super::inventory::Registration::owned(&endpoints)?);
            #[cfg(test)]
            lab_fault(&n.request, 3)?;
            let stable: Vec<_> = n
                .pending
                .descriptors()?
                .into_iter()
                .filter(|fd| !raw_endpoints.contains(&fd.as_raw_fd()))
                .filter(|fd| !n.borrowed_tokens.iter().any(|t| t.contains(*fd)))
                .collect();
            n.stable_token = Some(super::super::inventory::Registration::owned(&stable)?);

            super::super::inventory::verify()?;
            n.request.verify()
        })();
        if let Err(e) = result {
            n.fail(e);
            return Err(e);
        }
        Ok(value)
    }
    /// Retains Prepared/no-birth custody while route-only observations yield.
    /// The unchanged request end covers every preparation turn and constructor.
    pub(crate) fn poll_prepared(&mut self) -> Result<bool> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = (|| {
            if n.born || n.failure.is_some() {
                return Err(Error::Interrupted);
            }
            n.request.verify()?;
            if !n.pending.validate_prepared()? {
                return Ok(false);
            }
            n.request.verify()?;
            owner_admission_permitted()?;
            require_child_capacity()?;
            let original = n.pending.birth()?;
            n._capacity = Some(ChildCapacity::created());
            n.born = true;
            n.intent
                .lease()
                .native_job_mut()
                .born_wireguard(original.clone());
            n.original = Some(original);
            // Original birth is now recorded without any intervening native
            // observation. These endpoints were closed by the lower parent.
            n.child_tokens.take();
            #[cfg(test)]
            lab_fault(&n.request, 1)?;
            n.pid_token = Some(super::super::inventory::Registration::owned(&[n
                .pending
                .pidfd()?])?);
            n.birth = Some(n.pending.identify()?);
            n.request.check()?;
            Ok(true)
        })();
        if let Err(e) = result {
            n.fail(e);
        }
        result
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
            #[cfg(test)]
            let span =
                super::super::attachment::movement::trace::Span::new("native", "entry_verify");
            n.request.verify()?;
            #[cfg(test)]
            span.finish();
            if let Some(e) = n.failure {
                return Err(e);
            }
            if let Pending::Sockets(p) = &mut n.pending {
                p.receive_native().map_err(map)?;
            }
            // Own every SCM FD in the lower original context, register all of
            // them here, and only THEN permit any frame/policy rejection.
            #[cfg(test)]
            let span = super::super::attachment::movement::trace::Span::new("native", "inventory");
            n.register_received()?;
            #[cfg(test)]
            span.finish();
            match &mut n.pending {
                Pending::Sockets(p) => {
                    let Some(v) = p.poll().map_err(map)? else {
                        return Ok(false);
                    };
                    let at = v.accepted_at().map_err(map)?;
                    let (dev, ino) = v.namespace_identity().map_err(map)?;
                    n.result = Some(PublicResult {
                        namespace: Identity { dev, ino },
                        link: None,
                        wireguard: None,
                    });
                    n.accepted_at = Some(at);
                    n.complete = Some(Complete::Sockets(Some(v)));
                }
                Pending::Provision(p) => {
                    let Some(v) = p.poll().map_err(map)? else {
                        return Ok(false);
                    };
                    n.result = Some(PublicResult {
                        namespace: n.request.source_identity(),
                        link: Some(v.link_observation().map_err(map)?.clone()),
                        wireguard: Some(v.observation().map_err(map)?.clone()),
                    });
                    n.accepted_at = Some(v.accepted_at().map_err(map)?);
                    n.complete = Some(Complete::Provision(Some(v)));
                }
                Pending::Query(p) => {
                    let Some(v) = p.poll().map_err(map)? else {
                        return Ok(false);
                    };
                    n.result = Some(PublicResult {
                        namespace: n.request.source_identity(),
                        link: Some(v.link_observation().map_err(map)?.clone()),
                        wireguard: Some(v.observation().map_err(map)?.clone()),
                    });
                    n.accepted_at = Some(v.accepted_at().map_err(map)?);
                    #[cfg(test)]
                    {
                        n.lab_query_sequences = Some(v.lab_query_sequences().map_err(map)?);
                    }
                    n.complete = Some(Complete::Query(Some(v)));
                }
                Pending::Move(p) => {
                    #[cfg(test)]
                    let span =
                        super::super::attachment::movement::trace::Span::new("native", "move_poll");
                    let moved = p.poll().map_err(map)?;
                    #[cfg(test)]
                    span.finish();
                    let Some(v) = moved else {
                        return Ok(false);
                    };
                    let (link, wireguard) = v.observation().map_err(map)?;
                    n.result = Some(PublicResult {
                        namespace: n.request.target_identity(),
                        link: Some(link.clone()),
                        wireguard: Some(wireguard.clone()),
                    });
                    n.accepted_at = Some(v.accepted_at().map_err(map)?);
                    n.complete = Some(Complete::Move(v));
                }
                Pending::Empty => return Err(Error::OwnershipMismatch),
            }
            #[cfg(test)]
            if !matches!(n.request.kind(), Kind::Sockets | Kind::DataSockets)
                && n.lab_postcompletion_inventory_polls < 2
            {
                return Err(Error::DescriptorInventory);
            }
            n.pending = Pending::Empty;
            if n.original()?.actual_status().map_err(raw)? != Some(0) {
                return Err(Error::ChildFailed);
            }
            #[cfg(test)]
            let span =
                super::super::attachment::movement::trace::Span::new("native", "final_verify");
            n.request.verify()?;
            #[cfg(test)]
            span.finish();
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => Ok(Some(Verified {
                native: self.native.take(),
            })),
            Err(e) => {
                #[cfg(test)]
                if n.request.kind() == Kind::Move
                    && super::super::attachment::movement::trace::active()
                {
                    eprintln!("LAB_MOVEMENT_PRIMARY_FAILURE scope=native reason={e:?}");
                    super::super::attachment::movement::trace::emit(
                        "native",
                        e,
                        n.lab_cached_progress().unwrap_or(serde_json::Value::Null),
                    );
                }
                n.fail(e);
                n.collect();
                #[cfg(test)]
                if let Pending::Provision(p) = &n.pending {
                    let allowed = LAB_FAILURE_LOGS.with(|count| {
                        let old = count.get();
                        count.set(old.saturating_add(1));
                        old < 8
                    });
                    if allowed {
                        let diagnostic = p.lab_failure().ok();
                        let original = n.original.as_ref().and_then(|r| r.original().ok());
                        let status = n
                            .original
                            .as_ref()
                            .and_then(|r| r.actual_status().ok())
                            .flatten();
                        let child = diagnostic.as_ref().and_then(|d| d.2);
                        eprintln!(
                            "LAB_WIREGUARD_FAILURE {}",
                            serde_json::json!({
                                "kind":n.request.kind(), "request":n.request.digest(),
                                "original_pid":original.map(|o|o.0), "original_start":original.and_then(|o|o.1),
                                "actual_wait_status":status, "requested_at":n.request.requested_at(), "deadline":n.request.deadline(),
                                "parent_stage":diagnostic.as_ref().map(|d|d.0),
                                "parent_reason":diagnostic.as_ref().and_then(|d|d.1).map(|e|format!("{e:?}")),
                                "diagnostic_bound":child.is_some(), "child_stage":child.map(|d|d.stage),
                                "child_code":child.map(|d|d.code), "child_errno":child.map(|d|d.errno), "child_at":child.map(|d|d.at),
                            })
                        );
                    }
                }
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
            NativeJobKind::WireguardSecret,
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

    #[cfg(test)]
    pub(crate) fn lab_move_borrowed_from(&self, source: &Self, target: &Self) -> Result<bool> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let s = source.native.as_ref().ok_or(Error::Interrupted)?;
        let t = target.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        s.creator()?;
        t.creator()?;
        n.intent.verify_move_source(&s.intent, false)?;
        n.intent.verify_move_source(&t.intent, true)?;
        let originals: Vec<_> = s
            .received_tokens
            .iter()
            .chain(&s.borrowed_tokens)
            .chain(t.received_tokens.iter())
            .chain(&t.borrowed_tokens)
            .collect();
        Ok(originals.len() == 4
            && n.borrowed_tokens.len() == 4
            && originals.iter().all(|old| {
                n.borrowed_tokens
                    .iter()
                    .filter(|v| Rc::ptr_eq(old, v))
                    .count()
                    == 1
            }))
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

/// Exact directional filters, original native child/EOF/reap, and actual fresh
/// route+generic sockets. No namespace entry or WireGuard mutation is claimed.
#[cfg(test)]
pub(super) fn lab_filter_selftest() -> Result<()> {
    use rustix::net::{self, RecvFlags, SendFlags};
    let mut producer_proof = None;
    let mut bootstrap_proof = None;
    let mut veth_proof = None;
    let mut veth_move_proof = None;
    for mode in [0, 1, 2, 3, 4, 5, 6, 7, 8] {
        let veth = mode == 6 || mode == 7;
        let bootstrap = mode == 8;
        let producer = mode == 5 || bootstrap;
        let sockets = mode == 1 || mode == 3;
        let movement = mode == 2 || mode == 7;
        let netfilter = (3..=5).contains(&mode) || bootstrap;
        let (result, child_result) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let (gate, child_gate) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let namespace = super::network()?;
        let originals = super::super::inventory::Registration::owned(&[
            result.as_fd(),
            gate.as_fd(),
            namespace.as_fd(),
        ])?;
        let child_tokens = super::super::inventory::Registration::owned(&[
            child_result.as_fd(),
            child_gate.as_fd(),
        ])?;
        let requested_at = vprouter_core::health::boot_seconds();
        let end = requested_at + 2.;
        let (pid, pidfd) = fork_with_pidfd()?;
        if pid == 0 {
            let stage = std::cell::Cell::new(0u8);
            let answer = (|| {
                let a = rustix::io::fcntl_dupfd_cloexec(&child_result, 70)
                    .map_err(|_| Error::DescriptorDuplicate)?;
                let b = rustix::io::fcntl_dupfd_cloexec(&child_gate, 70)
                    .map_err(|_| Error::DescriptorDuplicate)?;
                let c = rustix::io::fcntl_dupfd_cloexec(&namespace, 70)
                    .map_err(|_| Error::DescriptorDuplicate)?;
                dup_fixed(&a, 65, true)?;
                dup_fixed(&b, 66, true)?;
                dup_fixed(&c, 67, true)?;
                if movement {
                    dup_fixed(&c, 68, true)?;
                }
                drop(a);
                drop(b);
                drop(c);
                close_except(if movement {
                    &[65, 66, 67, 68]
                } else {
                    &[65, 66, 67]
                })?;
                secret::non_dumpable()?;
                cv(
                    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                    Error::ConfinementPolicy,
                )?;
                // The real WG constructor always selects two netlink FDs.
                // Empty fd selectors in the generic rule builder mean no fd
                // restriction, so an empty synthetic set is not this policy.
                let mut selected_sockets = Vec::new();
                if !sockets {
                    for protocol in if netfilter {
                        [Some(net::netlink::NETFILTER); 2]
                    } else {
                        [None, Some(net::netlink::GENERIC)]
                    }
                    .into_iter()
                    .cycle()
                    .take(if movement { 4 } else { 2 })
                    {
                        let fd = net::socket_with(
                            net::AddressFamily::NETLINK,
                            net::SocketType::RAW,
                            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                            protocol,
                        )
                        .map_err(|_| Error::DescriptorPolicy)?;
                        if fd.as_raw_fd() != 3 + selected_sockets.len() as i32 {
                            return Err(Error::DescriptorPolicy);
                        }
                        net::bind(&fd, &net::netlink::SocketAddrNetlink::new(0, 0))
                            .map_err(|_| Error::DescriptorPolicy)?;
                        selected_sockets.push(fd);
                    }
                }
                let mut producer_descriptors = Vec::new();
                if producer {
                    for raw in 5..=10 {
                        let fd = rustix::fs::open(
                            "/dev/null",
                            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                            rustix::fs::Mode::empty(),
                        )
                        .map_err(|_| Error::DescriptorNull)?;
                        let st = rustix::fs::fstat(&fd).map_err(|_| Error::DescriptorNull)?;
                        if fd.as_raw_fd() != raw
                            || rustix::fs::FileType::from_raw_mode(st.st_mode)
                                != rustix::fs::FileType::CharacterDevice
                            || rustix::fs::major(st.st_rdev) != 1
                            || rustix::fs::minor(st.st_rdev) != 3
                        {
                            return Err(Error::DescriptorNull);
                        }
                        producer_descriptors.push(fd);
                    }
                }
                let ancestry_name =
                    std::ffi::CString::new("null").map_err(|_| Error::DescriptorPolicy)?;
                let other_name =
                    std::ffi::CString::new("null").map_err(|_| Error::DescriptorPolicy)?;
                if bootstrap {
                    for raw in [11, 12] {
                        let fd = rustix::fs::open(
                            "/dev",
                            rustix::fs::OFlags::RDONLY
                                | rustix::fs::OFlags::DIRECTORY
                                | rustix::fs::OFlags::CLOEXEC,
                            rustix::fs::Mode::empty(),
                        )
                        .map_err(|_| Error::DescriptorPolicy)?;
                        if fd.as_raw_fd() != raw {
                            return Err(Error::DescriptorPolicy);
                        }
                        producer_descriptors.push(fd);
                    }
                }
                let policy = if bootstrap {
                    vprouter_native_role::lab_producer_bootstrap_filter(67, 65, 66, &ancestry_name)
                } else if veth && movement {
                    vprouter_native_role::lab_veth_move_filter(67, 68, 65, 66)
                } else if veth {
                    vprouter_native_role::lab_veth_filter(67, 65, 66)
                } else if producer {
                    vprouter_native_role::lab_producer_netfilter_filter(67, 65, 66)
                } else if netfilter {
                    vprouter_native_role::lab_netfilter_filter(sockets, 67, 65, 66)
                } else if movement {
                    vprouter_native_role::lab_movement_filter(67, 68, 65, 66)
                } else {
                    vprouter_native_role::lab_fixed_filter(sockets, 67, 65, 66)
                };
                apply_filter(&policy)?;
                stage.set(1);
                if bootstrap {
                    let dir = unsafe { BorrowedFd::borrow_raw(11) };
                    let foreign = unsafe { BorrowedFd::borrow_raw(12) };
                    let observed = rustix::fs::statat(
                        dir,
                        &*ancestry_name,
                        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                    )
                    .map_err(|_| Error::DescriptorPolicy)?;
                    if rustix::fs::FileType::from_raw_mode(observed.st_mode)
                        != rustix::fs::FileType::CharacterDevice
                        || rustix::fs::major(observed.st_rdev) != 1
                        || rustix::fs::minor(observed.st_rdev) != 3
                    {
                        return Err(Error::DescriptorPolicy);
                    }
                    for (fd, name, flags) in [
                        (
                            foreign,
                            &*ancestry_name,
                            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                        ),
                        (dir, &*other_name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW),
                        (dir, &*ancestry_name, rustix::fs::AtFlags::empty()),
                    ] {
                        if rustix::fs::statat(fd, name, flags).err()
                            != Some(rustix::io::Errno::PERM)
                        {
                            return Err(Error::DescriptorPolicy);
                        }
                    }
                }
                secret::lab_denials()?;
                for nr in [libc::SYS_setns, libc::SYS_unshare] {
                    if unsafe { libc::syscall(nr, -1, libc::CLONE_NEWNET) } != -1
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                    {
                        return Err(Error::DescriptorPolicy);
                    }
                }
                let output = unsafe { BorrowedFd::borrow_raw(65) };
                let gate = unsafe { BorrowedFd::borrow_raw(66) };
                let mut byte = [0u8; 1];
                if net::recv(output, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
                    != Err(rustix::io::Errno::PERM)
                    || net::send(gate, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                        != Err(rustix::io::Errno::PERM)
                {
                    return Err(Error::DescriptorPolicy);
                }
                stage.set(2);
                secret::gate(gate, end)?;
                stage.set(3);
                if producer {
                    for (index, fd) in producer_descriptors.iter().enumerate() {
                        rustix::fs::fstat(fd).map_err(|_| Error::DescriptorPolicy)?;
                        rustix::fs::fstatfs(fd).map_err(|_| Error::DescriptorPolicy)?;
                        rustix::io::fcntl_getfd(fd).map_err(|_| Error::DescriptorPolicy)?;
                        let read = rustix::io::pread(fd, &mut byte, 0);
                        if (!(2..6).contains(&index) && read != Err(rustix::io::Errno::PERM))
                            || ((2..6).contains(&index) && read != Ok(0))
                        {
                            return Err(Error::DescriptorPolicy);
                        }
                        for nr in [libc::SYS_write, libc::SYS_pwrite64] {
                            if unsafe {
                                libc::syscall(nr, fd.as_raw_fd(), byte.as_ptr(), 1usize, 0u64)
                            } != -1
                                || std::io::Error::last_os_error().raw_os_error()
                                    != Some(libc::EPERM)
                            {
                                return Err(Error::DescriptorPolicy);
                            }
                        }
                        if index >= 2
                            && (unsafe {
                                libc::syscall(
                                    libc::SYS_pread64,
                                    (1u64 << 32) | fd.as_raw_fd() as u64,
                                    byte.as_mut_ptr(),
                                    1usize,
                                    0u64,
                                )
                            } != -1
                                || std::io::Error::last_os_error().raw_os_error()
                                    != Some(libc::EPERM))
                        {
                            return Err(Error::DescriptorPolicy);
                        }
                    }
                    if unsafe {
                        libc::syscall(libc::SYS_pread64, 67, byte.as_mut_ptr(), 1usize, 0u64)
                    } != -1
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                    {
                        return Err(Error::DescriptorPolicy);
                    }
                }
                if movement || veth || (netfilter && !sockets) {
                    for (index, fd) in selected_sockets.iter().enumerate() {
                        if veth && index % 2 == 1 {
                            rustix::fs::fstat(fd).map_err(|_| Error::DescriptorPolicy)?;
                            rustix::io::fcntl_getfd(fd).map_err(|_| Error::DescriptorPolicy)?;
                            for raw in [fd.as_raw_fd() as u64, (1u64 << 32) | fd.as_raw_fd() as u64]
                            {
                                if unsafe {
                                    libc::syscall(
                                        libc::SYS_sendto,
                                        raw,
                                        byte.as_ptr(),
                                        1usize,
                                        libc::MSG_DONTWAIT,
                                        1usize,
                                        std::mem::size_of::<libc::sockaddr_nl>(),
                                    )
                                } != -1
                                    || std::io::Error::last_os_error().raw_os_error()
                                        != Some(libc::EPERM)
                                    || unsafe {
                                        libc::syscall(
                                            libc::SYS_recvfrom,
                                            raw,
                                            byte.as_mut_ptr(),
                                            1usize,
                                            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                                            0usize,
                                            0usize,
                                        )
                                    } != -1
                                    || std::io::Error::last_os_error().raw_os_error()
                                        != Some(libc::EPERM)
                                {
                                    return Err(Error::DescriptorPolicy);
                                }
                            }
                            continue;
                        }
                        // Empty original queue: exact receive permission without reading payload.
                        if net::recv(fd, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
                            != Err(rustix::io::Errno::AGAIN)
                        {
                            return Err(Error::DescriptorPolicy);
                        }
                        // Invalid address pointer proves send permission reaches the kernel,
                        // without submitting any netlink transaction or reading a raw reply.
                        let send = |raw: u64| unsafe {
                            libc::syscall(
                                libc::SYS_sendto,
                                raw,
                                byte.as_ptr(),
                                1usize,
                                libc::MSG_DONTWAIT,
                                1usize,
                                std::mem::size_of::<libc::sockaddr_nl>(),
                            )
                        };
                        if send(fd.as_raw_fd() as u64) != -1
                            || std::io::Error::last_os_error().raw_os_error() != Some(libc::EFAULT)
                        {
                            return Err(Error::DescriptorPolicy);
                        }
                        if send((1u64 << 32) | fd.as_raw_fd() as u64) != -1
                            || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                        {
                            return Err(Error::DescriptorPolicy);
                        }
                    }
                    for raw in if movement { &[67, 68][..] } else { &[67][..] } {
                        let pin = unsafe { BorrowedFd::borrow_raw(*raw) };
                        rustix::fs::fstatfs(pin).map_err(|_| Error::DescriptorPolicy)?;
                        if net::recv(pin, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
                            != Err(rustix::io::Errno::PERM)
                        {
                            return Err(Error::DescriptorPolicy);
                        }
                    }
                    if unsafe {
                        libc::syscall(
                            libc::SYS_sendmsg,
                            65,
                            0usize,
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    } != -1
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                    {
                        return Err(Error::DescriptorPolicy);
                    }
                }
                if sockets {
                    let route = net::socket_with(
                        net::AddressFamily::NETLINK,
                        net::SocketType::RAW,
                        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                        if netfilter {
                            Some(net::netlink::NETFILTER)
                        } else {
                            None
                        },
                    )
                    .map_err(|_| Error::DescriptorPolicy)?;
                    let generic = net::socket_with(
                        net::AddressFamily::NETLINK,
                        net::SocketType::RAW,
                        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                        Some(if netfilter {
                            net::netlink::NETFILTER
                        } else {
                            net::netlink::GENERIC
                        }),
                    )
                    .map_err(|_| Error::DescriptorPolicy)?;
                    if route.as_raw_fd() != 3 || generic.as_raw_fd() != 4 {
                        return Err(Error::DescriptorPolicy);
                    }
                    for fd in [&route, &generic] {
                        net::bind(fd, &net::netlink::SocketAddrNetlink::new(0, 0))
                            .map_err(|_| Error::DescriptorPolicy)?;
                        let addr = net::netlink::SocketAddrNetlink::try_from(
                            net::getsockname(fd).map_err(|_| Error::DescriptorPolicy)?,
                        )
                        .map_err(|_| Error::DescriptorPolicy)?;
                        if addr.pid() == 0 || addr.groups() != 0 {
                            return Err(Error::DescriptorPolicy);
                        }
                        if net::send(fd, &[0u8; 16], SendFlags::DONTWAIT)
                            != Err(rustix::io::Errno::PERM)
                        {
                            return Err(Error::DescriptorPolicy);
                        }
                    }
                    if netfilter {
                        for protocol in [None, Some(net::netlink::GENERIC)] {
                            if !matches!(
                                net::socket_with(
                                    net::AddressFamily::NETLINK,
                                    net::SocketType::RAW,
                                    net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                                    protocol,
                                ),
                                Err(rustix::io::Errno::PERM)
                            ) {
                                return Err(Error::DescriptorPolicy);
                            }
                        }
                    }
                    let descriptors = [route.as_fd(), generic.as_fd()];
                    let mut buffer =
                        [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
                    let mut ancillary = net::SendAncillaryBuffer::new(&mut buffer);
                    if !ancillary.push(net::SendAncillaryMessage::ScmRights(&descriptors)) {
                        return Err(Error::DescriptorPolicy);
                    }
                    net::sendmsg(
                        output,
                        &[std::io::IoSlice::new(&[1])],
                        &mut ancillary,
                        SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                    )
                    .map_err(|_| Error::DescriptorPolicy)?;
                } else {
                    net::send(output, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                        .map_err(|_| Error::DescriptorPolicy)?;
                }
                stage.set(4);
                Ok(())
            })();
            die(if answer.is_ok() {
                0
            } else {
                40 + stage.get() as i32
            });
        }
        let original = ParentReap::born(pid as u32).ok_or(Error::ChildFailed)?;
        let pidfd = pidfd.expect("original atomic pidfd");
        drop(child_tokens);
        drop(child_result);
        drop(child_gate);
        let mut pid_token = None;
        let mut received = Vec::new();
        let answer = (|| {
            pid_token = Some(super::super::inventory::Registration::owned(&[
                pidfd.as_fd()
            ])?);
            if wait_ready(&pidfd, Duration::ZERO)? {
                return Err(Error::ChildFailed);
            }
            let start = process::stat_start(
                &std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .map_err(|_| Error::ProcessUnavailable)?,
                pid as u32,
            )?;
            if wait_ready(&pidfd, Duration::ZERO)? {
                return Err(Error::ChildFailed);
            }
            original.start.set(Some(start));
            net::send(&gate, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                .map_err(|_| Error::DescriptorPolicy)?;
            loop {
                namespace_attachment::check(end)?;
                let mut bytes = [0u8; 1];
                let mut buffer =
                    [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
                let mut ancillary = net::RecvAncillaryBuffer::new(&mut buffer);
                match net::recvmsg(
                    &result,
                    &mut [std::io::IoSliceMut::new(&mut bytes)],
                    &mut ancillary,
                    RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
                ) {
                    Err(rustix::io::Errno::AGAIN) => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(_) => return Err(Error::DescriptorPolicy),
                    Ok(message) => {
                        for item in ancillary.drain() {
                            if let net::RecvAncillaryMessage::ScmRights(fds) = item {
                                for fd in fds {
                                    received
                                        .push(namespace_attachment::Received { fd, token: None });
                                }
                            } else {
                                return Err(Error::DescriptorPolicy);
                            }
                        }
                        for fd in &mut received {
                            fd.token = Some(super::super::inventory::Registration::owned(&[fd
                                .fd
                                .as_fd()])?);
                        }
                        if message.bytes != 1
                            || bytes != [1]
                            || message.flags.bits() & !(libc::MSG_CMSG_CLOEXEC as u32) != 0
                            || received.len() != if sockets { 2 } else { 0 }
                        {
                            return Err(Error::DescriptorPolicy);
                        }
                        break;
                    }
                }
            }
            if sockets {
                for (index, item) in received.iter().enumerate() {
                    let fd = &item.fd;
                    let addr = net::netlink::SocketAddrNetlink::try_from(
                        net::getsockname(fd).map_err(|_| Error::DescriptorPolicy)?,
                    )
                    .map_err(|_| Error::DescriptorPolicy)?;
                    if net::sockopt::socket_domain(fd).map_err(|_| Error::DescriptorPolicy)?
                        != net::AddressFamily::NETLINK
                        || net::sockopt::socket_type(fd).map_err(|_| Error::DescriptorPolicy)?
                            != net::SocketType::RAW
                        || net::sockopt::socket_protocol(fd).map_err(|_| Error::DescriptorPolicy)?
                            != if netfilter {
                                Some(net::netlink::NETFILTER)
                            } else if index == 0 {
                                None
                            } else {
                                Some(net::netlink::GENERIC)
                            }
                        || addr.pid() == 0
                        || addr.groups() != 0
                        || !rustix::io::fcntl_getfd(fd)
                            .map_err(|_| Error::DescriptorPolicy)?
                            .contains(rustix::io::FdFlags::CLOEXEC)
                        || !rustix::fs::fcntl_getfl(fd)
                            .map_err(|_| Error::DescriptorPolicy)?
                            .contains(rustix::fs::OFlags::NONBLOCK)
                    {
                        return Err(Error::DescriptorPolicy);
                    }
                }
            }
            while original.poll(pid as u32, pidfd.as_fd())?.is_none() {
                namespace_attachment::check(end)?;
                std::thread::sleep(Duration::from_millis(1));
            }
            if original.status.get() != Some(0)
                || net::recv(&result, &mut [0u8; 1], RecvFlags::DONTWAIT) != Ok((0, 0))
            {
                return Err(Error::ChildFailed);
            }
            namespace_attachment::check(end)
        })();
        if let Err(error) = answer {
            if wait_ready(&pidfd, Duration::from_secs(2)).unwrap_or(false) {
                let _ = original.poll(pid as u32, pidfd.as_fd());
            }
            eprintln!(
                "LAB_FIXED_NETWORK_FILTER_FAILURE sockets={sockets} movement={movement} netfilter={netfilter} actual_wait_status={:?} reason={error:?}",
                original.status.get()
            );
            let mut tokens = vec![originals];
            tokens.extend(pid_token);
            let mut fds = vec![gate, namespace];
            for item in received {
                tokens.extend(item.token);
                fds.push(item.fd);
            }
            retain_fork_bundle_with_reap(
                pid,
                pidfd,
                result,
                None,
                tokens,
                fds,
                None,
                None,
                None,
                Some(original),
                None,
            );
            return Err(error);
        }
        if veth {
            let verified_at = vprouter_core::health::boot_seconds();
            if !verified_at.is_finite() || verified_at >= end {
                return Err(Error::Deadline);
            }
            let proof = serde_json::json!({
                "schema":1,"original_pid":pid,"original_start":original.start.get(),
                "actual_wait_status":original.status.get(),"requested_at":requested_at,
                "deadline":end,"verified_at":verified_at,"eof_verified":true,
                "route_io_reached_kernel":true,"generic_transactions_denied":true,
                "generic_custody_verified":true,"high_word_and_direction_denied":true,
                "scm_rights_denied":true,"no_netlink_transactions":true,
                "actual_pair_creation":false,"actual_host_mutation":false
            });
            if movement {
                veth_move_proof = Some(proof);
            } else {
                veth_proof = Some(proof);
            }
        }
        if producer && !bootstrap {
            let verified_at = vprouter_core::health::boot_seconds();
            if !verified_at.is_finite() || verified_at >= end {
                return Err(Error::Deadline);
            }
            producer_proof = Some(
                serde_json::json!({"schema":1,"original_pid":pid,"original_start":original.start.get(),"actual_wait_status":original.status.get(),"requested_at":requested_at,"deadline":end,"verified_at":verified_at,
                "eof_verified":true,"six_selected_descriptors":true,"four_read_only_inputs":true,"parent_group_pread_denied":true,"all_group_writes_denied":true,"foreign_and_high_word_denied":true,"role_direction_denied":true,"no_netlink_transactions":true,"actual_group_observation":false,"actual_table_observation":false}),
            );
        }
        if bootstrap {
            let verified_at = vprouter_core::health::boot_seconds();
            if !verified_at.is_finite() || verified_at >= end {
                return Err(Error::Deadline);
            }
            bootstrap_proof = Some(serde_json::json!({
                "schema":1,"original_pid":pid,"original_start":original.start.get(),
                "actual_wait_status":original.status.get(),"requested_at":requested_at,"deadline":end,"verified_at":verified_at,
                "eof_verified":true,"eight_selected_descriptors":true,"four_read_only_inputs":true,
                "exact_statat_reached_kernel":true,"foreign_directory_name_pointer_and_follow_denied":true,
                "all_group_writes_denied":true,"foreign_and_high_word_denied":true,"role_direction_denied":true,
                "no_netlink_transactions":true,"actual_group_ancestry_observation":false,"actual_bootstrap_installation":false
            }));
        }
    }
    println!(
        "LAB_FIXED_PRODUCER_BOOTSTRAP_FILTER {}",
        bootstrap_proof.ok_or(Error::OwnershipMismatch)?
    );
    println!(
        "LAB_FIXED_VETH_MOVE_FILTER {}",
        veth_move_proof.ok_or(Error::OwnershipMismatch)?
    );
    println!(
        "LAB_FIXED_VETH_FILTER {}",
        veth_proof.ok_or(Error::OwnershipMismatch)?
    );
    println!(
        "LAB_FIXED_PRODUCER_NETFILTER_FILTER {}",
        producer_proof.ok_or(Error::OwnershipMismatch)?
    );
    println!(
        "LAB_FIXED_NETFILTER_FILTER {{\"two_actual_wait_zero\":true,\"eof_verified\":true,\"two_original_netfilter_sockets\":true,\"route_generic_creator_denied\":true,\"direction_and_high_word_denied\":true,\"no_netlink_transactions\":true,\"actual_quarantine_installation\":false}}"
    );
    println!(
        "LAB_FIXED_MOVEMENT_FILTER {{\"four_original_sockets\":true,\"two_namespace_pins\":true,\"actual_wait_zero\":true,\"selected_io_reached_kernel\":true,\"high_word_and_direction_denied\":true,\"scm_rights_denied\":true,\"no_netlink_transactions\":true,\"actual_namespace_movement\":false}}"
    );
    println!(
        "LAB_FIXED_NETWORK_FILTER {{\"distinct_gate_result\":true,\"two_actual_wait_zero\":true,\"eof_verified\":true,\"directional_denials\":true,\"actual_route_generic_sockets\":true,\"no_netlink_transactions\":true,\"entered_transport_namespace\":false,\"provisioning_proven\":false}}"
    );
    Ok(())
}

#[cfg(test)]
thread_local! { static LAB_FAILURE_LOGS: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
thread_local! { static LAB_FAULT: std::cell::Cell<Option<(u32, [u8;32], u8)>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
pub(crate) fn lab_arm_fault(request: &Request, fault: u8) -> Result<()> {
    request.verify()?;
    if !matches!(request.kind(), Kind::Sockets | Kind::Move)
        || ![1, 3].contains(&fault)
        || LAB_FAULT.with(|f| f.get().is_some())
    {
        return Err(Error::OwnershipMismatch);
    }
    LAB_FAULT.with(|f| f.set(Some((std::process::id(), request.digest(), fault))));
    Ok(())
}
#[cfg(test)]
fn lab_fault(request: &Request, stage: u8) -> Result<()> {
    let matched = LAB_FAULT.with(|flag| {
        if flag.get() == Some((std::process::id(), request.digest(), stage)) {
            flag.set(None);
            true
        } else {
            false
        }
    });
    if matched {
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
            serde_json::json!({"kind":self.request.kind(),"request":self.request.digest(),
            "requested_at":self.request.requested_at(),"deadline":self.request.deadline(),"birth":self.birth,
            "original_pid":original.map(|v|v.0),"original_start":original.and_then(|v|v.1),
            "actual_wait_status":status,"native_born":self.born,
            "native_job_state":match state { NativeJobState::Prepared=>"prepared",NativeJobState::Born=>"born",NativeJobState::NoBirth=>"no_birth",NativeJobState::Collected=>"collected",NativeJobState::TransferredResources=>"transferred_resources" },
            "full_descriptor_registration":all_registered,"registered_native_slots":registered_slots,"borrowed_registration_count":self.borrowed_tokens.len(),
            "accepted_at":self.accepted_at,"acknowledged":self.acknowledged,"result":self.result,
            "context_retained":true,"query_sequences":self.lab_query_sequences,
            "postcompletion_inventory_polls":self.lab_postcompletion_inventory_polls,
            "postcompletion_inventory_preserved":self.lab_postcompletion_inventory_polls>=2}),
        )
    }
}
#[cfg(test)]
pub(crate) fn lab_failed_context(request: &Request) -> Result<Option<serde_json::Value>> {
    RETAINED.with(|r| {
        let mut r = r.borrow_mut();
        let Some(n) = r
            .iter_mut()
            .find(|n| n.creator == std::process::id() && n.request.digest() == request.digest())
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
#[cfg(test)]
impl Verified {
    pub(crate) fn lab_evidence(&mut self) -> Result<serde_json::Value> {
        self.verify_history()?;
        self.native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .lab_evidence()
    }
    pub(crate) fn lab_borrowed_from(&self, previous: &Self) -> Result<bool> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let p = previous.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        p.creator()?;
        n.intent.verify_previous(&p.intent)?;
        Ok(n.borrowed_tokens.len() == 2
            && n.borrowed_tokens.iter().all(|token| {
                p.received_tokens
                    .iter()
                    .chain(&p.borrowed_tokens)
                    .any(|old| Rc::ptr_eq(token, old))
            }))
    }
}

#[cfg(test)]
impl Native {
    fn lab_cached_progress(&self) -> Option<serde_json::Value> {
        if self.creator != std::process::id() {
            return None;
        }
        let original = self.original.as_ref().and_then(|r| r.original().ok());
        let status = self
            .original
            .as_ref()
            .and_then(|r| r.actual_status().ok())
            .flatten();
        let movement = match (&self.pending, &self.complete) {
            (Pending::Move(p), _) => p.lab_cached_progress(),
            (_, Some(Complete::Move(c))) => c.lab_cached_progress(),
            _ => None,
        };
        Some(
            serde_json::json!({"request":self.request.digest(),"requested_at":self.request.requested_at(),
            "deadline":self.request.deadline(),"original_pid":original.map(|v|v.0),
            "original_start":original.and_then(|v|v.1),"actual_wait_status":status,
            "native_born":self.born,"complete_present":self.complete.is_some(),
            "result_present":self.result.is_some(),"accepted_at":self.accepted_at,"acknowledged":self.acknowledged,
            "postcompletion_inventory_polls":self.lab_postcompletion_inventory_polls,"movement":movement}),
        )
    }
}
#[cfg(test)]
impl Child {
    pub(crate) fn lab_cached_progress(&self) -> Option<serde_json::Value> {
        self.native.as_ref()?.lab_cached_progress()
    }
}
#[cfg(test)]
impl Verified {
    pub(crate) fn lab_cached_progress(&self) -> Option<serde_json::Value> {
        self.native.as_ref()?.lab_cached_progress()
    }
}
