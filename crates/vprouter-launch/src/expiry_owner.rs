#![forbid(unsafe_code)]
//! Parent-created fixed actors and private completion endpoints. No completion
//! writer exists in the guard; its only received FD is the health/control socket.
use super::super::supervision::{Domains, Role, Scope};
use super::*;
use std::os::fd::BorrowedFd;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
pub(super) enum Notice {
    Started {
        lifecycle: String,
        scope: u8,
        namespace: Identity,
        started_at: f64,
    },
    Health {
        message: Box<HealthMessage>,
        at: f64,
    },
    Liveness {
        lifecycle: String,
        sequence: u64,
        sent_at: f64,
        at: f64,
    },
    Terminal {
        lifecycle: String,
        scope: u8,
        outcome: TerminalResult,
        deadline: f64,
        finished_at: f64,
    },
}
/// Only this collector can mint completion authority. It is not deserializable.
#[derive(Clone)]
pub(crate) struct FixedCompletion {
    allocation: String,
    exit: String,
    lifecycle: String,
    completion: ExecutorCompletion,
}
impl FixedCompletion {
    pub(crate) fn bound_completion(
        &self,
        allocation: &str,
        exit: &str,
        lifecycle: &str,
    ) -> Result<ExecutorCompletion> {
        if self.allocation != allocation || self.exit != exit || self.lifecycle != lifecycle {
            return Err(Error::OwnershipMismatch);
        }
        Ok(self.completion.clone())
    }
}
pub(crate) struct FixedRegistration {
    allocation: String,
    exit: String,
    lifecycle: String,
    identity: ExecutorIdentity,
}
impl FixedRegistration {
    pub(crate) fn into_bound(
        self,
        allocation: &str,
        exit: &str,
        lifecycle: &str,
    ) -> Result<ExecutorIdentity> {
        if self.allocation != allocation || self.exit != exit || self.lifecycle != lifecycle {
            return Err(Error::OwnershipMismatch);
        }
        Ok(self.identity)
    }
}
struct Actor {
    child: kernel::Survivor,
    identity: ExecutorIdentity,
    completion: OwnedFd,
    control: Option<OwnedFd>,
    placement: Option<kernel::PlacementChild>,
    scope: Option<Scope>,
    clock: LeaseClock,
    started: bool,
    released: bool,
    cancelled: bool,
    transferred: bool,
    finished: bool,
    reaped: bool,
    failure: Option<Error>,
    _inventory: super::super::inventory::Registration,
}
struct UnregisteredActor {
    child: kernel::Survivor,
    reader: OwnedFd,
    control: OwnedFd,
    _inventory: Option<super::super::inventory::Registration>,
    reaped: bool,
    failure: Option<Error>,
}
pub(crate) struct NativeOwnerExecutors {
    creator: u32,
    retained_completions: Vec<FixedCompletion>,
    retained_error: Option<Error>,
    retirement_revoked: bool,
    domains: Domains,
    binding: Binding,
    policies: [Policy; 3],
    namespaces: [OwnedFd; 3],
    lease: OwnedFd,
    _inventory: super::super::inventory::Registration,
    started_at: Option<f64>,
    actors: Vec<Actor>,
    unregistered: Vec<UnregisteredActor>,
    #[cfg(test)]
    stop_host_after_containment: bool,
    #[cfg(test)]
    pause_next_placement: bool,
}
pub(crate) struct OwnerExecutors {
    native: Option<NativeOwnerExecutors>,
}
impl std::ops::Deref for OwnerExecutors {
    type Target = NativeOwnerExecutors;
    fn deref(&self) -> &Self::Target {
        self.native.as_ref().expect("expiry owner retained")
    }
}
impl std::ops::DerefMut for OwnerExecutors {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.native.as_mut().expect("expiry owner retained")
    }
}
impl OwnerExecutors {
    pub(crate) fn new(
        domains: Domains,
        binding: Binding,
        policies: [Policy; 3],
        namespaces: [OwnedFd; 3],
        lease: OwnedFd,
    ) -> Result<Self> {
        Ok(Self {
            native: Some(NativeOwnerExecutors::new(
                domains, binding, policies, namespaces, lease,
            )?),
        })
    }
}
thread_local! { static RETIRED_OWNERS: std::cell::RefCell<Vec<NativeOwnerExecutors>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl OwnerExecutors {
    pub(crate) fn release_retired(
        &mut self,
        permit: &super::super::owned::RetiredPermit,
        service: &super::super::owned::JournalServer,
    ) -> Result<()> {
        permit.verify_expiry_release(service, self)?;
        drop(self.native.take().ok_or(Error::OwnershipMismatch)?);
        Ok(())
    }
}
impl Drop for OwnerExecutors {
    fn drop(&mut self) {
        let Some(mut native) = self.native.take() else {
            return;
        };
        if native.creator != std::process::id() {
            return;
        }
        if native.actors.is_empty() && native.unregistered.is_empty() {
            return;
        }
        if let Err(error) = native.revoke_for_retirement() {
            native.retained_error.get_or_insert(error);
        }
        RETIRED_OWNERS.with(|owners| owners.borrow_mut().push(native));
    }
}
pub(crate) fn poll_retired_owners() {
    RETIRED_OWNERS.with(|owners| {
        for owner in owners
            .borrow_mut()
            .iter_mut()
            .filter(|owner| owner.creator == std::process::id())
        {
            match owner.poll() {
                // poll retains an original typed copy before delivery. Dropped
                // callers cannot discard a pending durable-enqueue receipt.
                Ok(_) => {}
                Err(error) => {
                    owner.retained_error.get_or_insert(error);
                }
            }
        }
    });
}
pub(crate) fn retired_owners_drained() -> bool {
    // Native reaping cannot erase authenticated but uncommitted completions or
    // the canonical context. Consuming retirement/reconciliation owns release.
    RETIRED_OWNERS.with(|owners| {
        owners
            .borrow()
            .iter()
            .all(|owner| owner.creator != std::process::id())
    })
}
impl NativeOwnerExecutors {
    pub(crate) fn revoke_for_retirement(&mut self) -> Result<()> {
        self.current()?;
        self.retirement_revoked = true;
        // Shutdown every original parent alias; never signal an expiry child.
        // Continue independently after any error and retain its original reason.
        let mut first = None;
        for child in self
            .actors
            .iter()
            .map(|a| &a.child)
            .chain(self.unregistered.iter().map(|a| &a.child))
        {
            if let Err(error) = child.revoke_terminal_control() {
                first.get_or_insert(error);
            }
        }
        if let Err(error) = self.cancel_spawn() {
            first.get_or_insert(error);
        }
        if let Some(error) = first {
            self.retained_error.get_or_insert(error);
            return Err(error);
        }
        Ok(())
    }

    fn admitting(&self) -> Result<()> {
        self.current()?;
        if self.retirement_revoked {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    fn current(&self) -> Result<()> {
        if self.creator == std::process::id() {
            Ok(())
        } else {
            Err(Error::OwnershipMismatch)
        }
    }

    #[cfg(test)]
    pub(crate) fn lab_require_inert(&self) -> Result<()> {
        self._inventory.lab_require_inert()
    }
    pub(crate) fn new(
        domains: Domains,
        binding: Binding,
        policies: [Policy; 3],
        namespaces: [OwnedFd; 3],
        lease: OwnedFd,
    ) -> Result<Self> {
        if binding.exit_id != domains.exit_id() {
            return Err(Error::OwnershipMismatch);
        }
        let inventory = super::super::inventory::Registration::owned(&[
            namespaces[0].as_fd(),
            namespaces[1].as_fd(),
            namespaces[2].as_fd(),
            lease.as_fd(),
        ])?;
        domains.verify_owner()?;
        Ok(Self {
            creator: std::process::id(),
            retained_completions: Vec::new(),
            retained_error: None,
            retirement_revoked: false,
            domains,
            binding,
            policies,
            namespaces,
            lease,
            _inventory: inventory,
            started_at: None,
            actors: vec![],
            unregistered: vec![],
            #[cfg(test)]
            stop_host_after_containment: false,
            #[cfg(test)]
            pause_next_placement: false,
        })
    }
    pub(crate) fn binds(&self, allocation: &str, exit: &str, lifecycle: &str) -> Result<()> {
        self.current()?;
        if self.domains.allocation() != allocation
            || self.domains.exit_id() != exit
            || self.domains.lifecycle() != lifecycle
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn begin(&mut self, original: f64) -> Result<()> {
        self.admitting()?;
        original_notice(original)?;
        if self.started_at.is_some() || !self.actors.is_empty() {
            return Err(Error::OwnershipMismatch);
        }
        self.started_at = Some(original);
        Ok(())
    }
    pub(crate) fn spawn(
        &mut self,
        guard: &kernel::Survivor,
        scope: u8,
        started_at: f64,
        sent_at: f64,
    ) -> Result<()> {
        self.admitting()?;
        if !self.unregistered.is_empty()
            || scope as usize != self.actors.len()
            || scope > 2
            || self.actors.iter().any(|a| !a.transferred)
        {
            return Err(Error::OwnershipMismatch);
        }
        if self.started_at != Some(started_at) {
            return Err(Error::Deadline);
        }
        let clock = LeaseClock::new(
            self.binding.clone(),
            self.domains.lifecycle().into(),
            started_at,
        )?;
        let (reader, writer) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let temporary =
            super::super::inventory::Registration::owned(&[reader.as_fd(), writer.as_fd()])?;
        let index = scope as usize;
        let (child, control) = kernel::spawn_terminal(
            &self.namespaces[index],
            &self.lease,
            &self.policies[index],
            ChildBinding {
                binding: &self.binding,
                lifecycle: self.domains.lifecycle(),
                scope,
                started_at,
            },
            Some(&self.domains),
            Some(kernel::OwnerTerminal {
                guard,
                completion: writer.as_fd(),
                completion_reader: reader.as_fd(),
                #[cfg(test)]
                stop_after_containment: self.stop_host_after_containment && scope == 0,
            }),
        )?;
        drop(temporary);
        drop(writer);
        self.unregistered.push(UnregisteredActor {
            child,
            reader,
            control,
            _inventory: None,
            reaped: false,
            failure: None,
        });
        let pending = self.unregistered.last_mut().ok_or(Error::Interrupted)?;
        pending._inventory = Some(super::super::inventory::Registration::owned(&[
            pending.reader.as_fd(),
            pending.control.as_fd(),
        ])?);
        let identity = pending
            .child
            .identity(scope, Identity::network(&self.namespaces[index])?)?;
        let pending = self.unregistered.pop().ok_or(Error::Interrupted)?;
        let child = pending.child;
        let reader = pending.reader;
        let control = pending.control;
        let inventory = pending._inventory.ok_or(Error::Interrupted)?;
        self.actors.push(Actor {
            child,
            identity,
            completion: reader,
            control: Some(control),
            placement: None,
            scope: None,
            clock,
            started: false,
            released: false,
            cancelled: false,
            transferred: false,
            finished: false,
            reaped: false,
            failure: None,
            _inventory: inventory,
        });
        let actor = &mut self.actors[index];
        actor.placement = Some(kernel::spawn_placement(
            &self.domains,
            &actor.child,
            role(scope)?,
            &self.lease,
            sent_at + 2.,
            #[cfg(test)]
            std::mem::take(&mut self.pause_next_placement),
        )?);
        Ok(())
    }
    pub(crate) fn released(&self) -> bool {
        self.actors.last().is_some_and(|a| a.released)
    }
    pub(crate) fn poll_placement(&mut self) -> Result<Option<FixedRegistration>> {
        self.admitting()?;
        let actor = self
            .actors
            .last_mut()
            .filter(|a| !a.released && !a.cancelled)
            .ok_or(Error::Interrupted)?;
        if actor.scope.is_none() {
            let Some(receipt) = actor.placement.as_mut().ok_or(Error::Interrupted)?.poll()? else {
                return Ok(None);
            };
            self.domains.complete_placement_retained(
                &actor.child,
                role(actor.identity.scope)?,
                receipt,
                &mut actor.scope,
            )?;
        }
        actor
            .scope
            .as_ref()
            .ok_or(Error::Interrupted)?
            .verify(&actor.child)?;
        let actual = rustix::fs::open(
            format!("/proc/{}/ns/net", actor.identity.pid),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        if Identity::network(actual)? != actor.identity.namespace
            || actor.child.start_time()? != actor.identity.start_time
        {
            return Err(Error::ProcessChanged);
        }
        Ok(Some(FixedRegistration {
            allocation: self.domains.allocation().into(),
            exit: self.domains.exit_id().into(),
            lifecycle: self.domains.lifecycle().into(),
            identity: actor.identity.clone(),
        }))
    }
    pub(crate) fn release_registered(&mut self) -> Result<()> {
        self.admitting()?;
        let actor = self
            .actors
            .last_mut()
            .filter(|a| !a.released && !a.cancelled && a.scope.is_some())
            .ok_or(Error::Interrupted)?;
        kernel::release_terminal(actor.control.as_ref().ok_or(Error::Interrupted)?)?;
        actor.released = true;
        Ok(())
    }
    pub(crate) fn poll_spawn(
        &mut self,
    ) -> Result<Option<(ExecutorIdentity, BorrowedFd<'_>, BorrowedFd<'_>)>> {
        self.admitting()?;
        let actor = self
            .actors
            .last_mut()
            .filter(|a| a.released && !a.transferred && !a.cancelled)
            .ok_or(Error::Interrupted)?;
        if !actor.started {
            let Some(notice) = receive::<Notice>(&actor.completion)? else {
                return Ok(None);
            };
            match notice {
                Notice::Started {
                    lifecycle,
                    scope,
                    namespace,
                    started_at,
                } if lifecycle == self.domains.lifecycle()
                    && scope == actor.identity.scope
                    && namespace == actor.identity.namespace
                    && Some(started_at) == self.started_at => {}
                _ => return Err(Error::OwnershipMismatch),
            }
            actor
                .scope
                .as_ref()
                .ok_or(Error::Interrupted)?
                .verify(&actor.child)?;
            let actual = rustix::fs::open(
                format!("/proc/{}/ns/net", actor.identity.pid),
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| Error::NamespaceMismatch)?;
            if Identity::network(actual)? != actor.identity.namespace
                || actor.child.start_time()? != actor.identity.start_time
            {
                return Err(Error::ProcessChanged);
            }
            actor.started = true;
        }
        Ok(Some((
            actor.identity.clone(),
            actor.control.as_ref().ok_or(Error::Interrupted)?.as_fd(),
            actor.child.pidfd(),
        )))
    }
    pub(crate) fn transferred(&mut self) -> Result<()> {
        self.admitting()?;
        let actor = self.actors.last_mut().ok_or(Error::Interrupted)?;
        if !actor.started || actor.transferred {
            return Err(Error::Interrupted);
        }
        actor.transferred = true;
        // Drop inventory before FD closure; completion retains a new exact registration.
        let replacement = super::super::inventory::Registration::owned(&[])?;
        drop(std::mem::replace(&mut actor._inventory, replacement));
        actor.control.take();
        actor._inventory =
            super::super::inventory::Registration::owned(&[actor.completion.as_fd()])?;
        Ok(())
    }
    pub(crate) fn registered_identity(&self, identity: &ExecutorIdentity) -> Result<()> {
        self.admitting()?;
        let actor = self
            .actors
            .get(identity.scope as usize)
            .ok_or(Error::OwnershipMismatch)?;
        if actor.identity != *identity || !actor.transferred || !actor.started {
            return Err(Error::OwnershipMismatch);
        }
        actor
            .scope
            .as_ref()
            .ok_or(Error::OwnershipMismatch)?
            .verify(&actor.child)?;
        if actor.child.start_time()? != identity.start_time {
            return Err(Error::ProcessChanged);
        }
        Ok(())
    }
    pub(crate) fn poll(&mut self) -> Result<Vec<FixedCompletion>> {
        self.current()?;
        let mut completed = vec![];
        for pending in &mut self.unregistered {
            if !pending.reaped {
                match pending.child.reap_exited() {
                    Ok(reaped) => pending.reaped = reaped,
                    Err(error) => pending.failure = Some(error),
                }
            }
        }
        for actor in &mut self.actors {
            if actor.failure.is_some() {
                if let Some(job) = &mut actor.placement
                    && !job.drained()
                {
                    let _ = job.poll();
                }
                if !actor.reaped
                    && let Ok(reaped) = actor.child.reap_exited()
                {
                    actor.reaped = reaped;
                }
                continue;
            }
            let result = (|| -> Result<Option<FixedCompletion>> {
                if actor.finished && !actor.reaped {
                    actor.reaped = actor.child.reap_exited()?;
                }
                if actor.cancelled {
                    if let Some(job) = &mut actor.placement
                        && !job.drained()
                    {
                        let _ = job.poll();
                    }
                    if !actor.released
                        && actor.child.require_live().is_err()
                        && actor.placement.as_ref().is_none_or(|p| p.drained())
                    {
                        actor.finished = true;
                    }
                }
                if (!actor.transferred && !actor.cancelled) || !actor.released || actor.finished {
                    return Ok(None);
                }
                let Some(notice) = receive::<Notice>(&actor.completion)? else {
                    return Ok(None);
                };
                match notice {
                    Notice::Started {
                        lifecycle,
                        scope,
                        namespace,
                        started_at,
                    } if actor.cancelled
                        && !actor.started
                        && lifecycle == self.domains.lifecycle()
                        && scope == actor.identity.scope
                        && namespace == actor.identity.namespace
                        && Some(started_at) == self.started_at =>
                    {
                        actor.started = true;
                    }
                    Notice::Health { message, at } => {
                        original_notice(at)?;
                        actor.clock.accept(&message, at)?;
                    }
                    Notice::Liveness {
                        lifecycle,
                        sequence,
                        sent_at,
                        at,
                    } => {
                        original_notice(at)?;
                        actor.clock.liveness(&lifecycle, sequence, sent_at, at)?;
                    }
                    Notice::Terminal {
                        lifecycle,
                        scope,
                        outcome,
                        deadline,
                        finished_at,
                    } => {
                        original_notice(finished_at)?;
                        if lifecycle != self.domains.lifecycle()
                            || scope != actor.identity.scope
                            || deadline != actor.clock.deadline.min(actor.clock.liveness_deadline)
                        {
                            return Err(Error::OwnershipMismatch);
                        }
                        let completion = ExecutorCompletion {
                            identity: actor.identity.clone(),
                            result: outcome,
                            deadline,
                            finished_at,
                        };
                        completion.validate()?;
                        return Ok(Some(FixedCompletion {
                            allocation: self.domains.allocation().into(),
                            exit: self.domains.exit_id().into(),
                            lifecycle,
                            completion,
                        }));
                    }
                    _ => return Err(Error::DescriptorPolicy),
                }
                Ok(None)
            })();
            retain_actor_result(
                result,
                &mut completed,
                &mut actor.finished,
                &mut actor.failure,
            );
        }

        if self.retained_completions.len() + completed.len() > 3 {
            return Err(Error::TooLarge);
        }
        self.retained_completions.extend(completed.iter().cloned());
        Ok(completed)
    }
    pub(crate) fn failure(&self) -> Option<Error> {
        self.unregistered
            .iter()
            .find_map(|a| a.failure)
            .or_else(|| self.actors.iter().find_map(|a| a.failure))
    }
    pub(crate) fn finished(&self) -> bool {
        self.creator == std::process::id()
            && self.unregistered.iter().all(|a| a.reaped)
            && self.actors.iter().all(|a| {
                (a.finished || a.failure.is_some())
                    && a.reaped
                    && a.placement.as_ref().is_none_or(|p| p.drained())
            })
    }
    pub(crate) fn require_registered_retirement(&self) -> Result<()> {
        self.current()?;
        if self.actors.len() != 3
            || !self.unregistered.is_empty()
            || self
                .actors
                .iter()
                .any(|a| !a.started || !a.released || !a.transferred || a.cancelled)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn retirement_reaps(&self) -> Result<[kernel::NativeReapProof; 3]> {
        self.current()?;
        if !self.finished()
            || !self.unregistered.is_empty()
            || self.actors.len() != 3
            || self.retained_completions.len() != 3
            || !kernel::terminal_births_drained(
                self.domains.allocation(),
                self.domains.exit_id(),
                self.domains.lifecycle(),
            )
        {
            return Err(Error::Interrupted);
        }
        let mut receipts = Vec::new();
        for (index, actor) in self.actors.iter().enumerate() {
            if actor.identity.scope as usize != index
                || actor.identity.pid != actor.child.pid()
                || !actor.started
                || !actor.released
                || !actor.transferred
                || !actor.finished
                || actor.failure.is_some()
                || !actor
                    .scope
                    .as_ref()
                    .ok_or(Error::CgroupMismatch)?
                    .quiescent()?
            {
                return Err(Error::OwnershipMismatch);
            }
            let completion = self
                .retained_completions
                .iter()
                .find(|receipt| receipt.completion.identity == actor.identity)
                .ok_or(Error::OwnershipMismatch)?;
            if completion.completion.result != TerminalResult::VerifiedBeforeDeadline
                || completion.completion.deadline
                    != actor.clock.deadline.min(actor.clock.liveness_deadline)
            {
                return Err(Error::OwnershipMismatch);
            }
            let receipt = actor
                .child
                .retirement_reap(actor.identity.start_time)?
                .ok_or(Error::Interrupted)?;
            if receipt.identity()? != (actor.identity.pid, actor.identity.start_time, 122 << 8) {
                return Err(Error::ChildFailed);
            }
            receipts.push(receipt);
        }
        receipts.try_into().map_err(|_| Error::OwnershipMismatch)
    }
    #[cfg(test)]
    pub(crate) fn drained(&self) -> usize {
        self.actors.iter().filter(|a| a.reaped).count()
    }
    pub(crate) fn cancel_spawn(&mut self) -> Result<()> {
        self.current()?;
        let mut failure = None;
        for pending in &self.unregistered {
            let _ = net::shutdown(&pending.control, net::Shutdown::Both);
        }
        for actor in &mut self.actors {
            if !actor.transferred {
                actor.cancelled = true;
                if let Some(job) = &mut actor.placement
                    && !job.drained()
                    && let Err(error) = job.cancel()
                {
                    failure.get_or_insert(error);
                }
                // Closing gated control never grants authority or frees capacity.
                if let Some(control) = &actor.control {
                    let _ = net::shutdown(control, net::Shutdown::Both);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
    #[cfg(test)]
    pub(crate) fn lab_pause_placement(&mut self) {
        self.pause_next_placement = true;
    }
    #[cfg(test)]
    pub(crate) fn lab_placement_checkpoint(&mut self) -> Result<Option<(u32, u64, f64)>> {
        match self.actors.last_mut().and_then(|a| a.placement.as_mut()) {
            Some(job) => job.lab_checkpoint(),
            None => Ok(None),
        }
    }
    #[cfg(test)]
    pub(crate) fn lab_placement_drained_without_grant(&self) -> Result<bool> {
        if self.actors.len() != 1 || !self.unregistered.is_empty() {
            return Err(Error::OwnershipMismatch);
        }
        let actor = &self.actors[0];
        if actor.released || actor.transferred || actor.started || actor.scope.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(
            actor.cancelled
                && actor.reaped
                && actor.placement.as_ref().is_some_and(|p| p.drained()),
        )
    }
    #[cfg(test)]
    pub(crate) fn stop_host_after_containment(&mut self) {
        self.stop_host_after_containment = true;
    }
    #[cfg(test)]
    pub(crate) fn lab_all_transferred(&self) -> bool {
        self.creator == std::process::id()
            && self.actors.len() == 3
            && self.unregistered.is_empty()
            && self.actors.iter().all(|actor| {
                actor.started
                    && actor.released
                    && actor.transferred
                    && !actor.finished
                    && actor.failure.is_none()
            })
    }
    #[cfg(test)]
    pub(crate) fn native_handles(&self) -> Result<Vec<kernel::Survivor>> {
        self.actors
            .iter()
            .map(|actor| actor.child.lab_clone_native())
            .collect()
    }
    #[cfg(test)]
    pub(crate) fn identities(&self) -> Vec<ExecutorIdentity> {
        self.actors.iter().map(|a| a.identity.clone()).collect()
    }
}
#[cfg(test)]
pub(crate) fn lab_retained_expiry(domains: &Domains) -> Result<serde_json::Value> {
    RETIRED_OWNERS.with(|owners| {
        let owners = owners.borrow();
        let mut found = owners.iter().filter(|owner| owner.creator == std::process::id()
            && owner.domains.allocation() == domains.allocation() && owner.domains.exit_id() == domains.exit_id()
            && owner.domains.lifecycle() == domains.lifecycle());
        let owner = found.next().ok_or(Error::OwnershipMismatch)?;
        if found.next().is_some() || owner.actors.len() != 3 || !owner.unregistered.is_empty()
            || !owner._inventory.contains(owner.lease.as_fd())
            || owner.namespaces.iter().any(|fd| !owner._inventory.contains(fd.as_fd())) {
            return Err(Error::OwnershipMismatch);
        }
        let mut actors = Vec::new();
        for actor in &owner.actors {
            if !actor._inventory.contains(actor.completion.as_fd()) || !actor.started || !actor.released || !actor.transferred {
                return Err(Error::OwnershipMismatch);
            }
            let status = actor.child.lab_terminal_status()?;
            let no_live_tasks = if actor.reaped {
                actor.scope.as_ref().ok_or(Error::CgroupMismatch)?.quiescent().inspect_err(|error| {
                    eprintln!("LAB_EXPIRY_SCOPE_FAILURE scope={} pid={} start={} status={status:?} reason={error}", actor.identity.scope, actor.identity.pid, actor.identity.start_time);
                })?
            } else { false };
            actors.push(serde_json::json!({"identity":actor.identity,"actual_wait_status":status,"actual_reaped":actor.reaped,
                "original_deadline":actor.clock.deadline.min(actor.clock.liveness_deadline),"no_live_tasks":no_live_tasks}));
        }
        let receipts: Vec<_> = owner.retained_completions.iter().map(|receipt| receipt.bound_completion(domains.allocation(), domains.exit_id(), domains.lifecycle())).collect::<Result<_>>()?;
        Ok(serde_json::json!({"original_started_at":owner.started_at,"actors":actors,"completions":receipts,
            "all_actual_reaped":owner.finished(),"all_native_context_retained":true,"uncommitted_receipts_retained":true,
            "failure":owner.failure().or(owner.retained_error).map(|error|error.to_string())}))
    })
}
fn retain_actor_result(
    result: Result<Option<FixedCompletion>>,
    completed: &mut Vec<FixedCompletion>,
    finished: &mut bool,
    failure: &mut Option<Error>,
) {
    match result {
        Ok(Some(receipt)) => {
            completed.push(receipt);
            *finished = true;
        }
        Ok(None) => {}
        Err(error) => *failure = Some(error),
    }
}
fn role(scope: u8) -> Result<Role> {
    match scope {
        0 => Ok(Role::ExpiryHost),
        1 => Ok(Role::ExpiryTransport),
        2 => Ok(Role::ExpiryData),
        _ => Err(Error::OwnershipMismatch),
    }
}
fn original_notice(at: f64) -> Result<()> {
    let now = boot_seconds();
    if !at.is_finite() || at < 0. || !now.is_finite() || now < at || now - at >= 2. {
        return Err(Error::Deadline);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn completion() -> FixedCompletion {
        FixedCompletion {
            allocation: "a".repeat(64),
            exit: "one".into(),
            lifecycle: "b".repeat(64),
            completion: ExecutorCompletion {
                identity: ExecutorIdentity {
                    scope: 0,
                    pid: 42,
                    start_time: 10,
                    namespace: Identity { dev: 1, ino: 2 },
                },
                result: TerminalResult::VerifiedBeforeDeadline,
                deadline: 123.,
                finished_at: 122.,
            },
        }
    }
    #[test]
    fn valid_receipts_survive_a_failed_middle_sibling_without_replay() {
        let mut completed = vec![];
        let mut finished = [false; 3];
        let mut failures = [None; 3];
        retain_actor_result(
            Ok(Some(completion())),
            &mut completed,
            &mut finished[0],
            &mut failures[0],
        );
        retain_actor_result(
            Err(Error::DescriptorPolicy),
            &mut completed,
            &mut finished[1],
            &mut failures[1],
        );
        let mut third = completion();
        third.completion.identity.scope = 2;
        retain_actor_result(
            Ok(Some(third)),
            &mut completed,
            &mut finished[2],
            &mut failures[2],
        );
        assert_eq!(
            completed
                .iter()
                .map(|c| c.completion.identity.scope)
                .collect::<Vec<_>>(),
            [0, 2]
        );
        assert_eq!(finished, [true, false, true]);
        assert_eq!(failures, [None, Some(Error::DescriptorPolicy), None]);
        assert!(
            completed
                .iter()
                .all(|c| c.completion.deadline == 123. && c.completion.finished_at == 122.)
        );
    }
    #[test]
    fn private_completion_binding_preserves_original_outcome_and_deadline() {
        let value = completion()
            .bound_completion(&"a".repeat(64), "one", &"b".repeat(64))
            .unwrap();
        assert_eq!(value.deadline, 123.);
        assert_eq!(value.finished_at, 122.);
        assert_eq!(value.result, TerminalResult::VerifiedBeforeDeadline);
        for (allocation, exit, lifecycle) in [
            ("c".repeat(64), "one", "b".repeat(64)),
            ("a".repeat(64), "two", "b".repeat(64)),
            ("a".repeat(64), "one", "c".repeat(64)),
        ] {
            assert!(
                completion()
                    .bound_completion(&allocation, exit, &lifecycle)
                    .is_err()
            );
        }
        let mut late = completion();
        late.completion.finished_at = 124.;
        assert!(late.completion.validate().is_err());
        late.completion.result = TerminalResult::LateVerified;
        let value = late
            .bound_completion(&"a".repeat(64), "one", &"b".repeat(64))
            .unwrap();
        value.validate().unwrap();
        assert_eq!(value.result, TerminalResult::LateVerified);
        assert_eq!(value.deadline, 123.);
    }
    #[test]
    fn actor_notice_cannot_reanchor_stale_future_or_invalid_time() {
        let now = boot_seconds();
        original_notice(now).unwrap();
        for at in [now - 2.001, now + 10., -1., f64::NAN, f64::INFINITY] {
            assert!(original_notice(at).is_err());
        }
    }
}
