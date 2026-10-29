//! Retained three-namespace enforcement. No readiness or caller proof constructor.
use crate::{Actuator, Error, Reconciliation, Result, Scope, Stage};

pub struct Enforcement {
    host: Actuator,
    transport: Actuator,
    data: Actuator,
}
impl Enforcement {
    pub fn bind_cleanup_deadline(
        &mut self,
        deadline: crate::BootDeadline,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        for actuator in [&mut self.host, &mut self.transport, &mut self.data] {
            actuator.bind_cleanup_deadline(deadline, timer.clone())?;
        }
        Ok(())
    }
    pub fn descriptors(&self) -> Vec<std::os::fd::BorrowedFd<'_>> {
        [&self.host, &self.transport, &self.data]
            .into_iter()
            .flat_map(|actuator| actuator.descriptors())
            .collect()
    }
    /// Same exact scoped cleanup with a caller-owned native producer fence before
    /// each destructive batch. It never authorizes removal of quarantine.
    pub fn cleanup_permits_with_fence(
        &mut self,
        mut fence: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        fence()?;
        self.offline()?;
        fence()?;
        self.host.cleanup_cooperation()?;
        fence()?;
        self.host.cleanup_permit()?;
        fence()?;
        self.data.cleanup_permit()?;
        fence()?;
        self.transport.cleanup_permit()
    }

    /// Inputs carry actual namespace-bound sockets. Full host quarantine is
    /// installed first, before any namespace permit table or network activation.
    pub fn quarantine(host: Actuator, transport: Actuator, data: Actuator) -> Result<Self> {
        if host.policy().scope() != Scope::Host
            || transport.policy().scope() != Scope::Transport
            || data.policy().scope() != Scope::Data
            || host.policy().binding() != transport.policy().binding()
            || host.policy().binding() != data.policy().binding()
            || host.policy().endpoint != transport.policy().endpoint
            || host.policy().endpoint != data.policy().endpoint
            || host.policy().wan != transport.policy().wan
            || host.policy().wan != data.policy().wan
            || host.namespace() == transport.namespace()
            || host.namespace() == data.namespace()
            || transport.namespace() == data.namespace()
        {
            return Err(Error::InvalidAllocation);
        }
        let mut e = Self {
            host,
            transport,
            data,
        };
        e.offline()?;
        Ok(e)
    }
    /// Immutable copies of the exact admitted policies for independent terminal
    /// writers. This exposes no live sockets or ready/phase construction API.
    pub fn terminal_policies(&self) -> [crate::Policy; 3] {
        [
            self.host.policy().clone(),
            self.transport.policy().clone(),
            self.data.policy().clone(),
        ]
    }
    /// Every scope is attempted even when another has failed. A failed scope
    /// leaves its other independent scopes quarantined; never stop/cleanup first.
    pub fn offline(&mut self) -> Result<()> {
        let h = self.host.install_quarantine();
        let d = self.data.install_quarantine();
        let t = self.transport.install_quarantine();
        h.and(d).and(t)
    }
    pub fn verify(
        &mut self,
        alias: &str,
        endpoint: std::net::SocketAddrV4,
        host: (u64, u64),
        transport: (u64, u64),
        data: (u64, u64),
        stage: Stage,
    ) -> Result<()> {
        if self.host.policy().binding() != alias
            || self.host.policy().endpoint != crate::Endpoint::new(endpoint)?
            || self.host.namespace() != host
            || self.transport.namespace() != transport
            || self.data.namespace() != data
        {
            return Err(Error::InvalidAllocation);
        }
        if matches!(stage, Stage::Bootstrap | Stage::Ready) {
            self.host.verify_cooperation()?;
            self.data.verify_producer()?;
        }
        for a in [&mut self.host, &mut self.transport, &mut self.data] {
            if stage == Stage::Ready {
                a.verify_ready()?;
                continue;
            }
            if stage == Stage::Offline {
                a.verify_emergency()?;
                continue;
            }
            if a.stage() != stage
                || a.reconcile() != (Reconciliation::Matching, Reconciliation::Matching)
            {
                return Err(Error::Drifted);
            }
        }
        Ok(())
    }
    pub fn bootstrap(&mut self) -> Result<()> {
        let result = (|| {
            // All permits stay hidden behind full quarantine during staging.
            self.host.install_cooperation()?;
            self.host.install_bootstrap_permit()?;
            self.transport.install_bootstrap_permit()?;
            self.data.install_bootstrap_permit()?;
            // Data forwarding remains denied in BOTH offline and bootstrap.
            self.data.install_bootstrap()?;
            self.transport.install_bootstrap()?;
            self.host.install_bootstrap()
        })();
        if result.is_err() {
            self.offline()?;
        }
        result
    }
    /// Actual scoped transition; the guard still owns authenticated health,
    /// native structure and advertisement decisions. No wire ACK or bool can
    /// substitute for these retained native namespace/policy descriptors.
    pub fn ready(&mut self) -> Result<()> {
        let result = (|| {
            self.host.verify_cooperation()?;
            self.data.verify_producer()?;
            for actuator in [&mut self.host, &mut self.transport, &mut self.data] {
                if actuator.stage() != Stage::Bootstrap
                    || actuator.reconcile() != (Reconciliation::Matching, Reconciliation::Matching)
                {
                    return Err(Error::Drifted);
                }
            }
            // Full host quarantine closes the path before any permissive table
            // is staged. Publish the upstream transport last.
            self.offline()?;
            self.host.install_permit()?;
            self.transport.install_permit()?;
            self.data.install_permit()?;
            for actuator in [&mut self.host, &mut self.transport, &mut self.data] {
                actuator.verify_staged_ready()?;
            }
            self.data.verify_producer()?;
            self.host.verify_cooperation()?;
            self.data.release_quarantine()?;
            self.transport.release_quarantine()?;
            self.host.release_quarantine()?;
            for actuator in [&mut self.host, &mut self.transport, &mut self.data] {
                actuator.verify_ready()?;
            }
            self.host.verify_cooperation()?;
            self.data.verify_producer()
        })();
        if result.is_err() {
            self.offline()?;
        }
        result
    }
    pub fn cleanup_permits(&mut self) -> Result<()> {
        self.offline()?;
        self.host.cleanup_cooperation()?;
        let h = self.host.cleanup_permit();
        let d = self.data.cleanup_permit();
        let t = self.transport.cleanup_permit();
        h.and(d).and(t)
    }
    /// Validate narrowly owned cooperation before deleting ANY native links.
    pub fn verify_cooperation(&mut self) -> Result<()> {
        self.host.verify_cooperation()
    }
}
