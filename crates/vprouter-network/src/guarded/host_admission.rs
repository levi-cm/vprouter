//! Admission compares an independently protected declaration with two original
//! ROUTE observations. Public metadata is never accepted as a completed read.
use super::*;
use std::{os::fd::BorrowedFd, rc::Rc};

pub struct PendingHostAdmission {
    creator: u32,
    observer: crate::RouteObserver,
    record: Rc<vprouter_core::allocation::AllocationRecord>,
    baseline: Snapshot,
    read: Option<crate::HostRead>,
    boot_end: f64,
    end: Instant,
    observations: u8,
    accepted_at: Option<f64>,
    failure: Option<Error>,
}
impl HostAuthority {
    /// Start two native reads against an authored complete baseline. The launch
    /// owner must retain its protected declaration and original owner context;
    /// this API does not learn a declaration from an observed host on drift.
    /// All validation precedes consuming the observer. No native transaction is
    /// sent until its returned owner has been stored and registered by launch.
    pub fn begin_declared(
        observer: &mut Option<crate::RouteObserver>,
        record: &vprouter_core::allocation::AllocationRecord,
        plan: &crate::Plan,
        declared: crate::HostObservation,
        expires_at: f64,
    ) -> Result<PendingHostAdmission> {
        let end = crate::secret_role::end_instant(expires_at)?;
        record
            .validate(&record.deployment_id, &[])
            .map_err(|_| Error::InvalidInput)?;
        declared.encode()?;
        let native = observer.as_ref().ok_or(Error::Foreign)?;
        let baseline = declared.snapshot();
        if native.namespace_identity() != declared.namespace
            || !record.exits.contains(&plan.allocation)
            || plan.alias
                != format!(
                    "vprouter-v2:{}:{}:{}",
                    record.deployment_id, record.generation, plan.allocation.exit_id
                )
            || baseline.links.iter().any(|l| {
                l.alias
                    .starts_with(&format!("vprouter-v2:{}:", record.deployment_id))
            })
        {
            return Err(Error::Foreign);
        }
        Ok(PendingHostAdmission {
            creator: std::process::id(),
            observer: observer.take().ok_or(Error::Foreign)?,
            record: Rc::new(record.clone()),
            baseline,
            read: None,
            boot_end: expires_at,
            end,
            observations: 0,
            accepted_at: None,
            failure: None,
        })
    }
}
impl PendingHostAdmission {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::Foreign);
        }
        Ok(())
    }
    fn check(&self) -> Result<()> {
        self.creator()?;
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now >= self.boot_end || Instant::now() >= self.end {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    /// Original descriptor inventory only; no exchange/read state is exposed.
    pub fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.creator()?;
        Ok(self.observer.descriptor())
    }
    /// Historical successful observation time. This does not renew the original
    /// window or prove that HOST is unchanged after the second read.
    pub fn accepted_at(&self) -> Result<f64> {
        self.creator()?;
        self.accepted_at.ok_or(Error::Interrupted)
    }
    pub fn poll(&mut self) -> Result<Option<HostAuthority>> {
        self.creator()?;
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.accepted_at.is_some() {
            return Err(Error::Foreign);
        }
        let result = (|| {
            self.check()?;
            if self.read.is_none() {
                self.read = Some(self.observer.start_host_read(self.boot_end)?);
            }
            let Some(observation) = self
                .observer
                .poll_host_read(self.read.as_mut().ok_or(Error::Interrupted)?)?
            else {
                self.check()?;
                return Ok(None);
            };
            if observation.namespace != self.observer.namespace_identity() {
                return Err(Error::Foreign);
            }
            exact(&observation.snapshot(), &self.baseline).map_err(|_| Error::HostDrift)?;
            self.check()?;
            self.observations += 1;
            if self.observations == 1 {
                self.read = Some(self.observer.start_host_read(self.boot_end)?);
                return Ok(None);
            }
            if self.observations != 2 {
                return Err(Error::Foreign);
            }
            let authority = HostAuthority {
                model: Rc::new(std::cell::RefCell::new(HostModel::new(
                    self.record.deployment_id.clone(),
                    self.record.generation,
                    self.observer.namespace_identity(),
                    self.baseline.clone(),
                ))),
                allowed: Rc::new(self.record.exits.clone()),
                record: self.record.clone(),
                creator: self.creator,
            };
            self.check()?;
            let at = vprouter_core::health::boot_seconds();
            if !at.is_finite() || at >= self.boot_end {
                return Err(Error::Deadline);
            }
            self.accepted_at = Some(at);
            Ok(Some(authority))
        })();
        if let Err(error) = result {
            self.failure = Some(error);
        }
        result
    }
}
