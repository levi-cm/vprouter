//! Original published DATA/TRANSPORT custody for a NEW policy query.
//! This binding is not permission to mutate DATA: the fixed query's current
//! native receipt and the separately durable movement gate are still required.
use super::*;

pub(crate) struct Binding {
    public: PublicBinding,
    transport: Rc<kernel::fresh_transport_mount::Mounted>,
    operations: Vec<wireguard::History>,
}
impl Binding {
    pub(crate) fn verify(&self, server: &Server) -> Result<()> {
        server.verify_transport_mounted(&self.transport)?;
        let n = server.native.as_ref().ok_or(Error::Interrupted)?;
        n.require_creator()?;
        let shared = &n.transaction.shared;
        let j = shared.journal.borrow();
        let spec = self.data().request().spec();
        if self.public.creator != n.creator
            || !Rc::ptr_eq(&self.public.shared, shared)
            || self.public.member != n.history.member
            || self.public.member != spec.exit.exit_id
            || !same_allocation(&j.record.allocation, &spec.allocation)?
            || j.record.primary_exit_id != self.public.member
            || j.record.entries.len() != 1
            || shared.services.borrow().len() != 1
            || n.owner.record(&n.domains)? != self.public.owner
        {
            return Err(Error::OwnershipMismatch);
        }
        let e = &j.record.entries[0];
        let p = e.preparation.as_ref().ok_or(Error::OwnershipMismatch)?;
        p.validate(&j.record, e)?;
        if e.phase != Phase::Creating
            || e.terminal.is_some()
            || p.result.as_ref() != Some(&self.public.result)
            || p.wireguard.get(..4) != Some(self.operations.as_slice())
            || !(4..=5).contains(&p.wireguard.len())
            || self.operations.len() != 4
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn data(&self) -> &Rc<kernel::namespace_attachment::Mounted> {
        self.transport.request().original().request().data()
    }
    pub(crate) fn public_result(&self) -> [u8; 32] {
        self.public.public_result()
    }
    pub(crate) fn public(&self) -> &PublicBinding {
        &self.public
    }
    pub(crate) fn query_public_binding(&self) -> PublicBinding {
        PublicBinding {
            creator: self.public.creator,
            shared: self.public.shared.clone(),
            member: self.public.member.clone(),
            result: self.public.result.clone(),
            owner: self.public.owner.clone(),
        }
    }
    pub(crate) fn transport(&self) -> &Rc<kernel::fresh_transport_mount::Mounted> {
        &self.transport
    }
}

impl Server {
    pub(crate) fn bind_movement(
        &self,
        transport: Rc<kernel::fresh_transport_mount::Mounted>,
        previous: &[kernel::wireguard_role::Verified],
    ) -> Result<Rc<Binding>> {
        self.verify_transport_mounted(&transport)?;
        if previous.len() != 4 {
            return Err(Error::OwnershipMismatch);
        }
        for v in previous {
            v.bind_service(self)?;
            v.require_acknowledged()?;
        }
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let shared = &n.transaction.shared;
        let j = shared.journal.borrow();
        let p = j
            .record
            .entries
            .iter()
            .find(|e| e.exit_id == n.history.member)
            .and_then(|e| e.preparation.as_ref())
            .ok_or(Error::OwnershipMismatch)?;
        if p.wireguard.len() != previous.len() || p.movement_query.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        for (h, v) in p.wireguard.iter().zip(previous) {
            h.matches_receipt(v)?;
        }
        let value = Rc::new(Binding {
            public: PublicBinding {
                creator: n.creator,
                shared: shared.clone(),
                member: n.history.member.clone(),
                result: p.result.clone().ok_or(Error::OwnershipMismatch)?,
                owner: p.owner.clone(),
            },
            transport,
            operations: p.wireguard.clone(),
        });
        drop(j);
        let mut jobs = shared.native_jobs.borrow_mut();
        jobs.prune()?;
        let mut count = 0;
        for (member, receipt) in jobs.pending.values() {
            if member == &n.history.member {
                let mut known = value.data().matches_job(receipt)?
                    || value.transport.matches_job(receipt)?
                    || value.transport.request().original().matches_job(receipt)?;
                for v in previous {
                    known |= v.matches_job(receipt)?;
                }
                if !known {
                    return Err(Error::OwnershipMismatch);
                }
                count += 1;
            }
        }
        if count != 7 {
            return Err(Error::OwnershipMismatch);
        }
        drop(jobs);
        value.verify(self)?;
        Ok(value)
    }
}
