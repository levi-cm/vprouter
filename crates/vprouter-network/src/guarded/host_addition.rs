//! Exact HOST appearance window from an original fixed EXCL pair constructor.
//! No parsed-link or arbitrary-index constructor can create this plan.
use super::*;
use std::rc::Rc;

/// Deterministic planned mutation data only. This neither reserves the index
/// nor admits any existing link. Both model and native collision checks remain
/// mandatory, including collisions with retained earlier generations.
pub fn planned_host_link_index(
    record: &vprouter_core::allocation::AllocationRecord,
    member: &str,
) -> Result<u32> {
    use sha2::Digest;
    if record.exits.iter().filter(|e| e.exit_id == member).count() != 1 {
        return Err(Error::Foreign);
    }
    let bytes = serde_json::to_vec(&("planned_original_host_link_index_v1", record, member))
        .map_err(|_| Error::InvalidInput)?;
    let hash = sha2::Sha256::digest(bytes);
    let word = u32::from_be_bytes(hash[..4].try_into().map_err(|_| Error::InvalidInput)?);
    const FIRST: u32 = 1_000_000;
    Ok(FIRST + word % (i32::MAX as u32 - FIRST + 1))
}

#[cfg(test)]
#[test]
fn planned_index_binds_full_allocation_and_generation_without_reserving() {
    let (mut record, _) = crate::tests::fixture();
    let member = record.exits[0].exit_id.clone();
    let original = planned_host_link_index(&record, &member).unwrap();
    assert!((1_000_000..=i32::MAX as u32).contains(&original));
    assert_eq!(planned_host_link_index(&record, &member).unwrap(), original);
    record.generation += 1;
    assert_ne!(planned_host_link_index(&record, &member).unwrap(), original);
    record.generation -= 1;
    record.exits[0].state_dir.push("other");
    assert_ne!(planned_host_link_index(&record, &member).unwrap(), original);
    assert!(planned_host_link_index(&record, "foreign").is_err());
    record.exits.push(record.exits[0].clone());
    assert!(planned_host_link_index(&record, &member).is_err());
}

pub struct HostAdditionPlan {
    creator: u32,
    model: Rc<std::cell::RefCell<HostModel>>,
    record: Rc<vprouter_core::allocation::AllocationRecord>,
    pair_origin: Rc<()>,
    owner: String,
    source_namespace: (u64, u64),
    original_host: Link,
    original_peer: Link,
    addition: Snapshot,
    revision: u64,
    active_revision: Option<u64>,
    intent: Vec<u8>,
    finished: bool,
}
impl HostAuthority {
    pub fn prepare_addition(
        &self,
        record: &vprouter_core::allocation::AllocationRecord,
        member: &str,
        created: &crate::VerifiedVethCreation,
    ) -> Result<HostAdditionPlan> {
        if self.creator != std::process::id()
            || self.record.schema_version != record.schema_version
            || self.record.deployment_id != record.deployment_id
            || self.record.generation != record.generation
            || self.record.exits != record.exits
        {
            return Err(Error::Foreign);
        }
        let ordinal = record
            .exits
            .iter()
            .position(|e| e.exit_id == member)
            .ok_or(Error::Foreign)?;
        let allocation = &record.exits[ordinal];
        let index = planned_host_link_index(record, member)?;
        i32::try_from(index).map_err(|_| Error::InvalidInput)?;
        let (pair, origin) = created.original_pair()?;
        let model = self.model.try_borrow().map_err(|_| Error::Interrupted)?;
        let owner = format!(
            "vprouter-v2:{}:{}:{}",
            record.deployment_id, record.generation, member
        );
        if pair.host.namespace != pair.transport.namespace
            || pair.host.namespace == model.namespace
            || pair.host.name() != allocation.host_interface
            || pair.transport.name() != allocation.data_interface
            || pair.host.link.alias != owner
            || pair.transport.link.alias != owner
            || pair.host.link.kind != "veth"
            || pair.transport.link.kind != "veth"
            || pair.host.link.up
            || pair.transport.link.up
            || pair.host.link.peer_index != Some(pair.transport.index())
            || pair.transport.link.peer_index != Some(pair.host.index())
            || model.adding.is_some()
            || model.removing.is_some()
            || model.members.contains_key(&owner)
        {
            return Err(Error::Foreign);
        }
        let before = model.expected(None, None);
        if before
            .links
            .iter()
            .any(|l| l.index == index || l.name == allocation.host_interface)
        {
            return Err(Error::Foreign);
        }
        let mut projected = pair.host.link.clone();
        projected.index = index;
        let addition = Snapshot {
            links: vec![projected],
            ..Snapshot::default()
        };
        let after = model.expected(None, Some(&addition));
        let before_bytes =
            crate::HostObservation::from_snapshot(model.namespace, before).encode()?;
        let after_bytes = crate::HostObservation::from_snapshot(model.namespace, after).encode()?;
        let intent = serde_json::to_vec(&(
            "original_down_pair_host_addition_v1",
            record,
            &owner,
            model.namespace,
            pair.host.namespace,
            &pair.host.link,
            &pair.transport.link,
            index,
            model.revision,
            before_bytes,
            after_bytes,
        ))
        .map_err(|_| Error::InvalidInput)?;
        Ok(HostAdditionPlan {
            creator: self.creator,
            model: self.model.clone(),
            record: self.record.clone(),
            pair_origin: origin.clone(),
            owner,
            source_namespace: pair.host.namespace,
            original_host: pair.host.link.clone(),
            original_peer: pair.transport.link.clone(),
            addition,
            revision: model.revision,
            active_revision: None,
            intent,
            finished: false,
        })
    }
}
impl HostAdditionPlan {
    pub fn intent_bytes(&self) -> Result<&[u8]> {
        if self.creator != std::process::id() {
            return Err(Error::Foreign);
        }
        Ok(&self.intent)
    }
    pub fn bind(
        &self,
        record: &vprouter_core::allocation::AllocationRecord,
        member: &str,
        host: (u64, u64),
        created: &crate::VerifiedVethCreation,
    ) -> Result<()> {
        let (pair, origin) = created.original_pair()?;
        if self.creator != std::process::id()
            || !Rc::ptr_eq(origin, &self.pair_origin)
            || self.record.schema_version != record.schema_version
            || self.record.deployment_id != record.deployment_id
            || self.record.generation != record.generation
            || self.record.exits != record.exits
            || self.owner
                != format!(
                    "vprouter-v2:{}:{}:{}",
                    record.deployment_id, record.generation, member
                )
            || self
                .model
                .try_borrow()
                .map_err(|_| Error::Interrupted)?
                .namespace
                != host
            || pair.host.namespace != self.source_namespace
            || pair.host.link != self.original_host
            || pair.transport.link != self.original_peer
        {
            return Err(Error::Foreign);
        }
        Ok(())
    }
    /// Launch calls this after the exact addition Intent is durable. It changes
    /// the monitor envelope, never a kernel link, placement or traffic permit.
    pub fn activate(&mut self) -> Result<()> {
        if self.creator != std::process::id() || self.active_revision.is_some() || self.finished {
            return Err(Error::Foreign);
        }
        let mut model = self
            .model
            .try_borrow_mut()
            .map_err(|_| Error::Interrupted)?;
        if model.revision != self.revision {
            return Err(Error::Foreign);
        }
        self.active_revision = Some(model.begin_addition(&self.owner, &self.addition)?);
        Ok(())
    }
    /// Planned public mutation data, not reservation or release authority.
    pub fn planned_index(&self) -> Result<u32> {
        if self.creator != std::process::id() {
            return Err(Error::Foreign);
        }
        Ok(self.addition.links[0].index)
    }
    pub fn target_index(&self) -> Result<u32> {
        if self.creator != std::process::id() || self.finished {
            return Err(Error::Foreign);
        }
        let model = self.model.try_borrow().map_err(|_| Error::Interrupted)?;
        if self.active_revision != Some(model.revision)
            || model.adding.as_ref() != Some(&(self.owner.clone(), self.addition.clone()))
        {
            return Err(Error::Foreign);
        }
        Ok(self.addition.links[0].index)
    }
    pub(crate) fn fixed_observations(
        &self,
        created: &crate::VerifiedVethCreation,
    ) -> Result<(crate::HostObservation, crate::HostObservation)> {
        let (_, origin) = created.original_pair()?;
        self.target_index()?;
        if !Rc::ptr_eq(origin, &self.pair_origin) {
            return Err(Error::Foreign);
        }
        let model = self.model.try_borrow().map_err(|_| Error::Interrupted)?;
        Ok((
            crate::HostObservation::from_snapshot(model.namespace, model.expected(None, None)),
            crate::HostObservation::from_snapshot(
                model.namespace,
                model.expected(None, Some(&self.addition)),
            ),
        ))
    }
    // Completion is crate-private: the same original fixed move must supply the
    // verified result; public metadata cannot independently commit membership.
    pub(crate) fn finish_original(
        &mut self,
        origin: &Rc<()>,
        actual: &crate::HostObservation,
    ) -> Result<()> {
        if self.creator != std::process::id()
            || !Rc::ptr_eq(origin, &self.pair_origin)
            || self.finished
        {
            return Err(Error::Foreign);
        }
        let mut model = self
            .model
            .try_borrow_mut()
            .map_err(|_| Error::Interrupted)?;
        if actual.namespace != model.namespace {
            return Err(Error::Foreign);
        }
        model.finish_addition(
            &self.owner,
            self.active_revision.ok_or(Error::Foreign)?,
            &actual.snapshot(),
        )?;
        self.finished = true;
        Ok(())
    }
}
