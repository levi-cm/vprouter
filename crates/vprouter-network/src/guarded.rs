//! Exact native activation behind retained independently verified quarantine.
mod host_addition;
mod host_admission;
use crate::{
    Address, DownLink, Error, Link, NativeNetwork, Result, Route, Rule, Snapshot, VethPair,
    audit::{expected_rules, same},
    socket::{Completion, deadline},
};
pub use host_addition::{HostAdditionPlan, planned_host_link_index};
pub use host_admission::PendingHostAdmission;
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage as N,
    address::{AddressAttribute, AddressMessage},
    link::{AfSpecInet6, AfSpecUnspec, In6AddrGenMode, LinkAttribute, LinkFlags, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};
use vprouter_netfilter::{Enforcement, Stage};

/// One shared host authority for an entire allocation generation. The declared
/// baseline is supplied by protected deployment policy, never learned on drift.
/// Clones share the same model; individual exits cannot freeze their neighbors.
#[derive(Clone)]
pub struct HostAuthority {
    model: std::rc::Rc<std::cell::RefCell<HostModel>>,
    allowed: std::rc::Rc<Vec<vprouter_core::allocation::ExitAllocation>>,
    record: std::rc::Rc<vprouter_core::allocation::AllocationRecord>,
    creator: u32,
}
pub struct HostAuditTicket {
    model: std::rc::Rc<std::cell::RefCell<HostModel>>,
    creator: u32,
    id: u64,
    sent_at: f64,
    active: bool,
}
impl HostAuditTicket {
    /// Retires this read window without accepting a native observation. Launch
    /// calls it after cancelled IO actually reaps, retaining its original frame.
    pub fn retire(&mut self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::Foreign);
        }
        if self.active {
            self.model
                .try_borrow_mut()
                .map_err(|_| Error::Interrupted)?
                .reads
                .remove(&self.id)
                .ok_or(Error::Foreign)?;
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for HostAuditTicket {
    fn drop(&mut self) {
        if self.creator == std::process::id() {
            let _ = self.retire();
        }
    }
}
const MAX_HOST_READS: usize = 64;
const MAX_HOST_READ_HISTORY: usize = 64;
struct HostReadWindow {
    owner: String,
    selected: Snapshot,
    revisions: std::collections::BTreeSet<u64>,
    shapes: Vec<std::rc::Rc<HostReadShape>>,
}
/// A single protected model plus, during one declared removal, an explicit
/// bounded disappearance envelope of the original B link/address/three routes.
/// It never combines fields from different allocations or arbitrary observations.
struct HostReadShape {
    survivors: Snapshot,
    disappearing: Option<Snapshot>,
    appearing: Option<Link>,
}
impl HostModel {
    fn begin_addition(&mut self, owner: &str, delta: &Snapshot) -> Result<u64> {
        self.owner(owner)?;
        if self.adding.is_some()
            || self.removing.is_some()
            || self.members.contains_key(owner)
            || delta.links.len() != 1
            || !delta.addresses.is_empty()
            || !delta.routes.is_empty()
            || !delta.rules.is_empty()
            || delta.wireguard.is_some()
        {
            return Err(Error::Foreign);
        }
        let link = &delta.links[0];
        let before = self.expected(None, None);
        if link.index == 0
            || link.alias != owner
            || link.kind != "veth"
            || link.up
            || link.peer_index.is_none_or(|index| index == 0)
            || before
                .links
                .iter()
                .any(|l| l.index == link.index || l.name == link.name)
        {
            return Err(Error::Foreign);
        }
        crate::HostObservation::from_snapshot(self.namespace, self.expected(None, Some(delta)))
            .encode()?;
        let revision = self.revision.checked_add(1).ok_or(Error::Interrupted)?;
        let shape = std::rc::Rc::new(HostReadShape {
            survivors: before,
            disappearing: None,
            appearing: Some(link.clone()),
        });
        self.publish_read_shape(revision, owner, shape.clone())?;
        self.adding = Some((owner.into(), delta.clone()));
        self.revision = revision;
        self.current_read = Some(shape);
        Ok(revision)
    }
    fn finish_addition(&mut self, owner: &str, revision: u64, actual: &Snapshot) -> Result<()> {
        let (original_owner, delta) = self.adding.as_ref().ok_or(Error::Foreign)?;
        if original_owner != owner
            || revision != self.revision
            || self.removing.is_some()
            || self.members.contains_key(owner)
        {
            return Err(Error::Foreign);
        }
        let final_shape = self.expected(None, Some(delta));
        exact(actual, &final_shape).map_err(|_| Error::HostDrift)?;
        let delta = delta.clone();
        let revision = self.revision.checked_add(1).ok_or(Error::Interrupted)?;
        let shape = std::rc::Rc::new(HostReadShape {
            survivors: final_shape,
            disappearing: None,
            appearing: None,
        });
        self.publish_read_shape(revision, owner, shape.clone())?;
        self.revision = revision;
        self.current_read = Some(shape);
        self.members.insert(owner.into(), delta);
        self.adding = None;
        Ok(())
    }
}
impl HostReadShape {
    fn accepts(&self, actual: &Snapshot) -> Result<()> {
        let mut rest = actual.clone();
        if self.disappearing.is_some() && self.appearing.is_some() {
            return Err(Error::HostDrift);
        }
        if let Some(original) = &self.appearing
            && let Some(index) = rest.links.iter().position(|link| link == original)
        {
            // Exactly absent or present once. No new address/route/rule, changed
            // field, duplicate endpoint or loss of any survivor is admitted.
            rest.links.remove(index);
        }
        if let Some(b) = &self.disappearing {
            fn subtract<T: PartialEq>(actual: &mut Vec<T>, original: &[T]) {
                for value in original {
                    if let Some(index) = actual.iter().position(|v| v == value) {
                        actual.remove(index);
                    }
                }
            }
            subtract(&mut rest.links, &b.links);
            subtract(&mut rest.addresses, &b.addresses);
            subtract(&mut rest.routes, &b.routes);
            // No rule changes, field changes, duplicate records, additions or
            // neighbor removals are in this explicit <=32-state read envelope.
        }
        exact(&rest, &self.survivors).map_err(|_| Error::HostDrift)
    }
}
/// Prepared exclusively from the canonical declared model and retained owned
/// ActiveLinks. No Deserialize/adoption constructor. Launch persists its exact
/// intent before activate(), and mutates native resources only after activation.
pub struct HostRemovalPlan {
    creator: u32,
    record: std::rc::Rc<vprouter_core::allocation::AllocationRecord>,
    model: std::rc::Rc<std::cell::RefCell<HostModel>>,
    owner: String,
    revision: u64,
    original: Snapshot,
    intent: Vec<u8>,
    active_revision: Option<u64>,
    finished: bool,
}
/// Immutable native-operation expectation captured from an activated declared
/// transition. It carries no canonical model or journal mutation authority.
pub struct NativeRemovalPlan {
    namespace: (u64, u64),
    owner: String,
    before: Snapshot,
    after: Snapshot,
}
impl HostRemovalPlan {
    pub fn bind(
        &self,
        record: &vprouter_core::allocation::AllocationRecord,
        exit: &str,
        namespace: (u64, u64),
    ) -> Result<()> {
        if self.creator != std::process::id()
            || self.record.schema_version != record.schema_version
            || self.record.deployment_id != record.deployment_id
            || self.record.generation != record.generation
            || self.record.exits != record.exits
            || self.owner
                != format!(
                    "vprouter-v2:{}:{}:{}",
                    record.deployment_id, record.generation, exit
                )
            || self
                .model
                .try_borrow()
                .map_err(|_| Error::Interrupted)?
                .namespace
                != namespace
        {
            return Err(Error::Foreign);
        }
        Ok(())
    }
    pub fn intent_bytes(&self) -> Result<&[u8]> {
        if self.creator != std::process::id() {
            return Err(Error::Foreign);
        }
        Ok(&self.intent)
    }
    pub fn activate(&mut self) -> Result<()> {
        if self.creator != std::process::id() || self.active_revision.is_some() || self.finished {
            return Err(Error::Foreign);
        }
        let mut model = self
            .model
            .try_borrow_mut()
            .map_err(|_| Error::Interrupted)?;
        if model.revision != self.revision
            || model.removing.is_some()
            || model.adding.is_some()
            || model.members.get(&self.owner) != Some(&self.original)
        {
            return Err(Error::Foreign);
        }
        let shape = std::rc::Rc::new(HostReadShape {
            survivors: model.expected(Some(&self.owner), None),
            disappearing: Some(self.original.clone()),
            appearing: None,
        });
        let revision = model.revision.checked_add(1).ok_or(Error::Interrupted)?;
        model.publish_read_shape(revision, &self.owner, shape.clone())?;
        model.revision = revision;
        model.current_read = Some(shape);
        model.removing = Some(self.owner.clone());
        self.active_revision = Some(revision);
        Ok(())
    }
    pub fn native_plan(&self) -> Result<NativeRemovalPlan> {
        if self.creator != std::process::id() || self.finished {
            return Err(Error::Foreign);
        }
        let model = self.model.try_borrow().map_err(|_| Error::Interrupted)?;
        if self.active_revision != Some(model.revision)
            || model.removing.as_deref() != Some(self.owner.as_str())
            || model.members.get(&self.owner) != Some(&self.original)
        {
            return Err(Error::Foreign);
        }
        Ok(NativeRemovalPlan {
            namespace: model.namespace,
            owner: self.owner.clone(),
            before: model.expected(None, None),
            after: model.expected(Some(&self.owner), None),
        })
    }
    pub fn finish(&mut self, observation: &crate::HostObservation) -> Result<()> {
        if self.creator != std::process::id() || self.finished {
            return Err(Error::Foreign);
        }
        observation.validate()?;
        let mut model = self
            .model
            .try_borrow_mut()
            .map_err(|_| Error::Interrupted)?;
        if self.active_revision != Some(model.revision)
            || model.removing.as_deref() != Some(self.owner.as_str())
            || model.namespace != observation.namespace
            || model.members.get(&self.owner) != Some(&self.original)
        {
            return Err(Error::Foreign);
        }
        let final_shape = model.expected(Some(&self.owner), None);
        exact(&observation.snapshot(), &final_shape).map_err(|_| Error::HostDrift)?;
        let shape = std::rc::Rc::new(HostReadShape {
            survivors: final_shape,
            disappearing: None,
            appearing: None,
        });
        let revision = model.revision.checked_add(1).ok_or(Error::Interrupted)?;
        model.publish_read_shape(revision, &self.owner, shape.clone())?;
        model.revision = revision;
        model.members.remove(&self.owner);
        model.removing = None;
        model.current_read = Some(shape);
        self.finished = true;
        Ok(())
    }
}
fn original_host_window(sent_at: f64) -> Result<()> {
    let now = vprouter_core::health::boot_seconds();
    if !sent_at.is_finite()
        || !now.is_finite()
        || sent_at <= 0.
        || now < sent_at
        || now >= sent_at + 2.
    {
        return Err(Error::Interrupted);
    }
    Ok(())
}
struct HostModel {
    revision: u64,
    next_read: u64,
    reads: std::collections::BTreeMap<u64, HostReadWindow>,
    current_read: Option<std::rc::Rc<HostReadShape>>,
    removing: Option<String>,
    adding: Option<(String, Snapshot)>,
    deployment: String,
    generation: u64,
    namespace: (u64, u64),
    baseline: Snapshot,
    members: std::collections::BTreeMap<String, Snapshot>,
}
impl HostModel {
    fn new(deployment: String, generation: u64, namespace: (u64, u64), baseline: Snapshot) -> Self {
        Self {
            revision: 0,
            next_read: 0,
            reads: Default::default(),
            current_read: None,
            removing: None,
            adding: None,
            deployment,
            generation,
            namespace,
            baseline,
            members: Default::default(),
        }
    }
    fn publish_read_shape(
        &mut self,
        revision: u64,
        removing: &str,
        shape: std::rc::Rc<HostReadShape>,
    ) -> Result<()> {
        for read in self.reads.values().filter(|r| r.owner != removing) {
            if self.members.get(&read.owner) != Some(&read.selected)
                || !read.revisions.contains(&self.revision)
                || read.shapes.len() >= MAX_HOST_READ_HISTORY
                || read.revisions.len() >= MAX_HOST_READ_HISTORY
            {
                return Err(Error::Interrupted);
            }
        }
        for read in self.reads.values_mut().filter(|r| r.owner != removing) {
            read.revisions.insert(revision);
            read.shapes.push(shape.clone());
        }
        Ok(())
    }
    fn read_shape(&mut self) -> std::rc::Rc<HostReadShape> {
        if let Some(shape) = &self.current_read {
            return shape.clone();
        }
        let shape = std::rc::Rc::new(HostReadShape {
            survivors: self.expected(None, None),
            disappearing: None,
            appearing: None,
        });
        self.current_read = Some(shape.clone());
        shape
    }
    fn owner(&self, owner: &str) -> Result<()> {
        let prefix = format!("vprouter-v2:{}:{}:", self.deployment, self.generation);
        let id = owner.strip_prefix(&prefix).ok_or(Error::Foreign)?;
        if id.is_empty()
            || id.len() > 32
            || !id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err(Error::Foreign);
        }
        Ok(())
    }
    fn expected(&self, omit: Option<&str>, addition: Option<&Snapshot>) -> Snapshot {
        let mut result = self.baseline.clone();
        for delta in self
            .members
            .iter()
            .filter(|(key, _)| Some(key.as_str()) != omit)
            .map(|(_, v)| v)
            .chain(addition)
        {
            result.links.extend(delta.links.clone());
            result.addresses.extend(delta.addresses.clone());
            result.routes.extend(delta.routes.clone());
            result.rules.extend(delta.rules.clone());
        }
        result
    }
    fn audit_member(&self, owner: &str, actual: &Snapshot) -> Result<()> {
        self.owner(owner)?;
        if !self.members.contains_key(owner) {
            return Err(Error::Foreign);
        }
        exact(actual, &self.expected(None, None)).map_err(|_| Error::HostDrift)
    }
    fn add(&mut self, owner: &str, delta: Snapshot, actual: &Snapshot) -> Result<()> {
        self.owner(owner)?;
        if self.removing.is_some()
            || self.adding.is_some()
            || self.members.contains_key(owner)
            || delta.links.len() != 1
            || !delta.rules.is_empty()
            || delta.wireguard.is_some()
        {
            return Err(Error::Foreign);
        }
        let link = &delta.links[0];
        if link.index == 0
            || link.alias != owner
            || self
                .expected(None, None)
                .links
                .iter()
                .any(|l| l.index == link.index || l.name == link.name)
            || delta.addresses.iter().any(|a| a.index != link.index)
            || delta.routes.iter().any(|r| r.output != link.index)
        {
            return Err(Error::Foreign);
        }
        let proposed = self.expected(None, Some(&delta));
        crate::HostObservation::from_snapshot(self.namespace, proposed.clone()).encode()?;
        exact(actual, &proposed).map_err(|_| Error::HostDrift)?;
        self.revision = self.revision.checked_add(1).ok_or(Error::Interrupted)?;
        self.current_read = None;
        self.members.insert(owner.into(), delta);
        Ok(())
    }
    fn remove(&mut self, owner: &str, actual: &Snapshot) -> Result<()> {
        self.owner(owner)?;
        if self.removing.is_some() || self.adding.is_some() || !self.members.contains_key(owner) {
            return Err(Error::Foreign);
        }
        exact(actual, &self.expected(Some(owner), None)).map_err(|_| Error::HostDrift)?;
        self.revision = self.revision.checked_add(1).ok_or(Error::Interrupted)?;
        self.members.remove(owner);
        self.current_read = None;
        Ok(())
    }
}
impl HostAuthority {
    /// The creator alone retains the canonical model; a fork copy is never an
    /// authority for observations or membership. Tickets do not authorize Ready.
    pub fn begin_audit(
        &self,
        record: &vprouter_core::allocation::AllocationRecord,
        exit: &str,
    ) -> Result<HostAuditTicket> {
        self.begin_audit_at(record, exit, vprouter_core::health::boot_seconds())
    }
    /// Original owner frame time, captured before any directory/lease/helper
    /// preparation. No model transition can renew the accepted read window.
    pub fn begin_audit_at(
        &self,
        record: &vprouter_core::allocation::AllocationRecord,
        exit: &str,
        sent_at: f64,
    ) -> Result<HostAuditTicket> {
        original_host_window(sent_at)?;
        if self.creator != std::process::id()
            || self.record.schema_version != record.schema_version
            || self.record.deployment_id != record.deployment_id
            || self.record.generation != record.generation
            || self.record.exits != record.exits
            || !record.exits.iter().any(|e| e.exit_id == exit)
        {
            return Err(Error::Foreign);
        }
        let mut model = self
            .model
            .try_borrow_mut()
            .map_err(|_| Error::Interrupted)?;
        let owner = format!(
            "vprouter-v2:{}:{}:{}",
            model.deployment, model.generation, exit
        );
        if model.removing.as_ref() == Some(&owner) || model.reads.len() >= MAX_HOST_READS {
            return Err(Error::Interrupted);
        }
        let selected = model.members.get(&owner).ok_or(Error::Foreign)?.clone();
        let id = model.next_read.checked_add(1).ok_or(Error::Interrupted)?;
        let shape = model.read_shape();
        let revision = model.revision;
        model.reads.insert(
            id,
            HostReadWindow {
                owner,
                selected,
                revisions: [revision].into(),
                shapes: vec![shape],
            },
        );
        model.next_read = id;
        Ok(HostAuditTicket {
            model: self.model.clone(),
            creator: self.creator,
            id,
            sent_at,
            active: true,
        })
    }
    /// Native receipt authentication remains the launch owner's responsibility.
    /// Only explicit canonical B-only transition history extends accepted shape
    /// metadata; the native observation and original2s window remain fresh.
    pub fn complete_audit(
        &self,
        ticket: &HostAuditTicket,
        observation: &crate::HostObservation,
    ) -> Result<()> {
        original_host_window(ticket.sent_at)?;
        observation.validate()?;
        if self.creator != std::process::id()
            || ticket.creator != self.creator
            || !ticket.active
            || !std::rc::Rc::ptr_eq(&self.model, &ticket.model)
        {
            return Err(Error::Foreign);
        }
        let model = self.model.try_borrow().map_err(|_| Error::Interrupted)?;
        let read = model.reads.get(&ticket.id).ok_or(Error::Foreign)?;
        if model.namespace != observation.namespace
            || !read.revisions.contains(&model.revision)
            || model.members.get(&read.owner) != Some(&read.selected)
        {
            return Err(Error::NamespaceUnverified);
        }
        let actual = observation.snapshot();
        if !read
            .shapes
            .iter()
            .any(|shape| shape.accepts(&actual).is_ok())
        {
            return Err(Error::HostDrift);
        }
        original_host_window(ticket.sent_at)
    }
    fn prepare_removal(&self, owner: &str, original: &Snapshot) -> Result<HostRemovalPlan> {
        if self.creator != std::process::id() {
            return Err(Error::Foreign);
        }
        let model = self.model.try_borrow().map_err(|_| Error::Interrupted)?;
        model.owner(owner)?;
        if model.removing.is_some()
            || model.adding.is_some()
            || model.members.get(owner) != Some(original)
            || original.links.len() != 1
            || original.addresses.len() > 1
            || original.routes.len() > 3
            || !original.rules.is_empty()
            || original.wireguard.is_some()
        {
            return Err(Error::Foreign);
        }
        let link = &original.links[0];
        if link.alias != owner
            || original.addresses.iter().any(|a| a.index != link.index)
            || original.routes.iter().any(|r| r.output != link.index)
        {
            return Err(Error::Foreign);
        }
        let before =
            crate::HostObservation::from_snapshot(model.namespace, model.expected(None, None))
                .encode()?;
        let disappearing =
            crate::HostObservation::from_snapshot(model.namespace, original.clone()).encode()?;
        let count = original.links.len() + original.addresses.len() + original.routes.len();
        let masks: Vec<u8> = (0..(1u8 << count)).collect();
        let intent = serde_json::to_vec(&(
            "vprouter-host-removal-v1",
            &*self.record,
            model.revision,
            model.namespace,
            owner,
            before,
            disappearing,
            ["links", "addresses", "routes", "rules"],
            masks,
        ))
        .map_err(|_| Error::InvalidInput)?;
        Ok(HostRemovalPlan {
            creator: self.creator,
            record: self.record.clone(),
            model: self.model.clone(),
            owner: owner.into(),
            revision: model.revision,
            original: original.clone(),
            intent,
            active_revision: None,
            finished: false,
        })
    }

    /// Admission requires a predeclared complete host shape, exact allocation
    /// generation and two matching native observations. Dynamic unrelated host
    /// resources require an explicit new deployment declaration while offline.
    pub fn admit_declared(
        host: &mut NativeNetwork,
        record: &vprouter_core::allocation::AllocationRecord,
        declared: Snapshot,
    ) -> Result<Self> {
        record
            .validate(&record.deployment_id, &[])
            .map_err(|_| Error::InvalidInput)?;
        let model = HostModel::new(
            record.deployment_id.clone(),
            record.generation,
            host.namespace,
            declared,
        );
        model.owner(host.plan.ownership_alias())?;
        crate::HostObservation::from_snapshot(model.namespace, model.baseline.clone()).encode()?;
        if !record.exits.contains(&host.plan.allocation)
            || model.baseline.links.iter().any(|l| {
                l.alias
                    .starts_with(&format!("vprouter-v2:{}:", record.deployment_id))
            })
        {
            return Err(Error::Foreign);
        }
        exact(&host.observe()?, &model.baseline).map_err(|_| Error::HostDrift)?;
        exact(&host.observe()?, &model.baseline).map_err(|_| Error::HostDrift)?;
        Ok(Self {
            model: std::rc::Rc::new(std::cell::RefCell::new(model)),
            allowed: std::rc::Rc::new(record.exits.clone()),
            record: std::rc::Rc::new(record.clone()),
            creator: std::process::id(),
        })
    }
    fn bind(&self, host: &NativeNetwork) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::Foreign);
        }
        let model = self.model.try_borrow().map_err(|_| Error::Interrupted)?;
        model.owner(host.plan.ownership_alias())?;
        if !self.allowed.contains(&host.plan.allocation) {
            return Err(Error::Foreign);
        }
        if model.namespace != host.namespace {
            return Err(Error::NamespaceUnverified);
        }
        Ok(())
    }
    /// Revalidate the complete declared host model before allocating another exit.
    pub fn verify_current(&self, host: &mut NativeNetwork) -> Result<()> {
        self.bind(host)?;
        exact(
            &host.observe()?,
            &self
                .model
                .try_borrow()
                .map_err(|_| Error::Interrupted)?
                .expected(None, None),
        )
        .map_err(|_| Error::HostDrift)
    }
    fn audit(&self, host: &mut NativeNetwork) -> Result<()> {
        self.bind(host)?;
        let actual = host.observe()?;
        self.model
            .try_borrow()
            .map_err(|_| Error::Interrupted)?
            .audit_member(host.plan.ownership_alias(), &actual)
    }
}

/// Non-clonable retained indices and exact expected kernel shapes. Deliberately
/// no caller constructor, mutable fields, readiness or activation booleans.
pub struct ActiveLinks {
    wg: DownLink,
    pair: VethPair,
    host_authority: HostAuthority,
    transport_expected: Snapshot,
    data_expected: Snapshot,
}
/// Retained fixed daemon metadata, not process authorization or readiness.
/// Only native observations against an existing ActiveLinks can construct it.
/// Explicit public identity declaration, not observed route metadata or a
/// readiness capability. The guard must load it from protected configuration and
/// verify the live authenticated LocalAPI self identity before pinning metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonDeclaration {
    node_id: String,
    address: std::net::Ipv4Addr,
    peers: Vec<DaemonPeer>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonPeer {
    pub node_id: String,
    pub address: std::net::Ipv4Addr,
}
impl DaemonDeclaration {
    pub fn new(
        node_id: String,
        address: std::net::Ipv4Addr,
        peers: Vec<DaemonPeer>,
    ) -> Result<Self> {
        fn node(id: &str) -> bool {
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        }
        fn ip(ip: std::net::Ipv4Addr) -> bool {
            u32::from(ip) & 0xffc00000 == 0x64400000
                && ip != std::net::Ipv4Addr::new(100, 100, 100, 100)
        }
        if !node(&node_id) || !ip(address) || peers.len() > 256 {
            return Err(Error::InvalidInput);
        }
        let mut nodes = std::collections::HashSet::from([node_id.clone()]);
        let mut addresses = std::collections::HashSet::from([address]);
        for peer in &peers {
            if !node(&peer.node_id)
                || !ip(peer.address)
                || !nodes.insert(peer.node_id.clone())
                || !addresses.insert(peer.address)
            {
                return Err(Error::InvalidInput);
            }
        }
        Ok(Self {
            node_id,
            address,
            peers,
        })
    }
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
    pub fn address(&self) -> std::net::Ipv4Addr {
        self.address
    }
    pub fn peers(&self) -> &[DaemonPeer] {
        &self.peers
    }
}
pub struct DaemonLinks {
    namespace: (u64, u64),
    wg_index: u32,
    alias: String,
    tun: Link,
    declaration: Option<DaemonDeclaration>,
}
impl ActiveLinks {
    pub fn prepare_host_removal(&self) -> Result<HostRemovalPlan> {
        let authority = &self.host_authority;
        if authority.creator != std::process::id() {
            return Err(Error::Foreign);
        }
        let owner = &self.pair.host.link.alias;
        let model = authority
            .model
            .try_borrow()
            .map_err(|_| Error::Interrupted)?;
        let original = model.members.get(owner).ok_or(Error::Foreign)?.clone();
        if original.links.len() != 1
            || original.links[0].index != self.pair.host.index()
            || original.links[0].name != self.pair.host.link.name
        {
            return Err(Error::Foreign);
        }
        drop(model);
        authority.prepare_removal(owner, &original)
    }
    pub fn indices(&self) -> (u32, u32, u32) {
        (
            self.pair.host.index(),
            self.pair.transport.index(),
            self.wg.index(),
        )
    }
    fn bind(
        &self,
        host: &NativeNetwork,
        transport: &NativeNetwork,
        data: &NativeNetwork,
    ) -> Result<()> {
        if host.namespace != self.pair.host.namespace
            || transport.namespace != self.pair.transport.namespace
            || data.namespace != self.wg.namespace
            || host.plan != transport.plan
            || host.plan != data.plan
        {
            return Err(Error::NamespaceUnverified);
        }
        Ok(())
    }
    /// Audits every link/address/route/rule in data and transport, the whole host
    /// baseline plus owned additions, exact peer/key/endpoint and pinned indices.
    /// Handshake age is a later health condition, never required to start it.
    pub fn audit(
        &self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
    ) -> Result<()> {
        self.host_authority.audit(host)?;
        self.audit_namespaces(host, transport, data)
    }
    pub fn audit_daemon_metadata(
        &self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        daemon: &DaemonLinks,
    ) -> Result<()> {
        self.host_authority.audit(host)?;
        self.audit_daemon_namespaces(host, transport, data, daemon)
    }
    pub fn audit_daemon_health(
        &self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        daemon: &DaemonLinks,
    ) -> Result<(f64, f64)> {
        let checked_at = vprouter_core::health::boot_seconds();
        self.host_authority.audit(host)?;
        let (local_at, age) = self.audit_daemon_namespace_health(host, transport, data, daemon)?;
        Ok((checked_at.min(local_at), age))
    }
    // Namespace-only methods below intentionally do NOT prove a host audit or
    // readiness. The launch layer's private remote capability supplies that.
    pub fn audit_namespaces(
        &self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
    ) -> Result<()> {
        self.bind(host, transport, data)?;
        let t = transport.observe()?;
        let d = data.observe()?;
        exact(&t, &self.transport_expected).map_err(|_| Error::TransportDrift)?;
        exact(&d, &self.data_expected).map_err(|_| Error::DataDrift)?;
        data.configuration(self.wg.index(), deadline())?;
        data.plan.bootstrap_structure(&d, self.wg.index())
    }
    pub fn pin_daemon_metadata(
        &self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
    ) -> Result<DaemonLinks> {
        self.host_authority.audit(host)?;
        self.pin_daemon_namespaces(host, transport, data, None)
    }
    pub fn pin_operational_metadata(
        &self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        declaration: DaemonDeclaration,
    ) -> Result<DaemonLinks> {
        self.host_authority.audit(host)?;
        self.pin_daemon_namespaces(host, transport, data, Some(declaration))
    }
    pub fn pin_daemon_namespaces(
        &self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        declaration: Option<DaemonDeclaration>,
    ) -> Result<DaemonLinks> {
        self.bind(host, transport, data)?;
        exact(&transport.observe()?, &self.transport_expected)
            .map_err(|_| Error::TransportDrift)?;
        let first = data.observe()?;
        let tun = daemon_data_authorized(&first, &self.data_expected, None, declaration.as_ref())?;
        // Transitional DOWN or changing shapes cannot become the baseline.
        let second = data.observe()?;
        daemon_data_authorized(
            &second,
            &self.data_expected,
            Some(&tun),
            declaration.as_ref(),
        )?;
        data.configuration(self.wg.index(), deadline())?;
        Ok(DaemonLinks {
            namespace: data.namespace,
            wg_index: self.wg.index(),
            alias: self.wg.link.alias.clone(),
            tun,
            declaration,
        })
    }
    pub fn audit_daemon_namespaces(
        &self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        daemon: &DaemonLinks,
    ) -> Result<()> {
        self.bind(host, transport, data)?;
        if daemon.namespace != data.namespace
            || daemon.wg_index != self.wg.index()
            || daemon.alias != self.wg.link.alias
        {
            return Err(Error::NamespaceUnverified);
        }
        exact(&transport.observe()?, &self.transport_expected)
            .map_err(|_| Error::TransportDrift)?;
        daemon_data_authorized(
            &data.observe()?,
            &self.data_expected,
            Some(&daemon.tun),
            daemon.declaration.as_ref(),
        )?;
        data.configuration(self.wg.index(), deadline())
    }
    /// Fresh privileged native evidence; original check start remains the age
    /// anchor across all dumps and any later serialization/acknowledgement.
    pub fn audit_daemon_namespace_health(
        &self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        daemon: &DaemonLinks,
    ) -> Result<(f64, f64)> {
        let checked_at = vprouter_core::health::boot_seconds();
        self.audit_daemon_namespaces(host, transport, data, daemon)?;
        let wg = data.checked_wireguard(self.wg.index(), deadline())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Drifted)?
            .as_secs_f64();
        let handshake = wg
            .peers
            .first()
            .and_then(|peer| peer.handshake_unix)
            .ok_or(Error::Drifted)?;
        let age = now - handshake;
        if !handshake.is_finite()
            || handshake <= 0.
            || !age.is_finite()
            || !(0.0..180.).contains(&age)
        {
            return Err(Error::Drifted);
        }
        Ok((checked_at, age))
    }
    /// Fixed native half of consuming retirement. The caller retains original
    /// ownership and supplies its native no-producer fence before EACH deletion.
    /// This never changes the canonical HostModel; the parent commits the returned
    /// observation only after authenticating its exact native helper and reap.
    pub fn cleanup_native(
        &self,
        removal: &NativeRemovalPlan,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        enforcement: &mut Enforcement,
        native_fence: impl FnMut() -> Result<()>,
    ) -> Result<crate::HostObservation> {
        self.cleanup_native_inner(
            removal,
            host,
            transport,
            data,
            enforcement,
            native_fence,
            |_| {},
        )
    }
    /// Fixed scalar diagnostics only; no observations, sockets, or authority leave
    /// this operation. The ordinary entry uses a no-op observer.
    #[cfg(feature = "lab")]
    #[allow(clippy::too_many_arguments)]
    pub fn cleanup_native_profiled(
        &self,
        removal: &NativeRemovalPlan,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        enforcement: &mut Enforcement,
        native_fence: impl FnMut() -> Result<()>,
        phase: impl FnMut(u8),
    ) -> Result<crate::HostObservation> {
        self.cleanup_native_inner(
            removal,
            host,
            transport,
            data,
            enforcement,
            native_fence,
            phase,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn cleanup_native_inner(
        &self,
        removal: &NativeRemovalPlan,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        enforcement: &mut Enforcement,
        mut native_fence: impl FnMut() -> Result<()>,
        mut phase: impl FnMut(u8),
    ) -> Result<crate::HostObservation> {
        phase(1);
        self.bind(host, transport, data)?;
        phase(2);
        if removal.namespace != host.namespace
            || removal.owner != self.pair.host.link.alias
            || removal.owner != host.plan.ownership_alias()
        {
            return Err(Error::Foreign);
        }
        phase(3);
        native_fence()?;
        phase(4);
        enforcement.offline().map_err(|_| Error::Drifted)?;
        phase(5);
        enforcement
            .verify_cooperation()
            .map_err(|_| Error::Drifted)?;
        phase(6);
        let before = host.observe()?;
        phase(7);
        exact(&before, &removal.before).map_err(|_| Error::HostDrift)?;
        drop(before);
        phase(8);
        self.audit_namespaces(host, transport, data)?;
        phase(9);
        verify(enforcement, host, transport, data, Stage::Offline)?;
        let end = deadline();
        phase(10);
        native_fence()?;
        phase(11);
        data.delete_active(&self.wg, end)?;
        phase(12);
        native_fence()?;
        phase(13);
        host.delete_active(&self.pair.host, end)?;
        phase(14);
        host.absent(host.plan.host_name().to_owned().as_str(), end)?;
        phase(15);
        transport.absent(transport.plan.transport_name().to_owned().as_str(), end)?;
        phase(16);
        let after = host.observe()?;
        phase(17);
        exact(&after, &removal.after).map_err(|_| Error::HostDrift)?;
        phase(18);
        enforcement
            .cleanup_permits_with_fence(|| {
                native_fence().map_err(|_| vprouter_netfilter::Error::Drifted)
            })
            .map_err(|_| Error::Drifted)?;
        phase(19);
        native_fence()?;
        Ok(crate::HostObservation::from_snapshot(host.namespace, after))
    }
    /// Quarantine is enforced in every namespace BEFORE touching a link. Drift
    /// refuses all deletion, retaining full policy and the durable ownership intent.
    pub fn cleanup(
        self,
        host: &mut NativeNetwork,
        transport: &mut NativeNetwork,
        data: &mut NativeNetwork,
        enforcement: &mut Enforcement,
    ) -> Result<()> {
        enforcement.offline().map_err(|_| Error::Drifted)?;
        enforcement
            .verify_cooperation()
            .map_err(|_| Error::Drifted)?;
        self.audit(host, transport, data)?;
        verify(enforcement, host, transport, data, Stage::Offline)?;
        let end = deadline();
        // All shapes were checked before any deletion. Deleting exact owned
        // links removes only addresses/routes tied to those retained ifindices.
        data.delete_active(&self.wg, end)?;
        host.delete_active(&self.pair.host, end)?;
        host.absent(host.plan.host_name().to_owned().as_str(), end)?;
        transport.absent(transport.plan.transport_name().to_owned().as_str(), end)?;
        self.host_authority.bind(host)?;
        let after = host.observe()?;
        self.host_authority
            .model
            .try_borrow_mut()
            .map_err(|_| Error::Interrupted)?
            .remove(host.plan.ownership_alias(), &after)?;
        enforcement.cleanup_permits().map_err(|_| Error::Drifted)
    }
}
fn daemon_rules() -> Vec<Rule> {
    [(5210, 254, 1), (5230, 253, 1), (5250, 0, 7), (5270, 52, 1)]
        .into_iter()
        .map(|(priority, table, action)| Rule {
            priority,
            table,
            action,
            fwmark: (priority != 5270).then_some(0x80000),
            fwmask: (priority != 5270).then_some(0xff0000),
            protocol: Some(0),
            ..Rule::default()
        })
        .collect()
}
#[cfg(test)]
fn daemon_data(actual: &Snapshot, baseline: &Snapshot, retained: Option<&Link>) -> Result<Link> {
    daemon_data_authorized(actual, baseline, retained, None)
}
fn daemon_data_authorized(
    actual: &Snapshot,
    baseline: &Snapshot,
    retained: Option<&Link>,
    declaration: Option<&DaemonDeclaration>,
) -> Result<Link> {
    if baseline.addresses.iter().any(|a| a.address.is_ipv6())
        || baseline.routes.iter().any(|r| r.destination.is_ipv6())
        || baseline.links.iter().any(|l| l.name == "tailscale0")
    {
        return Err(Error::DataDrift);
    }
    let mut candidates = actual.links.iter().filter(|l| l.name == "tailscale0");
    let tun = candidates.next().ok_or(Error::DataDrift)?;
    crate::project::fixed_tun_info(&tun.tun_info).map_err(|_| Error::DataDrift)?;
    if candidates.next().is_some()
        || tun.index == 0
        || baseline.links.iter().any(|l| l.index == tun.index)
        || retained.is_some_and(|old| old != tun)
        || tun.kind != "tun"
        || tun.hardware_type != 65534
        || !tun.up
        || tun.mtu != 1280
        || !tun.alias.is_empty()
        || tun.peer_index.is_some()
        || tun.controller != 0
        || !tun.port_kind.is_empty()
        || tun.promiscuity != 0
        || tun.all_multicast != 0
        || !tun.alternate_names.is_empty()
    {
        return Err(Error::DataDrift);
    }
    // TUN NLAs are independently checked by the native projector. Everything
    // else is the pre-daemon baseline plus precisely four fixed IPv4 rules.
    let mut expected = baseline.clone();
    expected.links.push(tun.clone());
    expected.rules.extend(daemon_rules());
    if let Some(declaration) = declaration {
        expected.addresses.push(Address {
            broadcast: None,
            route_priority: None,
            flags: 128,
            index: tun.index,
            address: declaration.address.into(),
            prefix: 32,
            scope: 0,
        });
        expected.routes.push(local(declaration.address, tun.index));
        for address in declaration
            .peers
            .iter()
            .map(|p| p.address)
            .chain(std::iter::once(std::net::Ipv4Addr::new(100, 100, 100, 100)))
        {
            expected.routes.push(Route {
                nexthop_id: None,
                preference: 0,
                destination: address.into(),
                prefix: 32,
                table: 52,
                output: tun.index,
                source: None,
                gateway: None,
                kind: 1,
                scope: 0,
                protocol: 3,
                metric: 0,
                flags: 0,
            });
        }
    }
    exact(actual, &expected).map_err(|_| Error::DataDrift)?;
    Ok(tun.clone())
}

pub(crate) fn exact(actual: &Snapshot, expected: &Snapshot) -> Result<()> {
    if !same(&actual.links, &expected.links)
        || !same(&actual.addresses, &expected.addresses)
        || !same(&actual.routes, &expected.routes)
        || !same(&actual.rules, &expected.rules)
    {
        return Err(Error::Drifted);
    }
    // WireGuard handshake counters/timestamps can progress independently.
    Ok(())
}
fn verify(
    e: &mut Enforcement,
    h: &NativeNetwork,
    t: &NativeNetwork,
    d: &NativeNetwork,
    stage: Stage,
) -> Result<()> {
    e.verify(
        h.plan.ownership_alias(),
        h.plan.endpoint(),
        h.namespace,
        t.namespace,
        d.namespace,
        stage,
    )
    .map_err(|_| Error::Drifted)
}
impl NativeNetwork {
    pub fn namespace_identity(&self) -> (u64, u64) {
        self.namespace
    }
    /// Called by the independent guard only after durable activation intent.
    /// Every mutation is preceded by actual three-scope offline reconciliation.
    /// Any error restores full quarantine before returning, retaining resources.
    pub fn activate_quarantined(
        host: &mut Self,
        transport: &mut Self,
        data: &mut Self,
        pair: VethPair,
        wg: DownLink,
        enforcement: &mut Enforcement,
        authority: &HostAuthority,
    ) -> Result<ActiveLinks> {
        let result = (|| {
            verify(enforcement, host, transport, data, Stage::Offline)?;
            if host.plan != transport.plan
                || host.plan != data.plan
                || host.namespace != pair.host.namespace
                || transport.namespace != pair.transport.namespace
                || data.namespace != wg.namespace
                || pair.host.link.peer_index != Some(pair.transport.index())
                || pair.transport.link.peer_index != Some(pair.host.index())
            {
                return Err(Error::NamespaceUnverified);
            }
            let end = deadline();
            host.owned_down(&pair.host, end)?;
            transport.owned_down(&pair.transport, end)?;
            data.owned_down(&wg, end)?;
            data.configuration(wg.index(), end)?;
            let mut hb = host.observe()?;
            hb.links.retain(|l| l.index != pair.host.index());
            authority.bind(host)?;
            exact(
                &hb,
                &authority
                    .model
                    .try_borrow()
                    .map_err(|_| Error::Interrupted)?
                    .expected(None, None),
            )
            .map_err(|_| Error::HostDrift)?;
            let tb = transport.observe()?;
            let db = data.observe()?;
            let tl = pristine(&tb, &pair.transport.link)?;
            let dl = pristine(&db, &wg.link)?;
            let (hip, tip) = host.plan.transport_addresses();
            macro_rules! step {
                ($stage:literal,$op:expr) => {{
                    verify(enforcement, host, transport, data, Stage::Offline)?;
                    $op.map_err(|e| match e {
                        Error::KernelErrno(errno) => Error::ActivationKernel {
                            step: $stage,
                            errno,
                        },
                        other => other,
                    })?;
                }};
            }
            // Every usable operation is behind a fresh three-scope audit.
            step!(
                "host_ipv6_autoconf_none",
                host.no_ipv6_autoconf(pair.host.index(), end)
            );
            step!(
                "transport_ipv6_autoconf_none",
                transport.no_ipv6_autoconf(pair.transport.index(), end)
            );
            step!(
                "data_ipv6_autoconf_none",
                data.no_ipv6_autoconf(wg.index(), end)
            );
            step!(
                "host_address",
                host.add_address(pair.host.index(), hip, end)
            );
            step!(
                "transport_address",
                transport.add_address(pair.transport.index(), tip, end)
            );
            step!(
                "data_address",
                data.add_address(wg.index(), data.plan.address(), end)
            );
            step!("data_loopback_up", data.up(dl, end));
            step!("transport_loopback_up", transport.up(tl, end));
            step!("data_wg_up", data.up(wg.index(), end));
            step!(
                "transport_veth_up",
                transport.up(pair.transport.index(), end)
            );
            step!("host_veth_up", host.up(pair.host.index(), end));
            step!(
                "host_peer_route",
                host.add_route(tip, 32, pair.host.index(), Some(hip), None, end)
            );
            step!(
                "transport_host_route",
                transport.add_route(hip, 32, pair.transport.index(), Some(tip), None, end)
            );
            step!(
                "transport_endpoint_route",
                transport.add_route(
                    *transport.plan.endpoint().ip(),
                    32,
                    pair.transport.index(),
                    Some(tip),
                    Some(hip),
                    end
                )
            );
            step!(
                "data_default",
                data.add_route(
                    Ipv4Addr::UNSPECIFIED,
                    0,
                    wg.index(),
                    Some(data.plan.address()),
                    None,
                    end
                )
            );
            verify(enforcement, host, transport, data, Stage::Offline)?;
            let hs = host.observe()?;
            let ts = transport.observe()?;
            let ds = data.observe()?;
            data.plan.bootstrap_structure(&ds, wg.index())?;
            transport_shape(&ts, &transport.plan, &pair.transport.link, tl)?;
            host_shape(&hs, &hb, &pair.host.link, hip, tip)?;
            authority
                .model
                .try_borrow_mut()
                .map_err(|_| Error::Interrupted)?
                .add(
                    host.plan.ownership_alias(),
                    host_delta(&pair.host.link, hip, tip),
                    &hs,
                )?;
            Ok(ActiveLinks {
                wg,
                pair,
                host_authority: authority.clone(),
                transport_expected: ts,
                data_expected: ds,
            })
        })();
        if result.is_err() {
            enforcement.offline().map_err(|_| Error::Drifted)?;
        }
        result
    }
    fn no_ipv6_autoconf(&mut self, index: u32, end: Instant) -> Result<()> {
        let mut m = LinkMessage::default();
        m.header.index = index;
        m.attributes
            .push(LinkAttribute::AfSpecUnspec(vec![AfSpecUnspec::Inet6(
                vec![AfSpecInet6::AddrGenMode(In6AddrGenMode::None)],
            )]));
        self.link_mutation(N::SetLink(m), end)
    }
    fn add_address(&mut self, index: u32, ip: Ipv4Addr, end: Instant) -> Result<()> {
        let mut m = AddressMessage::default();
        m.header.family = AddressFamily::Inet;
        m.header.prefix_len = 32;
        m.header.index = index;
        m.attributes = vec![
            AddressAttribute::Address(ip.into()),
            AddressAttribute::Local(ip.into()),
        ];
        self.route
            .request(N::NewAddress(m), 0x600, 20, Completion::Ack, end)
            .map(|_| ())
    }
    fn add_route(
        &mut self,
        destination: Ipv4Addr,
        prefix: u8,
        output: u32,
        source: Option<Ipv4Addr>,
        gateway: Option<Ipv4Addr>,
        end: Instant,
    ) -> Result<()> {
        let mut m = RouteMessage::default();
        m.header.address_family = AddressFamily::Inet;
        m.header.destination_prefix_length = prefix;
        m.header.table = 254;
        m.header.protocol = RouteProtocol::Static;
        m.header.scope = if gateway.is_some() {
            RouteScope::Universe
        } else {
            RouteScope::Link
        };
        m.header.kind = RouteType::Unicast;
        m.attributes = vec![RouteAttribute::Oif(output)];
        if prefix != 0 {
            m.attributes
                .push(RouteAttribute::Destination(RouteAddress::Inet(destination)));
        }
        if let Some(s) = source {
            m.attributes
                .push(RouteAttribute::PrefSource(RouteAddress::Inet(s)));
        }
        if let Some(g) = gateway {
            m.attributes
                .push(RouteAttribute::Gateway(RouteAddress::Inet(g)));
        }
        self.route
            .request(N::NewRoute(m), 0x600, 24, Completion::Ack, end)
            .map(|_| ())
    }
    fn up(&mut self, index: u32, end: Instant) -> Result<()> {
        let mut m = LinkMessage::default();
        m.header.index = index;
        m.header.change_mask = LinkFlags::Up;
        m.header.flags = LinkFlags::Up;
        self.link_mutation(N::SetLink(m), end)
    }
    fn delete_active(&mut self, token: &DownLink, end: Instant) -> Result<()> {
        if self.namespace != token.namespace {
            return Err(Error::NamespaceUnverified);
        }
        let mut m = LinkMessage::default();
        m.header.index = token.index();
        self.link_mutation(N::DelLink(m), end)
    }
}
fn pristine(s: &Snapshot, resource: &Link) -> Result<u32> {
    let lo = s
        .links
        .iter()
        .find(|l| l.name == "lo")
        .ok_or(Error::Drifted)?;
    if s.links.len() != 2 || !lo.kind.is_empty() || lo.hardware_type != 772
        || !s.links.contains(resource)
        || s.addresses.iter().any(|a| a.broadcast.is_some() || a.route_priority.is_some() || a.flags & !0x80 != 0 || a.index!=lo.index || a.scope!=254
            || !matches!((a.address,a.prefix),(IpAddr::V4(ip),8) if ip==Ipv4Addr::LOCALHOST)
                && !matches!((a.address,a.prefix),(IpAddr::V6(ip),128) if ip==std::net::Ipv6Addr::LOCALHOST))
        || s.routes.iter().any(|r| r.output!=lo.index || r.table!=255 || r.protocol!=2)
        || !same(&s.rules, &expected_rules())
    { return Err(Error::Drifted); }
    Ok(lo.index)
}
fn own_route(
    destination: Ipv4Addr,
    prefix: u8,
    output: u32,
    source: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
) -> Route {
    Route {
        nexthop_id: None,
        preference: 0,
        destination: destination.into(),
        prefix,
        table: 254,
        output,
        source: Some(source.into()),
        gateway: gateway.map(IpAddr::V4),
        kind: 1,
        scope: if gateway.is_some() { 0 } else { 253 },
        protocol: 4,
        metric: 0,
        flags: 0,
    }
}
fn local(ip: Ipv4Addr, index: u32) -> Route {
    Route {
        nexthop_id: None,
        preference: 0,
        destination: ip.into(),
        prefix: 32,
        table: 255,
        output: index,
        source: Some(ip.into()),
        gateway: None,
        kind: 2,
        scope: 254,
        protocol: 2,
        metric: 0,
        flags: 0,
    }
}
fn multicast(index: u32) -> Route {
    Route {
        nexthop_id: None,
        preference: 0,
        destination: "ff00::".parse().expect("literal"),
        prefix: 8,
        table: 255,
        output: index,
        source: None,
        gateway: None,
        kind: 5,
        scope: 0,
        protocol: 2,
        metric: 256,
        flags: 0,
    }
}
fn transport_shape(s: &Snapshot, p: &crate::Plan, token: &Link, lo: u32) -> Result<()> {
    let mut expected_link = token.clone();
    expected_link.up = true;
    if s.links.iter().any(|l| {
        l.controller != 0
            || !l.port_kind.is_empty()
            || l.promiscuity != 0
            || l.all_multicast != 0
            || !l.alternate_names.is_empty()
    }) || s.links.len() != 2
        || !s.links.contains(&expected_link)
        || s.wireguard.is_some()
        || !same(&s.rules, &expected_rules())
    {
        return Err(Error::Drifted);
    }
    let (hip, tip) = p.transport_addresses();
    let mut expected = crate::audit::expected_routes(p, &s.addresses, lo, token.index);
    // Replace the data-only default with the exact transport host + endpoint routes.
    expected.retain(|r| !(r.table == 254 && r.prefix == 0));
    expected.push(own_route(hip, 32, token.index, tip, None));
    expected.push(own_route(
        *p.endpoint().ip(),
        32,
        token.index,
        tip,
        Some(hip),
    ));
    let valid_addresses = s.addresses.iter().all(|a| {
        a.index == lo
            && a.scope == 254
            && ((a.address == IpAddr::V4(Ipv4Addr::LOCALHOST) && a.prefix == 8)
                || (a.address == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST) && a.prefix == 128))
            || a == &Address {
                broadcast: None,
                route_priority: None,
                flags: 0x80,
                index: token.index,
                address: tip.into(),
                prefix: 32,
                scope: 0,
            }
    });
    if s.addresses
        .iter()
        .any(|a| a.broadcast.is_some() || a.route_priority.is_some() || a.flags & !0x80 != 0)
        || !valid_addresses
        || s.addresses
            .iter()
            .filter(|a| a.index == token.index)
            .count()
            != 1
        || !same(&s.routes, &expected)
    {
        return Err(Error::Drifted);
    }
    Ok(())
}
fn host_shape(
    s: &Snapshot,
    before: &Snapshot,
    token: &Link,
    hip: Ipv4Addr,
    tip: Ipv4Addr,
) -> Result<()> {
    let mut want = before.clone();
    let delta = host_delta(token, hip, tip);
    want.links.extend(delta.links);
    want.addresses.extend(delta.addresses);
    want.routes.extend(delta.routes);
    exact(s, &want)
}
fn host_delta(token: &Link, hip: Ipv4Addr, tip: Ipv4Addr) -> Snapshot {
    let mut link = token.clone();
    link.up = true;
    Snapshot {
        links: vec![link],
        addresses: vec![Address {
            broadcast: None,
            route_priority: None,
            flags: 0x80,
            index: token.index,
            address: hip.into(),
            prefix: 32,
            scope: 0,
        }],
        routes: vec![
            local(hip, token.index),
            own_route(tip, 32, token.index, hip, None),
            multicast(token.index),
        ],
        ..Snapshot::default()
    }
}

#[cfg(test)]
mod daemon_tests {
    #[test]
    fn enrolled_daemon_requires_declared_identity_and_exact_ipv4_deltas() {
        use super::*;
        let identity = DaemonDeclaration::new(
            "node-self".into(),
            "100.64.0.7".parse().unwrap(),
            vec![DaemonPeer {
                node_id: "node-client".into(),
                address: "100.64.0.8".parse().unwrap(),
            }],
        )
        .unwrap();
        let mut baseline = crate::tests::snapshot(&crate::tests::plan());
        baseline.routes.retain(|r| !r.destination.is_ipv6());
        let mut actual = baseline.clone();
        let mut tun = baseline.links[1].clone();
        tun.name = "tailscale0".into();
        tun.index = 9;
        tun.kind = "tun".into();
        tun.mtu = 1280;
        tun.alias.clear();
        tun.tun_info = [(3, 1), (4, 0), (5, 1), (6, 0), (7, 0)]
            .into_iter()
            .map(|(kind, value)| (kind, vec![value]))
            .collect();
        actual.links.push(tun.clone());
        actual.rules.extend(daemon_rules());
        actual.addresses.push(Address {
            broadcast: None,
            route_priority: None,
            flags: 128,
            index: 9,
            address: "100.64.0.7".parse().unwrap(),
            prefix: 32,
            scope: 0,
        });
        actual.routes.push(Route {
            nexthop_id: None,
            preference: 0,
            destination: "100.64.0.7".parse().unwrap(),
            prefix: 32,
            table: 255,
            output: 9,
            source: Some("100.64.0.7".parse().unwrap()),
            gateway: None,
            kind: 2,
            scope: 254,
            protocol: 2,
            metric: 0,
            flags: 0,
        });
        for dst in ["100.64.0.8", "100.100.100.100"] {
            actual.routes.push(Route {
                nexthop_id: None,
                preference: 0,
                destination: dst.parse().unwrap(),
                prefix: 32,
                table: 52,
                output: 9,
                source: None,
                gateway: None,
                kind: 1,
                scope: 0,
                protocol: 3,
                metric: 0,
                flags: 0,
            });
        }
        assert!(daemon_data_authorized(&actual, &baseline, None, Some(&identity)).is_ok());
        assert!(daemon_data(&actual, &baseline, None).is_err()); // observer stays unenrolled
        for field in 0..9 {
            let mut drift = actual.clone();
            match field {
                0 => drift.addresses.last_mut().unwrap().address = "100.64.0.9".parse().unwrap(),
                1 => drift.routes.last_mut().unwrap().destination = "100.64.0.9".parse().unwrap(),
                2 => drift.routes.last_mut().unwrap().prefix = 10,
                3 => drift.routes.last_mut().unwrap().table = 254,
                4 => drift.routes.last_mut().unwrap().output = 1,
                5 => drift.routes.last_mut().unwrap().protocol = 4,
                6 => drift.routes.last_mut().unwrap().gateway = Some("100.64.0.8".parse().unwrap()),
                7 => drift.routes.push(drift.routes.last().unwrap().clone()),
                _ => drift.rules.push(Rule {
                    ipv6: true,
                    priority: 5270,
                    table: 52,
                    ..Rule::default()
                }),
            }
            assert!(
                daemon_data_authorized(&drift, &baseline, Some(&tun), Some(&identity)).is_err(),
                "field{field}"
            );
        }
        assert!(
            DaemonDeclaration::new(
                "node-self".into(),
                "100.64.0.7".parse().unwrap(),
                vec![DaemonPeer {
                    node_id: "node-self".into(),
                    address: "100.64.0.8".parse().unwrap()
                }]
            )
            .is_err()
        );
        assert!(
            DaemonDeclaration::new("node-self".into(), "8.8.8.8".parse().unwrap(), vec![]).is_err()
        );
    }
    #[test]
    fn fixed_daemon_delta_refuses_tun_reuse_and_each_rule_address_route_or_link_drift() {
        use super::*;
        let mut baseline = crate::tests::snapshot(&crate::tests::plan());
        baseline.routes.retain(|r| !r.destination.is_ipv6());
        let mut actual = baseline.clone();
        let mut tun = baseline.links[1].clone();
        tun.name = "tailscale0".into();
        tun.index = 9;
        tun.kind = "tun".into();
        tun.mtu = 1280;
        tun.alias.clear();
        tun.tun_info = [(3, 1), (4, 0), (5, 1), (6, 0), (7, 0)]
            .into_iter()
            .map(|(kind, value)| (kind, vec![value]))
            .collect();
        actual.links.push(tun.clone());
        actual.rules.extend(daemon_rules());
        assert_eq!(daemon_data(&actual, &baseline, None).unwrap(), tun);
        assert!(daemon_data(&actual, &baseline, Some(&tun)).is_ok());
        let mut foreign_profile = actual.clone();
        foreign_profile.links[2].tun_info[2].1 = vec![0];
        assert!(daemon_data(&foreign_profile, &baseline, None).is_err());
        for fault in 0..39 {
            let mut d = actual.clone();
            let link = &mut d.links[2];
            match fault {
                0 => link.index = 0,
                1 => link.index = baseline.links[1].index,
                2 => link.index += 1,
                3 => link.up = false,
                4 => link.mtu = 1500,
                5 => link.hardware_type = 772,
                6 => link.kind = "dummy".into(),
                7 => link.alias = "foreign".into(),
                8 => link.peer_index = Some(1),
                9 => link.controller = 1,
                10 => link.port_kind = "bridge".into(),
                11 => link.promiscuity = 1,
                12 => link.all_multicast = 1,
                13 => link.alternate_names.push("alias".into()),
                14 => {
                    d.links.pop();
                }
                15 => d.links.push(tun.clone()),
                16 => d.links.push(baseline.links[0].clone()),
                17 => d.links[0].mtu -= 1,
                18 => d.addresses[0].address = "::1".parse().unwrap(),
                19 => d.addresses.push(d.addresses[0].clone()),
                20 => d.routes[0].table = 52,
                21 => d.routes.push(d.routes[0].clone()),
                22 => {
                    d.rules.pop();
                }
                23 => d.rules.push(d.rules.last().unwrap().clone()),
                24 => d.rules[5].ipv6 = true,
                25 => d.rules[5].protocol = Some(2),
                26 => d.rules[5].fwmask = Some(u32::MAX),
                27 => d.rules[5].fwmark = Some(1),
                28 => d.rules[5].action = 7,
                29 => d.rules[5].priority += 1,
                30 => d.rules[5].table = 52,
                31 => d.rules[5].suppress_prefixlen = Some(0),
                32 => d.rules[5].flags = 1,
                33 => d.rules[5].goto = Some(1),
                34 => d.rules[5].realm = Some(1),
                35 => d.rules[5].suppress_ifgroup = Some(1),
                36 => d.routes[0].destination = "::".parse().unwrap(),
                37 => link.name = "foreign".into(),
                _ => d.rules.push(Rule {
                    ipv6: true,
                    table: 52,
                    priority: 5270,
                    ..Rule::default()
                }),
            }
            assert!(
                daemon_data(&d, &baseline, Some(&tun)).is_err(),
                "fault{fault}"
            );
        }
        let mut ipv6_baseline = baseline.clone();
        ipv6_baseline.addresses[0].address = "::1".parse().unwrap();
        assert!(daemon_data(&actual, &ipv6_baseline, None).is_err());
    }
}

#[cfg(test)]
mod shared_host_tests {
    use super::*;
    #[test]
    fn shared_host_addition_window_accepts_only_original_down_endpoint_and_preserves_neighbor() {
        let a = "vprouter-v2:fleet:7:a";
        let b = "vprouter-v2:fleet:7:b";
        let baseline = delta(3, "external-owner");
        let mut model = HostModel::new("fleet".into(), 7, (4, 99), baseline.clone());
        let original_a = delta(10, a);
        let with_a = model.expected(None, Some(&original_a));
        model.add(a, original_a, &with_a).unwrap();
        let mut addition = delta(1_000_001, b);
        addition.links[0].kind = "veth".into();
        addition.links[0].up = false;
        addition.links[0].peer_index = Some(17);
        let before = model.expected(None, None);
        let after = model.expected(None, Some(&addition));
        let revision = model.begin_addition(b, &addition).unwrap();
        let shape = model.read_shape();
        shape.accepts(&before).unwrap();
        shape.accepts(&after).unwrap();
        let mut wrong = after.clone();
        wrong.links.last_mut().unwrap().index += 1;
        assert!(shape.accepts(&wrong).is_err());
        wrong = after.clone();
        wrong.links.last_mut().unwrap().up = true;
        assert!(shape.accepts(&wrong).is_err());
        wrong = after.clone();
        wrong.links.push(addition.links[0].clone());
        assert!(shape.accepts(&wrong).is_err());
        wrong = before.clone();
        wrong.links.retain(|l| l.alias != a);
        assert!(shape.accepts(&wrong).is_err());
        assert!(model.begin_addition(b, &addition).is_err());
        assert!(model.remove(a, &baseline).is_err());
        assert!(model.finish_addition(b, revision + 1, &after).is_err());
        assert!(model.finish_addition(b, revision, &before).is_err());
        model.finish_addition(b, revision, &after).unwrap();
        model.audit_member(a, &after).unwrap();
        model.audit_member(b, &after).unwrap();
        assert!(model.read_shape().accepts(&before).is_err());
    }
    #[test]
    fn retained_host_admission_requires_two_original_native_reads_and_declared_exact_match() {
        let (record, _) = crate::tests::fixture();
        let plan = crate::tests::plan();
        // This test-only metadata capture supplies a known matching fixture.
        // The launch path must load its baseline from protected authored input.
        let mut observer = crate::RouteObserver::open().unwrap();
        let baseline = observer
            .observe_until(vprouter_core::health::boot_seconds() + 2.)
            .unwrap();
        let expected = baseline.snapshot();
        let namespace = observer.namespace_identity();
        let mut slot = Some(observer);
        let end = vprouter_core::health::boot_seconds() + 2.;
        let mut pending =
            HostAuthority::begin_declared(&mut slot, &record, &plan, baseline, end).unwrap();
        assert!(slot.is_none());
        let mut polls = 0;
        let authority = loop {
            polls += 1;
            if let Some(authority) = pending.poll().unwrap() {
                break authority;
            }
            std::thread::yield_now();
        };
        assert!(polls >= 14);
        let model = authority.model.borrow();
        assert_eq!(model.namespace, namespace);
        assert_eq!(model.baseline, expected);
        assert!(model.members.is_empty());
        assert!(matches!(pending.poll(), Err(Error::Foreign)));
        assert!(vprouter_core::health::boot_seconds() < end);
    }
    #[test]
    fn retained_host_admission_refuses_declared_drift_without_learning_or_retry() {
        let (record, _) = crate::tests::fixture();
        let plan = crate::tests::plan();
        let mut observer = crate::RouteObserver::open().unwrap();
        let observed = observer
            .observe_until(vprouter_core::health::boot_seconds() + 2.)
            .unwrap();
        let mut baseline = observed.snapshot();
        baseline
            .links
            .iter_mut()
            .find(|l| l.name == "lo")
            .unwrap()
            .mtu += 1;
        let declaration =
            crate::HostObservation::from_snapshot(observer.namespace_identity(), baseline);
        let mut slot = Some(observer);
        let mut pending = HostAuthority::begin_declared(
            &mut slot,
            &record,
            &plan,
            declaration,
            vprouter_core::health::boot_seconds() + 2.,
        )
        .unwrap();
        loop {
            match pending.poll() {
                Ok(None) => std::thread::yield_now(),
                Err(Error::HostDrift) => break,
                _ => panic!("mismatched authored baseline accepted"),
            }
        }
        assert!(matches!(pending.poll(), Err(Error::HostDrift)));
    }
    fn delta(index: u32, alias: &str) -> Snapshot {
        let mut link = crate::tests::snapshot(&crate::tests::plan()).links[1].clone();
        link.index = index;
        link.name = format!("vh{index}");
        link.alias = alias.into();
        Snapshot {
            links: vec![link],
            ..Snapshot::default()
        }
    }
    #[test]
    fn owner_native_ticket_rejects_changed_record_revision_namespace_and_fork_copy() {
        let (record, _) = crate::tests::fixture();
        let owner = format!(
            "vprouter-v2:{}:{}:{}",
            record.deployment_id, record.generation, record.exits[0].exit_id
        );
        let actual = delta(10, &owner);
        let mut model = HostModel::new(
            record.deployment_id.clone(),
            record.generation,
            (8, 19),
            Snapshot::default(),
        );
        model.add(&owner, actual.clone(), &actual).unwrap();
        let mut authority = HostAuthority {
            model: std::rc::Rc::new(std::cell::RefCell::new(model)),
            allowed: std::rc::Rc::new(record.exits.clone()),
            record: std::rc::Rc::new(record.clone()),
            creator: std::process::id(),
        };
        let exit = &record.exits[0].exit_id;
        let ticket = authority.begin_audit(&record, exit).unwrap();
        let observed = crate::HostObservation::from_snapshot((8, 19), actual.clone());
        authority.complete_audit(&ticket, &observed).unwrap();
        let mut changed = record.clone();
        changed.exits[0].state_dir = "/changed".into();
        assert!(authority.begin_audit(&changed, exit).is_err());
        assert!(authority.begin_audit(&record, "unknown").is_err());
        let wrong_ns = crate::HostObservation::from_snapshot((8, 20), actual.clone());
        assert!(authority.complete_audit(&ticket, &wrong_ns).is_err());
        let mut drift = actual;
        drift.links[0].headroom = Some(23);
        assert_eq!(
            authority.complete_audit(
                &ticket,
                &crate::HostObservation::from_snapshot((8, 19), drift)
            ),
            Err(Error::HostDrift)
        );
        authority.model.borrow_mut().revision += 1;
        assert!(authority.complete_audit(&ticket, &observed).is_err());
        authority.creator = std::process::id() + 1;
        assert!(authority.begin_audit(&record, exit).is_err());
    }
    #[test]
    fn declared_removal_preserves_original_neighbor_window_and_rejects_foreign_or_expired_shapes() {
        let (mut record, _) = crate::tests::fixture();
        let mut second = record.exits[0].clone();
        second.exit_id = "other".into();
        record.exits.push(second);
        let a_owner = format!(
            "vprouter-v2:{}:{}:{}",
            record.deployment_id, record.generation, record.exits[0].exit_id
        );
        let b_owner = format!(
            "vprouter-v2:{}:{}:other",
            record.deployment_id, record.generation
        );
        let a = delta(10, &a_owner);
        let b = host_delta(
            &delta(11, &b_owner).links[0],
            "10.11.0.1".parse().unwrap(),
            "10.11.0.2".parse().unwrap(),
        );
        let mut model = HostModel::new(
            record.deployment_id.clone(),
            record.generation,
            (8, 19),
            Snapshot::default(),
        );
        model.add(&a_owner, a.clone(), &a).unwrap();
        let mut both = a.clone();
        both.links.extend(b.links.clone());
        both.addresses.extend(b.addresses.clone());
        both.routes.extend(b.routes.clone());
        model.add(&b_owner, b.clone(), &both).unwrap();
        let authority = HostAuthority {
            model: std::rc::Rc::new(std::cell::RefCell::new(model)),
            allowed: std::rc::Rc::new(record.exits.clone()),
            record: std::rc::Rc::new(record.clone()),
            creator: std::process::id(),
        };
        let sent = vprouter_core::health::boot_seconds();
        let old = authority
            .begin_audit_at(&record, &record.exits[0].exit_id, sent)
            .unwrap();
        let mut removal = authority.prepare_removal(&b_owner, &b).unwrap();
        let original = removal.intent_bytes().unwrap().to_vec();
        removal.activate().unwrap();
        assert_eq!(original, removal.intent_bytes().unwrap());
        for mask in 0..32u8 {
            let mut observed = a.clone();
            if mask & 1 != 0 {
                observed.links.extend(b.links.clone());
            }
            if mask & 2 != 0 {
                observed.addresses.extend(b.addresses.clone());
            }
            for (i, route) in b.routes.iter().enumerate() {
                if mask & (1 << (i + 2)) != 0 {
                    observed.routes.push(route.clone());
                }
            }
            authority
                .complete_audit(
                    &old,
                    &crate::HostObservation::from_snapshot((8, 19), observed),
                )
                .unwrap();
        }
        let mut wrong = both.clone();
        wrong.links[0].headroom = Some(123);
        assert!(
            authority
                .complete_audit(&old, &crate::HostObservation::from_snapshot((8, 19), wrong))
                .is_err()
        );
        let mut duplicate = both.clone();
        duplicate.links.push(b.links[0].clone());
        assert!(
            authority
                .complete_audit(
                    &old,
                    &crate::HostObservation::from_snapshot((8, 19), duplicate)
                )
                .is_err()
        );
        let mut modified = both.clone();
        modified.routes.last_mut().unwrap().metric += 1;
        assert!(
            authority
                .complete_audit(
                    &old,
                    &crate::HostObservation::from_snapshot((8, 19), modified)
                )
                .is_err()
        );
        removal
            .finish(&crate::HostObservation::from_snapshot((8, 19), a.clone()))
            .unwrap();
        authority
            .complete_audit(
                &old,
                &crate::HostObservation::from_snapshot((8, 19), both.clone()),
            )
            .unwrap();
        let new = authority
            .begin_audit_at(&record, &record.exits[0].exit_id, sent)
            .unwrap();
        assert!(
            authority
                .complete_audit(&new, &crate::HostObservation::from_snapshot((8, 19), both))
                .is_err()
        );
        authority
            .complete_audit(
                &new,
                &crate::HostObservation::from_snapshot((8, 19), a.clone()),
            )
            .unwrap();
        assert!(
            authority
                .begin_audit_at(&record, &record.exits[0].exit_id, sent - 3.)
                .is_err()
        );
        let mut expired = new;
        expired.sent_at -= 3.;
        assert!(
            authority
                .complete_audit(&expired, &crate::HostObservation::from_snapshot((8, 19), a))
                .is_err()
        );
    }
    #[test]
    fn shared_model_preserves_neighbors_and_rejects_foreign_and_generation_drift() {
        let baseline = Snapshot::default();
        let mut model = HostModel::new("fleet".into(), 7, (1, 2), baseline.clone());
        let a = delta(10, "vprouter-v2:fleet:7:a");
        let b = delta(11, "vprouter-v2:fleet:7:b");
        model.add("vprouter-v2:fleet:7:a", a.clone(), &a).unwrap();
        let mut both = a.clone();
        both.links.extend(b.links.clone());
        model
            .add("vprouter-v2:fleet:7:b", b.clone(), &both)
            .unwrap();
        model.audit_member("vprouter-v2:fleet:7:a", &both).unwrap();
        model.audit_member("vprouter-v2:fleet:7:b", &both).unwrap();
        assert!(model.audit_member("vprouter-v2:fleet:8:a", &both).is_err());
        let mut drift = both.clone();
        drift.links[1].alias = "foreign".into();
        assert!(model.audit_member("vprouter-v2:fleet:7:a", &drift).is_err());
        assert!(model.remove("vprouter-v2:fleet:7:b", &both).is_err());
        model.remove("vprouter-v2:fleet:7:b", &a).unwrap();
        model.audit_member("vprouter-v2:fleet:7:a", &a).unwrap();
        assert!(model.audit_member("vprouter-v2:fleet:7:b", &a).is_err());
        model.remove("vprouter-v2:fleet:7:a", &baseline).unwrap();
    }
    #[test]
    fn shared_model_detects_pacing_and_buffer_room_drift_on_host_and_owned_links() {
        let mut baseline = delta(1, "");
        baseline.links[0].max_pacing_offload_horizon = Some(0);
        baseline.links[0].headroom = Some(12);
        baseline.links[0].tailroom = Some(0);
        let mut model = HostModel::new("fleet".into(), 7, (1, 2), baseline.clone());
        let mut a = delta(10, "vprouter-v2:fleet:7:a");
        a.links[0].max_pacing_offload_horizon = Some(0);
        a.links[0].headroom = Some(0);
        a.links[0].tailroom = Some(0);
        let mut actual = baseline;
        actual.links.extend(a.links.clone());
        model.add("vprouter-v2:fleet:7:a", a, &actual).unwrap();
        model
            .audit_member("vprouter-v2:fleet:7:a", &actual)
            .unwrap();
        for index in [0, 1] {
            for field in 0..6 {
                let mut drift = actual.clone();
                let link = &mut drift.links[index];
                match field {
                    0 => link.max_pacing_offload_horizon = Some(1),
                    1 => link.headroom = Some(64),
                    2 => link.tailroom = Some(1),
                    3 => link.max_pacing_offload_horizon = None,
                    4 => link.headroom = None,
                    _ => link.tailroom = None,
                }
                assert_eq!(
                    model.audit_member("vprouter-v2:fleet:7:a", &drift),
                    Err(Error::HostDrift)
                );
            }
        }
    }
    #[test]
    fn shared_model_never_adopts_undeclared_host_resources_or_partial_failed_additions() {
        let baseline = Snapshot::default();
        let mut model = HostModel::new("fleet".into(), 7, (1, 2), baseline.clone());
        let a = delta(10, "vprouter-v2:fleet:7:a");
        let b = delta(11, "vprouter-v2:fleet:7:b");
        let mut foreign = a.clone();
        foreign.links.extend(b.links.clone());
        assert!(
            model
                .add("vprouter-v2:fleet:7:a", a.clone(), &foreign)
                .is_err()
        );
        assert!(model.audit_member("vprouter-v2:fleet:7:a", &a).is_err());
        model.add("vprouter-v2:fleet:7:a", a.clone(), &a).unwrap();
        assert!(model.add("vprouter-v2:fleet:7:a", a.clone(), &a).is_err());
        let mut drift = a.clone();
        drift.rules.push(Rule::default());
        assert!(model.audit_member("vprouter-v2:fleet:7:a", &drift).is_err());
        assert!(
            model
                .audit_member("vprouter-v2:fleet:7:a", &baseline)
                .is_err()
        );
    }
}
