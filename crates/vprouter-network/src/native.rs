mod host_read;
mod readback;
use crate::{
    Address, Error, Link, Plan, Result, Route, Rule, Snapshot, Wireguard, project,
    socket::{Completion, RouteRead, Socket, deadline},
};
pub use host_read::HostRead;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::{
    GenlMessage,
    ctrl::{GenlCtrl, GenlCtrlCmd, nlas::GenlCtrlAttrs},
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage as N,
    address::AddressMessage,
    link::{InfoData, InfoKind, InfoVeth, LinkAttribute as L, LinkFlags, LinkInfo, LinkMessage},
    route::RouteMessage,
    rule::RuleMessage,
};
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr as I,
    WireguardAttribute as W, WireguardCmd, WireguardDeviceFlags, WireguardMessage, WireguardPeer,
    WireguardPeerAttribute as P, WireguardPeerFlags,
};
pub(crate) use readback::{Readback, ReadbackResult};
use std::{
    fs,
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, BorrowedFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    time::Instant,
};
use vprouter_core::profile::Profile;
use zeroize::Zeroize;

pub(crate) type NamespaceIdentity = (u64, u64);
fn current_namespace() -> Result<NamespaceIdentity> {
    let m = fs::metadata("/proc/thread-self/ns/net").map_err(|_| Error::NamespaceUnverified)?;
    Ok((m.dev(), m.ino()))
}

/// Unprivileged metadata only, intentionally not accepted by Plan::audit.
/// No WG peer/key/handshake observation or structural-validity claim.
pub struct MetadataSnapshot {
    pub links: Vec<Link>,
    pub addresses: Vec<Address>,
    pub routes: Vec<Route>,
    pub rules: Vec<Rule>,
}

/// A pinned caller-supplied network namespace FD. This checks nsfs/type and
/// identity, NOT container/PID/cgroup/allocation authorization. A later trusted
/// launch helper MUST establish that provenance before constructing this value.
/// There is no caller-created quarantine evidence in this API.
pub struct NamespaceTarget {
    fd: OwnedFd,
    identity: NamespaceIdentity,
}
impl NamespaceTarget {
    pub fn from_trusted_network_namespace(fd: BorrowedFd<'_>) -> Result<Self> {
        let fd = fd
            .try_clone_to_owned()
            .map_err(|_| Error::NamespaceUnverified)?;
        let st = rustix::fs::fstat(&fd).map_err(|_| Error::NamespaceUnverified)?;
        let fs = rustix::fs::fstatfs(&fd).map_err(|_| Error::NamespaceUnverified)?;
        let path = fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
            .map_err(|_| Error::NamespaceUnverified)?;
        if fs.f_type as u64 != 0x6e736673
            || !path.as_os_str().as_encoded_bytes().starts_with(b"net:[")
        {
            return Err(Error::NamespaceUnverified);
        }
        Ok(Self {
            fd,
            identity: (st.st_dev, st.st_ino),
        })
    }
}
/// Non-forgeable record of the observed DOWN resource. This is not a kernel
/// lease or alias CAS: privileged concurrent writers must be excluded externally.
pub struct DownLink {
    pub(crate) link: Link,
    pub(crate) namespace: NamespaceIdentity,
}
impl DownLink {
    pub fn index(&self) -> u32 {
        self.link.index
    }
    pub fn name(&self) -> &str {
        &self.link.name
    }
}
/// An inseparable host/transport pair bound to its creation namespaces.
/// Inspection borrows the endpoints; callers cannot recombine owned tokens.
///
/// ```compile_fail,E0616
/// use vprouter_network::VethPair;
/// fn recombine(a: VethPair, b: VethPair) -> VethPair {
///     VethPair { host: a.host, transport: b.transport }
/// }
/// ```
pub struct VethPair {
    pub(crate) host: DownLink,
    pub(crate) transport: DownLink,
}
impl VethPair {
    pub fn host(&self) -> &DownLink {
        &self.host
    }
    pub fn transport(&self) -> &DownLink {
        &self.transport
    }
}

/// These two native sockets stay bound to their construction namespace even
/// when returned from a dedicated synchronous helper thread. No setns here.
pub struct NativeNetwork {
    pub(crate) plan: Plan,
    pub(crate) route: Socket,
    generic: Socket,
    family: Option<u16>,
    pub(crate) namespace: NamespaceIdentity,
}
impl NativeNetwork {
    pub(crate) fn from_socket_creator(
        plan: Plan,
        completed: &vprouter_native_role::SocketCompletion,
    ) -> Result<Self> {
        let namespace = completed
            .namespace_identity()
            .map_err(super::secret_role::mapped)?;
        let route = Socket::from_original_creator(completed, false)?;
        let generic = Socket::from_original_creator(completed, true)?;
        Ok(Self {
            plan,
            route,
            generic,
            family: None,
            namespace,
        })
    }
    pub(crate) fn confined(&self, role: &vprouter_native_role::ConfinedWireguard) -> Result<Self> {
        role.require().map_err(|_| Error::NamespaceUnverified)?;
        let [route, generic] = role
            .socket_owners()
            .map_err(|_| Error::NamespaceUnverified)?;
        Ok(Self {
            plan: self.plan.clone(),
            route: Socket::confined(route, self.route.port(), self.route.sequence()?, role)?,
            generic: Socket::confined(
                generic,
                self.generic.port(),
                self.generic.sequence()?,
                role,
            )?,
            family: None,
            namespace: self.namespace,
        })
    }
    pub(crate) fn confined_veth(&self, role: &vprouter_native_role::ConfinedVeth) -> Result<Self> {
        role.require().map_err(|_| Error::NamespaceUnverified)?;
        let [route, generic] = role
            .socket_owners()
            .map_err(|_| Error::NamespaceUnverified)?;
        Ok(Self {
            plan: self.plan.clone(),
            route: Socket::confined_veth(route, self.route.port(), self.route.sequence()?, role)?,
            generic: Socket::confined_veth(
                generic,
                self.generic.port(),
                self.generic.sequence()?,
                role,
            )?,
            family: None,
            namespace: self.namespace,
        })
    }
    pub(crate) fn sequences(&self) -> Result<[u32; 2]> {
        Ok([self.route.sequence()?, self.generic.sequence()?])
    }
    pub(crate) fn confined_move_target(
        &self,
        role: &vprouter_native_role::ConfinedWireguard,
    ) -> Result<Self> {
        let (_, identity) = role
            .move_target_namespace()
            .map_err(super::secret_role::mapped)?;
        if self.namespace != identity {
            return Err(Error::NamespaceUnverified);
        }
        let [route, generic] = role
            .move_target_sockets()
            .map_err(super::secret_role::mapped)?;
        Ok(Self {
            plan: self.plan.clone(),
            route: Socket::confined_move_target(
                route,
                self.route.port(),
                self.route.sequence()?,
                role,
            )?,
            generic: Socket::confined_move_target(
                generic,
                self.generic.port(),
                self.generic.sequence()?,
                role,
            )?,
            family: None,
            namespace: self.namespace,
        })
    }
    pub(crate) fn confined_veth_target(
        &self,
        role: &vprouter_native_role::ConfinedVeth,
    ) -> Result<Self> {
        let (_, identity) = role
            .move_target_namespace()
            .map_err(super::secret_role::mapped)?;
        if self.namespace != identity {
            return Err(Error::NamespaceUnverified);
        }
        let [route, generic] = role
            .move_target_sockets()
            .map_err(super::secret_role::mapped)?;
        Ok(Self {
            plan: self.plan.clone(),
            route: Socket::confined_veth_target(
                route,
                self.route.port(),
                self.route.sequence()?,
                role,
            )?,
            generic: Socket::confined_veth_target(
                generic,
                self.generic.port(),
                self.generic.sequence()?,
                role,
            )?,
            family: None,
            namespace: self.namespace,
        })
    }
    pub(crate) fn rebind_accepted_operation(
        &mut self,
        completed: &vprouter_native_role::Completed,
        sequences: [u32; 2],
        deadline: vprouter_netfilter::BootDeadline,
        timer: std::sync::Arc<OwnedFd>,
    ) -> Result<()> {
        self.route
            .rebind_accepted_operation(completed, sequences[0], deadline, timer.clone())?;
        self.generic
            .rebind_accepted_operation(completed, sequences[1], deadline, timer)
    }
    pub(crate) fn rebind_veth_operation(
        &mut self,
        completed: &vprouter_native_role::VethCompleted,
        sequences: [u32; 2],
        deadline: vprouter_netfilter::BootDeadline,
        timer: std::sync::Arc<OwnedFd>,
    ) -> Result<()> {
        self.route
            .rebind_veth_operation(completed, sequences[0], deadline, timer.clone())?;
        self.generic
            .rebind_veth_operation(completed, sequences[1], deadline, timer)
    }
    pub(crate) fn matches_socket_owners(
        &self,
        sockets: &[(std::sync::Arc<OwnedFd>, u32); 2],
    ) -> bool {
        self.route.same_original_owner(&sockets[0].0, sockets[0].1)
            && self
                .generic
                .same_original_owner(&sockets[1].0, sockets[1].1)
    }
    pub(crate) fn accept_sequences(
        &mut self,
        completed: &vprouter_native_role::Completed,
        sequences: [u32; 2],
    ) -> Result<()> {
        self.route.accept_sequence(completed, sequences[0])?;
        self.generic.accept_sequence(completed, sequences[1])
    }
    pub(crate) fn accept_veth_sequences(
        &mut self,
        completed: &vprouter_native_role::VethCompleted,
        sequences: [u32; 2],
    ) -> Result<()> {
        self.route.accept_veth_sequence(completed, sequences[0])?;
        self.generic.accept_veth_sequence(completed, sequences[1])
    }
    pub(crate) fn finish_operation(
        &mut self,
        completed: &vprouter_native_role::Completed,
    ) -> Result<()> {
        self.route.finish_operation(completed)?;
        self.generic.finish_operation(completed)
    }
    pub fn bind_cleanup_deadline(
        &mut self,
        deadline: vprouter_netfilter::BootDeadline,
        timer: std::sync::Arc<OwnedFd>,
    ) -> Result<()> {
        self.route.bind_cleanup_deadline(deadline, timer.clone())?;
        self.generic.bind_cleanup_deadline(deadline, timer)
    }
    /// Borrowed original sockets for a fixed native retirement role. These are
    /// descriptor identities, not namespace or resource admission capabilities.
    pub fn descriptors(&self) -> [BorrowedFd<'_>; 2] {
        [self.route.descriptor(), self.generic.descriptor()]
    }

    /// Caller establishes trusted transport/data/host context before opening.
    pub fn open(plan: Plan) -> Result<Self> {
        let namespace = current_namespace()?;
        let route = Socket::open(false)?;
        let generic = Socket::open(true)?;
        if current_namespace()? != namespace {
            return Err(Error::NamespaceUnverified);
        }
        Ok(Self {
            plan,
            route,
            generic,
            family: None,
            namespace,
        })
    }
    fn compatible(&self, other: &Self, target: &NamespaceTarget) -> Result<()> {
        if self.plan != other.plan
            || target.identity != other.namespace
            || target.identity == self.namespace
        {
            return Err(Error::NamespaceUnverified);
        }
        Ok(())
    }
    fn family(&mut self, end: Instant) -> Result<u16> {
        if let Some(f) = self.family {
            return Ok(f);
        }
        let request = GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName("wireguard".into())],
        });
        let replies = self
            .generic
            .request(request, 0, 16, Completion::Single, end)?;
        project::preflight(&replies[0], true)?;
        let message = NetlinkMessage::<GenlMessage<GenlCtrl>>::deserialize(&replies[0])
            .map_err(|_| Error::Malformed)?;
        let NetlinkPayload::InnerMessage(message) = message.payload else {
            return Err(Error::Malformed);
        };
        if message.payload.cmd != GenlCtrlCmd::NewFamily {
            return Err(Error::Malformed);
        }
        let ids: Vec<_> = message
            .payload
            .nlas
            .iter()
            .filter_map(|a| {
                if let GenlCtrlAttrs::FamilyId(id) = a {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        let names: Vec<_> = message
            .payload
            .nlas
            .iter()
            .filter_map(|a| {
                if let GenlCtrlAttrs::FamilyName(n) = a {
                    Some(n.as_str())
                } else {
                    None
                }
            })
            .collect();
        if ids.len() != 1 || ids[0] < 16 || names != ["wireguard"] {
            return Err(Error::Malformed);
        }
        self.family = Some(ids[0]);
        Ok(ids[0])
    }
    pub(crate) fn links(&mut self, end: Instant) -> Result<Vec<Link>> {
        route_links(&mut self.route, end)
    }
    pub(crate) fn addresses(&mut self, end: Instant) -> Result<Vec<Address>> {
        route_addresses(&mut self.route, end)
    }
    pub(crate) fn routes(&mut self, end: Instant) -> Result<Vec<Route>> {
        route_routes(&mut self.route, end)
    }
    pub(crate) fn rules(&mut self, end: Instant) -> Result<Vec<Rule>> {
        route_rules(&mut self.route, end)
    }
    fn wireguard(&mut self, index: u32, end: Instant) -> Result<Wireguard> {
        // A raw GetDevice reply can contain private key attributes even when
        // the eventual public projection discards them. Mark before the query.
        vprouter_core::secret_boundary::mark_ingress();
        let family = self.family(end)?;
        let mut m = GenlMessage::from_payload(WireguardMessage {
            cmd: WireguardCmd::GetDevice,
            attributes: vec![W::IfIndex(index)],
        });
        m.set_resolved_family_id(family);
        let replies = self.generic.request(m, 0, family, Completion::Dump, end)?;
        // Our one-peer/one-allowedIP policy fits one message. Split devices or
        // extra replies are unsupported; never silently omit continuation data.
        if replies.len() != 1 {
            return Err(Error::Unsupported);
        }
        let w = project::wireguard(&replies[0])?;
        if w.index != index {
            return Err(Error::Drifted);
        }
        Ok(w)
    }
    /// All link/address/route/rule metadata, without the privileged WG query.
    /// This is never a full Snapshot and cannot satisfy structural readiness.
    pub fn observe_metadata(&mut self) -> Result<MetadataSnapshot> {
        let end = deadline();
        let result = MetadataSnapshot {
            links: self.links(end)?,
            addresses: self.addresses(end)?,
            routes: self.routes(end)?,
            rules: self.rules(end)?,
        };
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        Ok(result)
    }
    /// ALL tables and both address families are dumped, with all policy rules.
    /// An error gives no partial/verified snapshot. No raw replies leave here.
    pub fn observe(&mut self) -> Result<Snapshot> {
        let end = deadline();
        let links = self.links(end)?;
        let addresses = self.addresses(end)?;
        let routes = self.routes(end)?;
        let rules = self.rules(end)?;
        let wireguard = match links.iter().find(|l| l.name == self.plan.wireguard_name()) {
            Some(l) if l.kind == "wireguard" => Some(self.wireguard(l.index, end)?),
            _ => None,
        };
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        Ok(Snapshot {
            links,
            addresses,
            routes,
            rules,
            wireguard,
        })
    }
    pub(crate) fn absent(&mut self, name: &str, end: Instant) -> Result<()> {
        if self.links(end)?.iter().any(|l| l.name == name) {
            Err(Error::Foreign)
        } else {
            Ok(())
        }
    }
    pub(crate) fn owned_down(&mut self, token: &DownLink, end: Instant) -> Result<Link> {
        if self.namespace != token.namespace {
            return Err(Error::NamespaceUnverified);
        }
        let l = self
            .links(end)?
            .into_iter()
            .find(|l| l.index == token.index())
            .ok_or(Error::Absent)?;
        if l != token.link
            || l.alias != self.plan.alias
            || l.up
            || l.controller != 0
            || !l.port_kind.is_empty()
            || l.promiscuity != 0
            || l.all_multicast != 0
            || !l.alternate_names.is_empty()
            || ![
                self.plan.wireguard_name(),
                self.plan.host_name(),
                self.plan.transport_name(),
            ]
            .contains(&l.name.as_str())
        {
            return Err(Error::Drifted);
        }
        if self.addresses(end)?.iter().any(|a| a.index == l.index)
            || self.routes(end)?.iter().any(|r| r.output == l.index)
        {
            return Err(Error::Drifted);
        }
        Ok(l)
    }
    pub(crate) fn new_token(&mut self, name: &str, kind: &str, end: Instant) -> Result<DownLink> {
        let link = self
            .links(end)?
            .into_iter()
            .find(|l| l.name == name)
            .ok_or(Error::Absent)?;
        if link.kind != kind
            || link.alias != self.plan.alias
            || link.up
            || link.mtu != 1420
            || link.controller != 0
            || !link.port_kind.is_empty()
            || link.promiscuity != 0
            || link.all_multicast != 0
            || !link.alternate_names.is_empty()
        {
            #[cfg(test)]
            eprintln!(
                "LAB_NEW_TOKEN_MISMATCH index={} kind_matches={} alias_matches={} up={} mtu={}",
                link.index,
                link.kind == kind,
                link.alias == self.plan.alias,
                link.up,
                link.mtu
            );
            return Err(Error::Drifted);
        }
        if self.addresses(end)?.iter().any(|a| a.index == link.index) {
            return Err(Error::Drifted);
        }
        Ok(DownLink {
            link,
            namespace: self.namespace,
        })
    }
    // Private initialization is called ONLY after our successful EXCL NEWLINK
    // ACK, never as an adoption path for a resource that existed beforehand.
    // Linux may ignore IFLA_IFALIAS in NEWLINK, including both veth ends.
    fn created_down(&mut self, name: &str, kind: &str, end: Instant) -> Result<Link> {
        let link = self
            .links(end)?
            .into_iter()
            .find(|l| l.name == name)
            .ok_or(Error::Absent)?;
        let hardware = if kind == "wireguard" { 65534 } else { 1 };
        if link.kind != kind
            || link.up
            || link.mtu != 1420
            || link.hardware_type != hardware
            || link.controller != 0
            || !link.port_kind.is_empty()
            || link.promiscuity != 0
            || link.all_multicast != 0
            || !link.alternate_names.is_empty()
            || (!link.alias.is_empty() && link.alias != self.plan.alias)
        {
            return Err(Error::Foreign);
        }
        if self.addresses(end)?.iter().any(|a| a.index == link.index)
            || self.routes(end)?.iter().any(|r| r.output == link.index)
        {
            return Err(Error::Drifted);
        }
        Ok(link)
    }
    fn mark_created_down(&mut self, link: &Link, end: Instant) -> Result<()> {
        if !link.alias.is_empty() {
            return Ok(());
        }
        let mut m = LinkMessage::default();
        m.header.index = link.index;
        m.attributes.push(L::IfAlias(self.plan.alias.clone()));
        self.link_mutation(N::SetLink(m), end)
    }
    pub(crate) fn link_mutation(&mut self, m: N, end: Instant) -> Result<()> {
        self.route
            .request(m, 0, 16, Completion::Ack, end)
            .map(|_| ())
    }
    /// Create initially DOWN, configure one peer in the transport birth namespace.
    /// Errors/ambiguous ACKs may leave an owned DOWN resource; reconcile first.
    pub fn create_wireguard_down(&mut self, profile: &Profile) -> Result<DownLink> {
        self.create_wireguard_down_inner(profile, None, |_| {})
    }
    #[cfg(not(feature = "lab"))]
    pub(crate) fn create_wireguard_down_until(
        &mut self,
        profile: &Profile,
        end: Instant,
    ) -> Result<DownLink> {
        self.create_wireguard_down_inner(profile, Some(end), |_| {})
    }
    #[cfg(feature = "lab")]
    pub(crate) fn create_wireguard_down_profiled(
        &mut self,
        profile: &Profile,
        end: Instant,
        phase: impl FnMut(u8),
    ) -> Result<DownLink> {
        self.create_wireguard_down_inner(profile, Some(end), phase)
    }
    fn create_wireguard_down_inner(
        &mut self,
        profile: &Profile,
        original_end: Option<Instant>,
        mut phase: impl FnMut(u8),
    ) -> Result<DownLink> {
        phase(10);
        if !self.plan.matches_profile(profile) {
            return Err(Error::InvalidInput);
        }
        let end = original_end.unwrap_or_else(deadline);
        let name = self.plan.wireguard_name().to_owned();
        phase(11);
        self.absent(&name, end)?;
        let mut m = down_message(&name, &self.plan.alias);
        m.attributes
            .push(L::LinkInfo(vec![project::wireguard_kind()]));
        phase(12);
        self.route
            .request(N::NewLink(m), 0x600, 16, Completion::Ack, end)?;
        phase(13);
        let created = self.created_down(&name, "wireguard", end)?;
        if created.peer_index.is_some() {
            return Err(Error::Drifted);
        }
        phase(14);
        self.mark_created_down(&created, end)?;
        phase(15);
        let token = self.new_token(&name, "wireguard", end)?;
        phase(16);
        let family = self.family(end)?;
        let attributes = profile.with_private_key(|key| {
            vec![
                W::IfIndex(token.index()),
                W::PrivateKey(*key),
                W::Flags(WireguardDeviceFlags::ReplacePeers),
                W::Fwmark(0),
                W::Peers(vec![WireguardPeer(vec![
                    P::PublicKey(self.plan.peer),
                    P::Endpoint(self.plan.endpoint.into()),
                    P::Flags(WireguardPeerFlags::ReplaceAllowedIps),
                    P::PersistentKeepalive(0),
                    P::AllowedIps(vec![WireguardAllowedIp(vec![
                        I::Family(WireguardAddressFamily::Ipv4),
                        I::IpAddr(Ipv4Addr::UNSPECIFIED.into()),
                        I::Cidr(0),
                    ])]),
                ])]),
            ]
        });
        let mut m = GenlMessage::from_payload(WireguardMessage {
            cmd: WireguardCmd::SetDevice,
            attributes,
        });
        m.set_resolved_family_id(family);
        // Socket serialization borrows the request, so scrub its typed secret
        // once serialized/sent, including any exchange failure.
        phase(17);
        let result = self.generic.request_borrowed(&m, family, end);
        for a in &mut m.payload.attributes {
            if let W::PrivateKey(k) = a {
                k.zeroize();
            }
        }
        result?;
        phase(18);
        self.configuration(token.index(), end)?;
        phase(19);
        self.owned_down(&token, end)?;
        phase(20);
        complete(end, token)
    }
    /// Recover a handle only for this plan's exact configured, unaddressed DOWN
    /// WG resource. Incomplete/foreign/drifted provisioning remains untouched.
    pub fn reconcile_wireguard_down(&mut self) -> Result<DownLink> {
        let end = deadline();
        let name = self.plan.wireguard_name().to_owned();
        let token = self.new_token(&name, "wireguard", end)?;
        self.configuration(token.index(), end)?;
        self.owned_down(&token, end)?;
        complete(end, token)
    }
    pub(crate) fn configuration(&mut self, index: u32, end: Instant) -> Result<()> {
        self.checked_wireguard(index, end).map(|_| ())
    }
    pub(crate) fn checked_wireguard(
        &mut self,
        index: u32,
        end: Instant,
    ) -> Result<crate::Wireguard> {
        let w = self.wireguard(index, end)?;
        self.check_public_wireguard(&w, index)?;
        Ok(w)
    }
    pub(crate) fn check_public_wireguard(&self, w: &crate::Wireguard, index: u32) -> Result<()> {
        if w.index != index
            || w.name != self.plan.wireguard_name()
            || w.public_key != self.plan.public_key
            || w.peers.len() != 1
        {
            return Err(Error::Drifted);
        }
        let p = &w.peers[0];
        if p.public_key != self.plan.peer
            || p.endpoint != self.plan.endpoint.into()
            || p.allowed_ips != [(Ipv4Addr::UNSPECIFIED.into(), 0)]
        {
            return Err(Error::Drifted);
        }
        Ok(())
    }
    /// Move only a verified DOWN WG device. Its UDP socket birth namespace is
    /// preserved by the kernel. Target provenance remains the caller's duty.
    pub fn move_wireguard_down(
        &mut self,
        data: &mut Self,
        target: &NamespaceTarget,
        token: DownLink,
    ) -> Result<DownLink> {
        self.compatible(data, target)?;
        let end = deadline();
        let l = self.owned_down(&token, end)?;
        if l.name != self.plan.wireguard_name() || l.kind != "wireguard" {
            return Err(Error::Foreign);
        }
        self.configuration(l.index, end)?;
        data.absent(&l.name, end)?;
        let mut m = LinkMessage::default();
        m.header.index = l.index;
        m.attributes.push(L::NetNsFd(target.fd.as_raw_fd()));
        self.link_mutation(N::SetLink(m), end)?;
        if self.links(end)?.iter().any(|x| x.name == l.name) {
            return Err(Error::Drifted);
        }
        let next = data.new_token(&l.name, "wireguard", end)?;
        data.configuration(next.index(), end)?;
        complete(end, next)
    }
    /// Fixed no-fork operation only. Both original socket constructors and the
    /// admitted DATA pin are held by its Pending owner; no parent raw WG read.
    pub(crate) fn move_wireguard_down_fixed(
        &mut self,
        data: &mut Self,
        target: BorrowedFd<'_>,
        target_identity: NamespaceIdentity,
        token: &DownLink,
        end: Instant,
    ) -> Result<DownLink> {
        if self.plan != data.plan
            || data.namespace != target_identity
            || self.namespace == data.namespace
            || token.namespace != self.namespace
        {
            return Err(Error::NamespaceUnverified);
        }
        let stat = rustix::fs::fstat(target).map_err(|_| Error::NamespaceUnverified)?;
        if (stat.st_dev, stat.st_ino) != target_identity {
            return Err(Error::NamespaceUnverified);
        }
        let before = self.owned_down(token, end)?;
        if before.kind != "wireguard" || before.name != self.plan.wireguard_name() {
            return Err(Error::Foreign);
        }
        self.configuration(before.index, end)?;
        data.absent(&before.name, end)?;
        let mut message = LinkMessage::default();
        message.header.index = before.index;
        message.attributes.push(L::NetNsFd(target.as_raw_fd()));
        self.link_mutation(N::SetLink(message), end)?;
        self.absent(&before.name, end)?;
        let moved = data.new_token(&before.name, "wireguard", end)?;
        data.configuration(moved.index(), end)?;
        data.owned_down(&moved, end)?;
        complete(end, moved)
    }
    /// The host and transport ends are born DOWN and unaddressed. There is no
    /// public activation/address/route method until guard quarantine is enforced.
    pub fn create_veth_pair_down(
        &mut self,
        transport: &mut Self,
        target: &NamespaceTarget,
    ) -> Result<VethPair> {
        self.compatible(transport, target)?;
        let end = deadline();
        let host = self.plan.host_name().to_owned();
        let peer = self.plan.transport_name().to_owned();
        self.absent(&host, end)?;
        transport.absent(&peer, end)?;
        let mut peer_msg = down_message(&peer, &self.plan.alias);
        peer_msg.attributes.push(L::NetNsFd(target.fd.as_raw_fd()));
        let mut m = down_message(&host, &self.plan.alias);
        m.attributes.push(L::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::Data(InfoData::Veth(InfoVeth::Peer(peer_msg))),
        ]));
        self.route
            .request(N::NewLink(m), 0x600, 16, Completion::Ack, end)?;
        let created_host = self.created_down(&host, "veth", end)?;
        let created_peer = transport.created_down(&peer, "veth", end)?;
        if created_host.peer_index != Some(created_peer.index)
            || created_peer.peer_index != Some(created_host.index)
        {
            return Err(Error::Drifted);
        }
        self.mark_created_down(&created_host, end)?;
        transport.mark_created_down(&created_peer, end)?;
        let host = self.new_token(&host, "veth", end)?;
        let trans = transport.new_token(&peer, "veth", end)?;
        if host.link.peer_index != Some(trans.index())
            || trans.link.peer_index != Some(host.index())
        {
            #[cfg(test)]
            eprintln!(
                "LAB_VETH_RECIPROCAL_MISMATCH host={} transport={} host_iflink={:?} transport_iflink={:?}",
                host.index(),
                trans.index(),
                host.link.peer_index,
                trans.link.peer_index
            );
            return Err(Error::Drifted);
        }
        complete(
            end,
            VethPair {
                host,
                transport: trans,
            },
        )
    }
    /// Fixed child-only move of the constructor's exact original DOWN endpoint.
    /// Planned index and both complete HOST shapes precede mutation; no returned
    /// kernel metadata is adopted as a new declaration or wildcard envelope.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn move_veth_host_fixed(
        &mut self,
        host: &mut Self,
        target: BorrowedFd<'_>,
        target_identity: NamespaceIdentity,
        original: &VethPair,
        index: u32,
        before: &crate::HostObservation,
        after: &crate::HostObservation,
        end: Instant,
    ) -> Result<VethPair> {
        if self.plan != host.plan
            || self.namespace == host.namespace
            || host.namespace != target_identity
            || original.host.namespace != self.namespace
            || original.transport.namespace != self.namespace
            || before.namespace != target_identity
            || after.namespace != target_identity
            || index == 0
        {
            return Err(Error::Foreign);
        }
        let st = rustix::fs::fstat(target).map_err(|_| Error::NamespaceUnverified)?;
        if (st.st_dev, st.st_ino) != target_identity {
            return Err(Error::NamespaceUnverified);
        }
        let old_host = self.owned_down(&original.host, end)?;
        let old_peer = self.owned_down(&original.transport, end)?;
        if old_host.kind != "veth"
            || old_peer.kind != "veth"
            || old_host.peer_index != Some(old_peer.index)
            || old_peer.peer_index != Some(old_host.index)
        {
            return Err(Error::Drifted);
        }
        crate::guarded::exact(
            &host.fixed_host_observation(end)?.snapshot(),
            &before.snapshot(),
        )?;
        if before
            .snapshot()
            .links
            .iter()
            .any(|l| l.index == index || l.name == old_host.name)
        {
            return Err(Error::Foreign);
        }
        let mut planned_host = old_host.clone();
        planned_host.index = index;
        let mut planned_peer = old_peer.clone();
        planned_peer.peer_index = Some(index);
        let mut expected = before.snapshot();
        expected.links.push(planned_host.clone());
        crate::guarded::exact(&expected, &after.snapshot())?;
        let mut message = LinkMessage::default();
        message.header.index = old_host.index;
        message.attributes.push(L::NetNsFd(target.as_raw_fd()));
        message.attributes.push(L::NewIfIndex(
            i32::try_from(index).map_err(|_| Error::InvalidInput)?,
        ));
        self.link_mutation(N::SetLink(message), end)?;
        self.absent(&old_host.name, end)?;
        let moved = host.new_token(&old_host.name, "veth", end)?;
        let peer = self.new_token(&old_peer.name, "veth", end)?;
        if host.owned_down(&moved, end)? != planned_host
            || self.owned_down(&peer, end)? != planned_peer
        {
            return Err(Error::Drifted);
        }
        crate::guarded::exact(
            &host.fixed_host_observation(end)?.snapshot(),
            &after.snapshot(),
        )?;
        complete(
            end,
            VethPair {
                host: moved,
                transport: peer,
            },
        )
    }
    fn fixed_host_observation(&mut self, end: Instant) -> Result<crate::HostObservation> {
        let observation = crate::HostObservation::from_snapshot(
            self.namespace,
            Snapshot {
                links: route_links(&mut self.route, end)?,
                addresses: route_addresses(&mut self.route, end)?,
                routes: route_routes(&mut self.route, end)?,
                rules: route_rules(&mut self.route, end)?,
                wireguard: None,
            },
        );
        observation.encode()?;
        complete(end, observation)
    }
    /// Fixed child only: both ends are exclusively born in this same original
    /// TRANSPORT namespace. HOST remains unchanged until a separate typed move.
    pub(crate) fn create_isolated_veth_pair_fixed(&mut self, end: Instant) -> Result<VethPair> {
        let host = self.plan.host_name().to_owned();
        let peer = self.plan.transport_name().to_owned();
        self.absent(&host, end)?;
        self.absent(&peer, end)?;
        let mut request = down_message(&host, &self.plan.alias);
        request.attributes.push(L::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::Data(InfoData::Veth(InfoVeth::Peer(down_message(
                &peer,
                &self.plan.alias,
            )))),
        ]));
        self.route
            .request(N::NewLink(request), 0x600, 16, Completion::Ack, end)?;
        let created_host = self.created_down(&host, "veth", end)?;
        let created_peer = self.created_down(&peer, "veth", end)?;
        if created_host.index == created_peer.index
            || created_host.peer_index != Some(created_peer.index)
            || created_peer.peer_index != Some(created_host.index)
        {
            return Err(Error::Drifted);
        }
        self.mark_created_down(&created_host, end)?;
        self.mark_created_down(&created_peer, end)?;
        let host = self.new_token(&host, "veth", end)?;
        let transport = self.new_token(&peer, "veth", end)?;
        self.owned_down(&host, end)?;
        self.owned_down(&transport, end)?;
        if host.link.peer_index != Some(transport.index())
            || transport.link.peer_index != Some(host.index())
        {
            return Err(Error::Drifted);
        }
        complete(end, VethPair { host, transport })
    }
    pub fn cleanup_wireguard_down(&mut self, token: DownLink) -> Result<()> {
        let end = deadline();
        let l = self.owned_down(&token, end)?;
        if l.name != self.plan.wireguard_name() || l.kind != "wireguard" {
            return Err(Error::Foreign);
        }
        self.configuration(l.index, end)?;
        let mut m = LinkMessage::default();
        m.header.index = l.index;
        self.link_mutation(N::DelLink(m), end)?;
        self.absent(&l.name, end)?;
        complete(end, ())
    }
    pub fn cleanup_veth_pair_down(&mut self, transport: &mut Self, pair: VethPair) -> Result<()> {
        // Local ifindices (including reciprocal peer indices) can collide
        // across unrelated namespace pairs. Bind BOTH callers to this original,
        // inseparable pair before any observation or deletion request.
        if self.namespace != pair.host.namespace
            || transport.namespace != pair.transport.namespace
            || self.namespace == transport.namespace
            || self.plan != transport.plan
        {
            return Err(Error::NamespaceUnverified);
        }
        let end = deadline();
        let h = self.owned_down(&pair.host, end)?;
        let t = transport.owned_down(&pair.transport, end)?;
        if self.plan.alias != transport.plan.alias
            || h.name != self.plan.host_name()
            || t.name != self.plan.transport_name()
            || h.kind != "veth"
            || t.kind != "veth"
            || h.peer_index != Some(t.index)
            || t.peer_index != Some(h.index)
        {
            return Err(Error::Foreign);
        }
        let mut m = LinkMessage::default();
        m.header.index = h.index;
        self.link_mutation(N::DelLink(m), end)?;
        self.absent(&h.name, end)?;
        transport.absent(&t.name, end)?;
        complete(end, ())
    }
}
fn down_message(name: &str, alias: &str) -> LinkMessage {
    let mut m = LinkMessage::default();
    m.header.change_mask = LinkFlags::Up;
    m.attributes = vec![
        L::IfName(name.into()),
        L::IfAlias(alias.into()),
        L::Mtu(1420),
    ];
    m
}
fn complete<T>(end: Instant, value: T) -> Result<T> {
    if Instant::now() >= end {
        Err(Error::Deadline)
    } else {
        Ok(value)
    }
}

fn route_links(route: &mut Socket, end: Instant) -> Result<Vec<Link>> {
    let mut out = Vec::new();
    for b in route.request(
        N::GetLink(LinkMessage::default()),
        0,
        16,
        Completion::Dump,
        end,
    )? {
        let N::NewLink(m) = project::route_message(&b)? else {
            return Err(Error::Malformed);
        };
        out.push(project::link(m)?);
    }
    Ok(out)
}
fn route_addresses(route: &mut Socket, end: Instant) -> Result<Vec<Address>> {
    let mut out = Vec::new();
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let mut m = AddressMessage::default();
        m.header.family = family;
        for b in route.request(N::GetAddress(m), 0, 20, Completion::Dump, end)? {
            let N::NewAddress(m) = project::route_message(&b)? else {
                return Err(Error::Malformed);
            };
            out.push(project::address(m)?);
        }
    }
    Ok(out)
}
fn route_routes(route: &mut Socket, end: Instant) -> Result<Vec<Route>> {
    let mut out = Vec::new();
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let mut m = RouteMessage::default();
        m.header.address_family = family;
        for b in route.request(N::GetRoute(m), 0, 24, Completion::Dump, end)? {
            let N::NewRoute(m) = project::route_message(&b)? else {
                return Err(Error::Malformed);
            };
            out.push(project::route(m)?);
        }
    }
    Ok(out)
}
fn route_rules(route: &mut Socket, end: Instant) -> Result<Vec<Rule>> {
    let mut out = Vec::new();
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let mut m = RuleMessage::default();
        m.header.family = family;
        for b in route.request(N::GetRule(m), 0, 32, Completion::Dump, end)? {
            let N::NewRule(m) = project::route_message(&b)? else {
                return Err(Error::Malformed);
            };
            out.push(project::rule(m)?);
        }
    }
    Ok(out)
}

fn declared_wan_message(
    message: LinkMessage,
    name: &str,
    index: u32,
    address: [u8; 6],
) -> Result<bool> {
    let matching_name = message
        .attributes
        .iter()
        .any(|a| matches!(a, L::IfName(n) if n == name));
    if message.header.index != index && !matching_name {
        return Ok(false);
    }
    let addresses: Vec<_> = message
        .attributes
        .iter()
        .filter_map(|a| match a {
            L::Address(a) => Some(a.as_slice()),
            _ => None,
        })
        .collect();
    if addresses.as_slice() != [address.as_slice()] {
        return Err(Error::Drifted);
    }
    let link = project::link(message)?;
    if link.name != name || link.index != index || link.hardware_type != 1 {
        return Err(Error::Drifted);
    }
    Ok(true)
}

/// Opaque, consuming observation state bound to its original route socket and
/// namespace. Dropping unfinished work leaves that socket unavailable for reuse.
pub struct DeclaredWanRead {
    name: String,
    index: u32,
    address: [u8; 6],
    namespace: NamespaceIdentity,
    expires_at: f64,
    end: Instant,
    exchange: RouteRead,
    finished: bool,
}
impl DeclaredWanRead {
    fn check(&self) -> Result<()> {
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now >= self.expires_at || Instant::now() >= self.end {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}

/// Dedicated read observer: exactly one NETLINK_ROUTE socket, never GENERIC.
/// Its immutable native namespace provenance is captured at socket creation.
pub struct RouteObserver {
    route: Socket,
    namespace: NamespaceIdentity,
}
impl RouteObserver {
    pub fn open() -> Result<Self> {
        let namespace = current_namespace()?;
        let route = Socket::open(false)?;
        if current_namespace()? != namespace {
            return Err(Error::NamespaceUnverified);
        }
        Ok(Self { route, namespace })
    }
    pub fn descriptor(&self) -> BorrowedFd<'_> {
        self.route.descriptor()
    }
    pub fn namespace_identity(&self) -> NamespaceIdentity {
        self.namespace
    }
    /// Compare an authored Ethernet uplink identity in this observer's original
    /// namespace. This observation grants neither link ownership nor permission
    /// to change routes, tables, addresses, or link state.
    pub fn start_declared_wan_read(
        &mut self,
        name: &str,
        index: u32,
        address: [u8; 6],
        expires_at: f64,
    ) -> Result<DeclaredWanRead> {
        let now = vprouter_core::health::boot_seconds();
        if !expires_at.is_finite() || !now.is_finite() || expires_at <= now || expires_at - now > 2.
        {
            return Err(Error::Deadline);
        }
        if name.is_empty()
            || name.len() > 15
            || index == 0
            || address == [0; 6]
            || address[0] & 1 != 0
        {
            return Err(Error::InvalidInput);
        }
        let end = Instant::now() + std::time::Duration::from_secs_f64(expires_at - now);
        let exchange = self
            .route
            .start_route_read(N::GetLink(LinkMessage::default()), end)?;
        Ok(DeclaredWanRead {
            name: name.into(),
            index,
            address,
            namespace: self.namespace,
            expires_at,
            end,
            exchange,
            finished: false,
        })
    }
    /// Advance the same original socket's read by at most one datagram. This
    /// returns only an authored-identity comparison, never mutation authority.
    pub fn poll_declared_wan_read(&mut self, read: &mut DeclaredWanRead) -> Result<bool> {
        if read.namespace != self.namespace
            || read.finished
            || !self.route.owns_route_read(&read.exchange)
        {
            return Err(Error::Foreign);
        }
        let result = (|| {
            read.check()?;
            let Some(messages) = self.route.poll_route_read(&mut read.exchange)? else {
                read.check()?;
                return Ok(false);
            };
            let mut selected = false;
            for bytes in messages {
                let N::NewLink(message) = project::route_message(&bytes)? else {
                    return Err(Error::Malformed);
                };
                if declared_wan_message(message, &read.name, read.index, read.address)?
                    && std::mem::replace(&mut selected, true)
                {
                    return Err(Error::Drifted);
                }
            }
            if !selected {
                return Err(Error::Drifted);
            }
            read.check()?;
            Ok(true)
        })();
        if !matches!(result, Ok(false)) {
            read.finished = true;
        }
        result
    }
    pub fn observe_until(&mut self, expires_at: f64) -> Result<crate::HostObservation> {
        self.observe_until_inner(expires_at, None::<fn() -> Result<()>>)
    }
    /// A single checkpoint after native links. No data, socket or replacement
    /// deadline is exposed; all remaining dumps retain the original two bounds.
    pub fn observe_until_checkpoint(
        &mut self,
        expires_at: f64,
        checkpoint: impl FnOnce() -> Result<()>,
    ) -> Result<crate::HostObservation> {
        self.observe_until_inner(expires_at, Some(checkpoint))
    }
    fn observe_until_inner(
        &mut self,
        expires_at: f64,
        checkpoint: Option<impl FnOnce() -> Result<()>>,
    ) -> Result<crate::HostObservation> {
        let now = vprouter_core::health::boot_seconds();
        if !expires_at.is_finite() || !now.is_finite() || expires_at <= now || expires_at - now > 2.
        {
            return Err(Error::Deadline);
        }
        let end = Instant::now() + std::time::Duration::from_secs_f64(expires_at - now);
        let links = route_links(&mut self.route, end)?;
        if let Some(checkpoint) = checkpoint {
            checkpoint()?;
            if Instant::now() >= end || vprouter_core::health::boot_seconds() >= expires_at {
                return Err(Error::Deadline);
            }
        }
        let observation = crate::HostObservation::from_snapshot(
            self.namespace,
            Snapshot {
                links,
                addresses: route_addresses(&mut self.route, end)?,
                routes: route_routes(&mut self.route, end)?,
                rules: route_rules(&mut self.route, end)?,
                wireguard: None,
            },
        );
        if Instant::now() >= end || vprouter_core::health::boot_seconds() >= expires_at {
            return Err(Error::Deadline);
        }
        Ok(observation)
    }
}

/// Mechanical lab-only pending native dump; it never yields a network token.
#[cfg(feature = "lab")]
pub struct LabRouteRead {
    read: RouteRead,
    end: f64,
}
#[cfg(feature = "lab")]
impl LabRouteRead {
    pub fn sent_sequence(&self) -> Option<u32> {
        self.read.lab_sent_sequence()
    }
    pub fn release(&mut self) -> Result<()> {
        if vprouter_core::health::boot_seconds() >= self.end {
            return Err(Error::Deadline);
        }
        self.read.lab_release()
    }
}
#[cfg(feature = "lab")]
impl RouteObserver {
    pub fn lab_start_pending_read(&mut self, end: f64) -> Result<LabRouteRead> {
        let instant = crate::secret_role::end_instant(end)?;
        let mut read = self
            .route
            .start_route_read(N::GetLink(LinkMessage::default()), instant)?;
        read.lab_hold();
        Ok(LabRouteRead { read, end })
    }
    pub fn lab_poll_pending_read(&mut self, read: &mut LabRouteRead) -> Result<Option<usize>> {
        if vprouter_core::health::boot_seconds() >= read.end {
            return Err(Error::Deadline);
        }
        let result = self
            .route
            .poll_route_read(&mut read.read)?
            .map(|messages| messages.len());
        if vprouter_core::health::boot_seconds() >= read.end {
            return Err(Error::Deadline);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_host_read_rejects_another_observer_then_completes_original_seven_dumps() {
        let mut original = RouteObserver::open().unwrap();
        let mut other = RouteObserver::open().unwrap();
        let original_sequence = original.route.sequence().unwrap();
        let other_sequence = other.route.sequence().unwrap();
        let end = vprouter_core::health::boot_seconds() + 2.;
        let mut read = original.start_host_read(end).unwrap();
        assert!(matches!(
            other.poll_host_read(&mut read),
            Err(Error::Foreign)
        ));
        assert_eq!(other.route.sequence().unwrap(), other_sequence);
        let mut polls = 0;
        let observation = loop {
            polls += 1;
            if let Some(observation) = original.poll_host_read(&mut read).unwrap() {
                break observation;
            }
            // No other transaction may enter between this operation's dumps.
            assert!(matches!(original.route.sequence(), Err(Error::Interrupted)));
            std::thread::yield_now();
        };
        observation.validate().unwrap();
        assert_eq!(observation.namespace, original.namespace_identity());
        assert!(observation.snapshot().wireguard.is_none());
        assert!(observation.snapshot().links.iter().any(|l| l.name == "lo"));
        assert!(polls >= 7);
        assert_eq!(original.route.sequence().unwrap(), original_sequence + 7);
        assert!(matches!(
            original.poll_host_read(&mut read),
            Err(Error::Foreign)
        ));
        assert!(vprouter_core::health::boot_seconds() < end);
    }
    #[test]
    fn full_host_read_never_renews_its_original_deadline() {
        let mut original = RouteObserver::open().unwrap();
        let end = vprouter_core::health::boot_seconds() + 0.03;
        let mut read = original.start_host_read(end).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(40));
        assert!(matches!(
            original.poll_host_read(&mut read),
            Err(Error::Deadline)
        ));
        assert!(matches!(
            original.poll_host_read(&mut read),
            Err(Error::Deadline)
        ));
        assert!(matches!(original.route.sequence(), Err(Error::Interrupted)));
    }
    #[test]
    fn declared_wan_read_rejects_other_observer_without_consuming_original_exchange() {
        let mut original = RouteObserver::open().unwrap();
        let mut other = RouteObserver::open().unwrap();
        let mut read = original
            .start_declared_wan_read(
                "vp-missing-wan",
                u32::MAX,
                [2, 4, 6, 8, 10, 12],
                vprouter_core::health::boot_seconds() + 2.,
            )
            .unwrap();
        assert_eq!(other.poll_declared_wan_read(&mut read), Err(Error::Foreign));
        assert!(!read.finished);
        let outcome = loop {
            match original.poll_declared_wan_read(&mut read) {
                Ok(false) => std::thread::yield_now(),
                value => break value,
            }
        };
        assert_eq!(outcome, Err(Error::Drifted));
        assert!(read.finished);
        assert_eq!(
            original.poll_declared_wan_read(&mut read),
            Err(Error::Foreign)
        );
        assert!(
            original
                .start_declared_wan_read(
                    "eth0",
                    2,
                    [2, 4, 6, 8, 10, 12],
                    vprouter_core::health::boot_seconds() - 1.
                )
                .is_err()
        );
    }

    #[test]
    fn authored_wan_identity_requires_the_same_name_index_and_mac() {
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let mut m = LinkMessage::default();
        m.header.index = 2;
        m.header.link_layer_type = netlink_packet_route::link::LinkLayerType::Ether;
        m.attributes = vec![
            L::IfName("ens2".into()),
            L::Mtu(1500),
            L::Address(mac.to_vec()),
        ];
        assert_eq!(declared_wan_message(m.clone(), "ens2", 2, mac), Ok(true));
        assert_eq!(declared_wan_message(m.clone(), "eth0", 3, mac), Ok(false));
        assert!(declared_wan_message(m.clone(), "eth0", 2, mac).is_err());
        assert!(declared_wan_message(m.clone(), "ens2", 3, mac).is_err());
        let mut wrong = mac;
        wrong[5] ^= 1;
        assert!(declared_wan_message(m.clone(), "ens2", 2, wrong).is_err());
        m.attributes.push(L::Address(mac.to_vec()));
        assert!(declared_wan_message(m, "ens2", 2, mac).is_err());
    }

    fn network(plan: &Plan, namespace: NamespaceIdentity) -> NativeNetwork {
        NativeNetwork {
            plan: plan.clone(),
            route: Socket::unavailable_for_test(),
            generic: Socket::unavailable_for_test(),
            family: None,
            namespace,
        }
    }
    fn pair(plan: &Plan, host: NamespaceIdentity, transport: NamespaceIdentity) -> VethPair {
        let endpoint = |name: &str, namespace| DownLink {
            link: Link {
                name: name.into(),
                index: 2,
                peer_index: Some(2),
                kind: "veth".into(),
                up: false,
                mtu: 1420,
                alias: plan.alias.clone(),
                hardware_type: 1,
                controller: 0,
                port_kind: String::new(),
                promiscuity: 0,
                all_multicast: 0,
                alternate_names: Vec::new(),
                tun_info: Vec::new(),
                max_pacing_offload_horizon: None,
                headroom: None,
                tailroom: None,
            },
            namespace,
        };
        VethPair {
            host: endpoint(plan.host_name(), host),
            transport: endpoint(plan.transport_name(), transport),
        }
    }
    #[test]
    fn colliding_veth_indices_in_other_namespace_pairs_refuse_before_io() {
        let plan = crate::tests::plan();
        let (h1, t1, h2, t2) = ((1, 11), (1, 12), (1, 21), (1, 22));
        let a = pair(&plan, h1, t1);
        let b = pair(&plan, h2, t2);
        // The public link facts and reciprocal indices cannot distinguish the
        // original two pairs. Their retained namespace identities must do so.
        assert_eq!(a.host.link, b.host.link);
        assert_eq!(a.transport.link, b.transport.link);
        assert_eq!((a.host().index(), a.transport().index()), (2, 2));
        assert_eq!(a.host().name(), plan.host_name());
        assert_eq!(a.transport().name(), plan.transport_name());
        // These sockets reject every request with SequenceMismatch, before any
        // I/O. NamespaceUnverified therefore proves refusal precedes all
        // observations and, in particular, deletion of either real peer.
        assert_eq!(
            network(&plan, h1).cleanup_veth_pair_down(&mut network(&plan, t2), a),
            Err(Error::NamespaceUnverified)
        );
        assert_eq!(
            network(&plan, h1).cleanup_veth_pair_down(&mut network(&plan, t2), b),
            Err(Error::NamespaceUnverified)
        );
    }
}
