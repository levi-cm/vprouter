use crate::{
    Address, Error, Link, Plan, Result, Route, Rule, Snapshot, Wireguard, project,
    socket::{Completion, Socket, deadline},
};
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

type NamespaceIdentity = (u64, u64);
fn current_namespace() -> Result<NamespaceIdentity> {
    let m = fs::metadata("/proc/thread-self/ns/net").map_err(|_| Error::NamespaceUnverified)?;
    Ok((m.dev(), m.ino()))
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
    link: Link,
    namespace: NamespaceIdentity,
}
impl DownLink {
    pub fn index(&self) -> u32 {
        self.link.index
    }
    pub fn name(&self) -> &str {
        &self.link.name
    }
}
pub struct VethPair {
    pub host: DownLink,
    pub transport: DownLink,
}

/// These two native sockets stay bound to their construction namespace even
/// when returned from a dedicated synchronous helper thread. No setns here.
pub struct NativeNetwork {
    plan: Plan,
    route: Socket,
    generic: Socket,
    family: Option<u16>,
    namespace: NamespaceIdentity,
}
impl NativeNetwork {
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
    fn links(&mut self, end: Instant) -> Result<Vec<Link>> {
        let mut out = Vec::new();
        for b in self.route.request(
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
    fn addresses(&mut self, end: Instant) -> Result<Vec<Address>> {
        let mut out = Vec::new();
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut m = AddressMessage::default();
            m.header.family = family;
            for b in self
                .route
                .request(N::GetAddress(m), 0, 20, Completion::Dump, end)?
            {
                let N::NewAddress(m) = project::route_message(&b)? else {
                    return Err(Error::Malformed);
                };
                out.push(project::address(m)?);
            }
        }
        Ok(out)
    }
    fn routes(&mut self, end: Instant) -> Result<Vec<Route>> {
        let mut out = Vec::new();
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut m = RouteMessage::default();
            m.header.address_family = family;
            for b in self
                .route
                .request(N::GetRoute(m), 0, 24, Completion::Dump, end)?
            {
                let N::NewRoute(m) = project::route_message(&b)? else {
                    return Err(Error::Malformed);
                };
                out.push(project::route(m)?);
            }
        }
        Ok(out)
    }
    fn rules(&mut self, end: Instant) -> Result<Vec<Rule>> {
        let mut out = Vec::new();
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut m = RuleMessage::default();
            m.header.family = family;
            for b in self
                .route
                .request(N::GetRule(m), 0, 32, Completion::Dump, end)?
            {
                let N::NewRule(m) = project::route_message(&b)? else {
                    return Err(Error::Malformed);
                };
                out.push(project::rule(m)?);
            }
        }
        Ok(out)
    }
    fn wireguard(&mut self, index: u32, end: Instant) -> Result<Wireguard> {
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
    fn absent(&mut self, name: &str, end: Instant) -> Result<()> {
        if self.links(end)?.iter().any(|l| l.name == name) {
            Err(Error::Foreign)
        } else {
            Ok(())
        }
    }
    fn owned_down(&mut self, token: &DownLink, end: Instant) -> Result<Link> {
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
    fn new_token(&mut self, name: &str, kind: &str, end: Instant) -> Result<DownLink> {
        let link = self
            .links(end)?
            .into_iter()
            .find(|l| l.name == name)
            .ok_or(Error::Absent)?;
        if link.kind != kind || link.alias != self.plan.alias || link.up || link.mtu != 1420 {
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
    fn link_mutation(&mut self, m: N, end: Instant) -> Result<()> {
        self.route
            .request(m, 0, 16, Completion::Ack, end)
            .map(|_| ())
    }
    /// Create initially DOWN, configure one peer in the transport birth namespace.
    /// Errors/ambiguous ACKs may leave an owned DOWN resource; reconcile first.
    pub fn create_wireguard_down(&mut self, profile: &Profile) -> Result<DownLink> {
        if !self.plan.matches_profile(profile) {
            return Err(Error::InvalidInput);
        }
        let end = deadline();
        let name = self.plan.wireguard_name().to_owned();
        self.absent(&name, end)?;
        let mut m = down_message(&name, &self.plan.alias);
        m.attributes
            .push(L::LinkInfo(vec![project::wireguard_kind()]));
        self.route
            .request(N::NewLink(m), 0x600, 16, Completion::Ack, end)?;
        let created = self.created_down(&name, "wireguard", end)?;
        if created.peer_index.is_some() {
            return Err(Error::Drifted);
        }
        self.mark_created_down(&created, end)?;
        let token = self.new_token(&name, "wireguard", end)?;
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
        let result = self.generic.request_borrowed(&m, family, end);
        for a in &mut m.payload.attributes {
            if let W::PrivateKey(k) = a {
                k.zeroize();
            }
        }
        result?;
        self.configuration(token.index(), end)?;
        self.owned_down(&token, end)?;
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
    fn configuration(&mut self, index: u32, end: Instant) -> Result<()> {
        let w = self.wireguard(index, end)?;
        if w.name != self.plan.wireguard_name()
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
