//! Exact native activation behind retained independently verified quarantine.
use crate::{
    Address, DownLink, Error, Link, NativeNetwork, Result, Route, Snapshot, VethPair,
    audit::{expected_rules, same},
    socket::{Completion, deadline},
};
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

/// Non-clonable retained indices and exact expected kernel shapes. Deliberately
/// no caller constructor, mutable fields, readiness or activation booleans.
pub struct ActiveLinks {
    wg: DownLink,
    pair: VethPair,
    host_before: Snapshot,
    host_expected: Snapshot,
    transport_expected: Snapshot,
    data_expected: Snapshot,
}
impl ActiveLinks {
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
        self.bind(host, transport, data)?;
        let h = host.observe()?;
        let t = transport.observe()?;
        let d = data.observe()?;
        exact(&h, &self.host_expected).map_err(|_| Error::HostDrift)?;
        exact(&t, &self.transport_expected).map_err(|_| Error::TransportDrift)?;
        exact(&d, &self.data_expected).map_err(|_| Error::DataDrift)?;
        data.configuration(self.wg.index(), deadline())?;
        data.plan.bootstrap_structure(&d, self.wg.index())
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
        let mut after = host.observe()?;
        // No kernel generation value is used as namespace/allocation authority.
        let before = &self.host_before;
        after.wireguard = before.wireguard.clone();
        exact(&after, before)?;
        enforcement.cleanup_permits().map_err(|_| Error::Drifted)
    }
}
fn exact(actual: &Snapshot, expected: &Snapshot) -> Result<()> {
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
            Ok(ActiveLinks {
                wg,
                pair,
                host_before: hb,
                host_expected: hs,
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
    let mut link = token.clone();
    link.up = true;
    want.links.push(link);
    want.addresses.push(Address {
        broadcast: None,
        route_priority: None,
        flags: 0x80,
        index: token.index,
        address: hip.into(),
        prefix: 32,
        scope: 0,
    });
    want.routes.extend([
        local(hip, token.index),
        own_route(tip, 32, token.index, hip, None),
        multicast(token.index),
    ]);
    exact(s, &want)
}
