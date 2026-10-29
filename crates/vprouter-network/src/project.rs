//! Only bounded public structural facts leave this module. Raw WG replies and
//! private/preshared keys are never returned, serialized, formatted, or logged.
use crate::{Error, Result};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, Nla};
use netlink_packet_generic::GenlMessage;
use netlink_packet_route::{
    RouteNetlinkMessage,
    address::AddressAttribute as A,
    link::{InfoKind, LinkAttribute as L, LinkInfo},
    route::{RouteAddress, RouteAttribute as R},
    rule::RuleAttribute as U,
};
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIpAttr as I, WireguardAttribute as W, WireguardMessage,
    WireguardPeerAttribute as P,
};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub name: String,
    pub index: u32,
    pub kind: String,
    pub up: bool,
    pub mtu: u32,
    pub alias: String,
    pub peer_index: Option<u32>,
    pub hardware_type: u16,
    pub controller: u32,
    pub port_kind: String,
    pub promiscuity: u32,
    pub all_multicast: u32,
    pub alternate_names: Vec<String>,
    /// Bounded public TUN attributes, retained for exact host drift detection.
    pub tun_info: Vec<(u16, Vec<u8>)>,
    /// Exact Linux UAPI IFLA66/68/69; absence on older kernels is distinct.
    pub max_pacing_offload_horizon: Option<u32>,
    pub headroom: Option<u16>,
    pub tailroom: Option<u16>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    pub broadcast: Option<Ipv4Addr>,
    pub route_priority: Option<u32>,
    pub flags: u32,
    pub index: u32,
    pub address: IpAddr,
    pub prefix: u8,
    pub scope: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub nexthop_id: Option<u32>,
    pub preference: u8,
    pub destination: IpAddr,
    pub prefix: u8,
    pub table: u32,
    pub output: u32,
    pub source: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub kind: u8,
    pub scope: u8,
    pub protocol: u8,
    pub metric: u32,
    pub flags: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub ipv6: bool,
    pub priority: u32,
    pub table: u32,
    pub action: u8,
    pub flags: u32,
    pub fwmark: Option<u32>,
    pub fwmask: Option<u32>,
    pub suppress_prefixlen: Option<u32>,
    pub suppress_ifgroup: Option<u32>,
    pub goto: Option<u32>,
    pub realm: Option<u32>,
    pub protocol: Option<u8>,
}
impl Default for Rule {
    fn default() -> Self {
        Self {
            ipv6: false,
            priority: 0,
            table: 0,
            action: 1,
            flags: 0,
            fwmark: None,
            fwmask: None,
            suppress_prefixlen: Some(u32::MAX),
            suppress_ifgroup: None,
            goto: None,
            realm: None,
            protocol: Some(2),
        }
    }
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub public_key: [u8; 32],
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub handshake_unix: Option<f64>,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wireguard {
    pub index: u32,
    pub name: String,
    pub public_key: [u8; 32],
    pub peers: Vec<Peer>,
}

fn unique<'a, T: Nla + 'a>(attrs: impl IntoIterator<Item = &'a T>) -> Result<()> {
    let mut seen = HashSet::new();
    for a in attrs {
        if !seen.insert(a.kind() & 0x3fff) {
            return Err(Error::Malformed);
        }
    }
    Ok(())
}
pub(crate) fn route_message(bytes: &[u8]) -> Result<RouteNetlinkMessage> {
    preflight(bytes, false)?;
    match NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
        .map_err(|_| Error::Malformed)?
        .payload
    {
        NetlinkPayload::InnerMessage(v) => Ok(v),
        _ => Err(Error::Malformed),
    }
}
pub(crate) fn link(m: netlink_packet_route::link::LinkMessage) -> Result<Link> {
    unique(&m.attributes)?;
    #[cfg(test)]
    {
        static INVENTORY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !INVENTORY.swap(true, std::sync::atomic::Ordering::Relaxed) {
            let kinds: Vec<_> = m
                .attributes
                .iter()
                .take(128)
                .map(|a| (a.kind(), a.value_len()))
                .collect();
            eprintln!("LAB_LINK_ATTRIBUTE_INVENTORY kind_and_value_length={kinds:?}");
        }
    }
    let mut out = Link {
        name: String::new(),
        index: m.header.index,
        kind: String::new(),
        up: m.header.flags.bits() & 1 != 0,
        mtu: 0,
        alias: String::new(),
        peer_index: None,
        hardware_type: m.header.link_layer_type.into(),
        controller: 0,
        port_kind: String::new(),
        promiscuity: 0,
        all_multicast: 0,
        alternate_names: Vec::new(),
        tun_info: Vec::new(),
        max_pacing_offload_horizon: None,
        headroom: None,
        tailroom: None,
    };
    if m.header.index == 0 {
        return Err(Error::Malformed);
    }
    let mut tun_info = false;
    for a in m.attributes {
        let attribute_kind = a.kind();
        match a {
            L::IfName(n) => {
                if n.is_empty() || n.len() > 15 {
                    return Err(Error::Malformed);
                }
                out.name = n;
            }
            L::Mtu(v) => out.mtu = v,
            L::IfAlias(a) => {
                if a.len() > 255 {
                    return Err(Error::Oversized);
                }
                out.alias = a;
            }
            L::Link(v) => out.peer_index = Some(v),
            L::LinkInfo(infos) => {
                unique(&infos)?;
                for i in infos {
                    let info_kind = i.kind();
                    match i {
                        LinkInfo::Kind(k) => out.kind = k.to_string(),
                        LinkInfo::PortKind(k) => out.port_kind = k.to_string(),
                        LinkInfo::PortData(
                            netlink_packet_route::link::InfoPortData::BridgePort(_),
                        ) if out.port_kind == "bridge" => {}
                        LinkInfo::Data(netlink_packet_route::link::InfoData::Tun(info))
                            if out.kind == "tun" =>
                        {
                            unique(&info)?;
                            out.tun_info = info
                                .iter()
                                .map(|attribute| {
                                    let mut value = vec![0; attribute.value_len()];
                                    attribute.emit_value(&mut value);
                                    (attribute.kind(), value)
                                })
                                .collect();
                            out.tun_info.sort_unstable_by_key(|(kind, _)| *kind);
                            tun_info = true;
                        }
                        // Existing host Docker bridge metadata is observational;
                        // protected namespace audits reject every bridge kind.
                        LinkInfo::Data(netlink_packet_route::link::InfoData::Bridge(_))
                            if out.kind == "bridge" => {}
                        _ => return Err(Error::UnsupportedLinkInfo(info_kind)),
                    }
                }
            }
            L::Controller(v) => out.controller = v,
            L::Promiscuity(v) => out.promiscuity = v,
            L::AllMulticast(v) => out.all_multicast = v,
            L::PropList(props) => {
                for p in props {
                    match p {
                        netlink_packet_route::link::Prop::AltIfName(n)
                            if !n.is_empty()
                                && n.len() <= 127
                                && !out.alternate_names.contains(&n) =>
                        {
                            out.alternate_names.push(n)
                        }
                        _ => return Err(Error::Unsupported),
                    }
                }
            }
            L::ProtoDown(0) => {}
            L::Xdp(v)
                if v == [netlink_packet_route::link::LinkXdp::Attached(
                    netlink_packet_route::link::XdpAttached::None,
                )] => {}
            // IFLA_DEVLINK_PORT | NLA_F_NESTED (0x803e): an empty
            // bookkeeping nest is harmless; populated associations fail.
            L::DevlinkPort(v) if v.is_empty() => {}
            // IFLA_DPLL_PIN | NLA_F_NESTED (0x8041): only the empty
            // hardware-clock bookkeeping nest is tolerated.
            L::DpllPin(v) if v.is_empty() => {}
            // Pinned dependency predates these Linux UAPI fields. Decode only
            // exact unflagged scalar kinds/widths and retain canonical values
            // so declared host/owned link audits detect every later change.
            L::Other(v) if v.kind() == 66 && v.value_len() == 4 => {
                let mut bytes = [0; 4];
                v.emit_value(&mut bytes);
                out.max_pacing_offload_horizon = Some(u32::from_ne_bytes(bytes));
            }
            L::Other(v) if matches!(v.kind(), 68 | 69) && v.value_len() == 2 => {
                let mut bytes = [0; 2];
                v.emit_value(&mut bytes);
                let value = Some(u16::from_ne_bytes(bytes));
                if v.kind() == 68 {
                    out.headroom = value;
                } else {
                    out.tailroom = value;
                }
            }
            // Kernel bookkeeping: these do not supply another forwarding path.
            L::PermAddress(v) if v.len() <= 32 => {} // immutable physical hardware metadata, IFLA54
            // Observed Debian virtio hardware parent identifiers (IFLA56/57).
            // These describe hardware provenance, not a network controller.
            L::ParentDevName(v) | L::ParentDevBusName(v)
                if !v.is_empty() && v.len() <= 255 && !v.contains('\0') => {}
            L::Address(_)
            | L::Broadcast(_)
            | L::Qdisc(_)
            | L::TxQueueLen(_)
            | L::OperState(_)
            | L::Mode(_)
            | L::Group(_)
            | L::NumTxQueues(_)
            | L::NumRxQueues(_)
            | L::Carrier(_)
            | L::CarrierChanges(_)
            | L::CarrierUpCount(_)
            | L::CarrierDownCount(_)
            | L::GsoMaxSegs(_)
            | L::GsoMaxSize(_)
            | L::MinMtu(_)
            | L::MaxMtu(_)
            | L::GroMaxSize(_)
            | L::TsoMaxSize(_)
            | L::TsoMaxSegs(_)
            | L::GsoIpv4MaxSize(_)
            | L::GroIpv4MaxSize(_)
            | L::Stats(_)
            | L::Stats64(_)
            | L::Map(_)
            | L::AfSpecUnspec(_)
            | L::LinkNetNsId(_)
            | L::NetnsImmutable(_) => {}
            _ => {
                #[cfg(test)]
                eprintln!("LAB_UNSUPPORTED_LINK_ATTRIBUTE kind={attribute_kind}");
                return Err(Error::UnsupportedLinkAttribute(attribute_kind));
            }
        }
    }
    if out.name.is_empty() || out.mtu == 0 {
        return Err(Error::Malformed);
    }
    if (out.kind == "tun") != tun_info {
        return Err(Error::Malformed);
    }
    Ok(out)
}
// Fresh exact pinned-Go fixture: IFLA_TUN_TYPE=tun(1), PI=false,
// VNET_HDR=true, PERSIST=false, MULTI_QUEUE=false, no owner/group/queue attrs.
// These opaque dependency NLAs must not silently disappear from the projection.
pub(crate) fn fixed_tun_info(info: &[(u16, Vec<u8>)]) -> Result<()> {
    if info.len() != 5 {
        return Err(Error::Drifted);
    }
    for (kind, expected) in [(3, 1), (4, 0), (5, 1), (6, 0), (7, 0)] {
        let (_, value) = info
            .iter()
            .find(|(actual_kind, _)| *actual_kind == kind)
            .ok_or(Error::Drifted)?;
        if value.len() != 1 {
            return Err(Error::Malformed);
        }
        if value != &[expected] {
            return Err(Error::Drifted);
        }
    }
    Ok(())
}
pub(crate) fn address(m: netlink_packet_route::address::AddressMessage) -> Result<Address> {
    unique(&m.attributes)?;
    let mut flags = u32::from(m.header.flags.bits());
    let mut addr = None;
    let mut local = None;
    let mut broadcast = None;
    let mut route_priority = None;
    for a in m.attributes {
        let attribute_kind = a.kind();
        match a {
            A::Address(v) => addr = Some(v),
            A::Local(v) => local = Some(v),
            A::Broadcast(v) => broadcast = Some(v),
            A::RoutePriority(v) => route_priority = Some(v),
            A::Flags(f) => {
                if f.bits() & 0xff != flags {
                    return Err(Error::Malformed);
                }
                flags = f.bits();
            }
            A::Label(_) | A::CacheInfo(_) | A::Protocol(_) => {}
            _ => return Err(Error::UnsupportedAddressAttribute(attribute_kind)),
        }
    }
    if local.is_some() && addr.is_some() && local != addr {
        return Err(Error::Unsupported);
    }
    let address = local.or(addr).ok_or(Error::Malformed)?;
    let family: u8 = m.header.family.into();
    if !matches!((family, address), (2, IpAddr::V4(_)) | (10, IpAddr::V6(_)))
        || m.header.prefix_len > if address.is_ipv6() { 128 } else { 32 }
    {
        return Err(Error::Malformed);
    }
    Ok(Address {
        broadcast,
        route_priority,
        flags,
        index: m.header.index,
        address,
        prefix: m.header.prefix_len,
        scope: m.header.scope.into(),
    })
}
fn ip(a: RouteAddress) -> Result<IpAddr> {
    match a {
        RouteAddress::Inet(v) => Ok(v.into()),
        RouteAddress::Inet6(v) => Ok(v.into()),
        _ => Err(Error::Unsupported),
    }
}
pub(crate) fn route(m: netlink_packet_route::route::RouteMessage) -> Result<Route> {
    unique(&m.attributes)?;
    let h = m.header;
    let family: u8 = h.address_family.into();
    if h.source_prefix_length != 0 || h.tos != 0 || ![2, 10].contains(&family) {
        return Err(Error::Unsupported);
    }
    let mut out = Route {
        nexthop_id: None,
        preference: 0,
        destination: if family == 2 {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        },
        prefix: h.destination_prefix_length,
        table: u32::from(h.table),
        output: 0,
        source: None,
        gateway: None,
        kind: h.kind.into(),
        scope: h.scope.into(),
        protocol: h.protocol.into(),
        metric: 0,
        flags: h.flags.bits(),
    };
    for a in m.attributes {
        let attribute_kind = a.kind();
        match a {
            R::Destination(v) => out.destination = ip(v)?,
            R::Oif(v) => out.output = v,
            R::PrefSource(v) => out.source = Some(ip(v)?),
            R::Gateway(v) => out.gateway = Some(ip(v)?),
            R::Table(v) => {
                if h.table != 0 && u32::from(h.table) != v {
                    return Err(Error::Malformed);
                }
                out.table = v;
            }
            R::Priority(v) => out.metric = v,
            R::CacheInfo(_) => {}
            R::Preference(p) => out.preference = p.into(),
            R::NhId(id) if id != 0 => out.nexthop_id = Some(id),
            // In particular multipath, gateways-via, encapsulation, source rules,
            // nexthop IDs, marks, metrics/redirects are not silently projected away.
            _ => return Err(Error::UnsupportedRouteAttribute(attribute_kind)),
        }
    }
    if out.output == 0
        || out.prefix > if family == 2 { 32 } else { 128 }
        || out.destination.is_ipv6() != (family == 10)
        || out.source.is_some_and(|s| s.is_ipv6() != (family == 10))
        || out.gateway.is_some_and(|s| s.is_ipv6() != (family == 10))
    {
        return Err(Error::Malformed);
    }
    Ok(out)
}
pub(crate) fn rule(m: netlink_packet_route::rule::RuleMessage) -> Result<Rule> {
    unique(&m.attributes)?;
    let h = m.header;
    let family: u8 = h.family.into();
    if ![2, 10].contains(&family) || h.dst_len != 0 || h.src_len != 0 || h.tos != 0 {
        #[cfg(test)]
        eprintln!(
            "LAB_UNSUPPORTED_RULE_HEADER family={} dst={} src={} tos={} action={} flags={}",
            family,
            h.dst_len,
            h.src_len,
            h.tos,
            u8::from(h.action),
            h.flags.bits()
        );
        return Err(Error::Unsupported);
    }
    let mut out = Rule {
        ipv6: family == 10,
        priority: 0,
        table: u32::from(h.table),
        action: h.action.into(),
        flags: h.flags.bits(),
        fwmark: None,
        fwmask: None,
        suppress_prefixlen: None,
        suppress_ifgroup: None,
        goto: None,
        realm: None,
        protocol: None,
    };
    for a in m.attributes {
        #[cfg(test)]
        let diagnostic = (a.kind(), a.value_len());
        match a {
            U::Priority(v) => out.priority = v,
            U::Table(v) => {
                if h.table != 0 && u32::from(h.table) != v {
                    return Err(Error::Malformed);
                }
                out.table = v;
            }
            U::Protocol(p) => out.protocol = Some(p.into()),
            U::FwMark(v) => out.fwmark = Some(v),
            U::FwMask(v) => out.fwmask = Some(v),
            U::SuppressPrefixLen(v) => out.suppress_prefixlen = Some(v),
            U::SuppressIfGroup(v) => out.suppress_ifgroup = Some(v),
            U::Goto(v) => out.goto = Some(v),
            U::Realm(v) => out.realm = Some((u32::from(v.source) << 16) | u32::from(v.destination)),
            _ => {
                #[cfg(test)]
                {
                    eprintln!(
                        "LAB_UNSUPPORTED_RULE_ATTRIBUTE kind={} value_length={}",
                        diagnostic.0, diagnostic.1
                    );
                    if let U::SuppressPrefixLen(v) = a {
                        eprintln!("LAB_RULE_SUPPRESS_PREFIX_VALUE {v}");
                    }
                }
                return Err(Error::Unsupported);
            }
        }
    }
    Ok(out)
}
/// The maintained decoder does not zeroize partially built arrays/Vecs. It must
/// NEVER see secret bytes: sanitize a fixed-size Zeroizing copy before invoking
/// it, including before any dependency allocation/growth or later parse error.
fn sanitized_wireguard(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    preflight(bytes, true)?;
    let mut clean = Zeroizing::new(bytes.to_vec());
    scrub_wireguard_attrs(&mut clean[20..], WgLevel::Device, &mut 0)?;
    Ok(clean)
}
#[derive(Clone, Copy)]
enum WgLevel {
    Device,
    Peers,
    Peer,
    AllowedIps,
    AllowedIp,
}
fn scrub_wireguard_attrs(mut bytes: &mut [u8], level: WgLevel, count: &mut usize) -> Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(Error::Malformed);
        }
        let length = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let raw_kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        let kind = raw_kind & 0x3fff;
        let aligned = (length + 3) & !3;
        if length < 4 || aligned > bytes.len() || raw_kind & 0x4000 != 0 {
            return Err(Error::Malformed);
        }
        *count += 1;
        if *count > 2048 {
            return Err(Error::Oversized);
        }
        let (attribute, rest) = bytes.split_at_mut(aligned);
        let payload = &mut attribute[4..length];
        let nested = match (level, kind) {
            (WgLevel::Device, 8) => Some(WgLevel::Peers),
            (WgLevel::Peers, 0) => Some(WgLevel::Peer),
            (WgLevel::Peer, 9) => Some(WgLevel::AllowedIps),
            (WgLevel::AllowedIps, 0) => Some(WgLevel::AllowedIp),
            _ => None,
        };
        if let Some(next) = nested {
            // The dependency descends by semantic kind even without NESTED.
            // Mirror that grammar so a missing flag cannot hide a secret TLV.
            scrub_wireguard_attrs(payload, next, count)?;
        } else {
            if raw_kind & 0x8000 != 0 {
                return Err(Error::Unsupported);
            }
            match (level, kind) {
                (WgLevel::Device, 3) => {
                    if payload.len() != 32 {
                        return Err(Error::Malformed);
                    }
                    payload.zeroize();
                }
                (WgLevel::Peer, 2) => {
                    if payload.len() != 32 {
                        return Err(Error::Malformed);
                    }
                    let unsupported = payload.iter().any(|b| *b != 0);
                    payload.zeroize();
                    if unsupported {
                        return Err(Error::Unsupported);
                    }
                }
                (WgLevel::Device, 1 | 2 | 4 | 5 | 6 | 7)
                | (WgLevel::Peer, 1 | 3 | 4 | 5 | 6 | 7 | 8 | 10)
                | (WgLevel::AllowedIp, 1..=3) => (),
                _ => return Err(Error::Unsupported),
            }
        }
        bytes = rest;
    }
    Ok(())
}
pub(crate) fn wireguard(bytes: &[u8]) -> Result<Wireguard> {
    let clean = sanitized_wireguard(bytes)?;
    let mut msg = NetlinkMessage::<GenlMessage<WireguardMessage>>::deserialize(&clean)
        .map_err(|_| Error::Malformed)?;
    let result = (|| {
        let NetlinkPayload::InnerMessage(ref m) = msg.payload else {
            return Err(Error::Malformed);
        };
        if m.header.cmd != 0 || m.header.version != 1 {
            return Err(Error::Unsupported);
        }
        unique(&m.payload.attributes)?;
        let mut index = None;
        let mut name = None;
        let mut public = None;
        let mut peers = None;
        for a in &m.payload.attributes {
            match a {
                W::IfIndex(v) => index = Some(*v),
                W::IfName(v) => name = Some(v.clone()),
                W::PublicKey(v) => public = Some(*v),
                W::PrivateKey(_) | W::ListenPort(_) => {}
                W::Fwmark(0) => {}
                W::Peers(v) => {
                    let mut projected = Vec::new();
                    for p in v {
                        projected.push(peer(p)?);
                    }
                    peers = Some(projected);
                }
                _ => return Err(Error::Unsupported),
            }
        }
        Ok(Wireguard {
            index: index.ok_or(Error::Malformed)?,
            name: name.ok_or(Error::Malformed)?,
            public_key: public.ok_or(Error::Malformed)?,
            peers: peers.unwrap_or_default(),
        })
    })();
    // Defense in depth: typed secret slots are already zero BEFORE decode,
    // including every partial-decoder failure and Vec growth/free path. Keep
    // explicit cleanup too; the original/copy raw buffers have zeroizing owners.
    if let NetlinkPayload::InnerMessage(ref mut m) = msg.payload {
        for a in &mut m.payload.attributes {
            match a {
                W::PrivateKey(k) => k.zeroize(),
                W::Peers(p) => {
                    for p in p {
                        for a in &mut p.0 {
                            if let P::PresharedKey(k) = a {
                                k.zeroize();
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    result
}
fn peer(p: &netlink_packet_wireguard::WireguardPeer) -> Result<Peer> {
    unique(&p.0)?;
    let mut key = None;
    let mut endpoint = None;
    let mut allowed = None;
    let mut time = None;
    for a in &p.0 {
        match a {
            P::PublicKey(v) => key = Some(*v),
            P::Endpoint(v) => endpoint = Some(*v),
            P::AllowedIps(v) => {
                let mut ips = Vec::new();
                for i in v {
                    unique(&i.0)?;
                    let mut family = None;
                    let mut addr = None;
                    let mut prefix = None;
                    for a in &i.0 {
                        match a {
                            I::Family(f) => family = Some(*f),
                            I::IpAddr(ip) => addr = Some(*ip),
                            I::Cidr(p) => prefix = Some(*p),
                            _ => return Err(Error::Unsupported),
                        }
                    }
                    let ip = addr.ok_or(Error::Malformed)?;
                    if !matches!(
                        (family, ip),
                        (Some(WireguardAddressFamily::Ipv4), IpAddr::V4(_))
                            | (Some(WireguardAddressFamily::Ipv6), IpAddr::V6(_))
                    ) {
                        return Err(Error::Malformed);
                    }
                    ips.push((ip, prefix.ok_or(Error::Malformed)?));
                }
                allowed = Some(ips);
            }
            P::LastHandshake(t) => {
                if t.nano_seconds < 0 || t.nano_seconds >= 1_000_000_000 {
                    return Err(Error::Malformed);
                }
                time = Some(t.seconds as f64 + t.nano_seconds as f64 / 1e9);
            }
            P::PresharedKey(k) if *k == [0; 32] => {}
            P::PersistentKeepalive(0) | P::RxBytes(_) | P::TxBytes(_) | P::ProtocolVersion(1) => {}
            _ => return Err(Error::Unsupported),
        }
    }
    Ok(Peer {
        public_key: key.ok_or(Error::Malformed)?,
        endpoint: endpoint.ok_or(Error::Malformed)?,
        allowed_ips: allowed.ok_or(Error::Malformed)?,
        handshake_unix: time,
    })
}

pub(crate) fn wireguard_kind() -> LinkInfo {
    LinkInfo::Kind(InfoKind::Wireguard)
}

// Bounds and exact framing precede the maintained codecs. This is not another
// payload codec: payload interpretation/emission remains in rust-netlink.
pub(crate) fn preflight(bytes: &[u8], generic: bool) -> Result<()> {
    if bytes.len() > crate::socket::MAX_PACKET {
        return Err(Error::Oversized);
    }
    if bytes.len() < 16
        || u32::from_ne_bytes(bytes[..4].try_into().map_err(|_| Error::Malformed)?) as usize
            != bytes.len()
    {
        return Err(Error::Malformed);
    }
    let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
    let offset = if generic {
        20
    } else {
        match kind {
            16 => 32,
            20 => 24,
            24 | 32 => 28,
            _ => return Err(Error::Unsupported),
        }
    };
    let attrs = bytes.get(offset..).ok_or(Error::Malformed)?;
    let mut count = 0;
    check_attrs(attrs, 0, &mut count)?;
    if !generic && kind == 16 {
        // Veth's create-only nested peer can recursively contain LinkMessage.
        // It has no place in a GETLINK dump. Reject that grammar before parse.
        for a in netlink_packet_core::NlasIterator::new(attrs) {
            let a = a.map_err(|_| Error::Malformed)?;
            if a.kind() == 18 {
                for info in netlink_packet_core::NlasIterator::new(a.value()) {
                    let info = info.map_err(|_| Error::Malformed)?;
                    if info.kind() == 2 {
                        let observational_data = netlink_packet_core::NlasIterator::new(a.value())
                            .any(|v| {
                                v.is_ok_and(|v| {
                                    v.kind() == 1 && matches!(v.value(), b"tun\0" | b"bridge\0")
                                })
                            });
                        if !observational_data {
                            return Err(Error::Unsupported);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
fn check_attrs(mut bytes: &[u8], depth: usize, count: &mut usize) -> Result<()> {
    if depth > 8 {
        return Err(Error::Oversized);
    }
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(Error::Malformed);
        }
        let len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        if len < 4 || len > bytes.len() {
            return Err(Error::Malformed);
        }
        if u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x4000 != 0 {
            return Err(Error::Unsupported);
        }
        *count += 1;
        if *count > 2048 {
            return Err(Error::Oversized);
        }
        if u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x8000 != 0 {
            check_attrs(&bytes[4..len], depth + 1, count)?;
        }
        let aligned = (len + 3) & !3;
        if aligned > bytes.len() {
            return Err(Error::Malformed);
        }
        bytes = &bytes[aligned..];
    }
    Ok(())
}

#[cfg(test)]
mod secret_decode_tests {
    use super::*;
    fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = value.len() + 4;
        let mut out = vec![0; (length + 3) & !3];
        out[..2].copy_from_slice(&(length as u16).to_ne_bytes());
        out[2..4].copy_from_slice(&kind.to_ne_bytes());
        out[4..length].copy_from_slice(value);
        out
    }
    fn frame(attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0; 20];
        out[4..6].copy_from_slice(&30u16.to_ne_bytes());
        out[17] = 1;
        for a in attrs {
            out.extend(a);
        }
        let length = out.len() as u32;
        out[..4].copy_from_slice(&length.to_ne_bytes());
        out
    }
    #[test]
    fn malformed_after_private_key_never_passes_secret_to_typed_decoder() {
        let raw = frame(&[attr(3, &[77; 32]), attr(1, &[1, 2, 3])]);
        let clean = sanitized_wireguard(&raw).unwrap();
        assert!(clean[24..56].iter().all(|b| *b == 0));
        assert!(raw[24..56].iter().all(|b| *b == 77));
        assert!(NetlinkMessage::<GenlMessage<WireguardMessage>>::deserialize(&clean).is_err());
        assert_eq!(wireguard(&raw).err(), Some(Error::Malformed));
    }
    #[test]
    fn nested_psk_is_validated_before_erasure_even_without_nested_flags() {
        for nested in [0, 0x8000] {
            let good = frame(&[
                attr(3, &[77; 32]),
                attr(8 | nested, &attr(nested, &attr(2, &[0; 32]))),
            ]);
            sanitized_wireguard(&good).unwrap();
            let bad = frame(&[
                attr(3, &[77; 32]),
                attr(8 | nested, &attr(nested, &attr(2, &[88; 32]))),
            ]);
            assert_eq!(sanitized_wireguard(&bad).err(), Some(Error::Unsupported));
            assert_eq!(wireguard(&bad).err(), Some(Error::Unsupported));
        }
    }
    #[test]
    fn dependency_vector_growth_and_late_nested_failure_only_see_erased_keys() {
        let attrs = (0..65).map(|_| attr(3, &[77; 32])).collect::<Vec<_>>();
        let clean = sanitized_wireguard(&frame(&attrs)).unwrap();
        let decoded = NetlinkMessage::<GenlMessage<WireguardMessage>>::deserialize(&clean).unwrap();
        let NetlinkPayload::InnerMessage(message) = decoded.payload else {
            panic!("missing message")
        };
        assert_eq!(message.payload.attributes.len(), 65);
        assert!(
            message
                .payload
                .attributes
                .iter()
                .all(|a| matches!(a, W::PrivateKey(k) if *k == [0; 32]))
        );
        let raw = frame(&[
            attr(3, &[77; 32]),
            attr(
                8 | 0x8000,
                &attr(0x8000, &[attr(2, &[0; 32]), attr(6, &[0; 3])].concat()),
            ),
        ]);
        let clean = sanitized_wireguard(&raw).unwrap();
        assert!(!clean.windows(32).any(|v| v == [77; 32]));
        assert!(NetlinkMessage::<GenlMessage<WireguardMessage>>::deserialize(&clean).is_err());
    }
}
