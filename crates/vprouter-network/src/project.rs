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
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    pub index: u32,
    pub kind: String,
    pub up: bool,
    pub mtu: u32,
    pub alias: String,
    pub peer_index: Option<u32>,
    pub hardware_type: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub index: u32,
    pub address: IpAddr,
    pub prefix: u8,
    pub scope: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq)]
pub struct Peer {
    pub public_key: [u8; 32],
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub handshake_unix: Option<f64>,
}
#[derive(Clone, Debug, PartialEq)]
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
    };
    if m.header.index == 0 {
        return Err(Error::Malformed);
    }
    for a in m.attributes {
        #[cfg(test)]
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
                    match i {
                        LinkInfo::Kind(k) => out.kind = k.to_string(),
                        LinkInfo::Data(netlink_packet_route::link::InfoData::Tun(_)) => {}
                        _ => return Err(Error::Unsupported),
                    }
                }
            }
            L::Controller(0) | L::ProtoDown(0) | L::Promiscuity(0) => {}
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
            // Kernel bookkeeping: these do not supply another forwarding path.
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
            | L::AllMulticast(_)
            | L::NetnsImmutable(_) => {}
            _ => {
                #[cfg(test)]
                eprintln!("LAB_UNSUPPORTED_LINK_ATTRIBUTE kind={attribute_kind}");
                return Err(Error::Unsupported);
            }
        }
    }
    if out.name.is_empty() || out.mtu == 0 {
        return Err(Error::Malformed);
    }
    Ok(out)
}
pub(crate) fn address(m: netlink_packet_route::address::AddressMessage) -> Result<Address> {
    unique(&m.attributes)?;
    if m.header.flags.bits() & !0x80 != 0 {
        return Err(Error::Unsupported);
    }
    let mut addr = None;
    let mut local = None;
    for a in m.attributes {
        match a {
            A::Address(v) => addr = Some(v),
            A::Local(v) => local = Some(v),
            A::Flags(f) if f.bits() & !0x80 == 0 => {}
            A::Label(_) | A::CacheInfo(_) | A::Protocol(_) => {}
            _ => return Err(Error::Unsupported),
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
            R::Preference(netlink_packet_route::route::RoutePreference::Medium) => {}
            // In particular multipath, gateways-via, encapsulation, source rules,
            // nexthop IDs, marks, metrics/redirects are not silently projected away.
            _ => return Err(Error::Unsupported),
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
pub(crate) fn wireguard(bytes: &[u8]) -> Result<Wireguard> {
    preflight(bytes, true)?;
    let mut msg = NetlinkMessage::<GenlMessage<WireguardMessage>>::deserialize(bytes)
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
    // Maintained codecs own temporary key copies; scrub them on success and on
    // projection failure. Decode failure is redacted; no erasure claim for its
    // internal temporary allocations or compiler/OS copies is made.
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
                        let tun = netlink_packet_core::NlasIterator::new(a.value())
                            .any(|v| v.is_ok_and(|v| v.kind() == 1 && v.value() == b"tun\0"));
                        if !tun {
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
