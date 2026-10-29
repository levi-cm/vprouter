use crate::*;
use std::{
    net::{Ipv4Addr, SocketAddr},
    os::fd::AsFd,
};
use vprouter_core::{allocation::AllocationRecord, config::Configuration, profile::Profile};
const SYNTHETIC_PROFILE:&[u8]=b"[Interface]\nPrivateKey=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress=10.64.1.2/32\n[Peer]\nPublicKey=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint=185.65.134.88:51820\nAllowedIPs=0.0.0.0/0\n";
pub(crate) fn fixture() -> (AllocationRecord, Profile) {
    let p = Profile::parse(SYNTHETIC_PROFILE, "de-fra-wg-401", None).unwrap();
    let config=Configuration::parse(serde_json::to_vec(&serde_json::json!({"schema_version":2,"deployment_id":"networklab","site":"debdev","gateway_image":format!("sha256:{}","a".repeat(64)),"exits":[{"id":"primary","enabled":true,"state_dir":"/state/primary","mode":{"kind":"mullvad","profile":"/synthetic/profile.conf","expected_server":"de-fra-wg-401"}}],"dependency_adapters":[],"client_policies":[]})).unwrap().as_slice()).unwrap().validate_with(|_,server|Profile::parse(SYNTHETIC_PROFILE,server,None)).unwrap();
    (AllocationRecord::from_configuration(&config, 7).unwrap(), p)
}
pub(crate) fn plan() -> Plan {
    let (r, p) = fixture();
    Plan::new(&r, "networklab", &r.exits[0], &p).unwrap()
}
#[allow(clippy::too_many_arguments)]
fn route(
    ip: &str,
    prefix: u8,
    table: u32,
    output: u32,
    source: Option<&str>,
    kind: u8,
    scope: u8,
    protocol: u8,
    metric: u32,
) -> Route {
    Route {
        nexthop_id: None,
        preference: 0,
        destination: ip.parse().unwrap(),
        prefix,
        table,
        output,
        source: source.map(|s| s.parse().unwrap()),
        gateway: None,
        kind,
        scope,
        protocol,
        metric,
        flags: 0,
    }
}
pub(crate) fn snapshot(p: &Plan) -> Snapshot {
    let links = vec![
        Link {
            name: "lo".into(),
            index: 1,
            kind: String::new(),
            up: true,
            mtu: 65536,
            alias: String::new(),
            peer_index: None,
            hardware_type: 772,
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
        Link {
            name: p.wireguard_name().into(),
            index: 4,
            kind: "wireguard".into(),
            up: true,
            mtu: 1420,
            alias: p.alias.clone(),
            peer_index: None,
            hardware_type: 65534,
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
    ];
    let addresses = vec![
        Address {
            broadcast: None,
            route_priority: None,
            flags: 0x80,
            index: 1,
            address: Ipv4Addr::LOCALHOST.into(),
            prefix: 8,
            scope: 254,
        },
        Address {
            broadcast: None,
            route_priority: None,
            flags: 0x80,
            index: 4,
            address: p.address.into(),
            prefix: 32,
            scope: 0,
        },
    ];
    // Independent literal expectations from disposable guest ip-route oracle;
    // never call the implementation's expected-route builder for this fixture.
    let routes = vec![
        route("127.0.0.0", 8, 255, 1, Some("127.0.0.1"), 2, 254, 2, 0),
        route("127.0.0.1", 32, 255, 1, Some("127.0.0.1"), 2, 254, 2, 0),
        route(
            "127.255.255.255",
            32,
            255,
            1,
            Some("127.0.0.1"),
            3,
            253,
            2,
            0,
        ),
        route("10.64.1.2", 32, 255, 4, Some("10.64.1.2"), 2, 254, 2, 0),
        route("ff00::", 8, 255, 4, None, 5, 0, 2, 256),
        route("0.0.0.0", 0, 254, 4, Some("10.64.1.2"), 1, 253, 4, 0),
    ];
    Snapshot {
        links,
        addresses,
        routes,
        rules: vec![
            Rule {
                ipv6: false,
                priority: 0,
                table: 255,
                ..Rule::default()
            },
            Rule {
                ipv6: false,
                priority: 32766,
                table: 254,
                ..Rule::default()
            },
            Rule {
                ipv6: false,
                priority: 32767,
                table: 253,
                ..Rule::default()
            },
            Rule {
                ipv6: true,
                priority: 0,
                table: 255,
                ..Rule::default()
            },
            Rule {
                ipv6: true,
                priority: 32766,
                table: 254,
                ..Rule::default()
            },
        ],
        wireguard: Some(Wireguard {
            index: 4,
            name: p.wireguard_name().into(),
            public_key: p.public_key,
            peers: vec![Peer {
                public_key: p.peer,
                endpoint: p.endpoint.into(),
                allowed_ips: vec![(Ipv4Addr::UNSPECIFIED.into(), 0)],
                handshake_unix: Some(990.0),
            }],
        }),
    }
}
#[test]
fn ipv4_only_bootstrap_requires_no_ipv6_metadata_and_exact_ipv4_routes() {
    let p = plan();
    let mut ipv4 = snapshot(&p);
    ipv4.routes.retain(|route| route.destination.is_ipv4());
    assert!(p.bootstrap_structure(&ipv4, 4).is_ok());

    let mut multicast = ipv4.clone();
    multicast
        .routes
        .push(route("ff00::", 8, 255, 4, None, 5, 0, 2, 256));
    assert!(p.bootstrap_structure(&multicast, 4).is_err());

    let mut address = ipv4.clone();
    address.addresses.push(Address {
        address: "::1".parse().unwrap(),
        prefix: 128,
        ..ipv4.addresses[0].clone()
    });
    assert!(p.bootstrap_structure(&address, 4).is_err());

    for fault in 0..5 {
        let mut changed = ipv4.clone();
        let default = changed.routes.iter_mut().find(|r| r.prefix == 0).unwrap();
        match fault {
            0 => default.table = 52,
            1 => default.output = 1,
            2 => default.flags = 16,
            3 => default.gateway = Some("192.0.2.1".parse().unwrap()),
            _ => {
                changed.routes.pop();
            }
        }
        assert!(p.bootstrap_structure(&changed, 4).is_err(), "fault {fault}");
    }
}

#[test]
fn matching_is_observational_and_absent_is_not_unverified() {
    let p = plan();
    let mut s = snapshot(&p);
    assert_eq!(p.audit(Some(&s), 4, 1000.0), Audit::StructurallyValid);
    assert_eq!(p.audit(None, 4, 1000.0), Audit::Unverified);
    s.links.pop();
    assert_eq!(p.audit(Some(&s), 4, 1000.0), Audit::Absent);
}
#[test]
fn full_record_mode_and_exact_membership_validated() {
    let (mut r, p) = fixture();
    let selected = r.exits[0].clone();
    r.exits.push(selected.clone());
    assert!(matches!(
        Plan::new(&r, "networklab", &selected, &p),
        Err(Error::InvalidInput)
    ));
    let (r, p) = fixture();
    let mut foreign = r.exits[0].clone();
    foreign.state_dir = "/other".into();
    assert!(matches!(
        Plan::new(&r, "networklab", &foreign, &p),
        Err(Error::Foreign)
    ));
    let mut cfg = serde_json::json!({"schema_version":2,"deployment_id":"directlab","site":"debdev","gateway_image":format!("sha256:{}","a".repeat(64)),"exits":[{"id":"direct","enabled":true,"state_dir":"/state/direct","mode":{"kind":"direct"}}],"dependency_adapters":[],"client_policies":[]});
    let c = Configuration::parse(&serde_json::to_vec(&cfg).unwrap())
        .unwrap()
        .validate()
        .unwrap();
    let r = AllocationRecord::from_configuration(&c, 1).unwrap();
    assert!(matches!(
        Plan::new(&r, "directlab", &r.exits[0], &p),
        Err(Error::DirectUnsupported)
    ));
    cfg["schema_version"] = 3.into();
    assert!(
        Configuration::parse(&serde_json::to_vec(&cfg).unwrap())
            .unwrap()
            .validate()
            .is_err()
    );
}
#[test]
fn wrong_kind_index_name_key_endpoint_handshake_are_rejected() {
    let p = plan();
    let mut faults: Vec<Snapshot> = Vec::new();
    for kind in ["dummy", "veth", "tun"] {
        let mut s = snapshot(&p);
        s.links[1].kind = kind.into();
        faults.push(s);
    }
    let mut s = snapshot(&p);
    s.links[1].index = 9;
    faults.push(s);
    let mut s = snapshot(&p);
    s.links[1].alias.push_str("foreign");
    faults.push(s);
    let mut s = snapshot(&p);
    s.links[1].up = false;
    faults.push(s);
    let mut s = snapshot(&p);
    s.wireguard.as_mut().unwrap().public_key = [3; 32];
    faults.push(s);
    let mut s = snapshot(&p);
    s.wireguard.as_mut().unwrap().name = "foreign".into();
    faults.push(s);
    let mut s = snapshot(&p);
    s.wireguard.as_mut().unwrap().index = 99;
    faults.push(s);
    let mut s = snapshot(&p);
    s.wireguard.as_mut().unwrap().peers[0].public_key = [3; 32];
    faults.push(s);
    let mut s = snapshot(&p);
    s.wireguard.as_mut().unwrap().peers[0].endpoint =
        "185.65.134.89:51820".parse::<SocketAddr>().unwrap();
    faults.push(s);
    let mut s = snapshot(&p);
    let w = s.wireguard.as_mut().unwrap();
    w.peers.push(w.peers[0].clone());
    faults.push(s);
    let mut s = snapshot(&p);
    s.wireguard.as_mut().unwrap().peers[0]
        .allowed_ips
        .push(("::".parse().unwrap(), 0));
    faults.push(s);
    for s in faults {
        assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    }
    for time in [
        None,
        Some(0.0),
        Some(-1.0),
        Some(f64::NAN),
        Some(f64::INFINITY),
        Some(1001.0),
        Some(820.0),
    ] {
        let mut s = snapshot(&p);
        s.wireguard.as_mut().unwrap().peers[0].handshake_unix = time;
        assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    }
    let mut s = snapshot(&p);
    s.wireguard.as_mut().unwrap().peers[0].handshake_unix = Some(820.001);
    assert_eq!(p.audit(Some(&s), 4, 1000.0), Audit::StructurallyValid);
    for now in [0.0, -1.0, f64::NAN, f64::INFINITY] {
        assert!(matches!(p.audit(Some(&s), 4, now), Audit::Rejected(_)));
    }
}
#[test]
fn restored_default_endpoint_docker_extra_routes_rules_interfaces_and_ipv6_rejected() {
    let p = plan();
    let base = snapshot(&p);
    for (destination, prefix, output, table, gateway) in [
        ("0.0.0.0", 0, 9, 254, Some("10.0.0.1")),
        ("185.65.134.88", 32, 9, 254, None),
        ("172.17.0.0", 16, 9, 254, None),
        ("0.0.0.0", 0, 9, 52, None),
        ("::", 0, 4, 254, None),
        ("2001:db8::", 32, 4, 254, None),
    ] {
        let mut s = base.clone();
        let mut r = s.routes.last().unwrap().clone();
        r.destination = destination.parse().unwrap();
        r.prefix = prefix;
        r.output = output;
        r.table = table;
        r.gateway = gateway.map(|v| v.parse().unwrap());
        s.routes.push(r);
        assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    }
    let mut s = base.clone();
    s.routes.last_mut().unwrap().gateway = Some("10.0.0.1".parse().unwrap());
    assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    let mut s = base.clone();
    s.rules.push(Rule {
        ipv6: false,
        priority: 1,
        table: 52,
        ..Rule::default()
    });
    assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    let mut s = base.clone();
    s.rules.remove(0);
    assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    let mut s = base.clone();
    let mut l = s.links[0].clone();
    l.index = 10;
    l.name = "docker0".into();
    s.links.push(l);
    assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    for address in ["10.64.1.3", "fe80::1", "2001:db8::1", "::1"] {
        let mut s = base.clone();
        s.addresses.push(Address {
            broadcast: None,
            route_priority: None,
            flags: 0x80,
            index: 4,
            address: address.parse().unwrap(),
            prefix: if address.contains(':') { 128 } else { 32 },
            scope: 0,
        });
        assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    }
}
#[test]
fn wrong_source_and_missing_default_or_address_rejected() {
    let p = plan();
    for mutate in [0, 1, 2] {
        let mut s = snapshot(&p);
        match mutate {
            0 => s.routes.last_mut().unwrap().source = Some("10.64.1.3".parse().unwrap()),
            1 => {
                s.routes.pop();
            }
            _ => {
                s.addresses.pop();
            }
        }
        assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    }
}
#[test]
fn local_loopback_and_narrow_tailscale_ipv6_supported_but_no_forward_path() {
    let p = plan();
    let mut s = snapshot(&p);
    s.links.push(Link {
        name: "tailscale0".into(),
        index: 5,
        kind: "tun".into(),
        up: true,
        mtu: 1280,
        alias: String::new(),
        peer_index: None,
        hardware_type: 65534,
        controller: 0,
        port_kind: String::new(),
        promiscuity: 0,
        all_multicast: 0,
        alternate_names: Vec::new(),
        tun_info: Vec::new(),
        max_pacing_offload_horizon: None,
        headroom: None,
        tailroom: None,
    });
    for (index, address, scope) in [
        (1, "::1", 254),
        (5, "100.64.1.2", 0),
        (5, "fd7a:115c:a1e0::1", 0),
    ] {
        s.addresses.push(Address {
            broadcast: None,
            route_priority: None,
            flags: 0x80,
            index,
            address: address.parse().unwrap(),
            prefix: if address.contains(':') { 128 } else { 32 },
            scope,
        });
    }
    s.routes.extend([
        route("::1", 128, 255, 1, None, 2, 0, 2, 0),
        route("100.64.1.2", 32, 255, 5, Some("100.64.1.2"), 2, 254, 2, 0),
        route("fd7a:115c:a1e0::1", 128, 255, 5, None, 2, 0, 2, 0),
        route("fd7a:115c:a1e0::1", 128, 254, 5, None, 1, 0, 2, 256),
        route("ff00::", 8, 255, 5, None, 5, 0, 2, 256),
    ]);
    assert_eq!(p.audit(Some(&s), 4, 1000.0), Audit::StructurallyValid);
    let mut extra = s.routes.last().unwrap().clone();
    extra.destination = "fd7a:115c:a1e0::".parse().unwrap();
    extra.prefix = 48;
    extra.output = 5;
    s.routes.push(extra);
    assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
}
#[test]
fn private_material_never_enters_public_projection_or_fixed_errors() {
    use netlink_packet_core::NetlinkMessage;
    use netlink_packet_generic::GenlMessage;
    use netlink_packet_wireguard::{WireguardAttribute as W, WireguardCmd, WireguardMessage};
    let mut message = GenlMessage::from_payload(WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes: vec![
            W::IfIndex(4),
            W::IfName("wgsynthetic".into()),
            W::PrivateKey([77; 32]),
            W::PublicKey([2; 32]),
            W::Fwmark(0),
        ],
    });
    message.set_resolved_family_id(30);
    let mut n = NetlinkMessage::from(message);
    n.finalize();
    let mut bytes = vec![0; n.buffer_len()];
    n.serialize(&mut bytes);
    let p = crate::project::wireguard(&bytes).unwrap();
    let output = format!("{p:?}");
    assert!(!output.contains("PrivateKey"));
    assert!(!output.contains("77, 77"));
    assert!(!output.contains("Preshared"));
    bytes[20..24].copy_from_slice(&[1, 0, 0, 0]);
    let e = crate::project::wireguard(&bytes).unwrap_err();
    assert_eq!(e, Error::Malformed);
    assert_eq!(e.to_string(), "Malformed");
}
#[test]
fn multipath_encapsulation_rules_and_malformed_attributes_fail_closed() {
    use netlink_packet_route::{
        route::{RouteAttribute as R, RouteMessage},
        rule::{RuleAttribute as U, RuleMessage},
    };
    let mut route = RouteMessage::default();
    route.header.address_family = netlink_packet_route::AddressFamily::Inet;
    route.attributes.push(R::MultiPath(Vec::new()));
    assert!(matches!(
        crate::project::route(route),
        Err(Error::UnsupportedRouteAttribute(_))
    ));
    let mut route = RouteMessage::default();
    route.header.address_family = netlink_packet_route::AddressFamily::Inet;
    route.attributes.extend([R::NhId(7), R::Oif(2)]);
    assert_eq!(crate::project::route(route).unwrap().nexthop_id, Some(7));
    let p = plan();
    let mut protected = snapshot(&p);
    protected.routes[0].nexthop_id = Some(7);
    assert_eq!(
        p.audit(Some(&protected), 4, 1000.0),
        Audit::Rejected(Error::Drifted)
    );
    let mut rule = RuleMessage::default();
    rule.header.family = netlink_packet_route::AddressFamily::Inet;
    rule.header.action = netlink_packet_route::rule::RuleAction::ToTable;
    rule.attributes.push(U::FwMark(1));
    assert_eq!(crate::project::rule(rule).unwrap().fwmark, Some(1));
    let mut bytes = vec![0; crate::socket::MAX_PACKET + 1];
    assert_eq!(
        crate::project::preflight(&bytes, true),
        Err(Error::Oversized)
    );
    bytes.truncate(23);
    bytes[..4].copy_from_slice(&23u32.to_ne_bytes());
    assert_eq!(
        crate::project::preflight(&bytes, true),
        Err(Error::Malformed)
    );
    let file = std::fs::File::open("/dev/null").unwrap();
    assert!(matches!(
        NamespaceTarget::from_trusted_network_namespace(file.as_fd()),
        Err(Error::NamespaceUnverified)
    ));
}

#[test]
fn only_empty_hardware_metadata_and_explicit_no_xdp_are_bookkeeping() {
    use netlink_packet_route::link::{
        DevlinkPort, DpllPin, LinkAttribute as L, LinkMessage, LinkXdp, XdpAttached,
    };
    let mut m = LinkMessage::default();
    m.header.index = 1;
    m.attributes = vec![
        L::IfName("lo".into()),
        L::Mtu(65536),
        L::DevlinkPort(vec![]),
        L::DpllPin(vec![]),
        L::Xdp(vec![LinkXdp::Attached(XdpAttached::None)]),
    ];
    assert!(crate::project::link(m.clone()).is_ok());
    for extra in [
        L::DevlinkPort(vec![DevlinkPort::PortIndex(1)]),
        L::DpllPin(vec![DpllPin::PinId(1)]),
        L::Xdp(vec![LinkXdp::Attached(XdpAttached::Driver)]),
    ] {
        let mut x = m.clone();
        x.attributes
            .retain(|a| !matches!(a, L::DevlinkPort(_) | L::DpllPin(_) | L::Xdp(_)));
        x.attributes.push(extra);
        assert!(matches!(
            crate::project::link(x),
            Err(Error::UnsupportedLinkAttribute(_))
        ));
    }
}

#[test]
fn rule_suppression_is_retained_not_silently_discarded() {
    use netlink_packet_route::{
        AddressFamily,
        rule::{RuleAction, RuleAttribute as U, RuleMessage},
    };
    let mut m = RuleMessage::default();
    m.header.family = AddressFamily::Inet;
    m.header.action = RuleAction::ToTable;
    m.header.table = 255;
    m.attributes = vec![U::SuppressPrefixLen(u32::MAX)];
    assert_eq!(
        crate::project::rule(m.clone()),
        Ok(Rule {
            ipv6: false,
            priority: 0,
            table: 255,
            protocol: None,
            ..Rule::default()
        })
    );
    for prefix in [0, 1, 32, 128, u32::MAX - 1] {
        m.attributes = vec![U::SuppressPrefixLen(prefix)];
        assert_eq!(
            crate::project::rule(m.clone()).unwrap().suppress_prefixlen,
            Some(prefix)
        );
    }
}

#[test]
fn independent_pinned_daemon_raw_rules_preserve_all_functional_metadata() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/tailscale-rules.json")).unwrap();
    let mut projected = Vec::new();
    for value in fixture["rules"].as_array().unwrap() {
        let text = value["payload_hex"].as_str().unwrap();
        let payload: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        let mut bytes = vec![0; 16];
        bytes.extend_from_slice(&payload);
        let n = bytes.len() as u32;
        bytes[..4].copy_from_slice(&n.to_ne_bytes());
        bytes[4..6].copy_from_slice(&32u16.to_ne_bytes());
        let message = crate::project::route_message(&bytes).unwrap();
        let netlink_packet_route::RouteNetlinkMessage::NewRule(message) = message else {
            panic!("rule expected")
        };
        if ![2, 10].contains(&payload[0]) {
            assert_eq!(crate::project::rule(message), Err(Error::Unsupported));
            continue;
        }
        let rule = crate::project::rule(message).unwrap();
        assert_eq!(rule.suppress_prefixlen, Some(u32::MAX));
        assert_eq!(rule.suppress_ifgroup, None);
        assert_eq!(rule.goto, None);
        assert_eq!(rule.realm, None);
        assert_eq!(rule.flags, 0);
        match rule.priority {
            5210 | 5230 => {
                assert_eq!(rule.action, 1);
                assert_eq!(rule.fwmark, Some(0x80000));
                assert_eq!(rule.fwmask, Some(0xff0000));
                assert_eq!(rule.protocol, Some(0));
            }
            5250 => {
                assert_eq!(rule.action, 7);
                assert_eq!(rule.table, 0);
                assert_eq!(rule.fwmark, Some(0x80000));
                assert_eq!(rule.fwmask, Some(0xff0000));
                assert_eq!(rule.protocol, Some(0));
            }
            5270 => {
                assert_eq!(rule.table, 52);
                assert_eq!(rule.action, 1);
                assert_eq!(rule.fwmark, None);
                assert_eq!(rule.protocol, Some(0));
            }
            _ => {
                assert_eq!(rule.protocol, Some(2));
                assert_eq!(rule.action, 1);
                assert_eq!(rule.fwmark, None);
            }
        }
        projected.push(rule);
    }
    assert_eq!(projected.len(), 13);
    // This no-login oracle is not permission to accept unbound Tailscale policy.
    let p = plan();
    let mut s = snapshot(&p);
    s.rules = projected;
    assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    let base = snapshot(&p);
    for mutate in 0..9 {
        let mut s = base.clone();
        let r = &mut s.rules[0];
        match mutate {
            0 => r.action = 7,
            1 => r.flags = 2,
            2 => r.fwmark = Some(0),
            3 => r.fwmask = Some(u32::MAX),
            4 => r.suppress_prefixlen = Some(0),
            5 => r.suppress_ifgroup = Some(0),
            6 => r.goto = Some(0),
            7 => r.realm = Some(0),
            _ => r.protocol = Some(0),
        }
        assert!(matches!(p.audit(Some(&s), 4, 1000.0), Audit::Rejected(_)));
    }
}

#[test]
fn host_metadata_is_observed_but_protected_link_authority_stays_exact() {
    use netlink_packet_route::link::{LinkAttribute as L, LinkMessage, Prop};
    let mut m = LinkMessage::default();
    m.header.index = 44;
    m.attributes = vec![
        L::IfName("ens2".into()),
        L::Mtu(1500),
        L::Controller(3),
        L::Promiscuity(1),
        L::AllMulticast(1),
        L::PropList(vec![Prop::AltIfName("enp0s2".into())]),
        L::PermAddress(vec![1, 2, 3, 4, 5, 6]),
        L::ParentDevName("virtio0".into()),
        L::ParentDevBusName("virtio".into()),
    ];
    let observed = crate::project::link(m.clone()).unwrap();
    assert_eq!(observed.controller, 3);
    assert_eq!(observed.promiscuity, 1);
    assert_eq!(observed.all_multicast, 1);
    assert_eq!(observed.alternate_names, ["enp0s2"]);
    for extra in [
        L::ParentDevName(String::new()),
        L::ParentDevBusName("x".repeat(256)),
        L::PermAddress(vec![0; 33]),
    ] {
        let mut bad = m.clone();
        bad.attributes.retain(|a| {
            !matches!(
                a,
                L::ParentDevName(_) | L::ParentDevBusName(_) | L::PermAddress(_)
            )
        });
        bad.attributes.push(extra);
        assert!(crate::project::link(bad).is_err());
    }
    let p = plan();
    for field in 0..5 {
        let mut protected = snapshot(&p);
        let link = &mut protected.links[1];
        match field {
            0 => link.controller = 3,
            1 => link.port_kind = "bridge".into(),
            2 => link.promiscuity = 1,
            3 => link.all_multicast = 1,
            4 => link.alternate_names.push("foreign".into()),
            _ => unreachable!(),
        }
        assert_eq!(
            p.audit(Some(&protected), 4, 1000.0),
            Audit::Rejected(Error::Drifted)
        );
    }
}

#[test]
fn raw_host_bridge_data_is_bounded_and_veth_peer_grammar_still_rejected() {
    use netlink_packet_core::NetlinkMessage;
    use netlink_packet_route::{
        RouteNetlinkMessage,
        link::{InfoData, InfoKind, InfoVeth, LinkAttribute as L, LinkInfo, LinkMessage},
    };
    fn bytes(kind: InfoKind, data: InfoData) -> Vec<u8> {
        let mut m = LinkMessage::default();
        m.header.index = 3;
        m.attributes = vec![
            L::IfName("docker0".into()),
            L::Mtu(1500),
            L::LinkInfo(vec![LinkInfo::Kind(kind), LinkInfo::Data(data)]),
        ];
        let mut n = NetlinkMessage::from(RouteNetlinkMessage::NewLink(m));
        n.finalize();
        let mut b = vec![0; n.buffer_len()];
        n.serialize(&mut b);
        b
    }
    let bridge = bytes(InfoKind::Bridge, InfoData::Bridge(vec![]));
    let netlink_packet_route::RouteNetlinkMessage::NewLink(m) =
        crate::project::route_message(&bridge).unwrap()
    else {
        panic!()
    };
    assert_eq!(crate::project::link(m).unwrap().kind, "bridge");
    let peer = bytes(
        InfoKind::Veth,
        InfoData::Veth(InfoVeth::Peer(LinkMessage::default())),
    );
    assert!(crate::project::route_message(&peer).is_err());
}
#[test]
fn unrelated_host_tun_metadata_is_retained_without_owned_daemon_policy() {
    use netlink_packet_core::DefaultNla;
    use netlink_packet_route::link::{
        InfoData, InfoKind, InfoTun, LinkAttribute as L, LinkInfo, LinkMessage,
    };
    let check = |vnet_header| {
        let mut message = LinkMessage::default();
        message.header.index = 12;
        message.attributes = vec![
            L::IfName("vpn0".into()),
            L::Mtu(1500),
            L::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Tun),
                LinkInfo::Data(InfoData::Tun(
                    [(3, 1), (4, 0), (5, vnet_header), (6, 1), (7, 1)]
                        .into_iter()
                        .map(|(kind, value)| InfoTun::Other(DefaultNla::new(kind, vec![value])))
                        .collect(),
                )),
            ]),
        ];
        crate::project::link(message)
    };
    let original = check(0).expect("an unrelated persistent multiqueue host TUN is observable");
    let changed = check(1).expect("changed host TUN metadata is observable");
    assert_ne!(original, changed, "host TUN drift must remain visible");
}

#[test]
fn native_tun_info_requires_all_exact_fixed_values_and_no_unknown_duplicate_or_wide_attributes() {
    use netlink_packet_core::DefaultNla;
    use netlink_packet_route::link::{
        InfoData, InfoKind, InfoTun, LinkAttribute as L, LinkInfo, LinkMessage,
    };
    let fixed: Vec<_> = [(3, 1), (4, 0), (5, 1), (6, 0), (7, 0)]
        .into_iter()
        .map(|(k, v)| InfoTun::Other(DefaultNla::new(k, vec![v])))
        .collect();
    let check = |info| {
        let mut m = LinkMessage::default();
        m.header.index = 9;
        m.attributes = vec![
            L::IfName("tailscale0".into()),
            L::Mtu(1280),
            L::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Tun),
                LinkInfo::Data(InfoData::Tun(info)),
            ]),
        ];
        crate::project::link(m).and_then(|link| crate::project::fixed_tun_info(&link.tun_info))
    };
    assert!(check(fixed.clone()).is_ok());
    for i in 0..5 {
        let mut info = fixed.clone();
        info[i] = InfoTun::Other(DefaultNla::new((i + 3) as u16, vec![9]));
        assert!(check(info).is_err());
    }
    for extra in [
        DefaultNla::new(3, vec![1]),
        DefaultNla::new(1, vec![0; 4]),
        DefaultNla::new(8, vec![1; 4]),
        DefaultNla::new(100, vec![0]),
    ] {
        let mut info = fixed.clone();
        info.push(InfoTun::Other(extra));
        assert!(check(info).is_err());
    }
    let mut missing = fixed.clone();
    missing.pop();
    assert!(check(missing).is_err());
    let mut wide = fixed;
    wide[0] = InfoTun::Other(DefaultNla::new(3, vec![1, 0, 0, 0]));
    assert!(check(wide).is_err());
}

#[test]
fn dynamic_host_address_flags_are_retained_and_protected_dynamic_flags_rejected() {
    use netlink_packet_route::{
        AddressFamily,
        address::{AddressAttribute as A, AddressFlags, AddressMessage},
    };
    let mut m = AddressMessage::default();
    m.header.index = 2;
    m.header.family = AddressFamily::Inet6;
    m.header.prefix_len = 64;
    m.attributes = vec![
        A::Address("fe80::1".parse().unwrap()),
        A::Flags(AddressFlags::from_bits_retain(0x300)),
    ];
    let observed = crate::project::address(m.clone()).unwrap();
    assert_eq!(observed.flags, 0x300);
    m.header.flags = netlink_packet_route::address::AddressHeaderFlags::from_bits_retain(0x80);
    assert!(matches!(crate::project::address(m), Err(Error::Malformed)));
    let p = plan();
    let mut protected = snapshot(&p);
    protected.addresses[1].flags = 0x300;
    assert_eq!(
        p.audit(Some(&protected), 4, 1000.0),
        Audit::Rejected(Error::Drifted)
    );
}

#[test]
fn complete_local_host_rtm_oracle_projects_without_discarding_forwarding_fields() {
    use netlink_packet_route::RouteNetlinkMessage as N;
    let messages: Vec<String> =
        serde_json::from_str(include_str!("../tests/fixtures/task8a-local-host-rtm.json")).unwrap();
    let mut broadcast = false;
    let mut priority = false;
    let mut indirect = false;
    let mut flags = false;
    for hex in messages {
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        match crate::project::route_message(&bytes).unwrap() {
            N::NewAddress(m) => {
                let a = crate::project::address(m).unwrap();
                broadcast |= a.broadcast.is_some();
                priority |= a.route_priority.is_some();
                flags |= a.flags & !0x80 != 0;
            }
            N::NewRoute(m) => {
                let r = crate::project::route(m).unwrap();
                indirect |= r.nexthop_id.is_some();
            }
            _ => panic!("unexpected oracle message"),
        }
    }
    assert!(broadcast && priority && indirect && flags);
}

#[test]
fn pacing_horizon_and_buffer_room_are_typed_exact_retained_metadata() {
    use netlink_packet_core::DefaultNla;
    use netlink_packet_route::link::{LinkAttribute as L, LinkMessage};
    let message = |kind, value| {
        let mut m = LinkMessage::default();
        m.header.index = 1;
        m.attributes = vec![
            L::IfName("lo".into()),
            L::Mtu(65536),
            L::Other(DefaultNla::new(kind, value)),
        ];
        m
    };
    for (kind, bytes, changed) in [
        (66, 0u32.to_ne_bytes().to_vec(), 1u32.to_ne_bytes().to_vec()),
        (
            68,
            12u16.to_ne_bytes().to_vec(),
            13u16.to_ne_bytes().to_vec(),
        ),
        (69, 0u16.to_ne_bytes().to_vec(), 1u16.to_ne_bytes().to_vec()),
    ] {
        let good = message(kind, bytes.clone());
        let observed =
            crate::project::link(good.clone()).expect("exact canonical public link attribute");
        assert_ne!(
            observed,
            crate::project::link(message(kind, changed)).unwrap()
        );
        let mut duplicate = good.clone();
        duplicate.attributes.push(good.attributes[2].clone());
        assert!(crate::project::link(duplicate).is_err());
        for bad in [vec![], vec![0; bytes.len() - 1], vec![0; bytes.len() + 1]] {
            assert!(crate::project::link(message(kind, bad)).is_err());
        }
        for bad_kind in [kind | 0x8000, kind | 0x4000, 70] {
            assert!(crate::project::link(message(bad_kind, bytes.clone())).is_err());
        }
    }
}

#[test]
fn public_profile_plan_preserves_exact_existing_identity_without_private_access() {
    let (record, secret) = fixture();
    let old = Plan::new(&record, &record.deployment_id, &record.exits[0], &secret).unwrap();
    let metadata = secret.public_metadata();
    drop(secret);
    let public =
        Plan::from_public(&record, &record.deployment_id, &record.exits[0], &metadata).unwrap();
    assert_eq!(public, old);
    let mut altered = serde_json::to_value(metadata).unwrap();
    altered["device_public_key"] = serde_json::json!(vec![0; 32]);
    let invalid: vprouter_core::profile::PublicProfile = serde_json::from_value(altered).unwrap();
    assert_eq!(
        Plan::from_public(&record, &record.deployment_id, &record.exits[0], &invalid),
        Err(Error::InvalidInput)
    );
}
