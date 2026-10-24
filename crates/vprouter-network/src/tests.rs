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
fn snapshot(p: &Plan) -> Snapshot {
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
        },
    ];
    let addresses = vec![
        Address {
            index: 1,
            address: Ipv4Addr::LOCALHOST.into(),
            prefix: 8,
            scope: 254,
        },
        Address {
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
            },
            Rule {
                ipv6: false,
                priority: 32766,
                table: 254,
            },
            Rule {
                ipv6: false,
                priority: 32767,
                table: 253,
            },
            Rule {
                ipv6: true,
                priority: 0,
                table: 255,
            },
            Rule {
                ipv6: true,
                priority: 32766,
                table: 254,
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
    });
    for (index, address, scope) in [
        (1, "::1", 254),
        (5, "100.64.1.2", 0),
        (5, "fd7a:115c:a1e0::1", 0),
    ] {
        s.addresses.push(Address {
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
    assert_eq!(crate::project::route(route), Err(Error::Unsupported));
    let mut route = RouteMessage::default();
    route.header.address_family = netlink_packet_route::AddressFamily::Inet;
    route.attributes.push(R::NhId(7));
    assert_eq!(crate::project::route(route), Err(Error::Unsupported));
    let mut rule = RuleMessage::default();
    rule.header.family = netlink_packet_route::AddressFamily::Inet;
    rule.header.action = netlink_packet_route::rule::RuleAction::ToTable;
    rule.attributes.push(U::FwMark(1));
    assert_eq!(crate::project::rule(rule), Err(Error::Unsupported));
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
        L::Controller(2),
    ] {
        let mut x = m.clone();
        x.attributes
            .retain(|a| !matches!(a, L::DevlinkPort(_) | L::DpllPin(_) | L::Xdp(_)));
        x.attributes.push(extra);
        assert_eq!(crate::project::link(x), Err(Error::Unsupported));
    }
}

#[test]
fn disabled_rule_suppression_sentinel_does_not_admit_functional_suppression() {
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
            table: 255
        })
    );
    for prefix in [0, 1, 32, 128, u32::MAX - 1] {
        m.attributes = vec![U::SuppressPrefixLen(prefix)];
        assert_eq!(crate::project::rule(m.clone()), Err(Error::Unsupported));
    }
}
