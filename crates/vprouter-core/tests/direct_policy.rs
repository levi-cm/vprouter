mod support;
use support::{configuration, profile};
use vprouter_core::{
    allocation::AllocationRecord,
    config::Mode,
    direct::{Connection, DirectPath, DirectPlan, FlowTuple, HostSnapshot, Packet, Protocol},
};
fn host() -> HostSnapshot {
    HostSnapshot::parse(br#"{"generation":1,"addresses":["93.184.216.34","192.168.1.5"],"connected_prefixes":["93.184.216.0/24","192.168.1.0/24"],"local_prefixes":["9.9.0.0/16"]}"#).unwrap()
}
fn plan() -> DirectPlan {
    let mut cfg = configuration(1);
    cfg.exits[0].mode = Mode::Direct {};
    let cfg = cfg.validate_with(profile).unwrap();
    let allocations = AllocationRecord::from_configuration(&cfg, 7).unwrap();
    DirectPlan::prepare(
        &cfg,
        &allocations,
        "mullvad-1",
        host(),
        DirectPath {
            wan_interface: "directwan0".into(),
            ingress_ifindex: 17,
            wan_ifindex: 18,
        },
    )
    .unwrap()
}
fn packet(destination: &str) -> Packet {
    Packet {
        ingress_ifindex: 17,
        egress_ifindex: 18,
        source: "100.100.1.2".parse().unwrap(),
        destination: destination.parse().unwrap(),
        source_port: 32100,
        destination_port: 443,
        protocol: Protocol::Tcp,
        connection: Connection::New,
    }
}
#[test]
fn conservative_public_ranges_and_known_public_infrastructure_are_denied_at_every_boundary() {
    let p = plan();
    for (network, prefix) in [
        ("0.0.0.0", 8),
        ("10.0.0.0", 8),
        ("100.64.0.0", 10),
        ("127.0.0.0", 8),
        ("169.254.0.0", 16),
        ("172.16.0.0", 12),
        ("192.0.0.0", 24),
        ("192.0.2.0", 24),
        ("192.31.196.0", 24),
        ("192.52.193.0", 24),
        ("192.88.99.0", 24),
        ("192.168.0.0", 16),
        ("192.175.48.0", 24),
        ("198.18.0.0", 15),
        ("198.51.100.0", 24),
        ("203.0.113.0", 24),
        ("224.0.0.0", 4),
        ("240.0.0.0", 4),
    ] {
        let start = u32::from(network.parse::<std::net::Ipv4Addr>().unwrap());
        let end = start | (u32::MAX >> prefix);
        for ip in [start, start + 1, end - 1, end] {
            assert!(
                !p.allows(&packet(&std::net::Ipv4Addr::from(ip).to_string())),
                "denied {network}/{prefix} {ip}"
            );
        }
    }
    for denied in [
        "168.63.129.16",
        "147.75.207.207",
        "192.80.8.124",
        "169.254.169.254",
        "100.100.100.200",
        "93.184.216.34",
        "93.184.216.1",
        "93.184.216.255",
        "9.9.9.9",
        "192.168.1.1",
        "::1",
        "2606:4700:4700::1111",
    ] {
        assert!(!p.allows(&packet(denied)), "denied {denied}");
    }
    for allowed in [
        "1.1.1.1",
        "8.8.8.8",
        "100.63.255.255",
        "100.128.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.0.1.255",
        "198.17.255.255",
        "198.20.0.0",
        "223.255.255.255",
        "168.63.129.15",
        "168.63.129.17",
    ] {
        assert!(p.allows(&packet(allowed)), "allowed {allowed}");
    }
}
#[test]
fn exact_flow_interfaces_zone_and_original_tuple_bind_return_and_nat_without_dns_exception() {
    let p = plan();
    let mut out = packet("1.1.1.1");
    out.protocol = Protocol::Udp;
    out.destination_port = 53;
    assert!(p.allows(&out));
    let original = FlowTuple::from_packet(&out);
    out.connection = Connection::Established {
        scope: p.flow_scope().clone(),
        original: original.clone(),
    };
    assert!(p.allows(&out));
    let mut reply = Packet {
        ingress_ifindex: 18,
        egress_ifindex: 17,
        source: out.destination,
        destination: out.source,
        source_port: 53,
        destination_port: 32100,
        protocol: Protocol::Udp,
        connection: out.connection.clone(),
    };
    assert!(p.allows(&reply));
    reply.connection = Connection::New;
    assert!(!p.allows(&reply));
    reply.connection = out.connection.clone();
    reply.source = "8.8.8.8".parse().unwrap();
    assert!(!p.allows(&reply));
    for change in 0..6 {
        let mut wrong = out.clone();
        match change {
            0 => wrong.ingress_ifindex = 99,
            1 => wrong.egress_ifindex = 99,
            2 => wrong.source = "192.168.1.1".parse().unwrap(),
            3 => wrong.destination = "192.168.1.1".parse().unwrap(),
            4 => {
                if let Connection::Established { scope, .. } = &mut wrong.connection {
                    scope.zone += 1;
                }
            }
            _ => {
                if let Connection::Established { scope, .. } = &mut wrong.connection {
                    scope.exit_id = "foreign".into();
                }
            }
        }
        assert!(!p.allows(&wrong));
    }
    for dest in ["192.168.1.1", "93.184.216.34", "168.63.129.16"] {
        let mut dns = packet(dest);
        dns.protocol = Protocol::Udp;
        dns.destination_port = 53;
        assert!(!p.allows(&dns));
    }
    let json: serde_json::Value = serde_json::from_slice(&p.render().unwrap()).unwrap();
    assert_eq!(json["exposure"], "direct-exposed");
    assert_eq!(json["initial_state"], "quarantined");
    assert_eq!(json["flow"]["generation"], 7);
    assert_eq!(json["path"]["ingress_ifindex"], 17);
    assert_eq!(json["path"]["wan_ifindex"], 18);
    assert_eq!(json["ipv6_forwarding"], "drop");
    assert_eq!(json["nat"], "exact_original_flow_only");
    assert_eq!(json["reply"], "exact_reverse_established_only");
    assert!(json["allocation"]["wireguard_interface"].is_null());
}
#[test]
fn malformed_unknown_or_unbounded_host_metadata_refuses_and_shared_paths_cannot_be_prepared() {
    for bytes in [
        br#"{"generation":0,"addresses":["1.1.1.1"],"connected_prefixes":[],"local_prefixes":[]}"#.as_slice(),
        br#"{"generation":1,"addresses":[],"connected_prefixes":[],"local_prefixes":[]}"#,
        br#"{"generation":1,"addresses":["1.1.1.1"],"connected_prefixes":["1.1.1.1/24"],"local_prefixes":[]}"#,
        br#"{"generation":1,"addresses":["1.1.1.1"],"connected_prefixes":["1.1.1.0/33"],"local_prefixes":[]}"#,
        br#"{"generation":1,"addresses":["1.1.1.1"],"connected_prefixes":["1.1.1.0/24"],"local_prefixes":[],"fallback":true}"#,
        br#"{"generation":1,"generation":2,"addresses":["1.1.1.1"],"connected_prefixes":["1.1.1.0/24"],"local_prefixes":[]}"#,
    ] {assert!(HostSnapshot::parse(bytes).is_err());}
    let mut cfg = configuration(1);
    cfg.exits[0].mode = Mode::Direct {};
    let cfg = cfg.validate_with(profile).unwrap();
    let a = AllocationRecord::from_configuration(&cfg, 1).unwrap();
    for wan in [
        "lo",
        "tailscale0",
        a.exits[0].host_interface.as_str(),
        a.exits[0].data_interface.as_str(),
        "bad;name",
    ] {
        assert!(
            DirectPlan::prepare(
                &cfg,
                &a,
                "mullvad-1",
                host(),
                DirectPath {
                    wan_interface: wan.into(),
                    ingress_ifindex: 17,
                    wan_ifindex: 18
                }
            )
            .is_err()
        );
    }
    let mut cfg = configuration(1);
    cfg.exits[0].enabled = false;
    cfg.exits[0].mode = Mode::Direct {};
    let cfg = cfg.validate_with(profile).unwrap();
    let a = AllocationRecord::from_configuration(&cfg, 1).unwrap();
    assert!(
        DirectPlan::prepare(
            &cfg,
            &a,
            "mullvad-1",
            host(),
            DirectPath {
                wan_interface: "directwan0".into(),
                ingress_ifindex: 17,
                wan_ifindex: 18
            }
        )
        .is_err()
    );
}
#[test]
fn every_host_and_path_entry_point_revalidates_limits_and_drift_fingerprints_bind_flows() {
    let p = plan();
    let mut cfg = configuration(1);
    cfg.exits[0].mode = Mode::Direct {};
    let cfg = cfg.validate_with(profile).unwrap();
    let a = AllocationRecord::from_configuration(&cfg, 7).unwrap();
    let path = || DirectPath {
        wan_interface: "directwan0".into(),
        ingress_ifindex: 17,
        wan_ifindex: 18,
    };
    let mut value = serde_json::to_value(host()).unwrap();
    value["generation"] = 0.into();
    let bypass: HostSnapshot = serde_json::from_value(value).unwrap();
    assert!(DirectPlan::prepare(&cfg, &a, "mullvad-1", bypass, path()).is_err());
    let mut value = serde_json::to_value(host()).unwrap();
    value["addresses"] = serde_json::json!(vec!["1.1.1.1"; 257]);
    assert!(HostSnapshot::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(HostSnapshot::parse(&vec![b' '; 65537]).is_err());
    for (i, o) in [(0, 18), (17, 0), (17, 17)] {
        let mut bad = path();
        bad.ingress_ifindex = i;
        bad.wan_ifindex = o;
        assert!(DirectPlan::prepare(&cfg, &a, "mullvad-1", host(), bad).is_err());
    }
    let mut value = serde_json::to_value(host()).unwrap();
    value["generation"] = 2.into();
    let changed = HostSnapshot::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    let next = DirectPlan::prepare(&cfg, &a, "mullvad-1", changed, path()).unwrap();
    let mut out = packet("8.8.8.8");
    let original = FlowTuple::from_packet(&out);
    out.connection = Connection::Established {
        scope: p.flow_scope().clone(),
        original,
    };
    assert!(p.allows(&out));
    assert!(!next.allows(&out));
}
#[test]
fn changing_configuration_or_path_invalidates_preexisting_flow_scope() {
    let p = plan();
    let mut cfg = configuration(1);
    cfg.exits[0].mode = Mode::Direct {};
    cfg.site = "other-site".into();
    let cfg = cfg.validate_with(profile).unwrap();
    let a = AllocationRecord::from_configuration(&cfg, 7).unwrap();
    let next = DirectPlan::prepare(
        &cfg,
        &a,
        "mullvad-1",
        host(),
        DirectPath {
            wan_interface: "directwan0".into(),
            ingress_ifindex: 17,
            wan_ifindex: 18,
        },
    )
    .unwrap();
    let mut out = packet("8.8.8.8");
    let original = FlowTuple::from_packet(&out);
    out.connection = Connection::Established {
        scope: p.flow_scope().clone(),
        original,
    };
    assert!(p.allows(&out));
    assert!(!next.allows(&out));
}
#[test]
fn rendered_policy_describes_source_protocol_and_default_drop_predicates() {
    let json: serde_json::Value = serde_json::from_slice(&plan().render().unwrap()).unwrap();
    assert_eq!(json["application"]["source_prefix"], "100.64.0.0/10");
    assert_eq!(
        json["application"]["protocols"],
        serde_json::json!(["tcp", "udp"])
    );
    assert_eq!(json["application"]["default_verdict"], "drop");
    assert_eq!(json["application"]["new_flows"], "outbound_only");
}
