mod support;
use support::{configuration, profile};
use vprouter_core::{
    allocation::AllocationRecord,
    client::{ClientGuard, GuardConfig, GuardPlan, GuardStage, ProxyProtocol, Step},
    config::ClientPolicy,
    fleet::FleetPolicy,
    health::Binding,
};
fn fleet() -> FleetPolicy {
    fleet_at(1, false, "node-1")
}
fn fleet_at(generation: u64, direct: bool, node: &str) -> FleetPolicy {
    let mut cfg = configuration(1);
    if direct {
        cfg.exits[0].mode = vprouter_core::config::Mode::Direct {};
    }
    cfg.client_policies.push(ClientPolicy {
        id: "desktop".into(),
        exit_id: "mullvad-1".into(),
        selected_node_id: node.into(),
        mode: if direct {
            vprouter_core::config::ClientMode::Direct
        } else {
            vprouter_core::config::ClientMode::Protected
        },
        dependency_adapters: vec![],
    });
    let cfg = cfg.validate_with(profile).unwrap();
    let allocations = AllocationRecord::from_configuration(&cfg, generation).unwrap();
    let fingerprint = cfg
        .configuration()
        .clone()
        .validate_structure()
        .unwrap()
        .digest()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let binding = Binding {
        deployment_id: cfg.configuration().deployment_id.clone(),
        exit_id: "mullvad-1".into(),
        mode: cfg.exits()[0].exit().mode.kind(),
        generation,
        display_name: cfg.exits()[0].hostname().into(),
        expected_server: if direct {
            None
        } else {
            Some("de-fra-wg-404".into())
        },
        node_id: node.into(),
        config_fingerprint: fingerprint,
        boot_id: "11111111-1111-1111-1111-111111111111".into(),
    };
    FleetPolicy::new(&cfg, &allocations, vec![(binding, "a".repeat(64))], &[], 0.).unwrap()
}
fn config() -> serde_json::Value {
    serde_json::json!({"schema_version":1,"client_id":"desktop",
        "boot_id":"11111111-1111-1111-1111-111111111111", "namespace":{"device":4,"inode":123},
        "tailscale":{"name":"tailscale0","ifindex":7},"wan":{"name":"eth0","ifindex":2},
        "daemon":{"pid":25,"start_ticks":100,"executable_device":8,"executable_inode":900,"cgroup_id":500,"cgroup_level":3},
        "transport":[{"address":"185.65.134.88","port":41641,"source_port":41641,"protocol":"udp"}],
        "path":{"kind":"kernel"}})
}
fn plan_value(value: serde_json::Value) -> vprouter_core::reason::Result<GuardPlan> {
    GuardPlan::prepare(
        &fleet(),
        GuardConfig::parse(&serde_json::to_vec(&value).unwrap())?,
    )
}
fn plan() -> GuardPlan {
    plan_value(config()).unwrap()
}
fn proxy() -> GuardPlan {
    let mut value = config();
    value["path"] = serde_json::json!({"kind":"userspace","socks_listener":"127.0.0.1:1080","http_listener":"127.0.0.1:8080", "cgroup_id":600,"cgroup_level":3,"upstream":"100.64.0.9:1080"});
    plan_value(value).unwrap()
}
#[test]
fn guard_config_refuses_ambiguous_scope_daemon_and_injection() {
    assert!(plan_value(config()).is_ok());
    for (field, value) in [
        ("schema_version", serde_json::json!(2)),
        ("client_id", serde_json::json!("unknown")),
        (
            "boot_id",
            serde_json::json!("22222222-2222-2222-2222-222222222222"),
        ),
        ("fallback", serde_json::json!(true)),
    ] {
        let mut c = config();
        c[field] = value;
        assert!(plan_value(c).is_err(), "{field}");
    }
    for field in [
        "pid",
        "start_ticks",
        "executable_device",
        "executable_inode",
        "cgroup_id",
        "cgroup_level",
    ] {
        let mut c = config();
        c["daemon"][field] = serde_json::json!(0);
        assert!(plan_value(c).is_err(), "{field}");
    }
    for name in [
        "",
        "eth0; flush ruleset",
        "eth0\n",
        "é",
        "lo",
        "tailscale0",
        "1234567890123456",
    ] {
        let mut c = config();
        c["wan"]["name"] = serde_json::json!(name);
        assert!(plan_value(c).is_err(), "{name}");
    }
    for address in [
        "::ffff:185.65.134.88",
        "::1",
        "2001:4860::8888",
        "0xb9418658",
        "0311.0101.0206.0130",
        "185.065.134.88",
        "185.65.134.88/32",
        "8.8.8.8;accept",
        "0.0.0.0",
        "127.0.0.1",
    ] {
        let mut c = config();
        c["transport"][0]["address"] = serde_json::json!(address);
        assert!(plan_value(c).is_err(), "{address}");
    }
    for port in [0, 53, 853, 65536] {
        let mut c = config();
        c["transport"][0]["port"] = serde_json::json!(port);
        assert!(plan_value(c).is_err(), "{port}");
    }
    for count in [0, 2, 33] {
        let mut c = config();
        c["transport"] = serde_json::Value::Array(vec![c["transport"][0].clone(); count]);
        assert!(plan_value(c).is_err(), "{count}");
    }
    assert!(GuardConfig::parse(&vec![b' '; 65537]).is_err());
}
#[test]
fn userspace_requires_enclosure_and_disjoint_exact_proxy_authority() {
    proxy();
    for (key, value) in [
        ("socks_listener", "0.0.0.0:1080"),
        ("http_listener", "[::1]:8080"),
        ("upstream", "8.8.8.8:1080"),
        ("upstream", "[::ffff:100.64.0.9]:1080"),
    ] {
        let mut c = config();
        c["path"] = serde_json::to_value(proxy().config().path.clone()).unwrap();
        c["path"][key] = serde_json::json!(value);
        assert!(plan_value(c).is_err());
    }
    let mut c = config();
    c["path"] = serde_json::to_value(proxy().config().path.clone()).unwrap();
    c["path"]["cgroup_id"] = serde_json::json!(500);
    assert!(plan_value(c).is_err());
}
#[test]
fn install_order_interruption_stop_and_drift_keep_persistent_quarantine() {
    let mut guard = ClientGuard::new(plan(), 0).unwrap();
    let token = guard.token();
    let digest = guard.plan().fingerprint();
    assert!(guard.complete(&token, Step::Capture, digest, 1).is_err());
    assert_eq!(guard.status(1).unwrap().stage, GuardStage::Quarantined);
    for (i, step) in [
        Step::Quarantine,
        Step::Capture,
        Step::Commit,
        Step::Reconcile,
    ]
    .into_iter()
    .enumerate()
    {
        guard.complete(&token, step, digest, i as u64 + 2).unwrap();
        if step != Step::Reconcile {
            assert_ne!(
                guard.status(i as u64 + 2).unwrap().stage,
                GuardStage::Prepared
            );
        }
    }
    assert_eq!(guard.status(5).unwrap().stage, GuardStage::Prepared);
    assert_eq!(guard.status(5).unwrap().dns, "not_tested");
    guard.disappear(6).unwrap();
    assert_eq!(guard.status(6).unwrap().stage, GuardStage::Quarantined);
    assert!(guard.complete(&token, Step::Reconcile, digest, 7).is_err());
    let fresh = guard.restart(8).unwrap();
    assert!(guard.complete(&token, Step::Quarantine, digest, 9).is_err());
    guard
        .complete(&fresh, Step::Quarantine, digest, 10)
        .unwrap();
    assert!(guard.reconcile([0; 32], 11).is_err());
    guard.stop(12).unwrap();
    assert_eq!(guard.status(12).unwrap().stage, GuardStage::Stopped);
    assert!(guard.restart(13).is_err());
    assert!(guard.complete(&fresh, Step::Reconcile, digest, 14).is_err());
    guard.disappear(15).unwrap();
    assert_eq!(guard.status(15).unwrap().stage, GuardStage::Stopped);
}
#[test]
fn all_clock_callbacks_expire_before_processing_and_terminal_failure_never_weakens() {
    for which in 0..7 {
        let mut guard = ClientGuard::new(plan(), 10).unwrap();
        let token = guard.token();
        let digest = guard.plan().fingerprint();
        let result = match which {
            0 => guard.complete(&token, Step::Quarantine, digest, 9),
            1 => guard.disappear(9),
            2 => guard.reconcile(digest, 9),
            3 => guard.restart(9).map(|_| ()),
            4 => guard.stop(9),
            5 => guard.poll(9).map(|_| ()),
            _ => guard.select(plan(), 9).map(|_| ()),
        };
        // Poll drains terminal safety work, including invalid-clock failure.
        assert_eq!(result.is_ok(), which == 5);
        assert_eq!(guard.status(10).unwrap().stage, GuardStage::Failed);
        assert!(guard.restart(11).is_err());
        guard.stop(12).unwrap();
        guard.disappear(13).unwrap();
        assert_eq!(guard.status(13).unwrap().stage, GuardStage::Failed);
    }
    let mut g = ClientGuard::new(plan(), 0).unwrap();
    g.poll(5000).unwrap();
    assert_eq!(g.status(5000).unwrap().stage, GuardStage::Failed);
    assert!(g.status(4999).is_err());
    let mut g = ClientGuard::new(plan(), 0).unwrap();
    for n in 1..1024 {
        g.restart(n).unwrap();
    }
    assert!(g.restart(1024).is_err());
    assert_eq!(g.status(1024).unwrap().stage, GuardStage::Failed);
}
#[test]
fn proxy_requests_are_bounded_exit_resolved_and_never_supply_local_fallback() {
    let p = proxy();
    let request = p
        .proxy_request(
            ProxyProtocol::HttpConnect,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            0,
            1,
        )
        .unwrap();
    assert_eq!(request.host, "example.com");
    assert_eq!(request.port, 443);
    assert_eq!(request.resolver, "selected_exit_only");
    assert_eq!(request.pool_key, p.fingerprint());
    let socks = b"\x05\x01\x00\x03\x0bexample.com\x01\xbb";
    assert_eq!(
        p.proxy_request(ProxyProtocol::Socks5, socks, 0, 1)
            .unwrap()
            .host,
        "example.com"
    );
    for input in [
        b"CONNECT [::ffff:8.8.8.8]:443 HTTP/1.1\r\n\r\n".as_slice(),
        b"CONNECT localhost:53 HTTP/1.1\r\n\r\n",
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
        b"GET http://example.com/ HTTP/1.1\r\n\r\n",
        b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: secret\r\n\r\n",
        b"CONNECT example.com:0 HTTP/1.1\r\n\r\n",
    ] {
        assert!(
            p.proxy_request(ProxyProtocol::HttpConnect, input, 0, 1)
                .is_err()
        );
    }
    assert!(
        p.proxy_request(
            ProxyProtocol::Socks5,
            b"\x05\x03\x00\x01\x08\x08\x08\x08\x01\xbb",
            0,
            1
        )
        .is_err()
    );
    assert!(
        p.proxy_request(ProxyProtocol::HttpConnect, &vec![b'A'; 8193], 0, 1)
            .is_err()
    );
    assert!(
        p.proxy_request(ProxyProtocol::Socks5, socks, 0, 5000)
            .is_err()
    );
    assert!(p.proxy_request(ProxyProtocol::Socks5, socks, 2, 1).is_err());
    assert!(
        plan()
            .proxy_request(ProxyProtocol::Socks5, socks, 0, 1)
            .is_err()
    );
}

#[test]
fn transport_bare_config_parse_rejects_duplicate_fields_and_endpoint_overlap() {
    let mut c = config();
    c["transport"] = serde_json::json!([
        {"address":"185.65.134.88","port":41641,"source_port":40000,"protocol":"udp"},
        {"address":"185.65.134.88","port":41641,"source_port":40001,"protocol":"udp"}]);
    // Two exact disjoint source-port tuples are supported, not broad destination sets.
    let first = plan_value(c.clone()).unwrap();
    c["transport"].as_array_mut().unwrap().reverse();
    assert_eq!(first.fingerprint(), plan_value(c).unwrap().fingerprint());
    let bytes = serde_json::to_vec(&config()).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        GuardConfig::parse(
            text.replacen(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
                1
            )
            .as_bytes()
        )
        .is_err()
    );
    for address in [
        "192.0.2.1",
        "198.51.100.2",
        "203.0.113.3",
        "192.0.0.9",
        "168.63.129.16",
        "147.75.207.207",
        "192.80.8.124",
    ] {
        let mut c = config();
        c["transport"][0]["address"] = serde_json::json!(address);
        assert!(
            plan_value(c).is_err(),
            "special-purpose transport endpoint {address}"
        );
    }
}
#[test]
fn interrupted_install_reopen_always_starts_with_quarantine_and_foreign_tokens_refuse() {
    for completed in 0..=4 {
        let p = plan();
        let mut a = ClientGuard::new(p.clone(), 0).unwrap();
        let token = a.token();
        let digest = p.fingerprint();
        for (i, step) in [
            Step::Quarantine,
            Step::Capture,
            Step::Commit,
            Step::Reconcile,
        ]
        .into_iter()
        .take(completed)
        .enumerate()
        {
            a.complete(&token, step, digest, i as u64 + 1).unwrap();
        }
        drop(a);
        let mut reopened = ClientGuard::new(p, 5).unwrap();
        assert_eq!(reopened.status(5).unwrap().stage, GuardStage::Quarantined);
        assert_eq!(reopened.poll(5).unwrap(), vec![Step::Quarantine]);
        assert!(reopened.poll(5).unwrap().is_empty());
        assert!(
            reopened
                .complete(&token, Step::Quarantine, digest, 6)
                .is_err()
        );
    }
}
#[test]
fn watchdog_cannot_be_renewed_by_observations_restarts_or_status_and_no_catch_up() {
    for which in 0..5 {
        let mut g = ClientGuard::new(plan(), 0).unwrap();
        let token = g.token();
        let digest = g.plan().fingerprint();
        for n in [1000, 2000, 3000, 4999] {
            match which {
                0 => {
                    let _ = g.complete(&token, Step::Quarantine, digest, n);
                }
                1 => {
                    g.disappear(n).unwrap();
                }
                2 => {
                    g.reconcile(digest, n).unwrap();
                }
                3 => {
                    g.restart(n).unwrap();
                }
                _ => {
                    g.status(n).unwrap();
                }
            }
        }
        let result = g.reconcile(digest, 5000);
        assert!(result.is_err());
        assert_eq!(g.status(5000).unwrap().stage, GuardStage::Failed);
        assert_eq!(g.poll(5000).unwrap(), vec![Step::Quarantine]);
        assert!(g.poll(5000).unwrap().is_empty());
        assert!(
            g.poll(60000).unwrap().is_empty(),
            "terminal watchdog cannot rearm already-drained quarantine"
        );
    }
    assert!(ClientGuard::new(plan(), u64::MAX).is_err());
    let mut g = ClientGuard::new(plan(), 0).unwrap();
    assert_eq!(g.poll(u64::MAX).unwrap(), vec![Step::Quarantine]);
    assert_eq!(g.status(0).unwrap().stage, GuardStage::Failed);
}
#[test]
fn socks_lengths_http_ambiguity_ipv6_and_numeric_aliases_never_request_fallback() {
    let p = proxy();
    let socks = b"\x05\x01\x00\x03\x0bexample.com\x01\xbb";
    for len in 0..socks.len() {
        assert!(
            p.proxy_request(ProxyProtocol::Socks5, &socks[..len], 0, 1)
                .is_err()
        );
    }
    for authority in [
        "2130706433:443",
        "0177.0.0.1:443",
        "0x7f.0.0.1:443",
        "127.1:443",
        "[::1]:443",
        "user:pass@example.com:443",
        "example.com:65536",
        "example.com.:443",
        "-x.example:443",
        "x.local:443",
    ] {
        let wire = format!("CONNECT {authority} HTTP/1.1\r\n\r\n");
        assert!(
            p.proxy_request(ProxyProtocol::HttpConnect, wire.as_bytes(), 0, 1)
                .is_err(),
            "{authority}"
        );
    }
    for header in [
        "Host: wrong.example:443",
        "Host: example.com:443\r\nHost: example.com:443",
        "Content-Length: 5",
        "Transfer-Encoding: chunked",
        "X-Test: \r\n\tbad",
    ] {
        let wire = format!("CONNECT example.com:443 HTTP/1.1\r\n{header}\r\n\r\n");
        assert!(
            p.proxy_request(ProxyProtocol::HttpConnect, wire.as_bytes(), 0, 1)
                .is_err()
        );
    }
    for mode in [2, 3] {
        let mut bytes = socks.to_vec();
        bytes[1] = mode;
        assert!(
            p.proxy_request(ProxyProtocol::Socks5, &bytes, 0, 1)
                .is_err()
        );
    }
    let ipv6 = [
        5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 8, 8, 8, 8, 1, 187,
    ];
    assert!(p.proxy_request(ProxyProtocol::Socks5, &ipv6, 0, 1).is_err());
}

#[test]
fn selection_is_quarantine_first_generation_bound_and_requires_fresh_ordering() {
    let mut guard = ClientGuard::new(plan(), 0).unwrap();
    let old = guard.token();
    let digest = guard.plan().fingerprint();
    for (i, step) in [
        Step::Quarantine,
        Step::Capture,
        Step::Commit,
        Step::Reconcile,
    ]
    .into_iter()
    .enumerate()
    {
        guard.complete(&old, step, digest, i as u64).unwrap();
    }
    let next = GuardPlan::prepare(
        &fleet_at(2, true, "node-direct"),
        GuardConfig::parse(&serde_json::to_vec(&config()).unwrap()).unwrap(),
    )
    .unwrap();
    let token = guard.select(next, 4).unwrap();
    assert_eq!(guard.status(4).unwrap().stage, GuardStage::Quarantined);
    assert_eq!(guard.status(4).unwrap().exposure, "direct-exposed");
    assert_eq!(guard.plan().selection().node_id, "node-direct");
    assert!(guard.complete(&old, Step::Quarantine, digest, 5).is_err());
    let new_digest = guard.plan().fingerprint();
    for (i, step) in [
        Step::Quarantine,
        Step::Capture,
        Step::Commit,
        Step::Reconcile,
    ]
    .into_iter()
    .enumerate()
    {
        guard
            .complete(&token, step, new_digest, i as u64 + 6)
            .unwrap();
    }
    assert!(
        guard.select(plan(), 10).is_err(),
        "old generation cannot authorize selection"
    );
    assert_eq!(guard.status(10).unwrap().stage, GuardStage::Quarantined);
    assert_eq!(
        guard.plan().selection().node_id,
        "node-direct",
        "refusal never chooses old/provider fallback"
    );
    guard.stop(11).unwrap();
    let fresh = GuardPlan::prepare(
        &fleet_at(3, false, "node-1"),
        GuardConfig::parse(&serde_json::to_vec(&config()).unwrap()).unwrap(),
    )
    .unwrap();
    assert!(guard.select(fresh, 12).is_err());
    assert_eq!(guard.status(12).unwrap().stage, GuardStage::Stopped);
    let mut fresh = ClientGuard::new(plan(), 10).unwrap();
    assert!(fresh.select(plan(), 9).is_err());
    assert_eq!(fresh.status(10).unwrap().stage, GuardStage::Failed);
}

#[test]
fn directly_deserialized_configs_and_non_interfaces_cannot_bypass_plan_validation() {
    for name in [".", ".."] {
        let mut c = config();
        c["wan"]["name"] = serde_json::json!(name);
        assert!(plan_value(c).is_err(), "invalid Linux interface {name}");
    }
    for value in [
        serde_json::json!("41641;flush ruleset"),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!(null),
    ] {
        let mut c = config();
        c["transport"][0]["port"] = value;
        assert!(plan_value(c).is_err());
    }
    let mut c: GuardConfig = serde_json::from_value(config()).unwrap();
    c.schema_version = 2;
    assert!(GuardPlan::prepare(&fleet(), c).is_err());
    let mut c: GuardConfig = serde_json::from_value(config()).unwrap();
    c.transport = vec![c.transport[0].clone(); 33];
    assert!(GuardPlan::prepare(&fleet(), c).is_err());
}

#[test]
fn kernel_path_rejects_unknown_fallback_verify_and_userspace_fields() {
    for (name, value) in [
        ("fallback", serde_json::json!(true)),
        ("verify", serde_json::json!(false)),
        ("cgroup_id", serde_json::json!(600)),
        ("socks_listener", serde_json::json!("127.0.0.1:1080")),
    ] {
        let mut c = config();
        c["path"][name] = value;
        assert!(
            plan_value(c).is_err(),
            "kernel path must reject unexpected field {name}"
        );
    }
}

// These assertions catch the three concrete review failures independently.
#[test]
fn round1_i1_mixed_numeric_aliases_refuse_in_both_protocols() {
    let p = proxy();
    for host in [
        "127.0.0.0x1",
        "127.0.0X1",
        "0177.0.0.0x1",
        "169.254.0xa9.0xfe",
        "10.0.0.0x1",
    ] {
        assert_proxy_refuses(&p, host);
    }
}
fn assert_proxy_refuses(p: &GuardPlan, host: &str) {
    let http = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    assert!(
        p.proxy_request(ProxyProtocol::HttpConnect, http.as_bytes(), 0, 1)
            .is_err(),
        "HTTP accepted {host:?}"
    );
    if let Ok(len) = u8::try_from(host.len()) {
        let mut socks = vec![5, 1, 0, 3, len];
        socks.extend(host.as_bytes());
        socks.extend([1, 187]);
        assert!(
            p.proxy_request(ProxyProtocol::Socks5, &socks, 0, 1)
                .is_err(),
            "SOCKS accepted {host:?}"
        );
    }
}
fn prepared_at_ten() -> ClientGuard {
    let mut g = ClientGuard::new(plan(), 10).unwrap();
    let token = g.token();
    let digest = g.plan().fingerprint();
    for step in [
        Step::Quarantine,
        Step::Capture,
        Step::Commit,
        Step::Reconcile,
    ] {
        g.complete(&token, step, digest, 10).unwrap();
    }
    g
}
#[test]
fn round1_i2_broken_clock_delivers_quarantine_without_clock_recovery() {
    for bad in [9, u64::MAX] {
        let mut g = prepared_at_ten();
        assert_eq!(g.poll(bad).ok(), Some(vec![Step::Quarantine]));
        assert_eq!(g.status(10).unwrap().stage, GuardStage::Failed);
        assert_eq!(g.poll(bad).ok(), Some(vec![]));
        assert!(g.restart(10).is_err());
    }
}
#[test]
fn round1_m1_http11_connect_requires_host() {
    assert!(
        proxy()
            .proxy_request(
                ProxyProtocol::HttpConnect,
                b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
                0,
                1
            )
            .is_err()
    );
}

#[path = "support/address_cases.rs"]
mod address_cases;
#[test]
fn round1_address_encoding_cross_product_refuses_at_every_string_boundary() {
    use vprouter_core::direct::HostSnapshot;
    let p = proxy();
    let f = fleet();
    let base = config();
    let mut failures = Vec::new();
    for octets in address_cases::DENIED.iter().copied().chain([[8, 8, 8, 8]]) {
        let canonical = std::net::Ipv4Addr::from(octets).to_string();
        for host in address_cases::encodings(octets) {
            let noncanonical = host != canonical;
            let denied = octets != [8, 8, 8, 8];
            if noncanonical || denied {
                let http = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
                if p.proxy_request(ProxyProtocol::HttpConnect, http.as_bytes(), 0, 1)
                    .is_ok()
                {
                    failures.push(format!("HTTP {host:?}"));
                }
                if let Ok(n) = u8::try_from(host.len()) {
                    let mut wire = vec![5, 1, 0, 3, n];
                    wire.extend(host.as_bytes());
                    wire.extend([1, 187]);
                    if p.proxy_request(ProxyProtocol::Socks5, &wire, 0, 1).is_ok() {
                        failures.push(format!("SOCKS {host:?}"));
                    }
                }
                // A leading SP here is profile key=value grammar padding, not
                // part of the extracted endpoint. Raw host whitespace remains
                // covered by both proxy protocols, JSON and address::socket_v4.
                if !host.starts_with(' ') {
                    let profile_text =
                        include_str!("../../../examples/v2/profiles/profile-1.wg.example")
                            .replace("185.65.134.81:51820", &format!("{host}:51820"));
                    if vprouter_core::profile::Profile::parse(
                        profile_text.as_bytes(),
                        "de-fra-wg-404",
                        None,
                    )
                    .is_ok()
                    {
                        failures.push(format!("profile endpoint {host:?}"));
                    }
                }
                let mut c = base.clone();
                c["transport"][0]["address"] = serde_json::json!(host);
                if GuardConfig::parse(&serde_json::to_vec(&c).unwrap())
                    .and_then(|c| GuardPlan::prepare(&f, c))
                    .is_ok()
                {
                    failures.push(format!("transport {host:?}"));
                }
            }
            if noncanonical {
                // Host evidence may contain private IPs, but cannot contain aliases.
                for field in ["addresses", "connected_prefixes", "local_prefixes"] {
                    let mut h = serde_json::json!({"generation":1,"addresses":["8.8.8.8"],"connected_prefixes":["8.8.8.8/32"],"local_prefixes":[]});
                    h[field] = serde_json::json!([if field == "addresses" {
                        host.clone()
                    } else {
                        format!("{host}/32")
                    }]);
                    if HostSnapshot::parse(&serde_json::to_vec(&h).unwrap()).is_ok() {
                        failures.push(format!("host {field} {host:?}"));
                    }
                }
                for field in ["socks_listener", "http_listener", "upstream"] {
                    let mut c = base.clone();
                    c["path"] = serde_json::to_value(p.config().path.clone()).unwrap();
                    c["path"][field] = serde_json::json!(format!("{host}:1080"));
                    if GuardConfig::parse(&serde_json::to_vec(&c).unwrap()).is_ok() {
                        failures.push(format!("socket {field} {host:?}"));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} boundary escapes; first: {:?}",
        failures.len(),
        &failures[..failures.len().min(20)]
    );
    for host in [
        "xn--loclhost-3za.example",
        "LOCALHOST",
        "LOCALHOST.example.",
        "ExAmPlE.com",
        "example.123",
        "example.0x7f",
        "metadata.google.internal",
        "instance-data.ec2.internal",
        "éxample.com",
        "example.com\u{00a0}",
    ] {
        assert_proxy_refuses(&p, host);
    }
    // Positive controls cannot be satisfied by rejecting all requests.
    for host in ["8.8.8.8", "example.com", "api-1.example.com"] {
        let wire = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
        assert!(
            p.proxy_request(ProxyProtocol::HttpConnect, wire.as_bytes(), 0, 1)
                .is_ok()
        );
    }
}

#[test]
fn round1_http_request_matrix_fails_closed() {
    let p = proxy();
    let cases = [
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            true,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nhOsT:\texample.com:443\t\r\n\r\n",
            true,
        ),
        ("CONNECT example.com:443 HTTP/1.1\r\n\r\n", false),
        ("CONNECT example.com:443 HTTP/1.0\r\n\r\n", false),
        (
            "CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443\r\n\r\n",
            false,
        ),
        (
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
            false,
        ),
        ("GET http://example.com/ HTTP/1.0\r\n\r\n", false),
        (
            "CONNECT http://example.com:443 HTTP/1.1\r\nHost: http://example.com:443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nHost: example.com:443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nhost: other.com:443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: other.com:443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\n Host: example.com:443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\tcontinued\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost : example.com:443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost:\u{000b}example.com:443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost:\u{000c}example.com:443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:0443 HTTP/1.1\r\nHost: example.com:0443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:+443 HTTP/1.1\r\nHost: example.com:+443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nGET / HTTP/1.1\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\nHost: example.com:443\n\n",
            false,
        ),
        (
            "CONNECT  example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            false,
        ),
        (
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443",
            false,
        ),
    ];
    for (target, headers) in [
        ("example.com:443", "Host: example.com:443,other.com:443"),
        ("example.com:443", "Host: example.com:443\0"),
        ("example.com:443", "Host: example.com:443\rX: injected"),
        (
            "example.com:443",
            "Host: example.com:443\r\nContent-Length: 0\r\nContent-Length: 1",
        ),
        (
            "example.com:443",
            "Host: example.com:443\r\nTransfer-Encoding : chunked",
        ),
        (
            "example.com:443@127.0.0.1:443",
            "Host: example.com:443@127.0.0.1:443",
        ),
        ("example.com%2e:443", "Host: example.com%2e:443"),
        ("example.com:443/path", "Host: example.com:443/path"),
    ] {
        let wire = format!("CONNECT {target} HTTP/1.1\r\n{headers}\r\n\r\n");
        assert!(
            p.proxy_request(ProxyProtocol::HttpConnect, wire.as_bytes(), 0, 1)
                .is_err(),
            "{wire:?}"
        );
    }
    let failures: Vec<_> = cases
        .iter()
        .filter(|(wire, want)| {
            p.proxy_request(ProxyProtocol::HttpConnect, wire.as_bytes(), 0, 1)
                .is_ok()
                != *want
        })
        .collect();
    assert!(failures.is_empty(), "HTTP matrix mismatches: {failures:?}");
    for wire in [
        vec![b'A'; 8193],
        format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost:{}example.com:443\r\n\r\n",
            " ".repeat(8192)
        )
        .into_bytes(),
    ] {
        assert!(
            p.proxy_request(ProxyProtocol::HttpConnect, &wire, 0, 1)
                .is_err()
        );
    }
}

#[test]
fn round1_client_clock_matrix_preserves_obligations_and_terminal_states() {
    let p = plan();
    let next = GuardPlan::prepare(
        &fleet_at(2, false, "node-1"),
        GuardConfig::parse(&serde_json::to_vec(&config()).unwrap()).unwrap(),
    )
    .unwrap();
    // Client entry points accept u64, so NaN/infinities/negative values are
    // unrepresentable. Test the wire/type boundary without lossy f64 casts.
    for text in ["NaN", "Infinity", "-Infinity", "-1", "1e999", "null"] {
        assert!(serde_json::from_str::<u64>(text).is_err());
    }
    for queued in [false, true] {
        for now in [9, 10, 11, 1_000_000_000_000_001, u64::MAX] {
            for entry in [
                "complete",
                "disappear",
                "reconcile",
                "restart",
                "select",
                "stop",
                "poll",
                "status",
            ] {
                let mut g = prepared_at_ten();
                if queued {
                    g.disappear(10).unwrap();
                }
                let token = g.token();
                let bad = !(10..=1_000_000_000_000_000).contains(&now);
                let result = match entry {
                    "complete" => g.complete(&token, Step::Quarantine, p.fingerprint(), now),
                    "disappear" => g.disappear(now),
                    "reconcile" => g.reconcile(p.fingerprint(), now),
                    "restart" => g.restart(now).map(|_| ()),
                    "select" => g.select(next.clone(), now).map(|_| ()),
                    "stop" => g.stop(now),
                    "status" => g.status(now).map(|_| ()),
                    _ => g.poll(now).map(|actions| {
                        assert_eq!(
                            actions,
                            if bad || queued {
                                vec![Step::Quarantine]
                            } else {
                                vec![]
                            },
                            "initial poll queued={queued} now={now}"
                        );
                    }),
                };
                if bad && entry != "poll" {
                    assert!(result.is_err(), "{entry} {now}");
                }
                if bad && entry != "status" {
                    assert_eq!(
                        g.status(10).unwrap().stage,
                        GuardStage::Failed,
                        "{entry} {now}"
                    );
                    if entry != "poll" {
                        assert_eq!(
                            g.poll(now).ok(),
                            Some(vec![Step::Quarantine]),
                            "{entry} {now}"
                        );
                    }
                    assert_eq!(g.poll(now).ok(), Some(vec![]));
                    assert!(g.restart(10).is_err());
                } else if entry == "status" {
                    // Observational errors grant no authority and consume no work.
                    assert_eq!(
                        g.poll(10).unwrap(),
                        if queued {
                            vec![Step::Quarantine]
                        } else {
                            vec![]
                        }
                    );
                } else if !bad {
                    assert_eq!(
                        result.is_ok(),
                        entry != "complete" || queued,
                        "valid {entry} queued={queued}"
                    );
                    let want_stage = if entry == "stop" {
                        GuardStage::Stopped
                    } else if queued || ["disappear", "restart", "select"].contains(&entry) {
                        GuardStage::Quarantined
                    } else {
                        GuardStage::Prepared
                    };
                    assert_eq!(
                        g.status(now).unwrap().stage,
                        want_stage,
                        "valid {entry} queued={queued}"
                    );
                    let remains = entry != "poll"
                        && entry != "complete"
                        && (queued || ["disappear", "restart", "select", "stop"].contains(&entry));
                    assert_eq!(
                        g.poll(now).unwrap(),
                        if remains {
                            vec![Step::Quarantine]
                        } else {
                            vec![]
                        },
                        "valid {entry} queued={queued}"
                    );
                }
            }
        }
    }
    for stopped in [false, true] {
        for queued in [false, true] {
            for now in [9, 10, u64::MAX] {
                for entry in 0..8 {
                    let mut g = prepared_at_ten();
                    if stopped {
                        g.stop(10).unwrap();
                    } else {
                        let _ = g.reconcile(p.fingerprint(), 9);
                    }
                    if !queued {
                        g.poll(10).unwrap();
                    }
                    let token = g.token();
                    match entry {
                        0 => {
                            let _ = g.complete(&token, Step::Quarantine, p.fingerprint(), now);
                        }
                        1 => {
                            let _ = g.disappear(now);
                        }
                        2 => {
                            let _ = g.reconcile(p.fingerprint(), now);
                        }
                        3 => {
                            let _ = g.restart(now);
                        }
                        4 => {
                            let _ = g.select(next.clone(), now);
                        }
                        5 => {
                            let _ = g.stop(now);
                        }
                        6 => {
                            let _ = g.status(now);
                        }
                        _ => {
                            assert_eq!(
                                g.poll(now).ok(),
                                Some(if queued {
                                    vec![Step::Quarantine]
                                } else {
                                    vec![]
                                })
                            );
                        }
                    }
                    assert_eq!(
                        g.status(10).unwrap().stage,
                        if stopped {
                            GuardStage::Stopped
                        } else {
                            GuardStage::Failed
                        }
                    );
                    assert_eq!(
                        g.poll(10).unwrap(),
                        if queued && entry != 7 {
                            vec![Step::Quarantine]
                        } else {
                            vec![]
                        }
                    );
                }
            }
        }
    }
    for now in [0, 10, 1_000_000_000_000_000] {
        assert!(ClientGuard::new(p.clone(), now).is_ok());
    }
    for now in [1_000_000_000_000_001, u64::MAX] {
        assert!(ClientGuard::new(p.clone(), now).is_err());
    }
    let proxy = proxy();
    let wire = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    for (started, now, want) in [
        (10, 9, false),
        (10, 10, true),
        (10, 11, true),
        (10, u64::MAX, false),
        (u64::MAX, u64::MAX, false),
        (0, 5000, false),
    ] {
        assert_eq!(
            proxy
                .proxy_request(ProxyProtocol::HttpConnect, wire, started, now)
                .is_ok(),
            want
        );
    }
}

#[test]
fn round1_http_size_and_domain_boundaries_are_enforced_without_normalization() {
    let p = proxy();
    let valid = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    for (size, want) in [(8192, true), (8193, false)] {
        let wire = valid.replace(
            "Host: ",
            &format!("Host: {}", " ".repeat(size - valid.len())),
        );
        assert_eq!(wire.len(), size);
        assert_eq!(
            p.proxy_request(ProxyProtocol::HttpConnect, wire.as_bytes(), 0, 1)
                .is_ok(),
            want
        );
    }
    for (length, want) in [(253, true), (254, false)] {
        let host = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(length - 192)
        );
        assert_eq!(host.len(), length);
        let wire = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
        assert_eq!(
            p.proxy_request(ProxyProtocol::HttpConnect, wire.as_bytes(), 0, 1)
                .is_ok(),
            want
        );
    }
    for host in [
        format!("{}.example", "a".repeat(64)),
        "a..example".into(),
        "a.-example".into(),
    ] {
        assert_proxy_refuses(&p, &host);
    }
    for field in ["socks_listener", "http_listener", "upstream"] {
        for suffix in [":01080", ":+1080", ":0", ":65536", ":1080 "] {
            let mut c = config();
            c["path"] = serde_json::to_value(p.config().path.clone()).unwrap();
            let host = if field == "upstream" {
                "100.64.0.9"
            } else {
                "127.0.0.1"
            };
            c["path"][field] = serde_json::json!(format!("{host}{suffix}"));
            assert!(
                GuardConfig::parse(&serde_json::to_vec(&c).unwrap()).is_err(),
                "{field} {suffix}"
            );
        }
    }
}

#[test]
fn round1_profile_transport_endpoint_refuses_noncanonical_ports() {
    let original = include_str!("../../../examples/v2/profiles/profile-1.wg.example");
    for endpoint in ["185.65.134.81:051820", "185.65.134.81:+51820"] {
        let text = original.replace("185.65.134.81:51820", endpoint);
        assert!(
            vprouter_core::profile::Profile::parse(text.as_bytes(), "de-fra-wg-404", None).is_err(),
            "profile accepted {endpoint}"
        );
    }
}
