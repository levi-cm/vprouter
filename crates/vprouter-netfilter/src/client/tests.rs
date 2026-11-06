use super::*;
use crate::policy::tests::{base, eval};
use vprouter_core::{
    allocation::AllocationRecord, client::GuardConfig, config::Configuration, fleet::FleetPolicy,
    health::Binding, profile::Profile,
};
fn plan(userspace: bool) -> GuardPlan {
    plan_with(userspace, |_| {})
}
fn plan_with(userspace: bool, mutate: impl FnOnce(&mut serde_json::Value)) -> GuardPlan {
    let mut cfg =
        Configuration::parse(include_bytes!("../../../../examples/v2/five.json")).unwrap();
    cfg.exits.truncate(1);
    cfg.client_policies=serde_json::from_value(serde_json::json!([{"id":"desktop","exit_id":cfg.exits[0].id,"selected_node_id":"node-1","mode":"protected","dependency_adapters":[]}])).unwrap();
    let cfg = cfg
        .validate_with(|_, s| {
            Profile::parse(
                include_bytes!("../../../../examples/v2/profiles/profile-1.wg.example"),
                s,
                None,
            )
        })
        .unwrap();
    let allocations = AllocationRecord::from_configuration(&cfg, 1).unwrap();
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
    let b = Binding {
        deployment_id: cfg.configuration().deployment_id.clone(),
        exit_id: cfg.exits()[0].exit().id.clone(),
        mode: vprouter_core::config::ExitMode::Mullvad,
        generation: 1,
        display_name: cfg.exits()[0].hostname().into(),
        expected_server: Some("de-fra-wg-404".into()),
        node_id: "node-1".into(),
        config_fingerprint: fingerprint,
        boot_id: "11111111-1111-1111-1111-111111111111".into(),
    };
    let fleet = FleetPolicy::new(&cfg, &allocations, vec![(b, "a".repeat(64))], &[], 0.).unwrap();
    let mut config = serde_json::json!({"schema_version":1,"client_id":"desktop","boot_id":"11111111-1111-1111-1111-111111111111","namespace":{"device":4,"inode":123},"tailscale":{"name":"tailscale0","ifindex":7},"wan":{"name":"eth0","ifindex":2},"daemon":{"pid":25,"start_ticks":100,"executable_device":8,"executable_inode":900,"cgroup_id":500,"cgroup_level":3},"transport":[{"address":"185.65.134.88","port":41641,"source_port":41641,"protocol":"udp"}],"path":{"kind":"kernel"}});
    if userspace {
        config["path"] = serde_json::json!({"kind":"userspace","socks_listener":"127.0.0.1:1080","http_listener":"127.0.0.1:8080","cgroup_id":600,"cgroup_level":3,"upstream":"100.64.0.9:1080"});
    }
    mutate(&mut config);
    GuardPlan::prepare(
        &fleet,
        GuardConfig::parse(&serde_json::to_vec(&config).unwrap()).unwrap(),
    )
    .unwrap()
}
fn chain<'a>(table: &'a Table, name: &str) -> &'a Chain {
    table
        .chains
        .iter()
        .find(|c| c.name == name)
        .expect("mandatory namespace chain")
}
#[test]
fn client_kernel_rules_block_wan_dns_ipv6_and_scope_daemon_exception_to_socket_tuple() {
    let rules = ClientRuleset::prepare(&plan(false)).unwrap();
    let output = chain(&rules.permit, "output");
    let mut p = base();
    p.iif = "";
    p.oif = "eth0";
    p.okind = "ether";
    p.dst = "8.8.8.8".parse().unwrap();
    p.dport = 53;
    assert_eq!(eval(output, &p), 0, "ordinary DNS cannot escape on WAN");
    p.dst = "185.65.134.88".parse().unwrap();
    p.dport = 41641;
    p.sport = 41641;
    assert_eq!(
        eval(output, &p),
        0,
        "all-root/all-UDP exemption is forbidden"
    );
    p.owner = Some(500);
    assert_eq!(
        eval(output, &p),
        1,
        "exact daemon socket/tuple positive control"
    );
    p.owner = Some(600);
    assert_eq!(eval(output, &p), 0);
    p.owner = Some(500);
    p.dport = 53;
    assert_eq!(eval(output, &p), 0);
    p.dport = 41641;
    p.oindex = 3;
    assert_eq!(eval(output, &p), 0);
    p.oindex = 2;
    p.family = 10;
    assert_eq!(eval(output, &p), 0);
    p.family = 2;
    p.owner = None;
    p.oif = "tailscale0";
    p.okind = "tun";
    p.oindex = 7;
    p.dst = "8.8.8.8".parse().unwrap();
    p.dport = 53;
    assert_eq!(
        eval(output, &p),
        1,
        "DNS traverses selected authorized overlay path"
    );
    p.okind = "dummy";
    assert_eq!(eval(output, &p), 0);
    p.okind = "tun";
    p.proto = 1;
    assert_eq!(eval(output, &p), 0);
    p.proto = 17;
    assert_eq!(eval(chain(&rules.quarantine, "output"), &p), 0);
    assert_eq!(eval(chain(&rules.permit, "forward"), &p), 0);
}
#[test]
fn userspace_bypass_and_upstream_failure_have_no_direct_socket_or_dns_path() {
    let rules = ClientRuleset::prepare(&plan(true)).unwrap();
    let output = chain(&rules.permit, "output");
    let mut p = base();
    p.oif = "tailscale0";
    p.okind = "tun";
    p.oindex = 7;
    p.dst = "100.64.0.9".parse().unwrap();
    p.dport = 1080;
    p.proto = 6;
    assert_eq!(
        eval(output, &p),
        0,
        "bypassed app cannot contact even overlay upstream"
    );
    p.owner = Some(600);
    assert_eq!(eval(output, &p), 1);
    p.dst = "8.8.8.8".parse().unwrap();
    assert_eq!(eval(output, &p), 0);
    p.dport = 53;
    assert_eq!(eval(output, &p), 0);
    p.oif = "eth0";
    p.oindex = 2;
    assert_eq!(eval(output, &p), 0);
    p.owner = None;
    p.oif = "lo";
    p.oindex = 1;
    p.src = "127.0.0.1".parse().unwrap();
    p.dst = p.src;
    p.dport = 1080;
    assert_eq!(eval(output, &p), 1);
    p.dport = 8080;
    assert_eq!(eval(output, &p), 1);
    p.dport = 53;
    assert_eq!(eval(output, &p), 0, "no host resolver via loopback");
    p.dport = 1080;
    p.family = 10;
    assert_eq!(eval(output, &p), 0);
}
#[test]
fn rendered_operations_are_bounded_owned_and_drift_is_rejected() {
    let rules = ClientRuleset::prepare(&plan(false)).unwrap();
    let bytes = rules.render().unwrap();
    assert!(!bytes.is_empty());
    rules.validate_rendered(&bytes).unwrap();
    assert_eq!(bytes, rules.render().unwrap());
    let mut rendered: Rendered = serde_json::from_slice(&bytes).unwrap();
    assert!(!rendered.quarantine.is_empty());
    assert!(!rendered.permit.is_empty());
    for op in rendered.quarantine.iter().chain(&rendered.permit) {
        assert!(matches!(op.kind, NFT | 0x0a03 | 0x0a06));
        let decoded = attrs(&op.attributes).unwrap();
        assert!(decoded.len() <= 2048);
        if op.kind == NFT | 6 {
            crate::actuator::canonical_exprs(&attrs(get(&decoded, 4).unwrap()).unwrap()).unwrap();
        }
    }
    rendered.permit.pop();
    assert!(
        rules
            .validate_rendered(&serde_json::to_vec(&rendered).unwrap())
            .is_err()
    );
    assert!(rules.validate_rendered(&vec![0; 1024 * 1024 + 1]).is_err());
    assert_ne!(rules.permit.name, rules.quarantine.name);
    assert!(rules.permit.marker.starts_with(b"vprouter-client-v1\0"));
}

#[test]
fn reverse_transport_requires_established_exact_socket_tuple_and_scope() {
    let rules = ClientRuleset::prepare(&plan(false)).unwrap();
    let input = chain(&rules.permit, "input");
    let mut p = base();
    p.iif = "eth0";
    p.iindex = 2;
    p.src = "185.65.134.88".parse().unwrap();
    p.dst = "9.9.9.9".parse().unwrap();
    p.sport = 41641;
    p.dport = 41641;
    p.owner = Some(500);
    p.state = 2;
    assert_eq!(eval(input, &p), 1);
    for field in 0..9 {
        let mut p = base();
        p.iif = "eth0";
        p.iindex = 2;
        p.src = "185.65.134.88".parse().unwrap();
        p.sport = 41641;
        p.dport = 41641;
        p.owner = Some(500);
        p.state = 2;
        match field {
            0 => p.src = "185.65.134.89".parse().unwrap(),
            1 => p.sport = 53,
            2 => p.dport = 123,
            3 => p.owner = None,
            4 => p.owner = Some(600),
            5 => p.state = 0,
            6 => p.iindex = 3,
            7 => p.iif = "foreign",
            _ => p.family = 10,
        }
        assert_eq!(eval(input, &p), 0, "reverse field {field}");
    }
    p.iif = "tailscale0";
    p.iindex = 7;
    p.ikind = "tun";
    p.owner = None;
    p.src = "8.8.8.8".parse().unwrap();
    p.sport = 443;
    p.dport = 1234;
    p.state = 0;
    p.proto = 6;
    assert_eq!(eval(input, &p), 0);
    p.state = 2;
    assert_eq!(eval(input, &p), 1);
    p.ikind = "dummy";
    assert_eq!(eval(input, &p), 0);
}
#[test]
fn generated_tables_round_trip_existing_native_semantic_verifier_and_reject_rule_order_drift() {
    for userspace in [false, true] {
        let rules = ClientRuleset::prepare(&plan(userspace)).unwrap();
        for table in [&rules.quarantine, &rules.permit] {
            let mut chains = vec![];
            let mut rule_messages = vec![];
            for (kind, flags, a) in table.operations().into_iter().skip(1) {
                let messages = messages(&message(kind, flags, 1, INET, 0, &a)).unwrap();
                if kind == NFT | 3 {
                    chains.extend(messages);
                } else {
                    rule_messages.extend(messages);
                }
            }
            crate::actuator::verify(table, &table.table_attrs(), &chains, &rule_messages).unwrap();
            let mut foreign = table.table_attrs();
            foreign[2].value.push(1);
            assert!(crate::actuator::verify(table, &foreign, &chains, &rule_messages).is_err());
            let last = rule_messages.pop().unwrap();
            assert!(
                crate::actuator::verify(table, &table.table_attrs(), &chains, &rule_messages)
                    .is_err()
            );
            rule_messages.push(last);
            // Reordering within one chain changes semantics even when userdata stays equal.
            rule_messages.swap(0, 1);
            assert!(
                crate::actuator::verify(table, &table.table_attrs(), &chains, &rule_messages)
                    .is_err()
            );
        }
    }
}
#[test]
fn rendered_mutation_matrix_rejects_added_sets_foreign_names_missing_rules_and_unknown_fields() {
    let rules = ClientRuleset::prepare(&plan(true)).unwrap();
    let bytes = rules.render().unwrap();
    for mutation in 0..7 {
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        match mutation {
            0 => value["permit"][0]["kind"] = serde_json::json!(0x0a09), // never permit sets/deletions
            1 => value["permit"][0]["flags"] = serde_json::json!(0),
            2 => value["permit"][0]["attributes"][5] = serde_json::json!(255),
            3 => value["quarantine"] = serde_json::json!([]),
            4 => value["permit"].as_array_mut().unwrap().reverse(),
            5 => value["fingerprint"][0] = serde_json::json!(999),
            _ => value["verify"] = serde_json::json!(true),
        }
        assert!(
            rules
                .validate_rendered(&serde_json::to_vec(&value).unwrap())
                .is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn maximum_endpoint_set_is_deterministic_bounded_and_preserves_every_exact_rule() {
    let first = plan_with(false, |c| {
        c["transport"]=serde_json::Value::Array((0..32).map(|n|serde_json::json!({"address":"185.65.134.88","port":41641,"source_port":40000+n,"protocol":"udp"})).collect());
    });
    let second = plan_with(false, |c| {
        c["transport"]=serde_json::Value::Array((0..32).rev().map(|n|serde_json::json!({"address":"185.65.134.88","port":41641,"source_port":40000+n,"protocol":"udp"})).collect());
    });
    let rules = ClientRuleset::prepare(&first).unwrap();
    let bytes = rules.render().unwrap();
    assert!(bytes.len() < MAX_RENDER_BYTES);
    assert_eq!(
        bytes,
        ClientRuleset::prepare(&second).unwrap().render().unwrap()
    );
    let output = chain(&rules.permit, "output");
    let mut p = base();
    p.owner = Some(500);
    p.oif = "eth0";
    p.oindex = 2;
    p.dst = "185.65.134.88".parse().unwrap();
    p.dport = 41641;
    for port in 40000..40032 {
        p.sport = port;
        assert_eq!(eval(output, &p), 1);
    }
    for port in [0, 39999, 40032, 65535] {
        p.sport = port;
        assert_eq!(eval(output, &p), 0);
    }
}

#[path = "../../../vprouter-core/tests/support/address_cases.rs"]
mod address_cases;
#[test]
fn round1_all_ruleset_endpoints_share_the_conservative_target_classifier() {
    let mut escapes = Vec::new();
    for octets in address_cases::DENIED.iter().copied() {
        let ip = std::net::Ipv4Addr::from(octets);
        if crate::Endpoint::new(std::net::SocketAddrV4::new(ip, 443)).is_ok() {
            escapes.push(ip);
        }
    }
    assert!(
        escapes.is_empty(),
        "special endpoints admitted by ruleset: {escapes:?}"
    );
    assert!(crate::Endpoint::new("8.8.8.8:443".parse().unwrap()).is_ok());
}
#[test]
fn round1_ruleset_address_encodings_cannot_become_endpoint_exceptions() {
    // Endpoint has no string constructor: every potential spelling must first
    // pass the same shared IPv4 socket parser. Typed canonical private addresses
    // must still refuse in Endpoint, rather than become transport exceptions.
    for octets in address_cases::DENIED.iter().copied().chain([[8, 8, 8, 8]]) {
        let canonical = std::net::Ipv4Addr::from(octets).to_string();
        for host in address_cases::encodings(octets) {
            let result = vprouter_core::address::socket_v4(&format!("{host}:443"))
                .ok()
                .and_then(|endpoint| crate::Endpoint::new(endpoint).ok());
            assert_eq!(
                result.is_some(),
                host == canonical && octets == [8, 8, 8, 8],
                "{host:?}"
            );
        }
    }
}
