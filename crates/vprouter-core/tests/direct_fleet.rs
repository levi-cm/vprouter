mod support;
use support::{configuration, profile};
use vprouter_core::{
    allocation::AllocationRecord,
    config::{Configuration, ExitMode, Mode},
    fleet::{ActionKind, FleetPolicy},
    health::{Binding, HealthMessage, Snapshot},
    state::{Evidence, HealthState, VerificationResult},
    transaction::{ExitChange, PreparedFleet},
};
fn mixed(providers: usize) -> Configuration {
    let mut cfg = configuration(providers.max(1));
    cfg.exits.truncate(providers);
    cfg.exits.push(
        serde_json::from_value(serde_json::json!({
            "id":"residential", "enabled":true, "state_dir":"/synthetic/residential",
            "mode":{"kind":"direct"}
        }))
        .unwrap(),
    );
    cfg
}
fn fleet(providers: usize) -> FleetPolicy {
    let cfg = mixed(providers).validate_with(profile).unwrap();
    let allocations = AllocationRecord::from_configuration(&cfg, 1).unwrap();
    let fingerprint: String = cfg
        .configuration()
        .clone()
        .validate_structure()
        .unwrap()
        .digest()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let bindings = cfg
        .exits()
        .iter()
        .enumerate()
        .map(|(i, e)| {
            (
                Binding {
                    deployment_id: cfg.configuration().deployment_id.clone(),
                    exit_id: e.exit().id.clone(),
                    mode: e.exit().mode.kind(),
                    generation: 1,
                    display_name: e.hostname().into(),
                    expected_server: match &e.exit().mode {
                        Mode::Mullvad {
                            expected_server, ..
                        } => Some(expected_server.clone()),
                        Mode::Direct {} => None,
                    },
                    node_id: format!("node-{i}"),
                    config_fingerprint: fingerprint.clone(),
                    boot_id: "11111111-1111-1111-1111-111111111111".into(),
                },
                format!("{i:064x}"),
            )
        })
        .collect();
    FleetPolicy::new(&cfg, &allocations, bindings, &[], 0.).unwrap()
}
fn observation(
    f: &FleetPolicy,
    id: &str,
    sequence: u64,
    now: f64,
    state: HealthState,
) -> HealthMessage {
    let (binding, lifecycle) = f.binding(id).unwrap();
    HealthMessage {
        version: 1,
        lifecycle: lifecycle.into(),
        sequence,
        sent_at: now,
        snapshot: Some(Snapshot {
            version: 2,
            binding: binding.clone(),
            sequence,
            published_at: now,
            state,
            reason: None,
            evidence: Some(Evidence {
                provider_ok: true,
                structural_ok: true,
                provider_at: now,
                structural_at: now,
                heartbeat_at: now,
                handshake_age_seconds: if binding.mode == ExitMode::Mullvad {
                    Some(1.)
                } else {
                    None
                },
                online: true,
                policy_approved: true,
                server: binding.expected_server.clone(),
                node_id: Some(binding.node_id.clone()),
                egress: Some("8.8.8.8".parse().unwrap()),
                verified_at: Some(now),
                dns: VerificationResult::NotTested,
                ipv6: VerificationResult::NotTested,
            }),
        }),
    }
}
#[test]
fn direct_transactions_preserve_ids_reconcile_all_names_and_never_convert_mode_by_pin() {
    let prepared = PreparedFleet::initial(mixed(1), profile, &[]).unwrap();
    let initial = prepared.record().encode().unwrap();
    assert!(
        prepared
            .record()
            .prepare(
                ExitChange::PinServer {
                    exit_id: "residential".into(),
                    profile: "/synthetic/profile-1.wg.example".into(),
                    expected_server: "de-fra-wg-404".into()
                },
                profile,
                &[]
            )
            .is_err()
    );
    assert_eq!(prepared.record().encode().unwrap(), initial);
    let mut second = prepared.record().configuration().exits[1].clone();
    second.id = "spare".into();
    second.state_dir = "/synthetic/spare".into();
    second.enabled = false;
    let added = prepared
        .record()
        .prepare(ExitChange::Add { exit: second }, profile, &[])
        .unwrap();
    assert_eq!(
        added.configuration().exits()[1].hostname(),
        "unsafe-direct-host-ip-debdev-exit-residential"
    );
    assert_eq!(
        added.configuration().exits()[2].hostname(),
        "unsafe-direct-host-ip-debdev-exit-spare"
    );
    assert_eq!(added.renames().len(), 2);
    let disabled = added
        .record()
        .prepare(
            ExitChange::Disable {
                exit_id: "residential".into(),
            },
            profile,
            &[],
        )
        .unwrap();
    let enabled = disabled
        .record()
        .prepare(
            ExitChange::Enable {
                exit_id: "residential".into(),
            },
            profile,
            &[],
        )
        .unwrap();
    assert_eq!(
        added.record().allocations().exits,
        enabled.record().allocations().exits
    );
    let removed = enabled
        .record()
        .prepare(
            ExitChange::Remove {
                exit_id: "spare".into(),
            },
            profile,
            &[],
        )
        .unwrap();
    assert_eq!(
        removed.configuration().exits()[1].hostname(),
        "unsafe-direct-host-ip-debdev-exit"
    );
    let bytes = removed.record().encode().unwrap();
    assert!(
        vprouter_core::transaction::FleetRecord::decode(
            &bytes,
            &removed.record().configuration().deployment_id
        )
        .is_ok()
    );
}
#[test]
fn five_provider_plus_direct_is_scoped_and_unknown_witness_never_becomes_ready() {
    let mut f = fleet(5);
    assert_eq!(f.enabled_count(), 6);
    let direct = f.select("residential").unwrap();
    for (sequence, state) in [
        (1, HealthState::Starting),
        (2, HealthState::Starting),
        (3, HealthState::Recovering),
        (4, HealthState::Ready),
    ] {
        let now = sequence as f64 * 5.;
        for id in [
            "mullvad-1",
            "mullvad-2",
            "mullvad-3",
            "mullvad-4",
            "mullvad-5",
            "residential",
        ] {
            let token = f.select(id).unwrap();
            let m = observation(&f, id, sequence, now, state);
            assert_eq!(f.observe(&token, &m, now).unwrap(), state);
        }
    }
    f.poll(20.).unwrap();
    let provider = f.select("mullvad-1").unwrap();
    f.worker_failed(&provider).unwrap();
    assert_eq!(
        f.status("residential", 20.).unwrap().state,
        HealthState::Ready
    );
    assert_eq!(
        f.status("residential", 20.).unwrap().exposure,
        "direct-exposed"
    );
    let json = serde_json::to_value(f.status("residential", 20.).unwrap()).unwrap();
    assert_eq!(json["dns"], "not_tested");
    assert_eq!(json["ipv6"], "not_tested");
    assert!(
        f.poll(20.)
            .unwrap()
            .iter()
            .all(|a| a.exit_id == "mullvad-1")
    );
    let mut unknown = observation(&f, "residential", 5, 21., HealthState::Ready);
    unknown
        .snapshot
        .as_mut()
        .unwrap()
        .evidence
        .as_mut()
        .unwrap()
        .verified_at = None;
    assert!(f.observe(&direct, &unknown, 21.).is_err());
    assert_eq!(
        f.status("residential", 21.).unwrap().state,
        HealthState::Blocked
    );
    f.restart(&direct, "a".repeat(64), 22.).unwrap();
    assert!(f.worker_failed(&direct).is_err());
    assert_eq!(f.status("residential", 22.).unwrap().mode, ExitMode::Direct);
    let fresh = f.select("residential").unwrap();
    let mut provider_claim = observation(&f, "residential", 1, 23., HealthState::Starting);
    provider_claim
        .snapshot
        .as_mut()
        .unwrap()
        .evidence
        .as_mut()
        .unwrap()
        .server = Some("de-fra-wg-404".into());
    assert!(f.observe(&fresh, &provider_claim, 23.).is_err());
    assert_eq!(
        f.poll(23.)
            .unwrap()
            .iter()
            .filter(|a| a.exit_id == "residential" && a.kind == ActionKind::Quarantine)
            .count(),
        1
    );
}
#[test]
fn direct_host_time_failure_and_late_callbacks_keep_terminal_emergency() {
    for entry in 0..5 {
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1., 0.] {
            let mut f = fleet(1);
            let token = f.select("residential").unwrap();
            f.poll(1.).unwrap();
            let m = observation(&f, "residential", 1, 1., HealthState::Starting);
            match entry {
                0 => {
                    let _ = f.observe(&token, &m, bad);
                }
                1 => {
                    let _ = f.observe_bytes(&token, b"bad", bad);
                }
                2 => {
                    let _ = f.sample_finished(&token, bad);
                }
                3 => {
                    let _ = f.restart(&token, "b".repeat(64), bad);
                }
                _ => {
                    let _ = f.poll(bad);
                }
            }
            assert_eq!(
                f.status("residential", 1.).unwrap().state,
                HealthState::Failed
            );
            let _ = f.cancel(&token);
            let _ = f.cleanup_failed(&token);
            let _ = f.worker_failed(&token);
            // poll(bad) may already have drained emergency actions.
            let actions = f.poll(2.).unwrap();
            assert!(
                actions
                    .iter()
                    .all(|a| a.kind == ActionKind::EmergencyQuarantineAndStop)
            );
            assert!(f.poll(3.).unwrap().is_empty());
            assert_eq!(
                f.status("residential", 3.).unwrap().state,
                HealthState::Failed
            );
        }
    }
}
#[test]
fn client_selection_requires_enabled_exit_exact_node_and_explicit_matching_mode() {
    use vprouter_core::config::ClientMode;
    let f = fleet(1);
    assert!(
        f.select_client("residential", "node-1", ClientMode::Direct)
            .is_ok()
    );
    assert!(
        f.select_client("residential", "node-1", ClientMode::Protected)
            .is_err()
    );
    assert!(
        f.select_client(
            "residential",
            "unsafe-direct-host-ip-debdev-exit",
            ClientMode::Direct
        )
        .is_err()
    );
    assert!(
        f.select_client(
            "unsafe-direct-host-ip-debdev-exit",
            "node-1",
            ClientMode::Direct
        )
        .is_err()
    );
    assert!(
        f.select_client("mullvad-1", "node-0", ClientMode::Direct)
            .is_err()
    );
    assert!(
        f.select_client("mullvad-1", "node-0", ClientMode::Protected)
            .is_ok()
    );
}
#[test]
fn direct_drift_is_quarantined_before_any_more_work_and_does_not_renew_witness() {
    use vprouter_core::direct::{DirectPath, DirectPlan, HostSnapshot};
    let cfg = mixed(1).validate_with(profile).unwrap();
    let a = AllocationRecord::from_configuration(&cfg, 1).unwrap();
    let host=HostSnapshot::parse(br#"{"generation":1,"addresses":["93.184.216.34"],"connected_prefixes":["93.184.216.0/24"],"local_prefixes":[]}"#).unwrap();
    let plan = DirectPlan::prepare(
        &cfg,
        &a,
        "residential",
        host.clone(),
        DirectPath {
            wan_interface: "directwan0".into(),
            ingress_ifindex: 17,
            wan_ifindex: 18,
        },
    )
    .unwrap();
    let mut f = fleet(1);
    let token = f.select("residential").unwrap();
    f.poll(0.).unwrap();
    assert!(
        f.reconcile_direct_host(&token, &plan, Some(&host), 1.)
            .is_ok()
    );
    assert_eq!(
        f.status("residential", 1.).unwrap().state,
        HealthState::Starting
    );
    assert!(f.reconcile_direct_host(&token, &plan, None, 2.).is_err());
    assert_eq!(
        f.status("mullvad-1", 2.).unwrap().state,
        HealthState::Starting
    );
    assert_eq!(
        f.status("residential", 2.).unwrap().state,
        HealthState::Blocked
    );
    let actions = f.poll(2.).unwrap();
    assert_eq!(actions[0].exit_id, "residential");
    assert_eq!(actions[0].kind, ActionKind::Quarantine);
    assert!(
        actions
            .iter()
            .all(|a| a.exit_id != "residential" || a.kind != ActionKind::Sample)
    );
    f.cleanup_failed(&token).unwrap();
    assert!(
        f.reconcile_direct_host(&token, &plan, Some(&host), 3.)
            .is_err()
    );
    assert_eq!(
        f.status("residential", 3.).unwrap().state,
        HealthState::Failed
    );
    assert!(
        f.reconcile_direct_host(&token, &plan, Some(&host), f64::NAN)
            .is_err()
    );
    assert_eq!(
        f.status("mullvad-1", 3.).unwrap().state,
        HealthState::Failed
    );
}
#[test]
fn direct_only_has_one_slot_no_catchup_and_foreign_or_retired_tokens_refuse() {
    let mut f = fleet(0);
    let token = f.select("residential").unwrap();
    assert_eq!(f.enabled_count(), 1);
    assert_eq!(f.poll(0.).unwrap().len(), 2);
    f.sample_finished(&token, 9.999).unwrap();
    assert!(f.poll(9.999).unwrap().is_empty());
    assert_eq!(f.poll(10.).unwrap()[0].kind, ActionKind::Sample);
    let foreign = fleet(0).select("residential").unwrap();
    assert!(f.worker_failed(&foreign).is_err());
    f.worker_failed(&token).unwrap();
    f.restart(&token, "c".repeat(64), 11.).unwrap();
    assert!(f.sample_finished(&token, 12.).is_err());
    let new = f.select("residential").unwrap();
    assert!(f.restart(&new, "c".repeat(64), 12.).is_err());
    assert_eq!(
        f.status("residential", 12.).unwrap().exposure,
        "direct-exposed"
    );
}
#[test]
fn direct_enrollment_and_mixed_metadata_cannot_be_smuggled_into_preparation() {
    let mut cfg = mixed(0);
    cfg.exits[0].enrollment_key_file = Some("/synthetic/cloned-key".into());
    assert!(PreparedFleet::initial(cfg, profile, &[]).is_err());
    for mode in [
        serde_json::json!({"kind":"direct","profile":"/synthetic/profile-1.wg.example","expected_server":"de-fra-wg-404"}),
        serde_json::json!({"kind":"mullvad","profile":"/synthetic/profile-1.wg.example","expected_server":"de-fra-wg-404","wan_interface":"directwan0"}),
        serde_json::json!({"kind":"direct","fallback":true}),
    ] {
        let mut value = serde_json::to_value(mixed(0)).unwrap();
        value["exits"][0]["mode"] = mode;
        assert!(Configuration::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
#[test]
fn selection_plans_label_exposure_without_claiming_observed_dns_ipv6_or_protection() {
    use vprouter_core::config::ClientMode;
    let f = fleet(1);
    let value = serde_json::to_value(
        f.client_plan("residential", "node-1", ClientMode::Direct)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["exposure"], "direct-exposed");
    assert_eq!(value["mode"], "direct");
    assert_eq!(value["node_id"], "node-1");
    assert_eq!(value["exit_id"], "residential");
    assert_eq!(value["observed_egress"], "not_tested");
    assert_eq!(value["dns"], "not_tested");
    assert_eq!(value["ipv6"], "not_tested");
    assert!(
        f.client_plan("residential", "node-1", ClientMode::Protected)
            .is_err()
    );
}
#[test]
fn every_provider_failure_keeps_direct_and_other_providers_unchanged_without_fallback() {
    for failed in 1..=5 {
        let mut f = fleet(5);
        for (sequence, state) in [
            (1, HealthState::Starting),
            (2, HealthState::Starting),
            (3, HealthState::Recovering),
            (4, HealthState::Ready),
        ] {
            let now = sequence as f64 * 5.;
            for id in [
                "mullvad-1",
                "mullvad-2",
                "mullvad-3",
                "mullvad-4",
                "mullvad-5",
                "residential",
            ] {
                let t = f.select(id).unwrap();
                let m = observation(&f, id, sequence, now, state);
                f.observe(&t, &m, now).unwrap();
            }
        }
        f.poll(20.).unwrap();
        let id = format!("mullvad-{failed}");
        let t = f.select(&id).unwrap();
        f.worker_failed(&t).unwrap();
        f.cleanup_failed(&t).unwrap();
        f.cancel(&t).unwrap();
        assert_eq!(f.status(&id, 20.).unwrap().state, HealthState::Failed);
        for n in 1..=5 {
            if n != failed {
                assert_eq!(
                    f.status(&format!("mullvad-{n}"), 20.).unwrap().state,
                    HealthState::Ready
                );
            }
        }
        assert_eq!(
            f.status("residential", 20.).unwrap().state,
            HealthState::Ready
        );
        assert_eq!(f.binding("residential").unwrap().0.node_id, "node-5");
        let actions = f.poll(20.).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].exit_id, id);
        assert_eq!(actions[0].kind, ActionKind::QuarantineAndStop);
    }
}
#[test]
fn host_reconciliation_checks_all_drift_fields_and_clock_before_foreign_tokens() {
    use vprouter_core::direct::{DirectPath, DirectPlan, HostSnapshot};
    let cfg = mixed(1).validate_with(profile).unwrap();
    let a = AllocationRecord::from_configuration(&cfg, 1).unwrap();
    let original = serde_json::json!({"generation":1,"addresses":["93.184.216.34"],"connected_prefixes":["93.184.216.0/24"],"local_prefixes":[]});
    let host = HostSnapshot::parse(&serde_json::to_vec(&original).unwrap()).unwrap();
    let plan = DirectPlan::prepare(
        &cfg,
        &a,
        "residential",
        host.clone(),
        DirectPath {
            wan_interface: "directwan0".into(),
            ingress_ifindex: 17,
            wan_ifindex: 18,
        },
    )
    .unwrap();
    for (field, value) in [
        ("generation", serde_json::json!(2)),
        ("addresses", serde_json::json!(["93.184.216.35"])),
        ("connected_prefixes", serde_json::json!(["93.184.0.0/16"])),
        ("local_prefixes", serde_json::json!(["8.0.0.0/8"])),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        let changed = HostSnapshot::parse(&serde_json::to_vec(&changed).unwrap()).unwrap();
        let mut f = fleet(1);
        let token = f.select("residential").unwrap();
        f.poll(0.).unwrap();
        assert!(
            f.reconcile_direct_host(&token, &plan, Some(&changed), 1.)
                .is_err()
        );
        assert_eq!(
            f.status("residential", 1.).unwrap().state,
            HealthState::Blocked
        );
        assert_eq!(
            f.status("mullvad-1", 1.).unwrap().state,
            HealthState::Starting
        );
        let actions = f.poll(1.).unwrap();
        assert_eq!(actions[0].exit_id, "residential");
        assert_eq!(actions[0].kind, ActionKind::Quarantine);
        // Returning to old metadata cannot renew a revoked worker session.
        f.reconcile_direct_host(&token, &plan, Some(&host), 2.)
            .unwrap();
        let m = observation(&f, "residential", 1, 2., HealthState::Starting);
        assert!(f.observe(&token, &m, 2.).is_err());
    }
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1., 0., 1e17] {
        let mut f = fleet(1);
        f.poll(1.).unwrap();
        let foreign = fleet(1).select("residential").unwrap();
        assert!(
            f.reconcile_direct_host(&foreign, &plan, Some(&host), bad)
                .is_err()
        );
        let actions = f.poll(2.).unwrap();
        assert_eq!(actions.len(), 2);
        assert!(
            actions
                .iter()
                .all(|a| a.kind == ActionKind::EmergencyQuarantineAndStop)
        );
        assert!(f.poll(3.).unwrap().is_empty());
    }
}
