mod support;
use support::{configuration, profile};
use vprouter_core::{
    allocation::AllocationRecord,
    config::{ExitMode, Mode},
    fleet::{ActionKind, FleetPolicy},
    health::{Binding, HealthMessage, Snapshot},
    state::{Evidence, HealthState, VerificationResult},
};
fn fleet(count: usize) -> FleetPolicy {
    let cfg = configuration(count).validate_with(profile).unwrap();
    let allocations = AllocationRecord::from_configuration(&cfg, 1).unwrap();
    let bindings = cfg
        .exits()
        .iter()
        .enumerate()
        .map(|(i, e)| {
            (
                Binding {
                    deployment_id: cfg.configuration().deployment_id.clone(),
                    exit_id: e.exit().id.clone(),
                    mode: ExitMode::Mullvad,
                    generation: 1,
                    display_name: e.hostname().into(),
                    expected_server: match &e.exit().mode {
                        Mode::Mullvad {
                            expected_server, ..
                        } => Some(expected_server.clone()),
                        _ => unreachable!(),
                    },
                    node_id: format!("node{i}"),
                    config_fingerprint: cfg
                        .configuration()
                        .clone()
                        .validate_structure()
                        .unwrap()
                        .digest()
                        .unwrap()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                    boot_id: "11111111-1111-1111-1111-111111111111".into(),
                },
                format!("{i:064x}"),
            )
        })
        .collect();
    FleetPolicy::new(&cfg, &allocations, bindings, &[], 0.).unwrap()
}
fn message(
    fleet: &FleetPolicy,
    id: &str,
    sequence: u64,
    now: f64,
    state: HealthState,
) -> HealthMessage {
    let (binding, lifecycle) = fleet.binding(id).unwrap();
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
                handshake_age_seconds: Some(1.),
                online: true,
                policy_approved: true,
                server: binding.expected_server.clone(),
                node_id: Some(binding.node_id.clone()),
                egress: Some("185.65.134.88".parse().unwrap()),
                verified_at: Some(now),
                dns: VerificationResult::NotTested,
                ipv6: VerificationResult::NotTested,
            }),
        }),
    }
}
fn ready_all(fleet: &mut FleetPolicy) {
    for (sequence, state) in [
        (1, HealthState::Starting),
        (2, HealthState::Starting),
        (3, HealthState::Recovering),
        (4, HealthState::Ready),
    ] {
        let at = sequence as f64 * 5.;
        // Host callbacks share one clock: advance all exits at each instant.
        for n in 1..=fleet.enabled_count() {
            let id = format!("mullvad-{n}");
            let token = fleet.select(&id).unwrap();
            let m = message(fleet, &id, sequence, at, state);
            assert_eq!(fleet.observe(&token, &m, at).unwrap(), state);
        }
    }
}
#[test]
fn crash_and_malformed_witness_quarantine_only_selected_exit_and_tokens_cannot_cross_fleets() {
    let mut f = fleet(5);
    ready_all(&mut f);
    let token = f.select("mullvad-1").unwrap();
    let foreign = fleet(5);
    let wrong = foreign.select("mullvad-1").unwrap();
    let m = message(&f, "mullvad-1", 5, 25., HealthState::Ready);
    assert!(f.observe(&wrong, &m, 25.).is_err());
    f.worker_failed(&token).unwrap();
    assert_eq!(
        f.status("mullvad-1", 25.).unwrap().state,
        HealthState::Blocked
    );
    for n in 2..=5 {
        assert_eq!(
            f.status(&format!("mullvad-{n}"), 25.).unwrap().state,
            HealthState::Ready
        );
    }
    let token2 = f.select("mullvad-2").unwrap();
    assert!(
        f.observe_bytes(&token2, br#"{"unknown":true}"#, 25.)
            .is_err()
    );
    assert_eq!(
        f.status("mullvad-2", 25.).unwrap().state,
        HealthState::Blocked
    );
    let cross = message(&f, "mullvad-4", 5, 25., HealthState::Ready);
    let token3 = f.select("mullvad-3").unwrap();
    assert!(f.observe(&token3, &cross, 25.).is_err());
    assert_eq!(
        f.status("mullvad-4", 25.).unwrap().state,
        HealthState::Ready
    );
}
#[test]
fn blocked_sample_does_not_starve_peer_deadlines_and_status_is_observational() {
    let mut f = fleet(5);
    let initial = f.poll(0.).unwrap();
    assert_eq!(
        initial
            .iter()
            .filter(|a| a.kind == ActionKind::Quarantine)
            .count(),
        5
    );
    let due = f.poll(5.).unwrap();
    assert_eq!(
        due.iter().filter(|a| a.kind == ActionKind::Sample).count(),
        5
    );
    assert!(f.poll(5.).unwrap().is_empty()); // No overlapping sample or burst.
    let token = f.select("mullvad-2").unwrap();
    f.sample_finished(&token, 5.).unwrap();
    let _ = f.status("mullvad-1", 40.).unwrap();
    assert_eq!(
        f.status("mullvad-1", 40.).unwrap().state,
        HealthState::Starting
    );
    let next = f.poll(40.).unwrap();
    assert!(
        next.iter()
            .any(|a| a.exit_id == "mullvad-2" && a.kind == ActionKind::Sample)
    );
    assert!(
        next.iter()
            .any(|a| a.exit_id == "mullvad-1" && a.kind == ActionKind::Quarantine)
    );
    assert_eq!(
        f.status("mullvad-1", 40.).unwrap().state,
        HealthState::Blocked
    );
}
#[test]
fn disabled_and_absent_exits_have_no_machine_schedule_or_token() {
    let mut one = fleet(1);
    assert_eq!(one.enabled_count(), 1);
    assert!(one.select("mullvad-2").is_err());
    assert_eq!(one.poll(0.).unwrap().len(), 2); // Quarantine then zero-offset sample.
    assert_eq!(one.next_deadline().unwrap(), 34.);
    let mut cfg = configuration(5);
    for e in &mut cfg.exits {
        e.enabled = false;
    }
    let cfg = cfg.validate_with(profile).unwrap();
    let a = AllocationRecord::from_configuration(&cfg, 1).unwrap();
    let all = fleet(5);
    let b = (1..=5)
        .map(|i| {
            let (b, l) = all.binding(&format!("mullvad-{i}")).unwrap();
            {
                let mut b = b.clone();
                b.config_fingerprint = cfg
                    .configuration()
                    .clone()
                    .validate_structure()
                    .unwrap()
                    .digest()
                    .unwrap()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                (b, l.to_owned())
            }
        })
        .collect();
    let mut disabled = FleetPolicy::new(&cfg, &a, b, &[], 0.).unwrap();
    assert_eq!(disabled.enabled_count(), 0);
    assert_eq!(disabled.reserved_identity_count(), 5);
    assert!(disabled.poll(500.).unwrap().is_empty());
    assert!(disabled.next_deadline().is_none());
}
#[test]
fn container_failure_and_cleanup_ambiguity_are_terminal_and_restart_revokes_old_tokens() {
    let mut f = fleet(5);
    let old = f.select("mullvad-1").unwrap();
    f.worker_failed(&old).unwrap();
    f.restart(&old, "f".repeat(64), 1.).unwrap();
    assert!(f.worker_failed(&old).is_err());
    let current = f.select("mullvad-1").unwrap();
    assert_eq!(
        f.status("mullvad-1", 1.).unwrap().state,
        HealthState::Starting
    );
    f.cleanup_failed(&current).unwrap();
    assert_eq!(
        f.status("mullvad-1", 1.).unwrap().state,
        HealthState::Failed
    );
    assert!(f.restart(&current, "e".repeat(64), 2.).is_err());
    f.container_failed();
    let actions = f.poll(2.).unwrap();
    assert_eq!(actions.len(), 5);
    assert!(
        actions
            .iter()
            .all(|a| a.kind == ActionKind::EmergencyQuarantineAndStop)
    );
    assert!(f.poll(3.).unwrap().is_empty());
    assert!(f.next_deadline().is_none());
}
#[test]
fn stale_handshake_health_watchdog_and_false_ready_never_remain_ready() {
    let mut f = fleet(5);
    ready_all(&mut f);
    let token = f.select("mullvad-1").unwrap();
    let mut m = message(&f, "mullvad-1", 5, 25., HealthState::Ready);
    m.snapshot
        .as_mut()
        .unwrap()
        .evidence
        .as_mut()
        .unwrap()
        .handshake_age_seconds = Some(179.);
    f.observe(&token, &m, 25.).unwrap();
    f.poll(25.).unwrap();
    let at_expiry = f.poll(26.).unwrap();
    assert!(
        at_expiry
            .iter()
            .any(|a| a.exit_id == "mullvad-1" && a.kind == ActionKind::Quarantine)
    );
    assert_eq!(
        f.status("mullvad-2", 26.).unwrap().state,
        HealthState::Ready
    );
    f.poll(64.).unwrap(); // Last evidence20 +44; heartbeat cannot renew health.
    assert_eq!(
        f.status("mullvad-2", 64.).unwrap().state,
        HealthState::Blocked
    );
    let actions = f.poll(154.).unwrap(); // Independent guard loop missing for90s.
    assert_eq!(actions.len(), 5);
    assert!(
        actions
            .iter()
            .all(|a| a.kind == ActionKind::EmergencyQuarantineAndStop)
    );
    let mut f = fleet(1);
    let token = f.select("mullvad-1").unwrap();
    let premature = message(&f, "mullvad-1", 1, 5., HealthState::Ready);
    assert!(f.observe(&token, &premature, 5.).is_err());
    assert_eq!(
        f.status("mullvad-1", 5.).unwrap().state,
        HealthState::Blocked
    );
}
#[test]
fn identities_bindings_foreign_resources_and_duplicate_lifetimes_refuse_before_scheduling() {
    use vprouter_core::allocation::ResourceClaim;
    let cfg = configuration(5).validate_with(profile).unwrap();
    let a = AllocationRecord::from_configuration(&cfg, 1).unwrap();
    let source = fleet(5);
    let baseline: Vec<_> = (1..=5)
        .map(|i| {
            let (b, l) = source.binding(&format!("mullvad-{i}")).unwrap();
            (b.clone(), l.to_owned())
        })
        .collect();
    for fault in 0..8 {
        let mut bad = baseline.clone();
        match fault {
            0 => bad[1].0.node_id = bad[0].0.node_id.clone(),
            1 => bad[1].1 = bad[0].1.clone(),
            2 => bad[0].0.generation = 2,
            3 => bad[0].0.display_name = "wrong-name".into(),
            4 => bad[0].0.expected_server = Some("de-fra-wg-999".into()),
            5 => bad[0].0.config_fingerprint = "b".repeat(64),
            6 => bad[0].0.boot_id = "22222222-2222-2222-2222-222222222222".into(),
            7 => bad[1].0.exit_id = bad[0].0.exit_id.clone(),
            _ => unreachable!(),
        }
        assert!(
            FleetPolicy::new(&cfg, &a, bad, &[], 0.).is_err(),
            "fault {fault}"
        );
    }
    for foreign in [
        ResourceClaim::Namespace(a.exits[0].data_namespace.clone()),
        ResourceClaim::Interface(a.exits[0].host_interface.clone()),
        ResourceClaim::NftTable(a.exits[0].nft_table.clone()),
        ResourceClaim::Subnet(a.exits[0].transport_subnet.clone()),
    ] {
        assert!(FleetPolicy::new(&cfg, &a, baseline.clone(), &[foreign], 0.).is_err());
    }
    assert!(FleetPolicy::new(&cfg, &a, baseline.clone(), &[], f64::NAN).is_err());
}
#[test]
fn staggering_is_deterministic_bounded_and_cancellation_does_not_stop_peers() {
    let mut a = fleet(5);
    let mut b = fleet(5);
    a.poll(0.).unwrap();
    b.poll(0.).unwrap();
    assert_eq!(a.next_deadline(), b.next_deadline());
    assert!(a.next_deadline().unwrap() < 5.);
    let token = a.select("mullvad-1").unwrap();
    a.cancel(&token).unwrap();
    let actions = a.poll(5.).unwrap();
    assert_eq!(actions[0].kind, ActionKind::QuarantineAndStop);
    assert_eq!(
        actions
            .iter()
            .filter(|a| a.kind == ActionKind::Sample)
            .count(),
        4
    );
    assert_eq!(
        a.status("mullvad-1", 5.).unwrap().state,
        HealthState::Stopping
    );
    assert!(
        a.observe(
            &token,
            &message(&a, "mullvad-1", 1, 5., HealthState::Starting),
            5.
        )
        .is_err()
    );
}
#[test]
fn repeated_restarts_have_a_finite_memory_budget() {
    let mut f = fleet(1);
    for n in 1..1024 {
        let token = f.select("mullvad-1").unwrap();
        f.worker_failed(&token).unwrap();
        f.restart(&token, format!("{n:064x}"), 0.).unwrap();
    }
    let token = f.select("mullvad-1").unwrap();
    f.worker_failed(&token).unwrap();
    assert!(f.restart(&token, format!("{:064x}", 1024), 0.).is_err());
    assert_eq!(
        f.status("mullvad-1", 0.).unwrap().state,
        HealthState::Blocked
    );
}

#[test]
fn late_cleanup_and_cancel_cannot_weaken_container_emergency() {
    let mut f = fleet(5);
    let token = f.select("mullvad-1").unwrap();
    f.container_failed();
    let _ = f.cleanup_failed(&token);
    let _ = f.cancel(&token);
    assert_eq!(
        f.status("mullvad-1", 0.).unwrap().state,
        HealthState::Failed
    );
    let actions = f.poll(0.).unwrap();
    assert_eq!(actions.len(), 5);
    assert!(
        actions
            .iter()
            .all(|a| a.kind == ActionKind::EmergencyQuarantineAndStop)
    );
}

fn assert_terminal_emergency(f: &mut FleetPolicy) {
    let token = f.select("mullvad-1").unwrap();
    let late = message(f, "mullvad-1", 6, 24., HealthState::Ready);
    // Late callbacks must neither downgrade nor consume queued emergency work.
    let _ = f.cleanup_failed(&token);
    let _ = f.cancel(&token);
    let _ = f.worker_failed(&token);
    assert!(f.observe(&token, &late, 24.).is_err());
    assert!(f.observe_bytes(&token, b"invalid", 24.).is_err());
    assert!(f.sample_finished(&token, 24.).is_err());
    assert!(f.restart(&token, "f".repeat(64), 24.).is_err());
    for n in 1..=5 {
        assert_eq!(
            f.status(&format!("mullvad-{n}"), 24.).unwrap().state,
            HealthState::Failed,
            "exit {n} must retain terminal fleet emergency"
        );
    }
    let actions = f.poll(24.).unwrap();
    assert_eq!(actions.len(), 5);
    for n in 1..=5 {
        assert!(actions.iter().any(|a| a.exit_id == format!("mullvad-{n}")
            && a.kind == ActionKind::EmergencyQuarantineAndStop));
    }
    // Even another bad clock must not re-arm drained emergency actions.
    let _ = f.observe_bytes(&token, b"invalid", f64::NAN);
    let _ = f.cancel(&token);
    let _ = f.cleanup_failed(&token);
    assert!(f.poll(f64::NAN).unwrap().is_empty());
    assert!(f.poll(25.).unwrap().is_empty());
    assert!(f.next_deadline().is_none());
}

#[test]
fn review_nonfinite_host_observation_clock_must_quarantine_entire_fleet() {
    let mut f = fleet(5);
    ready_all(&mut f);
    f.poll(20.).unwrap();
    let token = f.select("mullvad-1").unwrap();
    let valid = message(&f, "mullvad-1", 5, 21., HealthState::Ready);
    assert!(f.observe(&token, &valid, f64::NAN).is_err());
    assert_terminal_emergency(&mut f);
}

#[test]
fn review_backwards_host_completion_clock_must_quarantine_entire_fleet() {
    for now in [21., 19., f64::NAN] {
        let mut f = fleet(5);
        ready_all(&mut f);
        assert_eq!(
            f.poll(20.)
                .unwrap()
                .iter()
                .filter(|a| a.kind == ActionKind::Sample)
                .count(),
            5
        );
        f.poll(22.).unwrap();
        let token = f.select("mullvad-1").unwrap();
        assert!(
            f.sample_finished(&token, now).is_err(),
            "host time {now} must be rejected against both start and latest poll"
        );
        assert_terminal_emergency(&mut f);
    }
}

#[test]
fn review_every_timed_callback_rejects_invalid_host_clock_fleet_wide() {
    for callback in 0..5 {
        for now in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1., 19.] {
            let mut f = fleet(5);
            ready_all(&mut f);
            f.poll(20.).unwrap();
            let token = f.select("mullvad-1").unwrap();
            let valid = message(&f, "mullvad-1", 5, 20., HealthState::Ready);
            match callback {
                0 => assert!(f.observe(&token, &valid, now).is_err()),
                // Validate host time even when the wire frame cannot decode.
                1 => assert!(f.observe_bytes(&token, b"invalid", now).is_err()),
                2 => assert!(f.sample_finished(&token, now).is_err()),
                3 => {
                    f.worker_failed(&token).unwrap();
                    assert!(f.restart(&token, "f".repeat(64), now).is_err());
                }
                4 => {
                    let actions = f.poll(now).unwrap();
                    assert_eq!(actions.len(), 5);
                    assert!(
                        actions
                            .iter()
                            .all(|a| { a.kind == ActionKind::EmergencyQuarantineAndStop })
                    );
                    assert!(f.next_deadline().is_none());
                    continue;
                }
                _ => unreachable!(),
            }
            assert_terminal_emergency(&mut f);
        }
    }
}

#[test]
fn review_timed_callbacks_share_one_host_clock_high_water_mark() {
    // Every producer of host time must constrain every subsequent callback,
    // across exits, even if no enforcement poll ran between the callbacks.
    for producer in 0..6 {
        for consumer in 0..5 {
            let mut f = fleet(5);
            ready_all(&mut f);
            f.poll(20.).unwrap();
            let first = f.select("mullvad-1").unwrap();
            let valid = message(&f, "mullvad-1", 5, 23., HealthState::Ready);
            match producer {
                0 => {
                    f.observe(&first, &valid, 23.).unwrap();
                }
                1 => {
                    f.observe_bytes(&first, &serde_json::to_vec(&valid).unwrap(), 23.)
                        .unwrap();
                }
                2 => {
                    f.worker_failed(&first).unwrap();
                    f.restart(&first, "f".repeat(64), 23.).unwrap();
                }
                3 => f.sample_finished(&first, 23.).unwrap(),
                4 => {
                    f.poll(23.).unwrap();
                }
                5 => {
                    assert!(f.observe_bytes(&first, b"invalid", 23.).is_err());
                }
                _ => unreachable!(),
            }
            let second = f.select("mullvad-2").unwrap();
            let valid = message(&f, "mullvad-2", 5, 22., HealthState::Ready);
            match consumer {
                0 => {
                    assert!(f.observe(&second, &valid, 22.).is_err());
                }
                1 => {
                    assert!(f.observe_bytes(&second, b"invalid", 22.).is_err());
                }
                2 => {
                    assert!(f.sample_finished(&second, 22.).is_err());
                }
                3 => {
                    f.worker_failed(&second).unwrap();
                    assert!(f.restart(&second, "e".repeat(64), 22.).is_err());
                }
                4 => {
                    let actions = f.poll(22.).unwrap();
                    assert_eq!(actions.len(), 5);
                    assert!(
                        actions
                            .iter()
                            .all(|a| a.kind == ActionKind::EmergencyQuarantineAndStop)
                    );
                    assert!(f.next_deadline().is_none());
                    continue;
                }
                _ => unreachable!(),
            }
            assert_terminal_emergency(&mut f);
        }
    }
}

#[test]
fn review_status_queries_do_not_advance_or_fail_the_host_clock() {
    let mut f = fleet(5);
    ready_all(&mut f);
    let deadline = f.next_deadline();
    assert!(f.status("mullvad-1", f64::NAN).is_err());
    assert!(f.status("mullvad-1", 19.).is_err());
    let _ = f.status("mullvad-1", 1000.);
    assert_eq!(f.next_deadline(), deadline);
    let actions = f.poll(20.).unwrap();
    assert_eq!(
        actions
            .iter()
            .filter(|a| a.kind == ActionKind::Sample)
            .count(),
        5
    );
    assert_eq!(
        f.status("mullvad-2", 20.).unwrap().state,
        HealthState::Ready
    );
}

#[test]
fn review_observation_clock_does_not_renew_enforcement_watchdog() {
    let mut f = fleet(5);
    ready_all(&mut f);
    f.poll(20.).unwrap();
    let token = f.select("mullvad-1").unwrap();
    let valid = message(&f, "mullvad-1", 5, 40., HealthState::Ready);
    f.observe(&token, &valid, 40.).unwrap();
    let actions = f.poll(110.).unwrap();
    assert_eq!(actions.len(), 5);
    assert!(
        actions
            .iter()
            .all(|a| a.kind == ActionKind::EmergencyQuarantineAndStop)
    );
}

#[test]
fn review_long_sample_must_skip_elapsed_cadence_ticks() {
    let mut f = fleet(1);
    let token = f.select("mullvad-1").unwrap();
    f.poll(0.).unwrap();
    assert!(f.poll(5.).unwrap().is_empty());
    f.sample_finished(&token, 9.999).unwrap();
    assert!(
        f.poll(9.999).unwrap().is_empty(),
        "missed 5s tick must not replay"
    );
    assert_eq!(f.next_deadline(), Some(10.));
    let actions = f.poll(10.).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, ActionKind::Sample);
    f.sample_finished(&token, 10.).unwrap(); // Completion at a slot boundary is valid.
    assert!(f.poll(10.).unwrap().is_empty());
    assert_eq!(f.next_deadline(), Some(15.));
}

#[test]
fn review_multitick_sample_resumes_stagger_without_starving_peers() {
    let mut f = fleet(5);
    ready_all(&mut f);
    for action in f.poll(20.).unwrap() {
        if action.kind == ActionKind::Sample {
            let token = f.select(&action.exit_id).unwrap();
            f.sample_finished(&token, 20.).unwrap();
        }
    }
    // Learn a stable slot from an actual on-time dispatch, independent of the
    // offset hash. Hold only that exit through three subsequent 5s ticks.
    let start = f.next_deadline().unwrap();
    assert!(start > 20. && start < 25.);
    let first = f.poll(start).unwrap();
    let held = first
        .iter()
        .find(|a| a.kind == ActionKind::Sample)
        .unwrap()
        .exit_id
        .clone();
    for action in first {
        if action.kind == ActionKind::Sample && action.exit_id != held {
            let token = f.select(&action.exit_id).unwrap();
            f.sample_finished(&token, start).unwrap();
        }
    }
    let completion = start + 19.999;
    let mut peer_samples = std::collections::HashMap::new();
    while f.next_deadline().unwrap() <= completion {
        let at = f.next_deadline().unwrap();
        for action in f.poll(at).unwrap() {
            assert_eq!(action.kind, ActionKind::Sample);
            assert_ne!(action.exit_id, held, "sample may not overlap itself");
            *peer_samples.entry(action.exit_id.clone()).or_insert(0) += 1;
            let token = f.select(&action.exit_id).unwrap();
            f.sample_finished(&token, at).unwrap();
        }
    }
    assert_eq!(peer_samples.len(), 4);
    assert!(peer_samples.values().all(|count| *count >= 3));
    f.poll(completion).unwrap();
    let token = f.select(&held).unwrap();
    f.sample_finished(&token, completion).unwrap();
    assert!(
        f.poll(completion).unwrap().is_empty(),
        "elapsed ticks must be discarded"
    );
    assert!((f.next_deadline().unwrap() - (start + 20.)).abs() < 1e-8);
    assert!(f.poll(start + 19.9995).unwrap().is_empty());
    let actions = f.poll(start + 20. + 1e-8).unwrap();
    assert!(
        actions
            .iter()
            .any(|a| a.exit_id == held && a.kind == ActionKind::Sample)
    );
    for n in 1..=5 {
        assert_eq!(
            f.status(&format!("mullvad-{n}"), start + 20. + 1e-8)
                .unwrap()
                .state,
            HealthState::Ready
        );
    }
}

#[test]
fn late_cancel_cannot_downgrade_a_scoped_failed_exit() {
    let mut f = fleet(5);
    let token = f.select("mullvad-1").unwrap();
    f.cleanup_failed(&token).unwrap();
    let before = f.status("mullvad-1", 0.).unwrap();
    assert_eq!(before.state, HealthState::Failed);
    f.cancel(&token).unwrap();
    let after = f.status("mullvad-1", 0.).unwrap();
    assert_eq!(after.state, HealthState::Failed);
    assert_eq!(after.reason, before.reason);
    // Peers are untouched and the failed exit still gets quarantine-and-stop.
    assert_ne!(
        f.status("mullvad-2", 0.).unwrap().state,
        HealthState::Failed
    );
    let actions = f.poll(0.).unwrap();
    assert!(
        actions
            .iter()
            .any(|a| a.kind == ActionKind::QuarantineAndStop)
    );
}

#[test]
fn repeated_container_failure_cannot_rearm_drained_emergency_actions() {
    let mut f = fleet(1);
    f.container_failed();
    assert_eq!(f.poll(1.).unwrap().len(), 1);
    f.container_failed();
    assert!(f.poll(2.).unwrap().is_empty());
}

#[test]
fn finite_host_time_must_represent_subsecond_stagger_and_retry_without_zero_progress() {
    // At this finite value f64 can represent 90s but cannot represent the 1s
    // retry or subsecond staggering. It must fail closed before scheduling.
    let mut f = fleet(1);
    let t = f.select("mullvad-1").unwrap();
    assert!(f.restart(&t, "d".repeat(64), 1e17).is_err());
    assert_eq!(
        f.status("mullvad-1", 0.).unwrap().state,
        HealthState::Failed
    );
    assert_eq!(
        f.poll(1.).unwrap()[0].kind,
        ActionKind::EmergencyQuarantineAndStop
    );
}

#[test]
fn status_refuses_host_time_behind_the_high_water_mark_without_side_effects() {
    let mut f = fleet(2);
    f.poll(0.).unwrap();
    f.poll(2.).unwrap();
    // Behind the accepted fleet time, non-finite and negative queries are refused.
    assert!(f.status("mullvad-1", 1.).is_err());
    assert!(f.status("mullvad-1", f64::NAN).is_err());
    assert!(f.status("mullvad-1", -1.).is_err());
    // Observational: no state change, no emergency, same-or-later time still works.
    let at = f.status("mullvad-1", 2.).unwrap();
    assert_eq!(at.state, f.status("mullvad-1", 3.).unwrap().state);
    assert!(f.status("mullvad-2", 2.).is_ok());
    assert!(
        f.poll(3.)
            .unwrap()
            .iter()
            .all(|a| { a.kind != ActionKind::EmergencyQuarantineAndStop })
    );
}
