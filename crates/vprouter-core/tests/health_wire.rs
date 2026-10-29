use vprouter_core::{
    config::ExitMode,
    health::{Binding, ReplayWindow, Snapshot},
    state::{Evidence, HealthMachine, VerificationResult},
};
fn binding() -> Binding {
    Binding {
        deployment_id: "test".into(),
        exit_id: "primary".into(),
        mode: ExitMode::Mullvad,
        generation: 7,
        display_name: "mullvad-site-exit-de-fra-wg-404".into(),
        expected_server: Some("de-fra-wg-404".into()),
        node_id: "node1".into(),
        config_fingerprint: "a".repeat(64),
        boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
    }
}
fn machine() -> HealthMachine {
    let mut m = HealthMachine::new(ExitMode::Mullvad, Some("de-fra-wg-404"), "node1").unwrap();
    for t in [100., 105., 110., 115.] {
        m.observe(
            t,
            Evidence {
                provider_ok: true,
                structural_ok: true,
                provider_at: t,
                structural_at: t,
                heartbeat_at: t,
                handshake_age_seconds: Some(1.),
                online: true,
                policy_approved: true,
                server: Some("de-fra-wg-404".into()),
                node_id: Some("node1".into()),
                egress: Some("8.8.8.8".parse().unwrap()),
                verified_at: Some(t),
                dns: VerificationResult::NotTested,
                ipv6: VerificationResult::NotTested,
            },
        )
        .unwrap();
    }
    m
}
#[test]
fn producer_wire_roundtrips_and_checks_boot_generation_sequence_and_evidence_age() {
    let b = binding();
    let m = machine();
    let s = Snapshot::from_machine(b.clone(), 1, 116., &m).unwrap();
    let wire = serde_json::to_vec(&s).unwrap();
    let read = Snapshot::decode(&wire).unwrap();
    assert_eq!(read.validate(&b, 117.), Ok(Some(2.)));
    let mut replay = ReplayWindow::default();
    replay.accept(&read, &b, 117.).unwrap();
    assert!(replay.accept(&read, &b, 118.).is_err());
    assert!(read.validate(&b, 160.).is_err()); // heartbeat cannot refresh provider age
    for field in 0..4 {
        let mut wrong = b.clone();
        match field {
            0 => wrong.boot_id = "11234567-1234-1234-1234-0123456789ab".into(),
            1 => wrong.generation += 1,
            2 => wrong.config_fingerprint = "b".repeat(64),
            _ => wrong.node_id = "node2".into(),
        }
        assert!(read.validate(&wrong, 117.).is_err());
    }
    assert!(read.validate(&b, 1.).is_err()); // process-origin clock is not boot time
    assert!(read.validate(&b, 1000.).is_err()); // suspend counts toward age
}
#[test]
fn blocked_state_discards_old_success_and_wire_refuses_unknown_duplicate_fields() {
    let mut m = machine();
    m.block(vprouter_core::reason::Reason::StructuralFailure);
    let s = Snapshot::from_machine(binding(), 2, 120., &m).unwrap();
    assert!(s.evidence.is_none());
    assert_eq!(s.validate(&binding(), 121.), Ok(None));
    let text = serde_json::to_string(&s).unwrap();
    assert!(Snapshot::decode(text.replacen("{", "{\"version\":2,", 1).as_bytes()).is_err());
    assert!(Snapshot::decode(text.replacen("{", "{\"foreign\":true,", 1).as_bytes()).is_err());
}

#[test]
fn replay_window_cannot_be_rebound_to_another_boot_or_generation() {
    let b = binding();
    let m = machine();
    let s = Snapshot::from_machine(b.clone(), 1, 116., &m).unwrap();
    let mut replay = ReplayWindow::default();
    replay.accept(&s, &b, 117.).unwrap();
    let mut changed = b.clone();
    changed.generation += 1;
    let other = Snapshot::from_machine(changed.clone(), 2, 118., &m).unwrap();
    assert!(replay.accept(&other, &changed, 119.).is_err());
}

#[test]
fn lifecycle_messages_cannot_replay_rebind_or_refresh_verification() {
    use vprouter_core::health::{HealthMessage, Session};
    let b = binding();
    let nonce = "c".repeat(64);
    let mut session = Session::new(b.clone(), nonce.clone(), 116.).unwrap();
    let s = Snapshot::from_machine(b.clone(), 1, 116., &machine()).unwrap();
    let first = HealthMessage {
        version: 1,
        lifecycle: nonce.clone(),
        sequence: 1,
        sent_at: 116.,
        snapshot: Some(s),
    };
    session.accept(&first, 116.).unwrap();
    assert_eq!(session.expires_at().unwrap(), 159.);
    for (seq, at) in [(2, 120.), (3, 130.), (4, 140.), (5, 158.)] {
        let heartbeat = HealthMessage {
            version: 1,
            lifecycle: nonce.clone(),
            sequence: seq,
            sent_at: at,
            snapshot: None,
        };
        session.accept(&heartbeat, at).unwrap();
        assert_eq!(session.expires_at().unwrap(), 159.);
    }
    // Last verification was115; fresh messages cannot extend its44s lease.
    assert!(session.check(158.99).is_ok());
    assert!(session.check(159.).is_err());
    let fresh = HealthMessage {
        version: 1,
        lifecycle: nonce.clone(),
        sequence: 6,
        sent_at: 159.,
        snapshot: None,
    };
    assert!(session.accept(&fresh, 159.).is_err());
    assert!(session.check(158.).is_err()); // expiration irrevocable
    let mut replay = Session::new(b.clone(), nonce.clone(), 116.).unwrap();
    replay.accept(&first, 116.).unwrap();
    assert!(replay.accept(&first, 117.).is_err());
    let mut other = Session::new(b, "d".repeat(64), 116.).unwrap();
    assert!(other.accept(&first, 116.).is_err());
}

#[test]
fn session_rejects_old_evidence_in_new_publications_and_bounded_wire() {
    use vprouter_core::health::{HealthMessage, Session};
    let b = binding();
    let nonce = "c".repeat(64);
    let mut session = Session::new(b.clone(), nonce.clone(), 116.).unwrap();
    let mut snapshot = Snapshot::from_machine(b, 1, 116., &machine()).unwrap();
    let first = HealthMessage {
        version: 1,
        lifecycle: nonce.clone(),
        sequence: 1,
        sent_at: 116.,
        snapshot: Some(snapshot.clone()),
    };
    let bytes = serde_json::to_vec(&first).unwrap();
    let wire = HealthMessage::decode(&bytes).unwrap();
    session.accept(&wire, 116.).unwrap();
    snapshot.sequence = 2;
    snapshot.published_at = 120.;
    let repeated = HealthMessage {
        version: 1,
        lifecycle: nonce,
        sequence: 2,
        sent_at: 120.,
        snapshot: Some(snapshot),
    };
    assert!(session.accept(&repeated, 120.).is_err());
    assert!(HealthMessage::decode(&vec![b' '; 32769]).is_err());
    let text = String::from_utf8(bytes).unwrap();
    assert!(HealthMessage::decode(text.replacen("{", "{\"version\":1,", 1).as_bytes()).is_err());
}

#[test]
fn ready_wire_refuses_negative_provider_and_structural_evidence() {
    let b = binding();
    for structural in [false, true] {
        let mut s = Snapshot::from_machine(b.clone(), 1, 116., &machine()).unwrap();
        if structural {
            s.evidence.as_mut().unwrap().structural_ok = false;
        } else {
            s.evidence.as_mut().unwrap().provider_ok = false;
        }
        assert!(s.validate(&b, 116.).is_err());
    }
}

#[test]
fn session_handshake_expiry_survives_heartbeats_and_cannot_overflow() {
    use vprouter_core::health::{HealthMessage, Session};
    let b = binding();
    let lifecycle = "c".repeat(64);
    let mut snapshot = Snapshot::from_machine(b.clone(), 1, 116., &machine()).unwrap();
    let evidence = snapshot.evidence.as_mut().unwrap();
    evidence.structural_at = 116.;
    evidence.handshake_age_seconds = Some(179.);
    let first = HealthMessage {
        version: 1,
        lifecycle: lifecycle.clone(),
        sequence: 1,
        sent_at: 116.,
        snapshot: Some(snapshot.clone()),
    };
    let mut session = Session::new(b.clone(), lifecycle.clone(), 116.).unwrap();
    session.accept(&first, 116.).unwrap();
    assert_eq!(session.expires_at().unwrap(), 117.);
    session
        .accept(
            &HealthMessage {
                version: 1,
                lifecycle: lifecycle.clone(),
                sequence: 2,
                sent_at: 116.5,
                snapshot: None,
            },
            116.5,
        )
        .unwrap();
    session.check(116.999).unwrap();
    assert!(session.check(117.).is_err());
    assert!(session.check(116.999).is_err()); // cannot revive by a clock regression
    let mut at_boundary = Session::new(b.clone(), lifecycle.clone(), 116.).unwrap();
    at_boundary.accept(&first, 116.).unwrap();
    assert!(
        at_boundary
            .accept(
                &HealthMessage {
                    version: 1,
                    lifecycle: lifecycle.clone(),
                    sequence: 2,
                    sent_at: 117.,
                    snapshot: None
                },
                117.
            )
            .is_err()
    );
    // No finite deadline can be represented when addition rounds/overflows.
    snapshot.published_at = f64::MAX;
    let e = snapshot.evidence.as_mut().unwrap();
    e.provider_at = f64::MAX;
    e.structural_at = f64::MAX;
    e.heartbeat_at = f64::MAX;
    e.verified_at = Some(f64::MAX);
    e.handshake_age_seconds = Some(1.);
    let mut extreme = Session::new(b, lifecycle.clone(), f64::MAX).unwrap();
    assert!(
        extreme
            .accept(
                &HealthMessage {
                    version: 1,
                    lifecycle,
                    sequence: 1,
                    sent_at: f64::MAX,
                    snapshot: Some(snapshot)
                },
                f64::MAX
            )
            .is_err()
    );
}

#[test]
fn blocked_recovery_samples_remain_publishable_without_granting_readiness() {
    use vprouter_core::{reason::Reason, state::HealthState};
    let mut m = machine();
    let mut evidence = Snapshot::from_machine(binding(), 1, 116., &m)
        .unwrap()
        .evidence
        .unwrap();
    m.block(Reason::ProviderFailure);
    for (sequence, at) in [(2, 120.), (3, 125.), (4, 130.), (5, 135.)] {
        evidence.provider_at = at;
        evidence.structural_at = at;
        evidence.heartbeat_at = at;
        evidence.verified_at = Some(at);
        let state = m.observe(at, evidence.clone()).unwrap();
        let snapshot = Snapshot::from_machine(binding(), sequence, at, &m).unwrap();
        snapshot.validate(&binding(), at).unwrap();
        assert_eq!(state == HealthState::Ready, sequence == 5);
        if sequence < 4 {
            assert_eq!(state, HealthState::Blocked);
        }
    }
}
