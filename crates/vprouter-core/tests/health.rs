use vprouter_core::{
    config::ExitMode,
    state::{Evidence, HealthMachine, HealthState, VerificationResult},
};
fn healthy(at: f64) -> Evidence {
    Evidence {
        provider_ok: true,
        structural_ok: true,
        provider_at: at,
        structural_at: at,
        heartbeat_at: at,
        handshake_age_seconds: Some(1.0),
        online: true,
        policy_approved: true,
        server: Some("de-fra-wg-404".into()),
        node_id: Some("node123".into()),
        egress: Some("185.65.134.88".parse().unwrap()),
        verified_at: Some(at),
        dns: VerificationResult::NotTested,
        ipv6: VerificationResult::NotTested,
    }
}
fn machine() -> HealthMachine {
    HealthMachine::new(ExitMode::Mullvad, Some("de-fra-wg-404"), "node123").unwrap()
}
#[test]
fn explicit_expiry_preserves_empty_startup_and_checks_cached_boundaries() {
    let mut empty = machine();
    assert!(!empty.expire(0.0));
    assert!(!empty.expire(100.0));
    assert_eq!(empty.state(), HealthState::Starting);
    for count in 1..=4 {
        for gap in [45.0, 46.0] {
            let mut m = machine();
            for n in 0..count {
                let at = 100.0 + n as f64 * 5.0;
                m.observe(at, healthy(at)).unwrap();
            }
            let at = 100.0 + (count - 1) as f64 * 5.0;
            assert!(!m.expire(at + 44.999));
            assert!(m.expire(at + gap));
            assert_eq!(m.state(), HealthState::Blocked);
            assert!(!m.expire(at + gap)); // already revoked
            for n in 0..2 {
                let now = at + gap + n as f64 * 5.0;
                assert_eq!(m.observe(now, healthy(now)).unwrap(), HealthState::Blocked);
            }
            let now = at + gap + 10.0;
            assert_eq!(
                m.observe(now, healthy(now)).unwrap(),
                HealthState::Recovering
            );
        }
    }
    for now in [99.0, -1.0, f64::NAN, f64::INFINITY] {
        let mut m = machine();
        m.observe(100.0, healthy(100.0)).unwrap();
        assert!(m.expire(now));
        assert_eq!(m.state(), HealthState::Blocked);
    }
    let mut m = machine();
    let mut e = healthy(100.0);
    e.handshake_age_seconds = Some(179.0);
    m.observe(100.0, e).unwrap();
    assert!(!m.expire(100.999));
    assert!(m.expire(101.0));
}
#[test]
fn startup_requires_three_fresh_checks_then_online_approval() {
    let mut m = machine();
    assert_eq!(
        m.observe(100.0, healthy(100.0)).unwrap(),
        HealthState::Starting
    );
    assert_eq!(
        m.observe(105.0, healthy(105.0)).unwrap(),
        HealthState::Starting
    );
    assert_eq!(
        m.observe(110.0, healthy(110.0)).unwrap(),
        HealthState::Recovering
    );
    let mut unapproved = healthy(115.0);
    unapproved.policy_approved = false;
    assert_eq!(
        m.observe(115.0, unapproved).unwrap(),
        HealthState::Recovering
    );
    assert_eq!(
        m.observe(120.0, healthy(120.0)).unwrap(),
        HealthState::Ready
    );
    assert_eq!(m.status(120.0).unwrap().dns, VerificationResult::NotTested);
    assert!(m.status(165.0).is_err());
}
#[test]
fn replayed_success_never_reaches_ready_and_failure_resets_streak() {
    let mut m = machine();
    m.observe(100.0, healthy(100.0)).unwrap();
    assert!(m.observe(101.0, healthy(100.0)).is_err());
    assert_eq!(m.state(), HealthState::Blocked);
    for at in [105.0, 110.0] {
        assert_eq!(m.observe(at, healthy(at)).unwrap(), HealthState::Blocked);
    }
    assert_eq!(
        m.observe(115.0, healthy(115.0)).unwrap(),
        HealthState::Recovering
    );
}
#[test]
fn invalid_time_age_server_or_node_blocks_immediately() {
    for mutation in 0..9 {
        let mut m = machine();
        for at in [100.0, 105.0, 110.0, 115.0] {
            m.observe(at, healthy(at)).unwrap();
        }
        let mut e = healthy(120.0);
        let mut now = 120.0;
        match mutation {
            0 => e.handshake_age_seconds = Some(180.0),
            1 => e.heartbeat_at = 75.0,
            2 => e.provider_at = 121.0,
            3 => e.handshake_age_seconds = Some(f64::NAN),
            4 => now = f64::INFINITY,
            5 => e.server = Some("de-fra-wg-405".into()),
            6 => e.node_id = None,
            7 => e.egress = None,
            _ => e.verified_at = None,
        }
        assert!(m.observe(now, e).is_err(), "case {mutation}");
        assert_eq!(m.state(), HealthState::Blocked);
    }
}
#[test]
fn direct_reports_exposure_and_cannot_change_mode_while_running() {
    let mut m = HealthMachine::new(ExitMode::Direct, None, "node123").unwrap();
    for at in [100.0, 105.0, 110.0, 115.0] {
        let mut e = healthy(at);
        e.server = None;
        e.handshake_age_seconds = None;
        m.observe(at, e).unwrap();
    }
    assert_eq!(m.status(115.0).unwrap().exposure, "direct-exposed");
    assert!(
        m.reconfigure(ExitMode::Mullvad, Some("de-fra-wg-404"), "node123")
            .is_err()
    );
    m.stop();
    assert!(
        m.reconfigure(ExitMode::Mullvad, Some("de-fra-wg-404"), "node123")
            .is_ok()
    );
}
#[test]
fn negative_verification_or_fatal_state_never_reports_protected() {
    for mutation in 0..6 {
        let mut m = machine();
        for at in [100.0, 105.0, 110.0, 115.0] {
            m.observe(at, healthy(at)).unwrap();
        }
        let mut e = healthy(120.0);
        match mutation {
            0 => e.dns = VerificationResult::Failed,
            1 => e.ipv6 = VerificationResult::Failed,
            2 => e.verified_at = Some(75.0),
            3 => e.handshake_age_seconds = Some(-1.0),
            4 => e.online = false,
            _ => e.policy_approved = false,
        }
        assert!(m.observe(120.0, e).is_err());
        assert_eq!(m.state(), HealthState::Blocked);
        assert_eq!(m.status(120.0).unwrap().exposure, "unverified");
    }
    let mut m = machine();
    m.fail(vprouter_core::reason::Reason::StructuralFailure);
    assert!(m.observe(100.0, healthy(100.0)).is_err());
    assert_eq!(m.state(), HealthState::Failed);
    m.stop();
    assert!(m.observe(100.0, healthy(100.0)).is_err());
}
#[test]
fn staggering_is_bounded_stable_and_absent_for_one_exit() {
    use vprouter_core::state::provider_offset_ms;
    assert_eq!(provider_offset_ms("fleet", "one", 1), 0);
    let a = provider_offset_ms("fleet", "one", 5);
    assert!(a < 5000);
    assert_eq!(a, provider_offset_ms("fleet", "one", 6));
    assert_ne!(a, provider_offset_ms("fleet", "two", 5));
}
#[test]
fn cached_handshake_ages_even_before_heartbeat_expires() {
    let mut m = machine();
    for at in [100.0, 105.0, 110.0] {
        m.observe(at, healthy(at)).unwrap();
    }
    let mut e = healthy(115.0);
    e.handshake_age_seconds = Some(179.0);
    assert_eq!(m.observe(115.0, e).unwrap(), HealthState::Ready);
    assert!(m.status(115.5).is_ok());
    assert!(m.status(116.0).is_err());
}

#[test]
fn observation_after_any_long_gap_requires_three_new_checks_and_recovery() {
    // Cover partial STARTING and BLOCKED streaks, RECOVERING, and READY.
    for scenario in 0..4 {
        let mut m = machine();
        let last = match scenario {
            0 => {
                m.observe(110.0, healthy(110.0)).unwrap();
                115.0
            }
            1 => {
                m.block(vprouter_core::reason::Reason::ProviderFailure);
                m.observe(110.0, healthy(110.0)).unwrap();
                115.0
            }
            2 => {
                for at in [105.0, 110.0] {
                    m.observe(at, healthy(at)).unwrap();
                }
                115.0
            }
            _ => {
                for at in [100.0, 105.0, 110.0] {
                    m.observe(at, healthy(at)).unwrap();
                }
                115.0
            }
        };
        m.observe(last, healthy(last)).unwrap();
        let before = m.state();
        if before == HealthState::Ready {
            assert!(m.status(160.0).is_err());
        }
        assert_eq!(m.state(), before, "status must stay observational");
        assert_eq!(
            m.observe(161.0, healthy(161.0)).unwrap(),
            HealthState::Blocked,
            "scenario {scenario}"
        );
        assert_eq!(
            m.observe(166.0, healthy(166.0)).unwrap(),
            HealthState::Blocked
        );
        assert_eq!(
            m.observe(171.0, healthy(171.0)).unwrap(),
            HealthState::Recovering
        );
        assert_eq!(
            m.observe(176.0, healthy(176.0)).unwrap(),
            HealthState::Ready
        );
    }
}
#[test]
fn expired_cached_handshake_resets_recovery_before_new_healthy_sample() {
    for scenario in 0..4 {
        let mut m = machine();
        if scenario == 1 {
            m.block(vprouter_core::reason::Reason::ProviderFailure);
        }
        let count = match scenario {
            0 | 1 => 2,
            2 => 3,
            _ => 4,
        };
        for i in 0..count {
            let at = 100.0 + f64::from(i) * 5.0;
            let mut e = healthy(at);
            if i == count - 1 {
                e.handshake_age_seconds = Some(179.0);
            }
            m.observe(at, e).unwrap();
        }
        // The cached handshake expires after1s; all other cached checks stay fresh.
        let next = 100.0 + f64::from(count - 1) * 5.0 + 2.0;
        assert_eq!(
            m.observe(next, healthy(next)).unwrap(),
            HealthState::Blocked,
            "scenario {scenario}"
        );
        assert_eq!(
            m.observe(next + 5.0, healthy(next + 5.0)).unwrap(),
            HealthState::Blocked
        );
        assert_eq!(
            m.observe(next + 10.0, healthy(next + 10.0)).unwrap(),
            HealthState::Recovering
        );
        assert_eq!(
            m.observe(next + 15.0, healthy(next + 15.0)).unwrap(),
            HealthState::Ready
        );
    }
}
