use super::*;
use std::{cell::RefCell, collections::VecDeque};
#[derive(Default)]
struct Faults {
    provider: VecDeque<Result<Confirmation>>,
    structure_at: Option<usize>,
    structures: usize,
    advertised: bool,
    approved: bool,
    age: f64,
    withdraw_fail: bool,
    delay: Duration,
    guard_seen: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    stop_after_withdraw: Option<watch::Sender<bool>>,
}
struct Script {
    origin: Instant,
    faults: Rc<RefCell<Faults>>,
    events: Rc<RefCell<Vec<(&'static str, Duration)>>>,
}
impl Script {
    fn event(&self, event: &'static str) {
        self.events
            .borrow_mut()
            .push((event, self.origin.elapsed()));
    }
}
impl Inputs for Script {
    fn now(&self) -> f64 {
        self.origin.elapsed().as_secs_f64()
    }
    async fn initialize(&mut self) -> Result<()> {
        self.event("initialize");
        Ok(())
    }
    async fn structure(&mut self) -> Result<Structural> {
        self.event("structure");
        let mut f = self.faults.borrow_mut();
        f.structures += 1;
        if f.structure_at == Some(f.structures) {
            return Err(Error::Structural);
        }
        Ok(Structural {
            at: self.origin.elapsed().as_secs_f64(),
            handshake_age: f.age,
        })
    }
    async fn provider(&mut self) -> Result<Confirmation> {
        self.event("provider");
        let delay = self.faults.borrow().delay;
        time::sleep(delay).await;
        self.faults
            .borrow_mut()
            .provider
            .pop_front()
            .unwrap_or(Ok(Confirmation {
                ip: "1.2.3.4".parse().unwrap(),
                server: "de-fra-wg-404".into(),
            }))
    }
    async fn local(&mut self) -> Result<Observation> {
        self.event("local");
        let f = self.faults.borrow();
        Ok(Observation {
            advertised: f.advertised,
            approved: f.approved,
        })
    }
    async fn advertise(&mut self) -> Result<()> {
        self.event("advertise");
        self.faults.borrow_mut().advertised = true;
        Ok(())
    }
    async fn withdraw(&mut self) -> Result<()> {
        self.event("withdraw");
        let mut f = self.faults.borrow_mut();
        if let Some(seen) = &f.guard_seen {
            assert!(
                seen.load(std::sync::atomic::Ordering::SeqCst),
                "withdrawal preceded guard notification"
            );
        }
        if let Some(stop) = f.stop_after_withdraw.take() {
            stop.send(true).unwrap();
        }
        f.advertised = false;
        if f.withdraw_fail {
            Err(Error::Transport)
        } else {
            Ok(())
        }
    }
    fn cancel(&mut self) {
        self.event("cancel");
    }
}
fn engine() -> Engine<Script> {
    let origin = Instant::now();
    let script = Script {
        origin,
        faults: Rc::new(RefCell::new(Faults::default())),
        events: Rc::new(RefCell::new(Vec::new())),
    };
    Engine::new(script, ExitMode::Mullvad, "de-fra-wg-404", "n123", origin).unwrap()
}
fn count(e: &Engine<Script>, event: &str) -> usize {
    e.inputs
        .events
        .borrow()
        .iter()
        .filter(|(s, _)| s == &event)
        .count()
}
fn operational_receipt(state: crate::operation::PolicyState) -> crate::operation::PolicyReceipt {
    crate::operation::PolicyReceipt {
        binding: vprouter_core::health::Binding {
            deployment_id: "test".into(),
            exit_id: "one".into(),
            mode: ExitMode::Mullvad,
            generation: 1,
            display_name: "test-exit".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "n123".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        },
        state,
    }
}
#[tokio::test(start_paused = true)]
async fn one_retry_has_actual_one_second_delay_and_fresh_structure_each_side() {
    for error in [Error::HttpTransient, Error::Transport, Error::Deadline] {
        let mut e = engine();
        e.inputs.faults.borrow_mut().provider.push_back(Err(error));
        e.sample().await.unwrap();
        assert_eq!(count(&e, "provider"), 2);
        assert_eq!(count(&e, "structure"), 5);
        let events = e.inputs.events.borrow();
        let providers: Vec<_> = events
            .iter()
            .filter(|(n, _)| *n == "provider")
            .map(|(_, t)| *t)
            .collect();
        assert_eq!(providers[1] - providers[0], Duration::from_secs(1));
        let second = events
            .iter()
            .position(|(n, t)| *n == "provider" && *t == providers[1])
            .unwrap();
        assert_eq!(events[second - 1].0, "structure");
    }
}
#[tokio::test(start_paused = true)]
async fn post_delay_drift_or_handshake_boundary_prevents_retry_and_success() {
    for check in [2, 3, 4, 5] {
        let mut e = engine();
        let f = e.inputs.faults.clone();
        f.borrow_mut().provider.push_back(Err(Error::HttpTransient));
        f.borrow_mut().structure_at = Some(check);
        assert_eq!(e.sample().await, Err(Error::Structural));
        assert_eq!(count(&e, "provider"), if check < 4 { 1 } else { 2 });
    }
    for age in [180.0, 180.1, -1.0, f64::NAN] {
        let mut e = engine();
        e.inputs.faults.borrow_mut().age = age;
        assert_eq!(e.sample().await, Err(Error::Structural));
    }
    let mut e = engine();
    e.inputs.faults.borrow_mut().age = 179.99;
    e.sample().await.unwrap();
}
#[tokio::test(start_paused = true)]
async fn permanent_negative_tls_wrongserver_never_retry_repeated_transport_stops_at_two() {
    for error in [
        Error::HttpPermanent,
        Error::Tls,
        Error::Malformed,
        Error::Oversized,
        Error::WrongServer,
        Error::ProviderNegative,
    ] {
        let mut e = engine();
        e.inputs.faults.borrow_mut().provider.push_back(Err(error));
        assert_eq!(e.sample().await, Err(error));
        assert_eq!(count(&e, "provider"), 1);
    }
    let mut e = engine();
    e.inputs
        .faults
        .borrow_mut()
        .provider
        .extend([Err(Error::Transport), Err(Error::Transport)]);
    assert_eq!(e.sample().await, Err(Error::Transport));
    assert_eq!(count(&e, "provider"), 2);
}
#[tokio::test(start_paused = true)]
async fn withdrawn_false_approval_recovers_offers_then_waits_for_admin_and_revocation_blocks() {
    let mut e = engine();
    for _ in 0..3 {
        e.sample().await.unwrap();
        time::advance(CADENCE).await;
    }
    assert_eq!(e.machine.state(), HealthState::Recovering);
    assert_eq!(count(&e, "advertise"), 0);
    e.sample().await.unwrap();
    assert_eq!(count(&e, "advertise"), 1);
    assert_eq!(e.machine.state(), HealthState::Recovering);
    time::advance(CADENCE).await;
    e.sample().await.unwrap();
    assert_eq!(e.machine.state(), HealthState::Recovering);
    time::advance(CADENCE).await;
    e.inputs.faults.borrow_mut().approved = true;
    e.sample().await.unwrap();
    assert_eq!(e.machine.state(), HealthState::Ready);
    let s = e.machine.status(e.origin.elapsed().as_secs_f64()).unwrap();
    assert_eq!(s.dns, VerificationResult::NotTested);
    assert_eq!(s.ipv6, VerificationResult::NotTested);
    time::advance(CADENCE).await;
    e.inputs.faults.borrow_mut().approved = false;
    assert_eq!(e.sample().await, Err(Error::Structural));
    assert_eq!(e.machine.state(), HealthState::Blocked);
}
#[tokio::test(start_paused = true)]
async fn whole_operation_is_bounded_and_freshness_expires_without_observation() {
    let mut e = engine();
    e.inputs.faults.borrow_mut().delay = Duration::from_secs(100);
    let start = Instant::now();
    assert_eq!(e.sample().await, Err(Error::Deadline));
    assert_eq!(start.elapsed(), OPERATION);
    assert_eq!(count(&e, "cancel"), 1);
    let mut e = engine();
    e.inputs.faults.borrow_mut().advertised = true;
    e.inputs.faults.borrow_mut().approved = true;
    for _ in 0..4 {
        e.sample().await.unwrap();
        time::advance(CADENCE).await;
    }
    assert_eq!(e.machine.state(), HealthState::Ready);
    time::advance(Duration::from_secs(45)).await;
    assert!(e.machine.status(e.origin.elapsed().as_secs_f64()).is_err());
}
fn publisher() -> (crate::publish::Publisher, PathBuf) {
    let path = crate::tests::temp();
    let fd = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    (crate::publish::Publisher::synthetic(fd), path)
}
#[tokio::test]
async fn failure_notifies_guard_then_withdraws_or_requests_fixed_init_termination() {
    use crate::tests::{UnixMock, json_response};
    for withdrawal_fails in [false, true] {
        let mut guard = UnixMock::scripted(vec![(
            "POST",
            "/v1/worker/block",
            Some(serde_json::json!({"version":1,"sequence":1,"reason":"structural"})),
            json_response(serde_json::json!({"version":1,"sequence":1,"recorded":true})),
        )]);
        let mut init = UnixMock::scripted(if withdrawal_fails {
            vec![(
                "POST",
                "/v1/init/stop-tailscaled",
                Some(serde_json::json!({"version":1})),
                json_response(serde_json::json!({"version":1,"stopped":true})),
            )]
        } else {
            vec![]
        });
        let engine = engine();
        engine.inputs.faults.borrow_mut().withdraw_fail = withdrawal_fails;
        let (publisher, path) = publisher();
        let mut r = Runner {
            engine,
            control: Control {
                placed: Rc::new(Placed::synthetic()),
                guard: guard.path.clone(),
                init: init.path.clone(),
                sequence: 0,
            },
            publisher,
        };
        r.fail_closed(Error::Structural).await.unwrap();
        assert_eq!(r.engine.machine.state(), HealthState::Blocked);
        assert_eq!(count(&r.engine, "withdraw"), 1);
        guard.finished().await;
        init.finished().await;
        let output = std::fs::read_to_string(path.join("health.json")).unwrap();
        assert!(output.contains("BLOCKED"));
        assert!(!output.contains("1.2.3.4"));
        std::fs::remove_dir_all(path).unwrap();
    }
}
#[tokio::test]
async fn guard_wrong_ack_does_not_skip_withdrawal_or_grant_authority() {
    use crate::tests::{UnixMock, json_response};
    let mut guard = UnixMock::scripted(vec![(
        "POST",
        "/v1/worker/block",
        Some(serde_json::json!({"version":1,"sequence":1,"reason":"structural"})),
        json_response(serde_json::json!({"version":1,"sequence":999,"recorded":true})),
    )]);
    let (publisher, path) = publisher();
    let mut r = Runner {
        engine: engine(),
        control: Control {
            placed: Rc::new(Placed::synthetic()),
            guard: guard.path.clone(),
            init: path.join("missing-init"),
            sequence: 0,
        },
        publisher,
    };
    assert_eq!(
        r.fail_closed(Error::Structural).await,
        Err(Error::GuardUnavailable)
    );
    assert_eq!(count(&r.engine, "withdraw"), 1);
    guard.finished().await;
    assert_eq!(r.engine.machine.state(), HealthState::Blocked);
    std::fs::remove_dir_all(path).unwrap();
}
#[tokio::test]
async fn real_control_heartbeat_continues_during_slow_provider_and_shutdown_withdraws() {
    use crate::tests::{UnixMock, json_response};
    let mut guard = UnixMock::scripted(vec![
        (
            "POST",
            "/v1/worker/heartbeat",
            Some(serde_json::json!({"version":1,"sequence":1,"reason":null})),
            json_response(serde_json::json!({"version":1,"sequence":1,"recorded":true})),
        ),
        (
            "POST",
            "/v1/worker/heartbeat",
            Some(serde_json::json!({"version":1,"sequence":2,"reason":null})),
            json_response(serde_json::json!({"version":1,"sequence":2,"recorded":true})),
        ),
        (
            "POST",
            "/v1/worker/block",
            Some(serde_json::json!({"version":1,"sequence":3,"reason":"cancelled"})),
            json_response(serde_json::json!({"version":1,"sequence":3,"recorded":true})),
        ),
    ]);
    let (publisher, path) = publisher();
    let engine = engine();
    engine.inputs.faults.borrow_mut().delay = Duration::from_secs(30);
    let mut r = Runner {
        engine,
        control: Control {
            placed: Rc::new(Placed::synthetic()),
            guard: guard.path.clone(),
            init: path.join("unused"),
            sequence: 0,
        },
        publisher,
    };
    let (tx, rx) = watch::channel(false);
    let shutdown = tokio::spawn(async move {
        time::sleep(Duration::from_secs(11)).await;
        tx.send(true).unwrap();
    });
    let start = Instant::now();
    r.run(rx, "deployment", "exit", 1).await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(13));
    assert_eq!(r.control.sequence, 3);
    assert_eq!(count(&r.engine, "provider"), 1);
    assert_eq!(count(&r.engine, "withdraw"), 1);
    assert_eq!(r.engine.machine.state(), HealthState::Stopping);
    guard.finished().await;
    shutdown.await.unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

struct TlsInputs {
    script: Script,
    provider: Provider,
}
impl Inputs for TlsInputs {
    fn now(&self) -> f64 {
        self.script.now()
    }
    async fn initialize(&mut self) -> Result<()> {
        self.script.initialize().await
    }
    async fn structure(&mut self) -> Result<Structural> {
        self.script.structure().await
    }
    async fn provider(&mut self) -> Result<Confirmation> {
        self.script.event("provider");
        self.provider.confirm().await
    }
    async fn local(&mut self) -> Result<Observation> {
        self.script.local().await
    }
    async fn advertise(&mut self) -> Result<()> {
        self.script.advertise().await
    }
    async fn withdraw(&mut self) -> Result<()> {
        self.script.withdraw().await
    }
    fn cancel(&mut self) {
        self.provider.cancel();
    }
}

#[tokio::test]
async fn real_transport_eof_and_reset_retry_only_after_fresh_checks() {
    use crate::tests::{TlsMock, TransportFault};
    use std::sync::atomic::Ordering;
    for fault in [
        TransportFault::HandshakeEof,
        TransportFault::HandshakeReset,
        TransportFault::HttpEof,
        TransportFault::HttpReset,
        TransportFault::BodyEof,
        TransportFault::BodyReset,
    ] {
        for drift in [false, true] {
            let server = TlsMock::fault_then_success(fault).await;
            let fixture = engine();
            if drift {
                fixture.inputs.faults.borrow_mut().structure_at = Some(3);
            }
            let mut e = Engine::new(
                TlsInputs {
                    script: fixture.inputs,
                    provider: server.provider(),
                },
                ExitMode::Mullvad,
                "de-fra-wg-404",
                "n123",
                fixture.origin,
            )
            .unwrap();
            let start = Instant::now();
            assert_eq!(
                e.sample().await,
                if drift {
                    Err(Error::Structural)
                } else {
                    Ok(())
                },
                "{fault:?}, drift={drift}"
            );
            assert!(start.elapsed() >= Duration::from_secs(1));
            assert_eq!(
                server.connections.load(Ordering::Relaxed),
                if drift { 1 } else { 2 },
                "{fault:?}"
            );
            let handshake = matches!(
                fault,
                TransportFault::HandshakeEof | TransportFault::HandshakeReset
            );
            assert_eq!(
                server.requests.load(Ordering::Relaxed),
                usize::from(!handshake) + usize::from(!drift)
            );
            let events = e.inputs.script.events.borrow();
            assert_eq!(
                events.iter().filter(|(s, _)| *s == "structure").count(),
                if drift { 3 } else { 5 }
            );
            let providers: Vec<_> = events
                .iter()
                .enumerate()
                .filter(|(_, (s, _))| *s == "provider")
                .collect();
            assert_eq!(providers.len(), if drift { 1 } else { 2 });
            if !drift {
                let (second, (_, at)) = providers[1];
                assert_eq!(events[second - 1].0, "structure");
                assert!(at.saturating_sub(providers[0].1.1) >= Duration::from_secs(1));
            }
        }
    }
}

#[tokio::test]
async fn real_certificate_refusal_is_not_retried_by_engine() {
    use crate::tests::{PROVIDER, TlsMock, response};
    use std::sync::atomic::Ordering;
    for name in ["wrong.invalid", "am.i.mullvad.net"] {
        let server = TlsMock::new(name, vec![response(200, PROVIDER)], 1).await;
        let fixture = engine();
        let mut provider = server.provider();
        if name == "am.i.mullvad.net" {
            provider = Provider::synthetic(
                Rc::new(Placed::synthetic()),
                rustls::RootCertStore::empty(),
                server.address(),
            );
        }
        let mut e = Engine::new(
            TlsInputs {
                script: fixture.inputs,
                provider,
            },
            ExitMode::Mullvad,
            "de-fra-wg-404",
            "n123",
            fixture.origin,
        )
        .unwrap();
        assert_eq!(e.sample().await, Err(Error::Tls));
        assert_eq!(server.connections.load(Ordering::Relaxed), 1);
        assert_eq!(server.requests.load(Ordering::Relaxed), 0);
        assert_eq!(e.inputs.script.faults.borrow().structures, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn recovering_expiry_before_sample_or_offer_resets_three_success_gate() {
    for (gap, delay) in [(45, 0), (46, 0), (44, 2)] {
        let mut e = engine();
        for n in 0..3 {
            if n > 0 {
                time::advance(CADENCE).await;
            }
            e.sample().await.unwrap();
        }
        assert_eq!(e.machine.state(), HealthState::Recovering);
        time::advance(Duration::from_secs(gap)).await;
        e.inputs.faults.borrow_mut().delay = Duration::from_secs(delay);
        assert_eq!(e.sample().await, Err(Error::Structural));
        e.inputs.faults.borrow_mut().delay = Duration::ZERO;
        assert_eq!(count(&e, "advertise"), 0);
        assert_eq!(e.machine.state(), HealthState::Blocked);
        for _ in 0..3 {
            e.sample().await.unwrap();
            assert_eq!(count(&e, "advertise"), 0);
            time::advance(CADENCE).await;
        }
        assert_eq!(e.machine.state(), HealthState::Recovering);
        e.sample().await.unwrap();
        assert_eq!(count(&e, "advertise"), 1);
    }
}

#[tokio::test]
async fn expired_ready_runner_notifies_guard_before_withdrawing_without_success_heartbeat() {
    use crate::tests::{json_response, read_request};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::{io::AsyncWriteExt, net::UnixListener};
    for gap in [45, 46] {
        time::pause();
        let mut engine = engine();
        engine.inputs.faults.borrow_mut().approved = true;
        for n in 0..4 {
            if n > 0 {
                time::advance(CADENCE).await;
            }
            engine.sample().await.unwrap();
        }
        assert_eq!(engine.machine.state(), HealthState::Ready);
        assert_eq!(count(&engine, "advertise"), 1);
        let providers_before = count(&engine, "provider");
        time::advance(Duration::from_secs(gap)).await;
        time::resume();
        let (publisher, path) = publisher();
        let guard = path.join("guard.sock");
        let listener = UnixListener::bind(&guard).unwrap();
        let seen = Arc::new(AtomicBool::new(false));
        let guard_seen = seen.clone();
        let server = tokio::spawn(async move {
            for (sequence, reason) in [(1, "structural"), (2, "cancelled")] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = read_request(&mut socket).await;
                assert_eq!((&*request.0, &*request.1), ("POST", "/v1/worker/block"));
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&request.2).unwrap(),
                    serde_json::json!({"version":1,"sequence":sequence,"reason":reason})
                );
                guard_seen.store(true, Ordering::SeqCst);
                socket
                    .write_all(&json_response(
                        serde_json::json!({"version":1,"sequence":sequence,"recorded":true}),
                    ))
                    .await
                    .unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        let (stop, rx) = watch::channel(false);
        engine.inputs.faults.borrow_mut().guard_seen = Some(seen);
        engine.inputs.faults.borrow_mut().stop_after_withdraw = Some(stop);
        let mut runner = Runner {
            engine,
            publisher,
            control: Control {
                placed: Rc::new(Placed::synthetic()),
                guard,
                init: path.join("unused"),
                sequence: 0,
            },
        };
        time::timeout(
            Duration::from_secs(4),
            runner.run(rx, "deployment", "exit", 1),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        assert_eq!(count(&runner.engine, "provider"), providers_before);
        assert_eq!(count(&runner.engine, "advertise"), 1);
        assert_eq!(count(&runner.engine, "withdraw"), 2); // expiry, then shutdown
        assert!(!runner.engine.inputs.faults.borrow().advertised);
        assert_eq!(runner.control.sequence, 2); // both blocks, no success heartbeat
        std::fs::remove_dir_all(path).unwrap();
    }
}
#[tokio::test]
async fn real_controlled_tls_retry_and_post_delay_drift_use_the_same_engine() {
    use crate::tests::{PROVIDER, TlsMock, response};
    for drift in [false, true] {
        let replies = if drift {
            vec![response(503, b"SYNTHETIC_SECRET")]
        } else {
            vec![response(503, b"SYNTHETIC_SECRET"), response(200, PROVIDER)]
        };
        let server = TlsMock::new("am.i.mullvad.net", replies, if drift { 1 } else { 2 }).await;
        let fixture = engine();
        if drift {
            fixture.inputs.faults.borrow_mut().structure_at = Some(3);
        }
        let origin = fixture.origin;
        let mut e = Engine::new(
            TlsInputs {
                script: fixture.inputs,
                provider: server.provider(),
            },
            ExitMode::Mullvad,
            "de-fra-wg-404",
            "n123",
            origin,
        )
        .unwrap();
        let start = Instant::now();
        assert_eq!(
            e.sample().await,
            if drift {
                Err(Error::Structural)
            } else {
                Ok(())
            }
        );
        assert!(
            start.elapsed() >= Duration::from_secs(1) && start.elapsed() < Duration::from_secs(4)
        );
        assert_eq!(
            server
                .connections
                .load(std::sync::atomic::Ordering::Relaxed),
            if drift { 1 } else { 2 }
        );
        assert_ne!(e.machine.state(), HealthState::Ready);
    }
}

#[test]
fn direct_mode_is_rejected() {
    let e = engine();
    let now = Instant::now();
    assert!(matches!(
        Engine::new(e.inputs, ExitMode::Direct, "de-fra-wg-404", "n123", now),
        Err(Error::DirectUnsupported)
    ));
}

#[tokio::test]
async fn operational_failure_waits_for_quarantine_ack_before_withdrawal_and_binds_commit() {
    use crate::operation::{Channel, Reply, Request};
    use vprouter_core::health::{Binding, HealthMessage, Snapshot, boot_seconds};
    for wrong_commit in [false, true] {
        let mut engine = engine();
        engine.machine.block(Reason::ProviderFailure);
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        engine.inputs.faults.borrow_mut().guard_seen = Some(seen.clone());
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer = std::thread::spawn(move || {
            for stage in 0..3 {
                let request: Request = crate::bootstrap::read_message(&mut server).unwrap();
                let frame = request.frame().clone();
                assert_eq!(frame.sequence, stage + 1);
                let reply = match (stage, request) {
                    (0, Request::Prepare { message, .. }) => {
                        assert_eq!(message.snapshot.unwrap().state, HealthState::Blocked);
                        seen.store(true, std::sync::atomic::Ordering::SeqCst);
                        Reply::Prepared {
                            frame,
                            policy: operational_receipt(crate::operation::PolicyState::Offline),
                        }
                    }
                    (
                        1,
                        Request::Persist {
                            snapshot_sequence: 1,
                            ..
                        },
                    ) => Reply::Persisted { frame },
                    (
                        2,
                        Request::Commit {
                            snapshot_sequence: 1,
                            ..
                        },
                    ) => Reply::Enforced {
                        frame,
                        policy: operational_receipt(crate::operation::PolicyState::Offline),
                        state: if wrong_commit {
                            HealthState::Ready
                        } else {
                            HealthState::Blocked
                        },
                    },
                    _ => panic!("out of order publication"),
                };
                crate::bootstrap::write_message(&mut server, &reply).unwrap();
            }
        });
        let channel = Rc::new(tokio::sync::Mutex::new(
            Channel::new(client, "a".repeat(64)).unwrap(),
        ));
        let binding = Binding {
            deployment_id: "test".into(),
            exit_id: "one".into(),
            mode: ExitMode::Mullvad,
            generation: 1,
            display_name: "test-exit".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "n123".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        };
        let now = boot_seconds();
        let snapshot = Snapshot::from_machine(binding, 1, now, &engine.machine).unwrap();
        let message = HealthMessage {
            version: 1,
            lifecycle: "a".repeat(64),
            sequence: 1,
            sent_at: now,
            snapshot: Some(snapshot),
        };
        let result = operational_publish(&channel, message, &mut engine.inputs, true).await;
        assert_eq!(result.is_ok(), !wrong_commit);
        assert_eq!(count(&engine, "withdraw"), 1);
        peer.join().unwrap();
    }
}

#[tokio::test]
async fn operational_failure_requires_bound_offline_receipts_and_returns_original_error_last() {
    use crate::operation::{Channel, PolicyState, Reply, Request};
    use vprouter_core::health::{HealthMessage, Snapshot, boot_seconds};
    // Each peer uses the real length-delimited channel. Wrong preparation
    // receipts must stop BEFORE withdrawal; wrong commits override the sample
    // error because its safe completion has not been acknowledged.
    for fault in 0..=9 {
        let mut engine = engine();
        engine.machine.block(Reason::ProviderFailure);
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        engine.inputs.faults.borrow_mut().guard_seen = Some(seen.clone());
        let now = boot_seconds();
        let snapshot = Snapshot::from_machine(
            operational_receipt(PolicyState::Offline).binding,
            1,
            now,
            &engine.machine,
        )
        .unwrap();
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        let peer = std::thread::spawn(move || {
            for stage in 0..3 {
                let Ok(request): std::result::Result<Request, _> =
                    crate::bootstrap::read_message(&mut server)
                else {
                    return;
                };
                let frame = request.frame().clone();
                let mut policy = operational_receipt(PolicyState::Offline);
                if stage == 0 {
                    match fault {
                        1 => policy.state = PolicyState::Bootstrap,
                        2 => policy.state = PolicyState::Ready,
                        3 => policy.binding.generation += 1,
                        4 => policy.binding.exit_id = "foreign".into(),
                        // Historical health-only ACK cannot prove quarantine.
                        9 => {
                            let reply = serde_json::json!({"disposition":"prepared","frame":frame});
                            crate::bootstrap::write_message(&mut server, &reply).unwrap();
                            return;
                        }
                        _ => (),
                    }
                } else if stage == 2 {
                    match fault {
                        5 => policy.state = PolicyState::Bootstrap,
                        6 => policy.state = PolicyState::Ready,
                        7 => policy.binding.generation += 1,
                        _ => (),
                    }
                }
                let reply = match request {
                    Request::Prepare { .. } if stage == 0 => {
                        seen.store(true, std::sync::atomic::Ordering::SeqCst);
                        Reply::Prepared { frame, policy }
                    }
                    Request::Persist {
                        snapshot_sequence: 1,
                        ..
                    } if stage == 1 => Reply::Persisted { frame },
                    Request::Commit {
                        snapshot_sequence: 1,
                        ..
                    } if stage == 2 => Reply::Enforced {
                        frame,
                        state: if fault == 8 {
                            HealthState::Ready
                        } else {
                            HealthState::Blocked
                        },
                        policy,
                    },
                    _ => panic!("unexpected failure publication phase"),
                };
                crate::bootstrap::write_message(&mut server, &reply).unwrap();
            }
        });
        let channel = Rc::new(tokio::sync::Mutex::new(
            Channel::new(client, "a".repeat(64)).unwrap(),
        ));
        let result = operational_complete(
            &channel,
            HealthMessage {
                version: 1,
                lifecycle: "a".repeat(64),
                sequence: 1,
                sent_at: now,
                snapshot: Some(snapshot),
            },
            &mut engine.inputs,
            Err(Error::ProviderNegative),
        )
        .await;
        assert_eq!(
            result,
            Err(if fault == 0 {
                Error::ProviderNegative
            } else if fault == 9 {
                Error::Malformed
            } else {
                Error::GuardUnavailable
            }),
            "fault {fault}"
        );
        assert_eq!(
            count(&engine, "withdraw"),
            usize::from(!matches!(fault, 1..=4 | 9))
        );
        assert_eq!(count(&engine, "provider"), 0);
        drop(channel);
        peer.join().unwrap();
    }
}

#[test]
fn actual_failure_and_fresh_recovery_snapshots_have_distinct_policy_expectations() {
    use crate::operation::PolicyState;
    use vprouter_core::health::{Snapshot, boot_seconds};
    let binding = operational_receipt(PolicyState::Offline).binding;
    let mut machine = HealthMachine::new(ExitMode::Mullvad, Some("de-fra-wg-404"), "n123").unwrap();
    let now = boot_seconds();
    let policy = |machine: &HealthMachine, sequence, at| {
        PolicyState::publication(
            &Snapshot::from_machine(binding.clone(), sequence, at, machine).unwrap(),
        )
    };
    assert_eq!(policy(&machine, 1, now - 5.), PolicyState::Bootstrap);
    machine.block(Reason::ProviderFailure);
    assert_eq!(policy(&machine, 2, now - 4.), PolicyState::Offline);
    for sample in 1..=4 {
        let at = now - 4. + sample as f64;
        machine
            .observe(
                at,
                Evidence {
                    provider_ok: true,
                    structural_ok: true,
                    provider_at: at,
                    structural_at: at,
                    heartbeat_at: at,
                    handshake_age_seconds: Some(1.),
                    online: true,
                    policy_approved: true,
                    server: Some("de-fra-wg-404".into()),
                    node_id: Some("n123".into()),
                    egress: Some("1.2.3.4".parse().unwrap()),
                    verified_at: Some(at),
                    dns: VerificationResult::NotTested,
                    ipv6: VerificationResult::NotTested,
                },
            )
            .unwrap();
        assert_eq!(
            policy(&machine, sample + 2, at),
            if sample == 4 {
                PolicyState::Ready
            } else {
                PolicyState::Bootstrap
            }
        );
    }
    machine.stop();
    assert_eq!(policy(&machine, 7, now), PolicyState::Offline);
    machine.fail(Reason::StructuralFailure);
    assert_eq!(policy(&machine, 8, now), PolicyState::Offline);
}

struct ChannelInputs {
    script: Script,
    channel: crate::operation::Channel,
}

// Real Channel and Engine; only provider/LocalAPI I/O is scripted. The peer
// withholds its heartbeat ACK until the ordinary failure has been processed.
struct RacingInputs {
    script: Script,
    channel: Rc<tokio::sync::Mutex<crate::operation::Channel>>,
    failure: Option<(bool, tokio::sync::oneshot::Receiver<()>)>,
    cancelled: Option<std::sync::mpsc::Sender<()>>,
}

#[tokio::test(start_paused = true)]
async fn heartbeat_drain_keeps_original_sample_timeout_polled() {
    use crate::operation::{Channel, Reply, Request};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (client, server) = std::os::unix::net::UnixStream::pair().unwrap();
    server.set_nonblocking(true).unwrap();
    let mut server = tokio::net::UnixStream::from_std(server).unwrap();
    let channel = Rc::new(tokio::sync::Mutex::new(
        Channel::new(client, "a".repeat(64)).unwrap(),
    ));
    let mut engine = engine();
    engine.inputs.faults.borrow_mut().delay = Duration::from_secs(60);
    let events = engine.inputs.events.clone();
    let start = Instant::now();
    let mut cadence = time::interval_at(start + Duration::from_secs(33), CADENCE);
    let peer = async move {
        time::advance(Duration::from_secs(33)).await;
        let length = server.read_u32().await.unwrap();
        let mut bytes = vec![0; length as usize];
        server.read_exact(&mut bytes).await.unwrap();
        let Request::Heartbeat { frame } = serde_json::from_slice(&bytes).unwrap() else {
            panic!("expected heartbeat")
        };
        time::advance(Duration::from_secs(1)).await;
        for _ in 0..16 {
            if events.borrow().iter().any(|(event, _)| *event == "cancel") {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            events
                .borrow()
                .contains(&("cancel", Duration::from_secs(34))),
            "heartbeat suspended or reset the original sample timeout: {:?}; elapsed {:?}",
            events.borrow(),
            start.elapsed()
        );
        let reply = serde_json::to_vec(&Reply::Alive { frame }).unwrap();
        server.write_u32(reply.len() as u32).await.unwrap();
        server.write_all(&reply).await.unwrap();
    };
    let run = async {
        tokio::join!(
            operational_sample(&mut engine, &channel, &mut cadence),
            peer
        )
    };
    let (result, ()) = tokio::select! {
        result = run => result,
        _ = async {
            // Disable paused-clock auto-advance while socket readiness is being
            // delivered: only the two explicit advances define this scenario.
            for _ in 0..10_000 { tokio::task::yield_now().await; }
        } => panic!("operational sample did not complete after its original deadline"),
    };
    assert_eq!(result, Err(Error::Deadline));
    assert_eq!(start.elapsed(), Duration::from_secs(34));
    assert_eq!(engine.machine.state(), HealthState::Blocked);
}
impl Inputs for RacingInputs {
    fn now(&self) -> f64 {
        vprouter_core::health::boot_seconds()
    }
    async fn initialize(&mut self) -> Result<()> {
        self.script.initialize().await
    }
    async fn structure(&mut self) -> Result<Structural> {
        let e = self.channel.lock().await.structure().await?;
        Ok(Structural {
            at: e.checked_at,
            handshake_age: e.handshake_age,
        })
    }
    async fn provider(&mut self) -> Result<Confirmation> {
        if self.failure.as_ref().is_some_and(|(local, _)| !local) {
            self.failure.take().unwrap().1.await.unwrap();
            return Err(Error::ProviderNegative);
        }
        self.script.provider().await
    }
    async fn local(&mut self) -> Result<Observation> {
        if let Some((true, gate)) = self.failure.take() {
            gate.await.unwrap();
            return Err(Error::Identity);
        }
        self.script.local().await
    }
    async fn advertise(&mut self) -> Result<()> {
        self.script.advertise().await
    }
    async fn withdraw(&mut self) -> Result<()> {
        self.script.withdraw().await
    }
    fn cancel(&mut self) {
        self.script.cancel();
        if let Some(sender) = self.cancelled.take() {
            sender.send(()).unwrap();
        }
    }
}

#[tokio::test]
async fn ordinary_failure_during_heartbeat_reply_preserves_channel_and_scripted_fresh_samples() {
    use crate::operation::{Channel, Reply, Request, StructuralEvidence};
    use vprouter_core::health::{Binding, HealthMessage, Snapshot, boot_seconds};
    for local_failure in [false, true] {
        let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
        let (fail, failed) = tokio::sync::oneshot::channel();
        let (cancelled, cancellation) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let mut fail = Some(fail);
            let mut sequence = 0;
            let mut published = Vec::new();
            let mut state = HealthState::Starting;
            loop {
                let request: Request = crate::bootstrap::read_message(&mut server).unwrap();
                let frame = request.frame().clone();
                sequence += 1;
                assert_eq!(frame.sequence, sequence);
                assert_eq!(frame.lifecycle, "a".repeat(64));
                let reply = match request {
                    Request::Structure { .. } => Reply::Structure {
                        frame,
                        evidence: StructuralEvidence {
                            checked_at: boot_seconds(),
                            handshake_age: 10.,
                        },
                    },
                    Request::Heartbeat { .. } => {
                        if let Some(fail) = fail.take() {
                            fail.send(()).unwrap();
                            // Engine must keep being polled while the ACK is pending.
                            cancellation.recv_timeout(Duration::from_secs(1)).unwrap();
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Reply::Alive { frame }
                    }
                    Request::Prepare { message, .. } => {
                        state = message.snapshot.unwrap().state;
                        Reply::Prepared {
                            frame,
                            policy: operational_receipt(if state == HealthState::Ready {
                                crate::operation::PolicyState::Bootstrap
                            } else {
                                crate::operation::PolicyState::Offline
                            }),
                        }
                    }
                    Request::Persist { .. } => Reply::Persisted { frame },
                    Request::Commit { .. } => {
                        published.push(state);
                        Reply::Enforced {
                            frame,
                            state,
                            policy: operational_receipt(if state == HealthState::Ready {
                                crate::operation::PolicyState::Ready
                            } else if published.len() == 1 {
                                crate::operation::PolicyState::Offline
                            } else {
                                crate::operation::PolicyState::Bootstrap
                            }),
                        }
                    }
                };
                crate::bootstrap::write_message(&mut server, &reply).unwrap();
                if published.last() == Some(&HealthState::Ready) {
                    return published;
                }
            }
        });
        let channel = Rc::new(tokio::sync::Mutex::new(
            Channel::new(client, "a".repeat(64)).unwrap(),
        ));
        let script = engine().inputs;
        script.faults.borrow_mut().approved = true;
        let inputs = RacingInputs {
            script,
            channel: channel.clone(),
            failure: Some((local_failure, failed)),
            cancelled: Some(cancelled),
        };
        let mut engine = Engine::new(
            inputs,
            ExitMode::Mullvad,
            "de-fra-wg-404",
            "n123",
            Instant::now(),
        )
        .unwrap();
        let binding = Binding {
            deployment_id: "test".into(),
            exit_id: "one".into(),
            mode: ExitMode::Mullvad,
            generation: 1,
            display_name: "test-exit".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "n123".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        };
        let mut cadence = time::interval_at(Instant::now() + Duration::from_millis(10), CADENCE);
        for sequence in 1..=5 {
            let result = operational_sample(&mut engine, &channel, &mut cadence).await;
            assert_eq!(
                result,
                if sequence == 1 {
                    Err(if local_failure {
                        Error::Identity
                    } else {
                        Error::ProviderNegative
                    })
                } else {
                    Ok(())
                }
            );
            let now = boot_seconds();
            let snapshot =
                Snapshot::from_machine(binding.clone(), sequence, now, &engine.machine).unwrap();
            let message = HealthMessage {
                version: 1,
                lifecycle: "a".repeat(64),
                sequence,
                sent_at: now,
                snapshot: Some(snapshot),
            };
            assert_eq!(
                operational_publish(&channel, message, &mut engine.inputs, result.is_err()).await,
                Ok(()),
                "ordinary failure poisoned the shared control channel"
            );
        }
        assert_eq!(
            peer.join().unwrap(),
            vec![
                HealthState::Blocked,
                HealthState::Blocked,
                HealthState::Blocked,
                HealthState::Recovering,
                HealthState::Ready
            ]
        );
        assert_eq!(
            engine
                .inputs
                .script
                .events
                .borrow()
                .iter()
                .filter(|(event, _)| *event == "withdraw")
                .count(),
            1
        );
    }
}
impl Inputs for ChannelInputs {
    fn now(&self) -> f64 {
        vprouter_core::health::boot_seconds()
    }
    async fn initialize(&mut self) -> Result<()> {
        self.script.initialize().await
    }
    async fn structure(&mut self) -> Result<Structural> {
        let evidence = self.channel.structure().await?;
        Ok(Structural {
            at: evidence.checked_at,
            handshake_age: evidence.handshake_age,
        })
    }
    async fn provider(&mut self) -> Result<Confirmation> {
        self.script.provider().await
    }
    async fn local(&mut self) -> Result<Observation> {
        self.script.local().await
    }
    async fn advertise(&mut self) -> Result<()> {
        self.script.advertise().await
    }
    async fn withdraw(&mut self) -> Result<()> {
        self.script.withdraw().await
    }
    fn cancel(&mut self) {
        self.script.cancel();
    }
}
#[tokio::test]
async fn same_engine_recovers_through_actual_framed_guard_structures_without_native_worker_socket()
{
    use crate::operation::{Channel, Reply, Request, StructuralEvidence};
    let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
    let peer = std::thread::spawn(move || {
        let mut checks = Vec::new();
        for sequence in 1..=12 {
            let request: Request = crate::bootstrap::read_message(&mut server).unwrap();
            let Request::Structure { frame } = request else {
                panic!("nonstructure request")
            };
            assert_eq!(frame.sequence, sequence);
            let checked_at = vprouter_core::health::boot_seconds();
            checks.push(checked_at);
            crate::bootstrap::write_message(
                &mut server,
                &Reply::Structure {
                    frame,
                    evidence: StructuralEvidence {
                        checked_at,
                        handshake_age: 10.,
                    },
                },
            )
            .unwrap();
        }
        checks
    });
    let script = engine().inputs;
    script.faults.borrow_mut().approved = true;
    let input = ChannelInputs {
        script,
        channel: Channel::new(client, "a".repeat(64)).unwrap(),
    };
    let mut engine = Engine::new(
        input,
        ExitMode::Mullvad,
        "de-fra-wg-404",
        "n123",
        Instant::now(),
    )
    .unwrap();
    for _ in 0..4 {
        engine.sample().await.unwrap();
    }
    assert_eq!(engine.machine.state(), HealthState::Ready);
    let checks = peer.join().unwrap();
    assert!(checks.windows(2).all(|pair| pair[0] < pair[1]));
    let snapshot = vprouter_core::health::Snapshot::from_machine(
        vprouter_core::health::Binding {
            deployment_id: "test".into(),
            exit_id: "one".into(),
            mode: ExitMode::Mullvad,
            generation: 1,
            display_name: "test-exit".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "n123".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        },
        4,
        vprouter_core::health::boot_seconds(),
        &engine.machine,
    )
    .unwrap();
    assert_eq!(
        snapshot.evidence.unwrap().structural_at,
        *checks.last().unwrap(),
        "original guard time was replaced by worker wrapper time"
    );
}

#[tokio::test]
async fn fresh_commit_frame_cannot_accept_expired_original_host_structure() {
    use crate::operation::{Channel, Reply, Request};
    use vprouter_core::{
        health::{Binding, HealthMessage, Snapshot, boot_seconds},
        state::{Evidence, VerificationResult},
    };
    let mut engine = engine();
    let now = boot_seconds();
    let binding = Binding {
        deployment_id: "test".into(),
        exit_id: "one".into(),
        mode: ExitMode::Mullvad,
        generation: 1,
        display_name: "test-exit".into(),
        expected_server: Some("de-fra-wg-404".into()),
        node_id: "n123".into(),
        config_fingerprint: "a".repeat(64),
        boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
    };
    let snapshot = Snapshot {
        version: 1,
        binding,
        sequence: 1,
        published_at: now,
        state: HealthState::Ready,
        reason: None,
        evidence: Some(Evidence {
            provider_ok: true,
            structural_ok: true,
            provider_at: now,
            structural_at: now - 1.8,
            heartbeat_at: now,
            handshake_age_seconds: Some(1.),
            online: true,
            policy_approved: true,
            server: Some("de-fra-wg-404".into()),
            node_id: Some("n123".into()),
            egress: Some("1.2.3.4".parse().unwrap()),
            verified_at: Some(now),
            dns: VerificationResult::NotTested,
            ipv6: VerificationResult::NotTested,
        }),
    };
    let message = HealthMessage {
        version: 1,
        lifecycle: "a".repeat(64),
        sequence: 1,
        sent_at: now,
        snapshot: Some(snapshot),
    };
    let (client, mut server) = std::os::unix::net::UnixStream::pair().unwrap();
    let peer = std::thread::spawn(move || {
        for stage in 0..3 {
            let request: Request = crate::bootstrap::read_message(&mut server).unwrap();
            let frame = request.frame().clone();
            let reply = match stage {
                0 => Reply::Prepared {
                    frame,
                    policy: operational_receipt(crate::operation::PolicyState::Bootstrap),
                },
                1 => Reply::Persisted { frame },
                _ => {
                    std::thread::sleep(Duration::from_millis(250));
                    Reply::Enforced {
                        frame,
                        state: HealthState::Ready,
                        policy: operational_receipt(crate::operation::PolicyState::Ready),
                    }
                }
            };
            crate::bootstrap::write_message(&mut server, &reply).unwrap();
        }
    });
    let channel = Rc::new(tokio::sync::Mutex::new(
        Channel::new(client, "a".repeat(64)).unwrap(),
    ));
    assert_eq!(
        operational_publish(&channel, message, &mut engine.inputs, false).await,
        Err(Error::GuardUnavailable)
    );
    peer.join().unwrap();
}
