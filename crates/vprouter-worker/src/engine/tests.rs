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
