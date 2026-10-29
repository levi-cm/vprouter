use crate::{
    Error, Result, client,
    localapi::{LocalApi, Observation},
    placement::Placed,
    provider::{Confirmation, Provider},
};
use std::{
    path::PathBuf,
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::watch,
    time::{self, Instant, MissedTickBehavior},
};
use vprouter_core::{
    config::ExitMode,
    reason::Reason,
    state::{Evidence, HealthMachine, HealthState, VerificationResult},
};
use vprouter_network::{Audit, NativeNetwork, Plan};
/// 34s outer bound leaves margin for a native5s synchronous dump completing
/// after cancellation becomes ready. Never reaches the45s freshness boundary.
pub(crate) const OPERATION: Duration = Duration::from_secs(34);
const CADENCE: Duration = Duration::from_secs(5);
const CONTROL: Duration = Duration::from_secs(2);
struct Structural {
    at: f64,
    handshake_age: f64,
}
/// Boundary injection is private, not a public trait granting production health.
trait Inputs {
    fn now(&self) -> f64;
    async fn initialize(&mut self) -> Result<()>;
    async fn structure(&mut self) -> Result<Structural>;
    async fn provider(&mut self) -> Result<Confirmation>;
    async fn local(&mut self) -> Result<Observation>;
    async fn advertise(&mut self) -> Result<()>;
    async fn withdraw(&mut self) -> Result<()>;
    fn cancel(&mut self);
}
struct Native {
    placed: Rc<Placed>,
    network: NativeNetwork,
    plan: Plan,
    index: u32,
    local: LocalApi,
    provider: Provider,
    origin: Instant,
}
impl Inputs for Native {
    fn now(&self) -> f64 {
        vprouter_core::health::boot_seconds()
    }
    async fn initialize(&mut self) -> Result<()> {
        self.local.initialize().await
    }
    async fn structure(&mut self) -> Result<Structural> {
        self.placed.check()?;
        let snapshot = self.network.observe().map_err(|_| Error::Structural)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Structural)?
            .as_secs_f64();
        if self.plan.audit(Some(&snapshot), self.index, now) != Audit::StructurallyValid {
            return Err(Error::Structural);
        }
        // Bind TUN address observations to the independently preserved identity;
        // network's generic CGNAT prefix acceptance is not identity authority.
        let ts = snapshot
            .links
            .iter()
            .find(|l| l.name == "tailscale0")
            .ok_or(Error::Structural)?;
        let ips: Vec<_> = snapshot
            .addresses
            .iter()
            .filter(|a| a.index == ts.index)
            .map(|a| a.address)
            .collect();
        let expected = &self.local.identity().ips;
        if ips.len() != expected.len() || !ips.iter().all(|ip| expected.contains(ip)) {
            return Err(Error::Structural);
        }
        let handshake = snapshot
            .wireguard
            .and_then(|w| w.peers.first().and_then(|p| p.handshake_unix))
            .ok_or(Error::Structural)?;
        self.placed.check()?;
        Ok(Structural {
            at: self.now(),
            handshake_age: now - handshake,
        })
    }
    async fn provider(&mut self) -> Result<Confirmation> {
        self.provider.confirm().await
    }
    async fn local(&mut self) -> Result<Observation> {
        self.local.observe().await
    }
    async fn advertise(&mut self) -> Result<()> {
        self.local.advertise().await
    }
    async fn withdraw(&mut self) -> Result<()> {
        self.local.withdraw().await
    }
    fn cancel(&mut self) {
        self.provider.cancel();
        self.local.cancel();
    }
}
struct Engine<I> {
    inputs: I,
    machine: HealthMachine,
    origin: Instant,
    node: String,
    initialized: bool,
}
impl<I: Inputs> Engine<I> {
    fn new(inputs: I, mode: ExitMode, server: &str, node: &str, origin: Instant) -> Result<Self> {
        if mode != ExitMode::Mullvad {
            return Err(Error::DirectUnsupported);
        }
        let machine = HealthMachine::new(mode, Some(server), node)
            .map_err(|_| Error::InvalidConfiguration)?;
        Ok(Self {
            inputs,
            machine,
            origin,
            node: node.into(),
            initialized: false,
        })
    }
    async fn sample(&mut self) -> Result<()> {
        let result = time::timeout(OPERATION, self.sample_inner())
            .await
            .map_err(|_| Error::Deadline)
            .and_then(|r| r);
        if let Err(error) = result {
            self.inputs.cancel();
            self.machine.block(reason(error));
        }
        result
    }
    async fn sample_inner(&mut self) -> Result<()> {
        self.cached_fresh()?;
        if !self.initialized {
            self.inputs.initialize().await?;
            self.initialized = true;
        }
        self.inputs.structure().await?;
        let provider = match self.inputs.provider().await {
            Ok(p) => p,
            Err(e) if eligible(e) => {
                // Recheck once immediately after failure and once AFTER delay;
                // neither a cached handshake nor pre-delay audit authorizes retry.
                self.inputs.structure().await?;
                time::sleep(Duration::from_secs(1)).await;
                self.inputs.structure().await?;
                self.inputs.provider().await?
            }
            Err(e) => return Err(e),
        };
        let provider_at = self.inputs.now();
        let structural = self.inputs.structure().await?;
        let mut local = self.inputs.local().await?;
        self.cached_fresh()?;
        // This private engine has no production constructor. Task8 must bind
        // retained health-only bootstrap enforcement before this recovery write.
        // It is possible only after three independent prior provider+structure samples
        // and a fresh online stable identity observation in THIS sample.
        // ExitNodeOption is offered&&approved: false while withdrawn is normal.
        if self.machine.state() == HealthState::Recovering && !local.advertised {
            self.inputs.advertise().await?;
            local = self.inputs.local().await?;
            if !local.advertised {
                return Err(Error::Preferences);
            }
        }
        // LocalAPI may have changed routes. Audit the ENTIRE structure again.
        let final_structure = self.inputs.structure().await?;
        let now = self.inputs.now();
        if now - structural.at >= 45.0 {
            return Err(Error::Structural);
        }
        self.cached_fresh()?;
        let previous = self.machine.state();
        let state = self
            .machine
            .observe(
                now,
                Evidence {
                    provider_ok: true,
                    structural_ok: true,
                    provider_at,
                    structural_at: final_structure.at,
                    heartbeat_at: now,
                    handshake_age_seconds: Some(final_structure.handshake_age),
                    online: true,
                    policy_approved: local.advertised && local.approved,
                    server: Some(provider.server),
                    node_id: Some(self.node.clone()),
                    egress: Some(provider.ip),
                    verified_at: Some(provider_at),
                    dns: VerificationResult::NotTested,
                    ipv6: VerificationResult::NotTested,
                },
            )
            .map_err(|_| Error::Structural)?;
        if previous == HealthState::Ready && state != HealthState::Ready {
            return Err(Error::Structural);
        }
        Ok(())
    }
    fn cached_fresh(&mut self) -> Result<()> {
        if self.machine.expire(self.inputs.now()) {
            Err(Error::Structural)
        } else {
            Ok(())
        }
    }
}
fn eligible(e: Error) -> bool {
    matches!(e, Error::HttpTransient | Error::Transport | Error::Deadline)
}
/// Draft private task8 wire boundary: explicit ACK, no quarantine removal
/// request exists. ACK means recorded ONLY, never enforcement or quarantine.
// Task8 must bind peer, exit/generation and retained health-only bootstrap
// authority outside this observational notification transport.
struct Control {
    placed: Rc<Placed>,
    guard: PathBuf,
    init: PathBuf,
    sequence: u64,
}
impl Control {
    async fn send(&mut self, path: &str, error: Option<Error>) -> Result<()> {
        self.placed.check()?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::GuardUnavailable)?;
        let body = serde_json::to_vec(
            &serde_json::json!({"version":1,"sequence":self.sequence,"reason":error}),
        )
        .map_err(|_| Error::GuardUnavailable)?;
        let reply = client::unix_request(&self.guard, "POST", path, &body, 256)
            .await
            .map_err(|_| Error::GuardUnavailable)?;
        let ack: serde_json::Value =
            crate::json::decode(&reply.body).map_err(|_| Error::GuardUnavailable)?;
        if ack != serde_json::json!({"version":1,"sequence":self.sequence,"recorded":true}) {
            return Err(Error::GuardUnavailable);
        }
        self.placed.check()?;
        Ok(())
    }
    async fn heartbeat(&mut self) -> Result<()> {
        self.send("/v1/worker/heartbeat", None).await
    }
    async fn block(&mut self, e: Error) -> Result<()> {
        self.send("/v1/worker/block", Some(e)).await
    }
    async fn terminate_daemon(&self) -> Result<()> {
        self.placed.check()?;
        let reply = client::unix_request(
            &self.init,
            "POST",
            "/v1/init/stop-tailscaled",
            br#"{"version":1}"#,
            256,
        )
        .await
        .map_err(|_| Error::InitUnavailable)?;
        if crate::json::decode::<serde_json::Value>(&reply.body)
            .map_err(|_| Error::InitUnavailable)?
            != serde_json::json!({"version":1,"stopped":true})
        {
            return Err(Error::InitUnavailable);
        }
        Ok(())
    }
}
struct Runner<I> {
    engine: Engine<I>,
    control: Control,
    publisher: crate::publish::Publisher,
}
impl<I: Inputs> Runner<I> {
    async fn fail_closed(&mut self, error: Error) -> Result<()> {
        self.engine.inputs.cancel();
        self.engine.machine.block(reason(error));
        // Guard notification first; even if unavailable still attempt withdrawal.
        let guard = time::timeout(CONTROL, self.control.block(error)).await;
        let withdrawal = time::timeout(Duration::from_secs(4), self.engine.inputs.withdraw()).await;
        let termination = if !matches!(withdrawal, Ok(Ok(()))) {
            self.engine.initialized = false;
            self.control.terminate_daemon().await
        } else {
            Ok(())
        };
        // Publish the blocked state even when the external init fails to ACK.
        let publication = self.publish().await;
        termination?;
        publication?;
        if !matches!(guard, Ok(Ok(()))) {
            return Err(Error::GuardUnavailable);
        }
        Ok(())
    }
    async fn publish(&self) -> Result<()> {
        self.publisher
            .write(&self.engine.machine, self.engine.inputs.now())
            .await
    }
    async fn run(
        &mut self,
        mut shutdown: watch::Receiver<bool>,
        deployment: &str,
        exit: &str,
        enabled_exits: usize,
    ) -> Result<()> {
        if enabled_exits == 0 {
            return Err(Error::InvalidConfiguration);
        }
        let offset = Duration::from_millis(vprouter_core::state::provider_offset_ms(
            deployment,
            exit,
            enabled_exits,
        ));
        let mut cadence = time::interval_at(Instant::now() + offset, CADENCE);
        cadence.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _=shutdown.changed()=>{break;}
                _=cadence.tick()=>{}
            }
            // One cadence drives new samples AND heartbeats while a bounded
            // provider operation is outstanding. There are no placeholder exits.
            let result = {
                let future = self.engine.sample();
                tokio::pin!(future);
                loop {
                    tokio::select! {
                        biased;
                        _=shutdown.changed()=>{break Err(Error::Cancelled);}
                        result=&mut future=>{break result;}
                        _=cadence.tick()=>{
                            // Poll HTTP attempt and its12s timer concurrently
                            // with the bounded control request; awaiting control
                            // alone must not suspend the attempt deadline.
                            tokio::select! {
                                biased;
                                _=shutdown.changed()=>{break Err(Error::Cancelled);}
                                result=&mut future=>{break result;}
                                result=self.control.heartbeat()=>{if let Err(e)=result{break Err(e);}}
                            }
                        }
                    }
                }
            };
            if let Err(e) = result {
                if e == Error::Cancelled {
                    break;
                }
                self.fail_closed(e).await?;
            } else {
                if let Err(e) = self.control.heartbeat().await {
                    self.fail_closed(e).await?;
                    return Err(e);
                }
                if let Err(e) = self.publish().await {
                    self.fail_closed(e).await?;
                    return Err(e);
                }
            }
        }
        self.engine.machine.stop();
        self.fail_closed(Error::Cancelled).await?;
        self.publish().await
    }
}
fn reason(e: Error) -> Reason {
    match e {
        Error::ProviderNegative
        | Error::WrongServer
        | Error::HttpPermanent
        | Error::HttpTransient
        | Error::Transport
        | Error::Tls
        | Error::Malformed
        | Error::Oversized => Reason::ProviderFailure,
        Error::Identity | Error::Preferences => Reason::InvalidEvidence,
        Error::Cancelled => Reason::Stopping,
        _ => Reason::StructuralFailure,
    }
}
#[cfg(test)]
mod tests;

/// Production zero-cap inputs: only the authenticated guard can issue native
/// WireGuard evidence. The worker never opens a privileged network socket.
struct Operational {
    placed: Rc<Placed>,
    channel: Rc<tokio::sync::Mutex<crate::operation::Channel>>,
    local: LocalApi,
    provider: Provider,
}
impl Inputs for Operational {
    fn now(&self) -> f64 {
        vprouter_core::health::boot_seconds()
    }
    async fn initialize(&mut self) -> Result<()> {
        self.local.initialize().await
    }
    async fn structure(&mut self) -> Result<Structural> {
        self.placed.check()?;
        let evidence = self.channel.lock().await.structure().await?;
        self.placed.check()?;
        Ok(Structural {
            at: evidence.checked_at,
            handshake_age: evidence.handshake_age,
        })
    }
    async fn provider(&mut self) -> Result<Confirmation> {
        self.provider.confirm().await
    }
    async fn local(&mut self) -> Result<Observation> {
        self.local.observe().await
    }
    async fn advertise(&mut self) -> Result<()> {
        self.local.advertise().await
    }
    async fn withdraw(&mut self) -> Result<()> {
        self.local.withdraw().await
    }
    fn cancel(&mut self) {
        self.provider.cancel();
        self.local.cancel();
    }
}
async fn operational_publish<I: Inputs>(
    channel: &Rc<tokio::sync::Mutex<crate::operation::Channel>>,
    message: vprouter_core::health::HealthMessage,
    inputs: &mut I,
    withdraw: bool,
) -> Result<()> {
    use crate::operation::{Reply, Request};
    let snapshot_sequence = message.snapshot.as_ref().ok_or(Error::Storage)?.sequence;
    let expected_state = message.snapshot.as_ref().ok_or(Error::Storage)?.state;
    // Retain the guard-matched earliest structural anchor BEFORE moving the
    // message. BOOTTIME includes suspend; fresh per-phase frames and Instant
    // budgets cannot rejuvenate this original host evidence.
    let host_at = if expected_state == HealthState::Ready {
        Some(
            message
                .snapshot
                .as_ref()
                .and_then(|s| s.evidence.as_ref())
                .ok_or(Error::GuardUnavailable)?
                .structural_at,
        )
    } else {
        None
    };
    let check_host = || -> Result<()> {
        if let Some(at) = host_at {
            let now = vprouter_core::health::boot_seconds();
            if !at.is_finite() || !now.is_finite() || at < 0. || now < at || now >= at + 2. {
                return Err(Error::GuardUnavailable);
            }
        }
        Ok(())
    };
    check_host()?;
    // Hold one channel transaction across the phases; heartbeat cannot interleave
    // with a prepared publication. Each phase remains independently bounded2s.
    let mut channel = channel.lock().await;
    let budget_end = Instant::now() + Duration::from_secs(6);
    check_host()?;
    match channel
        .exchange(|frame| Request::Prepare {
            frame,
            message: Box::new(message),
        })
        .await?
    {
        Reply::Prepared { .. } => (),
        _ => return Err(Error::GuardUnavailable),
    }
    check_host()?;
    if withdraw {
        // ACK proves exact Offline was read back BEFORE any withdrawal.
        // Failure exits this channel; guard/independent executors remain offline.
        inputs.withdraw().await?;
    }
    check_host()?;
    match channel
        .exchange(|frame| Request::Persist {
            frame,
            snapshot_sequence,
        })
        .await?
    {
        Reply::Persisted { .. } => (),
        _ => return Err(Error::GuardUnavailable),
    }
    check_host()?;
    match channel
        .exchange(|frame| Request::Commit {
            frame,
            snapshot_sequence,
        })
        .await?
    {
        Reply::Enforced { state, .. } if state == expected_state => (),
        _ => return Err(Error::GuardUnavailable),
    }
    check_host()?;
    if Instant::now() >= budget_end {
        return Err(Error::GuardUnavailable);
    }
    Ok(())
}
// Shared by the operational entrypoint and its real-channel regression tests.
async fn operational_sample<I: Inputs>(
    engine: &mut Engine<I>,
    channel: &Rc<tokio::sync::Mutex<crate::operation::Channel>>,
    cadence: &mut time::Interval,
) -> Result<()> {
    let sample = engine.sample();
    tokio::pin!(sample);
    loop {
        tokio::select! {
            biased;
            result = &mut sample => break result,
            _ = cadence.tick() => {
                // Provider timers remain polled during control IO.
                let heartbeat = async { channel.lock().await.heartbeat().await };
                tokio::pin!(heartbeat);
                tokio::select! {
                    biased;
                    result = &mut sample => {
                        // This stream is shared with Structure/publication. A
                        // cancelled in-flight exchange poisons it permanently.
                        // Retain the SAME bounded heartbeat future until its
                        // reply or original timeout; sample/provider deadlines
                        // were polled concurrently and are never restarted.
                        heartbeat.await?;
                        break result;
                    }
                    result = &mut heartbeat => { result?; }
                }
            }
        }
    }
}
pub(crate) fn run_operational(
    admission: crate::bootstrap::MonitorAdmission,
    placed: Rc<Placed>,
) -> Result<()> {
    use vprouter_core::health::{HealthMessage, Snapshot, boot_seconds};
    admission.check()?;
    let binding = admission
        .config()
        .health_binding
        .clone()
        .ok_or(Error::Bootstrap)?;
    let enrollment = admission
        .config()
        .enrollment
        .clone()
        .ok_or(Error::Bootstrap)?;
    enrollment.validate(&binding)?;
    let lifecycle = admission.config().nonce.clone();
    let resolver = admission.config().resolver;
    let enabled_exits = admission.config().allocation.exits.len();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| Error::Bootstrap)?;
    runtime.block_on(async move {
        let channel = Rc::new(tokio::sync::Mutex::new(crate::operation::Channel::new(
            admission.stream,
            lifecycle.clone(),
        )?));
        let local = LocalApi::new_enrolled(placed.clone(), &enrollment)?;
        let provider = Provider::new(
            placed.clone(),
            resolver,
            binding
                .expected_server
                .as_deref()
                .ok_or(Error::InvalidConfiguration)?,
        )?;
        let mut engine = Engine::new(
            Operational {
                placed,
                channel: channel.clone(),
                local,
                provider,
            },
            binding.mode,
            binding
                .expected_server
                .as_deref()
                .ok_or(Error::InvalidConfiguration)?,
            &binding.node_id,
            Instant::now(),
        )?;
        let offset = Duration::from_millis(vprouter_core::state::provider_offset_ms(
            &binding.deployment_id,
            &binding.exit_id,
            enabled_exits,
        ));
        let mut cadence = time::interval_at(Instant::now() + offset, CADENCE);
        cadence.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut sequence = 0u64;
        loop {
            cadence.tick().await;
            channel.lock().await.heartbeat().await?;
            let result = operational_sample(&mut engine, &channel, &mut cadence).await;
            sequence = sequence.checked_add(1).ok_or(Error::Storage)?;
            let now = boot_seconds();
            let snapshot = Snapshot::from_machine(binding.clone(), sequence, now, &engine.machine)
                .map_err(|_| Error::Storage)?;
            operational_publish(
                &channel,
                HealthMessage {
                    version: 1,
                    lifecycle: lifecycle.clone(),
                    sequence,
                    sent_at: now,
                    snapshot: Some(snapshot),
                },
                &mut engine.inputs,
                result.is_err(),
            )
            .await?;
        }
    })
}
