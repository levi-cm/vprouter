//! Bounded offline multi-exit lifecycle and deadline policy. All outputs are
//! instructions for a future admitted enforcer, never enforcement capabilities.
//! No namespace descriptors, sockets, threads, timers, or native mutations here.
use crate::{
    allocation::{AllocationRecord, ResourceClaim},
    config::{ExitMode, Mode, ValidatedConfiguration},
    health::{Binding, HealthMessage, Session},
    reason::{Reason, Result, err},
    state::{HealthMachine, HealthState, Status, WATCHDOG_SECONDS, provider_offset_ms},
};
use std::{collections::HashSet, sync::Arc};

/// Bounds active policy slots; disabled reservations use the existing schema cap.
pub const MAX_ACTIVE_EXITS: usize = 6;
pub const MAX_MULLVAD_EXITS: usize = 5;
const MAX_LIFECYCLES: usize = 1024;
/// Existing worker operation budget. Native synchronous cancellation may take
/// another 5s; policy expires independently of worker completion.
pub const SAMPLE_SECONDS: f64 = 34.;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    Quarantine,
    QuarantineAndStop,
    EmergencyQuarantineAndStop,
    Sample,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Action {
    pub exit_id: String,
    pub kind: ActionKind,
}
/// Correlation only, bound to this policy instance and exact process epoch.
/// Cannot be used with native launch/netfilter/worker placement APIs.
pub struct ExitToken {
    instance: Arc<()>,
    index: usize,
    epoch: u64,
}
struct ActiveExit {
    binding: Binding,
    lifecycle: String,
    epoch: u64,
    session: Session,
    machine: HealthMachine,
    next_sample: f64,
    in_flight: Option<f64>,
    pending: Option<ActionKind>,
}
/// Proposed selection only, explicitly separate from observed/runtime status.
#[derive(serde::Serialize)]
pub struct ClientPlan {
    pub exit_id: String,
    pub node_id: String,
    pub mode: ExitMode,
    pub generation: u64,
    pub exposure: &'static str,
    pub observed_egress: &'static str,
    pub dns: &'static str,
    pub ipv6: &'static str,
}
pub struct FleetPolicy {
    instance: Arc<()>,
    // Only enabled exits have state machines, sessions, or deadlines.
    active: Vec<ActiveExit>,
    // Disabled identities remain reserved without runtime placeholders.
    reserved_nodes: HashSet<String>,
    used_lifecycles: HashSet<String>,
    // Every operational callback shares the host clock, independently of the
    // enforcement-poll watchdog. Worker evidence timestamps do not update it.
    last_now: f64,
    last_poll: f64,
    stopped: bool,
}
fn time_valid(now: f64) -> bool {
    // Keep f64 precision finer than the millisecond staggering domain.
    now.is_finite() && (0. ..=1e12).contains(&now)
}
impl FleetPolicy {
    /// `bindings` are public expected data, not authenticated process witnesses.
    /// Native integration must retain the reviewed launch/guard authority.
    pub fn new(
        cfg: &ValidatedConfiguration,
        allocations: &AllocationRecord,
        bindings: Vec<(Binding, String)>,
        foreign: &[ResourceClaim],
        now: f64,
    ) -> Result<Self> {
        if !time_valid(now) || bindings.len() != cfg.exits().len() {
            return Err(err(Reason::InvalidEvidence));
        }
        allocations.validate(&cfg.configuration().deployment_id, foreign)?;
        allocations.matches_configuration(cfg)?;
        let fingerprint: String = cfg
            .configuration()
            .clone()
            .validate_structure()?
            .digest()?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let enabled = cfg.exits().iter().filter(|e| e.exit().enabled).count();
        if enabled > MAX_ACTIVE_EXITS
            || cfg
                .exits()
                .iter()
                .filter(|e| e.exit().enabled && e.exit().mode.kind() == ExitMode::Mullvad)
                .count()
                > MAX_MULLVAD_EXITS
        {
            return Err(err(Reason::InvalidSchema));
        }
        let mut nodes = HashSet::new();
        let mut lifecycles = HashSet::new();
        let mut ids = HashSet::new();
        let mut active = Vec::with_capacity(enabled);
        let mut boot = None;
        for (binding, lifecycle) in bindings {
            binding.validate()?;
            let e = cfg
                .exits()
                .iter()
                .find(|e| e.exit().id == binding.exit_id)
                .ok_or_else(|| err(Reason::InvalidReference))?;
            let expected_server = match &e.exit().mode {
                Mode::Mullvad {
                    expected_server, ..
                } => Some(expected_server.as_str()),
                Mode::Direct {} => None,
            };
            if binding.deployment_id != cfg.configuration().deployment_id
                || binding.generation != allocations.generation
                || binding.mode != e.exit().mode.kind()
                || binding.display_name != e.hostname()
                || binding.expected_server.as_deref() != expected_server
                || binding.config_fingerprint != fingerprint
                || boot.as_ref().is_some_and(|b| b != &binding.boot_id)
                || !ids.insert(binding.exit_id.clone())
                || !nodes.insert(binding.node_id.clone())
                || !lifecycles.insert(lifecycle.clone())
                || cfg
                    .configuration()
                    .client_policies
                    .iter()
                    .any(|p| p.exit_id == binding.exit_id && p.selected_node_id != binding.node_id)
            {
                return Err(err(Reason::InvalidEvidence));
            }
            boot = Some(binding.boot_id.clone());
            // Validate disabled lifecycle syntax too, but allocate no session.
            if lifecycle.len() != 64
                || !lifecycle
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(err(Reason::InvalidEvidence));
            }
            if e.exit().enabled {
                let offset = provider_offset_ms(&binding.deployment_id, &binding.exit_id, enabled)
                    as f64
                    / 1000.;
                let machine = HealthMachine::new(binding.mode, expected_server, &binding.node_id)?;
                let session = Session::new(binding.clone(), lifecycle.clone(), now)?;
                active.push(ActiveExit {
                    binding,
                    lifecycle,
                    epoch: 0,
                    session,
                    machine,
                    next_sample: now + offset,
                    in_flight: None,
                    pending: Some(ActionKind::Quarantine),
                });
            }
        }
        // Deterministic dispatch regardless of configuration/binding array order.
        active.sort_by(|a, b| a.binding.exit_id.cmp(&b.binding.exit_id));
        Ok(Self {
            instance: Arc::new(()),
            active,
            reserved_nodes: nodes,
            used_lifecycles: lifecycles,
            last_now: now,
            last_poll: now,
            stopped: false,
        })
    }
    pub fn enabled_count(&self) -> usize {
        self.active.len()
    }
    pub fn binding(&self, id: &str) -> Result<(&Binding, &str)> {
        let exit = self
            .active
            .iter()
            .find(|e| e.binding.exit_id == id)
            .ok_or_else(|| err(Reason::InvalidReference))?;
        Ok((&exit.binding, &exit.lifecycle))
    }
    pub fn select(&self, id: &str) -> Result<ExitToken> {
        let index = self
            .active
            .iter()
            .position(|e| e.binding.exit_id == id)
            .ok_or_else(|| err(Reason::InvalidReference))?;
        Ok(ExitToken {
            instance: self.instance.clone(),
            index,
            epoch: self.active[index].epoch,
        })
    }
    /// Offline client intent only; never native selection/activation authority.
    pub fn select_client(
        &self,
        id: &str,
        node_id: &str,
        mode: crate::config::ClientMode,
    ) -> Result<ExitToken> {
        let token = self.select(id)?;
        let binding = &self.active[token.index].binding;
        if binding.node_id != node_id
            || !matches!(
                (mode, binding.mode),
                (crate::config::ClientMode::Protected, ExitMode::Mullvad)
                    | (crate::config::ClientMode::Direct, ExitMode::Direct)
            )
        {
            return Err(err(Reason::InvalidReference));
        }
        Ok(token)
    }
    pub fn client_plan(
        &self,
        id: &str,
        node_id: &str,
        mode: crate::config::ClientMode,
    ) -> Result<ClientPlan> {
        let token = self.select_client(id, node_id, mode)?;
        let binding = &self.active[token.index].binding;
        Ok(ClientPlan {
            exit_id: binding.exit_id.clone(),
            node_id: binding.node_id.clone(),
            mode: binding.mode,
            generation: binding.generation,
            exposure: if binding.mode == ExitMode::Direct {
                "direct-exposed"
            } else {
                "unverified"
            },
            observed_egress: "not_tested",
            dns: "not_tested",
            ipv6: "not_tested",
        })
    }
    /// Validate current host-address evidence; this never authorizes release or
    /// renews a worker witness. Any missing/drifted evidence requests quarantine.
    pub fn reconcile_direct_host(
        &mut self,
        token: &ExitToken,
        plan: &crate::direct::DirectPlan,
        observed: Option<&crate::direct::HostSnapshot>,
        now: f64,
    ) -> Result<()> {
        self.accept_host_time(now)?;
        let exit = self.selected(token)?;
        if matches!(
            exit.machine.state(),
            HealthState::Stopping | HealthState::Failed
        ) {
            return Err(err(Reason::InvalidTransition));
        }
        if !plan.matches_binding(&exit.binding) || !plan.matches_host(observed) {
            exit.block();
            return Err(err(Reason::InvalidEvidence));
        }
        Ok(())
    }
    fn selected(&mut self, token: &ExitToken) -> Result<&mut ActiveExit> {
        if !Arc::ptr_eq(&self.instance, &token.instance) {
            return Err(err(Reason::InvalidReference));
        }
        let exit = self
            .active
            .get_mut(token.index)
            .ok_or_else(|| err(Reason::InvalidReference))?;
        if exit.epoch != token.epoch {
            return Err(err(Reason::InvalidReference));
        }
        Ok(exit)
    }
    fn accept_host_time(&mut self, now: f64) -> Result<()> {
        if self.stopped {
            return Err(err(Reason::InvalidTransition));
        }
        if !time_valid(now) || now < self.last_now {
            self.container_failed();
            return Err(err(Reason::StaleEvidence));
        }
        self.last_now = now;
        Ok(())
    }
    pub fn status(&self, id: &str, now: f64) -> Result<Status> {
        // Observational: never advances the high-water mark, renews a watchdog or
        // quarantines; it only refuses a host time the fleet has already passed.
        if !time_valid(now) || now < self.last_now {
            return Err(err(Reason::StaleEvidence));
        }
        self.active
            .iter()
            .find(|e| e.binding.exit_id == id)
            .ok_or_else(|| err(Reason::InvalidReference))?
            .machine
            .status(now)
    }
    pub fn observe_bytes(
        &mut self,
        token: &ExitToken,
        bytes: &[u8],
        now: f64,
    ) -> Result<HealthState> {
        self.accept_host_time(now)?;
        match HealthMessage::decode(bytes) {
            Ok(message) => self.observe(token, &message, now),
            Err(error) => {
                self.selected(token)?.block();
                Err(error)
            }
        }
    }
    pub fn observe(
        &mut self,
        token: &ExitToken,
        message: &HealthMessage,
        now: f64,
    ) -> Result<HealthState> {
        self.accept_host_time(now)?;
        let exit = self.selected(token)?;
        if matches!(
            exit.machine.state(),
            HealthState::Stopping | HealthState::Failed
        ) {
            return Err(err(Reason::InvalidTransition));
        }
        let result = (|| {
            if exit.machine.expire(now) {
                return Err(err(Reason::StaleEvidence));
            }
            exit.session.accept(message, now)?;
            if let Some(snapshot) = &message.snapshot {
                if let Some(evidence) = &snapshot.evidence {
                    let derived = exit.machine.observe(now, evidence.clone())?;
                    if derived != snapshot.state {
                        return Err(err(Reason::InvalidEvidence));
                    }
                } else {
                    match snapshot.state {
                        HealthState::Blocked => exit
                            .machine
                            .block(snapshot.reason.unwrap_or(Reason::InvalidEvidence)),
                        HealthState::Failed => {
                            exit.machine
                                .fail(snapshot.reason.unwrap_or(Reason::InvalidEvidence));
                            exit.pending = Some(ActionKind::QuarantineAndStop);
                        }
                        HealthState::Stopping => {
                            exit.machine.stop();
                            exit.pending = Some(ActionKind::QuarantineAndStop);
                        }
                        HealthState::Starting if exit.machine.state() == HealthState::Starting => {}
                        _ => return Err(err(Reason::InvalidEvidence)),
                    }
                    if snapshot.state == HealthState::Blocked {
                        exit.block();
                    }
                }
            }
            Ok(exit.machine.state())
        })();
        if result.is_err() {
            exit.block();
        }
        result
    }
    pub fn worker_failed(&mut self, token: &ExitToken) -> Result<()> {
        self.selected(token)?.block();
        Ok(())
    }
    pub fn cleanup_failed(&mut self, token: &ExitToken) -> Result<()> {
        if self.stopped {
            return Err(err(Reason::InvalidTransition));
        }
        let exit = self.selected(token)?;
        exit.session.revoke();
        exit.machine.fail(Reason::AllocationConflict);
        exit.in_flight = None;
        exit.pending = Some(ActionKind::QuarantineAndStop);
        Ok(())
    }
    pub fn cancel(&mut self, token: &ExitToken) -> Result<()> {
        if self.stopped {
            return Err(err(Reason::InvalidTransition));
        }
        let exit = self.selected(token)?;
        exit.session.revoke();
        // A scoped FAILED exit keeps its terminal state and failure reason; a late
        // cancel only (re)requests the same quarantine-and-stop.
        if exit.machine.state() != HealthState::Failed {
            exit.machine.stop();
        }
        exit.in_flight = None;
        exit.pending = Some(ActionKind::QuarantineAndStop);
        Ok(())
    }
    pub fn container_failed(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        for exit in &mut self.active {
            exit.session.revoke();
            exit.machine.fail(Reason::StructuralFailure);
            exit.in_flight = None;
            exit.pending = Some(ActionKind::EmergencyQuarantineAndStop);
        }
    }
    /// Explicit new process lifetime only. No fallback, name/server/identity
    /// replacement or native launch occurs. Old correlation tokens stay invalid.
    pub fn restart(&mut self, token: &ExitToken, lifecycle: String, now: f64) -> Result<()> {
        self.accept_host_time(now)?;
        if self.used_lifecycles.len() >= MAX_LIFECYCLES || self.used_lifecycles.contains(&lifecycle)
        {
            return Err(err(Reason::InvalidTransition));
        }
        let exit = self.selected(token)?;
        if exit.machine.state() != HealthState::Blocked {
            return Err(err(Reason::InvalidTransition));
        }
        let session = Session::new(exit.binding.clone(), lifecycle.clone(), now)?;
        let epoch = exit
            .epoch
            .checked_add(1)
            .ok_or_else(|| err(Reason::InvalidTransition))?;
        exit.machine.stop();
        exit.machine.reconfigure(
            exit.binding.mode,
            exit.binding.expected_server.as_deref(),
            &exit.binding.node_id,
        )?;
        exit.epoch = epoch;
        exit.session = session;
        exit.lifecycle = lifecycle.clone();
        exit.in_flight = None;
        exit.next_sample = now;
        exit.pending = Some(ActionKind::Quarantine);
        self.used_lifecycles.insert(lifecycle);
        Ok(())
    }
    /// Whole-sample completion. Retry eligibility/delay/fresh checks remain in
    /// the reviewed worker engine; this layer never retries a failed sample.
    pub fn sample_finished(&mut self, token: &ExitToken, now: f64) -> Result<()> {
        self.accept_host_time(now)?;
        let exit = self.selected(token)?;
        let start = exit
            .in_flight
            .ok_or_else(|| err(Reason::InvalidTransition))?;
        if now >= start + SAMPLE_SECONDS {
            exit.block();
            return Err(err(Reason::StaleEvidence));
        }
        // Discard cadence slots missed during this sample, retaining its phase.
        // A slot exactly at completion is still eligible for dispatch by poll.
        if now > exit.next_sample {
            let periods = ((now - exit.next_sample) / 5.).ceil();
            exit.next_sample += periods * 5.;
        }
        exit.in_flight = None;
        Ok(())
    }
    /// No I/O or awaiting an exit here: all enforcement expiries are inspected
    /// before returning any sample work. Missed cadence starts are skipped.
    pub fn poll(&mut self, now: f64) -> Result<Vec<Action>> {
        if self.accept_host_time(now).is_ok() {
            if !self.active.is_empty() && now - self.last_poll >= WATCHDOG_SECONDS as f64 {
                self.container_failed();
            } else {
                self.last_poll = now;
            }
        }
        let mut actions = Vec::with_capacity(self.active.len() * 2);
        for exit in &mut self.active {
            if !matches!(
                exit.machine.state(),
                HealthState::Stopping | HealthState::Failed | HealthState::Blocked
            ) && (exit.session.check(now).is_err()
                || exit.machine.expire(now)
                || exit
                    .in_flight
                    .is_some_and(|start| now >= start + SAMPLE_SECONDS))
            {
                exit.block();
            }
            if let Some(kind) = exit.pending.take() {
                actions.push(Action {
                    exit_id: exit.binding.exit_id.clone(),
                    kind,
                });
            }
        }
        if !self.stopped {
            for exit in &mut self.active {
                if !matches!(
                    exit.machine.state(),
                    HealthState::Stopping | HealthState::Failed | HealthState::Blocked
                ) && exit.in_flight.is_none()
                    && now >= exit.next_sample
                {
                    let periods = ((now - exit.next_sample) / 5.).floor() + 1.;
                    exit.next_sample += periods * 5.;
                    exit.in_flight = Some(now);
                    actions.push(Action {
                        exit_id: exit.binding.exit_id.clone(),
                        kind: ActionKind::Sample,
                    });
                }
            }
        }
        Ok(actions)
    }
    pub fn next_deadline(&self) -> Option<f64> {
        if self.stopped || self.active.is_empty() {
            return None;
        }
        let mut next = self.last_poll + WATCHDOG_SECONDS as f64;
        for exit in &self.active {
            if exit.pending.is_some() {
                return Some(self.last_poll);
            }
            if matches!(
                exit.machine.state(),
                HealthState::Blocked | HealthState::Stopping | HealthState::Failed
            ) {
                continue;
            }
            next = next.min(exit.session.expires_at().unwrap_or(self.last_poll));
            next = next.min(
                exit.in_flight
                    .map_or(exit.next_sample, |start| start + SAMPLE_SECONDS),
            );
        }
        Some(next)
    }
    pub fn reserved_identity_count(&self) -> usize {
        self.reserved_nodes.len()
    }
}
impl ActiveExit {
    fn block(&mut self) {
        if matches!(
            self.machine.state(),
            HealthState::Stopping | HealthState::Failed
        ) {
            return;
        }
        self.session.revoke();
        self.machine.block(Reason::StructuralFailure);
        self.in_flight = None;
        self.pending = Some(ActionKind::Quarantine);
    }
}
