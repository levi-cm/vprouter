use crate::{
    config::{ExitMode, server_name},
    profile::public_ipv4,
    reason::{Reason, Result, err},
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub const HANDSHAKE_MAX_SECONDS: f64 = 180.0;
pub const STALENESS_SECONDS: f64 = 45.0;
pub const WATCHDOG_SECONDS: u64 = 90;
pub const PROVIDER_CADENCE_SECONDS: u64 = 5;
pub const RETRY_SECONDS: u64 = 1;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthState {
    Starting,
    Blocked,
    Recovering,
    Ready,
    Stopping,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    Verified,
    Failed,
    NotTested,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub provider_ok: bool,
    pub structural_ok: bool,
    pub provider_at: f64,
    pub structural_at: f64,
    pub heartbeat_at: f64,
    pub handshake_age_seconds: Option<f64>,
    pub online: bool,
    pub policy_approved: bool,
    pub server: Option<String>,
    pub node_id: Option<String>,
    pub egress: Option<Ipv4Addr>,
    pub verified_at: Option<f64>,
    pub dns: VerificationResult,
    pub ipv6: VerificationResult,
}
#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub state: HealthState,
    pub mode: ExitMode,
    pub reason: Option<Reason>,
    pub exposure: &'static str,
    pub server: Option<String>,
    pub node_id: Option<String>,
    pub egress: Option<Ipv4Addr>,
    pub verified_at: Option<f64>,
    pub dns: VerificationResult,
    pub ipv6: VerificationResult,
}
pub struct HealthMachine {
    mode: ExitMode,
    expected_server: Option<String>,
    expected_node_id: String,
    state: HealthState,
    successes: u8,
    last_now: Option<f64>,
    last_provider_at: Option<f64>,
    last_structural_at: Option<f64>,
    evidence: Option<Evidence>,
    reason: Option<Reason>,
}
impl HealthMachine {
    pub fn new(mode: ExitMode, expected_server: Option<&str>, node_id: &str) -> Result<Self> {
        match (mode, expected_server) {
            (ExitMode::Mullvad, Some(s)) => server_name(s)?,
            (ExitMode::Direct, None) => {}
            _ => return Err(err(Reason::InvalidEvidence)),
        }
        if node_id.is_empty()
            || node_id.len() > 128
            || !node_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(err(Reason::InvalidEvidence));
        }
        Ok(Self {
            mode,
            expected_server: expected_server.map(str::to_owned),
            expected_node_id: node_id.to_owned(),
            state: HealthState::Starting,
            successes: 0,
            last_now: None,
            last_provider_at: None,
            last_structural_at: None,
            evidence: None,
            reason: None,
        })
    }
    pub fn state(&self) -> HealthState {
        self.state
    }
    pub fn observe(&mut self, now: f64, evidence: Evidence) -> Result<HealthState> {
        if matches!(self.state, HealthState::Stopping | HealthState::Failed) {
            return Err(err(Reason::InvalidTransition));
        }
        // Status is observational. Revoke expired cached success here before a
        // new healthy sample can extend an old streak or preserve READY.
        self.expire(now);
        if let Err(error) = self.check(now, &evidence, true) {
            self.block(error.reason());
            return Err(error);
        }
        self.last_now = Some(now);
        self.last_provider_at = Some(evidence.provider_at);
        self.last_structural_at = Some(evidence.structural_at);
        self.successes = self.successes.saturating_add(1).min(3);
        let ready_evidence = self.ready_evidence(now, &evidence);
        if self.state == HealthState::Ready && !ready_evidence {
            self.block(Reason::InvalidEvidence);
            return Err(err(Reason::InvalidEvidence));
        }
        if self.successes == 3 && matches!(self.state, HealthState::Starting | HealthState::Blocked)
        {
            self.state = HealthState::Recovering;
        } else if self.state == HealthState::Recovering && ready_evidence {
            self.state = HealthState::Ready;
        }
        self.reason = if self.state == HealthState::Recovering && !evidence.policy_approved {
            Some(Reason::PolicyUnapproved)
        } else {
            None
        };
        self.evidence = Some(evidence);
        Ok(self.state)
    }
    /// Revoke expired cached evidence before external lifecycle decisions.
    /// Returns true only when evidence was present and has just been revoked;
    /// callers must enforce withdrawal even if a new sample could be healthy.
    pub fn expire(&mut self, now: f64) -> bool {
        let expired = self
            .evidence
            .as_ref()
            .and_then(|previous| self.check(now, previous, false).err());
        if let Some(error) = expired {
            self.block(error.reason());
            return true;
        }
        false
    }
    fn check(&self, now: f64, e: &Evidence, fresh_sample: bool) -> Result<()> {
        if !valid_time(now)
            || self.last_now.is_some_and(|last| now < last)
            || !fresh(now, e.provider_at)
            || !fresh(now, e.structural_at)
            || !fresh(now, e.heartbeat_at)
            || e.verified_at.is_some_and(|t| !fresh(now, t))
            || e.handshake_age_seconds.is_some_and(|age| !valid_time(age))
        {
            return Err(err(Reason::StaleEvidence));
        }
        if fresh_sample
            && (self.last_provider_at.is_some_and(|t| e.provider_at <= t)
                || self
                    .last_structural_at
                    .is_some_and(|t| e.structural_at <= t))
        {
            return Err(err(Reason::StaleEvidence));
        }
        if !e.provider_ok {
            return Err(err(Reason::ProviderFailure));
        }
        if !e.structural_ok
            || self.mode == ExitMode::Mullvad
                && !e
                    .handshake_age_seconds
                    .is_some_and(|age| age + (now - e.structural_at) < HANDSHAKE_MAX_SECONDS)
        {
            return Err(err(Reason::StructuralFailure));
        }
        if self.mode == ExitMode::Mullvad
            && e.server
                .as_deref()
                .is_some_and(|s| Some(s) != self.expected_server.as_deref())
            || self.mode == ExitMode::Direct
                && (e.server.is_some() || e.handshake_age_seconds.is_some())
            || e.node_id
                .as_deref()
                .is_some_and(|s| s != self.expected_node_id)
            || e.egress.is_some_and(|ip| !public_ipv4(ip))
            || e.dns == VerificationResult::Failed
            || e.ipv6 == VerificationResult::Failed
        {
            return Err(err(Reason::InvalidEvidence));
        }
        Ok(())
    }
    fn ready_evidence(&self, now: f64, e: &Evidence) -> bool {
        e.online
            && e.policy_approved
            && e.node_id.as_deref() == Some(&self.expected_node_id)
            && e.server.as_deref() == self.expected_server.as_deref()
            && e.egress.is_some_and(public_ipv4)
            && e.verified_at.is_some_and(|t| fresh(now, t))
    }
    pub fn block(&mut self, reason: Reason) {
        if matches!(self.state, HealthState::Stopping | HealthState::Failed) {
            return;
        }
        self.state = HealthState::Blocked;
        self.successes = 0;
        self.evidence = None;
        self.reason = Some(reason);
    }
    pub fn fail(&mut self, reason: Reason) {
        self.state = HealthState::Failed;
        self.successes = 0;
        self.evidence = None;
        self.reason = Some(reason);
    }
    pub fn stop(&mut self) {
        self.state = HealthState::Stopping;
        self.successes = 0;
        self.evidence = None;
        self.reason = Some(Reason::Stopping);
    }
    pub fn reconfigure(
        &mut self,
        mode: ExitMode,
        expected_server: Option<&str>,
        node_id: &str,
    ) -> Result<()> {
        if self.state != HealthState::Stopping {
            return Err(err(Reason::InvalidTransition));
        }
        *self = Self::new(mode, expected_server, node_id)?;
        Ok(())
    }
    /// Readiness is checked again at observation time; stale cached success is never emitted.
    pub fn status(&self, now: f64) -> Result<Status> {
        if !valid_time(now) || self.last_now.is_some_and(|t| now < t) {
            return Err(err(Reason::StaleEvidence));
        }
        if self.state == HealthState::Ready {
            let e = self
                .evidence
                .as_ref()
                .ok_or_else(|| err(Reason::InvalidEvidence))?;
            self.check(now, e, false)?;
            if !self.ready_evidence(now, e) {
                return Err(err(Reason::InvalidEvidence));
            }
        }
        let e = self
            .evidence
            .as_ref()
            .filter(|e| self.check(now, e, false).is_ok());
        Ok(Status {
            state: self.state,
            mode: self.mode,
            reason: self.reason,
            exposure: match self.mode {
                ExitMode::Direct => "direct-exposed",
                ExitMode::Mullvad if self.state == HealthState::Ready => "protected",
                _ => "unverified",
            },
            server: e.and_then(|e| e.server.clone()),
            node_id: e.and_then(|e| e.node_id.clone()),
            egress: e.and_then(|e| e.egress),
            verified_at: e.and_then(|e| e.verified_at),
            dns: e.map_or(VerificationResult::NotTested, |e| e.dns),
            ipv6: e.map_or(VerificationResult::NotTested, |e| e.ipv6),
        })
    }
}
fn valid_time(t: f64) -> bool {
    t.is_finite() && t >= 0.0
}
fn fresh(now: f64, at: f64) -> bool {
    valid_time(at) && at <= now && now - at < STALENESS_SECONDS
}
/// Offset within the existing provider cadence; no additional timer for one exit.
pub fn provider_offset_ms(deployment_id: &str, exit_id: &str, exit_count: usize) -> u64 {
    if exit_count <= 1 {
        return 0;
    }
    crate::allocation::stable_hash(deployment_id, exit_id) % (PROVIDER_CADENCE_SECONDS * 1000)
}
