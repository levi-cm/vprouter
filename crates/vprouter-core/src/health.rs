//! Shared observational wire contract. A decoded snapshot is never enforcement
//! authority. All timestamps are seconds in the host CLOCK_BOOTTIME domain.
use crate::{
    config::{ExitMode, label},
    reason::{Reason, Result, err},
    state::{Evidence, HealthMachine, HealthState, STALENESS_SECONDS},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
pub const VERSION: u32 = 2;
pub const MAX_BYTES: usize = 16384;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub deployment_id: String,
    pub exit_id: String,
    pub mode: ExitMode,
    pub generation: u64,
    pub display_name: String,
    pub expected_server: Option<String>,
    pub node_id: String,
    pub config_fingerprint: String,
    pub boot_id: String,
}
impl Binding {
    pub fn validate(&self) -> Result<()> {
        label(&self.deployment_id, 32)?;
        label(&self.exit_id, 32)?;
        label(&self.display_name, 63)?;
        if self.generation == 0
            || self.config_fingerprint.len() != 64
            || !self
                .config_fingerprint
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || self.boot_id.len() != 36
            || !self.boot_id.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
                }
            })
        {
            return Err(err(Reason::InvalidEvidence));
        }
        HealthMachine::new(self.mode, self.expected_server.as_deref(), &self.node_id)?;
        Ok(())
    }
    pub fn host_directory(&self) -> Result<PathBuf> {
        self.validate()?;
        Ok(PathBuf::from("/run/vprouter-v2")
            .join(&self.deployment_id)
            .join(&self.exit_id))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub binding: Binding,
    pub sequence: u64,
    pub published_at: f64,
    pub state: HealthState,
    pub reason: Option<Reason>,
    pub evidence: Option<Evidence>,
}
impl Snapshot {
    pub fn from_machine(
        binding: Binding,
        sequence: u64,
        now: f64,
        machine: &HealthMachine,
    ) -> Result<Self> {
        binding.validate()?;
        let status = machine.status(now)?;
        if status.mode != binding.mode
            || !machine.matches_binding(
                binding.mode,
                binding.expected_server.as_deref(),
                &binding.node_id,
            )
        {
            return Err(err(Reason::InvalidEvidence));
        }
        let result = Self {
            version: VERSION,
            binding,
            sequence,
            published_at: now,
            state: status.state,
            reason: status.reason,
            evidence: machine.current_evidence(now),
        };
        result.validate(&result.binding, now)?;
        Ok(result)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(err(Reason::InvalidEvidence));
        }
        serde_json::from_slice(bytes).map_err(|_| err(Reason::InvalidEvidence))
    }
    /// Validates cache only. Does not reconstruct a recovery streak, authenticate
    /// a producer or grant liveness, policy ownership, or readiness.
    pub fn validate(&self, expected: &Binding, now: f64) -> Result<Option<f64>> {
        expected.validate()?;
        if self.version != VERSION || &self.binding != expected || self.sequence == 0 {
            return Err(err(Reason::InvalidEvidence));
        }
        if !fresh(now, self.published_at) {
            return Err(err(Reason::StaleEvidence));
        }
        let offline = matches!(self.state, HealthState::Stopping | HealthState::Failed);
        // Blocked can carry the first two NEW validated recovery samples. It
        // remains unready; an actual failure reason must discard evidence.
        if (offline || self.state == HealthState::Blocked && self.reason.is_some())
            && self.evidence.is_some()
        {
            return Err(err(Reason::InvalidEvidence));
        }
        let Some(e) = &self.evidence else {
            return if matches!(self.state, HealthState::Ready | HealthState::Recovering) {
                Err(err(Reason::InvalidEvidence))
            } else {
                Ok(None)
            };
        };
        if e.provider_at > self.published_at
            || e.structural_at > self.published_at
            || e.heartbeat_at > self.published_at
            || e.verified_at.is_some_and(|t| t > self.published_at)
        {
            return Err(err(Reason::InvalidEvidence));
        }
        let mut m = HealthMachine::new(
            expected.mode,
            expected.expected_server.as_deref(),
            &expected.node_id,
        )?;
        m.observe(now, e.clone())?;
        if self.state == HealthState::Ready
            && (!e.online
                || !e.policy_approved
                || e.node_id.as_deref() != Some(expected.node_id.as_str())
                || e.server.as_deref() != expected.expected_server.as_deref()
                || e.egress.is_none()
                || e.verified_at.is_none())
        {
            return Err(err(Reason::InvalidEvidence));
        }
        Ok(e.verified_at.map(|t| now - t))
    }
}
fn fresh(now: f64, at: f64) -> bool {
    now.is_finite() && at.is_finite() && at >= 0. && now >= at && now - at < STALENESS_SECONDS
}
/// Only the authenticated bridge retains this cursor. New generations/boots
/// require a fresh authority instance; a received message cannot reset it.
#[derive(Default)]
pub struct ReplayWindow {
    binding: Option<Binding>,
    last_sequence: u64,
    last_published: Option<f64>,
}
impl ReplayWindow {
    pub fn accept(&mut self, s: &Snapshot, expected: &Binding, now: f64) -> Result<Option<f64>> {
        let age = s.validate(expected, now)?;
        if self
            .binding
            .as_ref()
            .is_some_and(|binding| binding != expected)
            || s.sequence <= self.last_sequence
            || self.last_published.is_some_and(|t| s.published_at < t)
        {
            return Err(err(Reason::StaleEvidence));
        }
        self.binding = Some(expected.clone());
        self.last_sequence = s.sequence;
        self.last_published = Some(s.published_at);
        Ok(age)
    }
}
/// Includes suspend time, unlike process-relative Instant/CLOCK_MONOTONIC.
pub fn boot_seconds() -> f64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    t.tv_sec as f64 + t.tv_nsec as f64 / 1_000_000_000.
}

/// Authenticated-channel payload, never a process or enforcement capability.
/// Lifecycle is generated by the host for each *placed process*, not supplied
/// by the worker. A heartbeat carries no health evidence and cannot renew it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthMessage {
    pub version: u32,
    pub lifecycle: String,
    pub sequence: u64,
    pub sent_at: f64,
    pub snapshot: Option<Snapshot>,
}
impl HealthMessage {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BYTES * 2 {
            return Err(err(Reason::InvalidEvidence));
        }
        serde_json::from_slice(bytes).map_err(|_| err(Reason::InvalidEvidence))
    }
}
/// Retained wire validation for one authenticated host process lifetime. This
/// checks data only: the host must independently pin/verify its sender and apply
/// policy before acknowledging. Once invalid/expired, a session cannot revive.
pub struct Session {
    binding: Binding,
    lifecycle: String,
    replay: ReplayWindow,
    sequence: u64,
    sent_at: f64,
    seen_at: f64,
    verification_at: f64,
    handshake_deadline: Option<f64>,
    has_evidence: bool,
    revoked: bool,
}
impl Session {
    pub fn new(binding: Binding, lifecycle: String, now: f64) -> Result<Self> {
        binding.validate()?;
        if !now.is_finite()
            || now < 0.
            || lifecycle.len() != 64
            || !lifecycle
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(err(Reason::InvalidEvidence));
        }
        Ok(Self {
            binding,
            lifecycle,
            replay: ReplayWindow::default(),
            sequence: 0,
            sent_at: now,
            seen_at: now,
            verification_at: now,
            handshake_deadline: None,
            has_evidence: false,
            revoked: false,
        })
    }
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
    /// Earliest absolute BOOTTIME evidence expiry, for independent enforcers.
    /// This is data only, not a lease or permission to release quarantine.
    pub fn expires_at(&self) -> Result<f64> {
        let after = |at: f64| -> Result<f64> {
            let deadline = at + 44.;
            if !deadline.is_finite() || deadline <= at {
                return Err(err(Reason::StaleEvidence));
            }
            Ok(deadline)
        };
        if self.revoked {
            return Err(err(Reason::StaleEvidence));
        }
        let deadline = after(self.sent_at)?.min(after(self.verification_at)?);
        Ok(self
            .handshake_deadline
            .map_or(deadline, |handshake| deadline.min(handshake)))
    }
    /// One second margin below shared45s freshness. Caller must run this from
    /// its independent guard loop, including while worker/provider is stalled.
    pub fn check(&mut self, now: f64) -> Result<()> {
        if self.revoked
            || !now.is_finite()
            || now < self.seen_at
            || !self.expires_at().is_ok_and(|deadline| now < deadline)
        {
            self.revoke();
            return Err(err(Reason::StaleEvidence));
        }
        self.seen_at = now;
        Ok(())
    }
    pub fn accept(&mut self, message: &HealthMessage, now: f64) -> Result<()> {
        let result = self.accept_inner(message, now);
        if result.is_err() {
            self.revoke();
        }
        result
    }
    fn accept_inner(&mut self, message: &HealthMessage, now: f64) -> Result<()> {
        self.check(now)?;
        if message.version != 1
            || message.lifecycle != self.lifecycle
            || message.sequence
                != self
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| err(Reason::InvalidEvidence))?
            || !message.sent_at.is_finite()
            || message.sent_at < self.sent_at
            || message.sent_at > now
            || now - message.sent_at >= 2.
        {
            return Err(err(Reason::InvalidEvidence));
        }
        if let Some(snapshot) = &message.snapshot {
            self.replay.accept(snapshot, &self.binding, now)?;
            if snapshot.published_at > message.sent_at {
                return Err(err(Reason::InvalidEvidence));
            }
            if let Some(e) = &snapshot.evidence {
                let at = e
                    .verified_at
                    .ok_or_else(|| err(Reason::InvalidEvidence))?
                    .min(e.provider_at)
                    .min(e.structural_at)
                    .min(e.heartbeat_at);
                // Reserializing old evidence with a fresh publication or sequence
                // must not count as a new recovery sample or extend its lease.
                if (self.has_evidence && at <= self.verification_at) || now - at >= 44. {
                    return Err(err(Reason::StaleEvidence));
                }
                self.handshake_deadline = e
                    .handshake_age_seconds
                    .map(|age| {
                        let deadline = e.structural_at + (180. - age);
                        if !deadline.is_finite() || deadline <= now || deadline <= e.structural_at {
                            return Err(err(Reason::StaleEvidence));
                        }
                        Ok(deadline)
                    })
                    .transpose()?;
                self.verification_at = at;
                self.has_evidence = true;
            }
        }
        self.sequence = message.sequence;
        self.sent_at = message.sent_at;
        Ok(())
    }
}
