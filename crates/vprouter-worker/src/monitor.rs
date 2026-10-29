//! Fixed monitor startup publication. The initial exchange cannot request Ready.
//! A quarantined stop is the only command currently admitted; continued sampling
//! stays refused until the host's independent expiry authority is integrated.
use crate::{Error, Result, bootstrap, placement::Placed};
use serde::{Deserialize, Serialize};
use vprouter_core::{
    health::{HealthMessage, Snapshot, boot_seconds},
    state::HealthMachine,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthAck {
    pub version: u32,
    pub lifecycle: String,
    pub sequence: u64,
    pub snapshot_sequence: u64,
    pub disposition: Disposition,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Prepared,
    Persisted,
    QuarantinedStop,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStage {
    Persist,
    Finalize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationStep {
    pub version: u32,
    pub lifecycle: String,
    pub sequence: u64,
    pub snapshot_sequence: u64,
    pub stage: PublicationStage,
}
impl PublicationStep {
    pub fn validate(
        &self,
        lifecycle: &str,
        sequence: u64,
        snapshot: u64,
        stage: PublicationStage,
    ) -> Result<()> {
        if self.version != 1
            || self.lifecycle != lifecycle
            || self.sequence != sequence
            || self.snapshot_sequence != snapshot
            || self.stage != stage
        {
            return Err(Error::GuardUnavailable);
        }
        Ok(())
    }
}
fn acknowledgement(
    ack: &HealthAck,
    lifecycle: &str,
    sequence: u64,
    snapshot: u64,
    expected: Disposition,
) -> Result<()> {
    if ack.version != 1
        || ack.lifecycle != lifecycle
        || ack.sequence != sequence
        || ack.snapshot_sequence != snapshot
        || ack.disposition != expected
    {
        return Err(Error::GuardUnavailable);
    }
    Ok(())
}
/// Fixed three-phase startup transaction. No progress packet can restart the
/// total6s budget or turn an expired phase into a valid acknowledgement.
pub struct PublicationBudget {
    end: std::time::Instant,
    phase: u8,
    active: Option<std::time::Instant>,
    failed: bool,
}
impl Default for PublicationBudget {
    fn default() -> Self {
        Self::new()
    }
}
impl PublicationBudget {
    pub fn new() -> Self {
        Self {
            end: std::time::Instant::now() + std::time::Duration::from_secs(6),
            phase: 0,
            active: None,
            failed: false,
        }
    }
    pub fn next_deadline(&mut self) -> Result<std::time::Instant> {
        let now = std::time::Instant::now();
        if self.failed || self.active.is_some() || self.phase >= 3 || now >= self.end {
            self.failed = true;
            return Err(Error::GuardUnavailable);
        }
        self.phase += 1;
        let deadline = self.end.min(now + std::time::Duration::from_secs(2));
        self.active = Some(deadline);
        Ok(deadline)
    }
    pub fn complete_phase(&mut self) -> Result<()> {
        let now = std::time::Instant::now();
        if self.failed || self.active.is_none_or(|end| now >= end) || now >= self.end {
            self.failed = true;
            return Err(Error::GuardUnavailable);
        }
        self.active = None;
        Ok(())
    }
    pub fn complete(&mut self) -> Result<()> {
        if self.failed
            || self.active.is_some()
            || self.phase != 3
            || std::time::Instant::now() >= self.end
        {
            self.failed = true;
            return Err(Error::GuardUnavailable);
        }
        Ok(())
    }
}
/// The only public entry uses fixed protected paths and authenticates its host
/// before constructing placement. No configuration/namespace/argv overrides.
pub fn start() -> Result<()> {
    let mut admission = bootstrap::admit_monitor()?;
    let placed = Placed::authenticated(&admission)?;
    if admission.config().enrollment.is_some() {
        return crate::engine::run_operational(admission, std::rc::Rc::new(placed));
    }
    let binding = admission
        .config()
        .health_binding
        .clone()
        .ok_or(Error::Bootstrap)?;
    let lifecycle = admission.config().nonce.clone();
    let machine = HealthMachine::new(
        binding.mode,
        binding.expected_server.as_deref(),
        &binding.node_id,
    )
    .map_err(|_| Error::InvalidConfiguration)?;
    let now = boot_seconds();
    let snapshot = Snapshot::from_machine(binding, 1, now, &machine).map_err(|_| Error::Storage)?;
    let message = HealthMessage {
        version: 1,
        lifecycle: lifecycle.clone(),
        sequence: 1,
        sent_at: now,
        snapshot: Some(snapshot),
    };
    placed.check()?;
    let mut budget = PublicationBudget::new();
    let end = budget.next_deadline()?;
    bootstrap::write_message_before(&mut admission.stream, &message, end)?;
    // A fixed finite transaction splits expensive full audits from fsync. Every
    // frame retains the existing2s bound; these steps carry no new evidence and
    // grant no operational permission. Only the final ACK permits offline exit.
    let ack: HealthAck = bootstrap::read_message_before(&mut admission.stream, end)?;
    acknowledgement(&ack, &lifecycle, 1, 1, Disposition::Prepared)?;
    budget.complete_phase()?;
    for (stage, expected) in [
        (PublicationStage::Persist, Disposition::Persisted),
        (PublicationStage::Finalize, Disposition::QuarantinedStop),
    ] {
        let end = budget.next_deadline()?;
        admission.check()?;
        placed.check()?;
        bootstrap::write_message_before(
            &mut admission.stream,
            &PublicationStep {
                version: 1,
                lifecycle: lifecycle.clone(),
                sequence: 1,
                snapshot_sequence: 1,
                stage,
            },
            end,
        )?;
        let ack: HealthAck = bootstrap::read_message_before(&mut admission.stream, end)?;
        acknowledgement(&ack, &lifecycle, 1, 1, expected)?;
        budget.complete_phase()?;
    }
    admission.check()?;
    placed.check()?;
    budget.complete()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn publication_budget_has_three_two_second_phases_and_no_total_renewal() {
        use std::time::{Duration, Instant};
        let mut budget = PublicationBudget::new();
        let total = budget.end;
        for _ in 0..3 {
            let before = Instant::now();
            let phase = budget.next_deadline().unwrap();
            assert!(phase <= Instant::now() + Duration::from_secs(2));
            assert!(phase <= total && phase > before);
            budget.complete_phase().unwrap();
        }
        assert!(budget.next_deadline().is_err());
        let mut expired = PublicationBudget {
            end: Instant::now(),
            phase: 0,
            active: None,
            failed: false,
        };
        assert!(expired.next_deadline().is_err());
    }
    #[test]
    fn publication_phase_must_complete_on_time_before_advancing() {
        let mut budget = PublicationBudget::new();
        budget.next_deadline().unwrap();
        assert!(budget.next_deadline().is_err());
        assert!(budget.complete_phase().is_err());
        let mut budget = PublicationBudget::new();
        budget.next_deadline().unwrap();
        budget.active = Some(std::time::Instant::now());
        assert!(budget.complete_phase().is_err());
        assert!(budget.next_deadline().is_err());
    }
    #[test]
    fn staged_publication_rejects_skipped_repeated_and_unbound_steps() {
        let ack = HealthAck {
            version: 1,
            lifecycle: "bound".into(),
            sequence: 1,
            snapshot_sequence: 1,
            disposition: Disposition::Prepared,
        };
        acknowledgement(&ack, "bound", 1, 1, Disposition::Prepared).unwrap();
        assert!(acknowledgement(&ack, "bound", 1, 1, Disposition::Persisted).is_err());
        assert!(acknowledgement(&ack, "other", 1, 1, Disposition::Prepared).is_err());
        let step = PublicationStep {
            version: 1,
            lifecycle: "bound".into(),
            sequence: 1,
            snapshot_sequence: 1,
            stage: PublicationStage::Persist,
        };
        step.validate("bound", 1, 1, PublicationStage::Persist)
            .unwrap();
        for (life, seq, snap, stage) in [
            ("other", 1, 1, PublicationStage::Persist),
            ("bound", 2, 1, PublicationStage::Persist),
            ("bound", 1, 2, PublicationStage::Persist),
            ("bound", 1, 1, PublicationStage::Finalize),
        ] {
            assert!(step.validate(life, seq, snap, stage).is_err());
        }
    }
    #[test]
    fn initial_ack_cannot_change_lifecycle_sequence_or_request_activation() {
        let good = r#"{"version":1,"lifecycle":"bound","sequence":1,"snapshot_sequence":1,"disposition":"quarantined_stop"}"#;
        acknowledgement(
            &crate::json::decode(good.as_bytes()).unwrap(),
            "bound",
            1,
            1,
            Disposition::QuarantinedStop,
        )
        .unwrap();
        for (key, value) in [
            ("version", serde_json::json!(2)),
            ("lifecycle", serde_json::json!("old")),
            ("sequence", serde_json::json!(2)),
            ("snapshot_sequence", serde_json::json!(2)),
            ("disposition", serde_json::json!("ready")),
        ] {
            let mut wrong: serde_json::Value = serde_json::from_str(good).unwrap();
            wrong[key] = value;
            let result = crate::json::decode::<HealthAck>(&serde_json::to_vec(&wrong).unwrap())
                .and_then(|ack| acknowledgement(&ack, "bound", 1, 1, Disposition::QuarantinedStop));
            assert!(result.is_err(), "{key}");
        }
    }
}
