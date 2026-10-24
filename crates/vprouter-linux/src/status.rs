use crate::{
    Error, Result, sha256,
    storage::{self, Kind},
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::PathBuf};
use vprouter_core::{
    config::{ExitMode, Mode, ValidatedConfiguration},
    state::{Evidence, HealthMachine, HealthState},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub deployment_id: String,
    pub exit_id: String,
    pub mode: ExitMode,
    pub display_name: String,
    pub expected_server: Option<String>,
    pub config_fingerprint: String,
    pub boot_id: String,
    pub state: HealthState,
    pub evidence: Evidence,
}
#[derive(Serialize)]
pub struct ExitStatus {
    pub exit_id: String,
    pub display_name: String,
    pub mode: ExitMode,
    pub exposure: &'static str,
    pub state: &'static str,
    pub guard_runtime: bool,
    pub activation_ready: bool,
    pub source: &'static str,
    pub snapshot_valid: bool,
    pub snapshot_reason: Option<Error>,
    pub cached_verified_age_seconds: Option<f64>,
    pub dns: &'static str,
    pub ipv6: &'static str,
}
pub fn config_fingerprint(cfg: &ValidatedConfiguration) -> Result<String> {
    serde_json::to_vec(cfg.configuration())
        .map(|bytes| sha256(&bytes))
        .map_err(|_| Error::InvalidConfiguration)
}
fn public_text(path: &str) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(4097)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= 4096).then_some(())?;
    String::from_utf8(bytes).ok()
}
fn validate_snapshot(
    snapshot: &Snapshot,
    cfg: &ValidatedConfiguration,
    index: usize,
    now: f64,
    boot: &str,
) -> Result<Option<f64>> {
    let exit = &cfg.exits()[index];
    let expected_server = match &exit.exit().mode {
        Mode::Mullvad {
            expected_server, ..
        } => Some(expected_server.as_str()),
        Mode::Direct {} => None,
    };
    if snapshot.version != 1
        || snapshot.deployment_id != cfg.configuration().deployment_id
        || snapshot.exit_id != exit.exit().id
        || snapshot.mode != exit.exit().mode.kind()
        || snapshot.display_name != exit.hostname()
        || snapshot.expected_server.as_deref() != expected_server
        || snapshot.config_fingerprint != config_fingerprint(cfg)?
        || snapshot.boot_id != boot
    {
        return Err(Error::SnapshotBindingMismatch);
    }
    // A node ID supplied by the snapshot cannot be its own authority.
    let mut nodes = cfg
        .configuration()
        .client_policies
        .iter()
        .filter(|p| p.exit_id == exit.exit().id)
        .map(|p| p.selected_node_id.as_str());
    let node = nodes.next().ok_or(Error::InvalidSnapshot)?;
    if nodes.any(|n| n != node) {
        return Err(Error::InvalidSnapshot);
    }
    let mut machine = HealthMachine::new(snapshot.mode, expected_server, node)
        .map_err(|_| Error::InvalidSnapshot)?;
    machine
        .observe(now, snapshot.evidence.clone())
        .map_err(|e| match e.reason() {
            vprouter_core::reason::Reason::StaleEvidence => Error::StaleSnapshot,
            _ => Error::InvalidSnapshot,
        })?;
    machine.status(now).map_err(|_| Error::InvalidSnapshot)?;
    // Even cached declared READY must carry the full evidence fields. This
    // does not reconstruct a recovery streak, liveness or resource ownership.
    if snapshot.state == HealthState::Ready
        && (!snapshot.evidence.online
            || !snapshot.evidence.policy_approved
            || snapshot.evidence.node_id.as_deref() != Some(node)
            || snapshot.evidence.server.as_deref() != expected_server
            || snapshot.evidence.egress.is_none()
            || snapshot.evidence.verified_at.is_none())
    {
        return Err(Error::InvalidSnapshot);
    }
    Ok(snapshot.evidence.verified_at.map(|t| now - t))
}
pub fn status(cfg: &ValidatedConfiguration) -> Vec<ExitStatus> {
    let now =
        public_text("/proc/uptime").and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok());
    let boot = public_text("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_owned());
    cfg.exits()
        .iter()
        .enumerate()
        .map(|(i, exit)| {
            let mut row = ExitStatus {
                exit_id: exit.exit().id.clone(),
                display_name: exit.hostname().into(),
                mode: exit.exit().mode.kind(),
                exposure: if matches!(exit.exit().mode, Mode::Direct {}) {
                    "direct-exposed"
                } else {
                    "unverified"
                },
                state: if exit.exit().enabled {
                    "NOT_TESTED"
                } else {
                    "disabled"
                },
                guard_runtime: false,
                activation_ready: false,
                source: "none",
                snapshot_valid: false,
                snapshot_reason: None,
                cached_verified_age_seconds: None,
                dns: "NOT_TESTED",
                ipv6: "NOT_TESTED",
            };
            if !exit.exit().enabled {
                return row;
            }
            let path = PathBuf::from("/run/vprouter-v2")
                .join(&cfg.configuration().deployment_id)
                .join(&exit.exit().id)
                .join("health.json");
            let result = path
                .parent()
                .ok_or(Error::UnsafePath)
                .and_then(|parent| storage::metadata(parent, Kind::PrivateDirectory))
                .and_then(|_| storage::read(&path, Kind::SecretFile, 64 * 1024))
                .and_then(|bytes| {
                    serde_json::from_slice::<Snapshot>(&bytes).map_err(|_| Error::InvalidSnapshot)
                })
                .and_then(|snapshot| {
                    validate_snapshot(
                        &snapshot,
                        cfg,
                        i,
                        now.ok_or(Error::InvalidSnapshot)?,
                        boot.as_deref().ok_or(Error::InvalidSnapshot)?,
                    )
                });
            match result {
                Ok(age) => {
                    row.source = "cached";
                    row.snapshot_valid = true;
                    row.cached_verified_age_seconds = age;
                }
                Err(reason) => row.snapshot_reason = Some(reason),
            }
            row
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use vprouter_core::config::Configuration;
    fn config() -> ValidatedConfiguration {
        Configuration::parse(br#"{"schema_version":2,"deployment_id":"test","site":"site","gateway_image":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","exits":[{"id":"direct","enabled":true,"state_dir":"/private/direct","mode":{"kind":"direct"}}],"dependency_adapters":[],"client_policies":[{"id":"client","exit_id":"direct","selected_node_id":"node1","mode":"direct","dependency_adapters":[]}]}"#).unwrap().validate().unwrap()
    }
    fn snapshot(cfg: &ValidatedConfiguration) -> Snapshot {
        serde_json::from_value(serde_json::json!({"version":1,"deployment_id":"test","exit_id":"direct","mode":"direct","display_name":cfg.exits()[0].hostname(),"expected_server":null,"config_fingerprint":config_fingerprint(cfg).unwrap(),"boot_id":"boot","state":"READY",
            "evidence":{"provider_ok":true,"structural_ok":true,"provider_at":100.0,"structural_at":100.0,"heartbeat_at":100.0,"handshake_age_seconds":null,"online":true,"policy_approved":true,"server":null,"node_id":"node1","egress":"8.8.8.8","verified_at":100.0,"dns":"not_tested","ipv6":"not_tested"}})).unwrap()
    }
    #[test]
    fn stale_wrong_boot_or_config_cannot_validate() {
        let cfg = config();
        let mut s = snapshot(&cfg);
        assert_eq!(validate_snapshot(&s, &cfg, 0, 101.0, "boot"), Ok(Some(1.0)));
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 145.0, "boot"),
            Err(Error::StaleSnapshot)
        );
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 101.0, "otherboot"),
            Err(Error::SnapshotBindingMismatch)
        );
        s.display_name = "old-name".into();
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 101.0, "boot"),
            Err(Error::SnapshotBindingMismatch)
        );
        s = snapshot(&cfg);
        s.evidence.node_id = Some("forged-node".into());
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 101.0, "boot"),
            Err(Error::InvalidSnapshot)
        );
        for change in ["deployment", "id", "mode", "server", "fingerprint"] {
            let mut s = snapshot(&cfg);
            match change {
                "deployment" => s.deployment_id = "other".into(),
                "id" => s.exit_id = "other".into(),
                "mode" => s.mode = ExitMode::Mullvad,
                "server" => s.expected_server = Some("de-fra-wg-404".into()),
                "fingerprint" => s.config_fingerprint = "0".repeat(64),
                _ => unreachable!(),
            }
            assert_eq!(
                validate_snapshot(&s, &cfg, 0, 101.0, "boot"),
                Err(Error::SnapshotBindingMismatch)
            );
        }
        s = snapshot(&cfg);
        s.evidence.policy_approved = false;
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 101.0, "boot"),
            Err(Error::InvalidSnapshot)
        );
    }
    #[test]
    fn missing_health_never_yields_ready_and_direct_is_always_exposed() {
        let rows = status(&config());
        assert_eq!(rows[0].state, "NOT_TESTED");
        assert!(!rows[0].activation_ready);
        assert!(!rows[0].guard_runtime);
        assert_eq!(rows[0].exposure, "direct-exposed");
        let mut configuration = config().configuration().clone();
        configuration.exits[0].enabled = false;
        let disabled = configuration.validate().unwrap();
        let rows = status(&disabled);
        assert_eq!(rows[0].state, "disabled");
        assert_eq!(rows[0].exposure, "direct-exposed");
        assert_eq!(rows[0].source, "none");
    }
}
