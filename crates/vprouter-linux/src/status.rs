use crate::{
    Error, Result, sha256,
    storage::{self, Kind},
};
use serde::Serialize;
use std::{fs::File, io::Read, path::PathBuf};
use vprouter_core::{
    allocation::AllocationRecord,
    config::{ExitMode, Mode, ValidatedConfiguration},
    health::{Binding, Snapshot},
};

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
/// Shared producer-to-reader validation. Expected generation comes from the
/// independently owned allocation record, never from a received snapshot.
pub fn expected_binding(
    cfg: &ValidatedConfiguration,
    index: usize,
    generation: u64,
    boot: &str,
) -> Result<Binding> {
    let exit = cfg.exits().get(index).ok_or(Error::InvalidSnapshot)?;
    let expected_server = match &exit.exit().mode {
        Mode::Mullvad {
            expected_server, ..
        } => Some(expected_server.clone()),
        Mode::Direct {} => None,
    };
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
    let binding = Binding {
        deployment_id: cfg.configuration().deployment_id.clone(),
        exit_id: exit.exit().id.clone(),
        generation,
        mode: exit.exit().mode.kind(),
        display_name: exit.hostname().into(),
        expected_server,
        node_id: node.into(),
        config_fingerprint: config_fingerprint(cfg)?,
        boot_id: boot.into(),
    };
    Ok(binding)
}
pub fn validate_snapshot(
    snapshot: &Snapshot,
    cfg: &ValidatedConfiguration,
    index: usize,
    generation: u64,
    now: f64,
    boot: &str,
) -> Result<Option<f64>> {
    let binding = expected_binding(cfg, index, generation, boot)?;
    if snapshot.binding != binding {
        return Err(Error::SnapshotBindingMismatch);
    }
    snapshot
        .validate(&binding, now)
        .map_err(|e| match e.reason() {
            vprouter_core::reason::Reason::StaleEvidence => Error::StaleSnapshot,
            _ => Error::InvalidSnapshot,
        })
}
pub fn status(cfg: &ValidatedConfiguration) -> Vec<ExitStatus> {
    let now = vprouter_core::health::boot_seconds();
    let allocation_path = PathBuf::from("/run/vprouter-v2")
        .join(&cfg.configuration().deployment_id)
        .join("allocations.json");
    let allocation =
        storage::read(&allocation_path, Kind::SecretFile, 64 * 1024).and_then(|bytes| {
            let a = AllocationRecord::parse(&bytes, &cfg.configuration().deployment_id, &[])
                .map_err(|_| Error::InvalidSnapshot)?;
            a.matches_configuration(cfg)
                .map_err(|_| Error::SnapshotBindingMismatch)?;
            Ok(a)
        });
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
                .and_then(|bytes| Snapshot::decode(&bytes).map_err(|_| Error::InvalidSnapshot))
                .and_then(|snapshot| {
                    validate_snapshot(
                        &snapshot,
                        cfg,
                        i,
                        allocation.as_ref().map_err(|e| *e)?.generation,
                        now,
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
    const BOOT: &str = "01234567-1234-1234-1234-0123456789ab";
    fn snapshot(cfg: &ValidatedConfiguration) -> Snapshot {
        serde_json::from_value(serde_json::json!({"version":2,"binding":{"deployment_id":"test","exit_id":"direct","mode":"direct","generation":1,"node_id":"node1","display_name":cfg.exits()[0].hostname(),"expected_server":null,"config_fingerprint":config_fingerprint(cfg).unwrap(),"boot_id":BOOT},"sequence":1,"published_at":100.,"state":"READY","reason":null,
            "evidence":{"provider_ok":true,"structural_ok":true,"provider_at":100.0,"structural_at":100.0,"heartbeat_at":100.0,"handshake_age_seconds":null,"online":true,"policy_approved":true,"server":null,"node_id":"node1","egress":"8.8.8.8","verified_at":100.0,"dns":"not_tested","ipv6":"not_tested"}})).unwrap()
    }
    #[test]
    fn stale_wrong_boot_or_config_cannot_validate() {
        let cfg = config();
        let mut s = snapshot(&cfg);
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 1, 101.0, BOOT),
            Ok(Some(1.0))
        );
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 1, 145.0, BOOT),
            Err(Error::StaleSnapshot)
        );
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 1, 101.0, "otherboot"),
            Err(Error::SnapshotBindingMismatch)
        );
        s.binding.display_name = "old-name".into();
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 1, 101.0, BOOT),
            Err(Error::SnapshotBindingMismatch)
        );
        s = snapshot(&cfg);
        s.evidence.as_mut().unwrap().node_id = Some("forged-node".into());
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 1, 101.0, BOOT),
            Err(Error::InvalidSnapshot)
        );
        for change in ["deployment", "id", "mode", "server", "fingerprint"] {
            let mut s = snapshot(&cfg);
            match change {
                "deployment" => s.binding.deployment_id = "other".into(),
                "id" => s.binding.exit_id = "other".into(),
                "mode" => s.binding.mode = ExitMode::Mullvad,
                "server" => s.binding.expected_server = Some("de-fra-wg-404".into()),
                "fingerprint" => s.binding.config_fingerprint = "0".repeat(64),
                _ => unreachable!(),
            }
            assert_eq!(
                validate_snapshot(&s, &cfg, 0, 1, 101.0, BOOT),
                Err(Error::SnapshotBindingMismatch)
            );
        }
        s = snapshot(&cfg);
        s.evidence.as_mut().unwrap().policy_approved = false;
        assert_eq!(
            validate_snapshot(&s, &cfg, 0, 1, 101.0, BOOT),
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
