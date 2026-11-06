//! Offline configuration preparation. These values never authorize native
//! mutations, namespace placement, or quarantine release.
use crate::{
    allocation::{AllocationRecord, ResourceClaim},
    config::{Configuration, Exit, Mode, ValidatedConfiguration},
    profile::Profile,
    reason::{Reason, Result, err},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(crate) const MAX_PREPARATION_BYTES: usize = 2 * 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExitChange {
    Add {
        exit: Exit,
    },
    Remove {
        exit_id: String,
    },
    Enable {
        exit_id: String,
    },
    Disable {
        exit_id: String,
    },
    PinServer {
        exit_id: String,
        profile: PathBuf,
        expected_server: String,
    },
}
impl ExitChange {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 1024 * 1024 {
            return Err(err(Reason::InvalidSchema));
        }
        serde_json::from_slice(bytes).map_err(|_| err(Reason::InvalidSchema))
    }
}

/// One atomic *preparation* snapshot, deliberately separate from allocations.json.
/// Decoding verifies public shape, not current credentials or runtime ownership.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetRecord {
    schema_version: u32,
    configuration: Configuration,
    allocations: AllocationRecord,
}
#[derive(Debug, PartialEq, Eq)]
pub struct HostnameChange {
    pub exit_id: String,
    pub previous: Option<String>,
    pub next: String,
}
/// Not Serialize/Debug: retains the existing validated secret-owning object.
pub struct PreparedFleet {
    previous: Option<[u8; 32]>,
    record: FleetRecord,
    validated: ValidatedConfiguration,
    renames: Vec<HostnameChange>,
}
impl FleetRecord {
    pub fn generation(&self) -> u64 {
        self.allocations.generation
    }
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn allocations(&self) -> &AllocationRecord {
        &self.allocations
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| err(Reason::InvalidSchema))?;
        if bytes.len() > MAX_PREPARATION_BYTES {
            return Err(err(Reason::InvalidSchema));
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], deployment: &str) -> Result<Self> {
        if bytes.len() > MAX_PREPARATION_BYTES {
            return Err(err(Reason::InvalidSchema));
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| err(Reason::InvalidSchema))?;
        if record.schema_version != 1 {
            return Err(err(Reason::InvalidSchema));
        }
        let structure = record.configuration.clone().validate_structure()?;
        record.allocations.validate(deployment, &[])?;
        let expected = AllocationRecord::from_structure(&structure, record.generation())?;
        if serde_json::to_vec(&expected).map_err(|_| err(Reason::InvalidSchema))?
            != serde_json::to_vec(&record.allocations).map_err(|_| err(Reason::InvalidSchema))?
        {
            return Err(err(Reason::AllocationConflict));
        }
        Ok(record)
    }
    pub(crate) fn digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.encode()?).into())
    }
    pub fn prepare<F>(
        &self,
        change: ExitChange,
        reader: F,
        foreign: &[ResourceClaim],
    ) -> Result<PreparedFleet>
    where
        F: FnMut(&Path, &str) -> Result<Profile>,
    {
        let mut cfg = self.configuration.clone();
        let enabled = matches!(&change, ExitChange::Enable { .. });
        match change {
            ExitChange::Add { exit } => cfg.exits.push(exit),
            ExitChange::Remove { exit_id } => {
                let i = cfg
                    .exits
                    .iter()
                    .position(|e| e.id == exit_id)
                    .ok_or_else(|| err(Reason::InvalidReference))?;
                cfg.exits.remove(i);
            }
            ExitChange::Enable { exit_id } | ExitChange::Disable { exit_id } => {
                cfg.exits
                    .iter_mut()
                    .find(|e| e.id == exit_id)
                    .ok_or_else(|| err(Reason::InvalidReference))?
                    .enabled = enabled;
            }
            ExitChange::PinServer {
                exit_id,
                profile,
                expected_server,
            } => {
                let exit = cfg
                    .exits
                    .iter_mut()
                    .find(|e| e.id == exit_id)
                    .ok_or_else(|| err(Reason::InvalidReference))?;
                // Pinning cannot convert an exposed identity into a provider identity.
                if !matches!(exit.mode, Mode::Mullvad { .. }) {
                    return Err(err(Reason::InvalidTransition));
                }
                exit.mode = Mode::Mullvad {
                    profile,
                    expected_server,
                };
            }
        }
        let generation = self
            .generation()
            .checked_add(1)
            .ok_or_else(|| err(Reason::GenerationConflict))?;
        PreparedFleet::build(cfg, generation, Some(self), reader, foreign)
    }
}
impl PreparedFleet {
    pub fn initial<F>(cfg: Configuration, reader: F, foreign: &[ResourceClaim]) -> Result<Self>
    where
        F: FnMut(&Path, &str) -> Result<Profile>,
    {
        Self::build(cfg, 1, None, reader, foreign)
    }
    fn build<F>(
        cfg: Configuration,
        generation: u64,
        previous: Option<&FleetRecord>,
        reader: F,
        foreign: &[ResourceClaim],
    ) -> Result<Self>
    where
        F: FnMut(&Path, &str) -> Result<Profile>,
    {
        let validated = cfg.validate_with(reader)?;
        let allocations = AllocationRecord::from_configuration(&validated, generation)?;
        allocations.validate(&validated.configuration().deployment_id, foreign)?;
        // Distinct exits cannot preserve the same stable Tailscale node identity.
        let mut nodes = std::collections::HashMap::new();
        for policy in &validated.configuration().client_policies {
            if nodes
                .insert(&policy.selected_node_id, &policy.exit_id)
                .is_some_and(|exit| exit != &policy.exit_id)
            {
                return Err(err(Reason::InvalidReference));
            }
        }
        let previous_names = previous
            .map(|p| p.configuration.clone().validate_structure())
            .transpose()?;
        // Hostname computation is always the existing schema implementation.
        let old_names = previous_names
            .map(|p| p.hostnames_by_id())
            .unwrap_or_default();
        let renames = validated
            .exits()
            .iter()
            .filter_map(|e| {
                let previous = old_names.get(&e.exit().id).cloned();
                (previous.as_deref() != Some(e.hostname())).then(|| HostnameChange {
                    exit_id: e.exit().id.clone(),
                    previous,
                    next: e.hostname().into(),
                })
            })
            .collect();
        let record = FleetRecord {
            schema_version: 1,
            configuration: validated.configuration().clone(),
            allocations,
        };
        record.encode()?;
        Ok(Self {
            previous: previous.map(FleetRecord::digest).transpose()?,
            record,
            validated,
            renames,
        })
    }
    pub fn record(&self) -> &FleetRecord {
        &self.record
    }
    pub fn configuration(&self) -> &ValidatedConfiguration {
        &self.validated
    }
    pub fn renames(&self) -> &[HostnameChange] {
        &self.renames
    }
    pub(crate) fn expected_digest(&self) -> Option<[u8; 32]> {
        self.previous
    }
}
