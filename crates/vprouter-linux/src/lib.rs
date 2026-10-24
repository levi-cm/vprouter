#![forbid(unsafe_code)]
//! Observational Linux preparation only. No activation, locks, shell or guard.
pub mod docker;
pub mod host;
pub mod migration;
pub mod status;
pub mod storage;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use vprouter_core::{
    config::{Configuration, ValidatedConfiguration},
    profile::Profile,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidArguments,
    InvalidConfiguration,
    InvalidLegacyConfiguration,
    AlreadyV2,
    UnsafePath,
    Unavailable,
    TooLarge,
    InvalidProfile,
    InvalidPlatform,
    DockerUnavailable,
    DockerTimeout,
    DockerProtocol,
    DockerHttpFailure,
    DockerIncompatible,
    InvalidInventory,
    InvalidSnapshot,
    StaleSnapshot,
    SnapshotBindingMismatch,
    OutputExistsOrUnsafe,
    OutputDurabilityUncertain,
}
pub type Result<T> = std::result::Result<T, Error>;

pub fn capabilities() -> Value {
    json!({
        "read_only":true, "guard_runtime":false, "activation_ready":false,
        "implemented_commands":["validate", "status", "probe", "migrate inspect", "migrate plan", "diagnose"],
        "unimplemented_commands":["exit add", "exit remove", "exit enable", "exit disable", "migrate apply", "migrate resume", "migrate rollback", "client install", "client select", "client status"],
        "migration_apply":false, "native_feature_probes":"NOT_TESTED"
    })
}
pub fn load_configuration(path: &Path) -> Result<ValidatedConfiguration> {
    let bytes = storage::read(path, storage::Kind::PublicFile, 1024 * 1024)?;
    parse_configuration(&bytes)
}
/// Parse configuration content with the same redacted error mapping used by
/// the protected file loader. Referenced profiles still require secure reads.
pub fn parse_configuration(bytes: &[u8]) -> Result<ValidatedConfiguration> {
    Configuration::parse(bytes)
        .map_err(|_| Error::InvalidConfiguration)?
        .validate_with(load_profile)
        .map_err(|_| Error::InvalidConfiguration)
}
pub fn load_profile(path: &Path, expected: &str) -> vprouter_core::reason::Result<Profile> {
    let bytes = storage::read(path, storage::Kind::SecretFile, 64 * 1024).map_err(|_| {
        vprouter_core::reason::Error::new(vprouter_core::reason::Reason::ProfileUnavailable)
    })?;
    Profile::parse(&bytes, expected, Some(path))
}
pub fn failure(error: Error) -> Value {
    json!({"ok":false, "reason":error, "activation_ready":false, "capabilities":capabilities()})
}
pub fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
