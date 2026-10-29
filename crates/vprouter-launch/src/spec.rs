#![forbid(unsafe_code)]
use super::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vprouter_core::allocation::{AllocationRecord, ExitAllocation};
use vprouter_linux::storage::{self, Kind};

pub(super) const WORKER: &str = "/usr/local/bin/vprouter-worker";
pub(super) const LIMIT: usize = 64 * 1024 * 1024;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    pub(super) schema_version: u32,
    pub(super) allocation: AllocationRecord,
    pub(super) generation: u64,
    pub(super) exit: ExitAllocation,
    pub(super) container_id: String,
    pub(super) started_at: String,
    pub(super) process_start_time: u64,
    pub(super) image_ref: String,
    pub(super) worker_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagingEvidence {
    pub(super) schema_version: u32,
    pub(super) image_ref: String,
    pub(super) content_id: String,
    pub(super) os: String,
    pub(super) architecture: String,
    pub(super) artifact_kind: String,
    pub(super) artifact_path: PathBuf,
    pub(super) artifact_sha256: String,
    pub(super) artifact_size: u64,
    pub(super) worker_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) execution_policy_sha256: Option<String>,
}
pub(super) fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn image_ref(s: &str) -> bool {
    s.split_once("@sha256:").is_some_and(|(name, hash)| {
        !name.is_empty()
            && name.len() < 192
            && name
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"/._-:".contains(&c))
            && digest(hash)
    })
}
pub(super) fn safe_absolute(path: &Path) -> bool {
    path.to_str().is_some_and(|s| {
        s.starts_with('/')
            && s.len() <= 4096
            && !s.chars().any(char::is_control)
            && s.split('/')
                .skip(1)
                .all(|s| !s.is_empty() && s != "." && s != "..")
    })
}
fn read(path: &Path) -> Result<Vec<u8>> {
    storage::read(path, Kind::SecretFile, 512 * 1024).map_err(|_| Error::UnsafeInput)
}
impl LaunchSpec {
    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&read(path)?)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 512 * 1024 {
            return Err(Error::TooLarge);
        }
        let spec: Self = serde_json::from_slice(bytes).map_err(|_| Error::InvalidSpec)?;
        spec.validate()?;
        Ok(spec)
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.allocation
            .validate(&self.allocation.deployment_id, &[])
            .map_err(|_| Error::AllocationMismatch)?;
        if self.generation != self.allocation.generation
            || !self.allocation.exits.contains(&self.exit)
        {
            return Err(Error::AllocationMismatch);
        }
        if self.schema_version != 1
            || !digest(&self.container_id)
            || !digest(&self.worker_sha256)
            || !image_ref(&self.image_ref)
            || self.process_start_time == 0
            || !valid_start(&self.started_at)
        {
            return Err(Error::InvalidSpec);
        }
        Ok(())
    }
    pub(super) fn bind_staging(&self, staging: &StagingEvidence) -> Result<()> {
        self.validate()?;
        if self.image_ref != staging.image_ref || self.worker_sha256 != staging.artifact_sha256 {
            return Err(Error::ImageMismatch);
        }
        Ok(())
    }
}
pub(super) fn valid_start(s: &str) -> bool {
    // Docker RFC3339 UTC timestamp, exact comparison remains mandatory.
    let b = s.as_bytes();
    if b.len() < 20
        || b.len() > 35
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[b.len() - 1] != b'Z'
    {
        return false;
    }
    b.iter().enumerate().all(|(i, c)| match i {
        4 | 7 | 10 | 13 | 16 => true,
        i if i == b.len() - 1 => true,
        19 if b.len() > 20 => *c == b'.',
        _ => c.is_ascii_digit(),
    })
}
impl StagingEvidence {
    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&read(path)?)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = Self::decode(bytes)?;
        if value.artifact_kind != "vprouter_worker_v1" {
            return Err(Error::ExecutableMismatch);
        }
        // No worker implementation/staging integration exists yet. An operator
        // cannot turn arbitrary root-owned bytes into production worker evidence.
        Err(Error::LaunchUnavailable)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 512 * 1024 {
            return Err(Error::TooLarge);
        }
        let v: Self = serde_json::from_slice(bytes).map_err(|_| Error::InvalidSpec)?;
        if v.schema_version != 1
            || !image_ref(&v.image_ref)
            || !v.content_id.strip_prefix("sha256:").is_some_and(digest)
            || v.os != "linux"
            || !matches!(v.architecture.as_str(), "amd64" | "arm64")
            || !safe_absolute(&v.artifact_path)
            || !digest(&v.artifact_sha256)
            || v.artifact_size < 64
            || v.artifact_size > LIMIT as u64
            || v.execution_policy_sha256
                .as_ref()
                .is_some_and(|s| !digest(s))
            || v.worker_path != WORKER
        {
            return Err(Error::InvalidSpec);
        }
        let arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            return Err(Error::UnsupportedPlatform);
        };
        if v.architecture != arch {
            return Err(Error::UnsupportedPlatform);
        }
        Ok(v)
    }
    #[cfg(test)]
    pub(super) fn load_probe(path: &Path) -> Result<Self> {
        let v = Self::decode(&read(path)?)?;
        if v.artifact_kind != "synthetic_static_probe_v1" {
            return Err(Error::ExecutableMismatch);
        }
        Ok(v)
    }
    #[cfg(test)]
    pub(super) fn load_actual_gateway(path: &Path) -> Result<Self> {
        Self::parse_actual_gateway(&read(path)?)
    }
    #[cfg(test)]
    pub(super) fn parse_actual_gateway(bytes: &[u8]) -> Result<Self> {
        let value = Self::decode(bytes)?;
        let bundle = super::programs::ReviewedBundle::current()?;
        let (sha256, size) = bundle.init()?;
        if value.artifact_kind != "actual_gateway_lab_v1"
            || value.image_ref != format!("vprouter-v2-lab@{}", value.content_id)
            || value.artifact_path
                != Path::new(&format!(
                    "/var/lib/vprouter-v2-lab/task8b2-{sha256}.gateway-init"
                ))
            || value.artifact_sha256 != sha256
            || value.artifact_size != size
            || value.execution_policy_sha256.is_some()
        {
            return Err(Error::ExecutableMismatch);
        }
        // This is only the inert, immutable test image's staging declaration.
        // The fixed query and native process checks still verify actual bytes;
        // no production staging or placement authority is minted here.
        Ok(value)
    }
}
