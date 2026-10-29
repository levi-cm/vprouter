#![deny(unsafe_code)]
//! Public descriptor-backed admission refuses activation. Private staged paths
//! bind fixed probe and actual observation-only programs to retained authority.
#[allow(dead_code)]
mod actual;
#[cfg(test)]
pub mod actual_lab;
#[allow(dead_code)]
mod attachment;
#[allow(dead_code)]
mod daemon;
#[allow(dead_code)]
mod enrollment;
mod evidence;
#[allow(dead_code)]
mod execution;
#[cfg(test)]
pub mod execution_lab;
#[allow(dead_code)]
mod expiry;
#[allow(dead_code)]
mod handoff;
#[allow(dead_code)]
mod inspection;
#[allow(dead_code)]
mod inventory;
#[allow(unsafe_code, dead_code)]
mod kernel;
#[allow(unsafe_code, dead_code)]
mod kernel_base;
#[cfg(test)]
pub mod lab;
#[allow(dead_code)]
mod owned;
#[allow(dead_code)]
mod owner;
#[cfg(test)]
pub mod probe;
mod process;
#[allow(dead_code)]
mod producer;
#[allow(dead_code)]
mod programs;
#[allow(dead_code)]
mod publisher;
#[allow(dead_code)]
mod secret;
mod spec;
#[allow(dead_code)]
mod supervision;
#[cfg(test)]
mod tests;
#[allow(dead_code)]
mod transport;
#[cfg(test)]
pub mod transport_lab;

mod error;
pub use error::{Error, Result};
pub use spec::{LaunchSpec, StagingEvidence};
use std::path::Path;
use vprouter_linux::docker::DockerClient;

/// Non-clonable evidence. Handles are private, close-on-exec and intentionally
/// have no Debug, Serialize, raw-FD getter or caller-assertion constructor.
/// This does NOT authorize selected-exit placement or execution.
pub struct Admission {
    process: process::PinnedProcess,
    spec: LaunchSpec,
    staging: StagingEvidence,
    daemon_security: evidence::DaemonSecurity,
}
impl Admission {
    pub async fn inspect(spec_path: &Path, staging_path: &Path) -> Result<Self> {
        let (spec, staging) = load(spec_path, staging_path)?;
        Self::inspect_evidence(spec, staging).await
    }
    async fn inspect_evidence(spec: LaunchSpec, staging: StagingEvidence) -> Result<Self> {
        process::host_preflight()?;
        spec.bind_staging(&staging)?;
        process::single_threaded()?;
        let docker = DockerClient::default();
        let daemon = docker
            .launch_daemon()
            .await
            .map_err(|_| Error::DockerUnavailable)?;
        let daemon_security = evidence::daemon(&daemon)?;
        let image = docker
            .launch_image(&staging.content_id)
            .await
            .map_err(|_| Error::DockerUnavailable)?;
        evidence::image(&spec, &staging, &image)?;
        let container = docker
            .launch_container(&spec.container_id)
            .await
            .map_err(|_| Error::DockerUnavailable)?;
        evidence::container(&spec, &staging, &container)?;
        daemon_security.bind_container(&container)?;
        let process = process::PinnedProcess::open(&spec, &staging, &container)?;
        let admitted = Self {
            process,
            spec,
            staging,
            daemon_security,
        };
        admitted.revalidate().await?;
        Ok(admitted)
    }
    /// Bounded check future executor MUST perform immediately before placement.
    /// Revalidate again after placement in task6b; this cannot prevent later death.
    pub async fn revalidate(&self) -> Result<()> {
        process::single_threaded()?;
        self.process.revalidate(&self.spec, &self.staging)?;
        let docker = DockerClient::default();
        let daemon = docker
            .launch_daemon()
            .await
            .map_err(|_| Error::DockerUnavailable)?;
        if evidence::daemon(&daemon)? != self.daemon_security {
            return Err(Error::UnsupportedConfiguration);
        }

        let container = docker
            .launch_container(&self.spec.container_id)
            .await
            .map_err(|_| Error::DockerUnavailable)?;
        evidence::container(&self.spec, &self.staging, &container)?;
        self.daemon_security.bind_container(&container)?;
        self.process.bind_container(&container)?;
        self.process.revalidate(&self.spec, &self.staging)
    }
    pub fn launch(&self) -> Result<()> {
        Err(Error::LaunchUnavailable)
    }
}
/// Read a public launch manifest from protected root-owned files only. Neither
/// parser follows a profile/state path or performs a kernel/network mutation.
pub fn load(spec: &Path, staging: &Path) -> Result<(LaunchSpec, StagingEvidence)> {
    Ok((LaunchSpec::load(spec)?, StagingEvidence::load(staging)?))
}

/// Fixed immutable-image PID1. This is only an inert namespace holder; it cannot
/// place a worker, start Tailscale, remove quarantine or authorize production.
pub fn gateway_init() -> Result<()> {
    kernel_base::gateway_init()
}
