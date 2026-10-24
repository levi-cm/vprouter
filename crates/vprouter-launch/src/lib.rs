#![deny(unsafe_code)]
//! Descriptor-backed admission only. No namespace entry, mutation or execution.
mod evidence;
#[allow(dead_code)]
mod execution;
#[cfg(test)]
pub mod execution_lab;
#[allow(dead_code)]
mod inventory;
#[allow(unsafe_code, dead_code)]
mod kernel;
#[cfg(test)]
pub mod lab;
#[allow(dead_code)]
mod owned;
#[cfg(test)]
pub mod probe;
mod process;
mod spec;
#[cfg(test)]
mod tests;

use serde::Serialize;
pub use spec::{LaunchSpec, StagingEvidence};
use std::path::Path;
use vprouter_linux::docker::DockerClient;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidSpec,
    AllocationMismatch,
    UnsafeInput,
    UnsupportedPlatform,
    DockerUnavailable,
    ContainerMismatch,
    ImageMismatch,
    UnsupportedConfiguration,
    ProcessUnavailable,
    ProcessChanged,
    UnsupportedUserNamespace,
    NamespaceMismatch,
    RootMismatch,
    CgroupMismatch,
    ExecutableMismatch,
    TooLarge,
    NotSingleThreaded,
    LabRequired,
    LaunchUnavailable,
    OwnershipMismatch,
    LockBusy,
    Interrupted,
    NamespaceOperation,
    PlacementFailed,
    MountIsolation,
    MountContainerRoot,
    MountPrivate,
    MountTmp,
    MountExecutable,
    MountExecutableClone,
    MountStateClone,
    MountExecutableBind,
    MountExecutableReadonly,
    MountState,
    MountPivot,
    MountProc,
    MountReadonly,
    DescriptorPolicy,
    DescriptorNull,
    DescriptorDuplicate,
    DescriptorClose,
    DescriptorFlags,
    DescriptorStdio,
    DescriptorHealth,
    DescriptorExecutable,
    DescriptorInventory,
    DescriptorReadlink,
    DescriptorScanOpen,
    DescriptorScanDenied,
    DescriptorScanCount,
    CapabilityPolicy,
    ConfinementPolicy,
    ChildFailed,
    Deadline,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Stable enum-only redaction: never include external error payloads.
        let encoded = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        f.write_str(encoded.trim_matches('"'))
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

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
