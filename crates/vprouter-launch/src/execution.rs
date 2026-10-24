#![forbid(unsafe_code)]
//! Private execution policy. There is deliberately no production constructor.
use super::{Admission, Error, Result, kernel, owned, process};
use rustix::fs::{self, Mode, OFlags};
use std::{
    os::fd::{AsFd, OwnedFd},
    path::Path,
};
pub(super) const POLICY: &str = "vprouter-static-probe-v1;uid=65534;gid=65534;caps=0;lsm=docker-default;seccomp=probe-v1;resolver=192.0.2.53;env=LANG=C,PATH=/bin;argv=vprouter-worker,--isolated-probe";
pub(super) struct VerifiedProgram {
    digest: String,
    policy_digest: String,
}
impl VerifiedProgram {
    #[cfg(test)]
    pub fn probe(a: &Admission) -> Result<Self> {
        Self::probe_stage(&a.staging)
    }
    #[cfg(test)]
    fn probe_stage(stage: &super::StagingEvidence) -> Result<Self> {
        if stage.artifact_kind != "synthetic_static_probe_v1" {
            return Err(Error::ExecutableMismatch);
        }
        if stage.execution_policy_sha256.as_deref() != Some(&kernel::policy_digest()) {
            return Err(Error::ConfinementPolicy);
        }
        Ok(Self {
            digest: stage.artifact_sha256.clone(),
            policy_digest: kernel::policy_digest(),
        })
    }
    fn bind(&self, a: &Admission) -> Result<()> {
        if self.digest != a.staging.artifact_sha256
            || self.policy_digest != kernel::policy_digest()
            || a.staging.execution_policy_sha256.as_deref() != Some(&self.policy_digest)
        {
            return Err(Error::ConfinementPolicy);
        }
        Ok(())
    }
}
pub(super) struct Running {
    child: kernel::Child,
}
impl Running {
    pub fn pid(&self) -> u32 {
        self.child.pid()
    }
    pub fn terminate(self) -> Result<()> {
        self.child.terminate()
    }
    #[cfg(test)]
    pub fn signal(&self, signal: i32) -> Result<()> {
        self.child.signal(signal)
    }
}
/// Reject unexpected inherited descriptors before forking. All observed sockets
/// (including dormant async reactors) are forbidden. Child final inventory is
/// independently closed and verified before exec; stderr is /dev/null too.
fn inherited_descriptors() -> Result<()> {
    for entry in std::fs::read_dir("/proc/self/fd").map_err(|_| Error::DescriptorPolicy)? {
        let entry = entry.map_err(|_| Error::DescriptorPolicy)?;
        let name = entry.file_name();
        let Some(n) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            return Err(Error::DescriptorPolicy);
        };
        if n <= 2 {
            continue;
        }
        // read_dir's own CLOEXEC descriptor can disappear by the time queried.
        let target = match std::fs::read_link(entry.path()) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(Error::DescriptorPolicy),
        };
        if target
            .as_os_str()
            .as_encoded_bytes()
            .starts_with(b"socket:")
        {
            return Err(Error::DescriptorPolicy);
        }
        let fd = fs::open(
            format!("/proc/self/fd/{n}"),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let _ = fd;
    }
    Ok(())
}
fn state(a: &Admission) -> Result<OwnedFd> {
    // Allocation validation proves non-overlap with every peer path. Strict
    // ancestors and a private selected directory prohibit symlink selection.
    a.spec.validate()?;
    let path = &a.spec.exit.state_dir;
    if path.starts_with(Path::new("/proc"))
        || path.starts_with(Path::new("/run"))
        || path.starts_with(Path::new("/sys"))
    {
        return Err(Error::UnsafeInput);
    }
    let fd = owned::directory(path)?;
    // Refuse nested mounts: recursive bind must never smuggle a peer/host view.
    // Parse escaped mountpoints conservatively; paths needing escapes unsupported.
    let info =
        std::fs::read_to_string("/proc/self/mountinfo").map_err(|_| Error::MountIsolation)?;
    let root = path.to_str().ok_or(Error::UnsafeInput)?;
    for line in info.lines() {
        let m = line
            .split_whitespace()
            .nth(4)
            .ok_or(Error::MountIsolation)?;
        if m.contains('\\') {
            return Err(Error::MountIsolation);
        }
        if m != root && Path::new(m).starts_with(path) {
            return Err(Error::MountIsolation);
        }
    }
    let selected = fs::openat(
        &fd,
        "worker",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::UnsafeInput)?;
    let st = fs::fstat(&selected).map_err(|_| Error::UnsafeInput)?;
    if st.st_uid != 65534 || st.st_gid != 65534 || st.st_mode & 0o7777 != 0o700 {
        return Err(Error::UnsafeInput);
    }
    Ok(selected)
}
pub(super) fn launch(
    a: &Admission,
    tx: &owned::Transaction<'_>,
    ns: &owned::OwnedNamespaces,
    program: VerifiedProgram,
) -> Result<Running> {
    process::single_threaded()?;
    program.bind(a)?;
    tx.revalidate(&a.spec)?;
    // All Docker revalidation runtimes are created and dropped in this function;
    // none exists across fork or namespace entry. No caller-controlled runtime.
    revalidate(a)?;
    #[cfg(test)]
    eprintln!("LAB_EXEC_STAGE selected_state_admission");
    let state = state(a)?;
    #[cfg(test)]
    eprintln!("LAB_EXEC_STAGE descriptor_admission");
    inherited_descriptors()?;
    #[cfg(test)]
    eprintln!("LAB_EXEC_STAGE placement_gated_spawn");
    let mut child = kernel::spawn(a.process.launch_fds(), ns.data.as_fd(), state.as_fd())?;
    if a.process
        .place(child.pid(), &a.spec)
        .and_then(|()| revalidate(a))
        .and_then(|()| tx.revalidate(&a.spec))
        .and_then(|()| a.process.verify_placement(child.pid(), &a.spec))
        .is_err()
    {
        child.terminate()?;
        return Err(Error::PlacementFailed);
    }
    child.release()?;
    // PID1 readiness requires successful post-exec probe verification, not merely
    // child creation or Docker status. An error kills/reaps boundedly in Drop.
    #[cfg(test)]
    eprintln!("LAB_EXEC_STAGE post_exec_readiness");
    child.ready()?;
    a.process.verify_placement(child.pid(), &a.spec)?;
    Ok(Running { child })
}
fn revalidate(a: &Admission) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| Error::UnsupportedPlatform)?;
    let result = rt.block_on(a.revalidate());
    drop(rt);
    process::single_threaded()?;
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_policy_is_bound_to_fixed_probe_identity() {
        let (_, mut stage) = super::super::tests::fixture();
        assert!(matches!(
            VerifiedProgram::probe_stage(&stage),
            Err(Error::ConfinementPolicy)
        ));
        stage.execution_policy_sha256 = Some(kernel::policy_digest());
        assert!(VerifiedProgram::probe_stage(&stage).is_ok());
        stage.execution_policy_sha256 = Some("f".repeat(64));
        assert!(matches!(
            VerifiedProgram::probe_stage(&stage),
            Err(Error::ConfinementPolicy)
        ));
        stage.artifact_kind = "vprouter_worker_v1".into();
        assert!(matches!(
            VerifiedProgram::probe_stage(&stage),
            Err(Error::ExecutableMismatch)
        ));
    }
}
