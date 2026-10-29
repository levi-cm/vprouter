#![forbid(unsafe_code)]
//! Fixed host cache writer. Its private inherited IPC accepts data only from the
//! guard; worker sockets/paths are never exposed to this process.
use super::{Error, Result, kernel, owned};
use rustix::{
    fs::{self, FileType, Mode, OFlags},
    net::{self, RecvFlags, SendFlags},
};
use std::{io::Write, os::fd::AsFd};
use vprouter_core::health::{Binding, MAX_BYTES, Snapshot, boot_seconds};

#[derive(Default)]
struct Pending {
    value: Option<(u64, f64)>,
    failed: bool,
    original_expiry: Option<f64>,
}
impl Pending {
    fn begin(&mut self, sequence: u64, now: f64) -> Result<()> {
        self.check(now)?;
        if sequence == 0 || self.value.is_some() {
            return Err(Error::Interrupted);
        }
        self.value = Some((sequence, now));
        Ok(())
    }
    fn limit(&mut self, expiry: f64) -> Result<()> {
        if !expiry.is_finite() {
            self.failed = true;
            return Err(Error::Deadline);
        }
        self.original_expiry = Some(expiry);
        self.check(boot_seconds())
    }
    fn check(&mut self, now: f64) -> Result<()> {
        if self.failed
            || !now.is_finite()
            || now < 0.
            || self.original_expiry.is_some_and(|end| now >= end)
            || self.value.is_some_and(|(_, at)| now < at || now - at >= 2.)
        {
            self.failed = true;
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn ack(&mut self, sequence: u64, now: f64) -> Result<()> {
        self.check(now)?;
        if self.value.is_none_or(|(expected, _)| sequence != expected) {
            self.failed = true;
            return Err(Error::DescriptorPolicy);
        }
        self.value = None;
        self.original_expiry = None;
        Ok(())
    }
}
/// The host guard owns this channel. No public constructor or worker IPC path.
/// submit/poll never block on writer IO; one outstanding packet bounds memory.
/// Runtime must quarantine on any error, and only ACK health after poll succeeds.
pub(super) struct Publisher {
    child: kernel::Child,
    directory: owned::Identity,
    binding: Binding,
    pending: Pending,
}
fn publication_authority(
    snapshot: &Snapshot,
    proof: Option<&super::transport::ReadyPublication>,
) -> Result<()> {
    if snapshot.state == vprouter_core::state::HealthState::Ready {
        proof.ok_or(Error::DescriptorPolicy)?.check(snapshot)?;
    } else if proof.is_some() {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
impl Publisher {
    pub fn spawn(binding: Binding) -> Result<Self> {
        super::process::publisher_preflight()?;
        let dir = owned::directory(&binding.host_directory().map_err(|_| Error::InvalidSpec)?)?;
        let directory = owned::Identity::of(&dir)?;
        let child = kernel::spawn_publisher(&dir, &binding)?;
        Ok(Self {
            child,
            directory,
            binding,
            pending: Pending::default(),
        })
    }
    fn verify(&self) -> Result<()> {
        self.child.require_live()?;
        if owned::Identity::of(owned::directory(
            &self
                .binding
                .host_directory()
                .map_err(|_| Error::InvalidSpec)?,
        )?)? != self.directory
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub fn submit(&mut self, snapshot: &Snapshot) -> Result<()> {
        publication_authority(snapshot, None)?;
        self.submit_inner(snapshot, boot_seconds() + 2.)
    }
    pub fn submit_ready(
        &mut self,
        snapshot: &Snapshot,
        proof: &super::transport::ReadyPublication,
    ) -> Result<()> {
        publication_authority(snapshot, Some(proof))?;
        self.submit_inner(snapshot, proof.expires_at())?;
        proof.check(snapshot)
    }
    fn submit_inner(&mut self, snapshot: &Snapshot, expires_at: f64) -> Result<()> {
        self.verify()?;
        snapshot
            .validate(&self.binding, boot_seconds())
            .map_err(|_| Error::DescriptorPolicy)?;
        let snapshot_bytes = serde_json::to_vec(snapshot).map_err(|_| Error::DescriptorPolicy)?;
        let mut bytes = expires_at.to_be_bytes().to_vec();
        bytes.extend_from_slice(&snapshot_bytes);
        if bytes.len() > MAX_BYTES + 8 {
            return Err(Error::TooLarge);
        }
        self.pending.begin(snapshot.sequence, boot_seconds())?;
        self.pending.limit(expires_at)?;
        match net::send(
            self.child.publisher_socket()?,
            &bytes,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        ) {
            Ok(n) if n == bytes.len() => Ok(()),
            _ => {
                self.pending.failed = true;
                Err(Error::DescriptorPolicy)
            }
        }
    }
    pub fn poll(&mut self) -> Result<Option<u64>> {
        self.verify()?;
        self.pending.check(boot_seconds())?;
        let mut bytes = [0; 9];
        match net::recv(
            self.child.publisher_socket()?,
            &mut bytes,
            RecvFlags::DONTWAIT,
        ) {
            Err(rustix::io::Errno::AGAIN) => Ok(None),
            Ok((8, 8)) => {
                let sequence =
                    u64::from_be_bytes(bytes[..8].try_into().map_err(|_| Error::DescriptorPolicy)?);
                self.verify()?;
                self.pending.ack(sequence, boot_seconds())?;
                Ok(Some(sequence))
            }
            _ => {
                self.pending.failed = true;
                Err(Error::DescriptorPolicy)
            }
        }
    }
    #[cfg(test)]
    pub fn lab_pid(&self) -> u32 {
        self.child.pid()
    }
    #[cfg(test)]
    pub fn lab_freeze(&self) -> Result<()> {
        self.child.signal(libc::SIGSTOP)
    }
    pub fn stop(self) -> Result<()> {
        self.child.terminate()
    }
}
/// Runs only in the fixed confined child after namespace/root/FD/capability setup.
pub(super) fn run_child(directory: impl AsFd, socket: impl AsFd, binding: &Binding) -> Result<()> {
    let mut sequence = 0;
    let mut bytes = vec![0; MAX_BYTES + 9];
    loop {
        let (n, full) = net::recv(&socket, &mut bytes, RecvFlags::TRUNC)
            .map_err(|_| Error::DescriptorPolicy)?;
        if n != full || n <= 8 || n > MAX_BYTES + 8 {
            return Err(Error::TooLarge);
        }
        let expires_at =
            f64::from_be_bytes(bytes[..8].try_into().map_err(|_| Error::DescriptorPolicy)?);
        publication_time(expires_at)?;
        let snapshot = Snapshot::decode(&bytes[8..n]).map_err(|_| Error::DescriptorPolicy)?;
        snapshot
            .validate(binding, boot_seconds())
            .map_err(|_| Error::DescriptorPolicy)?;
        if snapshot.sequence <= sequence {
            return Err(Error::DescriptorPolicy);
        }
        write_cache(&directory, 0, &bytes[8..n], expires_at)?;
        publication_time(expires_at)?;
        sequence = snapshot.sequence;
        if net::send(&socket, &sequence.to_be_bytes(), SendFlags::NOSIGNAL)
            .map_err(|_| Error::DescriptorPolicy)?
            != 8
        {
            return Err(Error::DescriptorPolicy);
        }
        publication_time(expires_at)?;
    }
}
fn publication_time(expires_at: f64) -> Result<()> {
    let now = boot_seconds();
    if !expires_at.is_finite() || !now.is_finite() || now >= expires_at || expires_at - now > 2. {
        return Err(Error::Deadline);
    }
    Ok(())
}
fn write_cache(directory: impl AsFd, uid: u32, bytes: &[u8], expires_at: f64) -> Result<()> {
    publication_time(expires_at)?;
    let stat = fs::fstat(&directory).map_err(|_| Error::OwnershipMismatch)?;
    if stat.st_uid != uid
        || stat.st_mode & 0o7777 != 0o700
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
    {
        return Err(Error::OwnershipMismatch);
    }
    match fs::statat(&directory, "health.json", fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(s)
            if s.st_uid == uid
                && s.st_mode & 0o7777 == 0o600
                && s.st_nlink == 1
                && FileType::from_raw_mode(s.st_mode) == FileType::RegularFile => {}
        Err(rustix::io::Errno::NOENT) => (),
        _ => return Err(Error::OwnershipMismatch),
    }
    let fd = fs::openat(
        &directory,
        ".health.pending",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| Error::Interrupted)?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes).map_err(|_| Error::Interrupted)?;
    fs::fsync(&file).map_err(|_| Error::Interrupted)?;
    publication_time(expires_at)?;
    fs::renameat(&directory, ".health.pending", &directory, "health.json")
        .map_err(|_| Error::Interrupted)?;
    fs::fsync(&directory).map_err(|_| Error::Interrupted)?;
    publication_time(expires_at)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn atomic_host_publication_refuses_substituted_cache_and_interrupted_temp() {
        let path = std::env::temp_dir().join(format!("vpr-publisher-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = rustix::fs::open(
            &path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let uid = rustix::fs::fstat(&dir).unwrap().st_uid;
        write_cache(&dir, uid, b"first", boot_seconds() + 2.).unwrap();
        write_cache(&dir, uid, b"second", boot_seconds() + 2.).unwrap();
        assert_eq!(std::fs::read(path.join("health.json")).unwrap(), b"second");
        assert_eq!(
            std::fs::metadata(path.join("health.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::write(path.join(".health.pending"), b"retained-interruption").unwrap();
        assert!(write_cache(&dir, uid, b"third", boot_seconds() + 2.).is_err());
        assert_eq!(std::fs::read(path.join("health.json")).unwrap(), b"second");
        assert_eq!(
            std::fs::read(path.join(".health.pending")).unwrap(),
            b"retained-interruption"
        );
        std::fs::remove_file(path.join(".health.pending")).unwrap();
        std::fs::remove_file(path.join("health.json")).unwrap();
        symlink("foreign", path.join("health.json")).unwrap();
        assert!(write_cache(&dir, uid, b"third", boot_seconds() + 2.).is_err());
        assert!(!path.join("foreign").exists());
        std::fs::remove_file(path.join("health.json")).unwrap();
        std::fs::remove_dir(path).unwrap();
    }
    #[test]
    fn valid_ready_snapshot_alone_cannot_authorize_cache_publication() {
        use vprouter_core::{
            config::ExitMode,
            state::{Evidence, HealthMachine, VerificationResult},
        };
        let binding = Binding {
            deployment_id: "test".into(),
            exit_id: "one".into(),
            mode: ExitMode::Mullvad,
            generation: 1,
            display_name: "test-exit".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "node".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        };
        let mut machine =
            HealthMachine::new(ExitMode::Mullvad, Some("de-fra-wg-404"), "node").unwrap();
        for now in [10., 11., 12., 13.] {
            machine
                .observe(
                    now,
                    Evidence {
                        provider_ok: true,
                        structural_ok: true,
                        provider_at: now,
                        structural_at: now,
                        heartbeat_at: now,
                        handshake_age_seconds: Some(1.),
                        online: true,
                        policy_approved: true,
                        server: Some("de-fra-wg-404".into()),
                        node_id: Some("node".into()),
                        egress: Some("1.2.3.4".parse().unwrap()),
                        verified_at: Some(now),
                        dns: VerificationResult::NotTested,
                        ipv6: VerificationResult::NotTested,
                    },
                )
                .unwrap();
        }
        let snapshot = Snapshot::from_machine(binding.clone(), 4, 13., &machine).unwrap();
        snapshot.validate(&binding, 13.).unwrap();
        assert_eq!(
            publication_authority(&snapshot, None),
            Err(Error::DescriptorPolicy)
        );
        machine.block(vprouter_core::reason::Reason::ProviderFailure);
        let blocked = Snapshot::from_machine(binding, 5, 14., &machine).unwrap();
        publication_authority(&blocked, None).unwrap();
    }
    #[test]
    fn original_host_expiry_does_not_refresh_when_publication_starts_later() {
        let mut pending = Pending::default();
        pending.begin(7, 101.5).unwrap();
        pending.original_expiry = Some(102.);
        assert!(pending.check(101.9).is_ok());
        assert!(pending.ack(7, 102.).is_err());
        assert!(pending.ack(7, 101.9).is_err());
    }
    #[test]
    fn pending_publication_cannot_queue_more_or_accept_stale_ack() {
        let mut pending = Pending::default();
        pending.begin(7, 100.).unwrap();
        assert!(pending.begin(8, 101.).is_err());
        assert!(pending.ack(6, 101.).is_err());
        assert!(pending.begin(8, 101.).is_err());
        let mut pending = Pending::default();
        pending.begin(7, 100.).unwrap();
        pending.ack(7, 101.).unwrap();
        pending.begin(8, 101.).unwrap();
        assert!(pending.check(103.).is_err());
        assert!(pending.ack(8, 102.).is_err());
    }
}
