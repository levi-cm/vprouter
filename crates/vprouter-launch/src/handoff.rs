#![forbid(unsafe_code)]
//! Host side of the one-use observation handoff. Retains the exact guard-owned
//! allocation/namespace/producer authority; a reply cannot authorize readiness.
use super::{
    Admission, Error, Result,
    owned::{self, Identity, OwnedNamespaces, Transaction},
    producer::ProducerGroup,
    programs::ReviewedBundle,
    spec::LaunchSpec,
};
use rustix::{
    event::{PollFd, PollFlags, poll},
    fs::{self, Mode, OFlags},
};
use std::{
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{fs::PermissionsExt, net::UnixListener},
    },
    path::PathBuf,
    time::{Duration, Instant},
};
use vprouter_worker::bootstrap::{self, Configuration, Object, Permission, Request, Response};

pub(super) struct Handoff<'g, 'a> {
    listener: UnixListener,
    directory: OwnedFd,
    directory_id: Identity,
    file_id: Identity,
    socket_id: Identity,
    _inventory: super::inventory::Registration,
    config: Configuration,
    config_digest: String,
    admission: &'g Admission,
    producer: &'g ProducerGroup,
    transaction: &'g Transaction<'a>,
    namespaces: &'g OwnedNamespaces,
    attempt: OneUse,
}
#[derive(Default)]
struct OneUse {
    consumed: bool,
}
impl OneUse {
    fn begin(&mut self) -> Result<()> {
        if self.consumed {
            return Err(Error::DescriptorPolicy);
        }
        // Consumed before any accept, authority check or request validation.
        self.consumed = true;
        Ok(())
    }
}
fn request_binding(request: &Request, digest: &str, nonce: &str) -> Result<()> {
    if request.schema != 1 || request.config_sha256 != digest || request.nonce != nonce {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
impl<'g, 'a> Handoff<'g, 'a> {
    /// Private constructor called only by a freshly audited GuardTransport.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        admission: &'g Admission,
        producer: &'g ProducerGroup,
        transaction: &'g Transaction<'a>,
        namespaces: &'g OwnedNamespaces,
        plan: &vprouter_network::Plan,
        resolver: std::net::Ipv4Addr,
        bundle: &ReviewedBundle,
    ) -> Result<Self> {
        super::process::single_threaded()?;
        let spec = &admission.spec;
        producer.verify(transaction, spec)?;
        namespaces.bind(spec)?;
        transaction.revalidate(spec)?;
        admission.process.revalidate(spec, &admission.staging)?;
        let parent = owned::directory(&spec.exit.state_dir)?;
        fs::mkdirat(
            &parent,
            "placement",
            Mode::RUSR
                | Mode::WUSR
                | Mode::XUSR
                | Mode::RGRP
                | Mode::XGRP
                | Mode::ROTH
                | Mode::XOTH,
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        let directory = fs::openat(
            &parent,
            "placement",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        let directory_id = Identity::of(&directory)?;
        // Descriptor-relative proc-fd path, never a caller-supplied control path.
        // Only this selected root0700 state view can mount the control directory.
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/bootstrap.sock",
            directory.as_raw_fd()
        ));
        let listener = UnixListener::bind(&path).map_err(|_| Error::DescriptorPolicy)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::DescriptorPolicy)?;
        // Socket writability does not grant directory traversal: host ancestors
        // remain root0700 and the child receives only its selected private mount.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .map_err(|_| Error::DescriptorPolicy)?;
        let socket_id = path_identity(&directory, "bootstrap.sock")?;
        let mut nonce = [0; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut nonce))
            .map_err(|_| Error::DescriptorPolicy)?;
        let config = Configuration {
            schema: 1,
            allocation: spec.allocation.clone(),
            exit: spec.exit.clone(),
            container_id: spec.container_id.clone(),
            namespace: {
                let id = Identity::network(&namespaces.data)?;
                Object {
                    dev: id.dev,
                    ino: id.ino,
                }
            },
            // New private cgroup namespace root will be selected subgroup in8b2;
            // this is an additional local predicate, never host producer proof.
            cgroup: "0::/\n".into(),
            program_sha256: bundle.worker_digest()?.to_owned(),
            manifest_sha256: bundle.digest().to_owned(),
            socket: Object {
                dev: socket_id.dev,
                ino: socket_id.ino,
            },
            nonce: bootstrap::digest(&nonce),
            resolver,
            monitoring: plan.monitoring(),
        };
        config.validate().map_err(|_| Error::DescriptorPolicy)?;
        let bytes = serde_json::to_vec(&config).map_err(|_| Error::DescriptorPolicy)?;
        if bytes.len() > bootstrap::LIMIT {
            return Err(Error::TooLarge);
        }
        let file = fs::openat(
            &directory,
            "bootstrap.json",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        std::fs::File::from(file.try_clone().map_err(|_| Error::DescriptorPolicy)?)
            .write_all(&bytes)
            .map_err(|_| Error::DescriptorPolicy)?;
        fs::fchmod(&file, Mode::RUSR | Mode::RGRP | Mode::ROTH)
            .map_err(|_| Error::DescriptorPolicy)?;
        fs::fsync(&file)
            .and_then(|()| fs::fsync(&directory))
            .map_err(|_| Error::DescriptorPolicy)?;
        fs::fchmod(&directory, Mode::from_raw_mode(0o755)).map_err(|_| Error::DescriptorPolicy)?;
        let file_id = Identity::of(file)?;
        let inventory =
            super::inventory::Registration::owned(&[directory.as_fd(), listener.as_fd()])?;
        Ok(Self {
            listener,
            directory,
            directory_id,
            file_id,
            socket_id,
            _inventory: inventory,
            config_digest: bootstrap::digest(&bytes),
            config,
            admission,
            producer,
            transaction,
            namespaces,
            attempt: OneUse::default(),
        })
    }
    fn spec(&self) -> &LaunchSpec {
        &self.admission.spec
    }
    fn verify(&self) -> Result<()> {
        let parent = owned::directory(&self.spec().exit.state_dir)?;
        if path_identity(&parent, "placement")? != self.directory_id {
            return Err(Error::OwnershipMismatch);
        }
        let file = fs::openat(
            &self.directory,
            "bootstrap.json",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::OwnershipMismatch)?;
        let stat = fs::fstat(&file).map_err(|_| Error::OwnershipMismatch)?;
        if stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_mode & 0o7777 != 0o444
            || stat.st_nlink != 1
            || stat.st_size <= 0
            || stat.st_size as usize > bootstrap::LIMIT
        {
            return Err(Error::OwnershipMismatch);
        }
        let mut bytes = Vec::new();
        std::fs::File::from(file)
            .take(bootstrap::LIMIT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::OwnershipMismatch)?;
        if bootstrap::digest(&bytes) != self.config_digest {
            return Err(Error::OwnershipMismatch);
        }
        self.transaction.revalidate(self.spec())?;
        self.namespaces.bind(self.spec())?;
        self.producer.verify(self.transaction, self.spec())?;
        self.admission
            .process
            .revalidate(self.spec(), &self.admission.staging)?;
        if Identity::of(&self.directory)? != self.directory_id
            || path_identity(&self.directory, "bootstrap.json")? != self.file_id
            || path_identity(&self.directory, "bootstrap.sock")? != self.socket_id
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    /// Start only the fixed pinned daemon in the already admitted producer.
    /// The locked identity-free config cannot advertise or enroll.
    pub fn launch_daemon(&self, bundle: &ReviewedBundle) -> Result<super::kernel::Child> {
        self.verify()?;
        super::actual::launch(
            self.admission,
            self.transaction,
            self.namespaces,
            self.producer,
            bundle,
            super::kernel::ActualRole::Daemon,
            self.config.resolver,
            None,
        )
    }
    pub fn pin_daemon(
        &self,
        bundle: &ReviewedBundle,
        child: &super::kernel::Child,
        pid: u32,
    ) -> Result<super::daemon::LiveDaemon<'g, 'a>> {
        self.verify()?;
        super::daemon::LiveDaemon::pin(
            self.admission,
            self.transaction,
            self.namespaces,
            self.producer,
            bundle,
            child,
            pid,
            &self.config_digest,
        )
    }
    pub fn verify_daemon(
        &self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_, '_>,
    ) -> Result<()> {
        if let Err(error) = self.verify() {
            daemon.revoke();
            return Err(error);
        }
        daemon.verify(bundle, &self.config_digest)
    }
    pub fn launch_observer(&self, bundle: &ReviewedBundle) -> Result<super::kernel::Child> {
        self.verify()?;
        super::actual::launch(
            self.admission,
            self.transaction,
            self.namespaces,
            self.producer,
            bundle,
            super::kernel::ActualRole::Observer,
            self.config.resolver,
            Some(self.directory.as_fd()),
        )
    }
    /// Exact current accept peer is checked through host proc/pidfd and retained
    /// producer membership. Translation of worker-side PID0/cgroup'/' is irrelevant.
    pub fn serve_once(&mut self, bundle: &ReviewedBundle) -> Result<u32> {
        // Consume BEFORE accepting: malformed/unauthorized attempts never enable
        // another try with the same nonce/config. Failure stays quarantined.
        self.attempt.begin()?;
        self.verify()?;
        let end = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match self.listener.accept() {
                Ok(v) => break v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let left = end.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(Error::Deadline);
                    }
                    let mut p = [PollFd::new(&self.listener, PollFlags::IN)];
                    poll(
                        &mut p,
                        Some(
                            &rustix::event::Timespec::try_from(left)
                                .map_err(|_| Error::Deadline)?,
                        ),
                    )
                    .map_err(|_| Error::Deadline)?;
                }
                Err(_) => return Err(Error::DescriptorPolicy),
            }
        };
        stream
            .set_read_timeout(Some(
                end.saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(1)),
            ))
            .map_err(|_| Error::DescriptorPolicy)?;
        stream
            .set_write_timeout(Some(Duration::from_millis(100)))
            .map_err(|_| Error::DescriptorPolicy)?;
        let peer =
            rustix::net::sockopt::socket_peercred(&stream).map_err(|_| Error::DescriptorPolicy)?;
        if peer.uid.as_raw() != bootstrap::WORKER_UID || peer.gid.as_raw() != bootstrap::WORKER_UID
        {
            return Err(Error::DescriptorPolicy);
        }
        let pid = peer.pid.as_raw_pid() as u32;
        let sender = self.producer.pin_sender(
            pid,
            self.transaction,
            self.spec(),
            self.namespaces,
            bundle,
        )?;
        let request: Request = bootstrap::read_message_before(&mut stream, end)
            .map_err(|_| Error::DescriptorPolicy)?;
        request_binding(&request, &self.config_digest, &self.config.nonce)?;
        self.verify()?;
        sender.verify(
            self.producer,
            self.transaction,
            self.spec(),
            self.namespaces,
            bundle,
        )?;
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        bootstrap::write_message(
            &mut stream,
            &Response {
                schema: 1,
                config_sha256: self.config_digest.clone(),
                nonce: self.config.nonce.clone(),
                permission: Permission::ObserveOnce,
            },
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        Ok(pid)
    }
    /// Explicit ownership cleanup; never remove a substituted file/socket/dir.
    /// On ambiguity return error and retain the private state/quarantine.
    pub fn cleanup(self) -> Result<()> {
        self.verify()?;
        fs::unlinkat(&self.directory, "bootstrap.json", fs::AtFlags::empty())
            .map_err(|_| Error::OwnershipMismatch)?;
        fs::unlinkat(&self.directory, "bootstrap.sock", fs::AtFlags::empty())
            .map_err(|_| Error::OwnershipMismatch)?;
        let parent = owned::directory(&self.spec().exit.state_dir)?;
        if path_identity(&parent, "placement")? != self.directory_id {
            return Err(Error::OwnershipMismatch);
        }
        fs::unlinkat(parent, "placement", fs::AtFlags::REMOVEDIR)
            .map_err(|_| Error::OwnershipMismatch)
    }
}
fn path_identity(dir: impl AsFd, name: &str) -> Result<Identity> {
    let s = fs::statat(dir, name, fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| Error::OwnershipMismatch)?;
    Ok(Identity {
        dev: s.st_dev,
        ino: s.st_ino,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request(digest: &str, nonce: &str) -> Request {
        Request {
            schema: 1,
            config_sha256: digest.into(),
            nonce: nonce.into(),
        }
    }
    fn submit(gate: &mut OneUse, request: &Request) -> Result<()> {
        gate.begin()?;
        request_binding(request, "current-digest", "current-nonce")
    }
    #[test]
    fn one_use_consumes_success_and_authority_failure_before_validation() {
        let valid = request("current-digest", "current-nonce");
        let mut gate = OneUse::default();
        submit(&mut gate, &valid).unwrap();
        assert_eq!(submit(&mut gate, &valid), Err(Error::DescriptorPolicy));
        let mut failed_authority = OneUse::default();
        failed_authority.begin().unwrap();
        // The production authority/accept path may fail before any request;
        // nothing can restore Fresh or allow a second attempt afterward.
        assert_eq!(failed_authority.begin(), Err(Error::DescriptorPolicy));
    }
    #[test]
    fn wrong_digest_nonce_and_schema_consume_attempt_and_refuse_replay() {
        let valid = request("current-digest", "current-nonce");
        let mut wrong_schema = request("current-digest", "current-nonce");
        wrong_schema.schema = 2;
        for wrong in [
            request("stale-digest", "current-nonce"),
            request("current-digest", "stale-nonce"),
            request("stale-digest", "stale-nonce"),
            wrong_schema,
        ] {
            let mut gate = OneUse::default();
            assert_eq!(submit(&mut gate, &wrong), Err(Error::DescriptorPolicy));
            assert_eq!(submit(&mut gate, &valid), Err(Error::DescriptorPolicy));
        }
    }
}
