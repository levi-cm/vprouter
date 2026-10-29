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

#[cfg(test)]
pub(super) mod lab_profile {
    use std::{cell::RefCell, time::Instant};
    struct Active {
        creator: u32,
        end: Instant,
        emitted: usize,
        omitted: usize,
    }
    thread_local! { static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) }; }
    pub(super) struct Scope(u32);
    impl Scope {
        pub(super) fn new(end: Instant) -> Self {
            let creator = std::process::id();
            ACTIVE.with(|active| {
                *active.borrow_mut() = Some(Active {
                    creator,
                    end,
                    emitted: 0,
                    omitted: 0,
                });
            });
            Self(creator)
        }
    }
    impl Drop for Scope {
        fn drop(&mut self) {
            if self.0 != std::process::id() {
                return;
            }
            if let Some(active) = ACTIVE.with(|slot| slot.borrow_mut().take()) {
                eprintln!(
                    "LAB_HANDOFF_PROFILE phase=summary events={} omitted={} original_remaining_us={}",
                    active.emitted,
                    active.omitted,
                    active
                        .end
                        .saturating_duration_since(Instant::now())
                        .as_micros()
                );
            }
        }
    }
    pub(crate) struct Span {
        started: Option<Instant>,
        creator: u32,
        label: &'static str,
        sequence: u64,
        ok: bool,
    }
    impl Span {
        pub(crate) fn new(label: &'static str, sequence: u64) -> Self {
            let creator = std::process::id();
            let started = ACTIVE.with(|slot| {
                slot.borrow()
                    .as_ref()
                    .filter(|active| active.creator == creator)
                    .map(|_| Instant::now())
            });
            Self {
                started,
                creator,
                label,
                sequence,
                ok: false,
            }
        }
        pub(crate) fn success(mut self) {
            self.ok = true;
        }
    }
    impl Drop for Span {
        fn drop(&mut self) {
            let Some(started) = self.started else {
                return;
            };
            if self.creator != std::process::id() {
                return;
            }
            ACTIVE.with(|slot| {
                let mut slot = slot.borrow_mut();
                let Some(active) = slot.as_mut().filter(|active| active.creator == self.creator) else { return; };
                // Reserve the last of64 events for the scope summary. Never
                // reset this shared cap for an individual RPC or subphase.
                if active.emitted >= 63 { active.omitted += 1; return; }
                active.emitted += 1;
                eprintln!("LAB_HANDOFF_PROFILE phase={} sequence={} elapsed_us={} ok={} original_remaining_us={}",
                    self.label, self.sequence, started.elapsed().as_micros().min(600_000_000), self.ok,
                    active.end.saturating_duration_since(Instant::now()).as_micros());
            });
        }
    }
}

pub(super) struct Handoff<'g> {
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
    transaction: &'g Transaction,
    namespaces: &'g OwnedNamespaces,
    attempt: OneUse,
    worker_launched: bool,
    enrollment: Option<super::enrollment::AuthorizedEnrollment>,
    executors: Option<super::expiry::Executors>,
    audit: super::transport::ObservationAudit<'g>,
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
// The original publication end must travel through reads and the final ACK,
// including after Commit consumes its pending state.
fn operational_deadline(frame_end: Instant, publication_end: Option<Instant>) -> Instant {
    publication_end.map_or(frame_end, |end| end.min(frame_end))
}
fn operational_check(end: Instant) -> Result<()> {
    if Instant::now() >= end {
        Err(Error::Deadline)
    } else {
        Ok(())
    }
}
fn operational_read(
    stream: &mut std::os::unix::net::UnixStream,
    publication_end: Option<Instant>,
) -> Result<vprouter_worker::operation::Request> {
    bootstrap::read_message_before(
        stream,
        operational_deadline(Instant::now() + Duration::from_secs(2), publication_end),
    )
    .map_err(|_| Error::Deadline)
}
fn operational_reply<T: serde::Serialize>(
    stream: &mut std::os::unix::net::UnixStream,
    reply: &T,
    frame_end: Instant,
    publication_end: Option<Instant>,
    verify: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let end = operational_deadline(frame_end, publication_end);
    operational_check(end)?;
    verify()?;
    operational_check(end)?;
    bootstrap::write_message_before(stream, reply, end).map_err(|_| Error::Deadline)?;
    operational_check(end)
}
// The first response has exactly the original accepted-frame deadline. A
// syntactically valid request never skips the complete fresh authority verifier.
fn initial_reply(
    stream: &mut std::os::unix::net::UnixStream,
    request: &Request,
    digest: &str,
    nonce: &str,
    end: Instant,
    verify: impl FnOnce() -> Result<Permission>,
) -> Result<()> {
    request_binding(request, digest, nonce)?;
    operational_check(end)?;
    #[cfg(test)]
    let started = Instant::now();
    let permission = verify();
    #[cfg(test)]
    eprintln!(
        "LAB_HANDOFF_PHASE phase=full_permission_verification milliseconds={} original_remaining_ms={} verification_ok={}",
        started.elapsed().as_millis().min(600000),
        end.saturating_duration_since(Instant::now()).as_millis(),
        permission.is_ok()
    );
    let permission = permission?;
    operational_check(end)?;
    bootstrap::write_message_before(
        stream,
        &Response {
            schema: 1,
            config_sha256: digest.into(),
            nonce: nonce.into(),
            permission,
        },
        end,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    operational_check(end)
}
impl<'g> Handoff<'g> {
    /// Private constructor called only by a freshly audited GuardTransport.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        admission: &'g Admission,
        producer: &'g ProducerGroup,
        transaction: &'g Transaction,
        namespaces: &'g OwnedNamespaces,
        plan: &vprouter_network::Plan,
        resolver: std::net::Ipv4Addr,
        bundle: &ReviewedBundle,
        audit: super::transport::ObservationAudit<'g>,
        health_binding: Option<vprouter_core::health::Binding>,
        enrollment: Option<super::enrollment::AuthorizedEnrollment>,
    ) -> Result<Self> {
        super::process::single_threaded()?;
        let spec = &admission.spec;
        producer.verify(transaction, spec)?;
        namespaces.bind(spec)?;
        transaction.revalidate(spec)?;
        transaction.inspect_container(admission)?;
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
            program_sha256: if health_binding.is_some() {
                bundle.monitor_digest()?
            } else {
                bundle.worker_digest()?
            }
            .to_owned(),
            manifest_sha256: bundle.digest().to_owned(),
            socket: Object {
                dev: socket_id.dev,
                ino: socket_id.ino,
            },
            nonce: bootstrap::digest(&nonce),
            resolver,
            execution_policy: if enrollment.is_some() {
                "operational-monitor-ipv4-tcp-udp-unix-zero-caps-v1"
            } else if health_binding.is_some() {
                "starting-monitor-unix-netlink-zero-caps-v1"
            } else {
                "observer-unix-netlink-zero-caps-v1"
            }
            .into(),
            monitoring: plan.monitoring(),
            health_binding,
            enrollment: enrollment.as_ref().map(|e| e.value().clone()),
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
            worker_launched: false,
            enrollment,
            executors: None,
            audit,
        })
    }
    fn spec(&self) -> &LaunchSpec {
        &self.admission.spec
    }
    fn verify_placement(&self) -> Result<()> {
        if let Some(enrollment) = &self.enrollment {
            enrollment.verify(self.spec())?;
        }
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
        if Identity::of(&self.directory)? != self.directory_id
            || path_identity(&self.directory, "bootstrap.json")? != self.file_id
            || path_identity(&self.directory, "bootstrap.sock")? != self.socket_id
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    fn verify(&self) -> Result<()> {
        #[cfg(test)]
        let phase = lab_profile::Span::new("placement", 0);
        self.verify_placement()?;
        #[cfg(test)]
        phase.success();
        #[cfg(test)]
        let phase = lab_profile::Span::new("journal_revalidate", 0);
        self.transaction.revalidate(self.spec())?;
        #[cfg(test)]
        phase.success();
        self.namespaces.bind(self.spec())?;
        #[cfg(test)]
        let phase = lab_profile::Span::new("producer_verify", 0);
        self.producer.verify(self.transaction, self.spec())?;
        #[cfg(test)]
        phase.success();
        #[cfg(test)]
        let phase = lab_profile::Span::new("container_inspect", 0);
        self.transaction.inspect_container(self.admission)?;
        #[cfg(test)]
        phase.success();
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
            self.enrollment.as_ref(),
            |_| Ok(()),
        )
    }
    pub fn pin_daemon(
        &mut self,
        bundle: &ReviewedBundle,
        child: &super::kernel::Child,
        pid: u32,
    ) -> Result<super::daemon::LiveDaemon<'g>> {
        self.verify()?;
        let mut daemon = super::daemon::LiveDaemon::pin(
            self.admission,
            self.transaction,
            self.namespaces,
            self.producer,
            bundle,
            child,
            pid,
            &self.config_digest,
            if self.enrollment.is_some() {
                super::kernel::DaemonConfiguration::PreservedEnrollment
            } else {
                super::kernel::DaemonConfiguration::Unenrolled
            },
        )?;
        let result = (|| {
            daemon.verify(bundle, &self.config_digest)?;
            daemon.bind_shape(if let Some(enrollment) = &self.enrollment {
                self.audit.pin_operational(
                    enrollment
                        .value()
                        .declaration()
                        .map_err(|_| Error::InvalidSpec)?,
                )?
            } else {
                self.audit.pin()?
            })?;
            self.verify_daemon(bundle, &mut daemon)
        })();
        if let Err(error) = result {
            daemon.revoke();
            self.audit.offline()?;
            return Err(error);
        }
        Ok(daemon)
    }
    pub fn discover_daemon(&self, child: &super::kernel::Child) -> Result<u32> {
        self.verify()?;
        // Daemon startup discovery precedes any monitor bootstrap exchange;
        // it neither replaces nor reanchors the latter's original two seconds.
        super::actual::daemon_pid_hint(
            self.admission,
            child,
            Instant::now() + Duration::from_secs(5),
        )
    }
    pub fn verify_daemon(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
    ) -> Result<()> {
        let result = (|| {
            #[cfg(test)]
            let phase = lab_profile::Span::new("handoff_base", 0);
            self.verify()?;
            #[cfg(test)]
            phase.success();
            #[cfg(test)]
            let phase = lab_profile::Span::new("daemon_before_audit", 0);
            daemon.verify(bundle, &self.config_digest)?;
            #[cfg(test)]
            phase.success();
            #[cfg(test)]
            let phase = lab_profile::Span::new("host_and_native_shape", 0);
            self.audit.verify(daemon.shape()?)?;
            #[cfg(test)]
            phase.success();
            #[cfg(test)]
            let phase = lab_profile::Span::new("daemon_after_audit", 0);
            daemon.verify(bundle, &self.config_digest)?;
            #[cfg(test)]
            phase.success();
            Ok(())
        })();
        if let Err(error) = result {
            daemon.revoke();
            self.audit.offline()?;
            return Err(error);
        }
        Ok(())
    }
    pub fn launch_observer(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
    ) -> Result<super::kernel::Child> {
        self.verify_daemon(bundle, daemon)?;
        if self.config.health_binding.is_some() || self.worker_launched || self.attempt.consumed {
            return Err(Error::DescriptorPolicy);
        }
        // Duplicate only this already verified placement directory, so the
        // parent can mutably audit while launch retains its fixed mount input.
        let placement = rustix::io::fcntl_dupfd_cloexec(&self.directory, 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let _placement_inventory = super::inventory::Registration::owned(&[placement.as_fd()])?;
        let child = super::actual::launch(
            self.admission,
            self.transaction,
            self.namespaces,
            self.producer,
            bundle,
            super::kernel::ActualRole::Observer,
            self.config.resolver,
            Some(placement.as_fd()),
            None,
            |actual_role| self.verify_before_release(bundle, daemon, actual_role),
        )?;
        self.worker_launched = true;
        Ok(child)
    }
    pub fn launch_monitor(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
    ) -> Result<super::kernel::Child> {
        self.verify_daemon(bundle, daemon)?;
        if self.config.health_binding.is_none() || self.worker_launched || self.attempt.consumed {
            return Err(Error::DescriptorPolicy);
        }
        if self.enrollment.is_some() {
            if self.executors.is_some() {
                return Err(Error::Interrupted);
            }
            self.executors = Some(
                self.audit.expiry(
                    self.transaction,
                    self.spec(),
                    self.namespaces,
                    self.config
                        .health_binding
                        .clone()
                        .ok_or(Error::DescriptorPolicy)?,
                    &self.config.nonce,
                )?,
            );
        }
        // Duplicate only this already verified placement directory, so the
        // parent can mutably audit while launch retains its fixed mount input.
        let placement = rustix::io::fcntl_dupfd_cloexec(&self.directory, 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let _placement_inventory = super::inventory::Registration::owned(&[placement.as_fd()])?;
        let authorization = self
            .enrollment
            .as_ref()
            .map(|enrollment| {
                super::enrollment::AuthorizedEnrollment::load(
                    self.spec(),
                    bundle,
                    &enrollment.value().binding,
                )
            })
            .transpose()?;
        let child = super::actual::launch(
            self.admission,
            self.transaction,
            self.namespaces,
            self.producer,
            bundle,
            if self.enrollment.is_some() {
                super::kernel::ActualRole::OperationalMonitor
            } else {
                super::kernel::ActualRole::Monitor
            },
            self.config.resolver,
            Some(placement.as_fd()),
            authorization.as_ref(),
            |actual_role| self.verify_before_release(bundle, daemon, actual_role),
        )?;
        self.worker_launched = true;
        Ok(child)
    }
    fn verify_before_release(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
        role: super::kernel::ActualRole,
    ) -> Result<()> {
        let expected = if self.enrollment.is_some() {
            super::kernel::ActualRole::OperationalMonitor
        } else if self.config.health_binding.is_some() {
            super::kernel::ActualRole::Monitor
        } else {
            super::kernel::ActualRole::Observer
        };
        if role != expected || self.worker_launched || self.attempt.consumed {
            return Err(Error::DescriptorPolicy);
        }
        // Keep both complete former post-spawn and pre-accept checks, including
        // retained executable bytes. Neither runs down the child's fixed2s
        // exchange budget: it has not been released from placement yet.
        for _ in 0..2 {
            #[cfg(test)]
            let verification_started = Instant::now();
            self.verify_daemon(bundle, daemon)?;
            #[cfg(test)]
            eprintln!(
                "LAB_TIMING stage=before_release_daemon_verification milliseconds={}",
                verification_started.elapsed().as_millis().min(600000)
            );
        }
        Ok(())
    }
    /// Real fixed-worker publication bridge. This initial path accepts Starting
    /// only, verifies Offline before writing and returns an offline stop command.
    /// It cannot activate or substitute for the pending independent expiry owner.
    pub fn serve_monitor_initial(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
        publisher: &mut super::publisher::Publisher,
        inspect: impl FnOnce(u32) -> Result<()>,
    ) -> Result<u32> {
        if self.enrollment.is_some() {
            return Err(Error::DescriptorPolicy);
        }
        let result = self.serve_session_inner(bundle, daemon, inspect, Some(publisher));
        if result.is_err() {
            self.audit.offline()?;
        }
        result
    }
    pub fn serve_operational(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
        publisher: &mut super::publisher::Publisher,
    ) -> Result<u32> {
        if self.enrollment.is_none() || self.executors.is_none() {
            return Err(Error::DescriptorPolicy);
        }
        let result = self.serve_session_inner(bundle, daemon, |_| Ok(()), Some(publisher));
        if result.is_err() {
            // Exact quarantine precedes socket revocation or caller child stop.
            let offline = self.audit.offline();
            if let Some(executors) = &mut self.executors {
                executors.stop();
            }
            offline?;
        }
        result
    }
    /// Exact current accept peer is checked through host proc/pidfd and retained
    /// producer membership. Translation of worker-side PID0/cgroup'/' is irrelevant.
    pub fn serve_once(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
    ) -> Result<u32> {
        self.serve_once_inner(bundle, daemon, |_| Ok(()))
    }
    #[cfg(test)]
    pub fn serve_once_inspected(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
        inspect: impl FnOnce(u32) -> Result<()>,
    ) -> Result<u32> {
        self.serve_once_inner(bundle, daemon, inspect)
    }
    fn serve_once_inner(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
        inspect: impl FnOnce(u32) -> Result<()>,
    ) -> Result<u32> {
        self.serve_session_inner(bundle, daemon, inspect, None)
    }
    fn serve_session_inner(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
        inspect: impl FnOnce(u32) -> Result<()>,
        publisher: Option<&mut super::publisher::Publisher>,
    ) -> Result<u32> {
        if publisher.is_some() != self.config.health_binding.is_some() {
            return Err(Error::DescriptorPolicy);
        }
        // Consume BEFORE accepting: malformed/unauthorized attempts never enable
        // another try with the same nonce/config. Failure stays quarantined.
        self.attempt.begin()?;
        if !self.worker_launched {
            return Err(Error::DescriptorPolicy);
        }
        #[cfg(test)]
        let placement_started = Instant::now();
        // Only fixed placement/config/listener binding is needed before accept.
        // The complete fresh authority check remains mandatory before Response.
        self.verify_placement()?;
        #[cfg(test)]
        eprintln!(
            "LAB_HANDOFF_PHASE phase=placement_preaccept milliseconds={}",
            placement_started.elapsed().as_millis().min(600000)
        );
        let end = Instant::now() + Duration::from_secs(2);
        #[cfg(test)]
        let profile = lab_profile::Scope::new(end);
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
        #[cfg(test)]
        let sender_started = Instant::now();
        let sender = if publisher.is_some() {
            self.producer.pin_monitor_sender(
                pid,
                self.transaction,
                self.spec(),
                self.namespaces,
                bundle,
            )?
        } else {
            self.producer
                .pin_sender(pid, self.transaction, self.spec(), self.namespaces, bundle)?
        };
        #[cfg(test)]
        eprintln!(
            "LAB_HANDOFF_PHASE phase=pin_sender milliseconds={} original_remaining_ms={}",
            sender_started.elapsed().as_millis().min(600000),
            end.saturating_duration_since(Instant::now()).as_millis()
        );
        let request: Request = bootstrap::read_message_before(&mut stream, end)
            .map_err(|_| Error::DescriptorPolicy)?;
        request_binding(&request, &self.config_digest, &self.config.nonce)?;
        // The ignored oracle inspects this authenticated process while it is
        // blocked awaiting the response. This avoids racing transient bootstrap
        // descriptors or post-response observer exit; no permission exists yet.
        #[cfg(test)]
        super::lab::stage("handoff_authenticated_peer_before_inspection");
        inspect(pid)?;
        #[cfg(test)]
        super::lab::stage("handoff_authenticated_peer_after_inspection");
        let mut session = None;
        let digest = self.config_digest.clone();
        let nonce = self.config.nonce.clone();
        initial_reply(&mut stream, &request, &digest, &nonce, end, || {
            self.verify_daemon(bundle, daemon)?;
            #[cfg(test)]
            let phase = lab_profile::Span::new("sender_verify", 0);
            sender.verify(
                self.producer,
                self.transaction,
                self.spec(),
                self.namespaces,
                bundle,
            )?;
            #[cfg(test)]
            phase.success();
            session = self
                .config
                .health_binding
                .clone()
                .map(|binding| {
                    vprouter_core::health::Session::new(
                        binding,
                        self.config.nonce.clone(),
                        vprouter_core::health::boot_seconds(),
                    )
                })
                .transpose()
                .map_err(|_| Error::DescriptorPolicy)?;
            Ok(if self.enrollment.is_some() {
                self.executors
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .check(self.transaction, &self.admission.spec)?;
                Permission::Operational
            } else if publisher.is_some() {
                Permission::Monitor
            } else {
                Permission::ObserveOnce
            })
        })?;
        #[cfg(test)]
        drop(profile);
        if let Some(publisher) = publisher {
            if self.enrollment.is_some() {
                self.operational_loop(bundle, daemon, publisher, &sender, &mut stream)?;
                return Ok(pid);
            }
            use vprouter_core::health::{HealthMessage, boot_seconds};
            let mut budget = vprouter_worker::monitor::PublicationBudget::new();
            let phase_end = budget.next_deadline().map_err(|_| Error::Deadline)?;
            let message: HealthMessage = bootstrap::read_message_before(&mut stream, phase_end)
                .map_err(|_| Error::DescriptorPolicy)?;
            session
                .as_mut()
                .ok_or(Error::DescriptorPolicy)?
                .accept(&message, boot_seconds())
                .map_err(|_| Error::DescriptorPolicy)?;
            let snapshot = initial_snapshot(&message)?;
            sender.verify(
                self.producer,
                self.transaction,
                self.spec(),
                self.namespaces,
                bundle,
            )?;
            self.verify_daemon(bundle, daemon)?;
            self.audit.offline()?;
            session
                .as_mut()
                .ok_or(Error::DescriptorPolicy)?
                .check(boot_seconds())
                .map_err(|_| Error::Deadline)?;
            use vprouter_worker::monitor::{
                Disposition, HealthAck, PublicationStage, PublicationStep,
            };
            let ack = |disposition| HealthAck {
                version: 1,
                lifecycle: self.config.nonce.clone(),
                sequence: message.sequence,
                snapshot_sequence: snapshot.sequence,
                disposition,
            };
            bootstrap::write_message_before(&mut stream, &ack(Disposition::Prepared), phase_end)
                .map_err(|_| Error::DescriptorPolicy)?;
            budget.complete_phase().map_err(|_| Error::Deadline)?;
            let phase_end = budget.next_deadline().map_err(|_| Error::Deadline)?;
            let step: PublicationStep = bootstrap::read_message_before(&mut stream, phase_end)
                .map_err(|_| Error::DescriptorPolicy)?;
            step.validate(
                &self.config.nonce,
                message.sequence,
                snapshot.sequence,
                PublicationStage::Persist,
            )
            .map_err(|_| Error::DescriptorPolicy)?;
            session
                .as_mut()
                .ok_or(Error::DescriptorPolicy)?
                .check(boot_seconds())
                .map_err(|_| Error::Deadline)?;
            publisher.submit(snapshot)?;
            loop {
                sender.verify(
                    self.producer,
                    self.transaction,
                    self.spec(),
                    self.namespaces,
                    bundle,
                )?;
                session
                    .as_mut()
                    .ok_or(Error::DescriptorPolicy)?
                    .check(boot_seconds())
                    .map_err(|_| Error::Deadline)?;
                if publisher.poll()? == Some(snapshot.sequence) {
                    break;
                }
                if Instant::now() >= phase_end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            bootstrap::write_message_before(&mut stream, &ack(Disposition::Persisted), phase_end)
                .map_err(|_| Error::DescriptorPolicy)?;
            budget.complete_phase().map_err(|_| Error::Deadline)?;
            let phase_end = budget.next_deadline().map_err(|_| Error::Deadline)?;
            let step: PublicationStep = bootstrap::read_message_before(&mut stream, phase_end)
                .map_err(|_| Error::DescriptorPolicy)?;
            step.validate(
                &self.config.nonce,
                message.sequence,
                snapshot.sequence,
                PublicationStage::Finalize,
            )
            .map_err(|_| Error::DescriptorPolicy)?;
            session
                .as_mut()
                .ok_or(Error::DescriptorPolicy)?
                .check(boot_seconds())
                .map_err(|_| Error::Deadline)?;
            self.verify_daemon(bundle, daemon)?;
            sender.verify(
                self.producer,
                self.transaction,
                self.spec(),
                self.namespaces,
                bundle,
            )?;
            session
                .as_mut()
                .ok_or(Error::DescriptorPolicy)?
                .check(boot_seconds())
                .map_err(|_| Error::Deadline)?;
            bootstrap::write_message_before(
                &mut stream,
                &vprouter_worker::monitor::HealthAck {
                    version: 1,
                    lifecycle: self.config.nonce.clone(),
                    sequence: message.sequence,
                    snapshot_sequence: snapshot.sequence,
                    disposition: vprouter_worker::monitor::Disposition::QuarantinedStop,
                },
                phase_end,
            )
            .map_err(|_| Error::DescriptorPolicy)?;
            budget.complete_phase().map_err(|_| Error::Deadline)?;
            budget.complete().map_err(|_| Error::Deadline)?;
        }
        Ok(pid)
    }
    fn operational_loop(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
        publisher: &mut super::publisher::Publisher,
        sender: &super::producer::Sender,
        stream: &mut std::os::unix::net::UnixStream,
    ) -> Result<()> {
        use vprouter_core::{
            health::{HealthMessage, boot_seconds},
            state::HealthState,
        };
        use vprouter_worker::operation::{Reply, Request, StructuralEvidence};
        struct Pending {
            message: HealthMessage,
            persisted: bool,
            proof: Option<super::transport::ReadyPublication>,
            end: Instant,
        }
        let mut sequence = 0u64;
        let mut structural: Option<StructuralEvidence> = None;
        let mut pending: Option<Pending> = None;
        loop {
            let pending_end = pending.as_ref().map(|p| p.end);
            if let Some(end) = pending_end {
                operational_check(end)?;
            }
            self.executors
                .as_mut()
                .ok_or(Error::Interrupted)?
                .check(self.transaction, &self.admission.spec)?;
            let poll_end =
                operational_deadline(Instant::now() + Duration::from_millis(100), pending_end);
            operational_check(poll_end)?;
            let mut descriptors = [PollFd::new(&*stream, PollFlags::IN)];
            if poll(
                &mut descriptors,
                Some(
                    &rustix::event::Timespec::try_from(
                        poll_end.saturating_duration_since(Instant::now()),
                    )
                    .map_err(|_| Error::Deadline)?,
                ),
            )
            .map_err(|_| Error::DescriptorPolicy)?
                == 0
            {
                continue;
            }
            let request = operational_read(stream, pending_end)?;
            sequence = sequence.checked_add(1).ok_or(Error::DescriptorPolicy)?;
            let frame = request.frame().clone();
            let now = boot_seconds();
            frame
                .validate(&self.config.nonce, sequence, now)
                .map_err(|_| Error::DescriptorPolicy)?;
            let end = operational_deadline(
                Instant::now() + Duration::from_secs_f64(2. - (now - frame.sent_at)),
                pending_end,
            );
            let publication_end =
                Instant::now() + Duration::from_secs_f64(6. - (now - frame.sent_at));
            sender.verify(
                self.producer,
                self.transaction,
                self.spec(),
                self.namespaces,
                bundle,
            )?;
            operational_check(end)?;
            self.verify()?;
            operational_check(end)?;
            frame
                .validate(&self.config.nonce, sequence, boot_seconds())
                .map_err(|_| Error::Deadline)?;
            let mut reply_proof = None;
            let reply = match request {
                Request::Structure { .. } => {
                    if pending.is_some() {
                        return Err(Error::DescriptorPolicy);
                    }
                    let checked_at = boot_seconds();
                    self.verify_daemon(bundle, daemon)?;
                    let mut evidence = self.audit.structural(daemon.shape()?)?;
                    // Full process+allocation verification predates the native dumps.
                    // Preserve that earlier check anchor conservatively.
                    evidence.checked_at = evidence.checked_at.min(checked_at);
                    sender.verify(
                        self.producer,
                        self.transaction,
                        self.spec(),
                        self.namespaces,
                        bundle,
                    )?;
                    evidence
                        .validate(frame.sent_at, boot_seconds())
                        .map_err(|_| Error::Deadline)?;
                    structural = Some(evidence.clone());
                    Reply::Structure { frame, evidence }
                }
                Request::Heartbeat { .. } => {
                    if pending.is_some() {
                        return Err(Error::DescriptorPolicy);
                    }
                    self.executors
                        .as_mut()
                        .ok_or(Error::Interrupted)?
                        .liveness()?;
                    Reply::Alive { frame }
                }
                Request::Prepare { message, .. } => {
                    if pending.is_some() {
                        return Err(Error::DescriptorPolicy);
                    }
                    let snapshot = message.snapshot.as_ref().ok_or(Error::DescriptorPolicy)?;
                    // Exact Offline precedes a failure ACK and all withdrawal.
                    if snapshot.state != HealthState::Ready {
                        self.audit.offline()?;
                    }
                    if snapshot.evidence.is_some() {
                        structural
                            .take()
                            .ok_or(Error::DescriptorPolicy)?
                            .matches(&message)
                            .map_err(|_| Error::DescriptorPolicy)?;
                    } else {
                        structural = None;
                    }
                    self.verify_daemon(bundle, daemon)?;
                    operational_check(end)?;
                    frame
                        .validate(&self.config.nonce, sequence, boot_seconds())
                        .map_err(|_| Error::Deadline)?;
                    self.executors.as_mut().ok_or(Error::Interrupted)?.health(
                        self.transaction,
                        &self.admission.spec,
                        &message,
                    )?;
                    pending = Some(Pending {
                        message: *message,
                        persisted: false,
                        proof: None,
                        end: publication_end,
                    });
                    Reply::Prepared { frame }
                }
                Request::Persist {
                    snapshot_sequence, ..
                } => {
                    let p = pending.as_mut().ok_or(Error::DescriptorPolicy)?;
                    let snapshot = p.message.snapshot.as_ref().ok_or(Error::DescriptorPolicy)?;
                    if p.persisted
                        || snapshot.sequence != snapshot_sequence
                        || Instant::now() >= p.end
                    {
                        return Err(Error::DescriptorPolicy);
                    }
                    // Ready requires a private native enforcement proof bound
                    // to these exact bytes BEFORE the publisher accepts them.
                    if Instant::now() >= end {
                        return Err(Error::Deadline);
                    }
                    if snapshot.state == HealthState::Ready {
                        let proof = self.audit.ready_publication(
                            self.executors.as_mut().ok_or(Error::Interrupted)?,
                            self.transaction,
                            &self.admission.spec,
                            snapshot,
                        )?;
                        operational_check(end)?;
                        publisher.submit_ready(snapshot, &proof)?;
                        p.end = p.end.min(
                            Instant::now()
                                + Duration::from_secs_f64(
                                    (proof.expires_at() - boot_seconds()).max(0.),
                                ),
                        );
                        p.proof = Some(proof);
                    } else {
                        publisher.submit(snapshot)?;
                    }
                    operational_check(end)?;
                    while publisher.poll()? != Some(snapshot_sequence) {
                        self.executors
                            .as_mut()
                            .ok_or(Error::Interrupted)?
                            .check(self.transaction, &self.admission.spec)?;
                        operational_check(end)?;
                        sender.verify(
                            self.producer,
                            self.transaction,
                            self.spec(),
                            self.namespaces,
                            bundle,
                        )?;
                        if Instant::now() >= end || Instant::now() >= p.end {
                            return Err(Error::Deadline);
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    operational_check(end)?;
                    if let Some(proof) = &p.proof {
                        proof.check(snapshot)?;
                    }
                    reply_proof = p.proof.clone();
                    p.persisted = true;
                    Reply::Persisted { frame }
                }
                Request::Commit {
                    snapshot_sequence, ..
                } => {
                    let p = pending.take().ok_or(Error::DescriptorPolicy)?;
                    let snapshot = p.message.snapshot.as_ref().ok_or(Error::DescriptorPolicy)?;
                    if !p.persisted
                        || snapshot.sequence != snapshot_sequence
                        || Instant::now() >= p.end
                    {
                        return Err(Error::DescriptorPolicy);
                    }
                    self.verify_daemon(bundle, daemon)?;
                    operational_check(end)?;
                    frame
                        .validate(&self.config.nonce, sequence, boot_seconds())
                        .map_err(|_| Error::Deadline)?;
                    if let Some(proof) = &p.proof {
                        proof.check(snapshot)?;
                    }
                    self.audit.apply_health(
                        self.executors.as_mut().ok_or(Error::Interrupted)?,
                        self.transaction,
                        &self.admission.spec,
                        snapshot.state,
                    )?;
                    operational_check(end)?;
                    if let Some(proof) = &p.proof {
                        proof.check(snapshot)?;
                    }
                    reply_proof = p.proof;
                    Reply::Enforced {
                        frame,
                        state: snapshot.state,
                    }
                }
            };
            operational_reply(
                stream,
                &reply,
                end,
                pending_end.or_else(|| pending.as_ref().map(|p| p.end)),
                || {
                    if let Some(proof) = &reply_proof {
                        proof.check_time()?;
                    }
                    sender.verify(
                        self.producer,
                        self.transaction,
                        self.spec(),
                        self.namespaces,
                        bundle,
                    )?;
                    if let Some(proof) = &reply_proof {
                        proof.check_time()?;
                    }
                    operational_check(end)?;
                    self.executors
                        .as_mut()
                        .ok_or(Error::Interrupted)?
                        .check(self.transaction, &self.admission.spec)?;
                    if let Some(proof) = &reply_proof {
                        proof.check_time()?;
                    }
                    Ok(())
                },
            )?;
            if let Some(proof) = &reply_proof {
                proof.check_time()?;
            }
        }
    }
    #[cfg(test)]
    pub fn assert_offline(&mut self) -> Result<()> {
        self.audit.assert_offline()
    }
    pub fn quarantine_daemon(
        &mut self,
        bundle: &ReviewedBundle,
        daemon: &mut super::daemon::LiveDaemon<'_>,
    ) -> Result<()> {
        self.verify_daemon(bundle, daemon)?;
        self.audit.offline()?;
        self.verify_daemon(bundle, daemon)
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
fn initial_snapshot(
    message: &vprouter_core::health::HealthMessage,
) -> Result<&vprouter_core::health::Snapshot> {
    let snapshot = message.snapshot.as_ref().ok_or(Error::DescriptorPolicy)?;
    if message.sequence != 1
        || snapshot.sequence != 1
        || snapshot.state != vprouter_core::state::HealthState::Starting
        || snapshot.reason.is_some()
        || snapshot.evidence.is_some()
    {
        return Err(Error::DescriptorPolicy);
    }
    Ok(snapshot)
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
    fn operation_frame() -> vprouter_worker::operation::Frame {
        vprouter_worker::operation::Frame {
            version: 1,
            lifecycle: "a".repeat(64),
            sequence: 1,
            sent_at: vprouter_core::health::boot_seconds(),
        }
    }
    #[test]
    fn first_response_rejects_forged_binding_or_placement_without_permission_bytes() {
        use std::os::unix::net::UnixStream;
        for fault in 0..3 {
            let (mut worker, mut guard) = UnixStream::pair().unwrap();
            let end = Instant::now() + Duration::from_secs(1);
            let wire = request(
                if fault == 0 {
                    "forged-config"
                } else {
                    "digest"
                },
                if fault == 1 { "forged-nonce" } else { "nonce" },
            );
            bootstrap::write_message_before(&mut worker, &wire, end).unwrap();
            let received: Request = bootstrap::read_message_before(&mut guard, end).unwrap();
            let verified = std::cell::Cell::new(false);
            let result = initial_reply(&mut guard, &received, "digest", "nonce", end, || {
                verified.set(true);
                // The native placement verifier's failure crosses the actual
                // first-response gate. This is protocol/control-flow evidence.
                Err(Error::OwnershipMismatch)
            });
            assert!(result.is_err());
            assert_eq!(verified.get(), fault == 2);
            drop(guard);
            let mut bytes = Vec::new();
            worker.read_to_end(&mut bytes).unwrap();
            assert!(bytes.is_empty());
        }
    }
    #[test]
    fn first_response_requires_fresh_verifier_and_original_deadline() {
        use std::os::unix::net::UnixStream;
        for late in [false, true] {
            let (mut worker, mut guard) = UnixStream::pair().unwrap();
            let end = Instant::now()
                + if late {
                    Duration::from_millis(10)
                } else {
                    Duration::from_secs(1)
                };
            let verified = std::cell::Cell::new(false);
            let result = initial_reply(
                &mut guard,
                &request("digest", "nonce"),
                "digest",
                "nonce",
                end,
                || {
                    verified.set(true);
                    if late {
                        std::thread::sleep(Duration::from_millis(30));
                    }
                    Ok(Permission::ObserveOnce)
                },
            );
            assert!(verified.get());
            if late {
                assert_eq!(result, Err(Error::Deadline));
                drop(guard);
                let mut bytes = Vec::new();
                worker.read_to_end(&mut bytes).unwrap();
                assert!(bytes.is_empty());
            } else {
                result.unwrap();
                let reply: Response = bootstrap::read_message_before(&mut worker, end).unwrap();
                assert!(reply.permission == Permission::ObserveOnce);
                assert_eq!(reply.config_sha256, "digest");
                assert_eq!(reply.nonce, "nonce");
            }
        }
    }
    #[test]
    fn operational_final_verification_cannot_ack_past_original_publication_end() {
        use vprouter_worker::operation::Reply;
        for reply in [
            Reply::Persisted {
                frame: operation_frame(),
            },
            Reply::Enforced {
                frame: operation_frame(),
                state: vprouter_core::state::HealthState::Ready,
            },
        ] {
            let (mut writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
            let now = Instant::now();
            let result = operational_reply(
                &mut writer,
                &reply,
                now + Duration::from_secs(1),
                Some(now + Duration::from_millis(20)),
                || {
                    std::thread::sleep(Duration::from_millis(60));
                    Ok(())
                },
            );
            assert_eq!(
                result,
                Err(Error::Deadline),
                "late verification emitted an ACK after the aggregate budget"
            );
            reader.set_nonblocking(true).unwrap();
            let mut byte = [0];
            assert_eq!(
                reader.read(&mut byte).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
    #[test]
    fn operational_pending_request_read_retains_original_publication_end() {
        let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let end = Instant::now() + Duration::from_millis(20);
        let peer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            bootstrap::write_message(
                &mut writer,
                &vprouter_worker::operation::Request::Commit {
                    frame: operation_frame(),
                    snapshot_sequence: 1,
                },
            )
            .unwrap();
        });
        assert!(
            matches!(
                operational_read(&mut reader, Some(end)),
                Err(Error::Deadline)
            ),
            "a new frame budget extended the original publication"
        );
        peer.join().unwrap();
    }
    #[test]
    fn operational_ack_serialization_retains_original_publication_end() {
        struct Delayed;
        impl serde::Serialize for Delayed {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                std::thread::sleep(Duration::from_millis(60));
                serializer.serialize_u64(1)
            }
        }
        let (mut writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let now = Instant::now();
        assert_eq!(
            operational_reply(
                &mut writer,
                &Delayed,
                now + Duration::from_secs(1),
                Some(now + Duration::from_millis(20)),
                || Ok(())
            ),
            Err(Error::Deadline)
        );
        reader.set_nonblocking(true).unwrap();
        assert_eq!(
            reader.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn operational_timely_ack_remains_available_with_or_without_pending_publication() {
        use vprouter_worker::operation::Reply;
        for pending in [false, true] {
            let (mut writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
            let now = Instant::now();
            operational_reply(
                &mut writer,
                &Reply::Alive {
                    frame: operation_frame(),
                },
                now + Duration::from_secs(1),
                pending.then_some(now + Duration::from_secs(2)),
                || Ok(()),
            )
            .unwrap();
            let reply: Reply = bootstrap::read_message(&mut reader).unwrap();
            assert!(matches!(reply, Reply::Alive { .. }));
            assert_eq!(reply.frame().sequence, 1);
        }
    }
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
    fn initial_monitor_publication_cannot_authorize_recovery_ready_or_replay() {
        use vprouter_core::{
            config::ExitMode,
            health::{Binding, HealthMessage, Snapshot},
            state::{HealthMachine, HealthState},
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
        let machine = HealthMachine::new(
            binding.mode,
            binding.expected_server.as_deref(),
            &binding.node_id,
        )
        .unwrap();
        let snapshot = Snapshot::from_machine(binding, 1, 100., &machine).unwrap();
        let good = HealthMessage {
            version: 1,
            lifecycle: "a".repeat(64),
            sequence: 1,
            sent_at: 100.,
            snapshot: Some(snapshot),
        };
        initial_snapshot(&good).unwrap();
        for state in [
            HealthState::Recovering,
            HealthState::Ready,
            HealthState::Blocked,
        ] {
            let mut wrong = good.clone();
            wrong.snapshot.as_mut().unwrap().state = state;
            assert!(initial_snapshot(&wrong).is_err());
        }
        let mut wrong = good.clone();
        wrong.sequence = 2;
        assert!(initial_snapshot(&wrong).is_err());
        let mut wrong = good.clone();
        wrong.snapshot.as_mut().unwrap().sequence = 2;
        assert!(initial_snapshot(&wrong).is_err());
        let mut wrong = good;
        wrong.snapshot = None;
        assert!(initial_snapshot(&wrong).is_err());
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
