//! Fixed no-fork Docker policy query. The parent receives no Docker JSON, maps,
//! environment fields, command strings, or raw error bodies.
use super::super::{
    attachment::{InspectionRequest, QueryFacts},
    owned::preparation::{
        Server, ValidationBirth,
        inspection::{Gate, Intent, Receipt},
    },
};
use super::*;
use rustix::net::{self, RecvFlags, SendFlags};
use std::rc::Rc;

struct Sockets {
    fds: Vec<OwnedFd>,
    _inventory: Vec<super::super::inventory::Registration>,
    metadata: vprouter_linux::storage::Metadata,
    listener_pins: Vec<OwnedFd>,
    _listener_inventory: Vec<super::super::inventory::Registration>,
    listener_credentials: Option<net::UCred>,
}
impl Sockets {
    fn connect(end: f64, include_image: bool) -> Result<Self> {
        let metadata = vprouter_linux::storage::metadata(
            Path::new("/run/docker.sock"),
            vprouter_linux::storage::Kind::DockerSocket,
        )
        .map_err(|_| Error::UnsafeInput)?;
        let mut sockets = Self {
            fds: Vec::new(),
            _inventory: Vec::new(),
            metadata,
            listener_pins: Vec::new(),
            _listener_inventory: Vec::new(),
            listener_credentials: None,
        };
        for _ in 0..if include_image { 6 } else { 4 } {
            check(end)?;
            let fd = net::socket_with(
                net::AddressFamily::UNIX,
                net::SocketType::STREAM,
                net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                None,
            )
            .map_err(|_| Error::DockerUnavailable)?;
            let inventory = super::super::inventory::Registration::owned(&[fd.as_fd()])?;
            let address =
                net::SocketAddrUnix::new("/run/docker.sock").map_err(|_| Error::UnsafeInput)?;
            match net::connect(&fd, &address) {
                Ok(()) => {}
                Err(rustix::io::Errno::INPROGRESS) => {
                    ready(&fd, rustix::event::PollFlags::OUT, end)?
                }
                Err(_) => return Err(Error::DockerUnavailable),
            }
            if net::sockopt::socket_error(&fd)
                .map_err(|_| Error::DockerUnavailable)?
                .is_err()
            {
                return Err(Error::DockerUnavailable);
            }
            let credentials =
                net::sockopt::socket_peercred(&fd).map_err(|_| Error::DockerUnavailable)?;
            require_listener_origin(credentials, sockets.listener_credentials)?;
            // These are the socket's listener-origin credentials/pin, including
            // PID1 for a socket-activated listener. Neither PID1 nor another
            // origin identifies the accepting HTTP handler: a listener can be
            // transferred. Authority remains the protected root-owned endpoint
            // plus the fixed Docker policy and original native container checks.
            // The numeric PID is compared only inside original-live brackets;
            // it is never passed to pidfd_open or used to adopt/signal a process.
            let peer = peer_pidfd(&fd)?;
            let peer_inventory = super::super::inventory::Registration::owned(&[peer.as_fd()])?;
            if wait_ready(&peer, Duration::ZERO)?
                || sockets
                    .listener_pins
                    .iter()
                    .any(|p| wait_ready(p, Duration::ZERO).unwrap_or(true))
            {
                return Err(Error::DockerUnavailable);
            }
            sockets.listener_credentials = Some(credentials);
            sockets.listener_pins.push(peer);
            sockets._listener_inventory.push(peer_inventory);
            sockets.fds.push(fd);
            sockets._inventory.push(inventory);
            sockets.verify()?;
            check(end)?;
        }
        Ok(sockets)
    }
    fn verify(&self) -> Result<()> {
        let current = vprouter_linux::storage::metadata(
            Path::new("/run/docker.sock"),
            vprouter_linux::storage::Kind::DockerSocket,
        )
        .map_err(|_| Error::DockerUnavailable)?;
        if (current.device, current.inode, current.uid, current.mode)
            != (
                self.metadata.device,
                self.metadata.inode,
                self.metadata.uid,
                self.metadata.mode,
            )
            || self.listener_pins.len() != self.fds.len()
            || self.listener_pins.is_empty()
            || self._listener_inventory.len() != self.listener_pins.len()
            || self
                .listener_pins
                .iter()
                .zip(&self._listener_inventory)
                .any(|(fd, token)| !token.contains(fd.as_fd()))
            || self
                .listener_pins
                .iter()
                .any(|p| wait_ready(p, Duration::ZERO).unwrap_or(true))
        {
            return Err(Error::DockerUnavailable);
        }
        for (fd, inventory) in self.fds.iter().zip(&self._inventory) {
            if !inventory.contains(fd.as_fd())
                || Some(net::sockopt::socket_peercred(fd).map_err(|_| Error::DockerUnavailable)?)
                    != self.listener_credentials
            {
                return Err(Error::DockerUnavailable);
            }
        }
        if self
            .listener_pins
            .iter()
            .any(|p| wait_ready(p, Duration::ZERO).unwrap_or(true))
        {
            return Err(Error::DockerUnavailable);
        }
        Ok(())
    }
}
fn require_listener_origin(credentials: net::UCred, previous: Option<net::UCred>) -> Result<()> {
    if credentials.uid.as_raw() != 0
        || credentials.gid.as_raw() != 0
        || credentials.pid.as_raw_nonzero().get() < 1
        || previous.is_some_and(|old| old != credentials)
    {
        return Err(Error::DockerUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod listener_tests {
    use super::*;
    fn credentials(pid: i32, uid: u32, gid: u32) -> net::UCred {
        net::UCred {
            pid: rustix::process::Pid::from_raw(pid).unwrap(),
            uid: rustix::process::Uid::from_raw(uid),
            gid: rustix::process::Gid::from_raw(gid),
        }
    }
    #[test]
    fn root_listener_origin_accepts_init_and_direct_listener_without_handler_claim() {
        for pid in [1, 12345] {
            let origin = credentials(pid, 0, 0);
            require_listener_origin(origin, None).unwrap();
            require_listener_origin(origin, Some(origin)).unwrap();
        }
    }
    #[test]
    fn root_listener_origin_refuses_nonroot_and_changed_origin() {
        let init = credentials(1, 0, 0);
        for other in [
            credentials(1, 1, 0),
            credentials(1, 0, 1),
            credentials(42, 0, 0),
        ] {
            assert!(require_listener_origin(other, Some(init)).is_err());
        }
        assert!(require_listener_origin(credentials(42, 1, 0), None).is_err());
        assert!(require_listener_origin(credentials(42, 0, 1), None).is_err());
    }
}

fn peer_pidfd(fd: impl AsFd) -> Result<OwnedFd> {
    let mut peer = -1i32;
    let mut length = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: the kernel writes one initialized int and its exact length. On
    // success SO_PEERPIDFD returns a new owned CLOEXEC descriptor; unsupported
    // kernels refuse, with no numeric-PID fallback.
    cv(
        unsafe {
            libc::getsockopt(
                fd.as_fd().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&mut peer as *mut i32).cast(),
                &mut length,
            )
        },
        Error::DockerUnavailable,
    )?;
    if peer < 0 {
        return Err(Error::DescriptorPolicy);
    }
    let peer = unsafe { OwnedFd::from_raw_fd(peer) };
    if length as usize != std::mem::size_of::<i32>()
        || peer.as_raw_fd() < 3
        || !descriptor_cloexec(peer.as_raw_fd())?
    {
        return Err(Error::DescriptorPolicy);
    }
    Ok(peer)
}
use std::path::Path;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    request: [u8; 32],
    facts: QueryFacts,
}
pub(crate) struct Child {
    native: Option<Native>,
}
struct Native {
    creator: u32,
    _capacity: ChildCapacity,
    intent: Intent,
    request: Rc<InspectionRequest>,
    sockets: Sockets,
    pid: u32,
    pidfd: OwnedFd,
    reap: Rc<ParentReap>,
    pidfd_inventory: Option<super::super::inventory::Registration>,
    channel: OwnedFd,
    _channel_inventory: super::super::inventory::Registration,
    birth: Option<ValidationBirth>,
    released: bool,
    failure: Option<Error>,
    packet: Option<Vec<u8>>,
}
pub(crate) struct Verified {
    native: Native,
    facts: QueryFacts,
    verified_at: f64,
}
pub(crate) struct Accepted {
    creator: u32,
    request: Rc<InspectionRequest>,
    facts: QueryFacts,
    _receipt: Receipt,
    #[cfg(test)]
    lab_original: (ValidationBirth, Rc<ParentReap>, f64),
    #[cfg(test)]
    lab_listener_origin: net::UCred,
}
impl Accepted {
    pub(crate) fn verify_movement_service(&self, service: &Server) -> Result<()> {
        self.require()?;
        if self.request.kind() != super::super::attachment::QueryKind::MovementRecheck {
            return Err(Error::OwnershipMismatch);
        }
        self.request.verify_service(service)?;
        self._receipt.verify_movement(self, service)?;
        self.require()
    }
    pub(crate) fn verify_quarantine_service(&self, service: &Server) -> Result<()> {
        self.require()?;
        if self.request.kind() != super::super::attachment::QueryKind::QuarantineRecheck {
            return Err(Error::OwnershipMismatch);
        }
        self.request.verify_service(service)?;
        self._receipt.verify_quarantine(self, service)?;
        self.require()
    }
    pub(crate) fn verify_producer_service(&self, service: &Server) -> Result<()> {
        self.require()?;
        if self.request.kind() != super::super::attachment::QueryKind::ProducerRecheck {
            return Err(Error::OwnershipMismatch);
        }
        self.request.verify_service(service)?;
        self._receipt.verify_producer(self, service)?;
        self.require()
    }
    pub(crate) fn verify_producer_binding_service(&self, service: &Server) -> Result<()> {
        self.require()?;
        if self.request.kind() != super::super::attachment::QueryKind::ProducerBindingRecheck {
            return Err(Error::OwnershipMismatch);
        }
        self.request.verify_service(service)?;
        self._receipt.verify_producer_binding(self, service)?;
        self.require()
    }
    pub(crate) fn verify_bootstrap_service(&self, service: &Server) -> Result<()> {
        self.require()?;
        if self.request.kind().bootstrap_index().is_none() {
            return Err(Error::OwnershipMismatch);
        }
        self.request.verify_service(service)?;
        self._receipt.verify_bootstrap(self, service)?;
        self.require()
    }
    pub(crate) fn request(&self) -> &Rc<InspectionRequest> {
        &self.request
    }
    pub(crate) fn facts(&self) -> &QueryFacts {
        &self.facts
    }
    pub(crate) fn require(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::ConfinementPolicy);
        }
        self.request.check_deadline()
    }
}
impl Verified {
    pub(crate) fn original_request(&self) -> Result<&Rc<InspectionRequest>> {
        self.native.creator()?;
        Ok(&self.native.request)
    }
    pub(crate) fn require_request(&self, request: &Rc<InspectionRequest>) -> Result<()> {
        self.native.creator()?;
        if !Rc::ptr_eq(&self.native.request, request) {
            return Err(Error::OwnershipMismatch);
        }
        request.check_deadline()
    }
    pub(crate) fn kind(&self) -> super::super::attachment::QueryKind {
        self.native.request.kind()
    }
    pub(crate) fn bind_service(&self, server: &Server) -> Result<()> {
        self.native.intent.same_service(server)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        self.native.birth.clone().ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn facts(&self) -> &QueryFacts {
        &self.facts
    }
    pub(crate) fn verified_at(&self) -> f64 {
        self.verified_at
    }
    pub(crate) fn verify_receipt(&self, receipt: &Receipt) -> Result<()> {
        self.native.creator()?;
        receipt.verify(
            &self.native.intent,
            &self.birth()?,
            &self.facts,
            self.verified_at,
        )
    }
    pub(crate) fn accept(slot: &mut Option<Self>, receipt: Receipt) -> Result<Accepted> {
        let value = slot.as_ref().ok_or(Error::Interrupted)?;
        value.verify_receipt(&receipt)?;
        value.native.request.check_deadline()?;
        value.native.sockets.verify()?;
        if value.native.reap.status.get() != Some(0) {
            return Err(Error::OwnershipMismatch);
        }
        let value = slot.take().ok_or(Error::Interrupted)?;
        Ok(Accepted {
            creator: value.native.creator,
            request: value.native.request.clone(),
            facts: value.facts,
            _receipt: receipt,
            #[cfg(test)]
            lab_listener_origin: value
                .native
                .sockets
                .listener_credentials
                .expect("verified original listener credentials"),
            #[cfg(test)]
            lab_original: (
                value.native.birth.clone().expect("verified original birth"),
                value.native.reap.clone(),
                value.verified_at,
            ),
        })
    }
}
thread_local! { static RETIRED: std::cell::RefCell<Vec<Native>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    fn cancel(&mut self, reason: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(reason);
        let _ = net::shutdown(&self.channel, net::Shutdown::Both);
        let _ = send_or_exited(self.pidfd.as_fd(), libc::SIGKILL);
    }
    fn reap(&mut self) -> Result<Option<i32>> {
        self.creator()?;
        if self.pidfd_inventory.is_none() {
            self.pidfd_inventory = Some(super::super::inventory::Registration::owned(&[self
                .pidfd
                .as_fd()])?);
        }
        self.reap.poll(self.pid, self.pidfd.as_fd())
    }
    fn receive(&mut self) -> Result<bool> {
        // One bounded packet plus EOF, including a final drain AFTER waitpid.
        // Child exit cannot discard a packet queued after the first EAGAIN.
        for _ in 0..2 {
            let mut bytes = [0; 512];
            match net::recv(
                &self.channel,
                &mut bytes,
                RecvFlags::DONTWAIT | RecvFlags::TRUNC,
            ) {
                Ok((0, _)) => return Ok(true),
                Ok((n, full)) if n == full && n <= bytes.len() && self.packet.is_none() => {
                    self.packet = Some(bytes[..n].to_vec())
                }
                Ok(_) => return Err(Error::TooLarge),
                Err(rustix::io::Errno::AGAIN) => return Ok(false),
                Err(_) => return Err(Error::ChildFailed),
            }
        }
        Err(Error::ChildFailed)
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(mut native) = self.native.take() {
            if native.creator != std::process::id() || native.reap.status.get().is_some() {
                return;
            }
            native.cancel(Error::Interrupted);
            RETIRED.with(|retired| retired.borrow_mut().push(native));
        }
    }
}
pub(super) fn poll_retired() {
    RETIRED.with(|retired| {
        retired.borrow_mut().retain_mut(|native| {
            if native.creator != std::process::id() {
                return true;
            }
            native.cancel(Error::Interrupted);
            native.reap().ok().flatten().is_none()
        })
    });
}
pub(super) fn retired_drained() -> bool {
    RETIRED.with(|retired| {
        retired
            .borrow()
            .iter()
            .all(|n| n.creator != std::process::id())
    })
}
impl Child {
    pub(crate) fn original_request(&self) -> Result<&Rc<InspectionRequest>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(&n.request)
    }
    pub(crate) fn require_request(&self, request: &Rc<InspectionRequest>) -> Result<()> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        if !Rc::ptr_eq(&n.request, request) {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn kind(&self) -> super::super::attachment::QueryKind {
        self.native.as_ref().expect("live query").request.kind()
    }
    pub(crate) fn bind_service(&self, server: &Server) -> Result<()> {
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .intent
            .same_service(server)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.creator()?;
        native.birth.clone().ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn cancel(&mut self, error: Error) {
        if let Some(native) = &mut self.native {
            native.cancel(error);
        }
    }
    pub(crate) fn collect(&mut self) {
        if let Some(native) = &mut self.native {
            let _ = native.reap();
        }
    }
    pub(crate) fn reaped(&self) -> bool {
        self.native
            .as_ref()
            .is_none_or(|n| n.creator == std::process::id() && n.reap.status.get().is_some())
    }
    pub(crate) fn release(&mut self, gate: Gate) -> Result<()> {
        owner_admission_permitted()?;
        let birth = self.birth()?;
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        gate.verify(&native.intent, &birth)?;
        native.request.check_deadline()?;
        native.sockets.verify()?;
        if native.released || native.failure.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        if net::send(
            &native.channel,
            &[1],
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )
        .map_err(|_| Error::ChildFailed)?
            != 1
        {
            return Err(Error::ChildFailed);
        }
        native.released = true;
        Ok(())
    }
    pub(crate) fn poll(&mut self) -> Result<Option<Verified>> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.creator()?;
        if let Some(error) = native.failure {
            let _ = native.reap();
            return Err(error);
        }
        let result = (|| {
            native.request.check_deadline()?;
            if !native.released {
                return Err(Error::OwnershipMismatch);
            }
            native.receive()?;
            match native.reap()? {
                None => return Ok(None),
                Some(0) => {}
                Some(_) => return Err(Error::ChildFailed),
            }
            if !native.receive()? {
                return Err(Error::ChildFailed);
            }
            let reply: Reply =
                serde_json::from_slice(native.packet.as_deref().ok_or(Error::ChildFailed)?)
                    .map_err(|_| Error::ChildFailed)?;
            if reply.request != native.request.digest()
                || reply.facts.pid <= 1
                || reply.facts.pid > i32::MAX as u32
            {
                return Err(Error::OwnershipMismatch);
            }
            native.sockets.verify()?;
            native.request.check_deadline()?;
            Ok(Some(reply.facts))
        })();
        match result {
            Ok(Some(facts)) => Ok(Some(Verified {
                native: self.native.take().ok_or(Error::Interrupted)?,
                facts,
                verified_at: vprouter_core::health::boot_seconds(),
            })),
            Ok(None) => Ok(None),
            Err(error) => {
                native.cancel(error);
                Err(error)
            }
        }
    }
}
pub(crate) fn spawn(request: Rc<InspectionRequest>, mut intent: Intent) -> Result<Child> {
    #[cfg(test)]
    let mut trace = super::super::attachment::lab_trace::Trace::new(
        std::process::id(),
        "query_constructor",
        "parent_seal_and_intent",
        request.requested_at(),
        request.deadline(),
    );
    process::single_threaded()?;
    secret::seal_parent()?;
    intent.prepare(&request)?;
    let end = request.deadline();
    #[cfg(test)]
    trace.step("selected_socket_connections");
    let mut sockets = Sockets::connect(end, request.kind().includes_image())?;
    #[cfg(test)]
    trace.step("private_channel_and_inventory");
    let (parent_channel, child_channel) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let parent_inventory = super::super::inventory::Registration::owned(&[parent_channel.as_fd()])?;
    let child_inventory = super::super::inventory::Registration::owned(&[child_channel.as_fd()])?;
    super::super::inventory::verify()?;
    request.check_deadline()?;
    owner_admission_permitted()?;
    let parent = std::process::id() as i32;
    let born_at = vprouter_core::health::boot_seconds();
    #[cfg(test)]
    trace.step("clone_and_original_identity");
    let (pid, pidfd) = fork_with_pidfd()?;
    if pid == 0 {
        let result = (|| {
            parent_death(parent)?;
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            let null = fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                .map_err(|_| Error::DescriptorNull)?;
            for fd in 0..3 {
                dup_fixed(&null, fd, false)?;
            }
            // Stdio owns its duplicated OFD references. Do not leave a stale
            // OwnedFd alive across close_except's raw descriptor revocation.
            drop(null);
            let mut retained: Vec<_> = sockets.fds.iter().map(AsRawFd::as_raw_fd).collect();
            retained.push(child_channel.as_raw_fd());
            // Includes NO inherited profiles, canonical journal, allocation
            // OFD, namespace pins or peer pidfd. Parent owns their lifetimes.
            close_except(&retained)?;
            drop_identity(0)?;
            parent_death(parent)?;
            secret::non_dumpable()?;
            cv(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                Error::ConfinementPolicy,
            )?;
            apply_filter(&query_filter(
                &retained[..retained.len() - 1],
                child_channel.as_raw_fd(),
            ))?;
            secret::gate(&child_channel, end)?;
            if unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } != 2 {
                return Err(Error::ConfinementPolicy);
            }
            let facts = evaluate(&request, std::mem::take(&mut sockets.fds))?;
            let bytes = serde_json::to_vec(&Reply {
                request: request.digest(),
                facts,
            })
            .map_err(|_| Error::ChildFailed)?;
            if bytes.len() > 512 {
                return Err(Error::TooLarge);
            }
            check(end)?;
            ready(&child_channel, rustix::event::PollFlags::OUT, end)?;
            if net::send(
                &child_channel,
                &bytes,
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            )
            .map_err(|_| Error::ChildFailed)?
                != bytes.len()
            {
                return Err(Error::ChildFailed);
            }
            check(end)
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32).expect("atomic clone creates original child");
    intent
        .lease()
        .native_job_mut()
        .born(NativeJobKind::DockerInspection, &Some(reap.clone()));
    drop(child_inventory);
    drop(child_channel);
    let mut native = Native {
        creator: std::process::id(),
        _capacity: ChildCapacity::created(),
        intent,
        request,
        sockets,
        pid: pid as u32,
        pidfd: pidfd.expect("atomic parent clone includes pidfd"),
        reap,
        pidfd_inventory: None,
        channel: parent_channel,
        _channel_inventory: parent_inventory,
        birth: None,
        released: false,
        failure: None,
        packet: None,
    };
    let result = (|| {
        native.pidfd_inventory = Some(super::super::inventory::Registration::owned(&[native
            .pidfd
            .as_fd()])?);
        if wait_ready(&native.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| Error::ProcessUnavailable)?;
        let start = process::stat_start(&stat, pid as u32)?;
        if wait_ready(&native.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        native.reap.start.set(Some(start));
        native.birth = Some(ValidationBirth {
            pid: pid as u32,
            start,
            born_at,
            deadline: end,
        });
        check(end)
    })();
    if let Err(error) = result {
        native.cancel(error);
        RETIRED.with(|retired| retired.borrow_mut().push(native));
        return Err(error);
    }
    #[cfg(test)]
    trace.finish();
    Ok(Child {
        native: Some(native),
    })
}
fn evaluate(request: &InspectionRequest, sockets: Vec<OwnedFd>) -> Result<QueryFacts> {
    let include_image = request.kind().includes_image();
    let mut query =
        vprouter_linux::docker::fixed::Query::new(sockets, request.deadline(), include_image)
            .map_err(|_| Error::DockerUnavailable)?;
    let daemon = query.daemon().map_err(|_| Error::DockerUnavailable)?;
    let security = super::super::evidence::daemon(&daemon)?;
    if include_image {
        let image = query
            .image(&request.staging.content_id)
            .map_err(|_| Error::DockerUnavailable)?;
        super::super::evidence::image(&request.spec, &request.staging, &image)?;
    }
    let container = query
        .container(&request.spec.container_id)
        .map_err(|_| Error::DockerUnavailable)?;
    super::super::evidence::container_quiet(&request.spec, &request.staging, &container)?;
    let expected_apparmor = match security {
        super::super::evidence::DaemonSecurity::BuiltinSeccomp => "",
        super::super::evidence::DaemonSecurity::AppArmorBuiltinSeccomp => "docker-default",
    };
    if container.app_armor_profile != expected_apparmor {
        return Err(Error::UnsupportedConfiguration);
    }
    let facts = QueryFacts {
        pid: container.state.pid,
        security,
    };
    query.finish().map_err(|_| Error::DockerUnavailable)?;
    request.check_deadline()?;
    Ok(facts)
}
fn check(end: f64) -> Result<()> {
    let now = vprouter_core::health::boot_seconds();
    if !end.is_finite() || !now.is_finite() || now <= 0. || now >= end || end - now > 2. {
        return Err(Error::Deadline);
    }
    Ok(())
}
fn ready(fd: impl AsFd, flags: rustix::event::PollFlags, end: f64) -> Result<()> {
    use rustix::event::{PollFd, Timespec, poll};
    loop {
        check(end)?;
        let remaining = end - vprouter_core::health::boot_seconds();
        if !remaining.is_finite() || remaining <= 0. {
            return Err(Error::Deadline);
        }
        let timeout =
            Timespec::try_from(Duration::from_secs_f64(remaining)).map_err(|_| Error::Deadline)?;
        let mut fds = [PollFd::new(&fd, flags)];
        let result = poll(&mut fds, Some(&timeout));
        check(end)?;
        match result {
            Ok(0) => return Err(Error::Deadline),
            Ok(_) if fds[0].revents().intersects(flags) => return Ok(()),
            Ok(_) => return Err(Error::ChildFailed),
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(Error::ChildFailed),
        }
    }
}
pub(super) fn query_filter(sockets: &[i32], channel: i32) -> Vec<libc::sock_filter> {
    // No IO rule in the shared base. Each syscall below dispatches across all
    // exact FD/flags/address alternatives before refusing; an earlier failed
    // FD comparison cannot shadow another selected socket.
    let mut out = secret::fixed_read_filter(sockets, &[]);
    out.pop();
    let sends: Vec<_> = sockets
        .iter()
        .copied()
        .chain([channel])
        .map(|fd| {
            vec![
                (0, fd as u64),
                (3, (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64),
                (4, 0),
                (5, 0),
            ]
        })
        .collect();
    exact_io_alternatives(&mut out, libc::SYS_sendto, &sends);
    let mut receives: Vec<_> = sockets
        .iter()
        .map(|fd| {
            vec![
                (0, *fd as u64),
                (3, libc::MSG_DONTWAIT as u64),
                (4, 0),
                (5, 0),
            ]
        })
        .collect();
    receives.push(vec![
        (0, channel as u64),
        (3, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64),
        (4, 0),
        (5, 0),
    ]);
    exact_io_alternatives(&mut out, libc::SYS_recvfrom, &receives);
    allow_fixed_args(
        &mut out,
        libc::SYS_close,
        0,
        &sockets.iter().map(|fd| *fd as u32).collect::<Vec<_>>(),
    );
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out
}
fn exact_io_alternatives(
    out: &mut Vec<libc::sock_filter>,
    nr: libc::c_long,
    alternatives: &[Vec<(u32, u64)>],
) {
    let mut body = Vec::new();
    for alternative in alternatives {
        let parts: Vec<_> = alternative
            .iter()
            .flat_map(|(arg, value)| {
                [
                    (20 + arg * 8, (value >> 32) as u32),
                    (16 + arg * 8, *value as u32),
                ]
            })
            .collect();
        for (index, (offset, expected)) in parts.iter().enumerate() {
            body.push(libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: *offset,
            });
            body.push(libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: (2 * (parts.len() - index) - 1) as u8,
                k: *expected,
            });
        }
        body.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        });
    }
    body.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out.push(libc::sock_filter {
        code: 0x15,
        jt: 1,
        jf: 0,
        k: nr as u32,
    });
    out.push(libc::sock_filter {
        code: 0x05,
        jt: 0,
        jf: 0,
        k: body.len() as u32,
    });
    out.extend(body);
}

/// A real listener is created by this parent and inherited by a distinct
/// accepting child. The atomic socket-origin pin must still name this parent,
/// even after the only accepting child has been actually reaped.
#[cfg(test)]
fn lab_transferred_listener() -> Result<()> {
    let flags = net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK;
    let listener = net::socket_with(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        flags,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let listener_token = super::super::inventory::Registration::owned(&[listener.as_fd()])?;
    let name = format!("vprouter-listener-origin-{}", std::process::id());
    let address = net::SocketAddrUnix::new_abstract_name(name.as_bytes())
        .map_err(|_| Error::DescriptorPolicy)?;
    net::bind(&listener, &address).map_err(|_| Error::DescriptorPolicy)?;
    net::listen(&listener, 1).map_err(|_| Error::DescriptorPolicy)?;
    let client = net::socket_with(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        flags,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let client_token = super::super::inventory::Registration::owned(&[client.as_fd()])?;
    let parent = std::process::id();
    let end = vprouter_core::health::boot_seconds() + 2.;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result = (|| {
            parent_death(parent as i32)?;
            close_except(&[listener.as_raw_fd()])?;
            ready(&listener, rustix::event::PollFlags::IN, end)?;
            let accepted = net::accept_with(&listener, flags).map_err(|_| Error::ChildFailed)?;
            ready(&accepted, rustix::event::PollFlags::OUT, end)?;
            let handler = std::process::id().to_ne_bytes();
            if net::send(
                &accepted,
                &handler,
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            )
            .map_err(|_| Error::ChildFailed)?
                != handler.len()
            {
                return Err(Error::ChildFailed);
            }
            check(end)
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32);
    let pinned = pinned.expect("atomic clone parent pidfd");
    let registration = match super::super::inventory::Registration::owned(&[pinned.as_fd()]) {
        Ok(value) => value,
        Err(error) => {
            retain_fork_bundle_with_reap(
                pid,
                pinned,
                client,
                None,
                vec![listener_token, client_token],
                vec![listener],
                None,
                None,
                None,
                reap,
                None,
            );
            return Err(error);
        }
    };
    let original = Survivor {
        pid: pid as u32,
        pinned,
        _inventory: registration,
        reap,
    };
    let mut retained_fds = vec![listener];
    let mut retained_tokens = vec![listener_token, client_token];
    let result = (|| {
        net::connect(&client, &address).map_err(|_| Error::ChildFailed)?;
        let credentials = net::sockopt::socket_peercred(&client).map_err(|_| Error::ChildFailed)?;
        retained_fds.push(peer_pidfd(&client)?);
        let origin = retained_fds.last().ok_or(Error::DescriptorPolicy)?;
        retained_tokens.push(super::super::inventory::Registration::owned(&[
            origin.as_fd()
        ])?);
        if credentials.pid.as_raw_nonzero().get() as u32 != parent
            || credentials.uid != rustix::process::getuid()
            || credentials.gid != rustix::process::getgid()
            || wait_ready(origin, Duration::ZERO)?
            || pid as u32 == parent
        {
            return Err(Error::OwnershipMismatch);
        }
        ready(&client, rustix::event::PollFlags::IN, end)?;
        let mut response = [0u8; 4];
        let mut count = 0;
        while count < response.len() {
            ready(&client, rustix::event::PollFlags::IN, end)?;
            let (n, _) = net::recv(&client, &mut response[count..], RecvFlags::DONTWAIT)
                .map_err(|_| Error::ChildFailed)?;
            if n == 0 {
                return Err(Error::ChildFailed);
            }
            count += n;
        }
        if u32::from_ne_bytes(response) != original.pid {
            return Err(Error::OwnershipMismatch);
        }
        ready(&original.pinned, rustix::event::PollFlags::IN, end)?;
        if original.reap_status()? != Some(0)
            || wait_ready(origin, Duration::ZERO)?
            || net::sockopt::socket_peercred(&client).map_err(|_| Error::ChildFailed)?
                != credentials
            || !retained_tokens
                .last()
                .ok_or(Error::DescriptorPolicy)?
                .contains(origin.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        check(end)
    })();
    if let Err(error) = result {
        let Survivor {
            pid,
            pinned,
            _inventory,
            reap,
        } = original;
        retained_tokens.push(_inventory);
        retain_fork_bundle_with_reap(
            pid as i32,
            pinned,
            client,
            None,
            retained_tokens,
            retained_fds,
            None,
            None,
            None,
            reap,
            None,
        );
        return Err(error);
    }
    println!(
        "LAB_DOCKER_LISTENER_ORIGIN {{\"distinct_handler_actual_wait_zero\":true,\"original_listener_pin_live_after_handler_reap\":true,\"handler_identity_claimed\":false,\"real_docker_admission\":false}}"
    );
    Ok(())
}

#[cfg(test)]
pub(super) fn lab_filter_selftest() -> Result<()> {
    lab_transferred_listener()?;
    let mut sockets = Vec::new();
    let mut inventories = Vec::new();
    // These are non-secret protocol fixtures. The selftest proves selected
    // native socket IO/filter/FD exclusion, not real Docker admission or erasure.
    for body in [
        r#"{"Version":"26.1.5","ApiVersion":"1.45","MinAPIVersion":"1.24"}"#,
        r#"{"SecurityOptions":["name=seccomp,profile=builtin","name=cgroupns"],"CgroupDriver":"systemd","CgroupVersion":"2","OSType":"linux"}"#,
        "",
        "",
    ] {
        let (client, server) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::STREAM,
            net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let client_inventory = super::super::inventory::Registration::owned(&[client.as_fd()])?;
        let server_inventory = super::super::inventory::Registration::owned(&[server.as_fd()])?;
        let bytes = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if net::send(
            &server,
            bytes.as_bytes(),
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )
        .map_err(|_| Error::ChildFailed)?
            != bytes.len()
        {
            return Err(Error::ChildFailed);
        }
        // Keep the write peer until after the child has sent its fixed GET;
        // queued response bytes alone must not turn EPIPE into a false test.
        sockets.push(client);
        inventories.push(client_inventory);
        // A separate retained server endpoint is held in this parent only.
        SERVERS_FOR_TEST.with(|servers| servers.borrow_mut().push((server, server_inventory)));
    }
    let excluded = fs::open(
        c"/dev/null",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let excluded_inventory = super::super::inventory::Registration::owned(&[excluded.as_fd()])?;
    let excluded_number = excluded.as_raw_fd();
    let (parent_channel, child_channel) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let parent_inventory = super::super::inventory::Registration::owned(&[parent_channel.as_fd()])?;
    let child_inventory = super::super::inventory::Registration::owned(&[child_channel.as_fd()])?;
    let deadline = vprouter_core::health::boot_seconds() + 2.;
    let parent = std::process::id() as i32;
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        let result = (|| {
            parent_death(parent)?;
            let mut retained: Vec<_> = sockets.iter().map(AsRawFd::as_raw_fd).collect();
            retained.push(child_channel.as_raw_fd());
            close_except(&retained)?;
            if unsafe { libc::fcntl(excluded_number, libc::F_GETFD) } != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
            {
                return Err(Error::DescriptorPolicy);
            }
            secret::non_dumpable()?;
            cv(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                Error::ConfinementPolicy,
            )?;
            apply_filter(&query_filter(
                &retained[..retained.len() - 1],
                child_channel.as_raw_fd(),
            ))?;
            secret::lab_denials()?;
            let mut query = vprouter_linux::docker::fixed::Query::new(sockets, deadline, false)
                .map_err(|_| Error::ChildFailed)?;
            let daemon = query.daemon().map_err(|_| Error::ChildFailed)?;
            if super::super::evidence::daemon(&daemon)?
                != super::super::evidence::DaemonSecurity::BuiltinSeccomp
                || vprouter_core::secret_boundary::pristine()
            {
                return Err(Error::ChildFailed);
            }
            drop(query);
            secret::lab_denials()?;
            if net::send(
                &child_channel,
                &[1],
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            )
            .map_err(|_| Error::ChildFailed)?
                != 1
            {
                return Err(Error::ChildFailed);
            }
            Ok(())
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32);
    drop(child_inventory);
    drop(child_channel);
    let pinned = pinned.expect("atomic clone parent pidfd");
    let registration = match super::super::inventory::Registration::owned(&[pinned.as_fd()]) {
        Ok(value) => value,
        Err(error) => {
            inventories.push(parent_inventory);
            inventories.push(excluded_inventory);
            sockets.push(excluded);
            retain_fork_bundle_with_reap(
                pid,
                pinned,
                parent_channel,
                None,
                inventories,
                sockets,
                None,
                None,
                None,
                reap,
                None,
            );
            return Err(error);
        }
    };
    let original = Survivor {
        pid: pid as u32,
        pinned,
        _inventory: registration,
        reap,
    };
    let result = (|| {
        // Each exact peer returns EOF only after observing the corresponding
        // fixed request. No scheduling sleep or synthetic receipt is used.
        SERVERS_FOR_TEST.with(|servers| -> Result<()> {
            let mut servers = servers.borrow_mut();
            for (server, _) in servers.iter().take(2) {
                ready(server, rustix::event::PollFlags::IN, deadline)?;
                let mut request = [0u8; 512];
                let (n, _) = net::recv(server, &mut request, RecvFlags::DONTWAIT)
                    .map_err(|_| Error::ChildFailed)?;
                if !request[..n].starts_with(b"GET /") {
                    return Err(Error::ChildFailed);
                }
                net::shutdown(server, net::Shutdown::Write).map_err(|_| Error::ChildFailed)?;
            }
            servers.clear();
            Ok(())
        })?;
        ready(&original.pinned, rustix::event::PollFlags::IN, deadline)?;
        if original.reap_status()? != Some(0) {
            return Err(Error::ChildFailed);
        }
        let mut proof = [0; 2];
        if net::recv(
            &parent_channel,
            &mut proof,
            RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        )
        .map_err(|_| Error::ChildFailed)?
            != (1, 1)
            || proof[0] != 1
            || !excluded_inventory.contains(excluded.as_fd())
        {
            return Err(Error::DescriptorPolicy);
        }
        Ok(())
    })();
    if let Err(error) = result {
        let Survivor {
            pid,
            pinned,
            _inventory,
            reap,
        } = original;
        inventories.extend([parent_inventory, excluded_inventory, _inventory]);
        sockets.push(excluded);
        retain_fork_bundle_with_reap(
            pid as i32,
            pinned,
            parent_channel,
            None,
            inventories,
            sockets,
            None,
            None,
            None,
            reap,
            None,
        );
        return Err(error);
    }
    println!(
        "LAB_DOCKER_QUERY_FILTER {{\"native_exit_zero\":true,\"selected_http_io\":true,\"inherited_private_fd_excluded\":true,\"fork_exec_denied_before_and_after_ingress\":true,\"real_docker_admission\":false,\"requirement8_complete\":false}}"
    );
    Ok(())
}
#[cfg(test)]
thread_local! { static SERVERS_FOR_TEST: std::cell::RefCell<Vec<(OwnedFd, super::super::inventory::Registration)>> = const { std::cell::RefCell::new(Vec::new()) }; }
#[cfg(test)]
impl Accepted {
    pub(crate) fn lab_evidence(&self) -> Result<serde_json::Value> {
        let (birth, reap, at) = &self.lab_original;
        if self.creator != std::process::id()
            || reap.creator != self.creator
            || reap.pid != birth.pid
            || reap.start.get() != Some(birth.start)
            || reap.status.get() != Some(0)
            || !at.is_finite()
            || *at < birth.born_at
            || *at >= birth.deadline
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(
            serde_json::json!({"kind":self.request.kind(),"requested_at":self.request.requested_at(),
            "deadline":self.request.deadline(),"birth":birth,"verified_at":at,"actual_wait_status":reap.status.get(),
            "facts":self.facts,"original_peer_receipt":true,
            "listener_origin_pid":self.lab_listener_origin.pid.as_raw_nonzero().get(),
            "listener_origin_uid":self.lab_listener_origin.uid.as_raw(),
            "listener_origin_gid":self.lab_listener_origin.gid.as_raw(),
            "handler_identity_claimed":false}),
        )
    }
}
