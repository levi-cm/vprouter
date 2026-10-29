//! Fixed namespace-local route/generic socket creation. No netlink request,
//! profile access or caller-selected protocol is part of this operation.
use crate::{
    Error, Result,
    gate::{Origin, WireguardChildGate},
    linux,
    wireguard::{Birth, ReapState, ReapWitness},
};
use rustix::{
    event::{PollFd, PollFlags, Timespec},
    net::{self, RecvFlags, SendFlags},
};
use std::{
    cell::{Cell, RefCell},
    mem::ManuallyDrop,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    rc::Rc,
    sync::Arc,
    time::Duration,
};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    RouteGeneric,
    NetfilterPair,
}
impl Purpose {
    fn protocol(self, second: bool) -> Option<net::Protocol> {
        match self {
            Self::RouteGeneric if second => Some(net::netlink::GENERIC),
            Self::RouteGeneric => None,
            Self::NetfilterPair => Some(net::netlink::NETFILTER),
        }
    }
    fn frame_len(self) -> usize {
        if self == Self::RouteGeneric { 40 } else { 41 }
    }
}
struct Setup {
    purpose: Purpose,
    namespace: OwnedFd,
    identity: (u64, u64),
    result: OwnedFd,
    child: OwnedFd,
    gate: OwnedFd,
    origin: Rc<Origin>,
    digest: [u8; 32],
    end: f64,
}
pub struct PreparedSockets {
    creator: u32,
    inner: Option<Setup>,
}
impl Drop for PreparedSockets {
    fn drop(&mut self) {
        if self.creator != std::process::id()
            && let Some(p) = self.inner.take()
        {
            std::mem::forget(p);
        }
    }
}
fn namespace(fd: BorrowedFd<'_>) -> Result<(u64, u64)> {
    let s = rustix::fs::fstat(fd).map_err(|_| Error::Descriptor)?;
    if rustix::fs::fstatfs(fd)
        .map_err(|_| Error::Descriptor)?
        .f_type as u64
        != 0x6e736673
    {
        return Err(Error::Descriptor);
    }
    Ok((s.st_dev, s.st_ino))
}
impl PreparedSockets {
    pub fn new(
        ns: BorrowedFd<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<Self> {
        Self::prepare(ns, digest, end, gate, Purpose::RouteGeneric)
    }
    /// Fixed two-socket nftables constructor. It performs no transactions and
    /// does not authorize policy installation or accept arbitrary protocols.
    pub fn new_netfilter(
        ns: BorrowedFd<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
    ) -> Result<Self> {
        Self::prepare(ns, digest, end, gate, Purpose::NetfilterPair)
    }
    fn prepare(
        ns: BorrowedFd<'_>,
        digest: [u8; 32],
        end: f64,
        gate: WireguardChildGate,
        purpose: Purpose,
    ) -> Result<Self> {
        linux::preflight()?;
        linux::deadline(end)?;
        let (gate, origin) = gate.take(digest, end)?;
        let gate_high = linux::duplicate(gate.as_fd())?;
        drop(gate);
        let ns = linux::duplicate(ns)?;
        let identity = namespace(ns.as_fd())?;
        let (result, child) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| Error::Descriptor)?;
        let child_high = linux::duplicate(child.as_fd())?;
        drop(child);
        Ok(Self {
            creator: std::process::id(),
            inner: Some(Setup {
                purpose,
                namespace: ns,
                identity,
                result,
                child: child_high,
                gate: gate_high,
                origin,
                digest,
                end,
            }),
        })
    }
    fn get(&self) -> Result<&Setup> {
        if self.creator != std::process::id() {
            return Err(Error::Creator);
        }
        self.inner.as_ref().ok_or(Error::Interrupted)
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let p = self.get()?;
        Ok(vec![
            p.namespace.as_fd(),
            p.result.as_fd(),
            p.child.as_fd(),
            p.gate.as_fd(),
        ])
    }
    pub fn child_endpoints(&self) -> Result<[BorrowedFd<'_>; 2]> {
        let p = self.get()?;
        Ok([p.child.as_fd(), p.gate.as_fd()])
    }
    pub fn birth(mut self) -> Result<(SocketChild, ReapWitness)> {
        linux::preflight()?;
        let p = self.get()?;
        linux::deadline(p.end)?;
        if namespace(p.namespace.as_fd())? != p.identity
            || p.origin.reap.borrow().is_some()
            || p.origin.released.get()
            || crate::wireguard::live_count() >= 64
        {
            return Err(Error::Capacity);
        }
        let p = self.inner.take().ok_or(Error::Interrupted)?;
        let born_at = vprouter_core::health::boot_seconds();
        let parent = std::process::id();
        let (pid, pidfd) = linux::atomic_fork()?;
        if pid == 0 {
            let result = child(&p, parent);
            linux::die(if result.is_ok() { 0 } else { 122 });
        }
        drop(p.child);
        drop(p.gate);
        crate::wireguard::add_capacity();
        let reap = Rc::new(ReapState {
            creator: parent,
            pid: pid as u32,
            start: Cell::new(None),
            status: Cell::new(None),
            completed_at: Cell::new(None),
            capacity_retired: Cell::new(false),
            #[cfg(feature = "lab")]
            gated_capacity_refused: Cell::new(false),
        });
        *p.origin.reap.borrow_mut() = Some(reap.clone());
        Ok((
            SocketChild {
                native: Some(Guarded {
                    creator: parent,
                    value: ManuallyDrop::new(Native {
                        purpose: p.purpose,
                        creator: parent,
                        namespace: p.namespace,
                        identity: p.identity,
                        channel: p.result,
                        pidfd: pidfd.expect("atomic original pidfd"),
                        reap: reap.clone(),
                        origin: p.origin,
                        digest: p.digest,
                        end: p.end,
                        born_at,
                        received: Vec::new(),
                        ports: None,
                        eof: false,
                        failed: None,
                    }),
                }),
            },
            ReapWitness { inner: reap },
        ))
    }
}
fn wait(fd: BorrowedFd<'_>, flags: PollFlags, end: f64) -> Result<()> {
    loop {
        linux::deadline(end)?;
        let timeout = Timespec::try_from(Duration::from_secs_f64(
            (end - vprouter_core::health::boot_seconds()).max(0.),
        ))
        .map_err(|_| Error::Deadline)?;
        let mut fds = [PollFd::new(&fd, flags)];
        let result = rustix::event::poll(&mut fds, Some(&timeout));
        linux::deadline(end)?;
        match result {
            Ok(0) => return Err(Error::Deadline),
            Ok(_) => {
                return if fds[0].revents().intersects(flags) {
                    Ok(())
                } else {
                    Err(Error::Native)
                };
            }
            Err(rustix::io::Errno::INTR) => (),
            Err(_) => return Err(Error::Native),
        }
    }
}
fn child(p: &Setup, parent: u32) -> Result<()> {
    linux::child_setup(
        &[
            p.namespace.as_raw_fd(),
            p.child.as_raw_fd(),
            p.gate.as_raw_fd(),
        ],
        p.namespace.as_fd(),
        parent,
    )?;
    // child_setup verifies current task namespace against this original pin,
    // then the installed policy denies any subsequent namespace transition.
    let filter = match p.purpose {
        Purpose::RouteGeneric => crate::filter::socket_creator,
        Purpose::NetfilterPair => crate::filter::netfilter_socket_creator,
    };
    linux::install(&filter(
        p.namespace.as_raw_fd(),
        p.child.as_raw_fd(),
        p.gate.as_raw_fd(),
    ))?;
    wait(p.gate.as_fd(), PollFlags::IN, p.end)?;
    let mut gate = [0; 2];
    if net::recv(&p.gate, &mut gate, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
        .map_err(|_| Error::Protocol)?
        != (1, 1)
        || gate[0] != 1
    {
        return Err(Error::Protocol);
    }
    linux::deadline(p.end)?;
    let route = open_socket(p.purpose, false)?;
    if route.as_raw_fd() != 3 {
        return Err(Error::Descriptor);
    }
    linux::deadline(p.end)?;
    let generic = open_socket(p.purpose, true)?;
    if generic.as_raw_fd() != 4 {
        return Err(Error::Descriptor);
    }
    let ports = [port(route.as_fd())?, port(generic.as_fd())?];
    let mut bytes = [0; 41];
    bytes[..32].copy_from_slice(&p.digest);
    bytes[32..36].copy_from_slice(&ports[0].to_le_bytes());
    bytes[36..40].copy_from_slice(&ports[1].to_le_bytes());
    bytes[40] = 1; // Netfilter-only closed discriminator; old route frame remains40.
    let rights = [route.as_fd(), generic.as_fd()];
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut ancillary = net::SendAncillaryBuffer::new(&mut space);
    if !ancillary.push(net::SendAncillaryMessage::ScmRights(&rights)) {
        return Err(Error::Protocol);
    }
    wait(p.child.as_fd(), PollFlags::OUT, p.end)?;
    if net::sendmsg(
        &p.child,
        &[std::io::IoSlice::new(&bytes[..p.purpose.frame_len()])],
        &mut ancillary,
        SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
    )
    .map_err(|_| Error::Protocol)?
        != p.purpose.frame_len()
    {
        return Err(Error::Protocol);
    }
    linux::deadline(p.end)
}
fn open_socket(purpose: Purpose, generic: bool) -> Result<OwnedFd> {
    let fd = net::socket_with(
        net::AddressFamily::NETLINK,
        net::SocketType::RAW,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        purpose.protocol(generic),
    )
    .map_err(|_| Error::Native)?;
    net::bind(&fd, &net::netlink::SocketAddrNetlink::new(0, 0)).map_err(|_| Error::Native)?;
    Ok(fd)
}
fn port(fd: BorrowedFd<'_>) -> Result<u32> {
    let a = net::netlink::SocketAddrNetlink::try_from(
        net::getsockname(fd).map_err(|_| Error::Descriptor)?,
    )
    .map_err(|_| Error::Descriptor)?;
    if a.pid() == 0 || a.groups() != 0 {
        return Err(Error::Descriptor);
    }
    Ok(a.pid())
}
fn verify_socket(fd: BorrowedFd<'_>, purpose: Purpose, generic: bool, expected: u32) -> Result<()> {
    if net::sockopt::socket_domain(fd).map_err(|_| Error::Descriptor)?
        != net::AddressFamily::NETLINK
        || net::sockopt::socket_type(fd).map_err(|_| Error::Descriptor)? != net::SocketType::RAW
        || net::sockopt::socket_protocol(fd).map_err(|_| Error::Descriptor)?
            != purpose.protocol(generic)
        || !rustix::io::fcntl_getfd(fd)
            .map_err(|_| Error::Descriptor)?
            .contains(rustix::io::FdFlags::CLOEXEC)
        || !rustix::fs::fcntl_getfl(fd)
            .map_err(|_| Error::Descriptor)?
            .contains(rustix::fs::OFlags::NONBLOCK)
        || port(fd)? != expected
    {
        return Err(Error::Descriptor);
    }
    Ok(())
}
fn clean_flags(flags: net::ReturnFlags) -> bool {
    flags.bits() & !(libc::MSG_CMSG_CLOEXEC as u32) == 0
}
struct Native {
    purpose: Purpose,
    creator: u32,
    namespace: OwnedFd,
    identity: (u64, u64),
    channel: OwnedFd,
    pidfd: OwnedFd,
    reap: Rc<ReapState>,
    origin: Rc<Origin>,
    digest: [u8; 32],
    end: f64,
    born_at: f64,
    received: Vec<Arc<OwnedFd>>,
    ports: Option<[u32; 2]>,
    eof: bool,
    failed: Option<Error>,
}
struct Guarded {
    creator: u32,
    value: ManuallyDrop<Native>,
}
impl std::ops::Deref for Guarded {
    type Target = Native;
    fn deref(&self) -> &Native {
        &self.value
    }
}
impl std::ops::DerefMut for Guarded {
    fn deref_mut(&mut self) -> &mut Native {
        &mut self.value
    }
}
impl Drop for Guarded {
    fn drop(&mut self) {
        if self.creator == std::process::id() {
            self.value.reap.release_capacity_on_drop();
            unsafe { ManuallyDrop::drop(&mut self.value) };
        }
    }
}
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            Err(Error::Creator)
        } else {
            Ok(())
        }
    }
    fn cancel(&mut self, e: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failed.get_or_insert(e);
        let _ = net::shutdown(&self.channel, net::Shutdown::Both);
        if self.reap.status.get().is_none() {
            let _ = linux::kill(self.pidfd.as_fd());
        }
    }
    fn collect(&mut self) -> Result<Option<i32>> {
        self.creator()?;
        if self.reap.status.get().is_none() {
            self.reap.status.set(linux::reap(self.reap.pid)?);
        }
        Ok(self.reap.status.get())
    }
    // Ownership is installed before examining ANY returned frame or ancillary
    // property. The launch adapter registers descriptors before poll rejects.
    fn receive(&mut self) -> Result<()> {
        self.creator()?;
        for _ in 0..2 {
            let mut bytes = [0; 42];
            let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
            let mut ancillary = net::RecvAncillaryBuffer::new(&mut space);
            let msg = match net::recvmsg(
                &self.channel,
                &mut [std::io::IoSliceMut::new(&mut bytes)],
                &mut ancillary,
                RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
            ) {
                Err(rustix::io::Errno::AGAIN) => return Ok(()),
                Err(_) => {
                    self.failed.get_or_insert(Error::Protocol);
                    return Ok(());
                }
                Ok(m) => m,
            };
            let before = self.received.len();
            let mut messages = 0;
            let mut other = false;
            for item in ancillary.drain() {
                messages += 1;
                match item {
                    net::RecvAncillaryMessage::ScmRights(fds) => {
                        self.received.extend(fds.map(Arc::new))
                    }
                    _ => other = true,
                }
            }
            if msg.bytes == 0 && messages == 0 && clean_flags(msg.flags) {
                self.eof = true;
                return Ok(());
            }
            if other
                || msg.bytes != self.purpose.frame_len()
                || (self.purpose == Purpose::NetfilterPair && bytes[40] != 1)
                || messages != 1
                || self.received.len() != before + 2
                || before != 0
                || self.ports.is_some()
                || !clean_flags(msg.flags)
                || bytes[..32] != self.digest
            {
                self.failed.get_or_insert(Error::Protocol);
                return Ok(());
            }
            self.ports = Some([
                u32::from_le_bytes(bytes[32..36].try_into().expect("fixed")),
                u32::from_le_bytes(bytes[36..40].try_into().expect("fixed")),
            ]);
        }
        Ok(())
    }
    fn verify(&self) -> Result<()> {
        self.creator()?;
        linux::deadline(self.end)?;
        self.verify_retained()?;
        linux::deadline(self.end)
    }
    fn verify_retained(&self) -> Result<()> {
        self.creator()?;
        if self.failed.is_some()
            || self.reap.status.get() != Some(0)
            || !self.eof
            || self.received.len() != 2
            || namespace(self.namespace.as_fd())? != self.identity
        {
            return Err(Error::Protocol);
        }
        let ports = self.ports.ok_or(Error::Protocol)?;
        if self.purpose == Purpose::NetfilterPair && ports[0] == ports[1] {
            return Err(Error::Protocol);
        }
        for (i, fd) in self.received.iter().enumerate() {
            verify_socket(fd.as_fd(), self.purpose, i == 1, ports[i])?;
        }
        Ok(())
    }
}
thread_local! {static RETAINED:RefCell<Vec<Guarded>>=const{RefCell::new(Vec::new())};}
pub struct SocketChild {
    native: Option<Guarded>,
}
pub struct SocketCompletion {
    native: Option<Guarded>,
    accepted_at: f64,
}
fn retain(mut n: Guarded) {
    if n.creator == std::process::id() {
        n.cancel(Error::Interrupted);
        RETAINED.with(|r| r.borrow_mut().push(n));
    }
}
impl Drop for SocketChild {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl Drop for SocketCompletion {
    fn drop(&mut self) {
        if let Some(n) = self.native.take() {
            retain(n);
        }
    }
}
impl SocketChild {
    fn get(&self) -> Result<&Guarded> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(n)
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let n = self.get()?;
        Ok([n.namespace.as_fd(), n.channel.as_fd(), n.pidfd.as_fd()]
            .into_iter()
            .chain(n.received.iter().map(|fd| fd.as_fd()))
            .collect())
    }
    pub fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        Ok(self.get()?.pidfd.as_fd())
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        Ok(ReapWitness {
            inner: self.get()?.reap.clone(),
        })
    }
    pub fn identify(&mut self) -> Result<Birth> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        linux::deadline(n.end)?;
        let start = linux::start(n.reap.pid, n.pidfd.as_fd())?;
        if n.reap.start.get().is_some_and(|old| old != start) {
            return Err(Error::Creator);
        }
        n.reap.start.set(Some(start));
        Ok(Birth {
            pid: n.reap.pid,
            start,
            born_at: n.born_at,
            deadline: n.end,
        })
    }
    /// Call, register the complete descriptor list, then poll. The poll itself
    /// performs no receive and therefore introduces no unregistered SCM FD.
    pub fn receive_native(&mut self) -> Result<()> {
        self.native.as_mut().ok_or(Error::Interrupted)?.receive()
    }
    pub fn poll(&mut self) -> Result<Option<SocketCompletion>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        let result = (|| {
            linux::deadline(n.end)?;
            if let Some(e) = n.failed {
                return Err(e);
            }
            if !n.origin.released.get() {
                return Ok(false);
            }
            if n.collect()?.is_none() {
                return Ok(false);
            }
            if !n.eof {
                return Ok(false);
            }
            n.verify()?;
            Ok(true)
        })();
        match result {
            Ok(false) => Ok(None),
            Ok(true) => {
                let accepted_at = vprouter_core::health::boot_seconds();
                linux::deadline(n.end)?;
                if !accepted_at.is_finite()
                    || !n.born_at.is_finite()
                    || !n.end.is_finite()
                    || accepted_at < n.born_at
                    || accepted_at >= n.end
                {
                    return Err(Error::Deadline);
                }
                n.reap.completed_at.set(Some(accepted_at));
                Ok(Some(SocketCompletion {
                    native: self.native.take(),
                    accepted_at,
                }))
            }
            Err(e) => {
                n.cancel(e);
                Err(e)
            }
        }
    }
    pub fn cancel(&mut self, e: Error) {
        if let Some(n) = &mut self.native {
            n.cancel(e);
        }
    }
    pub fn collect(&mut self) -> Result<Option<i32>> {
        self.native.as_mut().ok_or(Error::Interrupted)?.collect()
    }
}
impl SocketCompletion {
    /// Original actual0/EOF custody only, not renewed namespace admission.
    pub fn retained_sockets(&self) -> Result<[(Arc<OwnedFd>, u32); 2]> {
        self.retained_pair(Purpose::RouteGeneric)
    }
    pub fn retained_netfilter_sockets(&self) -> Result<[(Arc<OwnedFd>, u32); 2]> {
        self.retained_pair(Purpose::NetfilterPair)
    }
    fn retained_pair(&self, purpose: Purpose) -> Result<[(Arc<OwnedFd>, u32); 2]> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.verify_retained()?;
        if n.purpose != purpose {
            return Err(Error::Protocol);
        }
        if !self.accepted_at.is_finite()
            || self.accepted_at < n.born_at
            || self.accepted_at >= n.end
        {
            return Err(Error::Protocol);
        }
        let ports = n.ports.ok_or(Error::Protocol)?;
        Ok([
            (n.received[0].clone(), ports[0]),
            (n.received[1].clone(), ports[1]),
        ])
    }
    fn get(&self) -> Result<&Guarded> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.verify()?;
        Ok(n)
    }
    pub fn original_child(&self) -> Result<ReapWitness> {
        Ok(ReapWitness {
            inner: self.get()?.reap.clone(),
        })
    }
    pub fn namespace_identity(&self) -> Result<(u64, u64)> {
        Ok(self.get()?.identity)
    }
    pub fn sockets(&self) -> Result<[(Arc<OwnedFd>, u32); 2]> {
        self.selected_pair(Purpose::RouteGeneric)
    }
    pub fn netfilter_sockets(&self) -> Result<[(Arc<OwnedFd>, u32); 2]> {
        self.selected_pair(Purpose::NetfilterPair)
    }
    fn selected_pair(&self, purpose: Purpose) -> Result<[(Arc<OwnedFd>, u32); 2]> {
        let n = self.get()?;
        if n.purpose != purpose {
            return Err(Error::Protocol);
        }
        let ports = n.ports.ok_or(Error::Protocol)?;
        Ok([
            (n.received[0].clone(), ports[0]),
            (n.received[1].clone(), ports[1]),
        ])
    }
    pub fn accepted_at(&self) -> Result<f64> {
        self.get()?;
        Ok(self.accepted_at)
    }
    /// Original timely actual0/EOF receipt only. No clock is refreshed.
    pub fn retained_receipt(&self) -> Result<(ReapWitness, f64)> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.verify_retained()?;
        if !self.accepted_at.is_finite()
            || self.accepted_at < n.born_at
            || self.accepted_at >= n.end
        {
            return Err(Error::Protocol);
        }
        Ok((
            ReapWitness {
                inner: n.reap.clone(),
            },
            self.accepted_at,
        ))
    }
}
pub(crate) fn poll_retained() {
    RETAINED.with(|r| {
        r.borrow_mut()
            .retain_mut(|n| n.collect().ok().flatten().is_none())
    });
}
pub(crate) fn retained_children_reaped() -> bool {
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reap.status.get().is_some())
    })
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    /// This exercises real SCM delivery/ownership/framing only. The test state
    /// is never passed to collect/verify and does not mint a native completion.
    fn receiver(channel: OwnedFd) -> Native {
        let fd = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let pin = rustix::io::fcntl_dupfd_cloexec(&fd, 3).unwrap();
        let creator = std::process::id();
        Native {
            purpose: Purpose::RouteGeneric,
            creator,
            namespace: fd,
            identity: (0, 0),
            channel,
            pidfd: pin,
            reap: Rc::new(ReapState {
                creator,
                pid: 0,
                start: Cell::new(None),
                status: Cell::new(None),
                completed_at: Cell::new(None),
                capacity_retired: Cell::new(false),
                #[cfg(feature = "lab")]
                gated_capacity_refused: Cell::new(false),
            }),
            origin: Rc::new(Origin {
                creator,
                request: [1; 32],
                end: 0.,
                reap: RefCell::new(None),
                released: Cell::new(false),
            }),
            digest: [1; 32],
            end: 0.,
            born_at: 0.,
            received: Vec::new(),
            ports: None,
            eof: false,
            failed: None,
        }
    }
    fn send(channel: &OwnedFd, count: usize, length: usize, digest: u8) {
        let original = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let mut bytes = vec![digest; length];
        if length >= 40 {
            bytes[32..36].copy_from_slice(&101u32.to_le_bytes());
            bytes[36..40].copy_from_slice(&102u32.to_le_bytes());
        }
        let rights = vec![original.as_fd(); count];
        let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut ancillary = net::SendAncillaryBuffer::new(&mut space);
        if count > 0 {
            assert!(ancillary.push(net::SendAncillaryMessage::ScmRights(&rights)));
        }
        net::sendmsg(
            channel,
            &[std::io::IoSlice::new(&bytes)],
            &mut ancillary,
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        )
        .unwrap();
    }
    #[test]
    fn purpose_bound_real_scm_frames_cannot_cross_socket_roles() {
        for purpose in [Purpose::RouteGeneric, Purpose::NetfilterPair] {
            for length in [40, 41] {
                let (a, b) = net::socketpair(
                    net::AddressFamily::UNIX,
                    net::SocketType::SEQPACKET,
                    net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                    None,
                )
                .unwrap();
                let mut n = receiver(a);
                n.purpose = purpose;
                send(&b, 2, length, 1);
                n.receive().unwrap();
                assert_eq!(n.failed.is_none(), length == purpose.frame_len());
                assert_eq!(n.received.len(), 2); // Even rejected roles retain both originals.
                assert_eq!(n.reap.status.get(), None); // Parsing never fabricates native completion.
            }
        }
        assert_eq!(
            Purpose::NetfilterPair.protocol(false),
            Some(net::netlink::NETFILTER)
        );
        assert_eq!(
            Purpose::NetfilterPair.protocol(true),
            Some(net::netlink::NETFILTER)
        );
    }
    #[test]
    fn actual_scm_retains_every_delivered_fd_before_rejecting() {
        for (count, length, digest, valid) in [
            (2, 40, 1, true),
            (1, 40, 1, false),
            (3, 40, 1, false),
            (8, 40, 1, false),
            (2, 42, 1, false),
            (2, 40, 2, false),
            (0, 40, 1, false),
        ] {
            let (a, b) = net::socketpair(
                net::AddressFamily::UNIX,
                net::SocketType::SEQPACKET,
                net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                None,
            )
            .unwrap();
            let mut n = receiver(a);
            send(&b, count, length, digest);
            n.receive().unwrap();
            assert_eq!(n.failed.is_none(), valid);
            if count > 4 {
                // Ancillary alignment can fit more than the requested four
                // descriptors. Every actually delivered descriptor is owned.
                assert!((4..count).contains(&n.received.len()));
            } else {
                assert_eq!(n.received.len(), count);
            }
            for fd in &n.received {
                assert!(
                    rustix::io::fcntl_getfd(fd)
                        .unwrap()
                        .contains(rustix::io::FdFlags::CLOEXEC)
                );
                assert_eq!(
                    rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(fd).unwrap().st_mode),
                    rustix::fs::FileType::CharacterDevice
                );
            }
            assert_eq!(n.reap.status.get(), None);
            if valid {
                drop(b);
                n.receive().unwrap();
                assert!(n.eof);
                assert_eq!(n.failed, None);
            }
        }
    }
    #[test]
    fn trailing_scm_packet_is_refused_without_discarding_original_rights() {
        let (a, b) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        let mut n = receiver(a);
        send(&b, 2, 40, 1);
        n.receive().unwrap();
        assert_eq!(n.ports, Some([101, 102]));
        send(&b, 2, 40, 1);
        n.receive().unwrap();
        assert_eq!(n.failed, Some(Error::Protocol));
        assert_eq!(n.received.len(), 4);
        for fd in &n.received {
            rustix::fs::fstat(fd).unwrap();
        }
    }
}
