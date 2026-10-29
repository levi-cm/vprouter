use crate::{Error, Result, filter, linux};
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

const MAX_REPORT: usize = 16 * 1024;
const HEADER: usize = 40;

/// Diagnostic only; exposed only after the exact original child failed.
#[cfg(feature = "lab")]
#[derive(Clone, Copy, Debug)]
pub struct LabFailure {
    pub stage: u8,
    pub code: u8,
    pub errno: i32,
    pub at: f64,
}
#[cfg(feature = "lab")]
fn decode_failure(
    bytes: &[u8],
    total: usize,
    digest: [u8; 32],
    born: f64,
    end: f64,
) -> Option<LabFailure> {
    if bytes.len() != 48
        || total != 48
        || bytes[..32] != digest
        || bytes[40] != 254
        || bytes[47] != 0
        || !(1..=31).contains(&bytes[41])
        || !(1..=31).contains(&bytes[42])
    {
        return None;
    }
    let at = f64::from_le_bytes(bytes[32..40].try_into().ok()?);
    let errno = i32::from_le_bytes(bytes[43..47].try_into().ok()?);
    if !at.is_finite()
        || !born.is_finite()
        || !end.is_finite()
        || at < born
        || at >= end
        || !(-4095..=4095).contains(&errno)
    {
        return None;
    }
    Some(LabFailure {
        stage: bytes[41],
        code: bytes[42],
        errno,
        at,
    })
}
#[cfg(feature = "lab")]
thread_local! { static LAB_STAGE: Cell<u8> = const { Cell::new(0) }; }

/// Descriptor custody only. The network owner separately binds these dedicated
/// sockets and original namespace to its private Plan and original DOWN token.
pub struct WireguardDescriptors<'a> {
    pub profiles: &'a [BorrowedFd<'a>],
    pub route: BorrowedFd<'a>,
    pub generic: BorrowedFd<'a>,
    pub namespace: BorrowedFd<'a>,
}
/// The sole additional pair for the fixed DOWN move. This is raw descriptor
/// custody; the network owner must bind its original target socket constructor
/// and launch must bind the original admitted DATA capability.
pub struct WireguardMoveTarget<'a> {
    pub route: BorrowedFd<'a>,
    pub generic: BorrowedFd<'a>,
    pub namespace: BorrowedFd<'a>,
}
struct Target {
    route: Arc<OwnedFd>,
    generic: Arc<OwnedFd>,
    namespace: OwnedFd,
    namespace_id: (u64, u64),
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Wireguard,
    Veth,
    Netfilter,
    ProducerNetfilter,
    ProducerBootstrap,
}
/// Closed, read-only cgroup metadata set for the fixed producer observation.
/// These are trusted raw mechanics, never original creation/placement authority.
pub struct ProducerDescriptors<'a> {
    pub parent: BorrowedFd<'a>,
    pub group: BorrowedFd<'a>,
    pub procs: BorrowedFd<'a>,
    pub events: BorrowedFd<'a>,
    pub kind: BorrowedFd<'a>,
    pub subtree: BorrowedFd<'a>,
}
struct ProducerPins {
    fds: [Arc<OwnedFd>; 6],
}
impl ProducerPins {
    fn verify(&self) -> Result<()> {
        for (index, fd) in self.fds.iter().enumerate() {
            let stat = rustix::fs::fstat(fd).map_err(|_| Error::Descriptor)?;
            if stat.st_uid != 0
                || stat.st_gid != 0
                || stat.st_mode & 0o022 != 0
                || (index == 1 && stat.st_mode & 0o7777 != 0o700)
                || rustix::fs::fstatfs(fd)
                    .map_err(|_| Error::Descriptor)?
                    .f_type as u64
                    != 0x63677270
            {
                return Err(Error::Descriptor);
            }
        }
        Ok(())
    }
    fn prepare(fds: ProducerDescriptors<'_>) -> Result<Self> {
        let fds = [
            fds.parent,
            fds.group,
            fds.procs,
            fds.events,
            fds.kind,
            fds.subtree,
        ];
        let mut selected = Vec::with_capacity(6);
        for (index, fd) in fds.into_iter().enumerate() {
            let stat = rustix::fs::fstat(fd).map_err(|_| Error::Descriptor)?;
            let expected = if index < 2 {
                rustix::fs::FileType::Directory
            } else {
                rustix::fs::FileType::RegularFile
            };
            if rustix::fs::FileType::from_raw_mode(stat.st_mode) != expected
                || stat.st_uid != 0
                || stat.st_gid != 0
                || rustix::fs::fstatfs(fd)
                    .map_err(|_| Error::Descriptor)?
                    .f_type as u64
                    != 0x63677270
                || rustix::fs::fcntl_getfl(fd)
                    .map_err(|_| Error::Descriptor)?
                    .contains(rustix::fs::OFlags::WRONLY)
                || rustix::fs::fcntl_getfl(fd)
                    .map_err(|_| Error::Descriptor)?
                    .contains(rustix::fs::OFlags::RDWR)
            {
                return Err(Error::Descriptor);
            }
            selected.push(Arc::new(linux::duplicate(fd)?));
        }
        Ok(Self {
            fds: selected.try_into().map_err(|_| Error::Descriptor)?,
        })
    }
}
struct Selected {
    role: Role,
    profiles: Vec<OwnedFd>,
    route: Arc<OwnedFd>,
    generic: Arc<OwnedFd>,
    namespace: OwnedFd,
    timer: Arc<OwnedFd>,
    namespace_id: (u64, u64),
    identities: Vec<(i32, u64, u64, u32)>,
    target: Option<Target>,
    producer: Option<ProducerPins>,
    ancestry: Option<Arc<crate::producer_bootstrap::Ancestry>>,
}
impl Selected {
    fn descriptors(&self) -> Vec<BorrowedFd<'_>> {
        let mut result: Vec<_> = self
            .profiles
            .iter()
            .map(AsFd::as_fd)
            .chain([
                self.route.as_fd(),
                self.generic.as_fd(),
                self.namespace.as_fd(),
                self.timer.as_fd(),
            ])
            .collect();
        if let Some(t) = &self.target {
            result.extend([t.route.as_fd(), t.generic.as_fd(), t.namespace.as_fd()]);
        }
        if let Some(p) = &self.producer {
            result.extend(p.fds.iter().map(AsFd::as_fd));
        }
        if let Some(a) = &self.ancestry {
            result.extend([a.root.as_fd(), a.system_slice.as_fd()]);
        }
        result
    }
    fn socket_numbers(&self) -> Vec<i32> {
        let mut sockets = vec![self.route.as_raw_fd()];
        if self.role != Role::Veth {
            sockets.push(self.generic.as_raw_fd());
        }
        if let Some(t) = &self.target {
            sockets.push(t.route.as_raw_fd());
            if self.role != Role::Veth {
                sockets.push(t.generic.as_raw_fd());
            }
        }
        sockets
    }
    fn pin_numbers(&self) -> Vec<i32> {
        let mut pins = vec![self.namespace.as_raw_fd(), self.timer.as_raw_fd()];
        // Veth retains generic OFDs for original custody, without transaction permission.
        if self.role == Role::Veth {
            pins.push(self.generic.as_raw_fd());
        }
        if let Some(t) = &self.target {
            pins.push(t.namespace.as_raw_fd());
            if self.role == Role::Veth {
                pins.push(t.generic.as_raw_fd());
            }
        }
        if let Some(p) = &self.producer {
            pins.extend(p.fds.iter().map(|f| f.as_raw_fd()));
        }
        if let Some(a) = &self.ancestry {
            pins.extend([a.root.as_raw_fd(), a.system_slice.as_raw_fd()]);
        }
        pins
    }
    fn read_numbers(&self) -> Vec<i32> {
        let mut inputs: Vec<_> = self.profiles.iter().map(AsRawFd::as_raw_fd).collect();
        if let Some(p) = &self.producer {
            inputs.extend(p.fds[2..].iter().map(|f| f.as_raw_fd()));
        }
        inputs
    }
    fn verify(&self) -> Result<()> {
        if self.role != Role::Wireguard && !self.profiles.is_empty()
            || !matches!(self.role, Role::Wireguard | Role::Veth) && self.target.is_some()
            || matches!(self.role, Role::ProducerNetfilter | Role::ProducerBootstrap)
                != self.producer.is_some()
            || (self.role == Role::ProducerBootstrap) != self.ancestry.is_some()
        {
            return Err(Error::Protocol);
        }
        if let Some(p) = &self.producer {
            p.verify()?;
        }
        if let Some(a) = &self.ancestry {
            let p = self.producer.as_ref().ok_or(Error::Protocol)?;
            a.verify(p.fds[0].as_fd(), p.fds[1].as_fd())?;
        }
        let stat = rustix::fs::fstat(&self.namespace).map_err(|_| Error::Descriptor)?;
        if (stat.st_dev, stat.st_ino) != self.namespace_id
            || rustix::fs::fstatfs(&self.namespace)
                .map_err(|_| Error::Descriptor)?
                .f_type as u64
                != 0x6e736673
        {
            return Err(Error::Descriptor);
        }
        if let Some(t) = &self.target {
            let stat = rustix::fs::fstat(&t.namespace).map_err(|_| Error::Descriptor)?;
            if (stat.st_dev, stat.st_ino) != t.namespace_id
                || t.namespace_id == self.namespace_id
                || !self.profiles.is_empty()
                || rustix::fs::fstatfs(&t.namespace)
                    .map_err(|_| Error::Descriptor)?
                    .f_type as u64
                    != 0x6e736673
            {
                return Err(Error::Descriptor);
            }
        }
        let descriptors = self.descriptors();
        if descriptors.len() != self.identities.len() {
            return Err(Error::Descriptor);
        }
        for (fd, expected) in descriptors.into_iter().zip(&self.identities) {
            let stat = rustix::fs::fstat(fd).map_err(|_| Error::Descriptor)?;
            if (fd.as_raw_fd(), stat.st_dev, stat.st_ino, stat.st_mode) != *expected {
                return Err(Error::Descriptor);
            }
            if !rustix::io::fcntl_getfd(fd)
                .map_err(|_| Error::Descriptor)?
                .contains(rustix::io::FdFlags::CLOEXEC)
            {
                return Err(Error::Descriptor);
            }
        }
        Ok(())
    }
}
struct Preparation {
    selected: Selected,
    parent: OwnedFd,
    child: OwnedFd,
    child_gate: OwnedFd,
    origin: Rc<crate::gate::Origin>,
    digest: [u8; 32],
    end: f64,
}
/// Allocate and register the complete descriptor set BEFORE calling birth.
/// A successful birth never returns a plain error after an original child exists.
pub struct PreparedWireguard {
    creator: u32,
    inner: Option<Preparation>,
}
impl Drop for PreparedWireguard {
    fn drop(&mut self) {
        if self.creator != std::process::id()
            && let Some(inner) = self.inner.take()
        {
            // Copied parent owners may have been raw-closed by another role.
            std::mem::forget(inner);
        }
    }
}
impl PreparedWireguard {
    pub fn new(
        fds: WireguardDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        child_gate: crate::WireguardChildGate,
    ) -> Result<Self> {
        Self::prepare(
            fds,
            None,
            digest,
            end,
            child_gate,
            Role::Wireguard,
            None,
            None,
        )
    }
    pub fn for_down_move(
        fds: WireguardDescriptors<'_>,
        target: WireguardMoveTarget<'_>,
        digest: [u8; 32],
        end: f64,
        child_gate: crate::WireguardChildGate,
    ) -> Result<Self> {
        if !fds.profiles.is_empty() {
            return Err(Error::Protocol);
        }
        Self::prepare(
            fds,
            Some(target),
            digest,
            end,
            child_gate,
            Role::Wireguard,
            None,
            None,
        )
    }
    pub(crate) fn for_veth(
        fds: WireguardDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: crate::WireguardChildGate,
    ) -> Result<Self> {
        if !fds.profiles.is_empty() {
            return Err(Error::Protocol);
        }
        Self::prepare(fds, None, digest, end, gate, Role::Veth, None, None)
    }
    pub(crate) fn for_veth_move(
        fds: WireguardDescriptors<'_>,
        target: WireguardMoveTarget<'_>,
        digest: [u8; 32],
        end: f64,
        gate: crate::WireguardChildGate,
    ) -> Result<Self> {
        if !fds.profiles.is_empty() {
            return Err(Error::Protocol);
        }
        Self::prepare(fds, Some(target), digest, end, gate, Role::Veth, None, None)
    }
    pub(crate) fn for_netfilter(
        fds: WireguardDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: crate::WireguardChildGate,
    ) -> Result<Self> {
        if !fds.profiles.is_empty() {
            return Err(Error::Protocol);
        }
        Self::prepare(fds, None, digest, end, gate, Role::Netfilter, None, None)
    }
    pub(crate) fn for_producer_netfilter(
        fds: WireguardDescriptors<'_>,
        producer: ProducerDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: crate::WireguardChildGate,
    ) -> Result<Self> {
        if !fds.profiles.is_empty() {
            return Err(Error::Protocol);
        }
        Self::prepare(
            fds,
            None,
            digest,
            end,
            gate,
            Role::ProducerNetfilter,
            Some(producer),
            None,
        )
    }
    pub(crate) fn for_producer_bootstrap(
        fds: WireguardDescriptors<'_>,
        producer: ProducerDescriptors<'_>,
        ancestry: crate::producer_bootstrap::ProducerAncestryDescriptors<'_>,
        digest: [u8; 32],
        end: f64,
        gate: crate::WireguardChildGate,
    ) -> Result<Self> {
        if !fds.profiles.is_empty() {
            return Err(Error::Protocol);
        }
        Self::prepare(
            fds,
            None,
            digest,
            end,
            gate,
            Role::ProducerBootstrap,
            Some(producer),
            Some(ancestry),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        fds: WireguardDescriptors<'_>,
        target: Option<WireguardMoveTarget<'_>>,
        digest: [u8; 32],
        end: f64,
        child_gate: crate::WireguardChildGate,
        role: Role,
        producer: Option<ProducerDescriptors<'_>>,
        ancestry: Option<crate::producer_bootstrap::ProducerAncestryDescriptors<'_>>,
    ) -> Result<Self> {
        linux::preflight()?;
        linux::deadline(end)?;
        let (child_gate, origin) = child_gate.take(digest, end)?;
        if digest == [0; 32] || fds.profiles.len() > vprouter_core::config::MAX_EXITS {
            return Err(Error::Protocol);
        }
        let mut sockets = match role {
            Role::Wireguard | Role::Veth => vec![
                (fds.route, None),
                (fds.generic, Some(net::netlink::GENERIC)),
            ],
            Role::Netfilter | Role::ProducerNetfilter | Role::ProducerBootstrap => vec![
                (fds.route, Some(net::netlink::NETFILTER)),
                (fds.generic, Some(net::netlink::NETFILTER)),
            ],
        };
        if let Some(t) = &target {
            sockets.extend([(t.route, None), (t.generic, Some(net::netlink::GENERIC))]);
        }
        for (fd, protocol) in sockets {
            if net::sockopt::socket_domain(fd).map_err(|_| Error::Descriptor)?
                != net::AddressFamily::NETLINK
                || net::sockopt::socket_type(fd).map_err(|_| Error::Descriptor)?
                    != net::SocketType::RAW
                || net::sockopt::socket_protocol(fd).map_err(|_| Error::Descriptor)? != protocol
            {
                return Err(Error::Descriptor);
            }
        }
        let namespace = linux::duplicate(fds.namespace)?;
        let ns = rustix::fs::fstat(&namespace).map_err(|_| Error::Descriptor)?;
        let timer = rustix::time::timerfd_create(
            rustix::time::TimerfdClockId::Boottime,
            rustix::time::TimerfdFlags::CLOEXEC | rustix::time::TimerfdFlags::NONBLOCK,
        )
        .map_err(|_| Error::Descriptor)?;
        let at = Duration::try_from_secs_f64(end)
            .map_err(|_| Error::Deadline)?
            .checked_sub(Duration::from_nanos(1))
            .ok_or(Error::Deadline)?;
        rustix::time::timerfd_settime(
            &timer,
            rustix::time::TimerfdTimerFlags::ABSTIME,
            &rustix::time::Itimerspec {
                it_interval: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: Timespec::try_from(at).map_err(|_| Error::Deadline)?,
            },
        )
        .map_err(|_| Error::Descriptor)?;
        let producer = producer.map(ProducerPins::prepare).transpose()?;
        let ancestry = ancestry
            .map(crate::producer_bootstrap::Ancestry::prepare)
            .transpose()?
            .map(Arc::new);
        let mut selected = Selected {
            ancestry,
            producer,
            role,
            profiles: fds
                .profiles
                .iter()
                .map(|fd| linux::duplicate(*fd))
                .collect::<Result<_>>()?,
            route: Arc::new(linux::duplicate(fds.route)?),
            generic: Arc::new(linux::duplicate(fds.generic)?),
            namespace,
            timer: Arc::new(timer),
            namespace_id: (ns.st_dev, ns.st_ino),
            identities: Vec::new(),
            target: target
                .map(|t| {
                    let namespace = linux::duplicate(t.namespace)?;
                    let stat = rustix::fs::fstat(&namespace).map_err(|_| Error::Descriptor)?;
                    Ok(Target {
                        route: Arc::new(linux::duplicate(t.route)?),
                        generic: Arc::new(linux::duplicate(t.generic)?),
                        namespace,
                        namespace_id: (stat.st_dev, stat.st_ino),
                    })
                })
                .transpose()?,
        };
        selected.identities = selected
            .descriptors()
            .into_iter()
            .map(|fd| {
                let stat = rustix::fs::fstat(fd).map_err(|_| Error::Descriptor)?;
                Ok((fd.as_raw_fd(), stat.st_dev, stat.st_ino, stat.st_mode))
            })
            .collect::<Result<_>>()?;
        selected.verify()?;
        let (parent, child) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            None,
        )
        .map_err(|_| Error::Descriptor)?;
        linux::deadline(end)?;
        Ok(Self {
            creator: std::process::id(),
            inner: Some(Preparation {
                selected,
                parent,
                child,
                child_gate,
                origin,
                digest,
                end,
            }),
        })
    }
    fn get(&self) -> Result<&Preparation> {
        if self.creator != std::process::id() {
            return Err(Error::Creator);
        }
        self.inner.as_ref().ok_or(Error::Interrupted)
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let p = self.get()?;
        Ok(p.selected
            .descriptors()
            .into_iter()
            .chain([p.parent.as_fd(), p.child.as_fd(), p.child_gate.as_fd()])
            .collect())
    }
    pub fn parent_channel(&self) -> Result<BorrowedFd<'_>> {
        Ok(self.get()?.parent.as_fd())
    }
    pub fn child_channel(&self) -> Result<BorrowedFd<'_>> {
        Ok(self.get()?.child.as_fd())
    }
    pub fn child_gate(&self) -> Result<BorrowedFd<'_>> {
        Ok(self.get()?.child_gate.as_fd())
    }
    pub fn timer_owner(&self) -> Result<Arc<OwnedFd>> {
        Ok(self.get()?.selected.timer.clone())
    }
    pub fn birth(mut self) -> Result<ForkOutcome> {
        let p = self.get()?;
        linux::preflight()?;
        p.selected.verify()?;
        linux::deadline(p.end)?;
        if p.origin.reap.borrow().is_some() || p.origin.released.get() {
            return Err(Error::Creator);
        }
        if live_count() >= 64 {
            return Err(Error::Capacity);
        }
        // All fallible allocation/preparation precedes clone; the parent outcome
        // takes custody immediately, before pidfd registration or proc stat work.
        let original_parent = self.creator;
        let born_at = vprouter_core::health::boot_seconds();
        let (pid, pidfd) = linux::atomic_fork()?;
        let p = self.inner.take().expect("prevalidated preparation");
        if pid == 0 {
            drop(p.parent);
            let installed: Result<ConfinedWireguard> = (|| {
                let keep: Vec<_> = p
                    .selected
                    .descriptors()
                    .iter()
                    .map(AsRawFd::as_raw_fd)
                    .chain([p.child.as_raw_fd(), p.child_gate.as_raw_fd()])
                    .collect();
                linux::child_setup(&keep, p.selected.namespace.as_fd(), original_parent)?;
                let inputs = p.selected.read_numbers();
                let sockets = p.selected.socket_numbers();
                let pins = p.selected.pin_numbers();
                let policy = if let Some(ancestry) = &p.selected.ancestry {
                    let producer = p.selected.producer.as_ref().ok_or(Error::Protocol)?;
                    filter::producer_bootstrap(
                        &inputs,
                        &sockets,
                        &pins,
                        p.child.as_raw_fd(),
                        p.child_gate.as_raw_fd(),
                        &ancestry.rules(producer.fds[0].as_fd()),
                    )
                } else {
                    filter::wireguard(
                        &inputs,
                        &sockets,
                        &pins,
                        p.child.as_raw_fd(),
                        p.child_gate.as_raw_fd(),
                    )
                };
                linux::install(&policy)?;
                let role = ConfinedWireguard {
                    creator: std::process::id(),
                    parent: original_parent,
                    selected: Some(p.selected),
                    channel: Some(p.child),
                    gate: Some(p.child_gate),
                    digest: p.digest,
                    end: p.end,
                };
                role.require()?;
                role.wait_gate()?;
                Ok(role)
            })();
            return match installed {
                Ok(role) => Ok(ForkOutcome::Child(role)),
                Err(_) => linux::die(122),
            };
        }
        drop(p.child);
        drop(p.child_gate);
        LIVE.with(|live| live.set((original_parent, live_count() + 1)));
        let receipt = Rc::new(ReapState {
            creator: original_parent,
            pid: pid as u32,
            start: Cell::new(None),
            status: Cell::new(None),
            completed_at: Cell::new(None),
            capacity_retired: Cell::new(false),
            #[cfg(feature = "lab")]
            gated_capacity_refused: Cell::new(false),
        });
        *p.origin.reap.borrow_mut() = Some(receipt.clone());
        let native = Native {
            creator: original_parent,
            selected: p.selected,
            channel: p.parent,
            pidfd: pidfd.expect("atomic original pidfd"),
            reap: receipt.clone(),
            digest: p.digest,
            end: p.end,
            born_at,
            origin: p.origin,
            failed: None,
            report: None,
            #[cfg(feature = "lab")]
            lab_failure: None,
            #[cfg(feature = "lab")]
            lab_diagnostic_seen: false,
            eof: false,
        };
        Ok(ForkOutcome::Parent(
            WireguardChild {
                native: Some(Guarded::new(native)),
            },
            ReapWitness { inner: receipt },
        ))
    }
}
pub enum ForkOutcome {
    Parent(WireguardChild, ReapWitness),
    Child(ConfinedWireguard),
}

/// Only the installed fixed-role branch can construct this. It does not carry
/// canonical launch permission; the private network entry consumes its own job.
pub struct ConfinedWireguard {
    creator: u32,
    parent: u32,
    selected: Option<Selected>,
    channel: Option<OwnedFd>,
    gate: Option<OwnedFd>,
    digest: [u8; 32],
    end: f64,
}
impl Drop for ConfinedWireguard {
    fn drop(&mut self) {
        linux::die(122)
    }
}
impl ConfinedWireguard {
    pub(crate) fn selected_namespace(&self) -> Result<(u64, u64)> {
        self.require()?;
        Ok(self
            .selected
            .as_ref()
            .ok_or(Error::Descriptor)?
            .namespace_id)
    }
    pub(crate) fn is_veth(&self) -> bool {
        self.selected.as_ref().is_some_and(|s| s.role == Role::Veth)
    }
    pub(crate) fn is_netfilter(&self) -> bool {
        self.selected
            .as_ref()
            .is_some_and(|s| s.role == Role::Netfilter)
    }
    pub(crate) fn is_producer_netfilter(&self) -> bool {
        self.selected
            .as_ref()
            .is_some_and(|s| s.role == Role::ProducerNetfilter)
    }
    pub(crate) fn is_producer_bootstrap(&self) -> bool {
        self.selected
            .as_ref()
            .is_some_and(|s| s.role == Role::ProducerBootstrap)
    }
    pub(crate) fn bootstrap_group(
        &self,
    ) -> Result<crate::producer_bootstrap::ConfinedProducerGroup> {
        self.require_producer_ancestry()?;
        let selected = self.selected.as_ref().ok_or(Error::Protocol)?;
        let producer = selected.producer.as_ref().ok_or(Error::Protocol)?;
        Ok(crate::producer_bootstrap::ConfinedProducerGroup::new(
            selected.ancestry.as_ref().ok_or(Error::Protocol)?.clone(),
            producer.fds[0].clone(),
            producer.fds[1].clone(),
            selected.namespace_id,
            self.end,
        ))
    }
    pub(crate) fn require_producer_ancestry(&self) -> Result<()> {
        if !self.is_producer_bootstrap() {
            return Err(Error::Protocol);
        }
        self.require()
    }
    pub(crate) fn producer_owners(&self) -> Result<[Arc<OwnedFd>; 6]> {
        self.require()?;
        if !self.is_producer_netfilter() && !self.is_producer_bootstrap() {
            return Err(Error::Protocol);
        }
        Ok(self
            .selected
            .as_ref()
            .and_then(|s| s.producer.as_ref())
            .ok_or(Error::Protocol)?
            .fds
            .clone())
    }
    pub fn require(&self) -> Result<()> {
        if self.creator != std::process::id() || self.creator == self.parent {
            return Err(Error::Creator);
        }
        linux::deadline(self.end)?;
        self.selected.as_ref().ok_or(Error::Descriptor)?.verify()
    }
    pub fn deadline(&self) -> f64 {
        self.end
    }
    pub fn profile_descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.require()?;
        Ok(self
            .selected
            .as_ref()
            .ok_or(Error::Descriptor)?
            .profiles
            .iter()
            .map(AsFd::as_fd)
            .collect())
    }
    pub fn socket_descriptors(&self) -> Result<[BorrowedFd<'_>; 2]> {
        self.require()?;
        let s = self.selected.as_ref().ok_or(Error::Descriptor)?;
        Ok([s.route.as_fd(), s.generic.as_fd()])
    }
    pub fn move_target_descriptors(&self) -> Result<[BorrowedFd<'_>; 2]> {
        self.require()?;
        let t = self
            .selected
            .as_ref()
            .and_then(|s| s.target.as_ref())
            .ok_or(Error::Descriptor)?;
        Ok([t.route.as_fd(), t.generic.as_fd()])
    }
    /// Shared ownership of the SAME selected descriptor, without a new dup or
    /// any additional syscall authority. Used by network's private Socket codec.
    pub fn socket_owners(&self) -> Result<[Arc<OwnedFd>; 2]> {
        self.require()?;
        let s = self.selected.as_ref().ok_or(Error::Descriptor)?;
        Ok([s.route.clone(), s.generic.clone()])
    }
    pub fn move_target_sockets(&self) -> Result<[Arc<OwnedFd>; 2]> {
        self.require()?;
        let t = self
            .selected
            .as_ref()
            .and_then(|s| s.target.as_ref())
            .ok_or(Error::Descriptor)?;
        Ok([t.route.clone(), t.generic.clone()])
    }
    pub fn move_target_namespace(&self) -> Result<(BorrowedFd<'_>, (u64, u64))> {
        self.require()?;
        let t = self
            .selected
            .as_ref()
            .and_then(|s| s.target.as_ref())
            .ok_or(Error::Descriptor)?;
        Ok((t.namespace.as_fd(), t.namespace_id))
    }
    pub fn timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.require()?;
        Ok(self
            .selected
            .as_ref()
            .ok_or(Error::Descriptor)?
            .timer
            .clone())
    }
    pub fn timer_descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.require()?;
        Ok(self
            .selected
            .as_ref()
            .ok_or(Error::Descriptor)?
            .timer
            .as_fd())
    }
    fn wait(&self, fd: BorrowedFd<'_>, flags: PollFlags) -> Result<()> {
        self.require()?;
        let remain = Duration::try_from_secs_f64(self.end - vprouter_core::health::boot_seconds())
            .map_err(|_| Error::Deadline)?;
        let mut fds = [
            PollFd::new(&fd, flags),
            PollFd::new(
                &self.selected.as_ref().ok_or(Error::Descriptor)?.timer,
                PollFlags::IN,
            ),
        ];
        rustix::event::poll(
            &mut fds,
            Some(&Timespec::try_from(remain).map_err(|_| Error::Deadline)?),
        )
        .map_err(|_| Error::Native)?;
        self.require()?;
        if !fds[1].revents().is_empty()
            || fds[0]
                .revents()
                .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
        {
            return Err(Error::Interrupted);
        }
        Ok(())
    }
    fn wait_gate(&self) -> Result<()> {
        loop {
            self.wait(
                self.gate.as_ref().ok_or(Error::Descriptor)?.as_fd(),
                PollFlags::IN,
            )?;
            let mut byte = [0u8; 1];
            match net::recv(
                self.gate.as_ref().ok_or(Error::Descriptor)?,
                &mut byte,
                RecvFlags::DONTWAIT | RecvFlags::TRUNC,
            ) {
                Ok((1, 1)) if byte == [1] => return self.require(),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => continue,
                _ => return Err(Error::Protocol),
            }
        }
    }
    /// Fixed network code supplies only its bounded public projection. This
    /// native packet alone is never accepted by an external DownLink constructor.
    pub fn finish(self, public: &[u8]) -> ! {
        let result = (|| {
            self.require()?;
            if public.is_empty() || public.len() > MAX_REPORT {
                return Err(Error::Protocol);
            }
            let mut packet = Vec::with_capacity(HEADER + public.len());
            packet.extend_from_slice(&self.digest);
            packet.extend_from_slice(&vprouter_core::health::boot_seconds().to_le_bytes());
            packet.extend_from_slice(public);
            loop {
                self.wait(
                    self.channel.as_ref().ok_or(Error::Descriptor)?.as_fd(),
                    PollFlags::OUT,
                )?;
                match net::send(
                    self.channel.as_ref().ok_or(Error::Descriptor)?,
                    &packet,
                    SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
                ) {
                    Ok(n) if n == packet.len() => break,
                    Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => continue,
                    _ => return Err(Error::Protocol),
                }
            }
            self.require()
        })();
        // All key/raw buffers are explicitly dropped by the fixed network entry
        // before it calls finish. This exit does not claim inherited Rust Drop.
        linux::die(if result.is_ok() { 0 } else { 122 })
    }
    #[cfg(feature = "lab")]
    pub fn lab_stage(&self, stage: u8) {
        if self.creator == std::process::id() {
            LAB_STAGE.with(|s| s.set(stage));
        }
    }
    #[cfg(feature = "lab")]
    pub fn lab_fail(self, code: u8, errno: i32) -> ! {
        if self.creator == std::process::id() {
            let mut packet = [0u8; 48];
            packet[..32].copy_from_slice(&self.digest);
            packet[32..40].copy_from_slice(&vprouter_core::health::boot_seconds().to_le_bytes());
            packet[40] = 254;
            packet[41] = LAB_STAGE.with(|s| s.get());
            packet[42] = code;
            packet[43..47].copy_from_slice(&errno.to_le_bytes());
            if let Some(channel) = &self.channel {
                // Single nonblocking attempt. Never wait/renew to recover diagnostics.
                let _ = net::send(channel, &packet, SendFlags::DONTWAIT | SendFlags::NOSIGNAL);
            }
        }
        linux::die(122)
    }
    pub fn fail(self) -> ! {
        linux::die(122)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Birth {
    pub pid: u32,
    pub start: u64,
    pub born_at: f64,
    pub deadline: f64,
}
pub(crate) struct ReapState {
    pub(crate) creator: u32,
    pub(crate) pid: u32,
    pub(crate) start: Cell<Option<u64>>,
    pub(crate) status: Cell<Option<i32>>,
    // Set only by final successful original protocol completion, not waitpid.
    pub(crate) completed_at: Cell<Option<f64>>,
    pub(crate) capacity_retired: Cell<bool>,
    #[cfg(feature = "lab")]
    pub(crate) gated_capacity_refused: Cell<bool>,
}
impl ReapState {
    pub(crate) fn release_capacity_on_drop(&self) {
        if self.creator == std::process::id() && !self.capacity_retired.replace(true) {
            remove_capacity();
        }
    }
}
#[derive(Clone)]
pub struct ReapWitness {
    pub(crate) inner: Rc<ReapState>,
}
impl ReapWitness {
    /// Trusted constructor mechanics only: eligibility to retire the original
    /// child-capacity charge. This is not resource collection, canonical ACK,
    /// current observation, or permission to use any retained resource.
    pub fn require_completed_capacity(&self) -> Result<()> {
        if self.inner.creator != std::process::id() {
            return Err(Error::Creator);
        }
        if self.inner.status.get() != Some(0)
            || self.inner.completed_at.get().is_none()
            || self.inner.capacity_retired.get()
        {
            return Err(Error::Native);
        }
        Ok(())
    }
    /// One-shot capacity retirement after the trusted canonical owner has
    /// accepted and retained this exact completed constructor's resources.
    /// Every descriptor, original timer and receipt remains in its owner.
    pub fn retire_completed_capacity(&self) -> Result<()> {
        self.require_completed_capacity()?;
        self.inner.capacity_retired.set(true);
        remove_capacity();
        Ok(())
    }
    /// Original constructor identity only, never native completion or resource authority.
    pub fn same_constructor(&self, other: &Self) -> Result<bool> {
        if self.inner.creator != std::process::id() || other.inner.creator != self.inner.creator {
            return Err(Error::Creator);
        }
        Ok(Rc::ptr_eq(&self.inner, &other.inner))
    }
    #[cfg(feature = "lab")]
    pub fn lab_gated_capacity_refused(&self) -> Result<bool> {
        if self.inner.creator != std::process::id() {
            return Err(Error::Creator);
        }
        Ok(self.inner.gated_capacity_refused.get())
    }
    pub fn actual_status(&self) -> Result<Option<i32>> {
        if self.inner.creator != std::process::id() {
            return Err(Error::Creator);
        }
        Ok(self.inner.status.get())
    }
    pub fn original(&self) -> Result<(u32, Option<u64>)> {
        if self.inner.creator != std::process::id() {
            return Err(Error::Creator);
        }
        Ok((self.inner.pid, self.inner.start.get()))
    }
}
struct Native {
    creator: u32,
    selected: Selected,
    channel: OwnedFd,
    pidfd: OwnedFd,
    reap: Rc<ReapState>,
    digest: [u8; 32],
    end: f64,
    born_at: f64,
    origin: Rc<crate::gate::Origin>,
    failed: Option<Error>,
    report: Option<(Vec<u8>, f64)>,
    #[cfg(feature = "lab")]
    lab_failure: Option<LabFailure>,
    #[cfg(feature = "lab")]
    lab_diagnostic_seen: bool,
    eof: bool,
}
/// Foreign fork copies never destruct potentially raw-closed or reused FDs.
struct Guarded {
    creator: u32,
    value: ManuallyDrop<Native>,
}
impl Guarded {
    fn new(value: Native) -> Self {
        Self {
            creator: value.creator,
            value: ManuallyDrop::new(value),
        }
    }
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
            // SAFETY: sole creator-side owner, exactly one ManuallyDrop release.
            unsafe { ManuallyDrop::drop(&mut self.value) };
        }
    }
}
thread_local! {
    static LIVE:Cell<(u32,usize)>=const{Cell::new((0,0))};
    static RETAINED:RefCell<Vec<Guarded>>=const{RefCell::new(Vec::new())};
}
pub(crate) fn add_capacity() {
    LIVE.with(|live| live.set((std::process::id(), live_count() + 1)));
}
pub(crate) fn remove_capacity() {
    LIVE.with(|live| {
        live.set((
            std::process::id(),
            live_count()
                .checked_sub(1)
                .expect("original child capacity"),
        ))
    });
}
pub(crate) fn live_count() -> usize {
    LIVE.with(|live| {
        let (creator, count) = live.get();
        if creator == std::process::id() {
            count
        } else {
            0
        }
    })
}
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator == std::process::id() {
            Ok(())
        } else {
            Err(Error::Creator)
        }
    }
    fn collect(&mut self) -> Result<Option<i32>> {
        self.creator()?;
        if let Some(status) = self.reap.status.get() {
            return Ok(Some(status));
        }
        if let Some(status) = linux::reap(self.reap.pid)? {
            self.reap.status.set(Some(status));
        }
        Ok(self.reap.status.get())
    }
    fn cancel(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failed.get_or_insert(error);
        let _ = net::shutdown(&self.channel, net::Shutdown::Both);
        if self.reap.status.get().is_none() {
            let _ = linux::kill(self.pidfd.as_fd());
        }
    }
    fn receive(&mut self) -> Result<()> {
        let result = self.receive_inner();
        #[cfg(feature = "lab")]
        if result.is_err() {
            self.lab_failure = None;
            if self.lab_diagnostic_seen {
                self.report = None;
            }
        }
        result
    }
    fn receive_inner(&mut self) -> Result<()> {
        for _ in 0..3 {
            let mut bytes = [0u8; HEADER + MAX_REPORT];
            match net::recv(
                &self.channel,
                &mut bytes,
                RecvFlags::DONTWAIT | RecvFlags::TRUNC,
            ) {
                Err(rustix::io::Errno::AGAIN) => return Ok(()),
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return Err(Error::Protocol),
                Ok((0, 0)) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok((n, total)) => {
                    #[cfg(feature = "lab")]
                    if n > HEADER && bytes[HEADER] == 254 {
                        let valid_context =
                            !self.lab_diagnostic_seen && !self.eof && self.report.is_none();
                        self.lab_diagnostic_seen = true;
                        self.report = None;
                        self.lab_failure = if valid_context {
                            bytes.get(..n).and_then(|bytes| {
                                decode_failure(bytes, total, self.digest, self.born_at, self.end)
                            })
                        } else {
                            None
                        };
                        // Even invalid diagnostic bytes cannot mint a success
                        // report or change the original failed-exit classification.
                        continue;
                    }
                    #[cfg(feature = "lab")]
                    if self.lab_diagnostic_seen {
                        return Err(Error::Protocol);
                    }
                    if n != total
                        || n <= HEADER
                        || self.eof
                        || self.report.is_some()
                        || bytes[..32] != self.digest
                    {
                        return Err(Error::Protocol);
                    }
                    let finished =
                        f64::from_le_bytes(bytes[32..40].try_into().map_err(|_| Error::Protocol)?);
                    if !finished.is_finite() || finished < self.born_at || finished >= self.end {
                        return Err(Error::Deadline);
                    }
                    self.report = Some((bytes[HEADER..n].to_vec(), finished));
                }
            }
        }
        Err(Error::Protocol)
    }
}
pub struct WireguardChild {
    native: Option<Guarded>,
}
impl Drop for WireguardChild {
    fn drop(&mut self) {
        if let Some(mut n) = self.native.take() {
            if n.creator != std::process::id() {
                return;
            }
            n.cancel(Error::Interrupted);
            RETAINED.with(|r| r.borrow_mut().push(n));
        }
    }
}
impl WireguardChild {
    fn get(&self) -> Result<&Native> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        n.creator()?;
        Ok(n)
    }
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        let n = self.get()?;
        Ok(n.selected
            .descriptors()
            .into_iter()
            .chain([n.channel.as_fd(), n.pidfd.as_fd()])
            .collect())
    }
    pub fn pidfd(&self) -> Result<BorrowedFd<'_>> {
        Ok(self.get()?.pidfd.as_fd())
    }
    pub fn identify(&mut self) -> Result<Birth> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        linux::deadline(n.end)?;
        let start = linux::start(n.reap.pid, n.pidfd.as_fd())?;
        if n.reap.start.get().is_some_and(|old| old != start) {
            return Err(Error::Native);
        }
        n.reap.start.set(Some(start));
        Ok(Birth {
            pid: n.reap.pid,
            start,
            born_at: n.born_at,
            deadline: n.end,
        })
    }
    pub fn reap_witness(&self) -> Result<ReapWitness> {
        Ok(ReapWitness {
            inner: self.get()?.reap.clone(),
        })
    }
    #[cfg(feature = "lab")]
    pub fn lab_failure(&self) -> Result<Option<LabFailure>> {
        let n = self.get()?;
        Ok(if n.reap.status.get().is_some_and(|status| status != 0) {
            n.lab_failure
        } else {
            None
        })
    }
    pub fn cancel(&mut self, error: Error) {
        if let Some(n) = self.native.as_mut() {
            n.cancel(error);
        }
    }
    pub fn collect(&mut self) -> Result<Option<i32>> {
        self.native.as_mut().ok_or(Error::Interrupted)?.collect()
    }
    pub fn poll(&mut self) -> Result<Option<Completed>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        n.creator()?;
        if let Some(error) = n.failed {
            let _ = n.collect();
            return Err(error);
        }
        let result = (|| {
            linux::deadline(n.end)?;
            if !n.origin.released.get() {
                return Ok(false);
            }
            n.receive()?;
            match n.collect()? {
                None => return Ok(false),
                Some(0) => (),
                Some(_) => {
                    #[cfg(feature = "lab")]
                    if linux::deadline(n.end).is_ok() {
                        // Exact child already reaped: drain only currently queued
                        // diagnostic/EOF, bounded by receive(), without waiting.
                        let _ = n.receive();
                    }
                    return Err(Error::Native);
                }
            }
            // A child may queue its final frame between EAGAIN and waitpid.
            n.receive()?;
            if !n.eof || n.report.is_none() {
                return Err(Error::Protocol);
            }
            #[cfg(feature = "lab")]
            if n.lab_diagnostic_seen {
                return Err(Error::Protocol);
            }
            n.selected.verify()?;
            linux::deadline(n.end)?;
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
                Ok(Some(Completed {
                    native: self.native.take().ok_or(Error::Interrupted)?,
                    accepted_at,
                }))
            }
            Err(error) => {
                n.cancel(error);
                Err(error)
            }
        }
    }
}
/// Only exact original channel + terminal waitpid0 + complete EOF + original
/// deadline creates this receipt. Network binds it to its original pending job.
pub struct Completed {
    native: Guarded,
    accepted_at: f64,
}
impl Completed {
    /// Original inventory after this same child's actual successful completion.
    /// The result channel and pidfd remain owned here while a caller performs
    /// resumable parent readback. No release-gate endpoint is included.
    pub fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.retained_timer_owner()?;
        Ok(self
            .native
            .selected
            .descriptors()
            .into_iter()
            .chain([self.native.channel.as_fd(), self.native.pidfd.as_fd()])
            .collect())
    }
    pub(crate) fn is_veth(&self) -> bool {
        self.native.selected.role == Role::Veth
    }
    pub(crate) fn is_netfilter(&self) -> bool {
        self.native.selected.role == Role::Netfilter
    }
    pub(crate) fn is_producer_netfilter(&self) -> bool {
        self.native.selected.role == Role::ProducerNetfilter
    }
    pub(crate) fn is_producer_bootstrap(&self) -> bool {
        self.native.selected.role == Role::ProducerBootstrap
    }

    /// Historical constructor custody only. This never makes its public
    /// readback current or authorizes another operation. The trusted network
    /// owner uses it solely to replace the SAME socket's old timer after its
    /// canonical owner has accepted this original result. The old timer stays
    /// armed and owned by this completion.
    pub fn retained_timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.native.creator()?;
        let (_, reported_at) = self.native.report.as_ref().ok_or(Error::Protocol)?;
        if self.native.reap.status.get() != Some(0)
            || self.native.failed.is_some()
            || !self.native.eof
            || !self.accepted_at.is_finite()
            || !reported_at.is_finite()
            || *reported_at < self.native.born_at
            || self.accepted_at < *reported_at
            || self.accepted_at >= self.native.end
        {
            return Err(Error::Native);
        }
        self.native.selected.verify()?;
        Ok(self.native.selected.timer.clone())
    }
    pub fn require_current(&self) -> Result<()> {
        self.native.creator()?;
        if self.native.reap.status.get() != Some(0) {
            return Err(Error::Native);
        }
        self.native.selected.verify()?;
        linux::deadline(self.native.end)
    }
    /// Exact unchanged timer ownership of this completed original operation.
    /// Cloning retains it; callers cannot rearm it through this API.
    pub fn timer_owner(&self) -> Result<Arc<OwnedFd>> {
        self.require_current()?;
        Ok(self.native.selected.timer.clone())
    }
    pub fn public_report(&self) -> Result<&[u8]> {
        self.native.creator()?;
        Ok(&self.native.report.as_ref().ok_or(Error::Protocol)?.0)
    }
    pub fn child_reported_at(&self) -> Result<f64> {
        self.native.creator()?;
        Ok(self.native.report.as_ref().ok_or(Error::Protocol)?.1)
    }
    pub fn accepted_at(&self) -> Result<f64> {
        self.native.creator()?;
        Ok(self.accepted_at)
    }
    pub fn birth(&self) -> Result<Birth> {
        self.native.creator()?;
        Ok(Birth {
            pid: self.native.reap.pid,
            start: self.native.reap.start.get().ok_or(Error::Native)?,
            born_at: self.native.born_at,
            deadline: self.native.end,
        })
    }
    pub fn reap_witness(&self) -> Result<ReapWitness> {
        self.native.creator()?;
        Ok(ReapWitness {
            inner: self.native.reap.clone(),
        })
    }
}
pub(crate) fn poll_retained() {
    RETAINED.with(|retained| {
        retained.borrow_mut().retain_mut(|n| {
            if n.creator != std::process::id() {
                return true;
            }
            n.cancel(Error::Interrupted);
            n.collect().ok().flatten().is_none()
        })
    });
}
pub(crate) fn retained_children_reaped() -> bool {
    RETAINED.with(|retained| {
        retained
            .borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reap.status.get().is_some())
    })
}

#[cfg(all(test, feature = "lab"))]
mod diagnostic_tests {
    use super::*;
    fn receiver(channel: OwnedFd) -> Native {
        let null = rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let fd = || linux::duplicate(null.as_fd()).unwrap();
        // Parser fixture only: no birth/reap/Completed capability is minted.
        Native {
            creator: std::process::id(),
            selected: Selected {
                role: Role::Wireguard,
                profiles: vec![],
                route: Arc::new(fd()),
                generic: Arc::new(fd()),
                namespace: fd(),
                timer: Arc::new(fd()),
                namespace_id: (0, 0),
                identities: vec![],
                target: None,
                producer: None,
                ancestry: None,
            },
            channel,
            pidfd: fd(),
            reap: Rc::new(ReapState {
                creator: std::process::id(),
                pid: 0,
                start: Cell::new(None),
                status: Cell::new(None),
                completed_at: Cell::new(None),
                capacity_retired: Cell::new(false),
                #[cfg(feature = "lab")]
                gated_capacity_refused: Cell::new(false),
            }),
            digest: [1; 32],
            end: 3.,
            born_at: 1.,
            origin: Rc::new(crate::gate::Origin {
                creator: std::process::id(),
                request: [1; 32],
                end: 3.,
                reap: RefCell::new(None),
                released: Cell::new(false),
            }),
            failed: None,
            report: None,
            lab_failure: None,
            lab_diagnostic_seen: false,
            eof: false,
        }
    }
    #[test]
    fn veth_selection_retains_generic_without_transaction_permission() {
        let (channel, _peer) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let mut n = receiver(channel);
        n.selected.role = Role::Veth;
        assert_eq!(
            n.selected.socket_numbers(),
            vec![n.selected.route.as_raw_fd()]
        );
        assert!(
            n.selected
                .pin_numbers()
                .contains(&n.selected.generic.as_raw_fd())
        );
        let route = Arc::new(n.selected.route.try_clone().unwrap());
        let generic = Arc::new(n.selected.generic.try_clone().unwrap());
        n.selected.target = Some(Target {
            route: route.clone(),
            generic: generic.clone(),
            namespace: n.selected.namespace.try_clone().unwrap(),
            namespace_id: n.selected.namespace_id,
        });
        assert_eq!(
            n.selected.socket_numbers(),
            vec![n.selected.route.as_raw_fd(), route.as_raw_fd()]
        );
        assert!(n.selected.pin_numbers().contains(&generic.as_raw_fd()));
        n.selected.target.take();
        n.selected.role = Role::Wireguard;
        assert_eq!(
            n.selected.socket_numbers(),
            vec![n.selected.route.as_raw_fd(), n.selected.generic.as_raw_fd()]
        );
    }
    fn packet() -> Vec<u8> {
        let mut p = vec![0; 48];
        p[..32].fill(1);
        p[32..40].copy_from_slice(&2f64.to_le_bytes());
        p[40] = 254;
        p[41] = 17;
        p[42] = 12;
        p[43..47].copy_from_slice(&1i32.to_le_bytes());
        p
    }
    #[test]
    fn actual_private_failure_frames_never_become_success_reports() {
        for fault in 0..7 {
            let (a, b) = net::socketpair(
                net::AddressFamily::UNIX,
                net::SocketType::SEQPACKET,
                net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                None,
            )
            .unwrap();
            let mut n = receiver(a);
            let mut p = packet();
            match fault {
                1 => p[0] = 2,
                2 => p[32..40].copy_from_slice(&3f64.to_le_bytes()),
                3 => p.truncate(47),
                4 => p.push(0),
                5 => p[41] = 32,
                6 => p[32..40].copy_from_slice(&f64::NAN.to_le_bytes()),
                _ => (),
            }
            net::send(&b, &p, SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
            n.receive().unwrap();
            assert!(n.report.is_none());
            assert!(n.reap.status.get().is_none());
            assert_eq!(n.lab_failure.is_some(), fault == 0);
            drop(b);
            n.receive().unwrap();
            assert!(n.eof);
        }
    }
    #[test]
    fn diagnostic_then_success_or_duplicate_cannot_upgrade_failure() {
        for duplicate in [false, true] {
            let (a, b) = net::socketpair(
                net::AddressFamily::UNIX,
                net::SocketType::SEQPACKET,
                net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                None,
            )
            .unwrap();
            let mut n = receiver(a);
            net::send(&b, &packet(), SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
            n.receive().unwrap();
            let mut second = packet();
            if !duplicate {
                second.truncate(40);
                second.extend_from_slice(b"{}");
            }
            net::send(&b, &second, SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
            if duplicate {
                n.receive().unwrap();
                assert!(n.lab_failure.is_none());
            } else {
                assert_eq!(n.receive(), Err(Error::Protocol));
            }
            assert!(n.report.is_none());
            assert!(n.reap.status.get().is_none());
        }
    }
    #[test]
    fn success_before_diagnostic_and_malformed_extra_invalidate_all_binding() {
        for reverse in [false, true] {
            let (a, b) = net::socketpair(
                net::AddressFamily::UNIX,
                net::SocketType::SEQPACKET,
                net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
                None,
            )
            .unwrap();
            let mut n = receiver(a);
            let mut success = packet();
            success.truncate(40);
            success.extend_from_slice(b"{}");
            let first = if reverse { success } else { packet() };
            net::send(&b, &first, SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
            n.receive().unwrap();
            if reverse {
                assert!(n.report.is_some());
                net::send(&b, &packet(), SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
                n.receive().unwrap();
            } else {
                assert!(n.lab_failure.is_some());
                net::send(&b, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL).unwrap();
                assert_eq!(n.receive(), Err(Error::Protocol));
            }
            assert!(n.report.is_none());
            assert!(n.lab_failure.is_none());
            assert!(n.lab_diagnostic_seen);
            drop(b);
            n.receive().unwrap();
            assert!(n.eof);
            assert!(n.reap.status.get().is_none());
        }
    }
}
