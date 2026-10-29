//! Bounded framing/transport around maintained rust-netlink payload codecs.
use crate::{Error, Result};
use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    net::{
        self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType,
        netlink::{self, SocketAddrNetlink},
    },
};
use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(crate) const MAX_PACKET: usize = 256 * 1024;
const MAX_EXCHANGE: usize = 4 * 1024 * 1024;
const MAX_MESSAGES: usize = 4096;
pub(crate) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
pub(crate) enum Completion {
    Ack,
    Single,
    Dump,
}
pub(crate) struct Socket {
    fd: Descriptor,
    port: u32,
    seq: u32,
    poisoned: bool,
    active_read: Option<u32>,
    origin: std::sync::Arc<()>,
    boot_deadline: Option<vprouter_netfilter::BootDeadline>,
    timer: Option<std::sync::Arc<OwnedFd>>,
}
enum Descriptor {
    Original(OwnedFd),
    Confined(std::sync::Arc<OwnedFd>),
}
impl AsFd for Descriptor {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Original(fd) => fd.as_fd(),
            Self::Confined(fd) => fd.as_fd(),
        }
    }
}
// Metadata-only queue proof: never receive even a prefix of raw WG traffic in
// the ordinary parent. Any readiness/error is uncertainty, with no drain/retry.
fn require_empty_queue(fd: BorrowedFd<'_>) -> Result<()> {
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    match poll(
        &mut fds,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    ) {
        Ok(0) if fds[0].revents().is_empty() => Ok(()),
        _ => Err(Error::SequenceMismatch),
    }
}
impl Socket {
    pub(crate) fn from_original_creator(
        completed: &vprouter_native_role::SocketCompletion,
        generic: bool,
    ) -> Result<Self> {
        let sockets = completed.sockets().map_err(super::secret_role::mapped)?;
        let (fd, port) = sockets[usize::from(generic)].clone();
        Ok(Self {
            fd: Descriptor::Confined(fd),
            port,
            seq: 0,
            poisoned: false,
            active_read: None,
            origin: std::sync::Arc::new(()),
            boot_deadline: None,
            timer: None,
        })
    }
    pub(crate) fn port(&self) -> u32 {
        self.port
    }
    /// Only the private fixed-role branch calls this with descriptors from its
    /// installed capability and the original dedicated socket's captured port.
    pub(crate) fn confined(
        fd: std::sync::Arc<OwnedFd>,
        port: u32,
        sequence: u32,
        role: &vprouter_native_role::ConfinedWireguard,
    ) -> Result<Self> {
        Self::confined_selected(fd, port, sequence, role, false)
    }
    pub(crate) fn confined_move_target(
        fd: std::sync::Arc<OwnedFd>,
        port: u32,
        sequence: u32,
        role: &vprouter_native_role::ConfinedWireguard,
    ) -> Result<Self> {
        Self::confined_selected(fd, port, sequence, role, true)
    }
    fn confined_selected(
        fd: std::sync::Arc<OwnedFd>,
        port: u32,
        sequence: u32,
        role: &vprouter_native_role::ConfinedWireguard,
        target: bool,
    ) -> Result<Self> {
        role.require().map_err(|_| Error::NamespaceUnverified)?;
        use std::os::fd::AsRawFd;
        let selected = if target {
            role.move_target_descriptors()
        } else {
            role.socket_descriptors()
        };
        if !selected
            .map_err(|_| Error::NamespaceUnverified)?
            .iter()
            .any(|selected| selected.as_raw_fd() == fd.as_raw_fd())
            || port == 0
        {
            return Err(Error::NamespaceUnverified);
        }
        Ok(Self {
            fd: Descriptor::Confined(fd),
            port,
            seq: sequence,
            poisoned: false,
            active_read: None,
            origin: std::sync::Arc::new(()),
            boot_deadline: Some(
                vprouter_netfilter::BootDeadline::at(role.deadline())
                    .map_err(|_| Error::Deadline)?,
            ),
            timer: Some(role.timer_owner().map_err(|_| Error::Deadline)?),
        })
    }
    pub(crate) fn confined_veth(
        fd: std::sync::Arc<OwnedFd>,
        port: u32,
        sequence: u32,
        role: &vprouter_native_role::ConfinedVeth,
    ) -> Result<Self> {
        role.require().map_err(|_| Error::NamespaceUnverified)?;
        use std::os::fd::AsRawFd;
        let selected = role.socket_descriptors();
        if !selected
            .map_err(|_| Error::NamespaceUnverified)?
            .iter()
            .any(|selected| selected.as_raw_fd() == fd.as_raw_fd())
            || port == 0
        {
            return Err(Error::NamespaceUnverified);
        }
        Ok(Self {
            fd: Descriptor::Confined(fd),
            port,
            seq: sequence,
            poisoned: false,
            active_read: None,
            origin: std::sync::Arc::new(()),
            boot_deadline: Some(
                vprouter_netfilter::BootDeadline::at(role.deadline())
                    .map_err(|_| Error::Deadline)?,
            ),
            timer: Some(role.timer_owner().map_err(|_| Error::Deadline)?),
        })
    }
    pub(crate) fn confined_veth_target(
        fd: std::sync::Arc<OwnedFd>,
        port: u32,
        sequence: u32,
        role: &vprouter_native_role::ConfinedVeth,
    ) -> Result<Self> {
        role.require().map_err(|_| Error::NamespaceUnverified)?;
        use std::os::fd::AsRawFd;
        let selected = role.move_target_descriptors();
        if !selected
            .map_err(|_| Error::NamespaceUnverified)?
            .iter()
            .any(|selected| selected.as_raw_fd() == fd.as_raw_fd())
            || port == 0
        {
            return Err(Error::NamespaceUnverified);
        }
        Ok(Self {
            fd: Descriptor::Confined(fd),
            port,
            seq: sequence,
            poisoned: false,
            active_read: None,
            origin: std::sync::Arc::new(()),
            boot_deadline: Some(
                vprouter_netfilter::BootDeadline::at(role.deadline())
                    .map_err(|_| Error::Deadline)?,
            ),
            timer: Some(role.timer_owner().map_err(|_| Error::Deadline)?),
        })
    }
    pub(crate) fn same_original_owner(&self, fd: &std::sync::Arc<OwnedFd>, port: u32) -> bool {
        matches!(&self.fd, Descriptor::Confined(original) if std::sync::Arc::ptr_eq(original, fd))
            && self.port == port
            && !self.poisoned
    }
    pub(crate) fn sequence(&self) -> Result<u32> {
        if self.poisoned || self.active_read.is_some() {
            return Err(Error::Interrupted);
        }
        Ok(self.seq)
    }
    /// Private own-child success path only. The fixed child starts from this
    /// exact sequence; actual reap/EOF and a clean receive queue precede reuse.
    pub(crate) fn accept_sequence(
        &mut self,
        completed: &vprouter_native_role::Completed,
        sequence: u32,
    ) -> Result<()> {
        completed
            .require_current()
            .map_err(super::secret_role::mapped)?;
        self.sequence()?;
        if sequence
            .checked_sub(self.seq)
            .is_none_or(|delta| delta > 4096)
        {
            return Err(Error::SequenceMismatch);
        }
        if let Err(error) = require_empty_queue(self.fd.as_fd()) {
            self.poisoned = true;
            return Err(error);
        }
        self.check_boot_deadline()?;
        self.seq = sequence;
        Ok(())
    }
    pub(crate) fn accept_veth_sequence(
        &mut self,
        completed: &vprouter_native_role::VethCompleted,
        sequence: u32,
    ) -> Result<()> {
        completed
            .require_current()
            .map_err(super::secret_role::mapped)?;
        self.sequence()?;
        if sequence
            .checked_sub(self.seq)
            .is_none_or(|delta| delta > 4096)
        {
            return Err(Error::SequenceMismatch);
        }
        if let Err(error) = require_empty_queue(self.fd.as_fd()) {
            self.poisoned = true;
            return Err(error);
        }
        self.check_boot_deadline()?;
        self.seq = sequence;
        Ok(())
    }
    pub(crate) fn finish_operation(
        &mut self,
        completed: &vprouter_native_role::Completed,
    ) -> Result<()> {
        completed
            .require_current()
            .map_err(super::secret_role::mapped)?;
        self.sequence()?;
        let original = completed
            .timer_owner()
            .map_err(super::secret_role::mapped)?;
        if self.boot_deadline.is_none()
            || self
                .timer
                .as_ref()
                .is_none_or(|t| !std::sync::Arc::ptr_eq(t, &original))
        {
            return Err(Error::Foreign);
        }
        self.check_boot_deadline()?;
        // The completed receipt retains the original armed timer, untouched.
        self.boot_deadline = None;
        self.timer = None;
        Ok(())
    }
    /// Install a NEW bound before any subsequent I/O, retaining the old accepted
    /// operation's timer unchanged in its original receipt. This is custody
    /// transfer, not a refresh of its old kernel observation.
    pub(crate) fn rebind_accepted_operation(
        &mut self,
        completed: &vprouter_native_role::Completed,
        original_sequence: u32,
        deadline: vprouter_netfilter::BootDeadline,
        timer: std::sync::Arc<OwnedFd>,
    ) -> Result<()> {
        let result = (|| {
            let old = completed
                .retained_timer_owner()
                .map_err(super::secret_role::mapped)?;
            if self.sequence()? != original_sequence
                || self.boot_deadline.is_none()
                || self
                    .timer
                    .as_ref()
                    .is_none_or(|t| !std::sync::Arc::ptr_eq(t, &old))
                || std::sync::Arc::ptr_eq(&timer, &old)
            {
                return Err(Error::Foreign);
            }
            deadline.check().map_err(|_| Error::Deadline)?;
            require_empty_queue(self.fd.as_fd())?;
            deadline.check().map_err(|_| Error::Deadline)?;
            // No native call or usable unbounded state between these stores.
            self.boot_deadline = Some(deadline);
            self.timer = Some(timer);
            self.check_boot_deadline()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub(crate) fn rebind_veth_operation(
        &mut self,
        completed: &vprouter_native_role::VethCompleted,
        original_sequence: u32,
        deadline: vprouter_netfilter::BootDeadline,
        timer: std::sync::Arc<OwnedFd>,
    ) -> Result<()> {
        let result = (|| {
            let old = completed
                .retained_timer_owner()
                .map_err(super::secret_role::mapped)?;
            if self.sequence()? != original_sequence
                || self.boot_deadline.is_none()
                || self
                    .timer
                    .as_ref()
                    .is_none_or(|t| !std::sync::Arc::ptr_eq(t, &old))
                || std::sync::Arc::ptr_eq(&timer, &old)
            {
                return Err(Error::Foreign);
            }
            deadline.check().map_err(|_| Error::Deadline)?;
            require_empty_queue(self.fd.as_fd())?;
            deadline.check().map_err(|_| Error::Deadline)?;
            // No native call or usable unbounded state between these stores.
            self.boot_deadline = Some(deadline);
            self.timer = Some(timer);
            self.check_boot_deadline()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub(crate) fn bind_cleanup_deadline(
        &mut self,
        deadline: vprouter_netfilter::BootDeadline,
        timer: std::sync::Arc<OwnedFd>,
    ) -> Result<()> {
        if self.active_read.is_some() || self.boot_deadline.is_some() || self.timer.is_some() {
            return Err(Error::InvalidInput);
        }
        deadline.check().map_err(|_| Error::Deadline)?;
        self.boot_deadline = Some(deadline);
        self.timer = Some(timer);
        Ok(())
    }
    fn check_boot_deadline(&self) -> Result<()> {
        match self.boot_deadline {
            Some(deadline) => deadline.check().map_err(|_| Error::Deadline),
            None if self.timer.is_some() => Err(Error::InvalidInput),
            None => Ok(()),
        }
    }
    pub(crate) fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.fd)
    }
    #[cfg(test)]
    pub(crate) fn unavailable_for_test() -> Self {
        Self {
            fd: Descriptor::Original(std::fs::File::open("/dev/null").unwrap().into()),
            port: 0,
            seq: u32::MAX,
            poisoned: false,
            active_read: None,
            origin: std::sync::Arc::new(()),
            boot_deadline: None,
            timer: None,
        }
    }
    pub fn open(generic: bool) -> Result<Self> {
        // NETLINK_ROUTE is protocol zero, represented as None by rustix.
        let fd = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            if generic {
                Some(netlink::GENERIC)
            } else {
                None
            },
        )
        .map_err(|_| Error::SocketUnavailable)?;
        net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(|_| Error::SocketUnavailable)?;
        let port = SocketAddrNetlink::try_from(
            net::getsockname(&fd).map_err(|_| Error::SocketUnavailable)?,
        )
        .map_err(|_| Error::SocketUnavailable)?
        .pid();
        Ok(Self {
            fd: Descriptor::Original(fd),
            port,
            seq: 0,
            poisoned: false,
            active_read: None,
            origin: std::sync::Arc::new(()),
            boot_deadline: None,
            timer: None,
        })
    }
    fn wait(&self, flags: PollFlags, end: Instant) -> Result<()> {
        loop {
            self.check_boot_deadline()?;
            let remain = end
                .checked_duration_since(Instant::now())
                .ok_or(Error::Deadline)?;
            let timeout = Timespec::try_from(remain).map_err(|_| Error::Deadline)?;
            let mut fds = vec![PollFd::new(&self.fd, flags)];
            if let Some(timer) = &self.timer {
                fds.push(PollFd::new(timer, PollFlags::IN));
            }
            match poll(&mut fds, Some(&timeout)) {
                Ok(0) => return Err(Error::Deadline),
                Ok(_)
                    if fds[0]
                        .revents()
                        .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) =>
                {
                    return Err(Error::Io);
                }
                Ok(_) => {
                    self.check_boot_deadline()?;
                    if fds.get(1).is_some_and(|fd| !fd.revents().is_empty()) {
                        return Err(Error::Deadline);
                    }
                    return Ok(());
                }
                Err(Errno::INTR) => continue,
                Err(_) => return Err(Error::Io),
            }
        }
    }
    /// Retained route-only dump. No blocking wait, raw generic/WG receive,
    /// deadline reset, or mutation message is available through this method.
    pub(crate) fn start_route_read(
        &mut self,
        payload: netlink_packet_route::RouteNetlinkMessage,
        end: Instant,
    ) -> Result<RouteRead> {
        use netlink_packet_route::RouteNetlinkMessage as N;
        let expected = match &payload {
            N::GetLink(_) => 16,
            N::GetAddress(_) => 20,
            N::GetRoute(_) => 24,
            N::GetRule(_) => 32,
            _ => return Err(Error::InvalidInput),
        };
        self.sequence()?;
        self.check_boot_deadline()?;
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        if net::sockopt::socket_domain(&self.fd).map_err(|_| Error::SocketUnavailable)?
            != AddressFamily::NETLINK
            || net::sockopt::socket_protocol(&self.fd)
                .map_err(|_| Error::SocketUnavailable)?
                .is_some()
        {
            return Err(Error::Foreign);
        }
        let seq = self.seq.checked_add(1).ok_or(Error::SequenceMismatch)?;
        let mut m = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(payload),
        );
        m.header.flags = 1 | 0x300;
        m.header.sequence_number = seq;
        m.finalize();
        if m.buffer_len() > MAX_PACKET {
            return Err(Error::Oversized);
        }
        let mut packet = Zeroizing::new(vec![0; m.buffer_len()]);
        m.serialize(&mut packet);
        let read = RouteRead {
            creator: std::process::id(),
            origin: self.origin.clone(),
            sequence: seq,
            packet,
            sent: false,
            end,
            replies: Replies::new(
                seq,
                self.port,
                m.header.message_type,
                expected,
                Completion::Dump,
            ),
            buffer: Zeroizing::new(vec![0; MAX_PACKET]),
            complete: false,
            #[cfg(feature = "lab")]
            lab_hold_after_send: false,
        };
        self.seq = seq;
        self.active_read = Some(seq);
        Ok(read)
    }
    fn route_read_ready(&self, flags: PollFlags) -> Result<bool> {
        self.check_boot_deadline()?;
        let mut fds = vec![PollFd::new(&self.fd, flags)];
        if let Some(timer) = &self.timer {
            fds.push(PollFd::new(timer, PollFlags::IN));
        }
        match poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        ) {
            Err(Errno::INTR) => Ok(false),
            Err(_) => Err(Error::Io),
            Ok(_) => {
                self.check_boot_deadline()?;
                if fds[0]
                    .revents()
                    .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
                {
                    return Err(Error::Io);
                }
                if fds.get(1).is_some_and(|f| !f.revents().is_empty()) {
                    return Err(Error::Deadline);
                }
                Ok(fds[0].revents().contains(flags))
            }
        }
    }
    pub(crate) fn owns_route_read(&self, read: &RouteRead) -> bool {
        read.creator == std::process::id() && std::sync::Arc::ptr_eq(&self.origin, &read.origin)
    }
    /// A projection or multi-phase deadline failure poisons only its original
    /// socket, even when the last datagram already completed that phase.
    pub(crate) fn reject_route_read(&mut self, read: &RouteRead) {
        if self.owns_route_read(read) {
            self.poisoned = true;
        }
    }
    /// At most one nonblocking send and one nonblocking datagram receive per
    /// call. Dropping an unfinished RouteRead leaves the original socket locked.
    pub(crate) fn poll_route_read(
        &mut self,
        read: &mut RouteRead,
    ) -> Result<Option<Vec<Zeroizing<Vec<u8>>>>> {
        if !self.owns_route_read(read) {
            return Err(Error::Foreign);
        }
        let result = (|| {
            if self.poisoned
                || read.complete
                || self.active_read != Some(read.sequence)
                || self.seq != read.sequence
            {
                return Err(Error::SequenceMismatch);
            }
            self.check_boot_deadline()?;
            if Instant::now() >= read.end {
                return Err(Error::Deadline);
            }
            if !read.sent {
                if !self.route_read_ready(PollFlags::OUT)? {
                    return Ok(None);
                }
                let sent = net::sendto(
                    &self.fd,
                    &read.packet,
                    SendFlags::DONTWAIT,
                    &SocketAddrNetlink::new(0, 0),
                );
                self.check_boot_deadline()?;
                if Instant::now() >= read.end {
                    return Err(Error::Deadline);
                }
                match sent {
                    Ok(n) if n == read.packet.len() => read.sent = true,
                    Err(Errno::AGAIN | Errno::INTR) => return Ok(None),
                    _ => return Err(Error::Io),
                }
            }
            #[cfg(feature = "lab")]
            if read.lab_hold_after_send && read.sent {
                return Ok(None);
            }
            if !self.route_read_ready(PollFlags::IN)? {
                return Ok(None);
            }
            let received = net::recvfrom(
                &self.fd,
                read.buffer.as_mut_slice(),
                RecvFlags::TRUNC | RecvFlags::DONTWAIT,
            );
            self.check_boot_deadline()?;
            if Instant::now() >= read.end {
                return Err(Error::Deadline);
            }
            let (n, actual, from) = match received {
                Ok(v) => v,
                Err(Errno::AGAIN | Errno::INTR) => return Ok(None),
                Err(Errno::NOBUFS) => return Err(Error::Oversized),
                Err(_) => return Err(Error::Io),
            };
            if actual > read.buffer.len() || n == 0 {
                return Err(Error::Oversized);
            }
            let from = SocketAddrNetlink::try_from(from.ok_or(Error::SenderMismatch)?)
                .map_err(|_| Error::SenderMismatch)?;
            if from.pid() != 0 || from.groups() != 0 {
                return Err(Error::SenderMismatch);
            }
            read.replies.ingest(&read.buffer[..n])?;
            if !read.replies.complete() {
                return Ok(None);
            }
            self.check_boot_deadline()?;
            if Instant::now() >= read.end {
                return Err(Error::Deadline);
            }
            read.complete = true;
            self.active_read = None;
            Ok(Some(std::mem::take(&mut read.replies.data)))
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn request<T: NetlinkSerializable>(
        &mut self,
        payload: T,
        extra_flags: u16,
        expected_type: u16,
        completion: Completion,
        end: Instant,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        if self.poisoned || self.active_read.is_some() {
            return Err(Error::Io);
        }
        self.seq = self.seq.checked_add(1).ok_or(Error::SequenceMismatch)?;
        let mut m = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(payload),
        );
        m.header.flags = 1
            | extra_flags
            | if matches!(completion, Completion::Dump) {
                0x300
            } else {
                4
            };
        m.header.sequence_number = self.seq;
        m.finalize();
        if m.buffer_len() > MAX_PACKET {
            return Err(Error::Oversized);
        }
        let mut packet = Zeroizing::new(vec![0; m.buffer_len()]);
        m.serialize(&mut packet);
        let result = self.exchange(
            &packet,
            m.header.message_type,
            expected_type,
            completion,
            end,
        );
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn request_borrowed<T: NetlinkSerializable>(
        &mut self,
        payload: &T,
        expected_type: u16,
        end: Instant,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        self.request(
            BorrowedMessage(payload),
            0,
            expected_type,
            Completion::Ack,
            end,
        )
    }
    fn exchange(
        &self,
        packet: &[u8],
        request_type: u16,
        expected_type: u16,
        completion: Completion,
        end: Instant,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        loop {
            self.wait(PollFlags::OUT, end)?;
            self.check_boot_deadline()?;
            let sent = net::sendto(
                &self.fd,
                packet,
                SendFlags::DONTWAIT,
                &SocketAddrNetlink::new(0, 0),
            );
            self.check_boot_deadline()?;
            match sent {
                Ok(n) if n == packet.len() => break,
                Err(Errno::AGAIN | Errno::INTR) => continue,
                _ => return Err(Error::Io),
            }
        }
        let mut replies =
            Replies::new(self.seq, self.port, request_type, expected_type, completion);
        let mut buffer = Zeroizing::new(vec![0; MAX_PACKET]);
        while !replies.complete() {
            self.wait(PollFlags::IN, end)?;
            self.check_boot_deadline()?;
            let received = net::recvfrom(
                &self.fd,
                buffer.as_mut_slice(),
                RecvFlags::TRUNC | RecvFlags::DONTWAIT,
            );
            self.check_boot_deadline()?;
            let (n, actual, from) = match received {
                Ok(v) => v,
                Err(Errno::AGAIN | Errno::INTR) => continue,
                Err(Errno::NOBUFS) => return Err(Error::Oversized),
                Err(_) => return Err(Error::Io),
            };
            if actual > buffer.len() || n == 0 {
                return Err(Error::Oversized);
            }
            let from = SocketAddrNetlink::try_from(from.ok_or(Error::SenderMismatch)?)
                .map_err(|_| Error::SenderMismatch)?;
            if from.pid() != 0 || from.groups() != 0 {
                return Err(Error::SenderMismatch);
            }
            replies.ingest(&buffer[..n])?;
        }
        self.check_boot_deadline()?;
        Ok(replies.data)
    }
}
pub(crate) struct RouteRead {
    creator: u32,
    origin: std::sync::Arc<()>,
    sequence: u32,
    packet: Zeroizing<Vec<u8>>,
    sent: bool,
    end: Instant,
    replies: Replies,
    buffer: Zeroizing<Vec<u8>>,
    complete: bool,
    #[cfg(feature = "lab")]
    lab_hold_after_send: bool,
}
#[cfg(feature = "lab")]
impl RouteRead {
    pub(crate) fn lab_hold(&mut self) {
        self.lab_hold_after_send = true;
    }
    pub(crate) fn lab_sent_sequence(&self) -> Option<u32> {
        self.sent.then_some(self.sequence)
    }
    pub(crate) fn lab_release(&mut self) -> Result<()> {
        if !self.sent
            || !self.lab_hold_after_send
            || self.creator != std::process::id()
            || Instant::now() >= self.end
        {
            return Err(Error::Foreign);
        }
        self.lab_hold_after_send = false;
        Ok(())
    }
}

struct BorrowedMessage<'a, T>(&'a T);
impl<T: NetlinkSerializable> NetlinkSerializable for BorrowedMessage<'_, T> {
    fn message_type(&self) -> u16 {
        self.0.message_type()
    }
    fn buffer_len(&self) -> usize {
        self.0.buffer_len()
    }
    fn serialize(&self, buffer: &mut [u8]) {
        self.0.serialize(buffer);
    }
}
pub(crate) struct Replies {
    seq: u32,
    port: u32,
    request_type: u16,
    expected_type: u16,
    completion: Completion,
    ack: bool,
    done: bool,
    bytes: usize,
    messages: usize,
    data: Vec<Zeroizing<Vec<u8>>>,
}
fn u16n(b: &[u8]) -> u16 {
    u16::from_ne_bytes([b[0], b[1]])
}
fn u32n(b: &[u8]) -> u32 {
    u32::from_ne_bytes([b[0], b[1], b[2], b[3]])
}
impl Replies {
    fn new(
        seq: u32,
        port: u32,
        request_type: u16,
        expected_type: u16,
        completion: Completion,
    ) -> Self {
        Self {
            seq,
            port,
            request_type,
            expected_type,
            completion,
            ack: false,
            done: false,
            bytes: 0,
            messages: 0,
            data: Vec::new(),
        }
    }
    fn complete(&self) -> bool {
        match self.completion {
            Completion::Ack => self.ack,
            Completion::Single => self.ack && self.data.len() == 1,
            Completion::Dump => self.done,
        }
    }
    fn ingest(&mut self, mut bytes: &[u8]) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(Error::Oversized)?;
        if bytes.len() > MAX_PACKET || self.bytes > MAX_EXCHANGE {
            return Err(Error::Oversized);
        }
        while !bytes.is_empty() {
            self.messages += 1;
            if self.messages > MAX_MESSAGES {
                return Err(Error::Oversized);
            }
            if self.complete() || bytes.len() < 16 {
                return Err(Error::Malformed);
            }
            let len = u32n(bytes) as usize;
            if len < 16 || len > bytes.len() {
                return Err(Error::Malformed);
            }
            let m = &bytes[..len];
            let flags = u16n(&m[6..]);
            let kind = u16n(&m[4..]);
            if u32n(&m[8..]) != self.seq {
                return Err(Error::SequenceMismatch);
            }
            if ![0, self.port].contains(&u32n(&m[12..])) {
                return Err(Error::SenderMismatch);
            }
            if flags & 0x10 != 0 {
                return Err(Error::Interrupted);
            }
            match kind {
                2 => {
                    if len < 36
                        || i32::from_ne_bytes(m[16..20].try_into().map_err(|_| Error::Malformed)?)
                            > 0
                    {
                        return Err(Error::Malformed);
                    }
                    if u32n(&m[28..]) != self.seq || u16n(&m[24..]) != self.request_type {
                        return Err(Error::SequenceMismatch);
                    }
                    if m[16..20] != [0; 4] {
                        let errno =
                            i32::from_ne_bytes(m[16..20].try_into().map_err(|_| Error::Malformed)?);
                        if errno < -4095 {
                            return Err(Error::Malformed);
                        }
                        return Err(Error::KernelErrno(-errno));
                    }
                    if self.ack || matches!(self.completion, Completion::Dump) {
                        return Err(Error::Malformed);
                    }
                    self.ack = true;
                }
                3 => {
                    if !matches!(self.completion, Completion::Dump)
                        || self.done
                        || len != 20
                        || m[16..20] != [0; 4]
                    {
                        return Err(Error::Malformed);
                    }
                    self.done = true;
                }
                4 => return Err(Error::Oversized),
                k if k == self.expected_type => {
                    if matches!(self.completion, Completion::Ack)
                        || matches!(self.completion, Completion::Single)
                            && (!self.data.is_empty() || flags & 2 != 0)
                        || matches!(self.completion, Completion::Dump) && flags & 2 == 0
                    {
                        return Err(Error::Malformed);
                    }
                    self.data.push(Zeroizing::new(m.to_vec()));
                }
                _ => return Err(Error::Malformed),
            }
            let aligned = (len + 3) & !3;
            if aligned > bytes.len() {
                if len == bytes.len() {
                    bytes = &[];
                } else {
                    return Err(Error::Malformed);
                }
            } else {
                bytes = &bytes[aligned..];
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn retained_route_read_yields_on_silent_peer_and_locks_abandoned_state() {
        let (fd, peer) = net::socketpair(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        let mut socket = Socket {
            fd: Descriptor::Original(fd),
            port: 0,
            seq: 1,
            poisoned: false,
            active_read: Some(1),
            origin: std::sync::Arc::new(()),
            boot_deadline: None,
            timer: None,
        };
        // Exact retained receive phase, with no packet available. This exercises
        // the real nonblocking syscall, not a mocked readiness Boolean.
        let mut read = RouteRead {
            creator: std::process::id(),
            origin: socket.origin.clone(),
            sequence: 1,
            packet: Zeroizing::new(vec![]),
            sent: true,
            end: Instant::now() + Duration::from_secs(1),
            replies: Replies::new(1, 0, 18, 16, Completion::Dump),
            buffer: Zeroizing::new(vec![0; MAX_PACKET]),
            complete: false,
            #[cfg(feature = "lab")]
            lab_hold_after_send: false,
        };
        for _ in 0..3 {
            assert!(socket.poll_route_read(&mut read).unwrap().is_none());
        }
        assert_eq!(socket.seq, 1);
        assert_eq!(socket.active_read, Some(1));
        net::send(&peer, b"still queued", SendFlags::DONTWAIT).unwrap();
        read.end = Instant::now();
        assert!(matches!(
            socket.poll_route_read(&mut read),
            Err(Error::Deadline)
        ));
        let mut bytes = [0; 32];
        let (n, _) = net::recv(&socket.fd, &mut bytes, RecvFlags::DONTWAIT).unwrap();
        assert_eq!(&bytes[..n], b"still queued");
        drop(read);
        assert!(socket.sequence().is_err());
        assert!(socket.poisoned);
    }
    #[test]
    fn actual_route_dump_progresses_across_nonblocking_turns_and_rejects_generic() {
        use netlink_packet_route::{RouteNetlinkMessage as N, link::LinkMessage};
        let mut route = Socket::open(false).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        let mut read = route
            .start_route_read(N::GetLink(LinkMessage::default()), end)
            .unwrap();
        assert!(route.sequence().is_err());
        let mut other = Socket::open(false).unwrap();
        let mut other_read = other
            .start_route_read(N::GetLink(LinkMessage::default()), end)
            .unwrap();
        assert_eq!(other_read.sequence, read.sequence);
        assert!(matches!(
            other.poll_route_read(&mut read),
            Err(Error::Foreign)
        ));
        assert!(!read.sent);
        assert!(!other_read.sent);
        let old_creator = read.creator;
        read.creator = old_creator.wrapping_add(1);
        assert!(matches!(
            route.poll_route_read(&mut read),
            Err(Error::Foreign)
        ));
        assert!(!read.sent);
        read.creator = old_creator;
        // Both original states still work on their exact socket after refusal.
        while other.poll_route_read(&mut other_read).unwrap().is_none() {
            std::thread::yield_now();
        }
        let data = loop {
            if let Some(data) = route.poll_route_read(&mut read).unwrap() {
                break data;
            }
            assert!(Instant::now() < end);
            std::thread::yield_now();
        };
        assert!(!data.is_empty());
        assert_eq!(route.sequence().unwrap(), 1);
        for bytes in data {
            assert!(matches!(
                crate::project::route_message(&bytes).unwrap(),
                N::NewLink(_)
            ));
        }
        let mut generic = Socket::open(true).unwrap();
        assert!(matches!(
            generic.start_route_read(N::GetLink(LinkMessage::default()), end),
            Err(Error::Foreign)
        ));
        assert_eq!(generic.sequence().unwrap(), 0);
        assert!(matches!(
            route.start_route_read(N::NewLink(LinkMessage::default()), end),
            Err(Error::InvalidInput)
        ));
        assert_eq!(route.sequence().unwrap(), 1);
        let abandoned = route
            .start_route_read(N::GetLink(LinkMessage::default()), end)
            .unwrap();
        drop(abandoned);
        assert!(route.sequence().is_err());
        assert!(
            route
                .start_route_read(N::GetLink(LinkMessage::default()), end)
                .is_err()
        );
    }

    #[test]
    fn shared_cleanup_boot_timer_prevents_late_send_despite_fresh_exchange_budget() {
        use rustix::time::{
            ClockId, Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, clock_gettime,
            timerfd_create, timerfd_settime,
        };
        use std::sync::Arc;
        let (fd, peer) = net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        let mut socket = Socket {
            fd: Descriptor::Original(fd),
            port: 0,
            seq: 0,
            poisoned: false,
            active_read: None,
            origin: std::sync::Arc::new(()),
            boot_deadline: None,
            timer: None,
        };
        let timer = Arc::new(
            timerfd_create(
                TimerfdClockId::Boottime,
                TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
            )
            .unwrap(),
        );
        let now = clock_gettime(ClockId::Boottime);
        let end_seconds = now.tv_sec as f64 + now.tv_nsec as f64 / 1e9 + 0.04;
        let original = vprouter_netfilter::BootDeadline::at(end_seconds).unwrap();
        let duration = std::time::Duration::from_secs_f64(end_seconds)
            .checked_sub(std::time::Duration::from_nanos(1))
            .unwrap();
        timerfd_settime(
            &timer,
            TimerfdTimerFlags::ABSTIME,
            &Itimerspec {
                it_interval: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: Timespec::try_from(duration).unwrap(),
            },
        )
        .unwrap();
        socket
            .bind_cleanup_deadline(original, timer.clone())
            .unwrap();
        assert_eq!(
            socket.bind_cleanup_deadline(original, timer.clone()),
            Err(Error::InvalidInput)
        );
        // Silent peer: the ordinary fresh five-second exchange budget must not
        // mask the one original shared BOOTTIME timer.
        let began = Instant::now();
        assert_eq!(
            socket.wait(PollFlags::IN, began + std::time::Duration::from_secs(5)),
            Err(Error::Deadline)
        );
        assert!(began.elapsed() < std::time::Duration::from_secs(1));
        let end = Instant::now() + std::time::Duration::from_secs(5);
        // POLLOUT is ready now, but an expired original budget must refuse before
        // sendto. Peer remains empty; no renewed operation budget can send bytes.
        assert!(matches!(
            socket.exchange(&[1], 1, 1, Completion::Ack, end),
            Err(Error::Deadline)
        ));
        let mut byte = [0; 1];
        assert_eq!(
            net::recv(&peer, &mut byte, RecvFlags::DONTWAIT),
            Err(Errno::AGAIN)
        );
    }

    use super::*;
    fn frame(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0; 16];
        b[..4].copy_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        b[4..6].copy_from_slice(&kind.to_ne_bytes());
        b[6..8].copy_from_slice(&flags.to_ne_bytes());
        b[8..12].copy_from_slice(&1u32.to_ne_bytes());
        b.extend(payload);
        b
    }
    #[test]
    fn malformed_interrupted_truncated_and_limits_fail_closed() {
        for b in [
            vec![0; 15],
            frame(16, 0x12, &[]),
            frame(4, 0, &[]),
            frame(3, 0, &[1, 0, 0, 0]),
            frame(99, 2, &[]),
        ] {
            assert!(
                Replies::new(1, 5, 18, 16, Completion::Dump)
                    .ingest(&b)
                    .is_err()
            );
        }
        let mut b = frame(16, 2, &[]);
        b[0..4].copy_from_slice(&17u32.to_ne_bytes());
        assert!(
            Replies::new(1, 5, 18, 16, Completion::Dump)
                .ingest(&b)
                .is_err()
        );
        let mut r = Replies::new(1, 5, 18, 16, Completion::Dump);
        r.bytes = MAX_EXCHANGE;
        assert_eq!(r.ingest(&frame(16, 2, &[])), Err(Error::Oversized));
        let mut r = Replies::new(1, 5, 18, 16, Completion::Dump);
        r.messages = MAX_MESSAGES;
        assert_eq!(r.ingest(&frame(16, 2, &[])), Err(Error::Oversized));
    }
    #[test]
    fn data_never_substitutes_for_mutation_ack_and_ack_binds_request() {
        let mut r = Replies::new(1, 5, 16, 16, Completion::Ack);
        assert_eq!(r.ingest(&frame(16, 0, &[])), Err(Error::Malformed));
        let embedded = frame(17, 0, &[]);
        let mut payload = vec![0; 4];
        payload.extend(embedded);
        assert_eq!(
            r.ingest(&frame(2, 0, &payload)),
            Err(Error::SequenceMismatch)
        );
    }
    #[test]
    fn single_rejects_multipart_data_in_either_ack_order() {
        let mut payload = vec![0; 4];
        payload.extend(frame(18, 0, &[]));
        let ack = frame(2, 0, &payload);
        for ack_first in [false, true] {
            let mut r = Replies::new(1, 5, 18, 16, Completion::Single);
            if ack_first {
                r.ingest(&ack).unwrap();
                assert!(!r.complete());
            }
            assert_eq!(r.ingest(&frame(16, 2, &[])), Err(Error::Malformed));
            assert!(r.data.is_empty());
            assert!(!r.complete());

            let mut r = Replies::new(1, 5, 18, 16, Completion::Single);
            let data = frame(16, 0, &[]);
            let (first, last) = if ack_first {
                (&ack, &data)
            } else {
                (&data, &ack)
            };
            r.ingest(first).unwrap();
            assert!(!r.complete());
            r.ingest(last).unwrap();
            assert!(r.complete());
            assert_eq!(r.data.len(), 1);
        }
        let mut r = Replies::new(1, 5, 18, 16, Completion::Dump);
        r.ingest(&frame(16, 2, &[])).unwrap();
        assert!(!r.complete());
        r.ingest(&frame(3, 0, &[0; 4])).unwrap();
        assert!(r.complete());
    }
    #[test]
    fn deadline_poison_and_sequence_refuse_before_io() {
        let mut s = Socket::unavailable_for_test();
        assert_eq!(
            s.wait(PollFlags::IN, Instant::now() - Duration::from_secs(1)),
            Err(Error::Deadline)
        );
        let message = netlink_packet_route::RouteNetlinkMessage::GetLink(Default::default());
        assert!(matches!(
            s.request(message.clone(), 0, 16, Completion::Dump, deadline()),
            Err(Error::SequenceMismatch)
        ));
        s.poisoned = true;
        assert!(matches!(
            s.request(message, 0, 16, Completion::Dump, deadline()),
            Err(Error::Io)
        ));
    }
}

#[cfg(test)]
mod original_queue_tests {
    use super::*;
    #[test]
    fn readiness_refusal_preserves_actual_datagram() {
        let (sender, receiver) = net::socketpair(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )
        .unwrap();
        require_empty_queue(receiver.as_fd()).unwrap();
        net::send(&sender, b"original-packet", SendFlags::DONTWAIT).unwrap();
        assert_eq!(
            require_empty_queue(receiver.as_fd()),
            Err(Error::SequenceMismatch)
        );
        let mut bytes = [0u8; 32];
        let (n, _) = net::recv(&receiver, &mut bytes, RecvFlags::DONTWAIT).unwrap();
        assert_eq!(&bytes[..n], b"original-packet");
        require_empty_queue(receiver.as_fd()).unwrap();
    }
}
