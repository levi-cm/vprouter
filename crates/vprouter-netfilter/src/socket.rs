use crate::BootDeadline;
use crate::{Error, Result, codec::*};
use rustix::time::{
    Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags, timerfd_create, timerfd_settime,
};
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
    time::Instant,
};

/// A socket is permanently bound to the current network namespace at open time.
/// All mutating calls require &mut, preventing overlapping request sequences.
pub(crate) struct Socket {
    fd: std::sync::Arc<OwnedFd>,
    port: u32,
    constructor_identity: Option<(u64, u64)>,
    seq: u32,
    poisoned: bool,
    timer: Option<OwnedFd>,
    boot_deadline: Option<BootDeadline>,
    shared_timer: Option<std::sync::Arc<OwnedFd>>,
}
impl Socket {
    pub(crate) fn bind_cleanup_deadline(
        &mut self,
        deadline: BootDeadline,
        timer: std::sync::Arc<OwnedFd>,
    ) -> Result<()> {
        if self.boot_deadline.is_some() || self.timer.is_some() || self.shared_timer.is_some() {
            return Err(Error::InvalidInput);
        }
        deadline.check()?;
        self.boot_deadline = Some(deadline);
        self.shared_timer = Some(timer);
        Ok(())
    }
    pub(crate) fn matches_original(&self, fd: &std::sync::Arc<OwnedFd>, port: u32) -> bool {
        std::sync::Arc::ptr_eq(&self.fd, fd) && self.port == port && !self.poisoned
    }
    pub(crate) fn require_paired_deadline(&self, other: &Self) -> Result<()> {
        let a = self.boot_deadline.ok_or(Error::Deadline)?;
        let b = other.boot_deadline.ok_or(Error::Deadline)?;
        let at = a.timespec();
        let bt = b.timespec();
        if (at.tv_sec, at.tv_nsec) != (bt.tv_sec, bt.tv_nsec)
            || self
                .shared_timer
                .as_ref()
                .zip(other.shared_timer.as_ref())
                .is_none_or(|(a, b)| !std::sync::Arc::ptr_eq(a, b))
            || self.timer.is_some()
            || other.timer.is_some()
        {
            return Err(Error::Foreign);
        }
        a.check()
    }
    pub(crate) fn descriptor(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub(crate) fn from_original_creator(fd: std::sync::Arc<OwnedFd>, port: u32) -> Result<Self> {
        let address = SocketAddrNetlink::try_from(
            net::getsockname(&fd).map_err(|_| Error::SocketUnavailable)?,
        )
        .map_err(|_| Error::SocketUnavailable)?;
        if address.pid() != port
            || port == 0
            || address.groups() != 0
            || net::sockopt::socket_domain(&fd).map_err(|_| Error::SocketUnavailable)?
                != AddressFamily::NETLINK
            || net::sockopt::socket_type(&fd).map_err(|_| Error::SocketUnavailable)?
                != SocketType::RAW
            || net::sockopt::socket_protocol(&fd).map_err(|_| Error::SocketUnavailable)?
                != Some(netlink::NETFILTER)
            || !rustix::io::fcntl_getfd(&fd)
                .map_err(|_| Error::SocketUnavailable)?
                .contains(rustix::io::FdFlags::CLOEXEC)
            || !rustix::fs::fcntl_getfl(&fd)
                .map_err(|_| Error::SocketUnavailable)?
                .contains(rustix::fs::OFlags::NONBLOCK)
        {
            return Err(Error::Foreign);
        }
        let stat = rustix::fs::fstat(&fd).map_err(|_| Error::Foreign)?;
        Ok(Self {
            constructor_identity: Some((stat.st_dev, stat.st_ino)),
            fd,
            port,
            seq: 0,
            poisoned: false,
            timer: None,
            boot_deadline: None,
            shared_timer: None,
        })
    }
    pub(crate) fn confined(
        &self,
        role: &vprouter_native_role::ConfinedNetfilter,
        index: usize,
    ) -> Result<Self> {
        use std::os::fd::AsRawFd;
        role.require().map_err(|_| Error::Foreign)?;
        if index > 1 || self.poisoned {
            return Err(Error::Foreign);
        }
        let selected = role.socket_owners().map_err(|_| Error::Foreign)?;
        let fd = selected[index].clone();
        let s = rustix::fs::fstat(&fd).map_err(|_| Error::Foreign)?;
        // Parent numeric descriptors were closed during fixed child setup.
        // Compare the original constructor's cached socket identity to the
        // selected duplicate freshly verified by the installed native role.
        if Some((s.st_dev, s.st_ino)) != self.constructor_identity
            || role.socket_descriptors().map_err(|_| Error::Foreign)?[index].as_raw_fd()
                != fd.as_raw_fd()
        {
            return Err(Error::Foreign);
        }
        Ok(Self {
            constructor_identity: self.constructor_identity,
            fd,
            port: self.port,
            seq: self.seq,
            poisoned: false,
            timer: None,
            boot_deadline: Some(BootDeadline::at(role.deadline())?),
            shared_timer: Some(role.timer_owner().map_err(|_| Error::Foreign)?),
        })
    }
    pub(crate) fn confined_producer(
        &self,
        role: &vprouter_native_role::ConfinedProducerNetfilter,
        index: usize,
    ) -> Result<Self> {
        use std::os::fd::AsRawFd;
        role.require().map_err(|_| Error::Foreign)?;
        if index > 1 || self.poisoned {
            return Err(Error::Foreign);
        }
        let selected = role.socket_owners().map_err(|_| Error::Foreign)?;
        let fd = selected[index].clone();
        let stat = rustix::fs::fstat(&fd).map_err(|_| Error::Foreign)?;
        if Some((stat.st_dev, stat.st_ino)) != self.constructor_identity
            || role.socket_descriptors().map_err(|_| Error::Foreign)?[index].as_raw_fd()
                != fd.as_raw_fd()
        {
            return Err(Error::Foreign);
        }
        Ok(Self {
            fd,
            port: self.port,
            constructor_identity: self.constructor_identity,
            seq: self.seq,
            poisoned: false,
            timer: None,
            boot_deadline: Some(BootDeadline::at(role.deadline())?),
            shared_timer: Some(role.timer_owner().map_err(|_| Error::Foreign)?),
        })
    }
    pub(crate) fn confined_bootstrap(
        &self,
        role: &vprouter_native_role::ConfinedProducerBootstrap,
        index: usize,
    ) -> Result<Self> {
        use std::os::fd::AsRawFd;
        role.require().map_err(|_| Error::Foreign)?;
        if index > 1 || self.poisoned {
            return Err(Error::Foreign);
        }
        let selected = role.socket_owners().map_err(|_| Error::Foreign)?;
        let fd = selected[index].clone();
        let stat = rustix::fs::fstat(&fd).map_err(|_| Error::Foreign)?;
        if Some((stat.st_dev, stat.st_ino)) != self.constructor_identity
            || role.socket_descriptors().map_err(|_| Error::Foreign)?[index].as_raw_fd()
                != fd.as_raw_fd()
        {
            return Err(Error::Foreign);
        }
        Ok(Self {
            fd,
            port: self.port,
            constructor_identity: self.constructor_identity,
            seq: self.seq,
            poisoned: false,
            timer: None,
            boot_deadline: Some(BootDeadline::at(role.deadline())?),
            shared_timer: Some(role.timer_owner().map_err(|_| Error::Foreign)?),
        })
    }
    /// Same original accepted socket state; never refresh the old observation.
    pub(crate) fn rebind_accepted_initial(
        &mut self,
        original: &vprouter_native_role::NetfilterCompleted,
        sequence: u32,
        end: BootDeadline,
        timer: std::sync::Arc<OwnedFd>,
    ) -> Result<()> {
        let result = (|| {
            let old = original
                .retained_timer_owner()
                .map_err(|_| Error::Foreign)?;
            if self.poisoned
                || self.seq != sequence
                || self.timer.is_some()
                || self.boot_deadline.is_none()
                || self
                    .shared_timer
                    .as_ref()
                    .is_none_or(|own| !std::sync::Arc::ptr_eq(own, &old))
                || std::sync::Arc::ptr_eq(&old, &timer)
            {
                return Err(Error::Foreign);
            }
            let mut fds = [PollFd::new(&self.fd, PollFlags::IN)];
            end.check()?;
            if !matches!(
                poll(
                    &mut fds,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                ),
                Ok(0)
            ) || !fds[0].revents().is_empty()
            {
                return Err(Error::SequenceMismatch);
            }
            end.check()?;
            self.boot_deadline = Some(end);
            self.shared_timer = Some(timer);
            self.check_boot_deadline()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub(crate) fn rebind_accepted_producer(
        &mut self,
        original: &vprouter_native_role::ProducerNetfilterCompleted,
        sequence: u32,
        end: BootDeadline,
        timer: std::sync::Arc<OwnedFd>,
    ) -> Result<()> {
        let result = (|| {
            let old = original
                .retained_timer_owner()
                .map_err(|_| Error::Foreign)?;
            if self.poisoned
                || self.seq != sequence
                || self.timer.is_some()
                || self.boot_deadline.is_none()
                || self
                    .shared_timer
                    .as_ref()
                    .is_none_or(|own| !std::sync::Arc::ptr_eq(own, &old))
                || std::sync::Arc::ptr_eq(&old, &timer)
            {
                return Err(Error::Foreign);
            }
            let mut fds = [PollFd::new(&self.fd, PollFlags::IN)];
            end.check()?;
            if !matches!(
                poll(
                    &mut fds,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                ),
                Ok(0)
            ) || !fds[0].revents().is_empty()
            {
                return Err(Error::SequenceMismatch);
            }
            end.check()?;
            self.boot_deadline = Some(end);
            self.shared_timer = Some(timer);
            self.check_boot_deadline()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub(crate) fn accept_producer_sequence(
        &mut self,
        original: &vprouter_native_role::ProducerNetfilterCompleted,
        sequence: u32,
    ) -> Result<()> {
        let result = (|| {
            original.require_current().map_err(|_| Error::Interrupted)?;
            let timer = original.timer_owner().map_err(|_| Error::Interrupted)?;
            if self.poisoned
                || sequence.checked_sub(self.seq).is_none_or(|n| n > 4096)
                || self
                    .shared_timer
                    .as_ref()
                    .is_none_or(|own| !std::sync::Arc::ptr_eq(own, &timer))
            {
                return Err(Error::Foreign);
            }
            let mut fds = [PollFd::new(&self.fd, PollFlags::IN)];
            if !matches!(
                poll(
                    &mut fds,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                ),
                Ok(0)
            ) || !fds[0].revents().is_empty()
            {
                return Err(Error::SequenceMismatch);
            }
            self.check_boot_deadline()?;
            self.seq = sequence;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub(crate) fn accept_bootstrap_sequence(
        &mut self,
        original: &vprouter_native_role::ProducerBootstrapCompleted,
        sequence: u32,
    ) -> Result<()> {
        let result = (|| {
            original.require_current().map_err(|_| Error::Interrupted)?;
            let timer = original.timer_owner().map_err(|_| Error::Interrupted)?;
            if self.poisoned
                || sequence.checked_sub(self.seq).is_none_or(|n| n > 4096)
                || self
                    .shared_timer
                    .as_ref()
                    .is_none_or(|own| !std::sync::Arc::ptr_eq(own, &timer))
            {
                return Err(Error::Foreign);
            }
            let mut fds = [PollFd::new(&self.fd, PollFlags::IN)];
            if !matches!(
                poll(
                    &mut fds,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                ),
                Ok(0)
            ) || !fds[0].revents().is_empty()
            {
                return Err(Error::SequenceMismatch);
            }
            self.check_boot_deadline()?;
            self.seq = sequence;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub(crate) fn original_sequence(&self) -> Result<u32> {
        if self.poisoned {
            Err(Error::Io)
        } else {
            Ok(self.seq)
        }
    }
    pub(crate) fn accept_original_sequence(
        &mut self,
        original: &vprouter_native_role::NetfilterCompleted,
        seq: u32,
    ) -> Result<()> {
        let result = (|| {
            original.require_current().map_err(|_| Error::Interrupted)?;
            if self.poisoned || seq.checked_sub(self.seq).is_none_or(|n| n > 4096) {
                return Err(Error::SequenceMismatch);
            }
            let timer = original.timer_owner().map_err(|_| Error::Interrupted)?;
            if self
                .shared_timer
                .as_ref()
                .is_none_or(|t| !std::sync::Arc::ptr_eq(t, &timer))
            {
                return Err(Error::Foreign);
            }
            let mut fds = [PollFd::new(&self.fd, PollFlags::IN)];
            if !matches!(
                poll(
                    &mut fds,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                ),
                Ok(0)
            ) || !fds[0].revents().is_empty()
            {
                return Err(Error::SequenceMismatch);
            }
            self.check_boot_deadline()?;
            self.seq = seq;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn open() -> Result<Self> {
        let fd = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(netlink::NETFILTER),
        )
        .map_err(|_| Error::SocketUnavailable)?;
        net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(|_| Error::SocketUnavailable)?;
        let address = SocketAddrNetlink::try_from(
            net::getsockname(&fd).map_err(|_| Error::SocketUnavailable)?,
        )
        .map_err(|_| Error::SocketUnavailable)?;
        Ok(Self {
            constructor_identity: None,
            fd: std::sync::Arc::new(fd),
            port: address.pid(),
            seq: 0,
            poisoned: false,
            timer: None,
            boot_deadline: None,
            shared_timer: None,
        })
    }
    pub(crate) fn open_terminal() -> Result<Self> {
        let mut socket = Self::open()?;
        socket.timer = Some(
            timerfd_create(
                TimerfdClockId::Boottime,
                TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
            )
            .map_err(|_| Error::SocketUnavailable)?,
        );
        Ok(socket)
    }
    pub(crate) fn terminal_descriptors(&self) -> [BorrowedFd<'_>; 2] {
        [
            self.fd.as_fd(),
            self.timer
                .as_ref()
                .expect("terminal constructor owns timer")
                .as_fd(),
        ]
    }
    pub(crate) fn bind_deadline(&mut self, deadline: BootDeadline) -> Result<()> {
        if self.boot_deadline.is_some() {
            return Err(Error::InvalidInput);
        }
        deadline.check()?;
        timerfd_settime(
            self.timer.as_ref().ok_or(Error::InvalidInput)?,
            TimerfdTimerFlags::ABSTIME,
            &Itimerspec {
                it_interval: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: deadline.timespec(),
            },
        )
        .map_err(|_| Error::Io)?;
        self.boot_deadline = Some(deadline);
        self.check_boot_deadline()
    }
    fn check_boot_deadline(&self) -> Result<()> {
        match self.boot_deadline {
            Some(deadline) => deadline.check(),
            None if self.timer.is_some() || self.shared_timer.is_some() => Err(Error::InvalidInput),
            None => Ok(()),
        }
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn seq(&mut self) -> Result<u32> {
        self.seq = self.seq.checked_add(1).ok_or(Error::SequenceMismatch)?;
        Ok(self.seq)
    }
    fn wait(&self, flags: PollFlags, deadline: Instant) -> Result<()> {
        loop {
            self.check_boot_deadline()?;
            let remain = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Deadline)?;
            let timeout = Timespec::try_from(remain).map_err(|_| Error::Deadline)?;
            let mut fds = vec![PollFd::new(&self.fd, flags)];
            if let Some(timer) = &self.timer {
                fds.push(PollFd::new(timer, PollFlags::IN));
            } else if let Some(timer) = &self.shared_timer {
                fds.push(PollFd::new(timer, PollFlags::IN));
            }
            match poll(&mut fds, Some(&timeout)) {
                Ok(0) => return Err(Error::Deadline),
                Ok(_) => {
                    self.check_boot_deadline()?;
                    if fds.get(1).is_some_and(|fd| !fd.revents().is_empty()) {
                        return Err(Error::Deadline);
                    }
                    if fds[0]
                        .revents()
                        .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
                    {
                        return Err(Error::Io);
                    } else {
                        return Ok(());
                    }
                }
                Err(Errno::INTR) => continue,
                Err(_) => return Err(Error::Io),
            }
        }
    }
    pub fn exchange(
        &mut self,
        packet: &[u8],
        seqs: &[u32],
        dump: bool,
        deadline: Instant,
    ) -> Result<Vec<Message>> {
        if self.poisoned {
            return Err(Error::Io);
        }
        let result = self.exchange_inner(packet, seqs, dump, deadline, &[], !dump);
        // A timeout/truncated/error exchange may leave unread messages; never
        // reuse that socket and accidentally treat them as a later transaction.
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn exchange_inner(
        &self,
        packet: &[u8],
        seqs: &[u32],
        dump: bool,
        deadline: Instant,
        control: &[u32],
        single_data: bool,
    ) -> Result<Vec<Message>> {
        if packet.len() > MAX_PACKET || seqs.is_empty() {
            return Err(Error::Oversized);
        }
        loop {
            self.wait(PollFlags::OUT, deadline)?;
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
        let mut replies = Replies::new(seqs.iter().copied(), dump);
        replies.control(control);
        if single_data {
            replies.allow_single_data();
        }
        let mut buffer = vec![0u8; MAX_PACKET];
        while !replies.complete() {
            self.wait(PollFlags::IN, deadline)?;
            self.check_boot_deadline()?;
            let received = net::recvfrom(
                &self.fd,
                buffer.as_mut_slice(),
                RecvFlags::TRUNC | RecvFlags::DONTWAIT,
            );
            self.check_boot_deadline()?;
            let (n, actual, addr) = match received {
                Ok(v) => v,
                Err(Errno::AGAIN | Errno::INTR) => continue,
                Err(Errno::NOBUFS) => return Err(Error::Oversized),
                Err(_) => return Err(Error::Io),
            };
            if actual > buffer.len() || n == 0 {
                return Err(Error::Oversized);
            }
            let from = SocketAddrNetlink::try_from(addr.ok_or(Error::SenderMismatch)?)
                .map_err(|_| Error::SenderMismatch)?;
            if from.groups() != 0 {
                return Err(Error::SenderMismatch);
            }
            replies.ingest(&buffer[..n], from.pid(), self.port)?;
        }
        self.check_boot_deadline()?;
        Ok(replies.data)
    }
    pub fn generation(&mut self, deadline: Instant) -> Result<u32> {
        let seq = self.seq()?;
        let reply = self.exchange(
            &message(NFT | 16, REQUEST, seq, 0, 0, &[]),
            &[seq],
            false,
            deadline,
        )?;
        if reply.len() != 1 || reply[0].kind != NFT | 15 {
            return Err(Error::Malformed);
        }
        be32(get(&nfattrs(&reply[0])?, 1)?)
    }
    pub fn dump(&mut self, op: u16, a: &[Attr], deadline: Instant) -> Result<Vec<Message>> {
        self.dump_family(op, a, INET, deadline)
    }
    pub fn dump_family(
        &mut self,
        op: u16,
        a: &[Attr],
        family: u8,
        deadline: Instant,
    ) -> Result<Vec<Message>> {
        let seq = self.seq()?;
        let reply = self.exchange(
            &message(NFT | op, REQUEST | DUMP, seq, family, 0, a),
            &[seq],
            true,
            deadline,
        )?;
        if reply
            .iter()
            .any(|m| m.kind != NFT | (op - 1) || m.payload.first() != Some(&family))
        {
            return Err(Error::Malformed);
        }
        Ok(reply)
    }
    pub fn scoped_dump(&mut self, op: u16, table: &str, deadline: Instant) -> Result<Vec<Message>> {
        // Linux dump callbacks differ in whether they honor the table request
        // attribute. Always select exact table identity locally as well. The
        // entire unfiltered exchange remains bounded and generation checked.
        select_table(self.dump(op, &[string(1, table)], deadline)?, table)
    }
    pub fn batch(
        &mut self,
        ops: &[(u16, u16, Vec<Attr>)],
        generation: u32,
        deadline: Instant,
    ) -> Result<()> {
        self.batch_family(ops, generation, INET, deadline)
    }
    pub fn batch_family(
        &mut self,
        ops: &[(u16, u16, Vec<Attr>)],
        generation: u32,
        family: u8,
        deadline: Instant,
    ) -> Result<()> {
        let begin = self.seq()?;
        let mut packet = message(16, REQUEST, begin, 0, 10, &[u32a(1, generation)]);
        let mut seqs = Vec::new();
        for (kind, flags, a) in ops {
            let seq = self.seq()?;
            seqs.push(seq);
            packet.extend(message(*kind, REQUEST | ACK | *flags, seq, family, 0, a));
        }
        let end = self.seq()?;
        packet.extend(message(17, REQUEST, end, 0, 10, &[]));
        if self.poisoned {
            return Err(Error::Io);
        }
        let result = self.exchange_inner(&packet, &seqs, false, deadline, &[begin, end], false);
        if result.is_err() {
            self.poisoned = true;
        }
        result.map(|_| ())
    }
}

fn select_table(messages: Vec<Message>, table: &str) -> Result<Vec<Message>> {
    let mut selected = Vec::new();
    for message in messages {
        if text(get(&nfattrs(&message)?, 1)?)? == table {
            selected.push(message);
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
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
            constructor_identity: None,
            fd: std::sync::Arc::new(fd),
            port: 0,
            seq: 0,
            poisoned: false,
            boot_deadline: None,
            timer: None,
            shared_timer: None,
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
        let original = crate::BootDeadline::at(end_seconds).unwrap();
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
            socket.exchange(&[1], &[1], false, end),
            Err(Error::Deadline)
        ));
        let mut byte = [0; 1];
        assert_eq!(
            net::recv(&peer, &mut byte, RecvFlags::DONTWAIT),
            Err(Errno::AGAIN)
        );
    }

    use super::*;
    #[test]
    fn boot_timer_interrupts_silent_peer_and_cannot_be_rearmed() {
        // Ordinary UNIX pair only: exercise actual timer+poll plumbing without
        // opening a netfilter socket or changing the caller's network policy.
        let (fd, _peer) = net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let mut socket = Socket {
            constructor_identity: None,
            fd: std::sync::Arc::new(fd),
            port: 0,
            seq: 0,
            poisoned: false,
            timer: Some(
                timerfd_create(
                    TimerfdClockId::Boottime,
                    TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
                )
                .unwrap(),
            ),
            boot_deadline: None,
            shared_timer: None,
        };
        assert_eq!(
            socket.wait(
                PollFlags::IN,
                Instant::now() + std::time::Duration::from_secs(1)
            ),
            Err(Error::InvalidInput)
        );
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let at = now.tv_sec as f64 + now.tv_nsec as f64 / 1e9 + 0.025;
        socket.bind_deadline(BootDeadline::at(at).unwrap()).unwrap();
        assert_eq!(
            socket.bind_deadline(BootDeadline::at(at + 44.).unwrap()),
            Err(Error::InvalidInput)
        );
        let started = Instant::now();
        assert_eq!(
            socket.wait(PollFlags::IN, started + std::time::Duration::from_secs(1)),
            Err(Error::Deadline)
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        assert_eq!(
            socket.wait(
                PollFlags::OUT,
                Instant::now() + std::time::Duration::from_secs(1)
            ),
            Err(Error::Deadline)
        );
    }
    #[test]
    fn elapsed_deadline_fails_before_any_io() {
        // /dev/null is used only as a descriptor: wait checks deadline before poll.
        // No netfilter socket is opened or host nft state touched by offline tests.
        let file = std::fs::File::open("/dev/null").unwrap();
        let socket = Socket {
            constructor_identity: None,
            fd: std::sync::Arc::new(file.into()),
            port: 0,
            seq: 0,
            poisoned: false,
            timer: None,
            boot_deadline: None,
            shared_timer: None,
        };
        assert_eq!(
            socket.wait(
                PollFlags::IN,
                Instant::now() - std::time::Duration::from_secs(1)
            ),
            Err(Error::Deadline)
        );
        let mut socket = socket;
        socket.seq = u32::MAX;
        assert_eq!(socket.seq(), Err(Error::SequenceMismatch));
        socket.poisoned = true;
        assert!(socket.exchange(&[0], &[1], false, Instant::now()).is_err());
    }
    #[test]
    fn dump_selects_exact_table_locally_when_kernel_callback_ignores_filter() {
        let row = |name: &str| {
            messages(&message(
                NFT | 3,
                2,
                1,
                INET,
                0,
                &[string(1, name), string(3, "input")],
            ))
            .unwrap()
            .remove(0)
        };
        let selected = select_table(
            vec![
                row("own_q"),
                row("own_p"),
                row("own_p_suffix"),
                row("unrelated"),
            ],
            "own_p",
        )
        .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(
            text(get(&nfattrs(&selected[0]).unwrap(), 1).unwrap()).unwrap(),
            "own_p"
        );
        let invalid = messages(&message(NFT | 3, 2, 1, INET, 0, &[string(3, "input")])).unwrap();
        assert!(select_table(invalid, "own_p").is_err());
    }
}
