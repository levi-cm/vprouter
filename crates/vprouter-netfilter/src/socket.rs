use crate::{Error, Result, codec::*};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    net::{
        self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType,
        netlink::{self, SocketAddrNetlink},
    },
};
use std::{os::fd::OwnedFd, time::Instant};

/// A socket is permanently bound to the current network namespace at open time.
/// All mutating calls require &mut, preventing overlapping request sequences.
pub(crate) struct Socket {
    fd: OwnedFd,
    port: u32,
    seq: u32,
    poisoned: bool,
}
impl Socket {
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
            fd,
            port: address.pid(),
            seq: 0,
            poisoned: false,
        })
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
            let remain = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::Deadline)?;
            let timeout = Timespec::try_from(remain).map_err(|_| Error::Deadline)?;
            let mut fds = [PollFd::new(&self.fd, flags)];
            match poll(&mut fds, Some(&timeout)) {
                Ok(0) => return Err(Error::Deadline),
                Ok(_) => {
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
            match net::sendto(
                &self.fd,
                packet,
                SendFlags::DONTWAIT,
                &SocketAddrNetlink::new(0, 0),
            ) {
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
            let (n, actual, addr) = match net::recvfrom(
                &self.fd,
                buffer.as_mut_slice(),
                RecvFlags::TRUNC | RecvFlags::DONTWAIT,
            ) {
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
    use super::*;
    #[test]
    fn elapsed_deadline_fails_before_any_io() {
        // /dev/null is used only as a descriptor: wait checks deadline before poll.
        // No netfilter socket is opened or host nft state touched by offline tests.
        let file = std::fs::File::open("/dev/null").unwrap();
        let socket = Socket {
            fd: file.into(),
            port: 0,
            seq: 0,
            poisoned: false,
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
