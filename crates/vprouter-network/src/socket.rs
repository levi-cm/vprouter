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
    os::fd::OwnedFd,
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
    fd: OwnedFd,
    port: u32,
    seq: u32,
    poisoned: bool,
}
impl Socket {
    #[cfg(test)]
    pub(crate) fn unavailable_for_test() -> Self {
        Self {
            fd: std::fs::File::open("/dev/null").unwrap().into(),
            port: 0,
            seq: u32::MAX,
            poisoned: false,
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
            fd,
            port,
            seq: 0,
            poisoned: false,
        })
    }
    fn wait(&self, flags: PollFlags, end: Instant) -> Result<()> {
        loop {
            let remain = end
                .checked_duration_since(Instant::now())
                .ok_or(Error::Deadline)?;
            let timeout = Timespec::try_from(remain).map_err(|_| Error::Deadline)?;
            let mut fds = [PollFd::new(&self.fd, flags)];
            match poll(&mut fds, Some(&timeout)) {
                Ok(0) => return Err(Error::Deadline),
                Ok(_)
                    if fds[0]
                        .revents()
                        .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) =>
                {
                    return Err(Error::Io);
                }
                Ok(_) => return Ok(()),
                Err(Errno::INTR) => continue,
                Err(_) => return Err(Error::Io),
            }
        }
    }
    pub fn request<T: NetlinkSerializable>(
        &mut self,
        payload: T,
        extra_flags: u16,
        expected_type: u16,
        completion: Completion,
        end: Instant,
    ) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        if self.poisoned {
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
        let mut replies =
            Replies::new(self.seq, self.port, request_type, expected_type, completion);
        let mut buffer = Zeroizing::new(vec![0; MAX_PACKET]);
        while !replies.complete() {
            self.wait(PollFlags::IN, end)?;
            let (n, actual, from) = match net::recvfrom(
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
            let from = SocketAddrNetlink::try_from(from.ok_or(Error::SenderMismatch)?)
                .map_err(|_| Error::SenderMismatch)?;
            if from.pid() != 0 || from.groups() != 0 {
                return Err(Error::SenderMismatch);
            }
            replies.ingest(&buffer[..n])?;
        }
        Ok(replies.data)
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
                        return Err(Error::KernelRejected);
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
