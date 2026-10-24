//! Linux UAPI codec; no repr casts, pointer operations or external nft libraries.
//! Constants follow linux/netfilter/{nf_tables,nfnetlink}.h (syscall-note UAPI).
use crate::{Error, Result};
use std::collections::BTreeSet;

pub(crate) const MAX_PACKET: usize = 256 * 1024;
pub(crate) const MAX_DUMP: usize = 4 * 1024 * 1024;
pub(crate) const NFT: u16 = 10 << 8;
pub(crate) const REQUEST: u16 = 1;
pub(crate) const ACK: u16 = 4;
pub(crate) const DUMP: u16 = 0x300;
pub(crate) const CREATE: u16 = 0x400;
pub(crate) const EXCL: u16 = 0x200;
pub(crate) const APPEND: u16 = 0x800;
pub(crate) const NESTED: u16 = 0x8000;
pub(crate) const INET: u8 = 1;

pub(crate) fn align(n: usize) -> usize {
    (n + 3) & !3
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Attr {
    pub kind: u16,
    pub value: Vec<u8>,
}
pub(crate) fn attr(kind: u16, value: impl Into<Vec<u8>>) -> Attr {
    Attr {
        kind,
        value: value.into(),
    }
}
pub(crate) fn u32a(kind: u16, value: u32) -> Attr {
    attr(kind, value.to_be_bytes())
}
pub(crate) fn string(kind: u16, value: &str) -> Attr {
    let mut v = value.as_bytes().to_vec();
    v.push(0);
    attr(kind, v)
}
pub(crate) fn nested(kind: u16, attrs: &[Attr]) -> Attr {
    attr(kind | NESTED, encode_attrs(attrs))
}
pub(crate) fn encode_attrs(attrs: &[Attr]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in attrs {
        let len = 4 + a.value.len();
        assert!(len <= u16::MAX as usize, "internal bounded attribute");
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&a.kind.to_ne_bytes());
        out.extend_from_slice(&a.value);
        out.resize(align(out.len()), 0);
    }
    out
}
pub(crate) fn attrs(mut bytes: &[u8]) -> Result<Vec<Attr>> {
    if bytes.len() > MAX_PACKET {
        return Err(Error::Oversized);
    }
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(Error::Malformed);
        }
        let len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        if len < 4 || align(len) > bytes.len() || out.len() >= 2048 {
            return Err(Error::Malformed);
        }
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        // Padding is not semantically meaningful and need not be zero in a dump.
        out.push(attr(kind, bytes[4..len].to_vec()));
        bytes = &bytes[align(len)..];
    }
    Ok(out)
}
pub(crate) fn unique(attrs: &[Attr]) -> Result<()> {
    let mut seen = BTreeSet::new();
    if attrs.iter().any(|a| !seen.insert(a.kind & 0x3fff)) {
        return Err(Error::Malformed);
    }
    Ok(())
}
pub(crate) fn get(attrs: &[Attr], kind: u16) -> Result<&[u8]> {
    unique(attrs)?;
    attrs
        .iter()
        .find(|a| a.kind & 0x3fff == kind)
        .map(|a| a.value.as_slice())
        .ok_or(Error::Malformed)
}
pub(crate) fn be32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| Error::Malformed)?,
    ))
}
pub(crate) fn text(bytes: &[u8]) -> Result<&str> {
    let s = bytes.strip_suffix(&[0]).ok_or(Error::Malformed)?;
    if s.contains(&0) || s.len() > 255 {
        return Err(Error::Malformed);
    }
    std::str::from_utf8(s).map_err(|_| Error::Malformed)
}
#[derive(Debug, Clone)]
pub(crate) struct Message {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
    pub payload: Vec<u8>,
}
pub(crate) fn message(
    kind: u16,
    flags: u16,
    seq: u32,
    family: u8,
    res: u16,
    a: &[Attr],
) -> Vec<u8> {
    let mut payload = vec![family, 0];
    payload.extend_from_slice(&res.to_be_bytes());
    payload.extend(encode_attrs(a));
    raw_message(kind, flags, seq, 0, &payload)
}
pub(crate) fn raw_message(kind: u16, flags: u16, seq: u32, pid: u32, payload: &[u8]) -> Vec<u8> {
    let len = 16 + payload.len();
    let mut v = Vec::with_capacity(align(len));
    v.extend_from_slice(&(len as u32).to_ne_bytes());
    v.extend_from_slice(&kind.to_ne_bytes());
    v.extend_from_slice(&flags.to_ne_bytes());
    v.extend_from_slice(&seq.to_ne_bytes());
    v.extend_from_slice(&pid.to_ne_bytes());
    v.extend_from_slice(payload);
    v.resize(align(len), 0);
    v
}
pub(crate) fn messages(mut bytes: &[u8]) -> Result<Vec<Message>> {
    if bytes.len() > MAX_PACKET {
        return Err(Error::Oversized);
    }
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(Error::Malformed);
        }
        let len = u32::from_ne_bytes(bytes[..4].try_into().map_err(|_| Error::Malformed)?) as usize;
        if len < 16 || len > bytes.len() || align(len) > bytes.len() {
            return Err(Error::Malformed);
        }
        out.push(Message {
            kind: u16::from_ne_bytes([bytes[4], bytes[5]]),
            flags: u16::from_ne_bytes([bytes[6], bytes[7]]),
            seq: u32::from_ne_bytes(bytes[8..12].try_into().map_err(|_| Error::Malformed)?),
            pid: u32::from_ne_bytes(bytes[12..16].try_into().map_err(|_| Error::Malformed)?),
            payload: bytes[16..len].to_vec(),
        });
        bytes = &bytes[align(len)..];
    }
    Ok(out)
}
pub(crate) fn nfattrs(m: &Message) -> Result<Vec<Attr>> {
    if m.payload.len() < 4 || m.payload[1] != 0 {
        return Err(Error::Malformed);
    }
    attrs(&m.payload[4..])
}
/// Tracks all requested ACKs; success ACK is error=0, never positive errno.
/// All replies including DONE and ERROR must match sequence and local port ID.
pub(crate) struct Replies {
    pending: BTreeSet<u32>,
    control: BTreeSet<u32>,
    pub data: Vec<Message>,
    bytes: usize,
    dump: bool,
    single_data: bool,
    done: bool,
}
impl Replies {
    pub fn new(seqs: impl IntoIterator<Item = u32>, dump: bool) -> Self {
        Self {
            pending: seqs.into_iter().collect(),
            control: BTreeSet::new(),
            data: Vec::new(),
            bytes: 0,
            dump,
            single_data: false,
            done: false,
        }
    }
    pub fn allow_single_data(&mut self) {
        self.single_data = true;
    }
    pub fn control(&mut self, seqs: &[u32]) {
        self.control.extend(seqs);
    }
    pub fn ingest(&mut self, bytes: &[u8], sender: u32, port: u32) -> Result<()> {
        if sender != 0 {
            return Err(Error::SenderMismatch);
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or(Error::Oversized)?;
        if self.bytes > MAX_DUMP {
            return Err(Error::Oversized);
        }
        for m in messages(bytes)? {
            if !self.pending.contains(&m.seq) && !self.control.contains(&m.seq) {
                return Err(Error::SequenceMismatch);
            }
            if m.pid != port {
                return Err(Error::SenderMismatch);
            }
            if m.flags & 0x10 != 0 {
                return Err(Error::Interrupted);
            }
            match m.kind {
                2 => {
                    if m.payload.len() < 20 {
                        return Err(Error::Malformed);
                    }
                    let code = i32::from_ne_bytes(
                        m.payload[..4].try_into().map_err(|_| Error::Malformed)?,
                    );
                    let request_seq = u32::from_ne_bytes(
                        m.payload[12..16].try_into().map_err(|_| Error::Malformed)?,
                    );
                    if request_seq != m.seq {
                        return Err(Error::SequenceMismatch);
                    }
                    if code == -85 || code == -11 {
                        return Err(Error::GenerationChanged);
                    }
                    if code != 0 {
                        return Err(Error::KernelRejected);
                    }
                    if self.control.contains(&m.seq) {
                        return Err(Error::Malformed);
                    }
                    if !self.dump {
                        self.pending.remove(&m.seq);
                    }
                }
                3 => {
                    if !self.dump || m.payload.len() != 4 {
                        return Err(Error::Malformed);
                    }
                    if i32::from_ne_bytes(m.payload[..4].try_into().map_err(|_| Error::Malformed)?)
                        != 0
                    {
                        return Err(Error::KernelRejected);
                    }
                    self.pending.remove(&m.seq);
                    self.done = true;
                }
                4 => return Err(Error::Oversized),
                k if k & 0xff00 == NFT => {
                    if !self.dump && !self.single_data {
                        return Err(Error::Malformed);
                    }
                    if self.dump && m.flags & 2 == 0 {
                        return Err(Error::Malformed);
                    }
                    if !self.dump {
                        self.pending.remove(&m.seq);
                    }
                    self.data.push(m);
                }
                _ => return Err(Error::Malformed),
            }
        }
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.pending.is_empty() && (!self.dump || self.done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic fixtures encoded directly from Linux nlmsghdr/nfgenmsg/nlattr
    // UAPI layouts, not captures of live policy or production credentials.
    fn ack(seq: u32, port: u32, code: i32) -> Vec<u8> {
        let original = raw_message(NFT, REQUEST | ACK, seq, 0, &[1, 0, 0, 0]);
        let mut payload = code.to_ne_bytes().to_vec();
        payload.extend(&original[..16]);
        raw_message(2, 0, seq, port, &payload)
    }
    #[test]
    fn aligned_native_headers_big_endian_values_and_nested_roundtrip() {
        let a = vec![string(1, "xy"), nested(4, &[u32a(2, 0x12345678)])];
        let bytes = encode_attrs(&a);
        assert_eq!(&bytes[..2], &7u16.to_ne_bytes());
        assert_eq!(&bytes[4..8], b"xy\0\0");
        assert_eq!(&bytes[16..20], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(attrs(&bytes).unwrap(), a);
        let packet = message(NFT | 3, REQUEST, 9, INET, 10, &a);
        let m = messages(&packet).unwrap().remove(0);
        assert_eq!(m.seq, 9);
        assert_eq!(m.kind, NFT | 3);
        assert_eq!(&m.payload[..4], &[1, 0, 0, 10]);
        assert_eq!(nfattrs(&m).unwrap(), a);
    }
    #[test]
    fn malformed_attribute_and_message_lengths_are_rejected_without_panics() {
        for len in 0u16..100 {
            let mut a = vec![0u8; 32];
            a[..2].copy_from_slice(&len.to_ne_bytes());
            if !(29..=32).contains(&len) {
                assert!(attrs(&a).is_err());
            }
        }
        for len in 0u32..100 {
            let mut m = vec![0u8; 32];
            m[..4].copy_from_slice(&len.to_ne_bytes());
            if !(29..=32).contains(&len) {
                assert!(messages(&m).is_err());
            }
        }
        assert_eq!(
            messages(&vec![0; MAX_PACKET + 1]).unwrap_err(),
            Error::Oversized
        );
        assert!(attrs(&[4, 0, 1]).is_err());
        assert!(unique(&[u32a(1, 1), u32a(1, 2)]).is_err());
        assert!(text(b"a\0b\0").is_err());
    }
    #[test]
    fn all_acks_required_and_errors_never_expose_external_payloads() {
        let mut r = Replies::new([7, 8], false);
        r.ingest(&ack(7, 42, 0), 0, 42).unwrap();
        assert!(!r.complete());
        r.ingest(&ack(8, 42, 0), 0, 42).unwrap();
        assert!(r.complete());
        for code in [-1, -22, 1, 22] {
            let mut r = Replies::new([7], false);
            let mut packet = ack(7, 42, code);
            packet.extend(b"secret-kernel-payload");
            assert_eq!(r.ingest(&packet, 0, 42), Err(Error::Malformed));
            assert_eq!(
                r.ingest(&ack(7, 42, code), 0, 42),
                Err(Error::KernelRejected)
            );
        }
        assert!(!format!("{:?}", Error::KernelRejected).contains("secret"));
    }
    #[test]
    fn sender_sequence_embedded_sequence_and_generation_mismatches_fail() {
        for (packet, sender, expected) in [
            (ack(8, 42, 0), 0, Error::SequenceMismatch),
            (ack(7, 41, 0), 0, Error::SenderMismatch),
            (ack(7, 42, 0), 99, Error::SenderMismatch),
            (ack(7, 42, -85), 0, Error::GenerationChanged),
        ] {
            assert_eq!(
                Replies::new([7], false).ingest(&packet, sender, 42),
                Err(expected)
            );
        }
        let mut packet = ack(7, 42, 0);
        packet[28..32].copy_from_slice(&8u32.to_ne_bytes());
        assert_eq!(
            Replies::new([7], false).ingest(&packet, 0, 42),
            Err(Error::SequenceMismatch)
        );
        let mut r = Replies::new([8], false);
        r.control(&[7, 9]);
        assert_eq!(
            r.ingest(&ack(7, 42, -85), 0, 42),
            Err(Error::GenerationChanged)
        );
    }
    #[test]
    fn multipart_requires_done_and_rejects_interruption_truncation_overflow() {
        let mut r = Replies::new([7], true);
        let data = raw_message(NFT, 2, 7, 42, &[1, 0, 0, 0]);
        r.ingest(&data, 0, 42).unwrap();
        assert!(!r.complete());
        r.ingest(&raw_message(3, 2, 7, 42, &0i32.to_ne_bytes()), 0, 42)
            .unwrap();
        assert!(r.complete());
        for packet in [
            raw_message(NFT, 2 | 16, 7, 42, &[1, 0, 0, 0]),
            raw_message(4, 0, 7, 42, &[]),
        ] {
            assert!(Replies::new([7], true).ingest(&packet, 0, 42).is_err());
        }
        let mut truncated = data.clone();
        truncated.pop();
        assert_eq!(
            Replies::new([7], true).ingest(&truncated, 0, 42),
            Err(Error::Malformed)
        );
        let mut oversized = Replies::new([7], true);
        oversized.bytes = MAX_DUMP;
        assert_eq!(oversized.ingest(&data, 0, 42), Err(Error::Oversized));
        assert!(
            Replies::new([7], true)
                .ingest(&raw_message(3, 2, 7, 42, &[]), 0, 42)
                .is_err()
        );
        assert!(
            Replies::new([7], true)
                .ingest(&raw_message(3, 2, 7, 42, &(-4i32).to_ne_bytes()), 0, 42)
                .is_err()
        );
    }
    #[test]
    fn mutation_requires_ack_while_getgen_admits_one_typed_data_response() {
        let data = raw_message(NFT | 15, 0, 7, 42, &[0, 0, 0, 0]);
        assert_eq!(
            Replies::new([7], false).ingest(&data, 0, 42),
            Err(Error::Malformed)
        );
        let mut gen_reply = Replies::new([7], false);
        gen_reply.allow_single_data();
        gen_reply.ingest(&data, 0, 42).unwrap();
        assert!(gen_reply.complete());
        assert_eq!(gen_reply.data.len(), 1);
    }
}
