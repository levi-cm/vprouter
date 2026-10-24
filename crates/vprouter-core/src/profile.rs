use crate::{
    config::{absolute_path, server_name},
    reason::{Reason, Result, err},
};
use std::{
    collections::HashSet,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    path::Path,
};

pub const MAX_PROFILE_BYTES: usize = 64 * 1024;
// No Debug or Serialize implementation; callers cannot accidentally print keys.
struct SecretKey([u8; 32]);
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
pub struct Profile {
    private_key: SecretKey,
    public_key: [u8; 32],
    address: Ipv4Addr,
    endpoint: SocketAddrV4,
    expected_server: String,
    server_hint_verified: bool,
}
impl Profile {
    pub fn load(path: &Path, expected_server: &str) -> Result<Self> {
        absolute_path(path)?;
        let file = crate::allocation::secure_open_read(path)
            .map_err(|_| err(Reason::ProfileUnavailable))?;
        let mut bytes = Vec::new();
        file.take((MAX_PROFILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| err(Reason::ProfileUnavailable))?;
        Self::parse(&bytes, expected_server, Some(path))
    }
    pub fn parse(input: &[u8], expected_server: &str, source_path: Option<&Path>) -> Result<Self> {
        let invalid = || err(Reason::InvalidProfile);
        server_name(expected_server)?;
        if input.len() > MAX_PROFILE_BYTES {
            return Err(invalid());
        }
        let text = std::str::from_utf8(input).map_err(|_| invalid())?;
        let mut section = "";
        let mut sections = HashSet::new();
        let mut fields = HashSet::new();
        let mut private_key = None;
        let mut public_key = None;
        let mut address = None;
        let mut endpoint = None;
        let mut default_v4 = false;
        let mut hint = false;
        if let Some(stem) = source_path
            .and_then(Path::file_stem)
            .and_then(|s| s.to_str())
            && server_name(stem).is_ok()
        {
            check_hint(stem, expected_server)?;
            hint = true;
        }
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(comment) = line.strip_prefix('#') {
                let comment = comment.trim();
                for prefix in ["Server:", "Mullvad server:", "Server ="] {
                    if let Some(candidate) = comment.strip_prefix(prefix) {
                        check_hint(candidate.trim(), expected_server)?;
                        hint = true;
                    }
                }
                continue;
            }
            if line.starts_with('[') {
                if !matches!(line, "[Interface]" | "[Peer]") || !sections.insert(line) {
                    return Err(invalid());
                }
                if line == "[Peer]" && !sections.contains("[Interface]") {
                    return Err(invalid());
                }
                section = line;
                continue;
            }
            let (field, value) = line.split_once('=').ok_or_else(invalid)?;
            // Legacy ConfigParser writes known option names in lowercase. Normalize
            // before duplicate detection; section names and values stay strict.
            let (field, value) = (field.trim().to_ascii_lowercase(), value.trim());
            if value.is_empty() || !fields.insert((section, field.clone())) {
                return Err(invalid());
            }
            match (section, field.as_str()) {
                ("[Interface]", "privatekey") => private_key = Some(SecretKey(decode_key(value)?)),
                ("[Interface]", "address") => {
                    let mut seen = HashSet::new();
                    for network in value.split(',').map(str::trim) {
                        if !seen.insert(network) {
                            return Err(invalid());
                        }
                        let (ip, prefix) = network.split_once('/').ok_or_else(invalid)?;
                        match ip.parse::<IpAddr>().map_err(|_| invalid())? {
                            IpAddr::V4(ip) => {
                                if prefix != "32"
                                    || address.replace(ip).is_some()
                                    || ip.is_unspecified()
                                    || ip.is_multicast()
                                    || ip.is_loopback()
                                    || ip.is_broadcast()
                                {
                                    return Err(invalid());
                                }
                            }
                            IpAddr::V6(_) => {
                                if prefix != "128" {
                                    return Err(invalid());
                                }
                            }
                        }
                    }
                }
                ("[Interface]", "dns") => {
                    for dns in value.split(',') {
                        dns.trim().parse::<IpAddr>().map_err(|_| invalid())?;
                    }
                }
                ("[Interface]", "mtu") => {
                    if !value
                        .parse::<u16>()
                        .ok()
                        .is_some_and(|n| (576..=9000).contains(&n))
                    {
                        return Err(invalid());
                    }
                }
                ("[Peer]", "publickey") => public_key = Some(decode_key(value)?),
                ("[Peer]", "endpoint") => {
                    let ep = value.parse::<SocketAddrV4>().map_err(|_| invalid())?;
                    if ep.port() == 0 || !public_ipv4(*ep.ip()) {
                        return Err(invalid());
                    }
                    endpoint = Some(ep);
                }
                ("[Peer]", "allowedips") => {
                    let mut seen = HashSet::new();
                    for network in value.split(',').map(str::trim) {
                        if !seen.insert(network) {
                            return Err(invalid());
                        }
                        let (ip, prefix) = network.split_once('/').ok_or_else(invalid)?;
                        let ip = ip.parse::<IpAddr>().map_err(|_| invalid())?;
                        let prefix = prefix.parse::<u8>().map_err(|_| invalid())?;
                        match ip {
                            IpAddr::V4(v4) => {
                                if prefix > 32 {
                                    return Err(invalid());
                                }
                                if v4.is_unspecified() && prefix == 0 {
                                    default_v4 = true;
                                }
                            }
                            IpAddr::V6(_) => {
                                if prefix > 128 {
                                    return Err(invalid());
                                }
                            }
                        }
                    }
                }
                ("[Peer]", "persistentkeepalive") => {
                    value.parse::<u16>().map_err(|_| invalid())?;
                }
                _ => return Err(invalid()),
            }
        }
        let private_key = private_key.ok_or_else(invalid)?;
        let public_key = public_key.ok_or_else(invalid)?;
        if !default_v4 || private_key.0 == [0; 32] || public_key == [0; 32] {
            return Err(invalid());
        }
        Ok(Self {
            private_key,
            public_key,
            address: address.ok_or_else(invalid)?,
            endpoint: endpoint.ok_or_else(invalid)?,
            expected_server: expected_server.to_owned(),
            server_hint_verified: hint,
        })
    }
    pub fn expected_server(&self) -> &str {
        &self.expected_server
    }
    pub fn has_matching_server_hint(&self) -> bool {
        self.server_hint_verified
    }
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }
    pub fn endpoint(&self) -> SocketAddrV4 {
        self.endpoint
    }
    pub fn peer_public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub(crate) fn private_key_identity(&self) -> [u8; 32] {
        // WireGuard uses X25519, which ignores these scalar bits. Compare the
        // effective scalar so alternative encodings cannot create another exit
        // with the same cryptographic identity. This never leaves the crate.
        let mut identity = self.private_key.0;
        identity[0] &= 248;
        identity[31] &= 127;
        identity[31] |= 64;
        identity
    }
}
fn check_hint(hint: &str, expected: &str) -> Result<()> {
    if server_name(hint).is_err() || hint != expected {
        return Err(err(Reason::ProfileServerMismatch));
    }
    Ok(())
}
fn decode_key(s: &str) -> Result<[u8; 32]> {
    let invalid = || err(Reason::InvalidProfile);
    if s.len() != 44 || s.as_bytes()[43] != b'=' {
        return Err(invalid());
    }
    let mut out = [0u8; 32];
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut index = 0;
    for b in s.bytes().take(43) {
        let n = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(invalid()),
        };
        buffer = (buffer << 6) | u32::from(n);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[index] = (buffer >> bits) as u8;
            index += 1;
        }
    }
    if bits != 2 || buffer & 3 != 0 {
        return Err(invalid());
    }
    Ok(out)
}
/// Conservative public unicast IPv4 check, including special-use ranges.
pub fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || a == 169 && b == 254
        || a == 172 && (16..=31).contains(&b)
        || a == 192 && b == 168
        || a == 100 && (64..=127).contains(&b)
        || a == 198 && (b == 18 || b == 19)
        || a == 192 && b == 0 && (c == 0 || c == 2)
        || a == 192 && b == 88 && c == 99
        || a == 198 && b == 51 && c == 100
        || a == 203 && b == 0 && c == 113)
}
