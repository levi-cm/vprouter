//! Canonical, reject-only address syntax shared by client, proxy and ruleset
//! preparation. Classification is separate from context-specific admission:
//! local addresses are valid host evidence/listeners, never public targets.
use crate::reason::{Reason, Result, err};
use serde::{Deserialize, Deserializer, de::Error};
use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address<'a> {
    Ipv4(Ipv4Addr),
    Domain(&'a str),
}
fn invalid() -> crate::reason::Error {
    err(Reason::InvalidEvidence)
}

/// The only text host parser. Never trims, decodes, folds case or resolves.
pub fn parse(host: &str) -> Result<Address<'_>> {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(invalid());
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        if host == ip.to_string() {
            return Ok(Address::Ipv4(ip));
        }
        return Err(invalid());
    }
    // Numeric-aware connectors recognize the final numeric component even when
    // earlier components use different radices. Refuse numeric TLDs altogether,
    // rather than attempt to normalize any legacy inet_aton/URL spelling.
    let labels: Vec<_> = host.split('.').collect();
    if labels.len() < 2
        || !labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && !label.starts_with("xn--")
                && !label.starts_with("0x")
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || labels
            .last()
            .is_none_or(|label| label.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(invalid());
    }
    Ok(Address::Domain(host))
}
pub fn ipv4(host: &str) -> Result<Ipv4Addr> {
    match parse(host)? {
        Address::Ipv4(ip) => Ok(ip),
        Address::Domain(_) => Err(invalid()),
    }
}
pub fn public_target(host: &str) -> Result<Address<'_>> {
    let address = parse(host)?;
    match address {
        Address::Ipv4(ip) if !public_ipv4(ip) => return Err(invalid()),
        Address::Domain(name)
            if [
                "localhost",
                "local",
                "internal",
                "home.arpa",
                "invalid",
                "test",
                "onion",
            ]
            .iter()
            .any(|suffix| {
                name == *suffix || name.strip_suffix(suffix).is_some_and(|s| s.ends_with('.'))
            }) =>
        {
            return Err(invalid());
        }
        _ => {}
    }
    Ok(address)
}
/// IPv4/DNS authority only. Brackets, userinfo and additional colons refuse in
/// parse(); a nonzero canonical decimal port is the only admitted port syntax.
pub fn authority(value: &str) -> Result<(Address<'_>, u16)> {
    let (host, port) = value.split_once(':').ok_or_else(invalid)?;
    let address = parse(host)?;
    let number: u16 = port.parse().map_err(|_| invalid())?;
    if number == 0 || port != number.to_string() {
        return Err(invalid());
    }
    Ok((address, number))
}
pub fn socket_v4(value: &str) -> Result<SocketAddrV4> {
    match authority(value)? {
        (Address::Ipv4(ip), port) => Ok(SocketAddrV4::new(ip, port)),
        _ => Err(invalid()),
    }
}
pub(crate) fn deserialize_ipv4<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Ipv4Addr, D::Error> {
    ipv4(&String::deserialize(d)?).map_err(D::Error::custom)
}
pub(crate) fn deserialize_socket<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<SocketAddrV4, D::Error> {
    socket_v4(&String::deserialize(d)?).map_err(D::Error::custom)
}
pub(crate) fn deserialize_ipv4_vec<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<Ipv4Addr>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|s| ipv4(s).map_err(D::Error::custom))
        .collect()
}
/// Conservative IANA special-purpose snapshot plus documented provider services.
pub const DENIED_RANGE_VERSION: &str = "direct-ipv4-2026-11-06-v1";
pub(crate) const DENIED: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "168.63.129.16/32",
    "147.75.207.207/32",
    "192.80.8.124/32",
];
/// Shared conservative IPv4 target classification for offline client plans.
pub fn public_ipv4(ip: Ipv4Addr) -> bool {
    DENIED
        .iter()
        .all(|value| prefix(value).is_ok_and(|range| !contains(range, ip)))
}
pub fn prefix(value: &str) -> Result<(u32, u32)> {
    let (address, bits) = value
        .split_once('/')
        .ok_or_else(|| err(Reason::InvalidEvidence))?;
    let address = ipv4(address)?;
    let bits = bits
        .parse::<u8>()
        .map_err(|_| err(Reason::InvalidEvidence))?;
    if bits > 32 || value != format!("{address}/{bits}") {
        return Err(err(Reason::InvalidEvidence));
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    let start = u32::from(address);
    if start & mask != start {
        return Err(err(Reason::InvalidEvidence));
    }
    Ok((start, start | !mask))
}
fn contains(range: (u32, u32), ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    range.0 <= ip && ip <= range.1
}
