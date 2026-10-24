use crate::{Address, Error, Link, Plan, Route, Rule, Wireguard};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

/// A multi-dump observation, never an atomic enforcement or readiness proof.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub links: Vec<Link>,
    pub addresses: Vec<Address>,
    pub routes: Vec<Route>,
    pub rules: Vec<Rule>,
    pub wireguard: Option<Wireguard>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audit {
    Absent,
    Unverified,
    StructurallyValid,
    Rejected(Error),
}
impl Plan {
    /// `expected_index` comes from the namespace manager's independently bound
    /// ownership record. A caller may not substitute the observed index for it.
    /// `now_unix` must be a trusted realtime clock sample; all ages are strict.
    pub fn audit(&self, snapshot: Option<&Snapshot>, expected_index: u32, now_unix: f64) -> Audit {
        let Some(s) = snapshot else {
            return Audit::Unverified;
        };
        if !s.links.iter().any(|l| l.name == self.wireguard_name()) {
            return Audit::Absent;
        }
        match self.check(s, expected_index, now_unix, true) {
            Ok(()) => Audit::StructurallyValid,
            Err(e) => Audit::Rejected(e),
        }
    }
    pub(crate) fn bootstrap_structure(
        &self,
        s: &Snapshot,
        expected_index: u32,
    ) -> Result<(), Error> {
        if s.links.iter().any(|l| l.name == "tailscale0") {
            return Err(Error::Drifted);
        }
        self.check(s, expected_index, 1.0, false)
    }
    fn check(
        &self,
        s: &Snapshot,
        expected_index: u32,
        now: f64,
        handshake: bool,
    ) -> Result<(), Error> {
        if expected_index == 0 || !now.is_finite() || now <= 0.0 {
            return Err(Error::InvalidInput);
        }
        let mut indices = HashSet::new();
        let mut names = HashSet::new();
        for l in &s.links {
            if !indices.insert(l.index)
                || !names.insert(&l.name)
                || l.index == 0
                || l.controller != 0
                || !l.port_kind.is_empty()
                || l.promiscuity != 0
                || l.all_multicast != 0
                || !l.alternate_names.is_empty()
            {
                return Err(Error::Drifted);
            }
            let valid = if l.name == self.wireguard_name() {
                l.index == expected_index
                    && l.kind == "wireguard"
                    && l.hardware_type == 65534
                    && l.up
                    && l.alias == self.alias
                    && l.mtu == 1420
                    && l.peer_index.is_none()
            } else if l.name == "lo" {
                l.kind.is_empty() && l.hardware_type == 772 && l.up && l.peer_index.is_none()
            } else if l.name == "tailscale0" {
                l.kind == "tun" && l.hardware_type == 65534 && l.up && l.peer_index.is_none()
            } else {
                false
            };
            if !valid {
                return Err(Error::Drifted);
            }
        }
        let lo = s
            .links
            .iter()
            .find(|l| l.name == "lo")
            .ok_or(Error::Drifted)?;
        let ts = s.links.iter().find(|l| l.name == "tailscale0");
        let mut addrs = HashSet::new();
        for a in &s.addresses {
            if a.broadcast.is_some()
                || a.route_priority.is_some()
                || a.flags & !0x80 != 0
                || !addrs.insert((a.index, a.address, a.prefix, a.scope))
            {
                return Err(Error::Drifted);
            }
            let valid = if a.index == expected_index {
                a.address == IpAddr::V4(self.address) && a.prefix == 32 && a.scope == 0
            } else if a.index == lo.index {
                matches!((a.address,a.prefix,a.scope),(IpAddr::V4(ip),8,254) if ip==Ipv4Addr::LOCALHOST)
                    || matches!((a.address,a.prefix,a.scope),(IpAddr::V6(ip),128,254) if ip==Ipv6Addr::LOCALHOST)
            } else if ts.is_some_and(|l| l.index == a.index) {
                match a.address {
                    IpAddr::V4(ip) => {
                        a.prefix == 32 && a.scope == 0 && (u32::from(ip) & 0xffc00000) == 0x64400000
                    }
                    IpAddr::V6(ip) => {
                        a.prefix == 128
                            && a.scope == 0
                            && ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0]
                    }
                }
            } else {
                false
            };
            if !valid {
                return Err(Error::Drifted);
            }
        }
        if s.addresses
            .iter()
            .filter(|a| a.index == expected_index)
            .count()
            != 1
            || !s
                .addresses
                .iter()
                .any(|a| a.index == lo.index && a.address == IpAddr::V4(Ipv4Addr::LOCALHOST))
        {
            return Err(Error::Drifted);
        }
        let expected = expected_routes(self, &s.addresses, lo.index, expected_index);
        if !same(&s.routes, &expected) || !same(&s.rules, &expected_rules()) {
            return Err(Error::Drifted);
        }
        let w = s.wireguard.as_ref().ok_or(Error::Absent)?;
        if w.index != expected_index
            || w.name != self.wireguard_name()
            || w.public_key != self.public_key
            || w.peers.len() != 1
        {
            return Err(Error::Drifted);
        }
        let p = &w.peers[0];
        if p.public_key != self.peer
            || p.endpoint != SocketAddr::V4(self.endpoint)
            || p.allowed_ips != [(Ipv4Addr::UNSPECIFIED.into(), 0)]
        {
            return Err(Error::Drifted);
        }
        if !handshake {
            return Ok(());
        }
        let time = p.handshake_unix.ok_or(Error::Drifted)?;
        let age = now - time;
        if !time.is_finite() || time <= 0.0 || !age.is_finite() || !(0.0..180.0).contains(&age) {
            return Err(Error::Drifted);
        }
        Ok(())
    }
}
pub(crate) fn same<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.len() == b.len()
        && a.iter()
            .all(|x| a.iter().filter(|y| *y == x).count() == b.iter().filter(|y| *y == x).count())
}
pub(crate) fn expected_rules() -> Vec<Rule> {
    vec![
        Rule {
            ipv6: false,
            priority: 0,
            table: 255,
            ..Rule::default()
        },
        Rule {
            ipv6: false,
            priority: 32766,
            table: 254,
            ..Rule::default()
        },
        Rule {
            ipv6: false,
            priority: 32767,
            table: 253,
            ..Rule::default()
        },
        Rule {
            ipv6: true,
            priority: 0,
            table: 255,
            ..Rule::default()
        },
        Rule {
            ipv6: true,
            priority: 32766,
            table: 254,
            ..Rule::default()
        },
    ]
}
pub(crate) fn expected_routes(plan: &Plan, addresses: &[Address], lo: u32, wg: u32) -> Vec<Route> {
    let mut routes = Vec::new();
    let mut add =
        |destination: IpAddr, prefix, table, output, source, kind, scope, protocol, metric| {
            routes.push(Route {
                nexthop_id: None,
                preference: 0,
                destination,
                prefix,
                table,
                output,
                source,
                gateway: None,
                kind,
                scope,
                protocol,
                metric,
                flags: 0,
            })
        };
    for a in addresses {
        match a.address {
            IpAddr::V4(ip) if a.index == lo => {
                add(ip.into(), 32, 255, lo, Some(ip.into()), 2, 254, 2, 0);
                add(
                    Ipv4Addr::new(127, 255, 255, 255).into(),
                    32,
                    255,
                    lo,
                    Some(ip.into()),
                    3,
                    253,
                    2,
                    0,
                );
                add(
                    Ipv4Addr::new(127, 0, 0, 0).into(),
                    8,
                    255,
                    lo,
                    Some(ip.into()),
                    2,
                    254,
                    2,
                    0,
                );
            }
            IpAddr::V4(ip) => {
                add(ip.into(), 32, 255, a.index, Some(ip.into()), 2, 254, 2, 0);
            }
            IpAddr::V6(ip) => {
                add(ip.into(), 128, 255, a.index, None, 2, 0, 2, 0);
                if a.index != lo {
                    add(ip.into(), 128, 254, a.index, None, 1, 0, 2, 256);
                    add(
                        "ff00::".parse().expect("literal"),
                        8,
                        255,
                        a.index,
                        None,
                        5,
                        0,
                        2,
                        256,
                    );
                }
            }
        }
    }
    // Kernel device-up bookkeeping, even with no IPv6 WG address.
    add(
        "ff00::".parse().expect("literal"),
        8,
        255,
        wg,
        None,
        5,
        0,
        2,
        256,
    );
    add(
        Ipv4Addr::UNSPECIFIED.into(),
        0,
        254,
        wg,
        Some(plan.address.into()),
        1,
        253,
        4,
        0,
    );
    routes
}
