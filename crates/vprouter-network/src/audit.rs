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
#[derive(PartialEq, Eq)]
enum Check {
    Live,
    BootstrapIpv4,
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
        match self.check(s, expected_index, now_unix, Check::Live) {
            Ok(()) => Audit::StructurallyValid,
            Err(e) => Audit::Rejected(e),
        }
    }
    pub(crate) fn bootstrap_structure(
        &self,
        s: &Snapshot,
        expected_index: u32,
    ) -> Result<(), Error> {
        if s.links.iter().any(|l| l.name == "tailscale0")
            || s.addresses.iter().any(|a| a.address.is_ipv6())
            || s.routes.iter().any(|r| r.destination.is_ipv6())
        {
            return Err(Error::Drifted);
        }
        self.check(s, expected_index, 1.0, Check::BootstrapIpv4)
    }
    fn check(&self, s: &Snapshot, expected_index: u32, now: f64, mode: Check) -> Result<(), Error> {
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
        let mut expected = expected_routes(self, &s.addresses, lo.index, expected_index);
        if mode == Check::BootstrapIpv4 {
            // The guard disables IPv6 under Offline quarantine BEFORE capturing
            // its baseline. Linux consequently omits device-up multicast routes.
            // Bootstrap requires their absence rather than learning live state.
            expected.retain(|route| route.destination.is_ipv4());
        }
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
        if mode == Check::BootstrapIpv4 {
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
pub(crate) fn same<T: Ord>(a: &[T], b: &[T]) -> bool {
    if a == b {
        return true;
    }
    if a.len() != b.len() {
        return false;
    }
    // Reference sorting preserves complete values and multiplicity, with a
    // deterministic O(n log n) bound even for adversarial native dump order.
    let mut a: Vec<_> = a.iter().collect();
    let mut b: Vec<_> = b.iter().collect();
    a.sort_unstable();
    b.sort_unstable();
    a == b
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

#[cfg(test)]
mod comparison_tests {
    use super::same;
    use std::cell::Cell;

    #[test]
    fn unchanged_kernel_snapshot_requires_only_linear_comparison_work() {
        #[derive(Eq)]
        struct Entry<'a> {
            index: u32,
            comparisons: &'a Cell<usize>,
        }
        impl PartialEq for Entry<'_> {
            fn eq(&self, other: &Self) -> bool {
                self.comparisons.set(self.comparisons.get() + 1);
                self.index == other.index
            }
        }
        impl PartialOrd for Entry<'_> {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for Entry<'_> {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.index.cmp(&other.index)
            }
        }
        let comparisons = Cell::new(0);
        let entries = || {
            (0..128)
                .map(|index| Entry {
                    index,
                    comparisons: &comparisons,
                })
                .collect::<Vec<_>>()
        };
        let actual = entries();
        let retained = entries();
        assert!(same(&actual, &retained));
        assert!(
            comparisons.get() <= 2 * actual.len(),
            "unchanged audit used {} comparisons for {} entries",
            comparisons.get(),
            actual.len()
        );
    }

    #[test]
    fn reordered_host_snapshot_has_bounded_comparison_work() {
        #[derive(Eq)]
        struct Entry<'a>(u32, &'a Cell<usize>);
        impl PartialEq for Entry<'_> {
            fn eq(&self, other: &Self) -> bool {
                self.1.set(self.1.get() + 1);
                self.0 == other.0
            }
        }
        impl PartialOrd for Entry<'_> {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for Entry<'_> {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.1.set(self.1.get() + 1);
                self.0.cmp(&other.0)
            }
        }
        let calls = Cell::new(0);
        let a: Vec<_> = (0..4096).map(|i| Entry(i, &calls)).collect();
        let b: Vec<_> = (0..4096).rev().map(|i| Entry(i, &calls)).collect();
        assert!(same(&a, &b));
        assert!(calls.get() < 4096 * 64, "{} comparisons", calls.get());
    }

    #[test]
    fn snapshot_comparison_preserves_order_independence_and_duplicate_counts() {
        // All sequences of up to four values drawn from three distinct values.
        // Independently sorting copies supplies the multiset equality oracle.
        let mut sequences = vec![Vec::<u8>::new()];
        for length in 1..=4 {
            for mut encoding in 0..3u32.pow(length) {
                let mut values = Vec::new();
                for _ in 0..length {
                    values.push((encoding % 3) as u8);
                    encoding /= 3;
                }
                sequences.push(values);
            }
        }
        for actual in &sequences {
            for retained in &sequences {
                let mut a = actual.clone();
                let mut b = retained.clone();
                a.sort_unstable();
                b.sort_unstable();
                assert_eq!(same(actual, retained), a == b);
            }
        }
    }
}
