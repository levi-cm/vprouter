//! Offline direct-exit policy intent. No native enforcer consumes these values.
use crate::{
    allocation::{AllocationRecord, ExitAllocation},
    config::{ExitMode, ValidatedConfiguration},
    reason::{Reason, Result, err},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
};
/// Conservative IANA special-purpose snapshot plus documented provider services.
pub const DENIED_RANGE_VERSION: &str = "direct-ipv4-2026-11-06-v1";
const DENIED: &[&str] = &[
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
fn prefix(value: &str) -> Result<(u32, u32)> {
    let (address, bits) = value
        .split_once('/')
        .ok_or_else(|| err(Reason::InvalidEvidence))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| err(Reason::InvalidEvidence))?;
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSnapshot {
    generation: u64,
    addresses: Vec<Ipv4Addr>,
    connected_prefixes: Vec<String>,
    local_prefixes: Vec<String>,
}
impl HostSnapshot {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 65536 {
            return Err(err(Reason::InvalidEvidence));
        }
        let mut host: Self =
            serde_json::from_slice(bytes).map_err(|_| err(Reason::InvalidEvidence))?;
        host.validate()?;
        host.addresses.sort();
        host.addresses.dedup();
        host.connected_prefixes.sort();
        host.connected_prefixes.dedup();
        host.local_prefixes.sort();
        host.local_prefixes.dedup();
        Ok(host)
    }
    fn validate(&self) -> Result<()> {
        let host = self;
        if host.generation == 0
            || host.addresses.is_empty()
            || host.addresses.len() > 256
            || host.connected_prefixes.is_empty()
            || host.connected_prefixes.len() > 256
            || host.local_prefixes.len() > 256
        {
            return Err(err(Reason::InvalidEvidence));
        }
        for p in host.connected_prefixes.iter().chain(&host.local_prefixes) {
            prefix(p)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectPath {
    pub wan_interface: String,
    pub ingress_ifindex: u32,
    pub wan_ifindex: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlowScope {
    pub deployment_id: String,
    pub exit_id: String,
    pub generation: u64,
    pub zone: u32,
    pub policy_fingerprint: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowTuple {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: Protocol,
}
impl FlowTuple {
    pub fn from_packet(packet: &Packet) -> Self {
        Self {
            source: packet.source,
            destination: packet.destination,
            source_port: packet.source_port,
            destination_port: packet.destination_port,
            protocol: packet.protocol,
        }
    }
}
#[derive(Clone, Debug)]
pub enum Connection {
    New,
    Established {
        scope: FlowScope,
        original: FlowTuple,
    },
}
#[derive(Clone, Debug)]
pub struct Packet {
    pub ingress_ifindex: u32,
    pub egress_ifindex: u32,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: Protocol,
    pub connection: Connection,
}
#[derive(Serialize)]
struct ApplicationPolicy {
    source_prefix: &'static str,
    protocols: [&'static str; 2],
    default_verdict: &'static str,
    new_flows: &'static str,
}
#[derive(Serialize)]
pub struct DirectPlan {
    allocation: ExitAllocation,
    application: ApplicationPolicy,
    flow: FlowScope,
    path: DirectPath,
    host: HostSnapshot,
    config_fingerprint: String,
    exposure: &'static str,
    initial_state: &'static str,
    ipv6_forwarding: &'static str,
    nat: &'static str,
    reply: &'static str,
    denied_range_version: &'static str,
    denied_destinations: Vec<String>,
    #[serde(skip)]
    ranges: Vec<(u32, u32)>,
}
impl DirectPlan {
    pub fn prepare(
        cfg: &ValidatedConfiguration,
        allocations: &AllocationRecord,
        id: &str,
        host: HostSnapshot,
        path: DirectPath,
    ) -> Result<Self> {
        host.validate()?;
        allocations.validate(&cfg.configuration().deployment_id, &[])?;
        allocations.matches_configuration(cfg)?;
        let exit = cfg
            .exits()
            .iter()
            .find(|e| e.exit().id == id)
            .ok_or_else(|| err(Reason::InvalidReference))?;
        if exit.exit().mode.kind() != ExitMode::Direct || !exit.exit().enabled {
            return Err(err(Reason::InvalidTransition));
        }
        if path.ingress_ifindex == 0
            || path.wan_ifindex == 0
            || path.ingress_ifindex == path.wan_ifindex
            || path.wan_interface.is_empty()
            || path.wan_interface.len() > 15
            || !path
                .wan_interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || ["lo", "tailscale0"].contains(&path.wan_interface.as_str())
            || allocations.exits.iter().any(|a| {
                a.host_interface == path.wan_interface
                    || a.data_interface == path.wan_interface
                    || a.wireguard_interface.as_deref() == Some(&path.wan_interface)
            })
        {
            return Err(err(Reason::InvalidEvidence));
        }
        // Zone reservations are stable across config ordering, enabled states and
        // generation updates. Refuse collisions, never silently share conntrack.
        let zone = |id: &str| {
            ((crate::allocation::stable_hash(&allocations.deployment_id, id) & 0xffff) as u32)
                .max(1)
        };
        let mut zones = HashSet::new();
        if allocations
            .exits
            .iter()
            .any(|a| !zones.insert(zone(&a.exit_id)))
        {
            return Err(err(Reason::AllocationConflict));
        }
        let allocation = allocations
            .exits
            .iter()
            .find(|e| e.exit_id == id)
            .ok_or_else(|| err(Reason::InvalidReference))?
            .clone();
        let configuration_digest = cfg.configuration().clone().validate_structure()?.digest()?;
        let config_fingerprint = configuration_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let application = ApplicationPolicy {
            source_prefix: "100.64.0.0/10",
            protocols: ["tcp", "udp"],
            default_verdict: "drop",
            new_flows: "outbound_only",
        };
        let policy_fingerprint = Sha256::digest(
            serde_json::to_vec(&(
                DENIED_RANGE_VERSION,
                DENIED,
                configuration_digest,
                &allocation,
                &path,
                &host,
                &application,
            ))
            .map_err(|_| err(Reason::InvalidEvidence))?,
        )
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
        let flow = FlowScope {
            deployment_id: allocations.deployment_id.clone(),
            exit_id: id.into(),
            generation: allocations.generation,
            zone: zone(id),
            policy_fingerprint,
        };
        let mut denied_destinations: Vec<String> = DENIED.iter().map(|p| (*p).into()).collect();
        denied_destinations.extend(host.addresses.iter().map(|ip| format!("{ip}/32")));
        denied_destinations.extend(
            host.connected_prefixes
                .iter()
                .chain(&host.local_prefixes)
                .cloned(),
        );
        denied_destinations.sort();
        denied_destinations.dedup();
        let ranges = denied_destinations
            .iter()
            .map(|p| prefix(p))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            allocation,
            application,
            flow,
            path,
            host,
            config_fingerprint,
            exposure: "direct-exposed",
            initial_state: "quarantined",
            ipv6_forwarding: "drop",
            nat: "exact_original_flow_only",
            reply: "exact_reverse_established_only",
            denied_range_version: DENIED_RANGE_VERSION,
            denied_destinations,
            ranges,
        })
    }
    pub fn flow_scope(&self) -> &FlowScope {
        &self.flow
    }
    pub(crate) fn matches_host(&self, host: Option<&HostSnapshot>) -> bool {
        host == Some(&self.host)
    }
    pub(crate) fn matches_binding(&self, binding: &crate::health::Binding) -> bool {
        binding.mode == ExitMode::Direct
            && binding.exit_id == self.flow.exit_id
            && binding.deployment_id == self.flow.deployment_id
            && binding.generation == self.flow.generation
            && binding.config_fingerprint == self.config_fingerprint
    }
    pub fn render(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| err(Reason::InvalidEvidence))
    }
    pub fn allows(&self, packet: &Packet) -> bool {
        let IpAddr::V4(source) = packet.source else {
            return false;
        };
        let IpAddr::V4(destination) = packet.destination else {
            return false;
        };
        if packet.source_port == 0 || packet.destination_port == 0 {
            return false;
        }
        let outbound = packet.ingress_ifindex == self.path.ingress_ifindex
            && packet.egress_ifindex == self.path.wan_ifindex;
        let inbound = packet.ingress_ifindex == self.path.wan_ifindex
            && packet.egress_ifindex == self.path.ingress_ifindex;
        let public = |ip| !self.ranges.iter().any(|p| contains(*p, ip));
        // This exact predicate is rendered with the rest of the policy intent.
        let Ok(client_range) = prefix(self.application.source_prefix) else {
            return false;
        };
        let client = |ip| contains(client_range, ip);
        let tuple = FlowTuple::from_packet(packet);
        match &packet.connection {
            Connection::New => outbound && client(source) && public(destination),
            Connection::Established { scope, original } => {
                if scope != &self.flow {
                    return false;
                }
                if outbound {
                    return client(source) && public(destination) && original == &tuple;
                }
                inbound
                    && public(source)
                    && client(destination)
                    && original.source == packet.destination
                    && original.destination == packet.source
                    && original.source_port == packet.destination_port
                    && original.destination_port == packet.source_port
                    && original.protocol == packet.protocol
            }
        }
    }
}
