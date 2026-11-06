//! Offline client rules only. No socket, actuator, mutation or verification receipt.
use crate::{Error, Result, codec::*, policy::*};
use serde::{Deserialize, Serialize};
use vprouter_core::client::{ClientPath, GuardPlan, TransportProtocol};
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Operation {
    kind: u16,
    flags: u16,
    attributes: Vec<u8>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Rendered {
    format: String,
    fingerprint: [u8; 32],
    quarantine: Vec<Operation>,
    permit: Vec<Operation>,
}
pub struct ClientRuleset {
    plan: GuardPlan,
    quarantine: Table,
    permit: Table,
}
const MAX_RENDER_BYTES: usize = 1024 * 1024;
impl ClientRuleset {
    /// Dedicated namespace only. This does not accept native handles and cannot be
    /// converted into the existing Actuator or its quarantine-release authority.
    pub fn prepare(plan: &GuardPlan) -> Result<Self> {
        let quarantine = build(plan, true);
        let permit = build(plan, false);
        let this = Self {
            plan: plan.clone(),
            quarantine,
            permit,
        };
        // Exercise the same bounded attribute/expression grammar as native policy.
        for table in [&this.quarantine, &this.permit] {
            for chain in &table.chains {
                for rule in &chain.rules {
                    crate::actuator::canonical_exprs(rule)?;
                }
            }
        }
        this.render()?;
        Ok(this)
    }
    fn rendered(&self) -> Rendered {
        fn ops(table: &Table) -> Vec<Operation> {
            table
                .operations()
                .into_iter()
                .map(|(kind, flags, a)| Operation {
                    kind,
                    flags,
                    attributes: encode_attrs(&a),
                })
                .collect()
        }
        Rendered {
            format: "offline-linux-nft-uapi-v1".into(),
            fingerprint: self.plan.fingerprint(),
            quarantine: ops(&self.quarantine),
            permit: ops(&self.permit),
        }
    }
    /// Bounded JSON containing UAPI creation intents, NOT a netlink activation batch.
    /// No arbitrary names, deletion, flushing, sets, scripts or executable text.
    pub fn render(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&self.rendered()).map_err(|_| Error::Malformed)?;
        if bytes.len() > MAX_RENDER_BYTES {
            return Err(Error::Oversized);
        }
        Ok(bytes)
    }
    /// Compare the entire ordered generated intent; a digest/marker alone is insufficient.
    /// Not a kernel observation and never a native verification receipt.
    pub fn validate_rendered(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_RENDER_BYTES {
            return Err(Error::Oversized);
        }
        let got: Rendered = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        if got != self.rendered() {
            return Err(Error::Drifted);
        }
        Ok(())
    }
}
fn build(plan: &GuardPlan, quarantine: bool) -> Table {
    let cfg = plan.config();
    // Stable table name across selection changes; exact generation/fingerprint in userdata.
    // Separate client namespace scopes may never share a table accidentally.
    use sha2::{Digest, Sha256};
    let owner = Sha256::digest(
        serde_json::to_vec(&(cfg.client_id.as_str(), &cfg.namespace))
            .expect("bounded public tuple"),
    );
    let suffix: String = owner[..12].iter().map(|b| format!("{b:02x}")).collect();
    let mut marker = b"vprouter-client-v1\0".to_vec();
    marker.extend(plan.selection().generation.to_be_bytes());
    marker.extend(plan.fingerprint());
    let mut table = Table {
        name: format!("vpc_{suffix}_{}", if quarantine { 'q' } else { 'p' }),
        marker,
        chains: vec![],
    };
    for (name, hook) in [("input", 1), ("output", 3), ("forward", 2)] {
        let mut chain = Chain::new(
            name,
            hook,
            if quarantine { -310 } else { -150 },
            0,
            "filter",
        );
        chain.rule(vec![meta_eq(15, &[10]), verdict(0)]); // IPv6 before every permit, including loopback.
        if name == "forward" {
            table.chains.push(chain);
            continue;
        }
        let reverse = name == "input";
        let name_key = if reverse { 6 } else { 7 };
        let index_key = if reverse { 4 } else { 5 };
        let kind_key = if reverse { 26 } else { 27 };
        match &cfg.path {
            ClientPath::Kernel {} => chain.rule(vec![
                meta_eq(15, &[2]),
                meta_name(name_key, "lo"),
                meta_eq(index_key, &1u32.to_ne_bytes()),
                verdict(1),
            ]),
            ClientPath::Userspace {
                socks_listener,
                http_listener,
                ..
            } => {
                for listener in [socks_listener, http_listener] {
                    let mut parts = vec![
                        meta_eq(15, &[2]),
                        meta_eq(16, &[6]),
                        meta_name(name_key, "lo"),
                        meta_eq(index_key, &1u32.to_ne_bytes()),
                        ip(true, std::net::Ipv4Addr::LOCALHOST),
                        ip(false, std::net::Ipv4Addr::LOCALHOST),
                        port(false, listener.port()),
                    ];
                    parts.push(verdict(1));
                    chain.rule(parts);
                    chain.rule(vec![
                        meta_eq(15, &[2]),
                        meta_eq(16, &[6]),
                        meta_name(name_key, "lo"),
                        meta_eq(index_key, &1u32.to_ne_bytes()),
                        ip(true, std::net::Ipv4Addr::LOCALHOST),
                        ip(false, std::net::Ipv4Addr::LOCALHOST),
                        port(true, listener.port()),
                        established(),
                        verdict(1),
                    ]);
                }
            }
        }
        if quarantine {
            table.chains.push(chain);
            continue;
        }
        for t in &cfg.transport {
            let mut parts = vec![
                meta_eq(15, &[2]),
                meta_eq(
                    16,
                    &[match t.protocol {
                        TransportProtocol::Tcp => 6,
                        TransportProtocol::Udp => 17,
                    }],
                ),
                meta_name(name_key, &cfg.wan.name),
                meta_eq(index_key, &cfg.wan.ifindex.to_ne_bytes()),
                ip(reverse, t.address),
                port(reverse, t.port),
                port(!reverse, t.source_port),
                socket_owner(cfg.daemon.cgroup_id, cfg.daemon.cgroup_level),
            ];
            if reverse {
                parts.push(established());
            }
            parts.push(verdict(1));
            chain.rule(parts);
        }
        for protocol in [6, 17] {
            let mut parts = vec![
                meta_eq(15, &[2]),
                meta_eq(16, &[protocol]),
                meta_name(name_key, &cfg.tailscale.name),
                meta_eq(index_key, &cfg.tailscale.ifindex.to_ne_bytes()),
                meta_name(kind_key, "tun"),
            ];
            if let ClientPath::Userspace {
                cgroup_id,
                cgroup_level,
                upstream,
                ..
            } = &cfg.path
            {
                if protocol != 6 {
                    continue;
                }
                parts.extend([
                    socket_owner(*cgroup_id, *cgroup_level),
                    ip(reverse, *upstream.ip()),
                    port(reverse, upstream.port()),
                ]);
            }
            parts.extend([
                payload(2, 0, 2),
                compare(&0u16.to_be_bytes(), true),
                payload(2, 2, 2),
                compare(&0u16.to_be_bytes(), true),
            ]);
            if reverse {
                parts.push(established());
            }
            parts.push(verdict(1));
            chain.rule(parts);
        }
        table.chains.push(chain);
    }
    table
}
#[cfg(test)]
mod tests;
