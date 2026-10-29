use crate::{Error, Result, codec::*};
use std::net::{Ipv4Addr, SocketAddrV4};
use vprouter_core::{
    allocation::{AllocationRecord, ExitAllocation},
    config::ExitMode,
    profile::public_ipv4,
};

/// Exact enforced packet policy. Readiness is represented for oracle comparison;
/// this slice grants no readiness authority to the guard transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Offline,
    Bootstrap,
    Ready,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    Data,
    Transport,
    Host,
}
impl Scope {
    fn code(self) -> &'static str {
        match self {
            Self::Data => "d",
            Self::Transport => "t",
            Self::Host => "h",
        }
    }
}
/// Validated public unicast IPv4 endpoint, never DNS or IPv6 transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint(SocketAddrV4);
impl Endpoint {
    pub fn new(endpoint: SocketAddrV4) -> Result<Self> {
        if !public_ipv4(*endpoint.ip()) || endpoint.port() == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self(endpoint))
    }
}
#[derive(Clone, Debug)]
pub struct Policy {
    pub(crate) allocation: ExitAllocation,
    pub(crate) deployment: String,
    pub(crate) generation: u64,
    pub(crate) scope: Scope,
    pub(crate) endpoint: Endpoint,
    pub(crate) wan: String,
    pub(crate) transport_ip: Ipv4Addr,
    pub(crate) subnet: Ipv4Addr,
    pub(crate) producer: Option<std::sync::Arc<crate::SocketProducer>>,
}
impl Policy {
    /// Caller must independently observe link ownership/kind and namespace identity.
    /// Name+kind packet matches prevent a reused non-WireGuard name from passing.
    /// This API does not claim that observing the string "wireguard" authenticates
    /// a peer; peer/profile/namespace verification belongs to the later guard.
    pub fn new(
        record: &AllocationRecord,
        deployment: &str,
        exit: &ExitAllocation,
        endpoint: Endpoint,
        scope: Scope,
        wan: &str,
        wireguard_kind: &str,
    ) -> Result<Self> {
        record
            .validate(deployment, &[])
            .map_err(|_| Error::InvalidAllocation)?;
        if !record.exits.contains(exit) {
            return Err(Error::InvalidAllocation);
        }
        if exit.mode != ExitMode::Mullvad {
            return Err(Error::DirectUnsupported);
        }
        if wireguard_kind != "wireguard"
            || !interface(wan)
            || wan == "lo"
            || wan == "tailscale0"
            || record.exits.iter().any(|a| {
                a.host_interface == wan
                    || a.data_interface == wan
                    || a.wireguard_interface.as_deref() == Some(wan)
            })
        {
            return Err(Error::InvalidInput);
        }
        let subnet: Ipv4Addr = exit
            .transport_subnet
            .split_once('/')
            .ok_or(Error::InvalidAllocation)?
            .0
            .parse()
            .map_err(|_| Error::InvalidAllocation)?;
        let transport_ip = Ipv4Addr::from(u32::from(subnet) + 2);
        Ok(Self {
            allocation: exit.clone(),
            deployment: deployment.into(),
            generation: record.generation,
            scope,
            endpoint,
            wan: wan.into(),
            transport_ip,
            subnet,
            producer: None,
        })
    }
    /// Digest of authored public initial policy, never native authority.
    pub fn initial_digest(&self) -> Result<[u8; 32]> {
        use sha2::Digest;
        if self.producer.is_some() {
            return Err(Error::InvalidInput);
        }
        let mut hash = sha2::Sha256::new();
        hash.update(b"fixed_initial_quarantine_v1");
        for table in [self.emergency_table(), self.table(true), self.table(false)] {
            let ops = table.operations();
            hash.update((ops.len() as u64).to_le_bytes());
            for (kind, flags, attrs) in ops {
                let bytes = encode_attrs(&attrs);
                hash.update(kind.to_le_bytes());
                hash.update(flags.to_le_bytes());
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
            }
        }
        Ok(hash.finalize().into())
    }
    pub fn with_producer(
        mut self,
        producer: std::sync::Arc<crate::SocketProducer>,
    ) -> Result<Self> {
        producer.verify()?;
        // Namespace identity is checked again against the actual nft socket open.
        self.producer = Some(producer);
        Ok(self)
    }
    pub fn scope(&self) -> Scope {
        self.scope
    }
    pub fn permit_table_name(&self) -> String {
        self.name(false)
    }
    pub fn quarantine_table_name(&self) -> String {
        self.name(true)
    }
    fn name(&self, quarantine: bool) -> String {
        format!(
            "{}_{}{}",
            self.allocation.nft_table,
            self.scope.code(),
            if quarantine { "q" } else { "p" }
        )
    }
    fn marker(&self) -> Vec<u8> {
        let mut out = format!(
            "vprouter-v2\0{}\0{}\0{}\0",
            self.deployment,
            self.allocation.exit_id,
            self.scope.code()
        )
        .into_bytes();
        out.extend(self.generation.to_be_bytes());
        out
    }
    pub(crate) fn compatible(&self, other: &Self) -> bool {
        self.allocation == other.allocation
            && self.deployment == other.deployment
            && self.generation == other.generation
            && self.scope == other.scope
    }
    pub(crate) fn table(&self, quarantine: bool) -> Table {
        let mut t = Table {
            name: self.name(quarantine),
            marker: self.marker(),
            chains: Vec::new(),
        };
        match self.scope {
            Scope::Data | Scope::Transport => {
                for (name, hook, output) in [
                    ("input", 1, false),
                    ("output", 3, true),
                    ("forward", 2, false),
                ] {
                    let mut c = Chain::new(
                        name,
                        hook,
                        if quarantine { -310 } else { -150 },
                        0,
                        "filter",
                    );
                    c.rule(vec![meta_eq(15, &[10]), verdict(0)]);
                    if name != "forward" {
                        c.rule(vec![
                            meta_name(if output { 7 } else { 6 }, "lo"),
                            verdict(1),
                        ]);
                    }
                    if !quarantine {
                        match self.scope {
                            Scope::Data => self.data_rules(&mut c),
                            Scope::Transport => self.transport_rules(&mut c),
                            Scope::Host => unreachable!(),
                        }
                    }
                    t.chains.push(c);
                }
                if !quarantine && self.scope == Scope::Data {
                    let wg = self
                        .allocation
                        .wireguard_interface
                        .as_deref()
                        .expect("validated mullvad");
                    let mut c = Chain::new("postrouting", 4, 100, 1, "nat");
                    c.rule(vec![
                        meta_eq(15, &[2]),
                        meta_name(7, wg),
                        meta_name(27, "wireguard"),
                        network(true, Ipv4Addr::new(100, 64, 0, 0), 10),
                        expr("masq", vec![]),
                    ]);
                    t.chains.push(c);
                }
            }
            Scope::Host => {
                for (name, hook) in [("input", 1), ("output", 3), ("forward", 2)] {
                    let mut c = Chain::new(
                        name,
                        hook,
                        if quarantine { -310 } else { -150 },
                        1,
                        "filter",
                    );
                    if !quarantine && name == "forward" {
                        c.rule(self.flow(false, true));
                        c.rule(self.flow(true, true));
                    }
                    // No catch-all host verdicts. Only selected veth and /30 are blocked.
                    c.rule(vec![
                        meta_name(6, &self.allocation.host_interface),
                        verdict(0),
                    ]);
                    c.rule(vec![
                        meta_name(7, &self.allocation.host_interface),
                        verdict(0),
                    ]);
                    c.rule(vec![
                        meta_eq(15, &[2]),
                        network(true, self.subnet, 30),
                        verdict(0),
                    ]);
                    c.rule(vec![
                        meta_eq(15, &[2]),
                        network(false, self.subnet, 30),
                        verdict(0),
                    ]);
                    t.chains.push(c);
                }
                if !quarantine {
                    let mut c = Chain::new("postrouting", 4, 100, 1, "nat");
                    let mut flow = self.flow(false, true);
                    flow.pop();
                    flow.push(expr("masq", vec![]));
                    c.rule(flow);
                    t.chains.push(c);
                }
            }
        }
        t
    }
    /// Same owned quarantine table identity, atomically replaced as a whole.
    /// Bootstrap admits namespace-local WireGuard control/health and encrypted
    /// endpoint UDP only. Its data FORWARD chain has no ACCEPT rule.
    pub(crate) fn emergency_table(&self) -> Table {
        let mut t = self.table(true);
        t.name.push_str("_e");
        t
    }
    pub(crate) fn bootstrap_table(&self) -> Table {
        let mut t = self.table(true);
        for c in &mut t.chains {
            match self.scope {
                Scope::Data if c.name == "input" || c.name == "output" => {
                    let wg = self
                        .allocation
                        .wireguard_interface
                        .as_deref()
                        .expect("mullvad");
                    let mut rule = vec![
                        meta_eq(15, &[2]),
                        meta_name(if c.name == "output" { 7 } else { 6 }, wg),
                        meta_name(if c.name == "output" { 27 } else { 26 }, "wireguard"),
                    ];
                    if c.name == "input" {
                        rule.push(established());
                    }
                    if let Some(owner) = &self.producer {
                        // INPUT too: an established legacy application stream
                        // must not keep receiving during bootstrap.
                        rule.push(socket_owner(owner.id(), owner.level()));
                    } else {
                        continue;
                    } // no caller/synthetic fallback authority
                    rule.push(verdict(1));
                    c.rule(rule);
                }
                Scope::Transport => self.transport_rules(c),
                Scope::Host if c.name == "forward" => {
                    // Must precede quarantine's veth/subnet drop rules.
                    c.rules.insert(0, flatten(self.flow(true, true)));
                    c.rules.insert(0, flatten(self.flow(false, true)));
                }
                _ => {}
            }
        }
        t
    }
    /// Each independent filter remains restricted if its sibling is removed.
    /// Only the later readiness owner can choose the Ready representation.
    pub(crate) fn permit_stage_table(&self, stage: Stage) -> Table {
        if stage == Stage::Ready {
            return self.table(false);
        }
        let mut table = self.stage_table(stage);
        table.name = self.name(false);
        for chain in &mut table.chains {
            chain.priority = -150;
        }
        if stage == Stage::Bootstrap {
            table.chains.extend(
                self.table(false)
                    .chains
                    .into_iter()
                    .filter(|c| c.kind == "nat"),
            );
        }
        table
    }
    pub(crate) fn stage_table(&self, stage: Stage) -> Table {
        match stage {
            Stage::Offline => self.table(true),
            Stage::Bootstrap => self.bootstrap_table(),
            Stage::Ready => self.table(false),
        }
    }
    pub(crate) fn binding(&self) -> String {
        format!(
            "vprouter-v2:{}:{}:{}",
            self.deployment, self.generation, self.allocation.exit_id
        )
    }
    fn data_rules(&self, c: &mut Chain) {
        let wg = self
            .allocation
            .wireguard_interface
            .as_deref()
            .expect("validated mullvad");
        match c.name.as_str() {
            "input" => c.rule(vec![
                meta_name(6, wg),
                meta_name(26, "wireguard"),
                established(),
                verdict(1),
            ]),
            "output" => {
                c.rule(vec![
                    meta_name(7, wg),
                    meta_name(27, "wireguard"),
                    verdict(1),
                ]);
                // Native Tailscale DNS parity, narrowly restricted to UDP/TCP port53.
                for proto in [6, 17] {
                    c.rule(vec![
                        meta_name(7, "tailscale0"),
                        meta_eq(15, &[2]),
                        ip(false, Ipv4Addr::new(100, 100, 100, 100)),
                        meta_eq(16, &[proto]),
                        port(false, 53),
                        verdict(1),
                    ]);
                }
            }
            "forward" => {
                c.rule(vec![
                    meta_eq(15, &[2]),
                    meta_name(6, "tailscale0"),
                    meta_name(7, wg),
                    meta_name(27, "wireguard"),
                    network(true, Ipv4Addr::new(100, 64, 0, 0), 10),
                    verdict(1),
                ]);
                c.rule(vec![
                    meta_eq(15, &[2]),
                    meta_name(6, wg),
                    meta_name(26, "wireguard"),
                    meta_name(7, "tailscale0"),
                    established(),
                    verdict(1),
                ]);
            }
            _ => unreachable!(),
        }
    }
    fn transport_rules(&self, c: &mut Chain) {
        if c.name == "output" {
            c.rule(self.flow(false, false));
            c.rules.last_mut().expect("rule").push(verdict(1));
        }
        if c.name == "input" {
            c.rule(self.flow(true, false));
            c.rules.last_mut().expect("rule").push(verdict(1));
        }
    }
    pub(crate) fn flow(&self, reverse: bool, host: bool) -> Vec<Attr> {
        let mut a = vec![meta_eq(15, &[2]), meta_eq(16, &[17])];
        if host {
            a.push(meta_name(if reverse { 6 } else { 7 }, &self.wan));
            a.push(meta_name(
                if reverse { 7 } else { 6 },
                &self.allocation.host_interface,
            ));
            a.push(meta_name(if reverse { 27 } else { 26 }, "veth"));
        } else {
            a.push(meta_name(
                if reverse { 6 } else { 7 },
                &self.allocation.data_interface,
            ));
            a.push(meta_name(if reverse { 26 } else { 27 }, "veth"));
        }
        a.push(ip(!reverse, self.transport_ip));
        a.push(ip(reverse, *self.endpoint.0.ip()));
        a.push(port(reverse, self.endpoint.0.port()));
        if reverse {
            a.push(established());
        }
        if host {
            a.push(verdict(1));
        }
        a
    }
}
fn interface(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Table {
    pub name: String,
    pub marker: Vec<u8>,
    pub chains: Vec<Chain>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Chain {
    pub name: String,
    pub hook: u32,
    pub priority: i32,
    pub policy: u32,
    pub kind: String,
    pub rules: Vec<Vec<Attr>>,
}
impl Chain {
    fn new(name: &str, hook: u32, priority: i32, policy: u32, kind: &str) -> Self {
        Self {
            name: name.into(),
            hook,
            priority,
            policy,
            kind: kind.into(),
            rules: Vec::new(),
        }
    }
    fn rule(&mut self, parts: Vec<Attr>) {
        // Helpers may return a nested bundle of multiple expressions; flatten it.
        self.rules.push(flatten(parts));
    }
}
pub(crate) fn flatten(parts: Vec<Attr>) -> Vec<Attr> {
    parts
        .into_iter()
        .flat_map(|a| {
            if a.kind == 0xffff {
                attrs(&a.value).expect("internal expressions")
            } else {
                vec![a]
            }
        })
        .collect()
}
fn bundle(parts: Vec<Attr>) -> Attr {
    attr(0xffff, encode_attrs(&flatten(parts)))
}
fn expr(name: &str, data: Vec<Attr>) -> Attr {
    nested(1, &[string(1, name), nested(2, &data)])
}
fn compare(value: &[u8], unequal: bool) -> Attr {
    expr(
        "cmp",
        vec![
            u32a(1, 1),
            u32a(2, u32::from(unequal)),
            nested(3, &[attr(1, value.to_vec())]),
        ],
    )
}
fn meta_eq(key: u32, value: &[u8]) -> Attr {
    bundle(vec![
        expr("meta", vec![u32a(1, 1), u32a(2, key)]),
        compare(value, false),
    ])
}
fn meta_name(key: u32, name: &str) -> Attr {
    let mut value = name.as_bytes().to_vec();
    value.resize(16, 0);
    meta_eq(key, &value)
}
fn payload(base: u32, offset: u32, len: u32) -> Attr {
    expr(
        "payload",
        vec![u32a(1, 1), u32a(2, base), u32a(3, offset), u32a(4, len)],
    )
}
fn ip(source: bool, addr: Ipv4Addr) -> Attr {
    bundle(vec![
        payload(1, if source { 12 } else { 16 }, 4),
        compare(&addr.octets(), false),
    ])
}
fn port(source: bool, port: u16) -> Attr {
    bundle(vec![
        payload(2, if source { 0 } else { 2 }, 2),
        compare(&port.to_be_bytes(), false),
    ])
}
fn bitwise(mask: &[u8]) -> Attr {
    expr(
        "bitwise",
        vec![
            u32a(1, 1),
            u32a(2, 1),
            u32a(3, mask.len() as u32),
            nested(4, &[attr(1, mask.to_vec())]),
            nested(5, &[attr(1, vec![0; mask.len()])]),
            u32a(6, 0),
        ],
    )
}
fn network(source: bool, addr: Ipv4Addr, prefix: u8) -> Attr {
    bundle(vec![
        payload(1, if source { 12 } else { 16 }, 4),
        bitwise(&(u32::MAX << (32 - prefix)).to_be_bytes()),
        compare(&addr.octets(), false),
    ])
}
pub(crate) fn socket_owner(id: u64, level: u32) -> Attr {
    bundle(vec![
        expr("socket", vec![u32a(1, 3), u32a(2, 1), u32a(3, level)]),
        compare(&id.to_ne_bytes(), false),
    ])
}
fn established() -> Attr {
    bundle(vec![
        expr("ct", vec![u32a(1, 1), u32a(2, 0)]),
        bitwise(&6u32.to_ne_bytes()),
        compare(&0u32.to_ne_bytes(), true),
    ])
}
fn verdict(code: u32) -> Attr {
    expr(
        "immediate",
        vec![u32a(1, 0), nested(2, &[nested(2, &[u32a(1, code)])])],
    )
}

impl Table {
    pub fn table_attrs(&self) -> Vec<Attr> {
        vec![
            string(1, &self.name),
            u32a(2, 0),
            attr(6, self.marker.clone()),
        ]
    }
    pub fn operations(&self) -> Vec<(u16, u16, Vec<Attr>)> {
        let mut out = vec![(NFT, CREATE | EXCL, self.table_attrs())];
        for c in &self.chains {
            out.push((
                NFT | 3,
                CREATE | EXCL,
                vec![
                    string(1, &self.name),
                    string(3, &c.name),
                    nested(4, &[u32a(1, c.hook), u32a(2, c.priority as u32)]),
                    u32a(5, c.policy),
                    string(7, &c.kind),
                ],
            ));
            for r in &c.rules {
                out.push((
                    NFT | 6,
                    CREATE | APPEND,
                    vec![string(1, &self.name), string(2, &c.name), nested(4, r)],
                ));
            }
        }
        out
    }
}

#[cfg(test)]
pub(crate) fn fixture(scope: Scope) -> Policy {
    use vprouter_core::{config::Configuration, profile::Profile};
    let config=Configuration::parse(format!(r#"{{"schema_version":2,"deployment_id":"lab","site":"debdev","gateway_image":"sha256:{}","exits":[{{"id":"primary","enabled":true,"state_dir":"/lab/primary","mode":{{"kind":"mullvad","profile":"/lab/profile.conf","expected_server":"de-fra-wg-404"}}}}],"dependency_adapters":[],"client_policies":[]}}"#,"a".repeat(64)).as_bytes()).unwrap().validate_with(|_,server|Profile::parse(b"[Interface]\nPrivateKey=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress=10.64.0.2/32\n[Peer]\nPublicKey=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs=0.0.0.0/0\nEndpoint=185.65.134.88:51820\n",server,None)).unwrap();
    let record = AllocationRecord::from_configuration(&config, 1).unwrap();
    Policy::new(
        &record,
        "lab",
        &record.exits[0],
        Endpoint::new("185.65.134.88:51820".parse().unwrap()).unwrap(),
        scope,
        "eth0",
        "wireguard",
    )
    .unwrap()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone)]
    struct Packet<'a> {
        family: u8,
        proto: u8,
        iif: &'a str,
        oif: &'a str,
        ikind: &'a str,
        okind: &'a str,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        state: u32,
        owner: Option<u64>,
    }
    fn base() -> Packet<'static> {
        Packet {
            family: 2,
            proto: 17,
            iif: "tailscale0",
            oif: "",
            ikind: "tun",
            okind: "wireguard",
            src: Ipv4Addr::new(100, 64, 0, 9),
            dst: Ipv4Addr::new(8, 8, 8, 8),
            sport: 12345,
            dport: 443,
            state: 0,
            owner: None,
        }
    }
    // Independent small evaluator for this supported UAPI subset. Policy assertions
    // below test packet outcomes, not a digest or rendering of the desired model.
    fn eval(c: &Chain, p: &Packet<'_>) -> u32 {
        for r in &c.rules {
            let mut reg = Vec::new();
            let mut matches = true;
            for e in r {
                let a = attrs(&e.value).unwrap();
                let data = attrs(get(&a, 2).unwrap()).unwrap();
                match text(get(&a, 1).unwrap()).unwrap() {
                    "meta" => {
                        reg = match be32(get(&data, 2).unwrap()).unwrap() {
                            6 | 7 | 26 | 27 => {
                                let s = match be32(get(&data, 2).unwrap()).unwrap() {
                                    6 => p.iif,
                                    7 => p.oif,
                                    26 => p.ikind,
                                    _ => p.okind,
                                };
                                let mut v = s.as_bytes().to_vec();
                                v.resize(16, 0);
                                v
                            }
                            15 => vec![p.family],
                            16 => vec![p.proto],
                            _ => panic!("unsupported meta"),
                        }
                    }
                    "socket" => {
                        assert_eq!(be32(get(&data, 1).unwrap()).unwrap(), 3);
                        assert_eq!(be32(get(&data, 3).unwrap()).unwrap(), 3);
                        let Some(id) = p.owner else {
                            matches = false;
                            break;
                        };
                        reg = id.to_ne_bytes().to_vec();
                    }
                    "ct" => reg = p.state.to_ne_bytes().to_vec(),
                    "payload" => {
                        let base = be32(get(&data, 2).unwrap()).unwrap();
                        let offset = be32(get(&data, 3).unwrap()).unwrap();
                        reg = match (base, offset) {
                            (1, 12) => p.src.octets().to_vec(),
                            (1, 16) => p.dst.octets().to_vec(),
                            (2, 0) => p.sport.to_be_bytes().to_vec(),
                            (2, 2) => p.dport.to_be_bytes().to_vec(),
                            _ => panic!("unsupported payload"),
                        };
                    }
                    "cmp" => {
                        let expected = attrs(get(&data, 3).unwrap()).unwrap();
                        let equal = reg == get(&expected, 1).unwrap();
                        if equal == (be32(get(&data, 2).unwrap()).unwrap() == 1) {
                            matches = false;
                            break;
                        }
                    }
                    "bitwise" => {
                        let mask = attrs(get(&data, 4).unwrap()).unwrap();
                        let mask = get(&mask, 1).unwrap();
                        let xor = attrs(get(&data, 5).unwrap()).unwrap();
                        let xor = get(&xor, 1).unwrap();
                        reg = reg
                            .iter()
                            .zip(mask)
                            .zip(xor)
                            .map(|((r, m), x)| (r & m) ^ x)
                            .collect();
                    }
                    "immediate" => {
                        let d = attrs(get(&data, 2).unwrap()).unwrap();
                        let v = attrs(get(&d, 2).unwrap()).unwrap();
                        return be32(get(&v, 1).unwrap()).unwrap();
                    }
                    "masq" => return 2,
                    _ => panic!("unsupported expression"),
                }
            }
            if matches {
                panic!("rule lacks verdict");
            }
        }
        c.policy
    }
    fn chain(t: &Table, name: &str) -> Chain {
        t.chains.iter().find(|c| c.name == name).unwrap().clone()
    }
    #[test]
    fn data_packet_paths_require_ipv4_source_and_wireguard_kind() {
        let policy = fixture(Scope::Data);
        let t = policy.table(false);
        let c = chain(&t, "forward");
        let mut p = base();
        p.oif = policy.allocation.wireguard_interface.as_deref().unwrap();
        assert_eq!(eval(&c, &p), 1);
        for kind in ["dummy", "veth", ""] {
            let mut bad = p.clone();
            bad.okind = kind;
            assert_eq!(eval(&c, &bad), 0);
        }
        let mut bad = p.clone();
        bad.family = 10;
        assert_eq!(eval(&c, &bad), 0);
        let mut bad = p.clone();
        bad.src = Ipv4Addr::new(100, 128, 0, 1);
        assert_eq!(eval(&c, &bad), 0);
        let mut reverse = p.clone();
        reverse.iif = p.oif;
        reverse.ikind = "wireguard";
        reverse.oif = "tailscale0";
        reverse.state = 2;
        assert_eq!(eval(&c, &reverse), 1);
        reverse.state = 8;
        assert_eq!(eval(&c, &reverse), 0);
        reverse.state = 4;
        assert_eq!(eval(&c, &reverse), 1);
        reverse.ikind = "dummy";
        assert_eq!(eval(&c, &reverse), 0);
        let nat = chain(&t, "postrouting");
        assert_eq!(eval(&nat, &p), 2);
        assert_eq!(eval(&nat, &bad), 1);
    }
    #[test]
    fn data_input_output_dns_and_ipv6_are_narrow() {
        let policy = fixture(Scope::Data);
        let t = policy.table(false);
        let output = chain(&t, "output");
        let input = chain(&t, "input");
        let mut p = base();
        p.oif = "tailscale0";
        p.dst = Ipv4Addr::new(100, 100, 100, 100);
        p.dport = 53;
        assert_eq!(eval(&output, &p), 1);
        p.dport = 443;
        assert_eq!(eval(&output, &p), 0);
        p.oif = policy.allocation.wireguard_interface.as_deref().unwrap();
        assert_eq!(eval(&output, &p), 1);
        p.okind = "dummy";
        assert_eq!(eval(&output, &p), 0);
        p.iif = p.oif;
        p.ikind = "wireguard";
        p.state = 2;
        assert_eq!(eval(&input, &p), 1);
        p.state = 0;
        assert_eq!(eval(&input, &p), 0);
        p.family = 10;
        p.iif = "lo";
        p.oif = "lo";
        assert_eq!(eval(&input, &p), 0);
        assert_eq!(eval(&output, &p), 0);
    }
    #[test]
    fn transport_only_one_veth_and_exact_encrypted_udp_endpoint() {
        let policy = fixture(Scope::Transport);
        let t = policy.table(false);
        let c = chain(&t, "output");
        let mut p = base();
        p.oif = &policy.allocation.data_interface;
        p.okind = "veth";
        p.src = policy.transport_ip;
        p.dst = *policy.endpoint.0.ip();
        p.dport = policy.endpoint.0.port();
        assert_eq!(eval(&c, &p), 1);
        for (proto, dport, dst) in [
            (6, p.dport, p.dst),
            (17, 53, p.dst),
            (17, p.dport, Ipv4Addr::new(8, 8, 8, 8)),
        ] {
            let mut bad = p.clone();
            bad.proto = proto;
            bad.dport = dport;
            bad.dst = dst;
            assert_eq!(eval(&c, &bad), 0);
        }
        let mut bad = p.clone();
        bad.src = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(eval(&c, &bad), 0);
        let mut reverse = p.clone();
        reverse.iif = p.oif;
        reverse.ikind = "veth";
        reverse.src = p.dst;
        reverse.dst = p.src;
        reverse.sport = p.dport;
        reverse.state = 2;
        assert_eq!(eval(&chain(&t, "input"), &reverse), 1);
        reverse.state = 0;
        assert_eq!(eval(&chain(&t, "input"), &reverse), 0);
        assert_eq!(eval(&chain(&t, "forward"), &p), 0);
    }
    #[test]
    fn host_preserves_unrelated_traffic_and_anti_spoofs_every_owned_path() {
        let policy = fixture(Scope::Host);
        let t = policy.table(false);
        let c = chain(&t, "forward");
        let mut p = base();
        p.iif = &policy.allocation.host_interface;
        p.ikind = "veth";
        p.oif = "eth0";
        p.src = policy.transport_ip;
        p.dst = *policy.endpoint.0.ip();
        p.dport = policy.endpoint.0.port();
        assert_eq!(eval(&c, &p), 1);
        assert_eq!(eval(&chain(&t, "postrouting"), &p), 2);
        for oif in ["lo", "eth1", "tailscale0"] {
            let mut bad = p.clone();
            bad.oif = oif;
            assert_eq!(eval(&c, &bad), 0);
        }
        let mut bad = p.clone();
        bad.src = Ipv4Addr::new(1, 1, 1, 1);
        assert_eq!(eval(&c, &bad), 0);
        let mut bad = p.clone();
        bad.dport = 53;
        assert_eq!(eval(&c, &bad), 0);
        assert_eq!(eval(&chain(&t, "postrouting"), &bad), 1);
        assert_eq!(eval(&chain(&t, "input"), &p), 0);
        assert_eq!(eval(&chain(&t, "output"), &p), 0);
        let mut unrelated = base();
        unrelated.iif = "foreign0";
        unrelated.oif = "foreign1";
        assert_eq!(eval(&c, &unrelated), 1);
        unrelated.src = policy.transport_ip;
        assert_eq!(eval(&c, &unrelated), 0);
        let mut bad = p.clone();
        bad.family = 10;
        assert_eq!(eval(&c, &bad), 0);
    }
    #[test]
    fn quarantine_is_closed_and_selected_exit_only() {
        for scope in [Scope::Data, Scope::Transport, Scope::Host] {
            let policy = fixture(scope);
            let t = policy.table(true);
            let mut p = base();
            if scope == Scope::Host {
                p.iif = &policy.allocation.host_interface;
            }
            for c in &t.chains {
                assert_eq!(eval(c, &p), 0);
                assert_eq!(c.priority, -310);
            }
            if scope == Scope::Host {
                p.iif = "unrelated";
                assert_eq!(eval(&t.chains[0], &p), 1);
            }
        }
    }
    #[test]
    fn bootstrap_binds_both_directions_to_socket_producer_and_never_forwards_apps() {
        let mut policy = fixture(Scope::Data);
        policy.producer = Some(crate::producer::fixture(77));
        for t in [
            policy.stage_table(Stage::Bootstrap),
            policy.permit_stage_table(Stage::Bootstrap),
        ] {
            let mut p = base();
            p.oif = policy.allocation.wireguard_interface.as_deref().unwrap();
            p.owner = Some(77);
            assert_eq!(eval(&chain(&t, "output"), &p), 1);
            assert_eq!(eval(&chain(&t, "forward"), &p), 0);
            for owner in [None, Some(78)] {
                p.owner = owner;
                assert_eq!(eval(&chain(&t, "output"), &p), 0);
            }
            p.iif = p.oif;
            p.ikind = "wireguard";
            p.state = 2;
            // An already established legacy flow still cannot deliver INPUT.
            for owner in [None, Some(78)] {
                p.owner = owner;
                assert_eq!(eval(&chain(&t, "input"), &p), 0);
            }
            p.owner = Some(77);
            assert_eq!(eval(&chain(&t, "input"), &p), 1);
            p.family = 10;
            assert_eq!(eval(&chain(&t, "input"), &p), 0);
            assert_eq!(eval(&chain(&t, "output"), &p), 0);
            let closed = fixture(Scope::Data).bootstrap_table();
            p.family = 2;
            assert_eq!(eval(&chain(&closed, "input"), &p), 0);
            assert_eq!(eval(&chain(&closed, "output"), &p), 0);
        }
    }
    #[test]
    fn entire_record_membership_names_kind_wan_and_direct_are_validated() {
        let policy = fixture(Scope::Data);
        let record = AllocationRecord {
            schema_version: 2,
            deployment_id: "lab".into(),
            generation: 1,
            exits: vec![policy.allocation.clone()],
        };
        for wan in [
            "",
            "lo",
            "tailscale0",
            "eth0; accept",
            "too-long-interface-name",
        ] {
            assert!(
                Policy::new(
                    &record,
                    "lab",
                    &record.exits[0],
                    policy.endpoint,
                    Scope::Host,
                    wan,
                    "wireguard"
                )
                .is_err()
            );
        }
        assert!(
            Policy::new(
                &record,
                "lab",
                &record.exits[0],
                policy.endpoint,
                Scope::Host,
                "eth0",
                "dummy"
            )
            .is_err()
        );
        let mut forged = record.exits[0].clone();
        forged.exit_id = "foreign".into();
        assert!(
            Policy::new(
                &record,
                "lab",
                &forged,
                policy.endpoint,
                Scope::Host,
                "eth0",
                "wireguard"
            )
            .is_err()
        );
        let mut bad = record.clone();
        bad.exits.push(forged);
        assert!(
            Policy::new(
                &bad,
                "lab",
                &bad.exits[0],
                policy.endpoint,
                Scope::Host,
                "eth0",
                "wireguard"
            )
            .is_err()
        );
        let json = serde_json::json!({"schema_version":2,"deployment_id":"lab","site":"debdev","gateway_image":format!("sha256:{}","a".repeat(64)),"exits":[{"id":"primary","enabled":true,"state_dir":"/lab/primary","mode":{"kind":"direct"}}],"dependency_adapters":[],"client_policies":[]});
        let cfg = vprouter_core::config::Configuration::parse(json.to_string().as_bytes())
            .unwrap()
            .validate()
            .unwrap();
        let direct = AllocationRecord::from_configuration(&cfg, 1).unwrap();
        assert_eq!(
            Policy::new(
                &direct,
                "lab",
                &direct.exits[0],
                policy.endpoint,
                Scope::Host,
                "eth0",
                "wireguard"
            )
            .unwrap_err(),
            Error::DirectUnsupported
        );
        for ip in [
            "127.0.0.1:1",
            "10.1.1.1:1",
            "100.64.0.1:1",
            "192.0.2.1:1",
            "185.65.134.88:0",
        ] {
            assert!(Endpoint::new(ip.parse().unwrap()).is_err());
        }
    }
}
