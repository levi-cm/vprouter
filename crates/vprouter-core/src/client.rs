//! Offline client guard contracts. Public expected facts are never native receipts.
use crate::{
    fleet::FleetPolicy,
    reason::{Reason, Result, err},
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: String,
    pub ifindex: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Daemon {
    pub pid: u32,
    pub start_ticks: u64,
    pub executable_device: u64,
    pub executable_inode: u64,
    pub cgroup_id: u64,
    pub cgroup_level: u32,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    #[serde(deserialize_with = "crate::address::deserialize_ipv4")]
    pub address: std::net::Ipv4Addr,
    pub port: u16,
    pub source_port: u16,
    pub protocol: TransportProtocol,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientPath {
    Kernel {},
    Userspace {
        #[serde(deserialize_with = "crate::address::deserialize_socket")]
        socks_listener: std::net::SocketAddrV4,
        #[serde(deserialize_with = "crate::address::deserialize_socket")]
        http_listener: std::net::SocketAddrV4,
        cgroup_id: u64,
        cgroup_level: u32,
        #[serde(deserialize_with = "crate::address::deserialize_socket")]
        upstream: std::net::SocketAddrV4,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    pub schema_version: u32,
    pub client_id: String,
    pub boot_id: String,
    pub namespace: Namespace,
    pub tailscale: Interface,
    pub wan: Interface,
    pub daemon: Daemon,
    pub transport: Vec<Transport>,
    pub path: ClientPath,
}
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_TIME: u64 = 1_000_000_000_000_000;
const WATCHDOG_MS: u64 = 5000;
impl GuardConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(err(Reason::InvalidSchema));
        }
        let config: Self = serde_json::from_slice(bytes).map_err(|_| err(Reason::InvalidSchema))?;
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<()> {
        let good = self.schema_version == 1
            && !self.client_id.is_empty()
            && self.client_id.len() <= 32
            && self
                .client_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && self.namespace.device > 0
            && self.namespace.inode > 0
            && self.boot_id.len() == 36
            && self.boot_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
            && self.boot_id != "00000000-0000-0000-0000-000000000000"
            && interface(&self.tailscale.name)
            && interface(&self.wan.name)
            && self.tailscale.name != "lo"
            && self.wan.name != "lo"
            && self.tailscale.name != self.wan.name
            && self.tailscale.ifindex > 1
            && self.wan.ifindex > 1
            && self.tailscale.ifindex != self.wan.ifindex
            && self.daemon.pid > 1
            && self.daemon.start_ticks > 0
            && self.daemon.executable_device > 0
            && self.daemon.executable_inode > 0
            && owner(self.daemon.cgroup_id, self.daemon.cgroup_level)
            && !self.transport.is_empty()
            && self.transport.len() <= 32;
        if !good {
            return Err(err(Reason::InvalidSchema));
        }
        let mut seen = std::collections::BTreeSet::new();
        for t in &self.transport {
            if !crate::address::public_ipv4(t.address)
                || t.port == 0
                || t.source_port == 0
                || [53, 853].contains(&t.port)
                || [53, 853].contains(&t.source_port)
                || !seen.insert(t)
            {
                return Err(err(Reason::InvalidSchema));
            }
        }
        if let ClientPath::Userspace {
            socks_listener,
            http_listener,
            cgroup_id,
            cgroup_level,
            upstream,
        } = &self.path
            && (socks_listener.ip() != &std::net::Ipv4Addr::LOCALHOST
                || http_listener.ip() != &std::net::Ipv4Addr::LOCALHOST
                || socks_listener.port() == 0
                || http_listener.port() == 0
                || socks_listener == http_listener
                || !owner(*cgroup_id, *cgroup_level)
                || *cgroup_id == self.daemon.cgroup_id
                || *cgroup_level != self.daemon.cgroup_level
                || !tailnet(*upstream.ip())
                || upstream.ip() == &std::net::Ipv4Addr::new(100, 100, 100, 100)
                || upstream.port() == 0)
        {
            return Err(err(Reason::InvalidSchema));
        }
        Ok(())
    }
}
fn owner(id: u64, level: u32) -> bool {
    id > 0 && (1..=16).contains(&level)
}
fn interface(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
fn tailnet(ip: std::net::Ipv4Addr) -> bool {
    u32::from(ip) & 0xffc00000 == 0x64400000
}
#[derive(Clone)]
pub struct GuardPlan {
    config: GuardConfig,
    selection: crate::fleet::ClientPlan,
    deployment: String,
    fingerprint: [u8; 32],
}
impl GuardPlan {
    pub fn prepare(fleet: &FleetPolicy, mut config: GuardConfig) -> Result<Self> {
        use sha2::{Digest, Sha256};
        config.validate()?; // Also validates callers constructing public structs directly.
        let selection = fleet.configured_client_plan(&config.client_id)?;
        let (binding, lifecycle) = fleet.binding(&selection.exit_id)?;
        if binding.boot_id != config.boot_id {
            return Err(err(Reason::InvalidEvidence));
        }
        config.transport.sort();
        let bytes = serde_json::to_vec(&(&config, &selection, binding, lifecycle))
            .map_err(|_| err(Reason::InvalidSchema))?;
        let fingerprint = Sha256::digest(bytes).into();
        Ok(Self {
            config,
            selection,
            deployment: binding.deployment_id.clone(),
            fingerprint,
        })
    }
    pub fn config(&self) -> &GuardConfig {
        &self.config
    }
    pub fn selection(&self) -> &crate::fleet::ClientPlan {
        &self.selection
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    /// Parse an already-negotiated SOCKS5 CONNECT or a complete HTTP CONNECT header.
    /// No resolver, socket, authentication, retry, pool or network operation exists here.
    pub fn proxy_request(
        &self,
        protocol: ProxyProtocol,
        bytes: &[u8],
        started: u64,
        now: u64,
    ) -> Result<ProxyRequest> {
        if !matches!(self.config.path, ClientPath::Userspace { .. })
            || now > MAX_TIME
            || started > now
            || now - started >= 5000
            || bytes.len() > 8192
        {
            return Err(err(Reason::InvalidEvidence));
        }
        let (host, port) = match protocol {
            ProxyProtocol::HttpConnect => parse_connect(bytes)?,
            ProxyProtocol::Socks5 => parse_socks(bytes)?,
        };
        validate_target(&host, port)?;
        Ok(ProxyRequest {
            host,
            port,
            resolver: "selected_exit_only",
            address_family: "ipv4_only",
            pool_key: self.fingerprint,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStage {
    Quarantined,
    Prepared,
    Stopped,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Quarantine,
    Capture,
    Commit,
    Reconcile,
}
/// Instance/epoch correlation only, not a native receipt.
pub struct GuardToken {
    instance: std::sync::Arc<()>,
    epoch: u64,
}
pub struct ClientGuard {
    plan: GuardPlan,
    instance: std::sync::Arc<()>,
    epoch: u64,
    restarts: u16,
    stage: GuardStage,
    next: Option<Step>,
    last_now: u64,
    last_poll: u64,
    pending: bool,
}
#[derive(Serialize)]
pub struct GuardStatus {
    pub stage: GuardStage,
    pub dns: &'static str,
    pub ipv6: &'static str,
    pub observed_egress: &'static str,
    pub exposure: &'static str,
}
impl ClientGuard {
    pub fn new(plan: GuardPlan, now: u64) -> Result<Self> {
        if now > MAX_TIME {
            return Err(err(Reason::InvalidEvidence));
        }
        Ok(Self {
            plan,
            instance: std::sync::Arc::new(()),
            epoch: 0,
            restarts: 1,
            stage: GuardStage::Quarantined,
            next: Some(Step::Quarantine),
            last_now: now,
            last_poll: now,
            pending: true,
        })
    }
    pub fn plan(&self) -> &GuardPlan {
        &self.plan
    }
    pub fn token(&self) -> GuardToken {
        GuardToken {
            instance: self.instance.clone(),
            epoch: self.epoch,
        }
    }
    fn terminal(&self) -> bool {
        matches!(self.stage, GuardStage::Stopped | GuardStage::Failed)
    }
    fn fail(&mut self) {
        if self.terminal() {
            return;
        }
        self.stage = GuardStage::Failed;
        self.next = None;
        self.pending = true;
    }
    fn clock(&mut self, now: u64) -> Result<()> {
        if now > MAX_TIME || now < self.last_now {
            self.fail();
            return Err(err(Reason::InvalidEvidence));
        }
        self.last_now = now;
        if now - self.last_poll >= WATCHDOG_MS {
            self.fail();
            return Err(err(Reason::StaleEvidence));
        }
        Ok(())
    }
    fn quarantine(&mut self) {
        if self.terminal() {
            return;
        }
        if let Some(epoch) = self.epoch.checked_add(1) {
            self.epoch = epoch;
        } else {
            self.fail();
            return;
        }
        self.stage = GuardStage::Quarantined;
        self.next = Some(Step::Quarantine);
        self.pending = true;
    }
    pub fn complete(
        &mut self,
        token: &GuardToken,
        step: Step,
        digest: [u8; 32],
        now: u64,
    ) -> Result<()> {
        self.clock(now)?;
        if self.terminal()
            || !std::sync::Arc::ptr_eq(&self.instance, &token.instance)
            || token.epoch != self.epoch
            || self.next != Some(step)
        {
            return Err(err(Reason::InvalidTransition));
        }
        if digest != self.plan.fingerprint {
            self.quarantine();
            return Err(err(Reason::InvalidEvidence));
        }
        self.next = match step {
            Step::Quarantine => {
                self.pending = false;
                Some(Step::Capture)
            }
            Step::Capture => Some(Step::Commit),
            Step::Commit => Some(Step::Reconcile),
            Step::Reconcile => {
                self.stage = GuardStage::Prepared;
                None
            }
        };
        Ok(())
    }
    pub fn disappear(&mut self, now: u64) -> Result<()> {
        self.clock(now)?;
        self.quarantine();
        Ok(())
    }
    pub fn reconcile(&mut self, digest: [u8; 32], now: u64) -> Result<()> {
        self.clock(now)?;
        if self.terminal() {
            return Err(err(Reason::InvalidTransition));
        }
        if digest != self.plan.fingerprint {
            self.quarantine();
            return Err(err(Reason::InvalidEvidence));
        }
        // Equality alone never advances installation/recovery or renews the poll watchdog.
        Ok(())
    }
    /// Explicit recovery; complete all four ordering obligations again. No terminal revival.
    pub fn restart(&mut self, now: u64) -> Result<GuardToken> {
        self.clock(now)?;
        if self.terminal() {
            return Err(err(Reason::InvalidTransition));
        }
        if self.restarts >= 1024 {
            self.fail();
            return Err(err(Reason::InvalidTransition));
        }
        self.restarts += 1;
        self.quarantine();
        Ok(self.token())
    }
    /// Explicit generation-bound re-selection. Even rejected selection invalidates
    /// old callbacks and requests quarantine; no fallback to an old node/mode.
    pub fn select(&mut self, plan: GuardPlan, now: u64) -> Result<GuardToken> {
        self.clock(now)?;
        if self.terminal() {
            return Err(err(Reason::InvalidTransition));
        }
        self.quarantine();
        if plan.config.client_id != self.plan.config.client_id
            || plan.deployment != self.plan.deployment
            || plan.config.namespace != self.plan.config.namespace
            || plan.config.boot_id != self.plan.config.boot_id
            || plan.selection.generation <= self.plan.selection.generation
        {
            return Err(err(Reason::InvalidEvidence));
        }
        if self.restarts >= 1024 {
            self.fail();
            return Err(err(Reason::InvalidTransition));
        }
        self.restarts += 1;
        self.plan = plan;
        Ok(self.token())
    }
    /// Ordinary service/Tailscale stop retains enforcement and has no uninstall side effect.
    pub fn stop(&mut self, now: u64) -> Result<()> {
        self.clock(now)?;
        if !self.terminal() {
            self.stage = GuardStage::Stopped;
            self.next = None;
            self.pending = true;
        }
        Ok(())
    }
    pub fn poll(&mut self, now: u64) -> Result<Vec<Step>> {
        // Clock failure latches Failed and queues quarantine. Deliver that work
        // even while the clock remains broken; never lower the high-water mark
        // or renew the watchdog on an invalid/expired poll.
        if self.clock(now).is_ok() {
            self.last_poll = now;
        }
        // Coalesce missed work; never replay timer ticks, never remove quarantine.
        Ok(if std::mem::take(&mut self.pending) {
            vec![Step::Quarantine]
        } else {
            vec![]
        })
    }
    pub fn status(&self, now: u64) -> Result<GuardStatus> {
        if now > MAX_TIME || now < self.last_now {
            return Err(err(Reason::InvalidEvidence));
        }
        let stage = if !self.terminal() && now - self.last_poll >= WATCHDOG_MS {
            GuardStage::Quarantined
        } else {
            self.stage
        };
        Ok(GuardStatus {
            stage,
            dns: "not_tested",
            ipv6: "not_tested",
            observed_egress: "not_tested",
            exposure: if self.plan.selection.mode == crate::config::ExitMode::Direct {
                "direct-exposed"
            } else {
                "unverified"
            },
        })
    }
}
#[derive(Clone, Copy)]
pub enum ProxyProtocol {
    Socks5,
    HttpConnect,
}
pub struct ProxyRequest {
    pub host: String,
    pub port: u16,
    pub resolver: &'static str,
    pub address_family: &'static str,
    pub pool_key: [u8; 32],
}
fn invalid() -> crate::reason::Error {
    err(Reason::InvalidEvidence)
}
fn parse_socks(bytes: &[u8]) -> Result<(String, u16)> {
    if bytes.len() < 7 || bytes[..3] != [5, 1, 0] {
        return Err(invalid());
    }
    let (host, end) = match bytes[3] {
        1 if bytes.len() == 10 => (
            std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]).to_string(),
            8,
        ),
        3 => {
            let len = bytes[4] as usize;
            if len == 0 || bytes.len() != 7 + len {
                return Err(invalid());
            }
            (
                std::str::from_utf8(&bytes[5..5 + len])
                    .map_err(|_| invalid())?
                    .to_string(),
                5 + len,
            )
        }
        _ => return Err(invalid()),
    };
    Ok((host, u16::from_be_bytes([bytes[end], bytes[end + 1]])))
}
fn parse_connect(bytes: &[u8]) -> Result<(String, u16)> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    if !text.ends_with("\r\n\r\n") || !text.is_ascii() {
        return Err(invalid());
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let parts: Vec<_> = lines.next().ok_or_else(invalid)?.split(' ').collect();
    if parts.len() != 3 || parts[0] != "CONNECT" || parts[2] != "HTTP/1.1" {
        return Err(invalid());
    }
    let authority = parts[1];
    let mut seen = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        // Bounded CONNECT-only subset: credentials, body framing and ambiguous headers refuse.
        if !name.eq_ignore_ascii_case("host")
            || seen
            || value.trim_matches([' ', '\t']) != authority
        {
            return Err(invalid());
        }
        seen = true;
    }
    if !seen {
        return Err(invalid());
    }
    let (_, port) = crate::address::authority(authority)?;
    let (host, _) = authority.split_once(':').ok_or_else(invalid)?;
    Ok((host.to_string(), port))
}

fn validate_target(host: &str, port: u16) -> Result<()> {
    if port == 0 {
        return Err(invalid());
    }
    crate::address::public_target(host)?;
    Ok(())
}
