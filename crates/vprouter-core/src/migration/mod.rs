//! Fixture-only migration preparation. No native lifecycle or secret-byte authority.
use crate::{allocation::AllocationRecord, config::Configuration};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub mod contract;
mod storage;
pub use storage::FixtureTree;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    UnsafeTree,
    Drift,
    Busy,
    Interrupted,
    Offline,
    Terminal,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    CurrentMain,
    Retry528fece,
    Retry84fb353,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Host {
    Debian13Systemd,
    ArchSystemd,
    VoidGlibcRunit,
    Unsupported,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    DeclaredFixture,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub node_id: String,
    pub ips: Vec<String>,
    pub approved_routes: Vec<String>,
    pub expected_server: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyConfig {
    pub name: String,
    pub profile: String,
    pub state_dir: String,
    pub image_ref: String,
    pub compose_dir: String,
    #[serde(default, deserialize_with = "hostname_option")]
    pub tailscale_hostname: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source_sha256: String,
    pub image_sha256: String,
    pub release_format: u32,
    pub state_format: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Selector {
    StableNodeId,
    DeclaredHostname,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub id: String,
    pub hook: String,
    pub adapter: String,
    pub selector: Selector,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostnameUsers {
    CompleteFixtureDeclaration,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceScope {
    SyntheticFixtureOnly,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Containment {
    QuarantineRequired,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientCoverage {
    Unverified,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub schema_version: u32,
    pub layout: Layout,
    pub host: Host,
    pub ownership: Ownership,
    pub hostname_users: HostnameUsers,
    pub provenance: Provenance,
    pub identity: Identity,
    pub service: String,
    pub container: String,
    pub uplink: String,
    pub dependencies: Vec<Dependency>,
}
/// Only a closed set of PUBLIC text assets is admitted. Opaque files are separate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub files: BTreeMap<String, String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinKind {
    File,
    Directory,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mode: u32,
    pub owner: u32,
    pub group: u32,
    pub links: u64,
    pub kind: PinKind,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    inventory: Inventory,
    inventory_bytes: String,
    public_pins: BTreeMap<String, Pin>,
    bundle: Bundle,
    opaque: BTreeMap<String, Pin>,
    fingerprint: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub configuration: Configuration,
    pub release: Bundle,
    pub provenance: Provenance,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    scope: EvidenceScope,
    containment: Containment,
    client_coverage: ClientCoverage,
    inspection: Inspection,
    new: Bundle,
    configuration: Configuration,
    allocations: AllocationRecord,
    provenance: Provenance,
    fingerprint: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Forward,
    Reverse,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    CommittedFixture,
    RolledBackFixture,
    Offline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoStep {
    CreateDirectory,
    CreateFile,
    Write,
    SyncFile,
    PublishJournal,
    ExchangeRelease,
    SyncDirectory,
    RemoveFile,
    RemoveDirectory,
    Lifecycle,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edge {
    Before,
    After,
}
/// Inject errors or terminate the fixture harness at syscall boundaries. No exec hook.
pub trait Fault {
    fn boundary(&mut self, step: IoStep, edge: Edge) -> Result<()>;
}
pub struct NoFault;
impl Fault for NoFault {
    fn boundary(&mut self, _: IoStep, _: Edge) -> Result<()> {
        Ok(())
    }
}
// Must not exceed the strict JSON reader's per-object key bound (128, see the
// object-key check below): every admitted custody map has to round-trip through
// the real plan/journal decoder.
const MAX_OPAQUE: usize = 128;
const MAX_OPAQUE_DEPTH: usize = 16;
const MAX_JSON: usize = 2 * 1024 * 1024;
const MAX_FILE: usize = 128 * 1024;
const MAX_BUNDLE: usize = 512 * 1024;
const ASSETS: &[&str] = &[
    "image.fixture",
    "router_runtime.py",
    "router.nft",
    "Dockerfile",
    "docker-compose.yaml",
    "host/orchestrate.py",
    "host/vprouter@.service",
    "host/collector_services.py",
    "host/collector-services.conf",
];
fn hash(bytes: impl AsRef<[u8]>) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Invalid)?;
    if bytes.len() > MAX_JSON {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
// Validate duplicate keys at EVERY nested map, before typed decoding. Serde's
// ordinary BTreeMap decoder otherwise silently accepts the final duplicate.
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    use serde::de::{self, MapAccess, SeqAccess, Visitor};
    struct Strict;
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Strict;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("bounded JSON without duplicate keys")
                }
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Strict, A::Error> {
                    let mut keys = std::collections::HashSet::new();
                    while let Some(k) = a.next_key::<String>()? {
                        if k.len() > 4096 || keys.len() >= 128 || !keys.insert(k) {
                            return Err(de::Error::custom("invalid map"));
                        }
                        a.next_value::<Strict>()?;
                    }
                    Ok(Strict)
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Strict, A::Error> {
                    let mut n = 0;
                    while a.next_element::<Strict>()?.is_some() {
                        n += 1;
                        if n > 128 {
                            return Err(de::Error::custom("invalid array"));
                        }
                    }
                    Ok(Strict)
                }
                fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                    if v.len() > MAX_BUNDLE {
                        Err(de::Error::custom("invalid string"))
                    } else {
                        Ok(Strict)
                    }
                }
                fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<Strict, E> {
                    Ok(Strict)
                }
                fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<Strict, E> {
                    Ok(Strict)
                }
                fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<Strict, E> {
                    Ok(Strict)
                }
                fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Strict, E> {
                    Ok(Strict)
                }
                fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                    Ok(Strict)
                }
            }
            d.deserialize_any(V)
        }
    }
    if bytes.len() > MAX_JSON {
        return Err(Error::Invalid);
    }
    serde_json::from_slice::<Strict>(bytes).map_err(|_| Error::Invalid)?;
    serde_json::from_slice(bytes).map_err(|_| Error::Invalid)
}
fn hostname_option<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
fn name(s: &str) -> Result<()> {
    crate::config::label(s, 63).map_err(|_| Error::Invalid)
}
fn legacy_label(s: &str) -> Result<()> {
    name(s)?;
    if !(2..=50).contains(&s.len()) || !s.as_bytes()[0].is_ascii_lowercase() {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn path(s: &str) -> Result<()> {
    if s.len() > 256
        || !s.starts_with('/')
        || s == "/"
        || s.split('/')
            .skip(1)
            .any(|c| c.is_empty() || c == "." || c == "..")
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/._@-".contains(&c))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn pin_valid(p: &Provenance) -> Result<()> {
    if ![&p.source_sha256, &p.image_sha256].iter().all(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) || p.release_format == 0
        || p.state_format == 0
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
impl Inventory {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.dependencies.len() > 16 {
            return Err(Error::Invalid);
        }
        pin_valid(&self.provenance)?;
        for n in [
            &self.service,
            &self.container,
            &self.uplink,
            &self.identity.node_id,
        ] {
            name(n)?;
        }
        crate::config::server_name(&self.identity.expected_server).map_err(|_| Error::Invalid)?;
        if self.identity.ips.is_empty()
            || self.identity.ips.len() > 16
            || self.identity.approved_routes.is_empty()
            || self.identity.approved_routes.len() > 2
            || !self
                .identity
                .approved_routes
                .iter()
                .any(|s| s == "0.0.0.0/0")
            || self
                .identity
                .approved_routes
                .iter()
                .any(|s| s != "0.0.0.0/0" && s != "::/0")
            || self
                .identity
                .approved_routes
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != self.identity.approved_routes.len()
        {
            return Err(Error::Invalid);
        }
        let mut ips = std::collections::HashSet::new();
        for ip in &self.identity.ips {
            let ipv4 = crate::address::ipv4(ip)
                .is_ok_and(|a| a.octets()[0] == 100 && (64..128).contains(&a.octets()[1]));
            // IPv6 is retained control metadata ONLY, never a target or route grant.
            let ipv6 = ip.parse::<std::net::Ipv6Addr>().is_ok_and(|a| {
                a.to_string() == *ip && a.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0]
            });
            if (!ipv4 && !ipv6) || !ips.insert(ip) {
                return Err(Error::Invalid);
            }
        }
        let mut deps = std::collections::HashSet::new();
        let mut hooks = std::collections::HashSet::new();
        for d in &self.dependencies {
            name(&d.id)?;
            name(&d.adapter)?;
            hook_path(&d.hook)?;
            if !deps.insert(&d.id) || !hooks.insert(&d.hook) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}
fn hook_path(s: &str) -> Result<()> {
    let n = s
        .strip_prefix("host/")
        .and_then(|s| s.strip_suffix(".json"))
        .ok_or(Error::Invalid)?;
    name(n)
}
impl Bundle {
    fn bounded(&self) -> Result<()> {
        if self.files.len() > 32
            || self.files.keys().any(|s| s.len() > 256)
            || self
                .files
                .values()
                .any(|s| s.len() > MAX_FILE || s.contains('\0'))
        {
            return Err(Error::Invalid);
        }
        self.files.values().try_fold(0usize, |n, s| {
            n.checked_add(s.len())
                .filter(|n| *n <= MAX_BUNDLE)
                .ok_or(Error::Invalid)
        })?;
        Ok(())
    }
    fn validate(&self, inventory: &Inventory, extras: &[&str]) -> Result<()> {
        self.bounded()?;
        let expected: std::collections::BTreeSet<&str> = ASSETS
            .iter()
            .copied()
            .chain(extras.iter().copied())
            .chain(inventory.dependencies.iter().map(|d| d.hook.as_str()))
            .collect();
        if self
            .files
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != expected
            || self
                .files
                .values()
                .any(|s| s.len() > MAX_FILE || s.contains('\0'))
            || self.files.values().map(String::len).sum::<usize>() > MAX_BUNDLE
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn fingerprint(&self) -> Result<String> {
        self.bounded()?;
        Ok(hash(encode(self)?))
    }
}
impl Inspection {
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }
    pub fn opaque_pins(&self) -> &BTreeMap<String, Pin> {
        &self.opaque
    }
    fn digest(&self) -> Result<String> {
        Ok(hash(encode(&(
            &self.inventory_bytes,
            &self.bundle,
            &self.public_pins,
            &self.opaque,
        ))?))
    }
    fn validate(&self) -> Result<LegacyConfig> {
        self.inventory.validate()?;
        if encode(&Inventory::parse(self.inventory_bytes.as_bytes())?)? != encode(&self.inventory)?
            || self.fingerprint != self.digest()?
        {
            return Err(Error::Invalid);
        }
        self.bundle.validate(&self.inventory, &["config.json"])?;
        if self.opaque.len() > MAX_OPAQUE
            || !self.opaque.contains_key("/")
            || !self.opaque.contains_key("profile.wg")
            || !self.opaque.contains_key("state")
        {
            return Err(Error::Invalid);
        }
        let mut identities = std::collections::BTreeSet::new();
        for (name, pin) in &self.opaque {
            if name != "/" {
                path(&format!("/{name}"))?;
                if name != "profile.wg" && name != "state" && !name.starts_with("state/") {
                    return Err(Error::Invalid);
                }
                if name.split('/').count() > MAX_OPAQUE_DEPTH {
                    return Err(Error::Invalid);
                }
                if let Some((parent, _)) = name.rsplit_once('/')
                    && self.opaque.get(parent).map(|p| p.kind) != Some(PinKind::Directory)
                {
                    return Err(Error::Invalid);
                }
            }
            let directory = pin.kind == PinKind::Directory;
            if pin.mode != if directory { 0o700 } else { 0o600 }
                || (!directory && pin.links != 1)
                || !identities.insert((pin.device, pin.inode))
                || ((name == "/" || name == "state") && !directory)
                || (name == "profile.wg" && directory)
            {
                return Err(Error::Invalid);
            }
        }
        let mut legacy: LegacyConfig = decode(self.bundle.files["config.json"].as_bytes())?;
        if legacy.tailscale_hostname.is_none() {
            legacy.tailscale_hostname = Some(legacy.name.clone());
        }
        for p in [&legacy.profile, &legacy.state_dir, &legacy.compose_dir] {
            path(p)?;
        }
        legacy_label(&legacy.name)?;
        legacy_label(legacy.tailscale_hostname.as_deref().ok_or(Error::Invalid)?)?;
        if legacy.name != self.inventory.container
            || self.inventory.service != legacy.name
            || self.inventory.uplink != format!("{}-uplink", legacy.name)
            || legacy.image_ref != format!("sha256:{}", self.inventory.provenance.image_sha256)
        {
            return Err(Error::Invalid);
        }
        Ok(legacy)
    }
    pub fn plan(&self, mut request: Request) -> Result<Plan> {
        let legacy = self.validate()?;
        request.release.bounded()?;
        let source_bundle = |bundle: &Bundle| Bundle {
            files: bundle
                .files
                .iter()
                .filter(|(p, _)| ASSETS.contains(&p.as_str()))
                .map(|(p, v)| (p.clone(), v.clone()))
                .collect(),
        };
        if source_bundle(&self.bundle).fingerprint()? != self.inventory.provenance.source_sha256
            || hash(self.bundle.files["image.fixture"].as_bytes())
                != self.inventory.provenance.image_sha256
            || request.release.fingerprint()? != request.provenance.source_sha256
            || request
                .release
                .files
                .get("image.fixture")
                .map(|s| hash(s.as_bytes()))
                .as_ref()
                != Some(&request.provenance.image_sha256)
        {
            return Err(Error::Invalid);
        }

        if self.inventory.host == Host::Unsupported
            || self.inventory.ownership != Ownership::DeclaredFixture
            || self.inventory.hostname_users != HostnameUsers::CompleteFixtureDeclaration
        {
            return Err(Error::Invalid);
        }
        pin_valid(&request.provenance)?;
        if request.provenance.state_format != self.inventory.provenance.state_format
            || request.provenance.release_format == self.inventory.provenance.release_format
            || request.configuration.gateway_image
                != format!("sha256:{}", request.provenance.image_sha256)
        {
            return Err(Error::Invalid);
        }
        let c = &request.configuration;
        if c.exits.len() != 1
            || c.dependency_adapters.len() > 16
            || c.client_policies.len() > 128
            || c.client_policies
                .iter()
                .any(|p| p.selected_node_id != self.inventory.identity.node_id)
        {
            return Err(Error::Invalid);
        }
        let structure = c.clone().validate_structure().map_err(|_| Error::Invalid)?;
        let allocations =
            AllocationRecord::from_structure(&structure, 1).map_err(|_| Error::Invalid)?;
        allocations
            .validate(&c.deployment_id, &[])
            .map_err(|_| Error::Invalid)?;
        if c.exits.len() != 1
            || c.exits[0].id != "primary"
            || !c.exits[0].enabled
            || c.exits[0].state_dir.to_str() != Some(&legacy.state_dir)
            || c.exits[0].enrollment_key_file.is_some()
        {
            return Err(Error::Invalid);
        }
        match &c.exits[0].mode {
            crate::config::Mode::Mullvad {
                profile,
                expected_server,
            } if profile.to_str() == Some(&legacy.profile)
                && expected_server == &self.inventory.identity.expected_server => {}
            _ => return Err(Error::Invalid),
        }
        // Strengthen all executable/path encodings, including typed construction.
        for a in &c.dependency_adapters {
            for action in [&a.drain, &a.stop, &a.rebind, &a.start, &a.health_check] {
                path(action.executable.to_str().ok_or(Error::Invalid)?)?;
                if action.argv.iter().any(|arg| {
                    arg.len() > 256 || !arg.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
                }) {
                    return Err(Error::Invalid);
                }
            }
        }
        let declared: std::collections::BTreeSet<_> = self
            .inventory
            .dependencies
            .iter()
            .map(|d| d.adapter.as_str())
            .collect();
        let adapters: std::collections::BTreeSet<_> = c
            .dependency_adapters
            .iter()
            .map(|d| d.id.as_str())
            .collect();
        if declared != adapters
            || self
                .inventory
                .dependencies
                .iter()
                .any(|d| d.selector == Selector::Unknown)
        {
            return Err(Error::Invalid);
        }
        for d in &self.inventory.dependencies {
            if request
                .release
                .files
                .insert(d.hook.clone(), self.bundle.files[&d.hook].clone())
                .is_some()
            {
                return Err(Error::Invalid);
            }
        }
        request.release.validate(&self.inventory, &[])?;
        request.release.files.insert(
            "config.json".into(),
            String::from_utf8(encode(c)?).map_err(|_| Error::Invalid)?,
        );
        request.release.files.insert(
            "allocations.json".into(),
            String::from_utf8(encode(&allocations)?).map_err(|_| Error::Invalid)?,
        );
        request.release.files.insert(
            "wrappers.json".into(),
            String::from_utf8(encode(&contract::wrappers(
                "/synthetic/bin/vprouter",
                &legacy.name,
            )?)?)
            .map_err(|_| Error::Invalid)?,
        );
        request.release.validate(
            &self.inventory,
            &["config.json", "allocations.json", "wrappers.json"],
        )?;
        let mut plan = Plan {
            scope: EvidenceScope::SyntheticFixtureOnly,
            containment: Containment::QuarantineRequired,
            client_coverage: ClientCoverage::Unverified,
            inspection: self.clone(),
            new: request.release,
            configuration: request.configuration,
            allocations,
            provenance: request.provenance,
            fingerprint: String::new(),
        };
        plan.fingerprint = plan.digest()?;
        encode(&plan)?;
        storage::check_journal_capacity(&plan)?;
        Ok(plan)
    }
}
impl Plan {
    fn digest(&self) -> Result<String> {
        Ok(hash(encode(&(
            &self.scope,
            &self.containment,
            &self.client_coverage,
            &self.inspection,
            &self.new,
            &self.configuration,
            &self.allocations,
            &self.provenance,
        ))?))
    }
    fn validate(&self) -> Result<()> {
        self.new.bounded()?;
        self.inspection.bundle.bounded()?;
        if self.fingerprint != self.digest()? {
            return Err(Error::Invalid);
        }
        let mut release = self.new.clone();
        for p in ["config.json", "allocations.json", "wrappers.json"] {
            release.files.remove(p);
        }
        for d in &self.inspection.inventory.dependencies {
            release.files.remove(&d.hook);
        }
        let rebuilt = self.inspection.plan(Request {
            configuration: self.configuration.clone(),
            release,
            provenance: self.provenance.clone(),
        })?;
        if encode(&rebuilt)? != encode(self)? {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let plan: Self = decode(bytes)?;
        plan.validate()?;
        Ok(plan)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self)
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn old_bundle(&self) -> &Bundle {
        &self.inspection.bundle
    }
    pub fn new_bundle(&self) -> &Bundle {
        &self.new
    }
    pub fn identity(&self) -> &Identity {
        &self.inspection.inventory.identity
    }
}

/// Library JSON dispatch only. The production CLI does not consume this type.
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Inspect {},
    Plan { request: Request },
    Apply { plan: Plan },
    Resume { plan: Plan },
    Rollback { plan: Plan },
}
impl Command {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let command: Self = decode(bytes)?;
        match &command {
            Self::Apply { plan } | Self::Resume { plan } | Self::Rollback { plan } => {
                plan.validate()?
            }
            _ => {}
        }
        Ok(command)
    }
}
