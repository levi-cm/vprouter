use crate::{
    profile::{Profile, PublicProfile},
    reason::{Reason, Result, err},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

pub const MAX_EXITS: usize = 128;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub schema_version: u32,
    pub deployment_id: String,
    pub site: String,
    pub gateway_image: String,
    pub exits: Vec<Exit>,
    pub dependency_adapters: Vec<DependencyAdapter>,
    pub client_policies: Vec<ClientPolicy>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exit {
    pub id: String,
    pub enabled: bool,
    pub state_dir: PathBuf,
    pub enrollment_key_file: Option<PathBuf>,
    pub mode: Mode,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mode {
    Mullvad {
        profile: PathBuf,
        expected_server: String,
    },
    Direct {},
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitMode {
    Mullvad,
    Direct,
}
impl Mode {
    pub fn kind(&self) -> ExitMode {
        match self {
            Self::Mullvad { .. } => ExitMode::Mullvad,
            Self::Direct {} => ExitMode::Direct,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub timeout_seconds: u16,
    pub idempotent: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyAdapter {
    pub id: String,
    pub drain: Action,
    pub stop: Action,
    pub rebind: Action,
    pub start: Action,
    pub health_check: Action,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientMode {
    Protected,
    Direct,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPolicy {
    pub id: String,
    pub exit_id: String,
    pub selected_node_id: String,
    pub mode: ClientMode,
    pub dependency_adapters: Vec<String>,
}
// Deliberately not Debug/Serialize: this object owns parsed private keys.
pub struct ValidatedConfiguration {
    configuration: Configuration,
    exits: Vec<ValidatedExit>,
}
pub struct ValidatedExit {
    exit: Exit,
    hostname: String,
    profile: Option<Profile>,
}
/// Validated public shape, without any claim that a referenced profile exists.
/// Owner-domain/allocation intents may be established from this before the first
/// secret-role birth. No native mutation permit is derived from this type alone.
pub struct StructuredConfiguration {
    configuration: Configuration,
    hostnames: Vec<String>,
}
pub const MAX_PUBLIC_CONFIGURATION_BYTES: usize = 256 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicConfigurationReport {
    configuration_digest: [u8; 32],
    exits: Vec<PublicExitReport>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicExitReport {
    id: String,
    hostname: String,
    mode: ExitMode,
    profile: Option<PublicProfile>,
}
/// Public facts bound to the exact public input. Launch additionally requires
/// its constructor-origin no-fork child receipt; parsing this is not admission.
#[derive(Clone)]
pub struct PublicConfiguration {
    configuration: Configuration,
    exits: Vec<PublicExit>,
}
#[derive(Clone)]
pub struct PublicExit {
    exit: Exit,
    hostname: String,
    profile: Option<PublicProfile>,
}
fn public_configuration_digest(config: &Configuration) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(config).map_err(|_| err(Reason::InvalidSchema))?;
    Ok(Sha256::digest(bytes).into())
}
impl PublicConfigurationReport {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| err(Reason::InvalidSchema))?;
        if bytes.len() > MAX_PUBLIC_CONFIGURATION_BYTES {
            return Err(err(Reason::InvalidSchema));
        }
        Ok(bytes)
    }
}
impl StructuredConfiguration {
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        public_configuration_digest(&self.configuration)
    }
    pub fn bind_public_report(self, bytes: &[u8]) -> Result<PublicConfiguration> {
        if bytes.len() > MAX_PUBLIC_CONFIGURATION_BYTES {
            return Err(err(Reason::InvalidSchema));
        }
        let report: PublicConfigurationReport =
            serde_json::from_slice(bytes).map_err(|_| err(Reason::InvalidSchema))?;
        if report.configuration_digest != self.digest()?
            || report.exits.len() != self.configuration.exits.len()
        {
            return Err(err(Reason::InvalidSchema));
        }
        let mut devices = HashSet::new();
        let mut exits = Vec::with_capacity(report.exits.len());
        for ((exit, hostname), reported) in self
            .configuration
            .exits
            .iter()
            .zip(self.hostnames)
            .zip(report.exits)
        {
            if reported.id != exit.id
                || reported.hostname != hostname
                || reported.mode != exit.mode.kind()
            {
                return Err(err(Reason::InvalidSchema));
            }
            match (&exit.mode, &reported.profile) {
                (
                    Mode::Mullvad {
                        expected_server, ..
                    },
                    Some(profile),
                ) => {
                    profile.validate()?;
                    if profile.expected_server() != expected_server {
                        return Err(err(Reason::ProfileServerMismatch));
                    }
                    if !devices.insert(profile.device_public_key()) {
                        return Err(err(Reason::DuplicatePrivateKey));
                    }
                }
                (Mode::Direct {}, None) => {}
                _ => return Err(err(Reason::InvalidSchema)),
            }
            exits.push(PublicExit {
                exit: exit.clone(),
                hostname,
                profile: reported.profile,
            });
        }
        Ok(PublicConfiguration {
            configuration: self.configuration,
            exits,
        })
    }
}
impl PublicConfiguration {
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn exits(&self) -> &[PublicExit] {
        &self.exits
    }
    /// Re-encode only the already-public facts for an exact fixed-role reload
    /// comparison. This does not read profiles or mint native admission.
    pub fn public_report(&self) -> Result<PublicConfigurationReport> {
        Ok(PublicConfigurationReport {
            configuration_digest: public_configuration_digest(&self.configuration)?,
            exits: self
                .exits
                .iter()
                .map(|exit| PublicExitReport {
                    id: exit.exit.id.clone(),
                    hostname: exit.hostname.clone(),
                    mode: exit.exit.mode.kind(),
                    profile: exit.profile.clone(),
                })
                .collect(),
        })
    }
}
impl PublicExit {
    pub fn exit(&self) -> &Exit {
        &self.exit
    }
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
    pub fn profile(&self) -> Option<&PublicProfile> {
        self.profile.as_ref()
    }
}

impl ValidatedConfiguration {
    pub fn public_report(&self) -> Result<PublicConfigurationReport> {
        Ok(PublicConfigurationReport {
            configuration_digest: public_configuration_digest(&self.configuration)?,
            exits: self
                .exits
                .iter()
                .map(|exit| PublicExitReport {
                    id: exit.exit.id.clone(),
                    hostname: exit.hostname.clone(),
                    mode: exit.exit.mode.kind(),
                    profile: exit.profile.as_ref().map(Profile::public_metadata),
                })
                .collect(),
        })
    }
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn exits(&self) -> &[ValidatedExit] {
        &self.exits
    }
}
impl ValidatedExit {
    pub fn exit(&self) -> &Exit {
        &self.exit
    }
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
    pub fn profile(&self) -> Option<&Profile> {
        self.profile.as_ref()
    }
}
impl Configuration {
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(err(Reason::InvalidSchema));
        }
        serde_json::from_slice(input).map_err(|_| err(Reason::InvalidSchema))
    }
    pub fn validate(self) -> Result<ValidatedConfiguration> {
        self.validate_with(Profile::load)
    }
    /// Reader injection allows offline tests without opening real credentials.
    /// Readers MUST avoid symlinks and return only authored, sanitized errors.
    pub fn validate_with<F>(self, mut reader: F) -> Result<ValidatedConfiguration>
    where
        F: FnMut(&Path, &str) -> Result<Profile>,
    {
        let structural = self.validate_structure()?;
        let mut private_keys = Vec::with_capacity(structural.configuration.exits.len());
        let mut validated = Vec::with_capacity(structural.configuration.exits.len());
        for (exit, hostname) in structural
            .configuration
            .exits
            .iter()
            .zip(structural.hostnames)
        {
            let profile = match &exit.mode {
                Mode::Mullvad {
                    profile,
                    expected_server,
                } => {
                    let parsed = reader(profile, expected_server).map_err(|e| err(e.reason()))?;
                    // A reader cannot bypass the configured exact server binding.
                    if parsed.expected_server() != expected_server {
                        return Err(err(Reason::ProfileServerMismatch));
                    }
                    let identity = parsed.private_key_identity();
                    if private_keys.contains(&identity) {
                        return Err(err(Reason::DuplicatePrivateKey));
                    }
                    private_keys.push(identity);
                    Some(parsed)
                }
                Mode::Direct {} => None,
            };
            validated.push(ValidatedExit {
                exit: exit.clone(),
                hostname,
                profile,
            });
        }
        Ok(ValidatedConfiguration {
            configuration: structural.configuration,
            exits: validated,
        })
    }
    /// Public shape validation only: never opens or reads a profile. It cannot
    /// authorize provisioning; all profiles, including disabled members, still
    /// require the no-fork child's full validation and exact native receipt.
    pub fn validate_structure(self) -> Result<StructuredConfiguration> {
        if self.schema_version != 2
            || self.exits.is_empty()
            || self.exits.len() > MAX_EXITS
            || self.dependency_adapters.len() > 128
            || self.client_policies.len() > 1024
        {
            return Err(err(Reason::InvalidSchema));
        }
        label(&self.deployment_id, 32)?;
        label(&self.site, 63)?;
        pinned_image(&self.gateway_image)?;
        let mut ids = HashSet::new();
        let mut state_dirs: Vec<&Path> = Vec::new();
        let mut names = Vec::new();
        let mut counts = HashMap::new();
        for exit in &self.exits {
            label(&exit.id, 32)?;
            if !ids.insert(exit.id.as_str()) {
                return Err(err(Reason::DuplicateId));
            }
            absolute_path(&exit.state_dir)?;
            if exit.state_dir == Path::new("/")
                || state_dirs
                    .iter()
                    .any(|p| p.starts_with(&exit.state_dir) || exit.state_dir.starts_with(p))
            {
                return Err(err(Reason::StateConflict));
            }
            state_dirs.push(&exit.state_dir);
            if let Some(p) = &exit.enrollment_key_file {
                absolute_path(p)?;
            }
            let name = match &exit.mode {
                Mode::Mullvad {
                    profile,
                    expected_server,
                } => {
                    absolute_path(profile)?;
                    server_name(expected_server)?;
                    format!("mullvad-{}-exit-{}", self.site, expected_server)
                }
                Mode::Direct {} => format!("unsafe-direct-host-ip-{}-exit", self.site),
            };
            *counts.entry(name.clone()).or_insert(0usize) += 1;
            names.push(name);
        }
        let mut unique_names = HashSet::new();
        let mut hostnames = Vec::with_capacity(self.exits.len());
        for (exit, base_name) in self.exits.iter().zip(names) {
            let hostname = if counts[&base_name] > 1 {
                format!("{base_name}-{}", exit.id)
            } else {
                base_name
            };
            label(&hostname, 63)?;
            if !unique_names.insert(hostname.clone()) {
                return Err(err(Reason::HostnameConflict));
            }
            hostnames.push(hostname);
        }
        let mut adapters = HashSet::new();
        for adapter in &self.dependency_adapters {
            label(&adapter.id, 32)?;
            if !adapters.insert(adapter.id.as_str()) {
                return Err(err(Reason::DuplicateId));
            }
            for action in [
                &adapter.drain,
                &adapter.stop,
                &adapter.rebind,
                &adapter.start,
                &adapter.health_check,
            ] {
                action.validate()?;
            }
        }
        let mut policies = HashSet::new();
        for policy in &self.client_policies {
            label(&policy.id, 32)?;
            if !policies.insert(policy.id.as_str()) {
                return Err(err(Reason::DuplicateId));
            }
            let exit = self
                .exits
                .iter()
                .find(|e| e.id == policy.exit_id)
                .ok_or_else(|| err(Reason::InvalidReference))?;
            if policy.selected_node_id.is_empty()
                || policy.selected_node_id.len() > 128
                || !policy
                    .selected_node_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                || !matches!(
                    (policy.mode, exit.mode.kind()),
                    (ClientMode::Protected, ExitMode::Mullvad)
                        | (ClientMode::Direct, ExitMode::Direct)
                )
            {
                return Err(err(Reason::InvalidReference));
            }
            let mut references = HashSet::new();
            for reference in &policy.dependency_adapters {
                if !adapters.contains(reference.as_str()) || !references.insert(reference) {
                    return Err(err(Reason::InvalidReference));
                }
            }
        }
        Ok(StructuredConfiguration {
            configuration: self,
            hostnames,
        })
    }
}
impl Action {
    fn validate(&self) -> Result<()> {
        absolute_path(&self.executable)?;
        let shell = self
            .executable
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if matches!(shell, "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh")
            || !self.idempotent
            || !(1..=300).contains(&self.timeout_seconds)
            || self.argv.len() > 64
            || self.argv.iter().any(|a| a.len() > 4096 || a.contains('\0'))
        {
            return Err(err(Reason::InvalidAdapter));
        }
        Ok(())
    }
}
pub(crate) fn label(s: &str, max: usize) -> Result<()> {
    if s.is_empty()
        || s.len() > max
        || !s.as_bytes()[0].is_ascii_lowercase() && !s.as_bytes()[0].is_ascii_digit()
        || !s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(err(Reason::InvalidLabel));
    }
    Ok(())
}
pub(crate) fn absolute_path(path: &Path) -> Result<()> {
    let s = path.to_str().ok_or_else(|| err(Reason::InvalidPath))?;
    if !s.starts_with('/')
        || s.contains('\0')
        || (s != "/"
            && s.split('/')
                .skip(1)
                .any(|p| p.is_empty() || p == "." || p == ".."))
    {
        return Err(err(Reason::InvalidPath));
    }
    Ok(())
}
pub(crate) fn server_name(s: &str) -> Result<()> {
    let parts: Vec<_> = s.split('-').collect();
    if parts.len() != 4
        || parts[0].len() != 2
        || !(2..=6).contains(&parts[1].len())
        || !parts[0].bytes().all(|b| b.is_ascii_lowercase())
        || !parts[1].bytes().all(|b| b.is_ascii_lowercase())
        || parts[2] != "wg"
        || parts[3].is_empty()
        || parts[3].len() > 4
        || !parts[3].bytes().all(|b| b.is_ascii_digit())
    {
        return Err(err(Reason::InvalidServer));
    }
    Ok(())
}
fn pinned_image(s: &str) -> Result<()> {
    let digest = if let Some(d) = s.strip_prefix("sha256:") {
        d
    } else {
        let (repo, d) = s
            .split_once("@sha256:")
            .ok_or_else(|| err(Reason::InvalidImage))?;
        if repo.is_empty()
            || repo.len() > 255
            || repo.contains('@')
            || repo.split('/').any(|part| part.is_empty())
        {
            return Err(err(Reason::InvalidImage));
        }
        let parts: Vec<_> = repo.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            if i == 0
                && parts.len() > 1
                && (part.contains('.') || part.contains(':') || *part == "localhost")
            {
                let host = if let Some((host, port)) = part.split_once(':') {
                    if port.is_empty()
                        || !port.bytes().all(|b| b.is_ascii_digit())
                        || port.parse::<u16>().ok().filter(|p| *p > 0).is_none()
                    {
                        return Err(err(Reason::InvalidImage));
                    }
                    host
                } else {
                    part
                };
                if host.split('.').any(|label| {
                    label.is_empty()
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                }) {
                    return Err(err(Reason::InvalidImage));
                }
            } else if !repository_component(part) {
                return Err(err(Reason::InvalidImage));
            }
        }
        d
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(err(Reason::InvalidImage));
    }
    Ok(())
}

fn repository_component(s: &str) -> bool {
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = s.as_bytes();
    let mut i = 0;
    if bytes.is_empty() || !alnum(bytes[0]) {
        return false;
    }
    while i < bytes.len() {
        if alnum(bytes[i]) {
            i += 1;
            continue;
        }
        match bytes[i] {
            b'.' => i += 1,
            b'_' => {
                i += 1;
                if i < bytes.len() && bytes[i] == b'_' {
                    i += 1;
                }
            }
            b'-' => {
                while i < bytes.len() && bytes[i] == b'-' {
                    i += 1;
                }
            }
            _ => return false,
        }
        if i == bytes.len() || !alnum(bytes[i]) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod public_configuration_tests {
    use super::*;
    const PROFILE: &[u8] = b"[Interface]\nPrivateKey=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress=10.64.0.2/32\nDNS=10.64.0.1\n[Peer]\nPublicKey=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint=185.65.134.88:51820\nAllowedIPs=0.0.0.0/0\n";
    fn configuration() -> Configuration {
        Configuration::parse(serde_json::to_vec(&serde_json::json!({
            "schema_version":2,"deployment_id":"secretlab","site":"testsite",
            "gateway_image":format!("sha256:{}", "a".repeat(64)),
            "exits":[{"id":"first","enabled":false,"state_dir":"/synthetic/first",
                "mode":{"kind":"mullvad","profile":"/nonexistent/synthetic.conf","expected_server":"de-fra-wg-401"}}],
            "dependency_adapters":[],"client_policies":[]
        })).unwrap().as_slice()).unwrap()
    }
    #[test]
    fn structural_configuration_never_loads_profiles_and_public_report_binds_exact_input() {
        let cfg = configuration();
        let structural = cfg.clone().validate_structure().unwrap();
        let prebirth_allocation =
            crate::allocation::AllocationRecord::from_structure(&structural, 7).unwrap();
        let mut read_count = 0;
        let secret = cfg
            .clone()
            .validate_with(|_, server| {
                read_count += 1;
                Profile::parse(PROFILE, server, None)
            })
            .unwrap();
        assert_eq!(read_count, 1); // Disabled exits retain validation, too.
        let bytes = secret.public_report().unwrap().encode().unwrap();
        let old_allocation =
            crate::allocation::AllocationRecord::from_configuration(&secret, 7).unwrap();
        assert_eq!(
            serde_json::to_vec(&prebirth_allocation).unwrap(),
            serde_json::to_vec(&old_allocation).unwrap()
        );
        drop(secret);
        let public = structural.bind_public_report(&bytes).unwrap();
        let public_allocation =
            crate::allocation::AllocationRecord::from_public_configuration(&public, 7).unwrap();
        assert_eq!(
            serde_json::to_vec(&public_allocation).unwrap(),
            serde_json::to_vec(&old_allocation).unwrap()
        );
        assert_eq!(
            public.exits()[0].profile().unwrap().endpoint().to_string(),
            "185.65.134.88:51820"
        );
        let mut different = cfg;
        different.site = "changedsite".into();
        assert!(
            different
                .validate_structure()
                .unwrap()
                .bind_public_report(&bytes)
                .is_err()
        );
        assert!(
            !bytes
                .windows(44)
                .any(|window| window == b"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
        );
    }
    #[test]
    fn public_report_cannot_substitute_disabled_member_or_secret_field() {
        let cfg = configuration();
        let secret = cfg
            .clone()
            .validate_with(|_, server| Profile::parse(PROFILE, server, None))
            .unwrap();
        let value = serde_json::to_value(secret.public_report().unwrap()).unwrap();
        let mut altered = value.clone();
        altered["exits"][0]["id"] = serde_json::json!("other");
        assert!(
            cfg.clone()
                .validate_structure()
                .unwrap()
                .bind_public_report(&serde_json::to_vec(&altered).unwrap())
                .is_err()
        );
        let mut altered = value;
        altered["exits"][0]["profile"]["private_key"] =
            serde_json::json!("synthetic-rejected-marker");
        assert!(
            cfg.validate_structure()
                .unwrap()
                .bind_public_report(&serde_json::to_vec(&altered).unwrap())
                .is_err()
        );
    }
}
