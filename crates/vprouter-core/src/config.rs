use crate::{
    profile::Profile,
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
impl ValidatedConfiguration {
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
        let mut private_keys = HashSet::new();
        let mut validated = Vec::new();
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
                    if !private_keys.insert(parsed.private_key_identity()) {
                        return Err(err(Reason::DuplicatePrivateKey));
                    }
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
        Ok(ValidatedConfiguration {
            configuration: self,
            exits: validated,
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
