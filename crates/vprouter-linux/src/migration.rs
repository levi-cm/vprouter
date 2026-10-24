//! Review-only migration artifacts. No state bytes, backup, adapters or apply.
use crate::{
    Error, Result,
    docker::{Container, DockerClient},
    host, load_profile, sha256,
    storage::{self, Kind, Metadata},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use vprouter_core::config::{Configuration, Exit, Mode};

const RELEASE_FILES: &[&str] = &[
    "router_runtime.py",
    "router.nft",
    "Dockerfile",
    "docker-compose.yaml",
    "host/orchestrate.py",
    "host/vprouter@.service",
    "host/collector_services.py",
    "host/collector-services.conf",
];
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Legacy {
    pub name: String,
    pub profile: PathBuf,
    pub state_dir: PathBuf,
    pub image_ref: String,
    pub compose_dir: PathBuf,
    #[serde(default)]
    pub tailscale_hostname: Option<String>,
}
fn safe_path(p: &Path) -> bool {
    p.to_str().is_some_and(|s| {
        s.starts_with('/')
            && s != "/"
            && s.len() <= 4096
            && !s.chars().any(char::is_control)
            && s.split('/')
                .skip(1)
                .all(|s| !s.is_empty() && s != "." && s != "..")
    })
}
fn label(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
impl Legacy {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 1024 * 1024 {
            return Err(Error::TooLarge);
        }
        #[derive(Deserialize)]
        struct Version {
            schema_version: u32,
        }
        if serde_json::from_slice::<Version>(bytes).is_ok_and(|v| v.schema_version == 2) {
            return Err(Error::AlreadyV2);
        }
        let legacy: Self =
            serde_json::from_slice(bytes).map_err(|_| Error::InvalidLegacyConfiguration)?;
        if !label(&legacy.name, 63)
            || !safe_path(&legacy.profile)
            || !safe_path(&legacy.state_dir)
            || !safe_path(&legacy.compose_dir)
            || legacy
                .tailscale_hostname
                .as_ref()
                .is_some_and(|s| !label(s, 63))
        {
            return Err(Error::InvalidLegacyConfiguration);
        }
        // Reuse the strict image parser without reading a profile or identity.
        let check = Configuration {
            schema_version: 2,
            deployment_id: "inspection".into(),
            site: "inspection".into(),
            gateway_image: legacy.image_ref.clone(),
            exits: vec![Exit {
                id: "primary".into(),
                enabled: false,
                state_dir: legacy.state_dir.clone(),
                enrollment_key_file: None,
                mode: Mode::Direct {},
            }],
            dependency_adapters: vec![],
            client_policies: vec![],
        };
        check
            .validate()
            .map_err(|_| Error::InvalidLegacyConfiguration)?;
        Ok(legacy)
    }
    pub fn candidate(&self, site: &str, expected_server: &str, deployment: &str) -> Configuration {
        Configuration {
            schema_version: 2,
            deployment_id: deployment.into(),
            site: site.into(),
            gateway_image: self.image_ref.clone(),
            exits: vec![Exit {
                id: "primary".into(),
                enabled: true,
                state_dir: self.state_dir.clone(),
                enrollment_key_file: None,
                mode: Mode::Mullvad {
                    profile: self.profile.clone(),
                    expected_server: expected_server.into(),
                },
            }],
            dependency_adapters: vec![],
            client_policies: vec![],
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileObservation {
    pub path: PathBuf,
    pub metadata: Option<Metadata>,
    pub sha256: Option<String>,
    pub reason: Option<Error>,
}
fn observe(path: &Path, kind: Kind, hash: bool) -> FileObservation {
    let mut item = FileObservation {
        path: path.into(),
        metadata: None,
        sha256: None,
        reason: None,
    };
    match storage::metadata(path, kind) {
        Ok(metadata) => {
            item.metadata = Some(metadata);
            if hash {
                match storage::read(path, kind, 16 * 1024 * 1024) {
                    Ok(bytes) => item.sha256 = Some(sha256(&bytes)),
                    Err(e) => item.reason = Some(e),
                }
            }
        }
        Err(e) => item.reason = Some(e),
    }
    item
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseObservation {
    pub directory: FileObservation,
    pub files: Vec<FileObservation>,
}
fn release(path: &Path) -> ReleaseObservation {
    let directory = observe(path, Kind::ReleaseDirectory, false);
    let files = if directory.metadata.is_some() {
        RELEASE_FILES
            .iter()
            .map(|name| observe(&path.join(name), Kind::PublicFile, true))
            .collect()
    } else {
        vec![]
    };
    ReleaseObservation { directory, files }
}
#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    pub legacy: Legacy,
    pub profile_identity: FileObservation,
    pub state_identity: FileObservation,
    pub compose_release: ReleaseObservation,
    pub releases: Vec<ReleaseObservation>,
    pub release_inventory_reason: Option<Error>,
    pub unit_files: Vec<FileObservation>,
    pub declared_hook_files: Vec<FileObservation>,
    pub collector_declared_files: BTreeMap<String, PathBuf>,
    pub collector_reason: Option<Error>,
    pub unit_manager: &'static str,
    pub containers: Vec<Container>,
    pub container_inventory_reason: Option<Error>,
    pub container_ownership: &'static str,
    pub node_identity: &'static str,
    pub hostname_dependencies: &'static str,
    pub legacy_health_snapshot: &'static str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Collector {
    suggestions_compose: PathBuf,
}
fn collect_files() -> (BTreeMap<String, PathBuf>, Option<Error>) {
    let result = storage::read(
        Path::new("/etc/vprouter/collector-services.json"),
        Kind::SecretFile,
        64 * 1024,
    )
    .and_then(|bytes| {
        serde_json::from_slice::<Collector>(&bytes).map_err(|_| Error::InvalidLegacyConfiguration)
    })
    .and_then(|c| {
        if safe_path(&c.suggestions_compose) {
            Ok(c)
        } else {
            Err(Error::UnsafePath)
        }
    });
    match result {
        Ok(c) => (
            BTreeMap::from([("suggestions_compose".into(), c.suggestions_compose)]),
            None,
        ),
        Err(e) => (BTreeMap::new(), Some(e)),
    }
}
pub async fn inspect(legacy: Legacy) -> Inspection {
    let mut releases = vec![release(Path::new("/opt/vprouter/current"))];
    let releases_path = Path::new("/opt/vprouter/releases");
    let (dirs, release_inventory_reason) = directory_inventory(releases_path);
    releases.extend(dirs.iter().map(|p| release(p)));
    let unit_files = vec![
        observe(
            Path::new("/etc/systemd/system/vprouter@.service"),
            Kind::PublicFile,
            true,
        ),
        observe(
            &PathBuf::from("/etc/systemd/system").join(format!("vprouter@{}.service", legacy.name)),
            Kind::PublicFile,
            true,
        ),
        observe(Path::new("/etc/sv/vprouter/run"), Kind::PublicFile, true),
    ];
    let mut declared_hook_files = vec![
        observe(
            &PathBuf::from("/etc/systemd/system").join(format!(
                "vprouter@{}.service.d/collector-services.conf",
                legacy.name
            )),
            Kind::PublicFile,
            true,
        ),
        observe(
            &legacy.compose_dir.join("host/collector_services.py"),
            Kind::PublicFile,
            true,
        ),
        observe(
            &legacy.compose_dir.join("host/collector-services.conf"),
            Kind::PublicFile,
            true,
        ),
    ];
    for directory in [
        PathBuf::from("/etc/systemd/system/vprouter@.service.d"),
        PathBuf::from("/etc/systemd/system").join(format!("vprouter@{}.service.d", legacy.name)),
    ] {
        let (files, reason) = directory_inventory(&directory);
        if let Some(reason) = reason {
            declared_hook_files.push(FileObservation {
                path: directory,
                metadata: None,
                sha256: None,
                reason: Some(reason),
            });
        }
        declared_hook_files.extend(
            files
                .iter()
                .filter(|p| p.extension().is_some_and(|e| e == "conf"))
                .map(|p| observe(p, Kind::PublicFile, true)),
        );
    }
    declared_hook_files.sort_by(|a, b| a.path.cmp(&b.path));
    declared_hook_files.dedup_by(|a, b| a.path == b.path);
    let (collector_declared_files, collector_reason) = collect_files();
    let client = DockerClient::default();
    let inventory = client.inventory().await;
    let (containers, container_inventory_reason) = match inventory {
        Ok(all) => {
            let primary = all
                .iter()
                .find(|c| c.name.as_deref() == Some(&legacy.name))
                .map(|c| c.id.clone());
            let selected = all
                .into_iter()
                .filter(|c| {
                    c.name.as_deref() == Some(&legacy.name)
                        || c.name.as_deref() == Some(&format!("{}-uplink", legacy.name))
                        || c.network_mode.as_deref().is_some_and(|n| {
                            n == format!("container:{}", legacy.name)
                                || primary
                                    .as_ref()
                                    .is_some_and(|id| n == format!("container:{id}"))
                        })
                })
                .collect();
            (selected, None)
        }
        Err(e) => (vec![], Some(e)),
    };
    let unit_manager = if Path::new("/run/systemd/system").is_dir() {
        "systemd"
    } else if Path::new("/run/runit").is_dir() {
        "runit"
    } else {
        "NOT_TESTED"
    };
    Inspection {
        profile_identity: observe(&legacy.profile, Kind::SecretFile, false),
        state_identity: observe(&legacy.state_dir, Kind::PrivateDirectory, false),
        compose_release: release(&legacy.compose_dir),
        legacy,
        releases,
        release_inventory_reason,
        unit_files,
        declared_hook_files,
        collector_declared_files,
        collector_reason,
        unit_manager,
        containers,
        container_inventory_reason,
        container_ownership: "NOT_TESTED_legacy_names_are_not_ownership_proof",
        node_identity: "NOT_TESTED_no_state_bytes_read",
        hostname_dependencies: "NOT_TESTED_operator_declaration_required",
        legacy_health_snapshot: "NOT_TESTED_not_rust_readiness_evidence",
    }
}
fn directory_inventory(path: &Path) -> (Vec<PathBuf>, Option<Error>) {
    let result = storage::metadata(path, Kind::ReleaseDirectory)
        .and_then(|_| std::fs::read_dir(path).map_err(|_| Error::Unavailable));
    let mut paths = Vec::new();
    let mut reason = None;
    match result {
        Ok(entries) => {
            for (i, entry) in entries.take(129).enumerate() {
                if i == 128 {
                    reason = Some(Error::TooLarge);
                    break;
                }
                match entry {
                    Ok(entry) => match entry
                        .file_name()
                        .to_str()
                        .filter(|s| crate::docker::name(s))
                    {
                        Some(name) => paths.push(path.join(name)),
                        None => reason = Some(Error::UnsafePath),
                    },
                    Err(_) => reason = Some(Error::Unavailable),
                }
            }
        }
        Err(e) => reason = Some(e),
    }
    paths.sort();
    (paths, reason)
}
pub fn load_legacy(path: &Path) -> Result<(Legacy, Vec<u8>)> {
    let bytes = storage::read(path, Kind::SecretFile, 1024 * 1024)?;
    let legacy = Legacy::parse(&bytes)?;
    Ok((legacy, bytes))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub path: PathBuf,
    pub metadata: Option<Metadata>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerIdentity {
    pub container_id: String,
    pub pid: u32,
    pub started_at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Names {
    pub old_hostname: String,
    pub new_hostname: String,
    pub existing_container: String,
    pub proposed_container: String,
    pub existing_service: String,
    pub proposed_service: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRestriction {
    pub expected_server: String,
    pub endpoint: String,
    pub public_configuration_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preconditions {
    pub source_config: FileObservation,
    pub profile: Identity,
    pub profile_restriction: ProfileRestriction,
    pub state: Identity,
    pub primary_container: Option<ContainerIdentity>,
    pub releases: Vec<ReleaseObservation>,
    pub units: Vec<FileObservation>,
    pub hooks: Vec<FileObservation>,
    pub collector_declared_files: BTreeMap<String, PathBuf>,
    pub unit_manager: String,
    pub required_checks: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: String,
    pub requires: Vec<String>,
    pub operation: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanContent {
    pub version: u32,
    pub applicable: bool,
    pub verification_complete: bool,
    pub deployment_id: String,
    pub site: String,
    pub exit_id: String,
    pub names: Names,
    pub candidate: Configuration,
    pub preconditions: Preconditions,
    pub steps: Vec<Step>,
    pub blockers: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub content: PlanContent,
    pub content_sha256: String,
}
impl Plan {
    pub fn fingerprint_is_valid(&self) -> bool {
        serde_json::to_vec(&self.content).is_ok_and(|bytes| sha256(&bytes) == self.content_sha256)
    }
}
pub fn plan(
    source_path: &Path,
    source_bytes: &[u8],
    inspection: &Inspection,
    site: &str,
    server: &str,
    deployment: &str,
) -> Result<Plan> {
    let candidate = inspection.legacy.candidate(site, server, deployment);
    let validated = candidate
        .clone()
        .validate_with(load_profile)
        .map_err(|_| Error::InvalidConfiguration)?;
    let profile = validated.exits()[0]
        .profile()
        .ok_or(Error::InvalidProfile)?;
    build_plan(
        source_path,
        source_bytes,
        inspection,
        candidate,
        validated.exits()[0].hostname().into(),
        restricted_profile(profile)?,
    )
}
fn restricted_profile(profile: &vprouter_core::profile::Profile) -> Result<ProfileRestriction> {
    let public_projection = serde_json::to_vec(&(
        profile.expected_server(),
        profile.endpoint(),
        profile.address(),
        profile.peer_public_key(),
    ))
    .map_err(|_| Error::InvalidProfile)?;
    Ok(ProfileRestriction {
        expected_server: profile.expected_server().into(),
        endpoint: profile.endpoint().to_string(),
        public_configuration_sha256: sha256(&public_projection),
    })
}
fn build_plan(
    source_path: &Path,
    source_bytes: &[u8],
    inspection: &Inspection,
    candidate: Configuration,
    hostname: String,
    profile_restriction: ProfileRestriction,
) -> Result<Plan> {
    let l = &inspection.legacy;
    let mut releases = inspection.releases.clone();
    if !releases
        .iter()
        .any(|release| release.directory.path == inspection.compose_release.directory.path)
    {
        releases.push(inspection.compose_release.clone());
    }
    releases.sort_by(|a, b| a.directory.path.cmp(&b.directory.path));
    let mut source_config = observe(source_path, Kind::SecretFile, false);
    source_config.sha256 = Some(sha256(source_bytes));
    let primary_container = inspection
        .containers
        .iter()
        .find(|c| c.name.as_deref() == Some(&l.name))
        .map(|c| ContainerIdentity {
            container_id: c.id.clone(),
            pid: c.pid,
            started_at: c.started_at.clone(),
        });
    let required_checks: Vec<String> = [
        "unchanged_config_profile_metadata_and_public_binding",
        "unchanged_release_unit_hashes_and_container_pid_start_time",
        "native_guard_and_quarantine_installed_and_verified",
        "all_dependencies_declared_with_reviewed_idempotent_adapters",
        "all_real_clients_covered_by_persistent_fail_closed_guards",
        "exact_node_id_ips_approval_server_observed_without_copying_state",
        "stopped_identity_root_only_durable_backup",
        "compatible_immutable_release_and_state_rollback_verified",
        "hostname_dependencies_declared_and_approved",
    ]
    .map(str::to_owned)
    .to_vec();
    let steps = [
        (
            "preflight",
            "verify_all_unchanged_preconditions_and_lock_ownership",
            vec!["all_required_checks"],
        ),
        (
            "quarantine",
            "install_independent_quarantine_and_verify_client_coverage",
            vec!["preflight"],
        ),
        (
            "drain",
            "drain_and_stop_declared_dependency_adapters",
            vec!["quarantine"],
        ),
        (
            "stop",
            "stop_legacy_guard_and_verify_owned_containers_and_identity_offline",
            vec!["drain"],
        ),
        (
            "backup",
            "create_root_only_durable_stopped_state_and_release_backup",
            vec!["stop"],
        ),
        (
            "activate",
            "activate_real_immutable_release_directory_transactionally",
            vec!["backup"],
        ),
        (
            "restore",
            "reuse_same_state_verify_same_node_ips_approval_and_server_before_rename",
            vec!["activate"],
        ),
        (
            "rename",
            "rename_hostname_only_after_identity_verified_and_dependencies_declared",
            vec!["restore"],
        ),
        (
            "accept",
            "verify_real_client_egress_isolation_faults_and_dependency_health",
            vec!["rename"],
        ),
        (
            "commit",
            "commit_migration_then_resume_dependencies_and_release_quarantine",
            vec!["accept"],
        ),
        (
            "rollback_on_failure",
            "quarantine_first_restore_compatible_release_and_state_or_remain_offline",
            vec!["any_failure"],
        ),
    ]
    .into_iter()
    .map(|(id, operation, requires)| Step {
        id: id.into(),
        operation: operation.into(),
        requires: requires.into_iter().map(str::to_owned).collect(),
    })
    .collect();
    let mut blockers: Vec<String> = [
        "apply_runtime_unimplemented",
        "guard_runtime_unimplemented",
        "active_kernel_feature_probes_not_tested",
        "node_identity_not_tested",
        "adapters_missing_or_unreviewed",
        "client_coverage_not_tested",
        "hostname_dependencies_undeclared",
        "rollback_compatibility_not_tested",
        "migration_interruptions_not_tested",
        "native_release_checksums_and_provenance_unavailable",
        "container_and_namespace_ownership_unverified",
    ]
    .map(str::to_owned)
    .to_vec();
    if inspection.container_inventory_reason.is_some() || primary_container.is_none() {
        blockers.push("container_identity_unverified".into());
    }
    if inspection.profile_identity.metadata.is_none()
        || inspection.state_identity.metadata.is_none()
    {
        blockers.push("identity_metadata_unverified".into());
    }
    if source_config.metadata.is_none() {
        blockers.push("source_config_metadata_unverified".into());
    }
    if inspection.release_inventory_reason.is_some()
        || releases.is_empty()
        || releases.iter().any(|r| {
            r.directory.metadata.is_none()
                || r.files.len() != RELEASE_FILES.len()
                || r.files.iter().any(|f| f.sha256.is_none())
        })
    {
        blockers.push("release_inventory_incomplete".into());
    }
    if !inspection.unit_files.iter().any(|f| f.sha256.is_some()) {
        blockers.push("unit_inventory_incomplete".into());
    }
    let service = format!("vprouter@{}.service", l.name);
    let content = PlanContent {
        version: 1,
        applicable: false,
        verification_complete: false,
        deployment_id: candidate.deployment_id.clone(),
        site: candidate.site.clone(),
        exit_id: "primary".into(),
        names: Names {
            old_hostname: l
                .tailscale_hostname
                .clone()
                .unwrap_or_else(|| l.name.clone()),
            new_hostname: hostname,
            existing_container: l.name.clone(),
            proposed_container: l.name.clone(),
            existing_service: service.clone(),
            proposed_service: service,
        },
        candidate,
        preconditions: Preconditions {
            source_config,
            profile: Identity {
                path: l.profile.clone(),
                metadata: inspection.profile_identity.metadata.clone(),
            },
            profile_restriction,
            state: Identity {
                path: l.state_dir.clone(),
                metadata: inspection.state_identity.metadata.clone(),
            },
            primary_container,
            releases,
            units: inspection.unit_files.clone(),
            hooks: inspection.declared_hook_files.clone(),
            collector_declared_files: inspection.collector_declared_files.clone(),
            unit_manager: inspection.unit_manager.into(),
            required_checks,
        },
        steps,
        blockers,
    };
    let bytes = serde_json::to_vec(&content).map_err(|_| Error::InvalidConfiguration)?;
    Ok(Plan {
        content,
        content_sha256: sha256(&bytes),
    })
}
pub fn inspection_json(inspection: Inspection) -> serde_json::Value {
    serde_json::json!({"ok":true,"read_only":true,"activation_ready":false,"inspection":inspection,"capabilities":crate::capabilities(),"acceptance":host::acceptance_manifest()})
}

#[cfg(test)]
mod tests {
    use super::*;
    const LEGACY:&[u8]=br#"{"name":"kept-container","profile":"/private/original.conf","state_dir":"/private/original-state","image_ref":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","compose_dir":"/opt/vprouter/current","tailscale_hostname":"kept-hostname"}"#;
    #[test]
    fn strict_legacy_and_candidate_preserve_paths_and_identity() {
        let l = Legacy::parse(LEGACY).unwrap();
        let candidate = l.candidate("debdev", "de-fra-wg-404", "deployment");
        assert_eq!(candidate.exits[0].state_dir, l.state_dir);
        assert_eq!(candidate.gateway_image, l.image_ref);
        assert!(
            matches!(&candidate.exits[0].mode,Mode::Mullvad{profile,..} if *profile==l.profile)
        );
        for extra in [",\"SECRET\":\"BAD_SECRET\"", ",\"tailscale_hostname\":42"] {
            let mut bytes = LEGACY[..LEGACY.len() - 1].to_vec();
            bytes.extend_from_slice(extra.as_bytes());
            bytes.push(b'}');
            assert!(Legacy::parse(&bytes).is_err());
        }
        assert_eq!(
            Legacy::parse(br#"{"schema_version":2}"#).unwrap_err(),
            Error::AlreadyV2
        );
    }
    #[test]
    fn deterministic_fingerprint_no_secret_file_hash_and_strict_plan() {
        let l = Legacy::parse(LEGACY).unwrap();
        let inspection = Inspection {
            profile_identity: observe(Path::new("/missing/profile"), Kind::SecretFile, false),
            state_identity: observe(Path::new("/missing/state"), Kind::PrivateDirectory, false),
            compose_release: release(Path::new("/missing/release")),
            legacy: l.clone(),
            releases: vec![],
            release_inventory_reason: Some(Error::Unavailable),
            unit_files: vec![],
            declared_hook_files: vec![],
            collector_declared_files: BTreeMap::new(),
            collector_reason: None,
            unit_manager: "NOT_TESTED",
            containers: vec![],
            container_inventory_reason: Some(Error::DockerUnavailable),
            container_ownership: "NOT_TESTED",
            node_identity: "NOT_TESTED",
            hostname_dependencies: "NOT_TESTED",
            legacy_health_snapshot: "NOT_TESTED",
        };
        let make = || {
            build_plan(
                Path::new("/missing/legacy"),
                LEGACY,
                &inspection,
                l.candidate("debdev", "de-fra-wg-404", "deployment"),
                "mullvad-debdev-exit-de-fra-wg-404".into(),
                ProfileRestriction {
                    expected_server: "de-fra-wg-404".into(),
                    endpoint: "185.1.2.3:51820".into(),
                    public_configuration_sha256: sha256(b"PUBLIC_FIELDS_ONLY"),
                },
            )
            .unwrap()
        };
        let a = make();
        let b = make();
        assert_eq!(a.content_sha256, b.content_sha256);
        assert!(a.fingerprint_is_valid());
        assert!(!a.content.applicable);
        assert_eq!(a.content.names.old_hostname, "kept-hostname");
        assert_eq!(
            a.content.names.existing_container,
            a.content.names.proposed_container
        );
        let text = serde_json::to_string(&a).unwrap();
        assert!(!text.contains("PrivateKey"));
        assert!(!text.contains("BAD_SECRET"));
        assert!(!text.contains("opaque_secret"));
        let mut value = serde_json::to_value(&a).unwrap();
        value["unexpected"] = true.into();
        assert!(serde_json::from_value::<Plan>(value).is_err());
        let mut changed = a;
        changed.content.site = "changed".into();
        assert!(!changed.fingerprint_is_valid());
    }
    #[test]
    fn profile_fingerprint_depends_only_on_public_fields() {
        let synthetic = include_str!("../../../examples/v2/profiles/profile-1.wg.example");
        let first =
            vprouter_core::profile::Profile::parse(synthetic.as_bytes(), "de-fra-wg-404", None)
                .unwrap();
        let original = synthetic
            .lines()
            .find(|line| line.starts_with("PrivateKey"))
            .unwrap();
        let changed = synthetic.replace(
            original,
            "PrivateKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        );
        let second =
            vprouter_core::profile::Profile::parse(changed.as_bytes(), "de-fra-wg-404", None)
                .unwrap();
        let a = restricted_profile(&first).unwrap();
        let b = restricted_profile(&second).unwrap();
        assert_eq!(a.public_configuration_sha256, b.public_configuration_sha256);
        let output = serde_json::to_string(&a).unwrap();
        assert!(!output.contains("PrivateKey"));
        assert!(!output.contains("AgICAg"));
        assert!(!output.contains(&sha256(synthetic.as_bytes())));
    }
}
