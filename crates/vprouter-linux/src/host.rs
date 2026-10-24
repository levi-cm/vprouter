use crate::{
    Error,
    docker::DockerClient,
    storage::{self, Kind},
};
use serde::Serialize;
use std::{fs::File, io::Read, path::Path};
use vprouter_core::config::{Mode, ValidatedConfiguration};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckState {
    Pass,
    Fail,
    NotTested,
}
#[derive(Clone, Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub state: CheckState,
    pub reason: Option<Error>,
}
#[derive(Serialize)]
pub struct Preflight {
    pub schema_valid: bool,
    /// Includes required feature usability; unknowns prevent support confirmation.
    pub host_supported: bool,
    pub activation_ready: bool,
    pub checks: Vec<Check>,
}
impl Check {
    pub fn tested(id: &'static str, ok: bool, reason: Error) -> Self {
        Self {
            id,
            state: if ok {
                CheckState::Pass
            } else {
                CheckState::Fail
            },
            reason: (!ok).then_some(reason),
        }
    }
    pub fn unknown(id: &'static str) -> Self {
        Self {
            id,
            state: CheckState::NotTested,
            reason: None,
        }
    }
}
fn small_read(path: &str) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(65537)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= 65536).then_some(())?;
    String::from_utf8(bytes).ok()
}
fn os_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut matches = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| *k == key);
    let (_, value) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(value.trim_matches('"'))
}
pub(crate) fn platform_checks(
    kernel: &str,
    arch: &str,
    os: &str,
    manager: &str,
    observed_host_glibc: Option<bool>,
) -> Vec<Check> {
    let mut parts = kernel.trim().split('.');
    let version = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .zip(parts.next().and_then(|s| s.parse::<u32>().ok()));
    let platform = match os_value(os, "ID") {
        Some("debian") => os_value(os, "VERSION_ID") == Some("13") && manager == "systemd",
        Some("arch" | "cachyos") => manager == "systemd",
        Some("void") => manager == "runit",
        _ => false,
    };
    let mut checks = vec![
        Check::tested(
            "linux_6_1",
            version.is_some_and(|v| v >= (6, 1)),
            Error::InvalidPlatform,
        ),
        Check::tested(
            "architecture",
            matches!(arch, "x86_64" | "aarch64"),
            Error::InvalidPlatform,
        ),
        Check::tested("distribution_and_manager", platform, Error::InvalidPlatform),
    ];
    if os_value(os, "ID") == Some("void") {
        checks.push(match observed_host_glibc {
            Some(glibc) => Check::tested("void_host_glibc", glibc, Error::InvalidPlatform),
            None => Check::unknown("void_host_glibc"),
        });
    }
    checks
}
pub async fn preflight(cfg: &ValidatedConfiguration) -> Preflight {
    let kernel = small_read("/proc/sys/kernel/osrelease").unwrap_or_default();
    let os = small_read("/etc/os-release").unwrap_or_default();
    let manager = small_read("/proc/1/comm").unwrap_or_default();
    let mut checks = platform_checks(
        &kernel,
        std::env::consts::ARCH,
        &os,
        manager.trim(),
        // The binary's target libc is not evidence of the host's libc. No
        // reliable native host-libc probe is implemented here; Void remains
        // explicitly unverified, including when this binary is statically linked.
        None,
    );
    let cgroup2 = File::open("/sys/fs/cgroup")
        .ok()
        .and_then(|fd| rustix::fs::fstatfs(fd).ok())
        .is_some_and(|st| st.f_type == 0x63677270);
    checks.push(Check::tested("cgroup_v2", cgroup2, Error::InvalidPlatform));
    checks.push(Check::tested(
        "tun_character_device",
        storage::metadata(Path::new("/dev/net/tun"), Kind::TunDevice).is_ok(),
        Error::UnsafePath,
    ));
    let docker = DockerClient::default();
    let socket = storage::metadata(docker.socket_path(), Kind::DockerSocket);
    checks.push(Check::tested(
        "docker_socket_root_ownership",
        socket.is_ok(),
        Error::UnsafePath,
    ));
    if socket.is_ok() {
        let version = docker.version().await;
        checks.push(Check::tested(
            "docker_engine_26_api_1_45",
            version.is_ok(),
            version.err().unwrap_or(Error::DockerIncompatible),
        ));
    } else {
        checks.push(Check::unknown("docker_engine_26_api_1_45"));
    }
    checks.push(Check::tested(
        "release_real_root_owned",
        storage::metadata(Path::new("/opt/vprouter/current"), Kind::ReleaseDirectory).is_ok(),
        Error::UnsafePath,
    ));
    for exit in cfg.exits() {
        checks.push(Check::tested(
            "exit_private_state",
            storage::metadata(&exit.exit().state_dir, Kind::PrivateDirectory).is_ok(),
            Error::UnsafePath,
        ));
        if let Some(path) = &exit.exit().enrollment_key_file {
            checks.push(Check::tested(
                "enrollment_key_metadata",
                storage::metadata(path, Kind::SecretFile).is_ok(),
                Error::UnsafePath,
            ));
        }
        if let Mode::Mullvad { profile, .. } = &exit.exit().mode {
            checks.push(Check::tested(
                "profile_key_metadata",
                storage::metadata(profile, Kind::SecretFile).is_ok(),
                Error::UnsafePath,
            ));
        }
    }
    // Module existence or even loading does not prove namespace-local usability.
    checks.push(Check::unknown("nftables_active_usability"));
    checks.push(Check::unknown("wireguard_active_usability"));
    checks.push(Check::unknown("guard_liveness_and_owned_resources"));
    let host_supported = checks.iter().all(|c| c.state == CheckState::Pass);
    Preflight {
        schema_valid: true,
        host_supported,
        activation_ready: false,
        checks,
    }
}
pub fn acceptance_manifest() -> serde_json::Value {
    serde_json::json!({"state":"NOT_RUN", "required":[
        "single_mullvad_real_client_ipv4_dns_ipv6_tcp_udp", "five_mullvad_real_clients", "direct_real_client", "five_plus_direct_isolation",
        "fault_matrix_and_positive_capture_controls", "reboot_with_boot_capture", "24h_mixed_soak", "performance_baseline_comparison",
        "second_existing_host", "unsafe_launcher_independent_review", "x86_64_and_aarch64_artifacts_sbom_provenance", "migration_interruption_and_rollback_compatibility"
    ]})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_supported_platforms_and_unknowns_fail_closed() {
        for (os, manager, glibc) in [
            ("ID=debian\nVERSION_ID=13", "systemd", true),
            ("ID=arch", "systemd", true),
            ("ID=cachyos", "systemd", true),
            ("ID=void", "runit", true),
        ] {
            assert!(
                platform_checks("6.1.0", "aarch64", os, manager, Some(glibc))
                    .iter()
                    .all(|c| c.state == CheckState::Pass)
            );
        }
        for (kernel, arch, os, manager, glibc) in [
            ("6.0.99", "x86_64", "ID=arch", "systemd", true),
            ("bad SECRET", "x86_64", "ID=arch", "systemd", true),
            ("6.1.0", "riscv64", "ID=arch", "systemd", true),
            (
                "6.1.0",
                "x86_64",
                "ID=debian\nVERSION_ID=12",
                "systemd",
                true,
            ),
            ("6.1.0", "x86_64", "ID=void", "runit", false),
            ("6.1.0", "x86_64", "ID=arch", "runit", true),
            ("6.1.0", "x86_64", "ID=arch\nID=arch", "systemd", true),
        ] {
            let checks = platform_checks(kernel, arch, os, manager, Some(glibc));
            assert!(checks.iter().any(|c| c.state == CheckState::Fail));
            assert!(!serde_json::to_string(&checks).unwrap().contains("SECRET"));
        }
    }
    #[test]
    fn void_host_libc_is_unknown_without_observation_regardless_of_build_target() {
        // Binary target labels deliberately never enter platform_checks: neither
        // static artifact establishes what libc is installed on its host.
        for binary_target in [
            "x86_64-unknown-linux-gnu-static",
            "x86_64-unknown-linux-musl",
        ] {
            for (observed_host_glibc, expected) in [
                (Some(true), CheckState::Pass),
                (Some(false), CheckState::Fail),
                (None, CheckState::NotTested),
            ] {
                let checks =
                    platform_checks("6.1.0", "x86_64", "ID=void", "runit", observed_host_glibc);
                assert_eq!(
                    checks
                        .iter()
                        .find(|check| check.id == "distribution_and_manager")
                        .unwrap()
                        .state,
                    CheckState::Pass,
                    "{binary_target}"
                );
                assert_eq!(
                    checks
                        .iter()
                        .find(|check| check.id == "void_host_glibc")
                        .unwrap()
                        .state,
                    expected,
                    "{binary_target}"
                );
                assert_eq!(
                    checks.iter().all(|check| check.state == CheckState::Pass),
                    observed_host_glibc == Some(true),
                    "{binary_target}"
                );
            }
        }
    }
}
