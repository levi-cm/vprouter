#![forbid(unsafe_code)]
use super::{
    Error, Result,
    spec::{LaunchSpec, StagingEvidence, WORKER},
};
use vprouter_linux::docker::{LaunchContainer, LaunchDaemon, LaunchImage};

/// Produced only by an exact native daemon-profile match. No caller boolean or
/// arbitrary security-option string can assert an accepted inherited profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DaemonSecurity {
    BuiltinSeccomp,
    AppArmorBuiltinSeccomp,
}
impl DaemonSecurity {
    pub(super) fn bind_container(self, c: &LaunchContainer) -> Result<()> {
        configuration(
            match self {
                Self::BuiltinSeccomp => c.app_armor_profile.is_empty(),
                Self::AppArmorBuiltinSeccomp => c.app_armor_profile == "docker-default",
            },
            "daemon_container_apparmor",
        )
    }
}
pub(super) fn daemon(d: &LaunchDaemon) -> Result<DaemonSecurity> {
    if d.cgroup_driver != "systemd" || d.cgroup_version != "2" || d.os_type != "linux" {
        return Err(Error::UnsupportedPlatform);
    }
    // Exact unordered sets: both builtin seccomp and cgroupns are mandatory.
    // Unknown/missing/duplicate markers and custom/unconfined seccomp fail closed.
    let matches = |expected: &[&str]| {
        d.security_options.len() == expected.len()
            && expected.iter().all(|s| {
                d.security_options
                    .iter()
                    .filter(|option| *option == s)
                    .count()
                    == 1
            })
    };
    if matches(&["name=seccomp,profile=builtin", "name=cgroupns"]) {
        Ok(DaemonSecurity::BuiltinSeccomp)
    } else if matches(&[
        "name=apparmor",
        "name=seccomp,profile=builtin",
        "name=cgroupns",
    ]) {
        Ok(DaemonSecurity::AppArmorBuiltinSeccomp)
    } else {
        Err(Error::UnsupportedConfiguration)
    }
}
pub(super) fn image(spec: &LaunchSpec, stage: &StagingEvidence, i: &LaunchImage) -> Result<()> {
    // Only the ignored exact-hash test payload can construct this private
    // staging kind. It binds a root-approved locally built immutable image ID;
    // no production parser accepts it and no upstream RepoDigest is invented.
    #[cfg(test)]
    if stage.artifact_kind == "actual_gateway_lab_v1" {
        if i.id != stage.content_id
            || i.os != stage.os
            || i.architecture != stage.architecture
            || spec.image_ref != format!("vprouter-v2-lab@{}", stage.content_id)
        {
            return Err(Error::ImageMismatch);
        }
        return Ok(());
    }
    if i.id != stage.content_id
        || i.os != stage.os
        || i.architecture != stage.architecture
        || i.repo_digests
            .iter()
            .filter(|s| *s == &spec.image_ref)
            .count()
            != 1
        || i.repo_digests.len() > 32
    {
        return Err(Error::ImageMismatch);
    }
    Ok(())
}
fn configuration(accepted: bool, reason: &'static str) -> Result<()> {
    if !accepted {
        #[cfg(test)]
        eprintln!("LAB_CONFIG_REASON {reason}");
        #[cfg(not(test))]
        let _ = reason;
        return Err(Error::UnsupportedConfiguration);
    }
    Ok(())
}
fn empty<T>(v: &Option<Vec<T>>) -> bool {
    v.as_ref().is_none_or(Vec::is_empty)
}
fn paths(v: &Option<Vec<String>>, expected: &[&str]) -> bool {
    v.as_ref().is_some_and(|p| {
        p.len() == expected.len()
            && expected
                .iter()
                .all(|s| p.iter().filter(|v| *v == s).count() == 1)
    })
}
pub(super) fn container(
    s: &LaunchSpec,
    stage: &StagingEvidence,
    c: &LaunchContainer,
) -> Result<()> {
    if c.id != s.container_id
        || c.image != stage.content_id
        || c.config.labels.get("io.vprouter.deployment") != Some(&s.allocation.deployment_id)
        || c.config.labels.get("io.vprouter.role").map(String::as_str) != Some("gateway")
        || !c.state.running
        || c.state.paused
        || c.state.restarting
        || c.state.dead
        || c.state.pid <= 1
        || c.state.pid > i32::MAX as u32
        || c.state.started_at != s.started_at
    {
        return Err(Error::ContainerMismatch);
    }
    let h = &c.host_config;
    #[cfg(test)]
    let exact_tun = stage.artifact_kind == "actual_gateway_lab_v1"
        && h.devices
            == vec![
                serde_json::json!({"PathOnHost":"/dev/net/tun","PathInContainer":"/dev/net/tun","CgroupPermissions":"rwm"}),
            ];
    #[cfg(not(test))]
    let exact_tun = false;
    for (key, value) in &h.additional {
        use serde_json::json;
        let accepted = match key.as_str() {
            "LogConfig" => value == &json!({"Type":"json-file","Config":{}}),
            "RestartPolicy" => value == &json!({"Name":"no","MaximumRetryCount":0}),
            "ConsoleSize" => value == &json!([0, 0]),
            "ShmSize" => value == &json!(67108864),
            "PortBindings" => value.is_null() || value == &json!({}),
            "AutoRemove" | "PublishAllPorts" => value == &json!(false),
            "ContainerIDFile" | "VolumeDriver" | "Isolation" | "CpusetCpus" | "CpusetMems"
            | "Cgroup" => value == &json!(""),
            "Dns"
            | "DnsOptions"
            | "DnsSearch"
            | "ExtraHosts"
            | "Links"
            | "Ulimits"
            | "BlkioWeightDevice"
            | "BlkioDeviceReadBps"
            | "BlkioDeviceWriteBps"
            | "BlkioDeviceReadIOps"
            | "BlkioDeviceWriteIOps"
            | "LxcConf" => value.is_null() || value == &json!([]),
            "StorageOpt" | "Annotations" => value.is_null() || value == &json!({}),
            "OomKillDisable" => value.is_null() || value == &json!(false),
            "MemorySwappiness" | "PidsLimit" => value.is_null(),
            "CpuShares" | "Memory" | "NanoCpus" | "BlkioWeight" | "CpuPeriod" | "CpuQuota"
            | "CpuRealtimePeriod" | "CpuRealtimeRuntime" | "MemoryReservation" | "MemorySwap"
            | "CpuCount" | "CpuPercent" | "IOMaximumIOps" | "IOMaximumBandwidth"
            | "OomScoreAdj" | "KernelMemory" | "KernelMemoryTCP" => value == &json!(0),
            _ => false,
        };
        configuration(
            accepted,
            match key.as_str() {
                "LogConfig" => "log_configuration",
                "RestartPolicy" => "restart_policy",
                "ConsoleSize" => "console_size",
                "ShmSize" => "shared_memory_size",
                "PortBindings" => "port_bindings",
                _ => "additional_host_configuration",
            },
        )?;
    }

    for (reason, accepted) in [
        ("network_mode", h.network_mode == "none"),
        ("privileged", !h.privileged),
        ("root_writable", h.readonly_rootfs),
        ("pid_mode", h.pid_mode.is_empty()),
        ("userns_mode", h.userns_mode.is_empty()),
        ("cgroupns_mode", h.cgroupns_mode == "private"),
        ("ipc_mode", h.ipc_mode == "private"),
        ("uts_mode", h.uts_mode.is_empty()),
        ("cap_add", empty(&h.cap_add)),
        ("cap_drop", paths(&h.cap_drop, &["ALL"])),
        (
            "security_opt",
            paths(&h.security_opt, &["no-new-privileges"]),
        ),
        ("extra_mounts", empty(&h.mounts)),
        (
            "devices",
            if exact_tun {
                true
            } else {
                h.devices.is_empty()
            },
        ),
        ("device_requests", empty(&h.device_requests)),
        ("device_cgroup_rules", empty(&h.device_cgroup_rules)),
        ("volumes_from", empty(&h.volumes_from)),
        ("tmpfs", h.tmpfs.as_ref().is_none_or(|v| v.is_empty())),
        ("sysctls", h.sysctls.as_ref().is_none_or(|v| v.is_empty())),
        ("group_add", empty(&h.group_add)),
        ("cgroup_parent", h.cgroup_parent.is_empty()),
        ("runtime", h.runtime == "runc"),
        ("init", h.init != Some(true)),
        (
            "apparmor_profile",
            matches!(c.app_armor_profile.as_str(), "" | "docker-default"),
        ),
        ("process_label", c.process_label.is_empty()),
        ("mount_label", c.mount_label.is_empty()),
        ("user", matches!(c.config.user.as_str(), "" | "0" | "0:0")),
        (
            "volumes",
            c.config.volumes.as_ref().is_none_or(|v| v.is_empty()),
        ),
    ] {
        configuration(accepted, reason)?;
    }
    // Two exact reviewed profiles only: Docker26's 11 entries and the same
    // list plus /proc/interrupts. No arbitrary subset/superset is accepted.
    let docker26 = [
        "/proc/asound",
        "/proc/acpi",
        "/proc/kcore",
        "/proc/keys",
        "/proc/latency_stats",
        "/proc/timer_list",
        "/proc/timer_stats",
        "/proc/sched_debug",
        "/proc/scsi",
        "/sys/firmware",
        "/sys/devices/virtual/powercap",
    ];
    let mut with_interrupts = docker26.to_vec();
    with_interrupts.push("/proc/interrupts");
    configuration(
        paths(&h.masked_paths, &docker26) || paths(&h.masked_paths, &with_interrupts),
        "masked_paths",
    )?;
    configuration(
        paths(
            &h.readonly_paths,
            &[
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger",
            ],
        ),
        "readonly_paths",
    )?;
    // Production image must contain its worker. Only the compiled test harness
    // can create synthetic staging evidence and permit this one exact RO bind.
    if stage.artifact_kind == "synthetic_static_probe_v1" {
        let expected = format!(
            "{}:{WORKER}:ro",
            stage.artifact_path.to_str().ok_or(Error::UnsafeInput)?
        );
        if c.mounts.len() != 1 || h.binds.as_ref() != Some(&vec![expected]) {
            configuration(false, "bind_list")?;
        }
        let m = &c.mounts[0];
        if m.kind != "bind"
            || m.source != stage.artifact_path.to_str().ok_or(Error::UnsafeInput)?
            || m.destination != WORKER
            || m.writable
            || m.propagation != "rprivate"
        {
            configuration(false, "bind_projection")?;
        }
    } else if !c.mounts.is_empty() || !empty(&h.binds) {
        return Err(Error::UnsupportedConfiguration);
    }
    Ok(())
}
