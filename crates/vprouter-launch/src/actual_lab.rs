#![forbid(unsafe_code)]
//! Ignored, identity-free actual-program oracle. Root alone executes this fixed
//! payload. Every failed attempt retains ownership records and quarantine.
use super::{
    Admission, Error, Result, kernel, lab,
    programs::{ReviewedBundle, Role},
    transport::GuardTransport,
};
use serde::Deserialize;
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const ROOT: &str = "/var/lib/vprouter-v2-lab";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    schema: u32,
    image_id: String,
    program_manifest_sha256: String,
}
pub(super) fn image() -> Result<String> {
    let bytes = vprouter_linux::storage::read(
        &PathBuf::from(format!("{ROOT}/task8b2-image")),
        vprouter_linux::storage::Kind::SecretFile,
        4096,
    )
    .map_err(|_| Error::LabRequired)?;
    let image: Image = serde_json::from_slice(&bytes).map_err(|_| Error::LabRequired)?;
    if image.schema != 1
        || !image
            .image_id
            .strip_prefix("sha256:")
            .is_some_and(super::spec::digest)
        || image.program_manifest_sha256 != ReviewedBundle::current()?.digest()
    {
        return Err(Error::LabRequired);
    }
    Ok(image.image_id)
}
fn group(a: &Admission) -> String {
    format!(
        "/sys/fs/cgroup/system.slice/docker-{}.scope/{}",
        a.spec.container_id,
        vprouter_netfilter::SocketProducer::group_name(&a.spec.allocation, &a.spec.exit)
    )
}
fn pids(a: &Admission) -> Result<Vec<u32>> {
    fs::read_to_string(format!("{}/cgroup.procs", group(a)))
        .map_err(|_| Error::CgroupMismatch)?
        .lines()
        .map(|s| s.parse().map_err(|_| Error::CgroupMismatch))
        .collect()
}
fn identify(a: &Admission, bundle: &ReviewedBundle, role: Role) -> Result<u32> {
    let mut found = Vec::new();
    for pid in pids(a)? {
        if let Ok(fd) = fs::File::open(format!("/proc/{pid}/exe"))
            && bundle.verify(fd, role).is_ok()
        {
            found.push(pid);
        }
    }
    if found.len() != 1 {
        return Err(Error::ExecutableMismatch);
    }
    Ok(found[0])
}
fn field<'a>(status: &'a str, key: &str) -> Result<&'a str> {
    status
        .lines()
        .find_map(|s| s.strip_prefix(key))
        .map(str::trim)
        .ok_or(Error::CapabilityPolicy)
}
fn inspect(a: &Admission, pid: u32, daemon: bool, dir: &Path) -> Result<()> {
    let status =
        fs::read_to_string(format!("/proc/{pid}/status")).map_err(|_| Error::ProcessUnavailable)?;
    for key in ["Uid:", "Gid:"] {
        if field(&status, key)?.split_whitespace().collect::<Vec<_>>() != ["65534"; 4] {
            return Err(Error::CapabilityPolicy);
        }
    }
    if !field(&status, "Groups:")?.is_empty()
        || field(&status, "NoNewPrivs:")? != "1"
        || field(&status, "Seccomp:")? != "2"
    {
        return Err(Error::CapabilityPolicy);
    }
    let expected = if daemon { 1 << 12 } else { 0 };
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        if u64::from_str_radix(field(&status, key)?, 16).ok() != Some(expected) {
            return Err(Error::CapabilityPolicy);
        }
    }
    if fs::read_to_string(format!("/proc/{pid}/attr/current"))
        .map_err(|_| Error::ConfinementPolicy)?
        .trim()
        != "docker-default (enforce)"
    {
        return Err(Error::ConfinementPolicy);
    }
    let expected_state =
        fs::metadata(
            a.spec
                .exit
                .state_dir
                .join(if daemon { "daemon" } else { "worker" }),
        )
        .map_err(|_| Error::MountIsolation)?;
    let state =
        fs::metadata(format!("/proc/{pid}/root/state")).map_err(|_| Error::MountIsolation)?;
    if (expected_state.dev(), expected_state.ino()) != (state.dev(), state.ino()) {
        return Err(Error::MountIsolation);
    }
    if fs::symlink_metadata(format!("/proc/{pid}/root/old")).is_ok()
        || fs::symlink_metadata(format!("/proc/{pid}/root/var/lib")).is_ok()
        || fs::symlink_metadata(format!("/proc/{pid}/root/bin/sh")).is_ok()
        || (!daemon
            && fs::symlink_metadata(format!("/proc/{pid}/root/state/tailscaled.state")).is_ok())
    {
        return Err(Error::MountIsolation);
    }
    let mounts =
        fs::read_to_string(format!("/proc/{pid}/mountinfo")).map_err(|_| Error::MountIsolation)?;
    for path in ["/", "/proc", "/etc/ssl/certs/ca-certificates.crt"] {
        let rows: Vec<_> = mounts
            .lines()
            .filter(|l| l.split_whitespace().nth(4) == Some(path))
            .collect();
        if rows.len() != 1
            || !rows[0]
                .split_whitespace()
                .nth(5)
                .is_some_and(|s| s.split(',').any(|v| v == "ro"))
        {
            return Err(Error::MountIsolation);
        }
    }
    let mut descriptors = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd")).map_err(|_| Error::DescriptorInventory)? {
        if descriptors.len() >= 256 {
            return Err(Error::DescriptorInventory);
        }
        let entry = entry.map_err(|_| Error::DescriptorInventory)?;
        let number: u32 = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
            .ok_or(Error::DescriptorInventory)?;
        let target = fs::read_link(entry.path()).map_err(|_| Error::DescriptorInventory)?;
        let text = target.to_str().ok_or(Error::DescriptorInventory)?;
        let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{number}"))
            .map_err(|_| Error::DescriptorInventory)?;
        let flags = u32::from_str_radix(field(&info, "flags:")?, 8)
            .map_err(|_| Error::DescriptorInventory)?;
        let metadata = fs::metadata(entry.path()).map_err(|_| Error::DescriptorInventory)?;
        descriptors.push(serde_json::json!({
            "number":number,"target":text,"flags":flags,
            "dev":metadata.dev(),"ino":metadata.ino(),"mode":metadata.mode()
        }));
    }
    descriptors.sort_by_key(|value| value["number"].as_u64());
    // Retain a bounded kernel-metadata witness before applying the descriptor
    // grammar. A rejected shape stays rejected and is never learned/adopted.
    lab::write(
        &dir.join(if daemon {
            "daemon-descriptors.json"
        } else {
            "observer-descriptors.json"
        }),
        &serde_json::to_vec(&descriptors).map_err(|_| Error::DescriptorInventory)?,
    )?;
    for descriptor in &descriptors {
        let text = descriptor["target"]
            .as_str()
            .ok_or(Error::DescriptorInventory)?;
        if !(text == "/dev/null"
            || text == "/dev/net/tun"
            || text.starts_with("socket:[")
            || text.starts_with("anon_inode:")
            || text.starts_with("/state/"))
        {
            return Err(Error::DescriptorPolicy);
        }
    }
    let cgroup =
        fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|_| Error::CgroupMismatch)?;
    if cgroup
        != format!(
            "0::/system.slice/docker-{}.scope/{}\n",
            a.spec.container_id,
            vprouter_netfilter::SocketProducer::group_name(&a.spec.allocation, &a.spec.exit)
        )
    {
        return Err(Error::CgroupMismatch);
    }
    let proof = serde_json::json!({"pid":pid,"role":if daemon{"actual_tailscaled"}else{"actual_rust_observer"},"uid":65534,"capabilities":expected,"no_new_privileges":true,"seccomp":2,"apparmor":"docker-default (enforce)","cgroup":cgroup,"nspid":field(&status,"NSpid:")?,"descriptors":descriptors,"private_state":true,"readonly_root_proc_ca":true,"readiness":false});
    lab::write(
        &dir.join(if daemon {
            "daemon-process.json"
        } else {
            "observer-process.json"
        }),
        &serde_json::to_vec(&proof).map_err(|_| Error::InvalidSpec)?,
    )
}
fn wait_exit(child: &mut kernel::Child) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(4);
    loop {
        if child.try_wait_success()? {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub(super) fn run(
    a: &Admission,
    g: &mut GuardTransport<'_>,
    dir: &Path,
    data_name: &str,
) -> Result<()> {
    let bundle = ReviewedBundle::current()?;
    bundle
        .open(a.process.root(), Role::GatewayInit)?
        .revalidate(&bundle)?;
    let parent = format!(
        "/sys/fs/cgroup/system.slice/docker-{}.scope",
        a.spec.container_id
    );
    let controls: Vec<_> = [
        "cgroup.procs",
        "cgroup.subtree_control",
        "cpu.max",
        "memory.max",
    ]
    .into_iter()
    .map(|name| {
        fs::read_to_string(format!("{parent}/{name}"))
            .map(|s| (name, s))
            .map_err(|_| Error::CgroupMismatch)
    })
    .collect::<Result<_>>()?;
    let mut handoff = g.prepare_observation(a, &bundle)?;
    lab::stage("actual_daemon_fixed_program_launch");
    let mut daemon = handoff.launch_daemon(&bundle)?;
    lab::stage("actual_daemon_setup_acknowledged");
    let end = Instant::now() + Duration::from_secs(5);
    let daemon_pid = loop {
        if daemon.try_wait_success()? {
            return Err(Error::ChildFailed);
        }
        if a.spec
            .exit
            .state_dir
            .join("daemon/tailscaled.sock")
            .exists()
            && let Ok(pid) = identify(a, &bundle, Role::Tailscaled)
        {
            break pid;
        }
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    lab::stage("actual_daemon_live_socket_program_identified");
    super::transport_lab::actual_metadata(data_name, dir)?;
    inspect(a, daemon_pid, true, dir)?;
    lab::case("actual_pinned_go_uid_netadmin_only_lsm_seccomp_private_root_state_fds");
    lab::stage("actual_observer_authenticated_launch");
    let mut observer = handoff.launch_observer(&bundle)?;
    let observer_pid = identify(a, &bundle, Role::WorkerObserver)?;
    inspect(a, observer_pid, false, dir)?;
    if handoff.serve_once(&bundle)? != observer_pid {
        return Err(Error::DescriptorPolicy);
    }
    if handoff.serve_once(&bundle).err() != Some(Error::DescriptorPolicy) {
        return Err(Error::DescriptorPolicy);
    }
    wait_exit(&mut observer)?;
    let result = fs::read(a.spec.exit.state_dir.join("worker/observation.json"))
        .map_err(|_| Error::ChildFailed)?;
    let result: serde_json::Value =
        serde_json::from_slice(&result).map_err(|_| Error::ChildFailed)?;
    if result["actual_localapi_unenrolled"] != true || result["readiness"] != false {
        return Err(Error::ChildFailed);
    }
    lab::case(
        "actual_rust_protected_readonly_configuration_authenticated_one_use_peer_metadata_localapi",
    );
    handoff.cleanup()?;
    if daemon.try_wait_success()? {
        return Err(Error::ChildFailed);
    }
    daemon.signal(libc::SIGTERM)?;
    wait_exit(&mut daemon)?;
    drop(daemon);
    drop(observer);
    if !pids(a)?.is_empty() {
        return Err(Error::PlacementFailed);
    }
    for (name, before) in controls {
        if fs::read_to_string(format!("{parent}/{name}")).map_err(|_| Error::CgroupMismatch)?
            != before
        {
            return Err(Error::CgroupMismatch);
        }
    }
    lab::case(
        "actual_go_signal_forwarding_bounded_reaping_empty_group_parent_accounting_unchanged",
    );
    g.audit()?;
    super::transport_lab::actual_packet_controls(
        g,
        dir,
        data_name,
        &a.spec.exit.transport_namespace,
    )?;
    lab::write(&dir.join("result.json"),br#"{"result":"actual_observer_and_go_observation_only","readiness":false,"production_changes":false,"quarantine_retained":true,"approved_identity_accessed":false,"real_client_acceptance":"NOT_RUN"}"#)?;
    Ok(())
}
