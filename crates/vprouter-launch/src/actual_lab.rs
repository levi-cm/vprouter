#![forbid(unsafe_code)]
//! Ignored, identity-free actual-program oracle. Root alone executes this fixed
//! payload. Every failed attempt retains ownership records and quarantine.
use super::{
    Admission, Error, Result, kernel, lab,
    programs::{ReviewedBundle, Role},
    transport::GuardTransport,
};
use serde::{Deserialize, Serialize};
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
fn field<'a>(status: &'a str, key: &str) -> Result<&'a str> {
    status
        .lines()
        .find_map(|s| s.strip_prefix(key))
        .map(str::trim)
        .ok_or(Error::CapabilityPolicy)
}
#[derive(Clone, Serialize)]
struct Descriptor {
    number: u32,
    target: String,
    flags: u32,
    dev: u64,
    ino: u64,
    mode: u32,
    rdev: u64,
}
#[derive(Clone, Copy)]
enum DescriptorAbi {
    Amd64,
    Arm64,
}
impl DescriptorAbi {
    fn current() -> Self {
        if cfg!(target_arch = "aarch64") {
            Self::Arm64
        } else {
            Self::Amd64
        }
    }
    fn largefile(self) -> u32 {
        // Linux UAPI bits, not libc's userspace O_LARGEFILE (which can be0).
        match self {
            Self::Amd64 => 0x8000,
            Self::Arm64 => 0x20000,
        }
    }
    fn null_flags(self, flags: u32) -> bool {
        flags & !self.largefile() == libc::O_RDWR as u32
    }
}
#[test]
fn descriptor_stdio_largefile_bits_are_exact_for_each_linux_abi() {
    for (abi, correct, foreign) in [
        (DescriptorAbi::Amd64, 0x8000, 0x20000),
        (DescriptorAbi::Arm64, 0x20000, 0x8000),
    ] {
        assert!(abi.null_flags(2));
        assert!(abi.null_flags(correct | 2));
        for bad in [
            0,
            1,
            foreign | 2,
            correct | foreign | 2,
            correct | 0x80000 | 2,
            correct | 0x800 | 2,
            correct | 0x400 | 2,
        ] {
            assert!(!abi.null_flags(bad), "flags {bad:x}");
        }
    }
}
fn descriptor_grammar(
    descriptors: &[Descriptor],
    daemon: bool,
    null: (u64, u64, u64),
) -> Result<()> {
    let mut numbers = std::collections::BTreeSet::new();
    let mut stdio = 0;
    let mut pipes = Vec::new();
    for d in descriptors {
        if !numbers.insert(d.number) {
            return Err(Error::DescriptorPolicy);
        }
        if d.number < 3 {
            if (d.dev, d.ino, d.rdev) != null
                || rustix::fs::major(d.rdev) != 1
                || rustix::fs::minor(d.rdev) != 3
                || d.mode & libc::S_IFMT != libc::S_IFCHR
                || !DescriptorAbi::current().null_flags(d.flags)
            {
                return Err(Error::DescriptorStdio);
            }
            stdio += 1;
        } else if d.target.starts_with("pipe:[") {
            pipes.push(d);
        } else if !(d.target == "/dev/net/tun"
            || d.target.starts_with("socket:[")
            || matches!(
                d.target.as_str(),
                "anon_inode:[eventpoll]" | "anon_inode:[eventfd]"
            )
            || d.target.starts_with("/state/"))
        {
            return Err(Error::DescriptorPolicy);
        }
    }
    if stdio != 3 || pipes.len() != if daemon { 2 } else { 0 } {
        return Err(Error::DescriptorPolicy);
    }
    if daemon {
        let a = pipes[0];
        let b = pipes[1];
        if a.dev == 0
            || a.ino == 0
            || (a.dev, a.ino) != (b.dev, b.ino)
            || a.mode != 0o10600
            || b.mode != 0o10600
            || a.rdev != 0
            || b.rdev != 0
            || a.target != format!("pipe:[{}]", a.ino)
            || b.target != a.target
            || !((a.flags == 0x80000 && b.flags == 0x80801)
                || (b.flags == 0x80000 && a.flags == 0x80801))
        {
            return Err(Error::DescriptorPolicy);
        }
    }
    Ok(())
}
#[test]
fn descriptor_metadata_requires_exact_null_and_one_canonical_daemon_fifo_pair() {
    let null = (7, 9, rustix::fs::makedev(1, 3));
    let stdio: Vec<_> = (0..3)
        .map(|number| Descriptor {
            number,
            target: "/null".into(),
            flags: DescriptorAbi::current().largefile() | 2,
            dev: null.0,
            ino: null.1,
            mode: libc::S_IFCHR | 0o666,
            rdev: null.2,
        })
        .collect();
    assert!(descriptor_grammar(&stdio, false, null).is_ok());
    let mut daemon = stdio.clone();
    for (number, flags) in [(9, 0x80000), (10, 0x80801)] {
        daemon.push(Descriptor {
            number,
            target: "pipe:[22]".into(),
            flags,
            dev: 15,
            ino: 22,
            mode: 0o10600,
            rdev: 0,
        });
    }
    assert!(descriptor_grammar(&daemon, true, null).is_ok());
    assert!(descriptor_grammar(&daemon, false, null).is_err());
    assert!(descriptor_grammar(&stdio, true, null).is_err());
    for change in 0..9 {
        let mut bad = daemon.clone();
        match change {
            0 => bad[3].ino += 1,
            1 => bad[3].dev += 1,
            2 => bad[3].flags = 0,
            3 => bad[4].flags &= !0x80000,
            4 => bad[4].flags |= 0x4000,
            5 => bad[3].mode = libc::S_IFREG | 0o600,
            6 => bad[3].target = "pipe:[23]".into(),
            7 => bad[0].rdev = rustix::fs::makedev(1, 5),
            8 => bad.push(Descriptor {
                number: 11,
                ..bad[3].clone()
            }),
            _ => unreachable!(),
        }
        assert!(
            descriptor_grammar(&bad, true, null).is_err(),
            "fault {change}"
        );
    }
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
    let label = fs::read_to_string(format!("/proc/{pid}/attr/current")).map_err(|_| {
        eprintln!("LAB_CONFINEMENT_FAILURE scope=inspected_process_lsm reason=read");
        Error::ConfinementPolicy
    })?;
    if label.trim() != "docker-default (enforce)" {
        let reason = match label.trim() {
            "unconfined" => "unconfined",
            "docker-default (complain)" => "complain",
            "" => "empty",
            _ => "other",
        };
        eprintln!("LAB_CONFINEMENT_FAILURE scope=inspected_process_lsm reason={reason}");
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
        descriptors.push(Descriptor {
            number,
            target: text.to_owned(),
            flags,
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            rdev: metadata.rdev(),
        });
    }
    descriptors.sort_by_key(|value| value.number);
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
    let null =
        fs::metadata(format!("/proc/{pid}/root/dev/null")).map_err(|_| Error::DescriptorStdio)?;
    descriptor_grammar(&descriptors, daemon, (null.dev(), null.ino(), null.rdev()))?;
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
fn container_death(
    a: &Admission,
    g: &mut GuardTransport<'_>,
    bundle: &ReviewedBundle,
    dir: &Path,
    data_name: &str,
) -> Result<()> {
    let dir = dir.join("container-death");
    fs::create_dir(&dir).map_err(|_| Error::LabRequired)?;
    g.lab_resume_bootstrap()?;
    let mut handoff = g.prepare_observation(a, bundle)?;
    let mut daemon = handoff.launch_daemon(bundle)?;
    let pid = handoff.discover_daemon(&daemon)?;
    let mut authority = handoff.pin_daemon(bundle, &daemon, pid)?;
    let mut observer = handoff.launch_observer(bundle, &mut authority)?;
    let mut captured = Vec::new();
    lab::stage("actual_go_and_rust_container_death_before_observe_reply");
    let response = handoff.serve_once_inspected(bundle, &mut authority, |observer_pid| {
        inspect(a, observer_pid, false, &dir)?;
        captured = pids(a)?;
        if captured.len() != 8 {
            return Err(Error::PlacementFailed);
        }
        // Fixed exact-owned fixture operation. No fallback signal occurs before
        // both actual launch trees are independently observed terminal/absent.
        lab::docker(&["kill", &a.spec.container_id])?;
        Ok(())
    });
    if response.is_ok()
        || authority.revalidate(bundle).is_ok()
        || authority.revalidate(bundle).is_ok()
    {
        return Err(Error::PlacementFailed);
    }
    drop(handoff);
    let end = Instant::now() + Duration::from_secs(4);
    loop {
        let daemon_done = daemon.try_wait_terminal()?;
        let observer_done = observer.try_wait_terminal()?;
        if daemon_done
            && observer_done
            && captured.iter().all(|pid| {
                fs::symlink_metadata(format!("/proc/{pid}"))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            })
        {
            break;
        }
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    match fs::read_to_string(format!("{}/cgroup.procs", group(a))) {
        Ok(pids) if pids.trim().is_empty() => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        _ => return Err(Error::CgroupMismatch),
    }
    drop(authority);
    drop(daemon);
    drop(observer);
    if g.audit().is_ok() {
        return Err(Error::PlacementFailed);
    }
    g.lab_offline()?;
    super::transport_lab::actual_metadata(data_name, &dir)?;
    lab::write(&dir.join("result.json"),br#"{"actual_go_and_rust_terminal":true,"fallback_signal_used":false,"all_captured_producer_pids_absent":true,"producer_empty_or_removed":true,"dead_authority_revoked":true,"full_offline_quarantine_verified":true,"resources_retained":true,"readiness":false}"#)?;
    lab::case(
        "actual_go_rust_container_death_natural_reap_revocation_empty_group_retained_offline_quarantine",
    );
    Ok(())
}
pub(super) fn run(
    a: &Admission,
    g: &mut GuardTransport<'_>,
    dir: &Path,
    data_name: &str,
    endpoint: &str,
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
    publisher_component(a, g, endpoint)?;
    let mut handoff = g.prepare_observation(a, &bundle)?;
    lab::stage("actual_daemon_fixed_program_launch");
    let mut daemon = handoff.launch_daemon(&bundle)?;
    lab::stage("actual_daemon_setup_acknowledged");
    let daemon_pid = handoff.discover_daemon(&daemon)?;
    lab::stage("actual_daemon_live_socket_program_identified");
    let mut daemon_authority = handoff.pin_daemon(&bundle, &daemon, daemon_pid)?;
    if daemon_authority.pid() != daemon_pid {
        return Err(Error::PlacementFailed);
    }
    lab::stage("actual_daemon_identity_pinned");
    lab::case("actual_live_daemon_fixed_native_tun_rules_bound_and_revalidated");
    super::transport_lab::actual_metadata(data_name, dir)?;
    handoff.verify_daemon(&bundle, &mut daemon_authority)?;
    inspect(a, daemon_pid, true, dir)?;
    lab::case("actual_pinned_go_uid_netadmin_only_lsm_seccomp_private_root_state_fds");
    lab::stage("actual_observer_authenticated_launch");
    let mut observer = handoff.launch_observer(&bundle, &mut daemon_authority)?;
    handoff.serve_once_inspected(&bundle, &mut daemon_authority, |pid| {
        inspect(a, pid, false, dir)
    })?;
    if handoff.serve_once(&bundle, &mut daemon_authority).err() != Some(Error::DescriptorPolicy) {
        return Err(Error::DescriptorPolicy);
    }
    wait_exit(&mut observer)?;
    lab::case(
        "actual_both_preexec_role_profiles_state_mount_exec_and_syscall_exec_init_proc_denials",
    );
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
    handoff.verify_daemon(&bundle, &mut daemon_authority)?;
    // Real post-pin kernel mutations, after both actual programs ran. Each
    // detected fault permanently revokes the old token and restores full offline
    // policy. Repairing metadata alone must not revive that revoked token.
    for (name, apply, reverse) in [
        (
            "tun_mtu",
            vec!["link", "set", "dev", "tailscale0", "mtu", "1400"],
            vec!["link", "set", "dev", "tailscale0", "mtu", "1280"],
        ),
        (
            "tun_address",
            vec!["address", "add", "100.64.99.9/32", "dev", "tailscale0"],
            vec!["address", "del", "100.64.99.9/32", "dev", "tailscale0"],
        ),
        (
            "route",
            vec![
                "route",
                "add",
                "8.8.8.8/32",
                "dev",
                "tailscale0",
                "table",
                "52",
            ],
            vec![
                "route",
                "del",
                "8.8.8.8/32",
                "dev",
                "tailscale0",
                "table",
                "52",
            ],
        ),
        (
            "rule",
            vec!["rule", "add", "pref", "4900", "lookup", "52"],
            vec!["rule", "del", "pref", "4900", "lookup", "52"],
        ),
    ] {
        let mutate = |args: &[&str]| -> Result<()> {
            let output = std::process::Command::new("/usr/sbin/ip")
                .args(["-n", data_name])
                .args(args)
                .output()
                .map_err(|_| Error::NetworkOperation)?;
            if !output.status.success() {
                return Err(Error::NetworkOperation);
            }
            Ok(())
        };
        mutate(&apply)?;
        if handoff
            .verify_daemon(&bundle, &mut daemon_authority)
            .is_ok()
        {
            return Err(Error::NetworkPolicy);
        }
        // Read-only exact emergency policy check BEFORE repair or any further
        // daemon verification can retry quarantine. Failure is not repaired here.
        handoff.assert_offline()?;
        mutate(&reverse)?;
        if handoff
            .verify_daemon(&bundle, &mut daemon_authority)
            .is_ok()
            || daemon_authority.revalidate(&bundle).is_ok()
        {
            return Err(Error::PlacementFailed);
        }
        // A new pin requires the same live process, exact repaired native shape,
        // and actual retained offline policy. It does not restore Bootstrap.
        daemon_authority = handoff.pin_daemon(&bundle, &daemon, daemon_pid)?;
        handoff.verify_daemon(&bundle, &mut daemon_authority)?;
        lab::case(&format!(
            "actual_post_pin_{name}_drift_revoked_offline_old_authority_stays_revoked_after_repair"
        ));
    }
    handoff.quarantine_daemon(&bundle, &mut daemon_authority)?;
    lab::stage("actual_daemon_pre_termination_full_offline_quarantine");
    handoff.cleanup()?;
    if daemon.try_wait_success()? {
        return Err(Error::ChildFailed);
    }
    daemon.signal(libc::SIGTERM)?;
    wait_exit(&mut daemon)?;
    if daemon_authority.revalidate(&bundle).is_ok() || daemon_authority.revalidate(&bundle).is_ok()
    {
        return Err(Error::PlacementFailed);
    }
    drop(daemon_authority);
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
    g.lab_audit_offline()?;
    lab::case("actual_daemon_dead_revoked_baseline_and_full_offline_quarantine");
    // Test-only packet controls deliberately restore owned Bootstrap after
    // daemon death and exact baseline audit. This does not mint readiness.
    g.lab_resume_bootstrap()?;
    g.audit()?;
    monitor_bridge_component(a, g, &bundle, dir, endpoint)?;
    g.lab_resume_bootstrap()?;
    g.audit()?;
    super::transport_lab::actual_packet_controls(
        g,
        dir,
        data_name,
        &a.spec.exit.transport_namespace,
    )?;
    g.lab_begin_offline()?;
    g.lab_audit_offline()?;
    container_death(a, g, &bundle, dir, data_name)?;
    lab::write(&dir.join("result.json"),br#"{"result":"actual_observer_and_go_observation_only","readiness":false,"production_changes":false,"quarantine_retained":true,"approved_identity_accessed":false,"real_client_acceptance":"NOT_RUN"}"#)?;
    Ok(())
}

/// Fixed publisher confinement + real cache and frozen-child containment oracle.
/// This does not authenticate a worker or supply runtime READY authority.
fn publisher_component(
    a: &Admission,
    g: &mut super::transport::GuardTransport<'_>,
    endpoint: &str,
) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    use vprouter_core::{
        health::{Snapshot, boot_seconds},
        state::HealthMachine,
    };
    let root = std::path::Path::new("/run/vprouter-v2");
    match std::fs::DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            super::owned::directory(root)?;
        }
        Err(_) => return Err(Error::OwnershipMismatch),
    }
    let deployment = root.join(&a.spec.allocation.deployment_id);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&deployment)
        .map_err(|_| Error::OwnershipMismatch)?;
    let directory = deployment.join(&a.spec.exit.exit_id);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|_| Error::OwnershipMismatch)?;
    let boot =
        fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| Error::InvalidSpec)?;
    let cfg = super::transport_lab::health_configuration_at(&a.spec, endpoint)?;
    a.spec
        .allocation
        .matches_configuration(&cfg)
        .map_err(|_| Error::AllocationMismatch)?;
    let binding = vprouter_linux::status::expected_binding(&cfg, 0, a.spec.generation, boot.trim())
        .map_err(|_| Error::InvalidSpec)?;
    lab::write(
        &deployment.join("allocations.json"),
        &serde_json::to_vec(&a.spec.allocation).map_err(|_| Error::InvalidSpec)?,
    )?;
    eprintln!("publisher_component: before_spawn");
    let mut publisher = super::publisher::Publisher::spawn(binding.clone())?;
    eprintln!("publisher_component: after_spawn");
    let pid = publisher.lab_pid();
    let status =
        fs::read_to_string(format!("/proc/{pid}/status")).map_err(|_| Error::ProcessUnavailable)?;
    for (field, expected) in [
        ("Uid:", "0 0 0 0"),
        ("Gid:", "0 0 0 0"),
        ("Groups:", ""),
        ("NoNewPrivs:", "1"),
        ("Seccomp:", "2"),
        ("CapInh:", "0000000000000000"),
        ("CapPrm:", "0000000000000000"),
        ("CapEff:", "0000000000000000"),
        ("CapBnd:", "0000000000000000"),
        ("CapAmb:", "0000000000000000"),
    ] {
        let values: Vec<_> = status
            .lines()
            .filter_map(|l| l.strip_prefix(field))
            .collect();
        if values.len() != 1
            || values[0].split_whitespace().collect::<Vec<_>>()
                != expected.split_whitespace().collect::<Vec<_>>()
        {
            return Err(Error::ConfinementPolicy);
        }
    }
    let childroot = fs::metadata(format!("/proc/{pid}/root")).map_err(|_| Error::MountIsolation)?;
    let cache = fs::metadata(&directory).map_err(|_| Error::MountIsolation)?;
    if (childroot.dev(), childroot.ino()) != (cache.dev(), cache.ino()) {
        return Err(Error::MountIsolation);
    }
    let mut fds = fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|_| Error::DescriptorPolicy)?
        .map(|e| {
            e.map_err(|_| Error::DescriptorPolicy).and_then(|e| {
                e.file_name()
                    .to_string_lossy()
                    .parse::<u32>()
                    .map_err(|_| Error::DescriptorPolicy)
            })
        })
        .collect::<Result<Vec<_>>>()?;
    fds.sort_unstable();
    eprintln!("publisher_component: child_fds={fds:?}");
    if fds != [0, 1, 2, 3, 4] {
        return Err(Error::DescriptorPolicy);
    }
    let machine = HealthMachine::new(
        binding.mode,
        binding.expected_server.as_deref(),
        &binding.node_id,
    )
    .map_err(|_| Error::InvalidSpec)?;
    let snapshot = Snapshot::from_machine(binding.clone(), 1, boot_seconds(), &machine)
        .map_err(|_| Error::InvalidSpec)?;
    eprintln!("publisher_component: before_submit");
    publisher.submit(&snapshot)?;
    eprintln!("publisher_component: submitted");
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        if publisher.poll()? == Some(1) {
            break;
        }
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    eprintln!("publisher_component: acknowledged");
    let bytes = fs::read(directory.join("health.json")).map_err(|_| Error::OwnershipMismatch)?;
    Snapshot::decode(&bytes)
        .map_err(|_| Error::DescriptorPolicy)?
        .validate(&binding, boot_seconds())
        .map_err(|_| Error::DescriptorPolicy)?;
    let rows = vprouter_linux::status::status(&cfg);
    if rows.len() != 1
        || !rows[0].snapshot_valid
        || rows[0].guard_runtime
        || rows[0].activation_ready
        || rows[0].source != "cached"
    {
        return Err(Error::DescriptorPolicy);
    }
    lab::case(
        "fixed_root_caps0_nnp_seccomp_cache_root_ipc_only_publisher_atomic_snapshot_cli_reader",
    );
    publisher.lab_freeze()?;
    let snapshot = Snapshot::from_machine(binding, 2, boot_seconds(), &machine)
        .map_err(|_| Error::InvalidSpec)?;
    publisher.submit(&snapshot)?;
    if publisher.poll()?.is_some() {
        return Err(Error::DescriptorPolicy);
    }
    // The writer is frozen, but the independent host can still enforce Offline.
    g.lab_begin_offline()?;
    g.lab_offline()?;
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        match publisher.poll() {
            Err(Error::Deadline) => break,
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(5)),
            _ => return Err(Error::DescriptorPolicy),
        }
    }
    publisher.stop()?;
    g.lab_resume_bootstrap()?;
    lab::case(
        "frozen_publisher_cannot_block_guard_quarantine_and_publication_expires_bounded_cleanup",
    );
    Ok(())
}

/// Actual fixed monitor -> authenticated guard Session -> separate host writer.
/// Uses only synthetic public binding, never advertises or queries a provider.
fn monitor_bridge_component(
    a: &Admission,
    g: &mut GuardTransport<'_>,
    bundle: &ReviewedBundle,
    dir: &Path,
    endpoint: &str,
) -> Result<()> {
    // Keep this fixed-role witness separate from the previous observer's
    // create_new evidence. Never overwrite an earlier confinement record.
    let monitor_evidence = dir.join("monitor-bridge");
    std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(), 0o700)
        .create(&monitor_evidence)
        .map_err(|_| Error::UnsafeInput)?;
    let cfg = super::transport_lab::health_configuration_at(&a.spec, endpoint)?;
    let boot =
        fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| Error::InvalidSpec)?;
    let binding = vprouter_linux::status::expected_binding(&cfg, 0, a.spec.generation, boot.trim())
        .map_err(|_| Error::InvalidSpec)?;
    let mut publisher = super::publisher::Publisher::spawn(binding.clone())?;
    let mut handoff = g.prepare_monitor(a, bundle, binding.clone())?;
    lab::stage("monitor_bridge_actual_daemon_launch");
    let mut daemon = handoff.launch_daemon(bundle)?;
    let daemon_pid = handoff.discover_daemon(&daemon)?;
    let mut authority = handoff.pin_daemon(bundle, &daemon, daemon_pid)?;
    lab::stage("monitor_bridge_actual_monitor_launch");
    let mut monitor = handoff.launch_monitor(bundle, &mut authority)?;
    let pid = handoff.serve_monitor_initial(bundle, &mut authority, &mut publisher, |pid| {
        inspect(a, pid, false, &monitor_evidence)
    })?;
    if pid == daemon_pid {
        return Err(Error::PlacementFailed);
    }
    wait_exit(&mut monitor)?;
    handoff.assert_offline()?;
    let bytes = fs::read(
        binding
            .host_directory()
            .map_err(|_| Error::InvalidSpec)?
            .join("health.json"),
    )
    .map_err(|_| Error::OwnershipMismatch)?;
    let snapshot =
        vprouter_core::health::Snapshot::decode(&bytes).map_err(|_| Error::DescriptorPolicy)?;
    snapshot
        .validate(&binding, vprouter_core::health::boot_seconds())
        .map_err(|_| Error::DescriptorPolicy)?;
    if snapshot.sequence != 1
        || snapshot.state != vprouter_core::state::HealthState::Starting
        || snapshot.evidence.is_some()
    {
        return Err(Error::DescriptorPolicy);
    }
    let rows = vprouter_linux::status::status(&cfg);
    if rows.len() != 1
        || !rows[0].snapshot_valid
        || rows[0].guard_runtime
        || rows[0].activation_ready
        || rows[0].source != "cached"
    {
        return Err(Error::DescriptorPolicy);
    }
    if handoff
        .serve_monitor_initial(bundle, &mut authority, &mut publisher, |_| Ok(()))
        .err()
        != Some(Error::DescriptorPolicy)
    {
        return Err(Error::DescriptorPolicy);
    }
    handoff.assert_offline()?;
    handoff.cleanup()?;
    daemon.signal(libc::SIGTERM)?;
    wait_exit(&mut daemon)?;
    drop(authority);
    publisher.stop()?;
    g.lab_audit_offline()?;
    lab::case(
        "actual_fixed_monitor_authenticated_lifecycle_starting_host_cache_cli_offline_stop_no_ready",
    );
    Ok(())
}

pub fn inspection_filter_selftest() -> Result<()> {
    kernel::inspection::lab_selftest()
}

/// Fixed current-namespace ROUTE metadata only. No caller target, output path,
/// journal, declaration installation, GENERIC socket or authority constructor.
/// The controller must independently reconcile and author any later declaration.
pub fn host_route_projection() -> Result<String> {
    kernel::secret::seal_parent()?;
    let pid = std::process::id();
    let start = super::process::stat_start(
        &fs::read_to_string("/proc/self/stat").map_err(|_| Error::ProcessUnavailable)?,
        pid,
    )?;
    let requested_at = vprouter_core::health::boot_seconds();
    let deadline = requested_at + 2.;
    // Fixed public codes only; never include a ROUTE message or external text.
    // This is a failed read boundary, not an accepted observation.
    let failure = |stage: &'static str, polls: u32, reason: vprouter_network::Error| {
        eprintln!(
            "LAB_HOST_ROUTE_PROJECTION_FAILURE {}",
            serde_json::json!({
                "schema":1,"creator_pid":pid,"creator_start":start,
                "requested_at":requested_at,"deadline":deadline,
                "stage":stage,"polls":polls,"reason":format!("{reason:?}")
            })
        );
        Error::NetworkOperation
    };
    let mut observer =
        vprouter_network::RouteObserver::open().map_err(|e| failure("open", 0, e))?;
    let registration = super::inventory::Registration::owned(&[observer.descriptor()])?;
    let st = rustix::fs::fstat(observer.descriptor()).map_err(|_| Error::DescriptorInventory)?;
    let mut read = observer
        .start_host_read(deadline)
        .map_err(|e| failure("start_read", 0, e))?;
    let mut polls = 0u32;
    let observation = loop {
        polls = polls.checked_add(1).ok_or(Error::TooLarge)?;
        if let Some(value) = observer
            .poll_host_read(&mut read)
            .map_err(|e| failure("poll_read", polls, e))?
        {
            break value;
        }
        std::thread::yield_now();
    };
    let current =
        rustix::fs::fstat(observer.descriptor()).map_err(|_| Error::DescriptorInventory)?;
    if (current.st_dev, current.st_ino, current.st_mode) != (st.st_dev, st.st_ino, st.st_mode)
        || !registration.contains(observer.descriptor())
        || super::process::stat_start(
            &fs::read_to_string("/proc/self/stat").map_err(|_| Error::ProcessUnavailable)?,
            pid,
        )? != start
        || !vprouter_core::secret_boundary::pristine()
    {
        return Err(Error::OwnershipMismatch);
    }
    let verified_at = vprouter_core::health::boot_seconds();
    if !requested_at.is_finite()
        || !verified_at.is_finite()
        || verified_at < requested_at
        || verified_at >= deadline
    {
        return Err(Error::Deadline);
    }
    serde_json::to_string(&serde_json::json!({
        "schema":1,"creator_pid":pid,"creator_start":start,
        "namespace":observer.namespace_identity(),"route_socket":{"dev":st.st_dev,"ino":st.st_ino},
        "requested_at":requested_at,"deadline":deadline,"verified_at":verified_at,
        "polls":polls,"projection":observation,"read_only":true,
        "declaration_authority":false,"host_change_authority":false
    }))
    .map_err(|_| Error::InvalidSpec)
}

/// Actual reduced-guard positive. The fixed LocalAPI socket supplies a PID hint;
/// every authority still comes from fresh owner-native role/ancestry inspection.
pub(super) fn owner_inspection_component(
    a: &Admission,
    g: &mut GuardTransport<'_>,
    bundle: &ReviewedBundle,
) -> Result<super::inspection::Token> {
    super::process::guard_preflight()?;
    let mut handoff = g.prepare_observation(a, bundle)?;
    let mut daemon = handoff.launch_daemon(bundle)?;
    let pid = handoff.discover_daemon(&daemon)?;
    let mut authority = handoff.pin_daemon(bundle, &daemon, pid)?;
    handoff.verify_daemon(bundle, &mut authority)?;
    let token = authority.lab_remote_token()?;
    lab::case(
        "actual_no_ptrace_guard_owner_native_daemon_ancestry_configuration_and_fresh_reinspection",
    );
    let mut observer = handoff.launch_observer(bundle, &mut authority)?;
    handoff.serve_once(bundle, &mut authority)?;
    wait_exit(&mut observer)?;
    let bytes = fs::read(a.spec.exit.state_dir.join("worker/observation.json"))
        .map_err(|_| Error::ChildFailed)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::ChildFailed)?;
    if value["actual_localapi_unenrolled"] != true || value["readiness"] != false {
        return Err(Error::ChildFailed);
    }
    handoff.verify_daemon(bundle, &mut authority)?;
    lab::case("actual_no_ptrace_guard_owner_native_sender_fresh_authenticated_one_use_observation");
    handoff.quarantine_daemon(bundle, &mut authority)?;
    handoff.cleanup()?;
    daemon.signal(libc::SIGTERM)?;
    wait_exit(&mut daemon)?;
    drop(authority);
    drop(observer);
    drop(daemon);
    if !pids(a)?.is_empty() {
        return Err(Error::PlacementFailed);
    }
    g.lab_resume_bootstrap()?;
    g.audit()?;
    Ok(token)
}
