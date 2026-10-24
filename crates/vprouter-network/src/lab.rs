//! Only compiled into the explicitly ignored disposable-kernel integration test.
use crate::{Error, Result};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use std::{fs, os::unix::fs::MetadataExt};

pub(crate) fn admit() -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(Error::LabRequired);
    }
    let own = fs::metadata("/proc/self/ns/net").map_err(|_| Error::LabRequired)?;
    let init = fs::metadata("/proc/1/ns/net").map_err(|_| Error::LabRequired)?;
    if (own.dev(), own.ino()) == (init.dev(), init.ino()) {
        return Err(Error::LabRequired);
    }
    let mut dir = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::LabRequired)?;
    for name in ["var", "lib", "vprouter-v2-lab"] {
        let st = fstat(&dir).map_err(|_| Error::LabRequired)?;
        if st.st_uid != 0 || st.st_mode & 0o022 != 0 {
            return Err(Error::LabRequired);
        }
        dir = openat(
            &dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::LabRequired)?;
    }
    let st = fstat(&dir).map_err(|_| Error::LabRequired)?;
    if st.st_uid != 0 || st.st_mode & 0o7777 != 0o700 {
        return Err(Error::LabRequired);
    }
    let marker = openat(
        &dir,
        "isolated-acceptance",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::LabRequired)?;
    let st = fstat(&marker).map_err(|_| Error::LabRequired)?;
    if st.st_uid != 0
        || st.st_gid != 0
        || st.st_mode & 0o7777 != 0o600
        || st.st_nlink != 1
        || FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
    {
        return Err(Error::LabRequired);
    }
    Ok(())
}

use crate::{NamespaceTarget, NativeNetwork, Plan};
use std::{fs::File, os::fd::AsFd, process::Command};
fn ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|_| Error::Io)?;
    if !output.status.success() {
        return Err(Error::KernelRejected);
    }
    Ok(())
}
fn json(args: &[&str]) -> Result<serde_json::Value> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|_| Error::Io)?;
    if !output.status.success() {
        return Err(Error::KernelRejected);
    }
    serde_json::from_slice(&output.stdout).map_err(|_| Error::Malformed)
}
fn open_in_namespace(plan: Plan, fd: &File) -> Result<(NativeNetwork, File)> {
    // Test-only dedicated synchronous thread; no async runtime or production
    // setns. Opening /proc/thread-self/ns/net binds identity to this thread.
    std::thread::scope(|s| {
        s.spawn(|| {
            rustix::thread::move_into_link_name_space(
                fd.as_fd(),
                Some(rustix::thread::LinkNameSpaceType::Network),
            )
            .map_err(|_| Error::NamespaceUnverified)?;
            let direct =
                File::open("/proc/thread-self/ns/net").map_err(|_| Error::NamespaceUnverified)?;
            Ok((NativeNetwork::open(plan)?, direct))
        })
        .join()
        .map_err(|_| Error::Io)?
    })
}
struct LabNamespaces {
    names: Vec<String>,
}
impl LabNamespaces {
    fn create(&mut self, name: String) -> Result<File> {
        ip(&["netns", "add", &name])?;
        self.names.push(name.clone());
        File::open(format!("/run/netns/{name}")).map_err(|_| Error::Io)
    }
}
impl Drop for LabNamespaces {
    fn drop(&mut self) {
        for n in &self.names {
            let _ = Command::new("ip").args(["netns", "delete", n]).output();
        }
    }
}
fn case(name: &str) {
    println!("{{\"case\":\"{name}\",\"result\":\"pass\"}}");
}
fn stage(name: &'static str) {
    eprintln!("LAB_STAGE {name}");
}
fn check_link(namespace: Option<&str>, name: &str, kind: &str, alias: &str) -> Result<()> {
    let args = if let Some(ns) = namespace {
        vec!["-n", ns, "-j", "-d", "link", "show", "dev", name]
    } else {
        vec!["-j", "-d", "link", "show", "dev", name]
    };
    let j = json(&args)?;
    let l = &j[0];
    if l["ifname"] != name
        || l["ifalias"] != alias
        || l["linkinfo"]["info_kind"] != kind
        || l["mtu"] != 1420
        || l["flags"]
            .as_array()
            .ok_or(Error::Malformed)?
            .iter()
            .any(|f| f == "UP")
    {
        return Err(Error::Drifted);
    }
    Ok(())
}
fn run() -> Result<()> {
    admit()?; // Before sockets, subprocesses, or any mutation.
    let (record, profile) = crate::tests::fixture();
    let plan = Plan::new(&record, "networklab", &record.exits[0], &profile)?;
    let mut namespaces = LabNamespaces { names: Vec::new() };
    let tn = format!("vr-network-lab-{}-t", std::process::id());
    let dn = format!("vr-network-lab-{}-d", std::process::id());
    stage("create_disposable_namespaces");
    let tf = namespaces.create(tn.clone())?;
    let df = namespaces.create(dn.clone())?;
    stage("open_host_sockets");
    let mut host = NativeNetwork::open(plan.clone())?;
    stage("open_transport_sockets_and_direct_proc_fd");
    let (mut transport, tdirect) = open_in_namespace(plan.clone(), &tf)?;
    stage("open_data_sockets_and_direct_proc_fd");
    let (mut data, ddirect) = open_in_namespace(plan.clone(), &df)?;
    stage("validate_direct_proc_namespace_fds");
    let target_t = NamespaceTarget::from_trusted_network_namespace(tdirect.as_fd())?;
    let target_d = NamespaceTarget::from_trusted_network_namespace(ddirect.as_fd())?;
    stage("create_foreign_control_and_refuse_native_creation");
    ip(&["link", "add", "vrnetsentinel", "type", "dummy"])?;
    ip(&[
        "-n",
        &tn,
        "link",
        "add",
        plan.wireguard_name(),
        "type",
        "dummy",
    ])?;
    if !matches!(
        transport.create_wireguard_down(&profile),
        Err(Error::Foreign)
    ) {
        return Err(Error::Drifted);
    }
    let j = json(&[
        "-n",
        &tn,
        "-j",
        "-d",
        "link",
        "show",
        "dev",
        plan.wireguard_name(),
    ])?;
    if j[0]["linkinfo"]["info_kind"] != "dummy" {
        return Err(Error::Foreign);
    }
    ip(&["-n", &tn, "link", "delete", plan.wireguard_name()])?;
    case("foreign_name_refused_without_replacement");
    stage("create_native_veth_pair_down");
    let pair = host.create_veth_pair_down(&mut transport, &target_t)?;
    check_link(None, plan.host_name(), "veth", plan.ownership_alias())?;
    check_link(
        Some(&tn),
        plan.transport_name(),
        "veth",
        plan.ownership_alias(),
    )?;
    if !matches!(
        host.create_veth_pair_down(&mut transport, &target_t),
        Err(Error::Foreign)
    ) {
        return Err(Error::Drifted);
    }
    case("native_veth_both_ends_down_owned_and_duplicate_refused");
    stage("create_and_configure_native_wireguard_down");
    let token = transport.create_wireguard_down(&profile)?;
    check_link(
        Some(&tn),
        plan.wireguard_name(),
        "wireguard",
        plan.ownership_alias(),
    )?;
    stage("move_native_wireguard_down_to_data");
    let token = transport.move_wireguard_down(&mut data, &target_d, token)?;
    check_link(
        Some(&dn),
        plan.wireguard_name(),
        "wireguard",
        plan.ownership_alias(),
    )?;
    stage("observe_post_move_namespaces");
    if transport
        .observe()?
        .links
        .iter()
        .any(|l| l.name == plan.wireguard_name())
        || data
            .observe()?
            .links
            .iter()
            .any(|l| l.name == plan.transport_name() || l.name == plan.host_name())
    {
        return Err(Error::Drifted);
    }
    stage("independent_wg_public_controls");
    let endpoints = Command::new("ip")
        .args([
            "netns",
            "exec",
            &dn,
            "wg",
            "show",
            plan.wireguard_name(),
            "endpoints",
        ])
        .output()
        .map_err(|_| Error::Io)?;
    let expected = format!(
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\t{}\n",
        plan.endpoint()
    );
    if !endpoints.status.success() || endpoints.stdout != expected.as_bytes() {
        return Err(Error::Drifted);
    }
    let allowed = Command::new("ip")
        .args([
            "netns",
            "exec",
            &dn,
            "wg",
            "show",
            plan.wireguard_name(),
            "allowed-ips",
        ])
        .output()
        .map_err(|_| Error::Io)?;
    if !allowed.status.success()
        || allowed.stdout != b"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\t0.0.0.0/0\n"
    {
        return Err(Error::Drifted);
    }
    case("native_wireguard_moved_down_peer_endpoint_allowedips_verified");
    stage("address_control_and_cleanup_refusal");
    let before = data.observe()?;
    if before.addresses.iter().any(|a| a.index == token.index()) {
        return Err(Error::Drifted);
    }
    // Independent TEST control demonstrates address projection and that scoped
    // cleanup refuses even owned names when an address/route has appeared. This
    // is not evidence for a production native address or activation API.
    let address = format!("{}/32", plan.address());
    ip(&[
        "-n",
        &dn,
        "address",
        "add",
        &address,
        "dev",
        plan.wireguard_name(),
    ])?;
    let observed = data.observe()?;
    if !observed.addresses.iter().any(|a| {
        a.index == token.index()
            && a.address == std::net::IpAddr::V4(plan.address())
            && a.prefix == 32
    }) {
        return Err(Error::Drifted);
    }
    let j = json(&[
        "-n",
        &dn,
        "-j",
        "address",
        "show",
        "dev",
        plan.wireguard_name(),
    ])?;
    if !j[0]["addr_info"]
        .as_array()
        .ok_or(Error::Malformed)?
        .iter()
        .any(|a| a["local"] == plan.address().to_string() && a["prefixlen"] == 32)
    {
        return Err(Error::Drifted);
    }
    if !matches!(data.cleanup_wireguard_down(token), Err(Error::Drifted)) {
        return Err(Error::Drifted);
    }
    ip(&[
        "-n",
        &dn,
        "address",
        "delete",
        &address,
        "dev",
        plan.wireguard_name(),
    ])?;
    case("address_projection_and_address_drift_cleanup_refusal");
    stage("reconcile_and_cleanup_owned_down_resources");
    let token = data.reconcile_wireguard_down()?;
    data.cleanup_wireguard_down(token)?;
    host.cleanup_veth_pair_down(&mut transport, pair)?;
    if host
        .observe()?
        .links
        .iter()
        .any(|l| l.name == plan.host_name())
        || transport
            .observe()?
            .links
            .iter()
            .any(|l| l.name == plan.transport_name())
        || data
            .observe()?
            .links
            .iter()
            .any(|l| l.name == plan.wireguard_name())
    {
        return Err(Error::Drifted);
    }
    json(&["-j", "-d", "link", "show", "dev", "vrnetsentinel"])?;
    case("owned_only_native_cleanup_sentinel_preserved");
    println!(
        "{{\"case\":\"native_network_isolated_acceptance\",\"result\":\"pass\",\"guard_runtime\":false,\"activation\":false}}"
    );
    Ok(())
}
#[test]
#[ignore = "requires admitted disposable guest and distinct PID1/self netns"]
fn native_acceptance() {
    if let Err(e) = run() {
        panic!("native network isolated acceptance: {e}");
    }
}
