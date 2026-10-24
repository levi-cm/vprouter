#![forbid(unsafe_code)]
//! Explicitly ignored, exact-artifact admitted LOCAL guest packet oracle.
//! All keys/profiles are fixed synthetic values. Failures retain owned records.
use super::{
    Admission, Error, Result, execution_lab, kernel, lab, owned, process, transport::GuardTransport,
};
use serde::Deserialize;
use std::{
    fs,
    net::{Ipv4Addr, UdpSocket},
    os::{
        fd::AsFd,
        unix::fs::{DirBuilderExt, MetadataExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use vprouter_core::{
    allocation::{AllocationRecord, AllocationStore},
    config::Configuration,
    profile::Profile,
};
const ROOT: &str = "/var/lib/vprouter-v2-lab";
const PROBE: &str = "/var/lib/vprouter-v2-lab/launch-execution-probe";
const ENDPOINT: &str = "185.65.134.88";
const HOST_WAN: &str = "185.65.134.89";
const SERVER_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
const CLIENT_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Actual,
    Reversible,
    DeletedWg,
    DeletedTransport,
    CooperationDrift,
    ForeignCollision,
    InterruptedActivation,
    InterruptedCleanup,
}
impl Scenario {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "reversible" => Self::Reversible,
            "deleted-wg" => Self::DeletedWg,
            "deleted-transport" => Self::DeletedTransport,
            "cooperation-drift" => Self::CooperationDrift,
            "foreign-collision" => Self::ForeignCollision,
            "interrupted-activation" => Self::InterruptedActivation,
            "interrupted-cleanup" => Self::InterruptedCleanup,
            _ => return None,
        })
    }
}
fn forward_rules() -> Result<Vec<serde_json::Value>> {
    let bytes = command(
        "nft",
        &["-j", "-a", "list", "chain", "ip", "filter", "FORWARD"],
    )?;
    let j: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| Error::NetworkPolicy)?;
    Ok(j["nftables"]
        .as_array()
        .ok_or(Error::NetworkPolicy)?
        .iter()
        .filter_map(|r| r.get("rule").cloned())
        .collect())
}
fn b64(input: [u8; 32]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in input.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        s.push(A[(n >> 18) as usize] as char);
        s.push(A[((n >> 12) & 63) as usize] as char);
        s.push(if c.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    s
}
fn profile_source() -> String {
    let peer = b64(x25519_dalek::x25519(
        [2; 32],
        x25519_dalek::X25519_BASEPOINT_BYTES,
    ));
    format!(
        "[Interface]\nPrivateKey={CLIENT_KEY}\nAddress=10.64.0.2/32\nDNS=10.64.0.1\n[Peer]\nPublicKey={peer}\nAllowedIPs=0.0.0.0/0\nEndpoint={ENDPOINT}:51820\n"
    )
}
fn profile() -> Result<Profile> {
    Profile::parse(profile_source().as_bytes(), "de-fra-wg-404", None)
        .map_err(|_| Error::InvalidSpec)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAdmission {
    artifact_sha256: String,
    network_dev: u64,
    network_ino: u64,
}
fn admit(actual: bool) -> Result<()> {
    process::single_threaded()?;
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(Error::LabRequired);
    }
    let own = fs::metadata("/proc/self/ns/net").map_err(|_| Error::LabRequired)?;
    let init = fs::metadata("/proc/1/ns/net").map_err(|_| Error::LabRequired)?;
    if (own.dev(), own.ino()) != (init.dev(), init.ino()) {
        return Err(Error::LabRequired);
    }
    let read = |p: &Path, max| {
        vprouter_linux::storage::read(p, vprouter_linux::storage::Kind::SecretFile, max)
            .map_err(|_| Error::LabRequired)
    };
    read(Path::new(&format!("{ROOT}/isolated-acceptance")), 4096)?;
    let m: HostAdmission = serde_json::from_slice(&read(
        Path::new(&format!(
            "{ROOT}/{}",
            if actual {
                "task8b2-host-acceptance"
            } else {
                "task8a-host-acceptance"
            }
        )),
        4096,
    )?)
    .map_err(|_| Error::LabRequired)?;
    let exe = std::env::current_exe().map_err(|_| Error::LabRequired)?;
    let bytes = vprouter_linux::storage::read(
        &exe,
        vprouter_linux::storage::Kind::PublicFile,
        64 * 1024 * 1024,
    )
    .map_err(|_| Error::LabRequired)?;
    if m.artifact_sha256 != vprouter_linux::sha256(&bytes)
        || (m.network_dev, m.network_ino) != (own.dev(), own.ino())
    {
        return Err(Error::LabRequired);
    }
    Ok(())
}
fn private(p: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(p)
        .map_err(|_| Error::UnsafeInput)
}
fn command(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let o = Command::new(program)
        .args(args)
        .output()
        .map_err(|_| Error::NetworkOperation)?;
    if !o.status.success() || o.stdout.len() > 4 * 1024 * 1024 {
        return Err(Error::NetworkOperation);
    }
    Ok(o.stdout)
}
fn ip(args: &[&str]) -> Result<()> {
    command("ip", args).map(|_| ())
}
fn ns_file(name: &str) -> Result<fs::File> {
    fs::File::open(format!("/run/netns/{name}")).map_err(|_| Error::NamespaceMismatch)
}
fn socket(fd: impl AsFd, address: &str) -> Result<UdpSocket> {
    kernel::network_scope(fd, || {
        let s = UdpSocket::bind(address).map_err(|_| Error::NetworkOperation)?;
        s.set_read_timeout(Some(Duration::from_millis(400)))
            .map_err(|_| Error::NetworkOperation)?;
        Ok(s)
    })
}
fn health_socket(g: &GuardTransport<'_>, port: u16) -> Result<UdpSocket> {
    let (ns, group) = g.lab_namespaces();
    kernel::network_scope(&ns.data, || {
        group.socket_scope(|| {
            let s = UdpSocket::bind((Ipv4Addr::new(10, 64, 0, 2), port))
                .map_err(|_| Error::NetworkOperation)?;
            s.set_read_timeout(Some(Duration::from_millis(800)))
                .map_err(|_| Error::NetworkOperation)?;
            Ok(s)
        })
    })
}
fn roundtrip(client: &UdpSocket, server: &UdpSocket, marker: &[u8]) -> Result<()> {
    fn packet<T>(stage: &'static str, result: std::io::Result<T>) -> Result<T> {
        result.map_err(|e| {
            eprintln!(
                "LAB_PACKET_FAILURE stage={stage} errno={:?}",
                e.raw_os_error()
            );
            Error::NetworkOperation
        })
    }
    packet("client_send", client.send_to(marker, "10.64.0.1:40444"))?;
    let mut b = [0u8; 2048];
    let (n, from) = packet("server_receive", server.recv_from(&mut b))?;
    if &b[..n] != marker {
        eprintln!("LAB_PACKET_FAILURE stage=server_marker");
        return Err(Error::NetworkOperation);
    }
    packet("server_send", server.send_to(marker, from))?;
    let (n, _) = packet("client_receive", client.recv_from(&mut b))?;
    if &b[..n] != marker {
        eprintln!("LAB_PACKET_FAILURE stage=client_marker");
        return Err(Error::NetworkOperation);
    }
    Ok(())
}
struct Capture {
    child: Child,
    path: PathBuf,
}
impl Capture {
    fn start(ns: Option<&str>, interface: &str, path: PathBuf) -> Result<Self> {
        let mut cmd = if let Some(n) = ns {
            let mut c = Command::new("ip");
            c.args(["netns", "exec", n, "tcpdump"]);
            c
        } else {
            Command::new("tcpdump")
        };
        let err = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.with_extension("stderr"))
            .map_err(|_| Error::UnsafeInput)?;
        let child = cmd
            .args([
                "--immediate-mode",
                "-p",
                "-U",
                "-n",
                "-s",
                "0",
                "-B",
                "4096",
                "-i",
                interface,
                "-w",
            ])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(err))
            .spawn()
            .map_err(|_| Error::NetworkOperation)?;
        let mut result = Self { child, path };
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            if fs::metadata(&result.path).is_ok_and(|m| m.len() >= 24) {
                return Ok(result);
            }
            if result
                .child
                .try_wait()
                .map_err(|_| Error::NetworkOperation)?
                .is_some()
                || Instant::now() >= end
            {
                return Err(Error::NetworkOperation);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn finish(mut self) -> Result<Vec<u8>> {
        // Test-only fixed signal to exact unreaped tcpdump child; no shell.
        command("kill", &["-INT", &self.child.id().to_string()])?;
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait().map_err(|_| Error::NetworkOperation)? {
                if !status.success() {
                    return Err(Error::NetworkOperation);
                }
                break;
            }
            if Instant::now() >= end {
                return Err(Error::Deadline);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let stderr = fs::read_to_string(self.path.with_extension("stderr"))
            .map_err(|_| Error::NetworkOperation)?;
        if !stderr.contains("0 packets dropped by kernel") {
            return Err(Error::NetworkOperation);
        }
        fs::read(&self.path).map_err(|_| Error::NetworkOperation)
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        // Flush exact still-owned child captures even when the packet oracle
        // fails before finish(). Never signal a PID after observing child exit.
        let _ = command("kill", &["-INT", &self.child.id().to_string()]);
        let end = Instant::now() + Duration::from_secs(2);
        while Instant::now() < end {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn has(bytes: &[u8], marker: &[u8]) -> bool {
    bytes.windows(marker.len()).any(|w| w == marker)
}
fn allocation(dir: &Path, deployment: &str) -> Result<AllocationRecord> {
    let value = serde_json::json!({"schema_version":2,"deployment_id":deployment,"site":"debdev","gateway_image":format!("sha256:{}","a".repeat(64)),"exits":[{"id":"one","enabled":true,"state_dir":dir.join("one"),"mode":{"kind":"mullvad","profile":dir.join("synthetic.conf"),"expected_server":"de-fra-wg-404"}}],"dependency_adapters":[],"client_policies":[]});
    let c = Configuration::parse(&serde_json::to_vec(&value).map_err(|_| Error::InvalidSpec)?)
        .map_err(|_| Error::InvalidSpec)?
        .validate_with(|_, _| Profile::parse(profile_source().as_bytes(), "de-fra-wg-404", None))
        .map_err(|_| Error::InvalidSpec)?;
    AllocationRecord::from_configuration(&c, 1).map_err(|_| Error::AllocationMismatch)
}
fn setup_wan(peer: &str, host: &str, other: &str, dir: &Path) -> Result<()> {
    ip(&["netns", "add", peer])?;
    ip(&[
        "link", "add", host, "type", "veth", "peer", "name", other, "netns", peer,
    ])?;
    ip(&["link", "set", host, "alias", "task8a-owned-synthetic-wan"])?;
    // Pin IPv4-only fixture topology before either end becomes usable. This
    // avoids unrelated tentative IPv6 DAD transitions during exact host audits.
    ip(&["link", "set", host, "addrgenmode", "none"])?;
    ip(&["-n", peer, "link", "set", other, "addrgenmode", "none"])?;
    ip(&["address", "add", &format!("{HOST_WAN}/32"), "dev", host])?;
    ip(&["link", "set", host, "up"])?;
    ip(&[
        "route",
        "add",
        &format!("{ENDPOINT}/32"),
        "dev",
        host,
        "src",
        HOST_WAN,
    ])?;
    ip(&[
        "-n",
        peer,
        "address",
        "add",
        &format!("{ENDPOINT}/32"),
        "dev",
        other,
    ])?;
    ip(&["-n", peer, "link", "set", other, "up"])?;
    ip(&["-n", peer, "link", "set", "lo", "up"])?;
    ip(&[
        "-n",
        peer,
        "route",
        "add",
        &format!("{HOST_WAN}/32"),
        "dev",
        other,
    ])?;
    ip(&["-n", peer, "link", "add", "wgpeer8a", "type", "wireguard"])?;
    let pubkey = b64(x25519_dalek::x25519(
        [1; 32],
        x25519_dalek::X25519_BASEPOINT_BYTES,
    ));
    let config = dir.join("synthetic-peer.conf");
    lab::write(&config,format!("[Interface]\nPrivateKey={SERVER_KEY}\nListenPort=51820\n[Peer]\nPublicKey={pubkey}\nAllowedIPs=10.64.0.2/32\n").as_bytes())?;
    command(
        "ip",
        &[
            "netns",
            "exec",
            peer,
            "wg",
            "setconf",
            "wgpeer8a",
            config.to_str().ok_or(Error::UnsafeInput)?,
        ],
    )?;
    ip(&[
        "-n",
        peer,
        "address",
        "add",
        "10.64.0.1/32",
        "dev",
        "wgpeer8a",
    ])?;
    ip(&["-n", peer, "link", "set", "wgpeer8a", "up"])?;
    ip(&[
        "-n",
        peer,
        "route",
        "add",
        "10.64.0.2/32",
        "dev",
        "wgpeer8a",
    ])
}
fn drain(server: &UdpSocket) -> Result<()> {
    server
        .set_nonblocking(true)
        .map_err(|_| Error::NetworkOperation)?;
    let mut b = [0u8; 2048];
    while let Ok((n, _)) = server.recv_from(&mut b) {
        if b[..n].starts_with(b"VR8A_FORBIDDEN_") {
            return Err(Error::NetworkPolicy);
        }
    }
    server
        .set_nonblocking(false)
        .map_err(|_| Error::NetworkOperation)
}
struct Continuous {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    attempts: std::sync::Arc<std::sync::atomic::AtomicU64>,
    thread: Option<std::thread::JoinHandle<()>>,
    checkpoints: std::cell::RefCell<Vec<serde_json::Value>>,
    path: PathBuf,
}
impl Continuous {
    fn start(socket: &UdpSocket, dir: &Path) -> Result<Self> {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        };
        let socket = socket.try_clone().map_err(|_| Error::NetworkOperation)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| Error::NetworkOperation)?;
        let stop = Arc::new(AtomicBool::new(false));
        let attempts = Arc::new(AtomicU64::new(0));
        let (end_flag, count) = (stop.clone(), attempts.clone());
        let thread = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(55);
            while !end_flag.load(Ordering::Acquire) && Instant::now() < deadline {
                let n = count.load(Ordering::Relaxed);
                let _ = socket.send_to(
                    format!("VR8A_FORBIDDEN_CONTINUOUS_{n}").as_bytes(),
                    "10.64.0.1:40444",
                );
                count.fetch_add(1, Ordering::Release);
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        let result = Self {
            stop,
            attempts,
            thread: Some(thread),
            checkpoints: std::cell::RefCell::new(Vec::new()),
            path: dir.join("continuous-sender.json"),
        };
        result.checkpoint("started_after_all_namespace_and_cgroup_socket_setup")?;
        Ok(result)
    }
    fn checkpoint(&self, label: &str) -> Result<()> {
        use std::sync::atomic::Ordering;
        let before = self.attempts.load(Ordering::Acquire);
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let after = self.attempts.load(Ordering::Acquire);
            if after >= before + 3 {
                self.checkpoints.borrow_mut().push(serde_json::json!({"phase":label,"attempts_before":before,"attempts_after":after}));
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn finish(mut self) -> Result<()> {
        self.stop_and_record()
    }
    fn stop_and_record(&mut self) -> Result<()> {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| Error::NetworkOperation)?;
            let data = serde_json::json!({"attempts":self.attempts.load(std::sync::atomic::Ordering::Acquire),"bounded_nonblocking_sender":true,"joined":true,"checkpoints":self.checkpoints.borrow().as_slice()});
            lab::write(
                &self.path,
                &serde_json::to_vec_pretty(&data).map_err(|_| Error::InvalidSpec)?,
            )?;
        }
        Ok(())
    }
}
impl Drop for Continuous {
    fn drop(&mut self) {
        let _ = self.stop_and_record();
    }
}
struct FaultTraffic<'a> {
    app: &'a UdpSocket,
    health: &'a UdpSocket,
    server: &'a UdpSocket,
    continuous: &'a Continuous,
}
fn fault_matrix(
    g: &mut GuardTransport<'_>,
    dn: &str,
    tn: &str,
    dir: &Path,
    traffic: &FaultTraffic<'_>,
) -> Result<()> {
    let (app, health, server) = (traffic.app, traffic.health, traffic.server);
    let wg = g.lab_plan().wireguard_name().to_owned();
    let trans = g.lab_plan().transport_name().to_owned();
    let endpoint = g.lab_plan().endpoint().to_string();
    let server_public = b64(x25519_dalek::x25519(
        [2; 32],
        x25519_dalek::X25519_BASEPOINT_BYTES,
    ));
    let client_config = dir.join("synthetic-client-device.conf");
    lab::write(&client_config,format!("[Interface]\nPrivateKey={CLIENT_KEY}\n[Peer]\nPublicKey={server_public}\nAllowedIPs=0.0.0.0/0\nEndpoint={endpoint}\n").as_bytes())?;
    let wrong_private = dir.join("synthetic-wrong-private.conf");
    let wrong_peer = dir.join("synthetic-wrong-peer.conf");
    let wrong_key = b64([3; 32]);
    let wrong_public = b64(x25519_dalek::x25519(
        [3; 32],
        x25519_dalek::X25519_BASEPOINT_BYTES,
    ));
    lab::write(&wrong_private,format!("[Interface]\nPrivateKey={wrong_key}\n[Peer]\nPublicKey={server_public}\nAllowedIPs=0.0.0.0/0\nEndpoint={endpoint}\n").as_bytes())?;
    lab::write(&wrong_peer,format!("[Interface]\nPrivateKey={CLIENT_KEY}\n[Peer]\nPublicKey={wrong_public}\nAllowedIPs=0.0.0.0/0\nEndpoint={endpoint}\n").as_bytes())?;
    for kind in 0..15 {
        g.audit()?;
        lab::stage(&format!("inject_network_fault_{kind}"));
        match kind {
            0 => ip(&["-n", dn, "link", "set", &wg, "down"]),
            1 => ip(&["-n", tn, "link", "set", &trans, "down"]),
            2 => command(
                "ip",
                &[
                    "netns",
                    "exec",
                    dn,
                    "wg",
                    "set",
                    &wg,
                    "peer",
                    &server_public,
                    "endpoint",
                    "185.65.134.90:51820",
                ],
            )
            .map(|_| ()),
            3 => command(
                "ip",
                &[
                    "netns",
                    "exec",
                    dn,
                    "wg",
                    "set",
                    &wg,
                    "peer",
                    &server_public,
                    "remove",
                ],
            )
            .map(|_| ()),
            4 => ip(&["-n", dn, "route", "del", "default", "dev", &wg]),
            5 => ip(&["-n", dn, "route", "add", "185.65.134.88/32", "dev", "lo"]),
            6 => ip(&["-n", dn, "route", "add", "172.17.0.0/16", "dev", &wg]),
            7 => ip(&["-n", dn, "-6", "route", "add", "default", "dev", &wg]),
            8 => ip(&["-n", dn, "rule", "add", "priority", "100", "table", "100"]),
            9 => ip(&["-n", dn, "link", "add", "vr8fault", "type", "dummy"]),
            10 => ip(&["-n", tn, "route", "add", "default", "dev", &trans]),
            11 => ip(&["-n", tn, "route", "del", "185.65.134.88/32"]),
            12 => ip(&["route", "add", "185.65.134.90/32", "dev", "lo"]),
            13 | 14 => command(
                "ip",
                &[
                    "netns",
                    "exec",
                    dn,
                    "wg",
                    "setconf",
                    &wg,
                    if kind == 13 {
                        wrong_private.to_str()
                    } else {
                        wrong_peer.to_str()
                    }
                    .ok_or(Error::UnsafeInput)?,
                ],
            )
            .map(|_| ()),
            _ => unreachable!(),
        }?;
        traffic
            .continuous
            .checkpoint(&format!("network_fault_{kind}_mutated_before_audit"))?;
        for n in 0..8 {
            let _ = app.send_to(
                format!("VR8A_FORBIDDEN_FAULT_{kind}_{n}").as_bytes(),
                "10.64.0.1:40444",
            );
        }
        if g.audit().is_ok() {
            return Err(Error::NetworkPolicy);
        }
        g.lab_offline()?;
        traffic.continuous.checkpoint(&format!(
            "network_fault_{kind}_verified_offline_before_repair"
        ))?;
        for n in 8..16 {
            let _ = app.send_to(
                format!("VR8A_FORBIDDEN_FAULT_{kind}_{n}").as_bytes(),
                "10.64.0.1:40444",
            );
        }
        match kind {
            0 => {
                ip(&["-n", dn, "link", "set", &wg, "up"])?;
                ip(&[
                    "-n",
                    dn,
                    "route",
                    "add",
                    "default",
                    "dev",
                    &wg,
                    "src",
                    "10.64.0.2",
                    "proto",
                    "static",
                    "scope",
                    "link",
                ])
            }
            1 => {
                ip(&["-n", tn, "link", "set", &trans, "up"])?;
                let (host, source) = g.lab_plan().transport_addresses();
                ip(&[
                    "-n",
                    tn,
                    "route",
                    "add",
                    &format!("{host}/32"),
                    "dev",
                    &trans,
                    "src",
                    &source.to_string(),
                    "proto",
                    "static",
                    "scope",
                    "link",
                ])?;
                ip(&[
                    "-n",
                    tn,
                    "route",
                    "add",
                    "185.65.134.88/32",
                    "via",
                    &host.to_string(),
                    "dev",
                    &trans,
                    "src",
                    &source.to_string(),
                    "proto",
                    "static",
                ])
            }
            2 => command(
                "ip",
                &[
                    "netns",
                    "exec",
                    dn,
                    "wg",
                    "set",
                    &wg,
                    "peer",
                    &server_public,
                    "endpoint",
                    &endpoint,
                ],
            )
            .map(|_| ()),
            3 => command(
                "ip",
                &[
                    "netns",
                    "exec",
                    dn,
                    "wg",
                    "setconf",
                    &wg,
                    client_config.to_str().ok_or(Error::UnsafeInput)?,
                ],
            )
            .map(|_| ()),
            4 => ip(&[
                "-n",
                dn,
                "route",
                "add",
                "default",
                "dev",
                &wg,
                "src",
                "10.64.0.2",
                "proto",
                "static",
                "scope",
                "link",
            ]),
            5 => ip(&["-n", dn, "route", "del", "185.65.134.88/32", "dev", "lo"]),
            6 => ip(&["-n", dn, "route", "del", "172.17.0.0/16", "dev", &wg]),
            7 => ip(&["-n", dn, "-6", "route", "del", "default", "dev", &wg]),
            8 => ip(&["-n", dn, "rule", "del", "priority", "100", "table", "100"]),
            9 => ip(&["-n", dn, "link", "del", "vr8fault"]),
            10 => ip(&["-n", tn, "route", "del", "default", "dev", &trans]),
            11 => {
                let (host, source) = g.lab_plan().transport_addresses();
                ip(&[
                    "-n",
                    tn,
                    "route",
                    "add",
                    "185.65.134.88/32",
                    "via",
                    &host.to_string(),
                    "dev",
                    &trans,
                    "src",
                    &source.to_string(),
                    "proto",
                    "static",
                ])
            }
            12 => ip(&["route", "del", "185.65.134.90/32", "dev", "lo"]),
            13 | 14 => command(
                "ip",
                &[
                    "netns",
                    "exec",
                    dn,
                    "wg",
                    "setconf",
                    &wg,
                    client_config.to_str().ok_or(Error::UnsafeInput)?,
                ],
            )
            .map(|_| ()),
            _ => unreachable!(),
        }?;
        drain(server)?;
        g.lab_resume_bootstrap()?;
        traffic
            .continuous
            .checkpoint(&format!("network_fault_{kind}_bootstrap_restored"))?;
        drain(server)?;
        roundtrip(
            health,
            server,
            format!("VR8A_RECOVERED_HEALTH_{kind}").as_bytes(),
        )?;
        lab::case(&format!(
            "network_fault_{kind}_full_quarantine_and_exact_recovery"
        ));
    }
    Ok(())
}
fn nft_in(namespace: &str, args: &[&str]) -> Result<Vec<u8>> {
    let mut command_args = vec!["netns", "exec", namespace, "nft"];
    command_args.extend_from_slice(args);
    command("ip", &command_args)
}
fn nft_json(namespace: &str, args: &[&str]) -> Result<serde_json::Value> {
    let mut flags = vec!["-j", "-a"];
    flags.extend_from_slice(args);
    serde_json::from_slice(&nft_in(namespace, &flags)?).map_err(|_| Error::NetworkPolicy)
}
fn forbidden_burst(app: &UdpSocket, label: &str) {
    for n in 0..16 {
        let _ = app.send_to(
            format!("VR8A_FORBIDDEN_{label}_{n}").as_bytes(),
            "10.64.0.1:40444",
        );
    }
}
fn nft_faults(
    g: &mut GuardTransport<'_>,
    dn: &str,
    dir: &Path,
    traffic: &FaultTraffic<'_>,
) -> Result<()> {
    let (app, health, server) = (traffic.app, traffic.health, traffic.server);
    let (q, p) = g.lab_data_tables();
    g.audit()?;
    // Fixed TEST-ONLY CLI batch; runtime actuation remains native. Exact live
    // policy comparison and native audit establish failed-update retention.
    let before = nft_json(dn, &["list", "table", "inet", &q])?;
    let batch = dir.join("owned-failed-atomic.nft");
    lab::write(
        &batch,
        format!("delete table inet {q}\nadd rule inet {q} vr8a_missing_chain drop\n").as_bytes(),
    )?;
    let failed = Command::new("ip")
        .args([
            "netns",
            "exec",
            dn,
            "nft",
            "-f",
            batch.to_str().ok_or(Error::UnsafeInput)?,
        ])
        .output()
        .map_err(|_| Error::NetworkOperation)?;
    if failed.status.success() || before != nft_json(dn, &["list", "table", "inet", &q])? {
        return Err(Error::NetworkPolicy);
    }
    g.audit()?;
    roundtrip(health, server, b"VR8A_AFTER_FAILED_ATOMIC")?;
    lab::case("fixed_cli_failed_atomic_batch_exact_policy_retained_native_audit_and_health");
    for table in [&q, &p] {
        g.audit()?;
        nft_in(dn, &["delete", "table", "inet", table])?;
        traffic
            .continuous
            .checkpoint("owned_filter_removed_before_audit")?;
        forbidden_burst(app, "NFT_REMOVED_BEFORE_AUDIT");
        if g.audit().is_ok() {
            return Err(Error::NetworkPolicy);
        }
        g.lab_offline()?;
        traffic
            .continuous
            .checkpoint("owned_filter_removed_verified_offline")?;
        forbidden_burst(app, "NFT_REMOVED_AFTER_AUDIT");
        drain(server)?;
        g.lab_resume_bootstrap()?;
        traffic
            .continuous
            .checkpoint("removed_filter_restored_bootstrap")?;
        drain(server)?;
        roundtrip(health, server, b"VR8A_AFTER_TABLE_REMOVAL")?;
        lab::case(&format!(
            "owned_table_{table}_removal_independent_filter_denial_and_emergency_restoration"
        ));
    }
    g.audit()?;
    const MARKER: &str = "VR8A_OWNED_TEST_DRIFT";
    nft_in(
        dn,
        &[
            "add", "rule", "inet", &q, "output", "counter", "accept", "comment", MARKER,
        ],
    )?;
    fn injected(namespace: &str, table: &str) -> Result<(u64, serde_json::Value)> {
        let json = nft_json(namespace, &["list", "chain", "inet", table, "output"])?;
        let rows = json["nftables"].as_array().ok_or(Error::NetworkPolicy)?;
        let selected: Vec<_> = rows
            .iter()
            .filter_map(|r| r.get("rule"))
            .filter(|r| r["comment"] == MARKER && r["table"] == table && r["chain"] == "output")
            .collect();
        if selected.len() != 1 {
            return Err(Error::NetworkPolicy);
        }
        let handle = selected[0]["handle"]
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or(Error::NetworkPolicy)?;
        Ok((handle, selected[0]["expr"].clone()))
    }
    let (handle, _) = injected(dn, &q)?;
    traffic
        .continuous
        .checkpoint("functional_quarantine_drift_before_audit")?;
    forbidden_burst(app, "NFT_DRIFT_BEFORE_AUDIT");
    if g.audit().is_ok() {
        return Err(Error::NetworkPolicy);
    }
    g.lab_offline()?;
    traffic
        .continuous
        .checkpoint("functional_drift_verified_emergency_offline")?;
    forbidden_burst(app, "NFT_DRIFT_AFTER_AUDIT");
    // Guard refuses changed table; the TEST writer alone removes its exact
    // injected rule. The changed resource must remain present until then.
    if injected(dn, &q)?.0 != handle {
        return Err(Error::NetworkPolicy);
    }
    nft_in(
        dn,
        &[
            "delete",
            "rule",
            "inet",
            &q,
            "output",
            "handle",
            &handle.to_string(),
        ],
    )?;
    drain(server)?;
    g.lab_resume_bootstrap()?;
    traffic
        .continuous
        .checkpoint("functional_drift_exactly_repaired_bootstrap")?;
    drain(server)?;
    roundtrip(health, server, b"VR8A_AFTER_EXACT_DRIFT_REPAIR")?;
    lab::case(
        "functional_quarantine_drift_refused_independent_permit_filter_and_emergency_retained",
    );
    Ok(())
}
pub fn run(scenario: Scenario) -> Result<()> {
    admit(scenario == Scenario::Actual)?;
    lab::stage("transport_admitted_exact_hash_guest_host_namespace");
    let pid = std::process::id();
    let dir = PathBuf::from(format!(
        "{ROOT}/{}-{pid}",
        if scenario == Scenario::Actual {
            "task8b2"
        } else {
            "task8a"
        }
    ));
    private(&dir)?;
    let deployment = format!("transportlab{pid}");
    let record = allocation(&dir, &deployment)?;
    private(&record.exits[0].state_dir)?;
    if scenario == Scenario::Actual {
        for role in ["worker", "daemon"] {
            let path = record.exits[0].state_dir.join(role);
            private(&path)?;
            let fd = owned::directory(&path)?;
            rustix::fs::fchown(
                &fd,
                Some(rustix::process::Uid::from_raw(65534)),
                Some(rustix::process::Gid::from_raw(65534)),
            )
            .map_err(|_| Error::UnsafeInput)?;
        }
    }
    let records = dir.join("records");
    private(&records)?;
    let store =
        AllocationStore::open(&records, &deployment).map_err(|_| Error::OwnershipMismatch)?;
    store
        .lock()
        .map_err(|_| Error::LockBusy)?
        .commit(None, &record)
        .map_err(|_| Error::AllocationMismatch)?;
    let actual_image = if scenario == Scenario::Actual {
        Some(super::actual_lab::image()?)
    } else {
        None
    };
    let (id, digest, probe_size) = if let Some(image) = &actual_image {
        let label = format!("io.vprouter.deployment={deployment}");
        let id = String::from_utf8(lab::docker(&[
            "run",
            "--detach",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--device",
            "/dev/net/tun:/dev/net/tun:rwm",
            "--label",
            &label,
            "--label",
            "io.vprouter.role=gateway",
            image,
        ])?)
        .map_err(|_| Error::DockerUnavailable)?
        .trim()
        .to_owned();
        (id, String::new(), 0)
    } else {
        let probe = vprouter_linux::storage::read(
            Path::new(PROBE),
            vprouter_linux::storage::Kind::PublicFile,
            super::spec::LIMIT,
        )
        .map_err(|_| Error::UnsafeInput)?;
        let digest = vprouter_linux::sha256(&probe);
        let bind = format!("{PROBE}:{}:ro", super::spec::WORKER);
        let label = format!("io.vprouter.deployment={deployment}");
        let id = String::from_utf8(lab::docker(&[
            "run",
            "--detach",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--label",
            &label,
            "--label",
            "io.vprouter.role=gateway",
            "--volume",
            &bind,
            "--entrypoint",
            super::spec::WORKER,
            lab::IMAGE,
            "--test-probe-container",
        ])?)
        .map_err(|_| Error::DockerUnavailable)?
        .trim()
        .to_string();
        (id, digest, probe.len() as u64)
    };
    if !super::spec::digest(&id) {
        return Err(Error::DockerUnavailable);
    }
    let peer = format!("vr8p{pid}");
    let wan = format!("vr8w{pid}");
    let other = format!("vr8o{pid}");
    lab::write(&dir.join("resources.json"),&serde_json::to_vec(&serde_json::json!({"container":id,"wan_namespace":peer,"wan_host":wan,"records":records,"deployment":deployment,"allocation":record})).map_err(|_|Error::InvalidSpec)?)?;
    setup_wan(&peer, &wan, &other, &dir)?;
    let a: Admission = if let Some(image) = &actual_image {
        execution_lab::inspect_actual(&id, &record, image)?
    } else {
        execution_lab::inspect(&id, &record, 0, &digest, probe_size)?
    };
    let mut tx =
        owned::Transaction::open(&store, &records, &a.spec, "one", a.process.base_network())?;
    let namespaces = tx.acquire(&a.spec, a.process.base_network())?;
    let data_name = record.exits[0].data_namespace.clone();
    let transport_name = record.exits[0].transport_namespace.clone();
    // ip netns handles are independent TEST observation references to exact
    // durable owned nsfs pins. No namespace is recreated or adopted by name.
    command("touch", &[&format!("/run/netns/{data_name}")])?;
    command(
        "mount",
        &[
            "--bind",
            records
                .join(&data_name)
                .to_str()
                .ok_or(Error::UnsafeInput)?,
            &format!("/run/netns/{data_name}"),
        ],
    )?;
    // Transport has no process; bind the exact durable nsfs path for observers.
    command("touch", &[&format!("/run/netns/{transport_name}")])?;
    command(
        "mount",
        &[
            "--bind",
            records
                .join(&transport_name)
                .to_str()
                .ok_or(Error::UnsafeInput)?,
            &format!("/run/netns/{transport_name}"),
        ],
    )?;
    let pf = ns_file(&peer)?;
    let server = socket(&pf, "10.64.0.1:40444")?;
    let forward_before = forward_rules()?;
    let without_dns = Profile::parse(
        profile_source().replace("DNS=10.64.0.1\n", "").as_bytes(),
        "de-fra-wg-404",
        None,
    )
    .map_err(|_| Error::InvalidSpec)?;
    if !matches!(
        GuardTransport::activate(tx, namespaces, &a, &without_dns, &wan),
        Err(Error::ResolverUnavailable)
    ) {
        return Err(Error::NetworkPolicy);
    }
    let mut tx =
        owned::Transaction::open(&store, &records, &a.spec, "one", a.process.base_network())?;
    let namespaces = tx.acquire(&a.spec, a.process.base_network())?;
    lab::case(
        "missing_private_dns_refused_before_intent_and_native_changes_offline_reacquire_succeeds",
    );
    if scenario == Scenario::InterruptedActivation {
        GuardTransport::lab_interrupt_activation_commit();
    }
    lab::stage("native_guard_down_provision_then_quarantined_activation");
    let mut guard = GuardTransport::activate(tx, namespaces, &a, &profile()?, &wan)?;
    guard.audit()?;
    lab::case("durable_primary_base_native_transport_socket_birth_and_bootstrap");
    if scenario == Scenario::Actual {
        drop(server);
        drop(pf);
        super::actual_lab::run(&a, &mut guard, &dir, &data_name)?;
        // End the actual phase before the existing packet/fault suite. Its
        // generated state is retained; stopped/unenrolled evidence is separate
        // from later8c enabled/advertised real-client acceptance.
        return Ok(());
    }
    lab::stage("bootstrap_positive_capture_controls");
    let positive = [
        Capture::start(
            Some(&data_name),
            guard.lab_plan().wireguard_name(),
            dir.join("positive-data.pcap"),
        )?,
        Capture::start(
            Some(&transport_name),
            guard.lab_plan().transport_name(),
            dir.join("positive-transport.pcap"),
        )?,
        Capture::start(None, &wan, dir.join("positive-host.pcap"))?,
    ];
    let health = health_socket(&guard, 40100)?;
    lab::stage("bootstrap_cgroup_owned_health_roundtrip");
    roundtrip(&health, &server, b"VR8A_POSITIVE_DATA_HEALTH")?;
    let direct = socket(&guard.lab_namespaces().0.transport, "0.0.0.0:0")?;
    direct
        .send_to(
            b"VR8A_POSITIVE_PLAINTEXT_CAPTURE",
            format!("{ENDPOINT}:51820"),
        )
        .map_err(|_| Error::NetworkOperation)?;
    std::thread::sleep(Duration::from_millis(250));
    let [pd, pt, ph] = positive;
    if !has(&pd.finish()?, b"VR8A_POSITIVE_DATA_HEALTH")
        || !has(&pt.finish()?, b"VR8A_POSITIVE_PLAINTEXT_CAPTURE")
        || !has(&ph.finish()?, b"VR8A_POSITIVE_PLAINTEXT_CAPTURE")
    {
        return Err(Error::NetworkOperation);
    }
    lab::case("independent_data_transport_host_positive_capture_sensitivity");
    let negative = [
        Capture::start(Some(&data_name), "any", dir.join("negative-data.pcap"))?,
        Capture::start(
            Some(&transport_name),
            "any",
            dir.join("negative-transport.pcap"),
        )?,
        Capture::start(None, &wan, dir.join("negative-host.pcap"))?,
    ];
    let application = socket(&guard.lab_namespaces().0.data, "10.64.0.2:40101")?;
    for n in 0..12 {
        match application.send_to(
            format!("VR8A_FORBIDDEN_APPLICATION_{n}").as_bytes(),
            "10.64.0.1:40444",
        ) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(_) => return Err(Error::NetworkOperation),
        }
        roundtrip(
            &health,
            &server,
            format!("VR8A_AUTHORIZED_HEALTH_{n}").as_bytes(),
        )?;
    }
    lab::case("same_namespace_destination_port_other_socket_producer_denied");
    // Preserve an established conntrack tuple, replacing its formerly admitted
    // socket with an unowned producer before the peer sends the next datagram.
    let warm = health_socket(&guard, 40102)?;
    roundtrip(&warm, &server, b"VR8A_WARM_ESTABLISHED_TUPLE")?;
    drop(warm);
    let stale = socket(&guard.lab_namespaces().0.data, "10.64.0.2:40102")?;
    server
        .send_to(b"VR8A_STALE_ESTABLISHED_INPUT", "10.64.0.2:40102")
        .map_err(|_| Error::NetworkOperation)?;
    let mut b = [0u8; 2048];
    if stale.recv_from(&mut b).is_ok() {
        return Err(Error::NetworkPolicy);
    }
    roundtrip(&health, &server, b"VR8A_HEALTH_AFTER_STALE_INPUT")?;
    lab::case("established_input_other_producer_denied");
    let continuous = Continuous::start(&application, &dir)?;
    let traffic = FaultTraffic {
        app: &application,
        health: &health,
        server: &server,
        continuous: &continuous,
    };
    if scenario == Scenario::Reversible {
        fault_matrix(&mut guard, &data_name, &transport_name, &dir, &traffic)?;
        nft_faults(&mut guard, &data_name, &dir, &traffic)?;
    } else {
        match scenario {
            Scenario::DeletedWg | Scenario::ForeignCollision => {
                let name = guard.lab_plan().wireguard_name();
                ip(&["-n", &data_name, "link", "del", name])?;
                if scenario == Scenario::ForeignCollision {
                    ip(&["-n", &data_name, "link", "add", name, "type", "dummy"])?;
                }
            }
            Scenario::DeletedTransport => {
                ip(&[
                    "-n",
                    &transport_name,
                    "link",
                    "del",
                    guard.lab_plan().transport_name(),
                ])?;
            }
            Scenario::CooperationDrift => {
                let new: Vec<_> = forward_rules()?
                    .into_iter()
                    .filter(|r| {
                        !forward_before
                            .iter()
                            .any(|old| old["handle"] == r["handle"])
                    })
                    .collect();
                if new.len() != 2 {
                    return Err(Error::NetworkPolicy);
                }
                let selected = &new[0];
                let handle = selected["handle"]
                    .as_u64()
                    .filter(|h| *h > 0)
                    .ok_or(Error::NetworkPolicy)?;
                // Full expression/handle identity is rechecked immediately before
                // deleting the exact rule created by this guard invocation.
                if !forward_rules()?.contains(selected) {
                    return Err(Error::NetworkPolicy);
                }
                lab::write(
                    &dir.join("cooperation-injected-removal.json"),
                    &serde_json::to_vec(selected).map_err(|_| Error::InvalidSpec)?,
                )?;
                command(
                    "nft",
                    &[
                        "delete",
                        "rule",
                        "ip",
                        "filter",
                        "FORWARD",
                        "handle",
                        &handle.to_string(),
                    ],
                )?;
            }
            Scenario::InterruptedActivation | Scenario::InterruptedCleanup => {}
            Scenario::Reversible | Scenario::Actual => unreachable!(),
        }
        continuous.checkpoint("terminal_fault_before_audit")?;
        forbidden_burst(&application, "TERMINAL_BEFORE_AUDIT");
        if matches!(
            scenario,
            Scenario::InterruptedActivation | Scenario::InterruptedCleanup
        ) {
            // A stopped activation/cleanup guard must first leave full quarantine.
            guard.lab_begin_offline()?;
        } else if guard.audit().is_ok() {
            return Err(Error::NetworkPolicy);
        }
        guard.lab_offline()?;
        continuous.checkpoint("terminal_fault_verified_full_offline")?;
        forbidden_burst(&application, "TERMINAL_AFTER_AUDIT");
        drain(&server)?;
        lab::case("terminal_fault_full_quarantine_actual_packet_witness");
    }
    continuous.finish()?;
    std::thread::sleep(Duration::from_millis(200));
    let [nd, nt, nh] = negative;
    let data = nd.finish()?;
    let transport = nt.finish()?;
    let host = nh.finish()?;
    if has(&data, b"VR8A_FORBIDDEN_")
        || has(&transport, b"VR8A_FORBIDDEN_")
        || has(&host, b"VR8A_FORBIDDEN_")
        || has(&transport, b"VR8A_AUTHORIZED_HEALTH_")
        || has(&host, b"VR8A_AUTHORIZED_HEALTH_")
        || !has(&data, b"VR8A_AUTHORIZED_HEALTH_")
    {
        return Err(Error::NetworkPolicy);
    }
    lab::case("encrypted_roundtrip_plaintext_negatives_and_actual_docker_forward_drop_cooperation");
    if scenario == Scenario::Reversible {
        guard.audit()?;
    }
    drop(application);
    drop(stale);
    drop(health);
    drop(direct);
    drop(server);
    if scenario == Scenario::Reversible {
        guard.cleanup()?;
        lab::case("native_owned_link_cooperation_and_empty_subgroup_cleanup_quarantine_retained");
    } else {
        if matches!(
            scenario,
            Scenario::InterruptedActivation | Scenario::InterruptedCleanup
        ) {
            guard.lab_interrupt_cleanup()?;
        } else if guard.cleanup().is_ok() {
            return Err(Error::OwnershipMismatch);
        }
        let mut reopened =
            owned::Transaction::open(&store, &records, &a.spec, "one", a.process.base_network())?;
        if !matches!(
            reopened.acquire(&a.spec, a.process.base_network()),
            Err(Error::Interrupted)
        ) {
            return Err(Error::OwnershipMismatch);
        }
        lab::case("terminal_cleanup_or_interruption_retains_intent_and_restart_refuses_adoption");
    }
    // The exact owned WAN and observation pins remain recorded until controller
    // inspection; retained full quarantine is an explicit successful end state.
    lab::write(&dir.join("result.json"),b"{\"result\":\"pass_partial_transport_smoke\",\"production_readiness\":false,\"quarantine_retained\":true,\"real_client_acceptance\":\"NOT_RUN\"}\n")?;
    println!(
        "{{\"case\":\"transport_lab\",\"result\":\"pass_partial_transport_smoke\",\"production_readiness\":false,\"quarantine_retained\":true}}"
    );
    Ok(())
}

pub(super) fn actual_metadata(namespace: &str, dir: &Path) -> Result<()> {
    let mut records = serde_json::Map::new();
    for (name, args) in [
        ("links", vec!["-j", "-d", "link", "show"]),
        ("addresses", vec!["-j", "address", "show"]),
        ("routes4", vec!["-j", "-4", "route", "show", "table", "all"]),
        ("routes6", vec!["-j", "-6", "route", "show", "table", "all"]),
        ("rules4", vec!["-j", "-4", "rule", "show"]),
        ("rules6", vec!["-j", "-6", "rule", "show"]),
    ] {
        let mut argv = vec!["netns", "exec", namespace, "ip"];
        argv.extend(args);
        let data = command("ip", &argv)?;
        records.insert(
            name.into(),
            serde_json::from_slice(&data).map_err(|_| Error::NetworkOperation)?,
        );
    }
    records.insert("nft".into(), nft_json(namespace, &["list", "ruleset"])?);
    lab::write(
        &dir.join("actual-daemon-kernel.json"),
        &serde_json::to_vec(&records).map_err(|_| Error::InvalidSpec)?,
    )
}
pub(super) fn actual_packet_controls(
    g: &mut GuardTransport<'_>,
    dir: &Path,
    data_name: &str,
    transport_name: &str,
) -> Result<()> {
    let pid = std::process::id();
    let peer = format!("vr8p{pid}");
    let wan = format!("vr8w{pid}");
    let peer_fd = ns_file(&peer)?;
    let server = socket(&peer_fd, "10.64.0.1:40444")?;
    let health = health_socket(g, 40100)?;
    let app = socket(&g.lab_namespaces().0.data, "10.64.0.2:40101")?;
    let positive = [
        Capture::start(
            Some(data_name),
            g.lab_plan().wireguard_name(),
            dir.join("actual-positive-data.pcap"),
        )?,
        Capture::start(
            Some(transport_name),
            g.lab_plan().transport_name(),
            dir.join("actual-positive-transport.pcap"),
        )?,
        Capture::start(None, &wan, dir.join("actual-positive-host.pcap"))?,
    ];
    roundtrip(&health, &server, b"VR8B2_POSITIVE_PRODUCER")?;
    let direct = socket(&g.lab_namespaces().0.transport, "0.0.0.0:0")?;
    direct
        .send_to(
            b"VR8B2_POSITIVE_PLAINTEXT_CAPTURE",
            format!("{ENDPOINT}:51820"),
        )
        .map_err(|_| Error::NetworkOperation)?;
    std::thread::sleep(Duration::from_millis(150));
    let [pd, pt, ph] = positive;
    if !has(&pd.finish()?, b"VR8B2_POSITIVE_PRODUCER")
        || !has(&pt.finish()?, b"VR8B2_POSITIVE_PLAINTEXT_CAPTURE")
        || !has(&ph.finish()?, b"VR8B2_POSITIVE_PLAINTEXT_CAPTURE")
    {
        return Err(Error::NetworkOperation);
    }
    let negative = [
        Capture::start(
            Some(data_name),
            "any",
            dir.join("actual-negative-data.pcap"),
        )?,
        Capture::start(
            Some(transport_name),
            "any",
            dir.join("actual-negative-transport.pcap"),
        )?,
        Capture::start(None, &wan, dir.join("actual-negative-host.pcap"))?,
    ];
    let mut denied = 0u32;
    let mut queued = 0u32;
    for _ in 0..16 {
        match app.send_to(b"VR8B2_FORBIDDEN_UNAUTHORIZED", "10.64.0.1:40444") {
            Ok(_) => queued += 1,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => denied += 1,
            Err(_) => return Err(Error::NetworkOperation),
        }
        roundtrip(&health, &server, b"VR8B2_AUTHORIZED_DURING_DENIAL")?;
    }
    // A successful local send does not prove remote delivery. Independently
    // inspect the synthetic peer and all three capture planes, with positive
    // controls above and zero capture drops required by Capture::finish.
    server
        .set_nonblocking(true)
        .map_err(|_| Error::NetworkOperation)?;
    let mut received = 0;
    let mut bytes = [0; 2048];
    while let Ok((size, _)) = server.recv_from(&mut bytes) {
        if has(&bytes[..size], b"VR8B2_FORBIDDEN_") {
            received += 1;
        }
    }
    std::thread::sleep(Duration::from_millis(150));
    for capture in negative {
        if has(&capture.finish()?, b"VR8B2_FORBIDDEN_") {
            return Err(Error::NetworkPolicy);
        }
    }
    if received != 0 || denied + queued != 16 {
        return Err(Error::NetworkPolicy);
    }
    lab::write(
        &dir.join("actual-packet-accounting.json"),
        &serde_json::to_vec(&serde_json::json!({
            "unauthorized_send_attempts":16,"kernel_permission_denials":denied,
            "locally_queued_sends":queued,"unauthorized_peer_receives":received,
            "authorized_roundtrips_during_denial":16,"capture_planes":["data","transport","host"],
            "positive_controls":true,"capture_kernel_drops":0,"readiness":false
        }))
        .map_err(|_| Error::InvalidSpec)?,
    )?;
    g.audit()?;
    lab::case(
        "actual_fixture_three_plane_positive_controls_capture_accounting_and_same_namespace_unauthorized_denial",
    );
    Ok(())
}
