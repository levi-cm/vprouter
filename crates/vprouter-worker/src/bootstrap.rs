//! One-shot observation handoff. Wire values are data, never placement/readiness
//! authority. No constructor for the monitor's private Placed token is exposed.
#![forbid(unsafe_code)]
use crate::{Error, Result};
use rustix::fs::{self, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    marker::PhantomData,
    net::Ipv4Addr,
    os::{fd::AsFd, unix::net::UnixStream},
    rc::Rc,
    time::Duration,
};
use vprouter_core::allocation::{AllocationRecord, ExitAllocation};
use vprouter_network::{MonitoringPlan, NativeNetwork, Plan};

pub const CONFIG: &str = "/run/vprouter/bootstrap.json";
pub const SOCKET: &str = "/run/vprouter/bootstrap.sock";
pub const LIMIT: usize = 65536;
pub const WORKER_UID: u32 = 65534;
pub const MAX_PROGRAM: u64 = 64 * 1024 * 1024;
/// Fixed protocol data, deliberately no Debug and no secret profile/key field.
/// An arbitrary instance does not construct a Placed/guard/ready capability.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub schema: u32,
    pub allocation: AllocationRecord,
    pub exit: ExitAllocation,
    pub container_id: String,
    pub namespace: Object,
    pub cgroup: String,
    pub program_sha256: String,
    pub manifest_sha256: String,
    pub socket: Object,
    pub nonce: String,
    pub resolver: Ipv4Addr,
    pub execution_policy: String,
    pub monitoring: MonitoringPlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_binding: Option<vprouter_core::health::Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<crate::operation::Enrollment>,
}
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub dev: u64,
    pub ino: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub config_sha256: String,
    pub nonce: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub schema: u32,
    pub config_sha256: String,
    pub nonce: String,
    pub permission: Permission,
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ObserveOnce,
    Monitor,
    Operational,
}
pub fn digest(bytes: &[u8]) -> String {
    digest_hex(&Sha256::digest(bytes))
}
fn digest_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
impl Configuration {
    pub fn validate(&self) -> Result<()> {
        self.allocation
            .validate(&self.allocation.deployment_id, &[])
            .map_err(|_| Error::Bootstrap)?;
        if self.schema != 1
            || !self.allocation.exits.contains(&self.exit)
            || !hash(&self.container_id)
            || !hash(&self.program_sha256)
            || !hash(&self.manifest_sha256)
            || !hash(&self.nonce)
            || self.namespace.ino == 0
            || self.socket.ino == 0
            || !self.resolver.is_private()
            || self.cgroup.len() > 512
            || !self.cgroup.starts_with("0::/")
            || !self.cgroup.ends_with('\n')
            || self.cgroup[..self.cgroup.len() - 1]
                .chars()
                .any(char::is_control)
            || self.cgroup.split('/').any(|p| p == "." || p == "..")
        {
            return Err(Error::Bootstrap);
        }
        if let Some(binding) = &self.health_binding {
            binding.validate().map_err(|_| Error::Bootstrap)?;
            if binding.deployment_id != self.allocation.deployment_id
                || binding.generation != self.allocation.generation
                || binding.exit_id != self.exit.exit_id
                || binding.mode != self.exit.mode
            {
                return Err(Error::Bootstrap);
            }
        }
        let expected_policy = if self.enrollment.is_some() {
            "operational-monitor-ipv4-tcp-udp-unix-zero-caps-v1"
        } else if self.health_binding.is_some() {
            "starting-monitor-unix-netlink-zero-caps-v1"
        } else {
            "observer-unix-netlink-zero-caps-v1"
        };
        if self.execution_policy != expected_policy {
            return Err(Error::Bootstrap);
        }
        if let Some(enrollment) = &self.enrollment {
            enrollment.validate(self.health_binding.as_ref().ok_or(Error::Bootstrap)?)?;
        }
        Plan::from_monitoring(&self.allocation, &self.exit, self.monitoring.clone())
            .map_err(|_| Error::Bootstrap)?;
        Ok(())
    }
}
fn object(fd: impl AsFd) -> Result<Object> {
    let s = fs::fstat(fd).map_err(|_| Error::Bootstrap)?;
    Ok(Object {
        dev: s.st_dev,
        ino: s.st_ino,
    })
}
fn read(fd: impl AsFd, max: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::from(
        fd.as_fd()
            .try_clone_to_owned()
            .map_err(|_| Error::Bootstrap)?,
    )
    .take(max + 1)
    .read_to_end(&mut bytes)
    .map_err(|_| Error::Bootstrap)?;
    if bytes.len() as u64 > max {
        return Err(Error::Bootstrap);
    }
    Ok(bytes)
}
fn protected_configuration() -> Result<(Configuration, String)> {
    // The fixed private mount tree is supplied by the reviewed executor. No path
    // override, env lookup or host resolver. Every ancestor is root-owned and
    // non-writable; the selected file must also be on a read-only mount.
    let mut directory = fs::openat(
        fs::CWD,
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Bootstrap)?;
    for name in ["run", "vprouter"] {
        let s = fs::fstat(&directory).map_err(|_| Error::Bootstrap)?;
        if s.st_uid != 0 || s.st_gid != 0 || s.st_mode & 0o022 != 0 {
            return Err(Error::Bootstrap);
        }
        directory = fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::Bootstrap)?;
    }
    let s = fs::fstat(&directory).map_err(|_| Error::Bootstrap)?;
    if s.st_uid != 0 || s.st_gid != 0 || s.st_mode & 0o022 != 0 {
        return Err(Error::Bootstrap);
    }
    let fd = fs::openat(
        &directory,
        "bootstrap.json",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Bootstrap)?;
    let before = fs::fstat(&fd).map_err(|_| Error::Bootstrap)?;
    if before.st_uid != 0
        || before.st_gid != 0
        || before.st_mode & 0o7777 != 0o444
        || before.st_nlink != 1
        || FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_size <= 0
        || before.st_size as u64 > LIMIT as u64
        || !fs::fstatvfs(&fd)
            .map_err(|_| Error::Bootstrap)?
            .f_flag
            .contains(fs::StatVfsMountFlags::RDONLY)
    {
        return Err(Error::Bootstrap);
    }
    let bytes = read(&fd, LIMIT as u64)?;
    let after = fs::fstat(&fd).map_err(|_| Error::Bootstrap)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mtime != after.st_mtime
        || before.st_mtime_nsec != after.st_mtime_nsec
        || before.st_ctime != after.st_ctime
        || before.st_ctime_nsec != after.st_ctime_nsec
    {
        return Err(Error::Bootstrap);
    }
    let config: Configuration = crate::json::decode(&bytes)?;
    config.validate()?;
    let socket = fs::statat(&directory, "bootstrap.sock", fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| Error::Bootstrap)?;
    if FileType::from_raw_mode(socket.st_mode) != FileType::Socket
        || socket.st_uid != 0
        || socket.st_gid != 0
        || (Object {
            dev: socket.st_dev,
            ino: socket.st_ino,
        }) != config.socket
    {
        return Err(Error::Bootstrap);
    }
    Ok((config, digest(&bytes)))
}
fn current_namespace() -> Result<Object> {
    let fd = fs::openat(
        fs::CWD,
        "/proc/thread-self/ns/net",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Bootstrap)?;
    if fs::fstatfs(&fd).map_err(|_| Error::Bootstrap)?.f_type as u64 != 0x6e736673 {
        return Err(Error::Bootstrap);
    }
    object(fd)
}
fn current_cgroup() -> Result<String> {
    let fd = fs::openat(
        fs::CWD,
        "/proc/self/cgroup",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Bootstrap)?;
    String::from_utf8(read(fd, 4096)?).map_err(|_| Error::Bootstrap)
}
fn credentials() -> Result<()> {
    let fd = fs::openat(
        fs::CWD,
        "/proc/self/status",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Bootstrap)?;
    let text = String::from_utf8(read(fd, 65536)?).map_err(|_| Error::Bootstrap)?;
    for (key, value) in [
        ("Uid:", "65534 65534 65534 65534"),
        ("Gid:", "65534 65534 65534 65534"),
        ("Groups:", ""),
        ("NoNewPrivs:", "1"),
        ("CapInh:", "0000000000000000"),
        ("CapPrm:", "0000000000000000"),
        ("CapEff:", "0000000000000000"),
        ("CapBnd:", "0000000000000000"),
        ("CapAmb:", "0000000000000000"),
    ] {
        let values: Vec<_> = text.lines().filter_map(|l| l.strip_prefix(key)).collect();
        if values.len() != 1
            || values[0].split_whitespace().collect::<Vec<_>>()
                != value.split_whitespace().collect::<Vec<_>>()
        {
            return Err(Error::Bootstrap);
        }
    }
    Ok(())
}
fn descriptor_inventory() -> Result<()> {
    use std::os::fd::AsRawFd;
    let directory = fs::openat(
        fs::CWD,
        "/proc/self/fd",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Bootstrap)?;
    let scan = directory.as_raw_fd();
    let mut seen = Vec::new();
    for entry in fs::Dir::new(directory).map_err(|_| Error::Bootstrap)? {
        let entry = entry.map_err(|_| Error::Bootstrap)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let n = std::str::from_utf8(name)
            .ok()
            .and_then(|n| n.parse::<i32>().ok())
            .ok_or(Error::Bootstrap)?;
        if n == scan {
            continue;
        }
        if !(0..=2).contains(&n) {
            return Err(Error::Bootstrap);
        }
        let s = fs::statat(fs::CWD, format!("/proc/self/fd/{n}"), fs::AtFlags::empty())
            .map_err(|_| Error::Bootstrap)?;
        if FileType::from_raw_mode(s.st_mode) != FileType::CharacterDevice
            || fs::major(s.st_rdev) != 1
            || fs::minor(s.st_rdev) != 3
        {
            return Err(Error::Bootstrap);
        }
        seen.push(n);
    }
    seen.sort_unstable();
    if seen != [0, 1, 2] {
        return Err(Error::Bootstrap);
    }
    Ok(())
}
fn environment() -> Result<()> {
    let mut entries: Vec<_> = std::env::vars_os().collect();
    entries.sort();
    let mut expected = vec![
        (
            std::ffi::OsString::from("LANG"),
            std::ffi::OsString::from("C"),
        ),
        (
            std::ffi::OsString::from("PATH"),
            std::ffi::OsString::from("/bin"),
        ),
    ];
    expected.sort();
    if entries != expected {
        return Err(Error::Bootstrap);
    }
    Ok(())
}
fn program() -> Result<String> {
    let fd = fs::openat(
        fs::CWD,
        "/proc/self/exe",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::Bootstrap)?;
    let s = fs::fstat(&fd).map_err(|_| Error::Bootstrap)?;
    if s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o022 != 0
        || FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
    {
        return Err(Error::Bootstrap);
    }
    Ok(digest(&read(fd, MAX_PROGRAM)?))
}
/// Length framed, bounded protocol. One absolute two-second deadline spans
/// prefix AND body; a trickling peer cannot renew a per-read timeout indefinitely.
pub fn write_message<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    write_message_before(
        stream,
        value,
        std::time::Instant::now() + Duration::from_secs(2),
    )
}
pub fn write_message_before<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    end: std::time::Instant,
) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Bootstrap)?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(Error::Bootstrap);
    }
    let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
    framed.extend(bytes);
    nonblocking(stream)?;
    let mut offset = 0;
    while offset < framed.len() {
        if std::time::Instant::now() >= end {
            return Err(Error::Bootstrap);
        }
        match stream.write(&framed[offset..]) {
            Ok(0) => return Err(Error::Bootstrap),
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait(stream, end, rustix::event::PollFlags::OUT)?
            }
            Err(_) => return Err(Error::Bootstrap),
        }
    }
    if std::time::Instant::now() >= end {
        return Err(Error::Bootstrap);
    }
    Ok(())
}
pub(crate) fn nonblocking(stream: &UnixStream) -> Result<()> {
    // Use the already admitted fcntl operations rather than std's Linux
    // FIONBIO ioctl. Preserve every existing status flag on framing streams.
    let flags = fs::fcntl_getfl(stream).map_err(|_| Error::Bootstrap)?;
    fs::fcntl_setfl(stream, flags | OFlags::NONBLOCK).map_err(|_| Error::Bootstrap)
}
fn wait(
    stream: &UnixStream,
    end: std::time::Instant,
    flags: rustix::event::PollFlags,
) -> Result<()> {
    let left = end.saturating_duration_since(std::time::Instant::now());
    if left.is_zero() {
        return Err(Error::Bootstrap);
    }
    let mut p = [rustix::event::PollFd::new(stream, flags)];
    if rustix::event::poll(
        &mut p,
        Some(&rustix::event::Timespec::try_from(left).map_err(|_| Error::Bootstrap)?),
    )
    .map_err(|_| Error::Bootstrap)?
        == 0
    {
        return Err(Error::Bootstrap);
    }
    if p[0]
        .revents()
        .intersects(rustix::event::PollFlags::ERR | rustix::event::PollFlags::NVAL)
    {
        return Err(Error::Bootstrap);
    }
    if std::time::Instant::now() >= end {
        return Err(Error::Bootstrap);
    }
    Ok(())
}
fn read_before(stream: &mut UnixStream, bytes: &mut [u8], end: std::time::Instant) -> Result<()> {
    nonblocking(stream)?;
    let mut offset = 0;
    while offset < bytes.len() {
        if std::time::Instant::now() >= end {
            return Err(Error::Bootstrap);
        }
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(Error::Bootstrap),
            Ok(n) => offset += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                wait(stream, end, rustix::event::PollFlags::IN)?
            }
            Err(_) => return Err(Error::Bootstrap),
        }
    }
    if std::time::Instant::now() >= end {
        return Err(Error::Bootstrap);
    }
    Ok(())
}
pub fn read_message<T: serde::de::DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    read_message_before(stream, std::time::Instant::now() + Duration::from_secs(2))
}
pub fn read_message_before<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    end: std::time::Instant,
) -> Result<T> {
    let mut size = [0; 4];
    read_before(stream, &mut size, end)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > 4096 {
        return Err(Error::Bootstrap);
    }
    let mut bytes = vec![0; size];
    read_before(stream, &mut bytes, end)?;
    let value = crate::json::decode(&bytes)?;
    if std::time::Instant::now() >= end {
        return Err(Error::Bootstrap);
    }
    Ok(value)
}
struct Observation {
    config: Configuration,
    _thread: PhantomData<Rc<()>>,
}
impl Observation {
    fn check(&self) -> Result<()> {
        if current_namespace()? != self.config.namespace || current_cgroup()? != self.config.cgroup
        {
            return Err(Error::Bootstrap);
        }
        Ok(())
    }
}
fn connect_before(path: &std::path::Path, end: std::time::Instant) -> Result<UnixStream> {
    use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    if std::time::Instant::now() >= end {
        return Err(Error::Bootstrap);
    }
    let address = SocketAddrUnix::new(path).map_err(|_| Error::Bootstrap)?;
    let stream = UnixStream::from(
        net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| Error::Bootstrap)?,
    );
    match net::connect(&stream, &address) {
        Ok(()) => (),
        Err(rustix::io::Errno::INPROGRESS) => {
            wait(&stream, end, rustix::event::PollFlags::OUT)?;
            net::sockopt::socket_error(&stream)
                .map_err(|_| Error::Bootstrap)?
                .map_err(|_| Error::Bootstrap)?;
        }
        // Linux AF_UNIX uses EAGAIN for a full listener backlog. It does not
        // mean connection-in-progress; refuse rather than block/retry it.
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::CONNREFUSED) => {
            return Err(Error::Bootstrap);
        }
        Err(_) => return Err(Error::Bootstrap),
    }
    if std::time::Instant::now() >= end || stream.peer_addr().is_err() {
        return Err(Error::Bootstrap);
    }
    Ok(stream)
}
fn response_binding(response: &Response, hash: &str, nonce: &str) -> Result<()> {
    response_permission(response, hash, nonce, Permission::ObserveOnce)
}
fn response_permission(
    response: &Response,
    hash: &str,
    nonce: &str,
    expected: Permission,
) -> Result<()> {
    if response.schema != 1
        || response.config_sha256 != hash
        || response.nonce != nonce
        || response.permission != expected
    {
        return Err(Error::Bootstrap);
    }
    Ok(())
}
fn root_peer(peer: &nix::sys::socket::UnixCredentials) -> Result<()> {
    if peer.uid() != 0 || peer.gid() != 0 {
        return Err(Error::Bootstrap);
    }
    Ok(())
}
fn admit() -> Result<Observation> {
    let (admitted, _) = admit_permission(Permission::ObserveOnce)?;
    Ok(admitted)
}
fn admit_permission(permission: Permission) -> Result<(Observation, UnixStream)> {
    let (config, hash) = protected_configuration()?;
    let permission = if permission == Permission::Monitor && config.enrollment.is_some() {
        Permission::Operational
    } else {
        permission
    };
    if (permission != Permission::ObserveOnce) != config.health_binding.is_some()
        || (permission == Permission::Operational) != config.enrollment.is_some()
    {
        return Err(Error::Bootstrap);
    }
    credentials()?;
    environment()?;
    if current_namespace()? != config.namespace
        || current_cgroup()? != config.cgroup
        || program()? != config.program_sha256
    {
        return Err(Error::Bootstrap);
    }
    descriptor_inventory()?;
    // This is the FIRST socket construction, after all placement/config checks.
    // Host-side retained authority independently verifies actual peer host PID,
    // starttime/pidfd/cgroup/netns/executable before returning ObserveOnce.
    let end = std::time::Instant::now() + Duration::from_secs(2);
    let mut stream = connect_before(std::path::Path::new(SOCKET), end)?;
    // A host-side guard can legitimately translate to PID0 here. rustix1.1.4's
    // UCred uses NonZeroI32 for pid, so that representation is invalid across
    // this private PID boundary. Pinned nix keeps libc's raw integer layout.
    let peer = nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|_| Error::Bootstrap)?;
    // PID may translate to zero in a private PID namespace. UID/GID root are
    // necessary here, not sufficient: the fixed protected socket+nonce+digest
    // and the independently checked current client bind the one-shot exchange.
    root_peer(&peer)?;
    write_message_before(
        &mut stream,
        &Request {
            schema: 1,
            config_sha256: hash.clone(),
            nonce: config.nonce.clone(),
        },
        end,
    )?;
    let response: Response = read_message_before(&mut stream, end)?;
    response_permission(&response, &hash, &config.nonce, permission)?;
    let result = Observation {
        config,
        _thread: PhantomData,
    };
    result.check()?;
    Ok((result, stream))
}

pub(crate) struct MonitorAdmission {
    observation: Observation,
    pub(crate) stream: UnixStream,
}
impl MonitorAdmission {
    pub(crate) fn check(&self) -> Result<()> {
        self.observation.check()
    }
    pub(crate) fn config(&self) -> &Configuration {
        &self.observation.config
    }
    pub(crate) fn namespace(&self) -> Result<(u64, u64)> {
        self.check()?;
        let ns = self.observation.config.namespace;
        Ok((ns.dev, ns.ino))
    }
}
pub(crate) fn admit_monitor() -> Result<MonitorAdmission> {
    let (observation, stream) = admit_permission(Permission::Monitor)?;
    Ok(MonitorAdmission {
        observation,
        stream,
    })
}
/// Fixed observation executable only. Native sockets are born after admission.
/// No provider query, LocalAPI writes, Placed token, Engine or readiness exists.
pub fn observe() -> Result<()> {
    let admitted = admit()?;
    let plan = Plan::from_monitoring(
        &admitted.config.allocation,
        &admitted.config.exit,
        admitted.config.monitoring.clone(),
    )
    .map_err(|_| Error::Bootstrap)?;
    admitted.check()?;
    let mut native = NativeNetwork::open(plan).map_err(|_| Error::Structural)?;
    admitted.check()?;
    let snapshot = native.observe_metadata().map_err(|_| Error::Structural)?;
    admitted.check()?;
    // Observation permission cannot write preferences, advertise, enroll or
    // create a Placed token. The only LocalAPI operations are fixed GETs.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| Error::Bootstrap)?;
    runtime.block_on(async {
        tokio::time::timeout(crate::client::LOCAL, async {
            admitted.check()?;
            let socket = tokio::net::UnixStream::connect("/run/tailscale/tailscaled.sock")
                .await
                .map_err(|_| Error::Transport)?;
            let mut http = crate::client::Http::connect(socket).await?;
            let status = http
                .request(
                    "GET",
                    "/localapi/v0/status?peers=false",
                    "local-tailscaled.sock",
                    b"",
                    65536,
                )
                .await?;
            let prefs = http
                .request(
                    "GET",
                    "/localapi/v0/prefs",
                    "local-tailscaled.sock",
                    b"",
                    65536,
                )
                .await?;
            crate::localapi::require_unenrolled(&status.body, &prefs.body)?;
            admitted.check()
        })
        .await
        .map_err(|_| Error::Deadline)?
    })?;
    drop(runtime);
    admitted.check()?;
    // A completed observation record is evidence only. It contains counts and
    // public placement binding; no daemon state, credential or LocalAPI body.
    let bytes=serde_json::to_vec(&serde_json::json!({"schema":1,"observation_only":true,"readiness":false,"configuration_sha256":digest(&serde_json::to_vec(&admitted.config).map_err(|_|Error::Bootstrap)?),"namespace":admitted.config.namespace,"links":snapshot.links.len(),"addresses":snapshot.addresses.len(),"routes":snapshot.routes.len(),"rules":snapshot.rules.len(),"actual_localapi_unenrolled":true})).map_err(|_|Error::Bootstrap)?;
    let file = fs::openat(
        fs::CWD,
        "/state/observation.json",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| Error::Bootstrap)?;
    File::from(file)
        .write_all(&bytes)
        .map_err(|_| Error::Bootstrap)?;
    admitted.check()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn assert_old_digest_equivalent(input: &[u8]) {
        let old: String = Sha256::digest(input)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest(input), old, "input length {}", input.len());
    }

    #[test]
    fn digest_matches_known_sha256_vectors() {
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn digest_matches_old_formatter_for_public_inputs_and_binary_boundaries() {
        for byte in 0..=255u8 {
            assert_old_digest_equivalent(&[byte]);
        }
        for length in [
            0usize, 1, 2, 3, 15, 31, 32, 33, 55, 56, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511,
            512, 513, 1023, 1024, 4095, 4096, 8192, 65535, 65536,
        ] {
            let input: Vec<_> = (0..length)
                .map(|i| (i.wrapping_mul(37) ^ (i >> 3) ^ 0xa5) as u8)
                .collect();
            assert_old_digest_equivalent(&input);
        }
        for repeats in [1, 2, 16, 256] {
            let input: Vec<_> = (0..repeats).flat_map(|_| 0..=255u8).collect();
            assert_old_digest_equivalent(&input);
        }
        for text in [
            "",
            "abc",
            "é",
            "e\u{301}",
            "💾",
            "\0",
            "\n\r\t\"\\\0é",
            "vprouter-v2-deployment-owner-v1:hexlab-public",
        ] {
            assert_old_digest_equivalent(text.as_bytes());
        }
        assert_old_digest_equivalent("💾".repeat(16384).as_bytes());
        let exit = |id: &str, mode, wireguard_interface| ExitAllocation {
            exit_id: id.into(),
            mode,
            state_dir: format!("/synthetic/hexlab/{id}").into(),
            data_namespace: format!("vr-data-{id}"),
            transport_namespace: format!("vr-trans-{id}"),
            nft_table: format!("vr_{id}"),
            host_interface: format!("vh{id}"),
            data_interface: format!("vd{id}"),
            wireguard_interface,
            transport_subnet: "10.202.1.0/30".into(),
        };
        let public = AllocationRecord {
            schema_version: 2,
            deployment_id: "hexlab-public".into(),
            generation: 7,
            exits: vec![
                exit(
                    "one",
                    vprouter_core::config::ExitMode::Mullvad,
                    Some("wgone".into()),
                ),
                exit("two", vprouter_core::config::ExitMode::Direct, None),
            ],
        };
        assert_old_digest_equivalent(&serde_json::to_vec(&public).unwrap());
    }

    #[test]
    fn digest_hex_preserves_every_byte_case_leading_zero_and_order() {
        let ordered: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            digest_hex(&ordered),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        let check = |bytes: &[u8; 32]| {
            let old: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(digest_hex(bytes), old);
        };
        for byte in 0..=255u8 {
            for position in 0..32 {
                let mut bytes = [0; 32];
                bytes[position] = byte;
                check(&bytes);
            }
        }
        for seed in 0..=255u8 {
            check(&std::array::from_fn(|i| {
                seed.wrapping_mul(17)
                    .wrapping_add((i as u8).wrapping_mul(13))
            }));
        }
        check(&[0; 32]);
        check(&[255; 32]);
    }

    #[test]
    fn decoding_cannot_complete_a_frame_after_its_absolute_deadline() {
        struct Slow;
        impl<'de> serde::Deserialize<'de> for Slow {
            fn deserialize<D: serde::Deserializer<'de>>(
                d: D,
            ) -> std::result::Result<Self, D::Error> {
                let _ = serde_json::Value::deserialize(d)?;
                std::thread::sleep(Duration::from_millis(50));
                Ok(Slow)
            }
        }
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        write_message(&mut writer, &serde_json::json!({})).unwrap();
        let end = std::time::Instant::now() + Duration::from_millis(30);
        assert!(read_message_before::<Slow>(&mut reader, end).is_err());
    }
    #[test]
    fn translated_pid_zero_retains_raw_layout_and_requires_both_root_credentials() {
        for (pid, uid, gid, allowed) in [
            (0, 0, 0, true),
            (1, 0, 0, true),
            (0, 65534, 0, false),
            (0, 0, 65534, false),
            (0, 65534, 65534, false),
        ] {
            let peer = nix::sys::socket::UnixCredentials::from(nix::libc::ucred { pid, uid, gid });
            assert_eq!(peer.pid(), pid);
            assert_eq!(root_peer(&peer).is_ok(), allowed);
        }
    }
    #[test]
    fn framing_nonblocking_preserves_existing_status_flags() {
        let (a, _b) = UnixStream::pair().unwrap();
        let before = fs::fcntl_getfl(&a).unwrap();
        assert!(!before.contains(OFlags::NONBLOCK));
        nonblocking(&a).unwrap();
        assert_eq!(fs::fcntl_getfl(&a).unwrap(), before | OFlags::NONBLOCK);
        nonblocking(&a).unwrap();
        assert_eq!(fs::fcntl_getfl(&a).unwrap(), before | OFlags::NONBLOCK);
    }
    #[test]
    fn stalled_listener_and_refusal_share_the_absolute_connection_exchange_deadline() {
        let path =
            std::env::temp_dir().join(format!("vprouter-bootstrap-stalled-{}", std::process::id()));
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let start = std::time::Instant::now();
        let end = start + Duration::from_millis(40);
        let mut stream = connect_before(&path, end).unwrap();
        assert!(read_message_before::<Response>(&mut stream, end).is_err());
        assert!(start.elapsed() < Duration::from_millis(200));
        assert!(connect_before(&path, start).is_err());
        drop(listener);
        assert!(
            connect_before(&path, std::time::Instant::now() + Duration::from_millis(40)).is_err()
        );
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn fresh_configuration_rejects_stale_response_digest_nonce_and_schema() {
        for (digest, nonce, schema) in [
            ("current-digest", "current-nonce", 1),
            ("stale-digest", "current-nonce", 1),
            ("current-digest", "stale-nonce", 1),
            ("stale-digest", "stale-nonce", 1),
            ("current-digest", "current-nonce", 2),
        ] {
            // Exercise the actual framed decoder followed by the exact helper
            // used by admit; a formerly valid reply cannot bind a new config.
            let (mut a, mut b) = UnixStream::pair().unwrap();
            write_message(
                &mut a,
                &Response {
                    schema,
                    config_sha256: digest.into(),
                    nonce: nonce.into(),
                    permission: Permission::ObserveOnce,
                },
            )
            .unwrap();
            let response = read_message::<Response>(&mut b).unwrap();
            assert_eq!(
                response_binding(&response, "current-digest", "current-nonce").is_ok(),
                digest == "current-digest" && nonce == "current-nonce" && schema == 1
            );
        }
    }
    #[test]
    fn full_unix_backlog_refuses_within_connection_deadline() {
        use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
        let path =
            std::env::temp_dir().join(format!("vprouter-bootstrap-backlog-{}", std::process::id()));
        let listener = net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        let address = SocketAddrUnix::new(&path).unwrap();
        net::bind(&listener, &address).unwrap();
        net::listen(&listener, 0).unwrap();
        let queued = net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        net::connect(&queued, &address).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker_path = path.clone();
        let worker = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let result = connect_before(&worker_path, start + Duration::from_millis(40));
            tx.send((result.is_err(), start.elapsed())).unwrap();
        });
        let result = rx.recv_timeout(Duration::from_millis(250));
        // Closing the listener also releases a regressed blocking connector,
        // so this regression test fails boundedly instead of hanging the suite.
        drop(listener);
        drop(queued);
        worker.join().unwrap();
        std::fs::remove_file(path).unwrap();
        let (refused, elapsed) = result.expect("backlog connect exceeded absolute deadline");
        assert!(refused);
        assert!(elapsed < Duration::from_millis(200));
    }
    fn configuration() -> Configuration {
        let profile = b"[Interface]\nPrivateKey=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress=10.64.0.2/32\nDNS=10.64.0.1\n[Peer]\nPublicKey=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs=0.0.0.0/0\nEndpoint=185.65.134.88:51820\n";
        let raw = serde_json::json!({"schema_version":2,"deployment_id":"bootlab","site":"debdev","gateway_image":format!("sha256:{}","a".repeat(64)),"exits":[{"id":"one","enabled":true,"state_dir":"/synthetic/one","mode":{"kind":"mullvad","profile":"/synthetic/no-read","expected_server":"de-fra-wg-404"}}],"dependency_adapters":[],"client_policies":[]});
        let cfg = vprouter_core::config::Configuration::parse(&serde_json::to_vec(&raw).unwrap())
            .unwrap()
            .validate_with(|_, server| {
                vprouter_core::profile::Profile::parse(profile, server, None)
            })
            .unwrap();
        let allocation = AllocationRecord::from_configuration(&cfg, 7).unwrap();
        let p = vprouter_core::profile::Profile::parse(profile, "de-fra-wg-404", None).unwrap();
        let exit = allocation.exits[0].clone();
        let monitoring = Plan::new(&allocation, "bootlab", &exit, &p)
            .unwrap()
            .monitoring();
        Configuration {
            schema: 1,
            allocation,
            exit,
            container_id: "a".repeat(64),
            namespace: Object { dev: 4, ino: 5 },
            cgroup: "0::/\n".into(),
            program_sha256: "b".repeat(64),
            manifest_sha256: "c".repeat(64),
            socket: Object { dev: 1, ino: 2 },
            nonce: "d".repeat(64),
            resolver: "10.64.0.1".parse().unwrap(),
            monitoring,
            health_binding: None,
            enrollment: None,
            execution_policy: "observer-unix-netlink-zero-caps-v1".into(),
        }
    }
    #[test]
    fn monitor_health_binding_rejects_cross_exit_generation_and_mode() {
        let mut config = configuration();
        let binding = vprouter_core::health::Binding {
            deployment_id: "bootlab".into(),
            exit_id: "one".into(),
            generation: 7,
            mode: vprouter_core::config::ExitMode::Mullvad,
            display_name: "monitor-fixture".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "fixture-node".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        };
        config.health_binding = Some(binding.clone());
        assert!(config.validate().is_err()); // observer policy cannot authorize monitor
        config.execution_policy = "starting-monitor-unix-netlink-zero-caps-v1".into();
        config.validate().unwrap();
        for fault in 0..5 {
            let mut wrong = binding.clone();
            match fault {
                0 => wrong.deployment_id = "other".into(),
                1 => wrong.exit_id = "other".into(),
                2 => wrong.generation += 1,
                3 => {
                    wrong.mode = vprouter_core::config::ExitMode::Direct;
                    wrong.expected_server = None;
                }
                _ => wrong.boot_id = "malformed".into(),
            }
            config.health_binding = Some(wrong);
            assert!(config.validate().is_err(), "fault {fault}");
        }
    }
    #[test]
    fn protected_config_binds_exact_member_and_has_only_public_monitoring_facts() {
        let original = configuration();
        original.validate().unwrap();
        let bytes = serde_json::to_vec(&original).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains("PrivateKey")
                && !text.contains("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
        );
        for change in 0..9 {
            let mut c: Configuration = crate::json::decode(&bytes).unwrap();
            match change {
                0 => c.schema = 2,
                1 => c.exit.exit_id = "foreign".into(),
                2 => c.exit.state_dir = "/synthetic/foreign".into(),
                3 => c.resolver = "8.8.8.8".parse().unwrap(),
                4 => c.namespace.ino = 0,
                5 => c.socket.ino = 0,
                6 => c.nonce = "invalid".into(),
                7 => c.cgroup = "0::/../foreign\n".into(),
                _ => c.cgroup = "0::/\n0::/foreign\n".into(),
            }
            assert!(c.validate().is_err(), "change {change}");
        }
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["private_key"] = "must-not-be-accepted".into();
        assert!(
            crate::json::decode::<Configuration>(&serde_json::to_vec(&value).unwrap()).is_err()
        );
    }
    #[test]
    fn trickling_protocol_has_one_deadline_for_prefix_and_body() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            for byte in 100u32
                .to_be_bytes()
                .into_iter()
                .chain(std::iter::repeat_n(b'x', 100))
            {
                if a.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let start = std::time::Instant::now();
        assert!(read_message_before::<Request>(&mut b, start + Duration::from_millis(35)).is_err());
        assert!(start.elapsed() < Duration::from_millis(250));
        drop(b);
        sender.join().unwrap();
    }
    #[test]
    fn framing_rejects_duplicate_fields_unknown_fields_oversize_and_truncation() {
        for bytes in [
            br#"{"schema":1,"schema":1,"config_sha256":"x","nonce":"n"}"#.as_slice(),
            br#"{"schema":1,"config_sha256":"x","nonce":"n","extra":1}"#.as_slice(),
        ] {
            let (mut a, mut b) = UnixStream::pair().unwrap();
            a.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
            a.write_all(bytes).unwrap();
            assert!(read_message::<Request>(&mut b).is_err());
        }
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&4097u32.to_be_bytes()).unwrap();
        assert!(read_message::<Request>(&mut b).is_err());
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&5u32.to_be_bytes()).unwrap();
        a.write_all(b"{}").unwrap();
        drop(a);
        assert!(read_message::<Request>(&mut b).is_err());
    }
    #[test]
    fn permission_is_observation_only_and_exchange_is_bounded() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        write_message(
            &mut a,
            &Response {
                schema: 1,
                config_sha256: "a".repeat(64),
                nonce: "b".repeat(64),
                permission: Permission::ObserveOnce,
            },
        )
        .unwrap();
        assert!(read_message::<Response>(&mut b).unwrap().permission == Permission::ObserveOnce);
        assert!(
            crate::json::decode::<Response>(
                br#"{"schema":1,"config_sha256":"x","nonce":"n","permission":"ready"}"#
            )
            .is_err()
        );
        b.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        assert!(read_message::<Response>(&mut b).is_err());
    }
    #[test]
    fn normal_worker_start_still_refuses_without_any_bootstrap_socket() {
        assert_eq!(crate::start(), Err(Error::StructuralGap));
        assert!(credentials().is_err()); // ordinary user is never a confined worker
    }
}
