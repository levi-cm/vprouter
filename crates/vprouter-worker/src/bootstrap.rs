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
    pub monitoring: MonitoringPlan,
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
}
pub fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
fn write_message_before<T: Serialize>(
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
    stream.set_nonblocking(true).map_err(|_| Error::Bootstrap)?;
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
    Ok(())
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
    Ok(())
}
fn read_before(stream: &mut UnixStream, bytes: &mut [u8], end: std::time::Instant) -> Result<()> {
    stream.set_nonblocking(true).map_err(|_| Error::Bootstrap)?;
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
    crate::json::decode(&bytes)
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
    if response.schema != 1
        || response.config_sha256 != hash
        || response.nonce != nonce
        || response.permission != Permission::ObserveOnce
    {
        return Err(Error::Bootstrap);
    }
    Ok(())
}
fn admit() -> Result<Observation> {
    let (config, hash) = protected_configuration()?;
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
    let peer = rustix::net::sockopt::socket_peercred(&stream).map_err(|_| Error::Bootstrap)?;
    // PID may translate to zero in a private PID namespace. UID/GID root are
    // necessary here, not sufficient: the fixed protected socket+nonce+digest
    // and the independently checked current client bind the one-shot exchange.
    if peer.uid.as_raw() != 0 || peer.gid.as_raw() != 0 {
        return Err(Error::Bootstrap);
    }
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
    response_binding(&response, &hash, &config.nonce)?;
    let result = Observation {
        config,
        _thread: PhantomData,
    };
    result.check()?;
    Ok(result)
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
            if !crate::localapi::parse_status(&status.body)?.unenrolled()
                || !crate::localapi::parse_prefs(&prefs.body)?.unenrolled()
            {
                return Err(Error::Identity);
            }
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
