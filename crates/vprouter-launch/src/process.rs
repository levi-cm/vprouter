#![forbid(unsafe_code)]
use super::{
    Error, Result,
    spec::{LIMIT, LaunchSpec, StagingEvidence, WORKER, safe_absolute},
};
use rustix::{
    event::{PollFd, PollFlags, poll},
    fs::{self, FileType, Mode, OFlags, ResolveFlags, fstat, fstatfs, open, openat, openat2},
    process::{Pid, PidfdFlags, pidfd_open},
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    os::fd::{AsFd, OwnedFd},
    path::Path,
};
use vprouter_linux::docker::LaunchContainer;
const PROC: i64 = 0x9fa0;
const NSFS: i64 = 0x6e736673;
const CGROUP2: i64 = 0x63677270;
const RD: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
const DIR: OFlags = RD.union(OFlags::DIRECTORY);

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn identity(fd: impl AsFd) -> Result<Identity> {
    let s = fstat(fd).map_err(|_| Error::ProcessUnavailable)?;
    Ok(Identity {
        dev: s.st_dev,
        ino: s.st_ino,
        mode: s.st_mode,
        uid: s.st_uid,
        gid: s.st_gid,
        size: s.st_size,
        mtime: s.st_mtime,
        mtime_ns: s.st_mtime_nsec as i64,
        ctime: s.st_ctime,
        ctime_ns: s.st_ctime_nsec as i64,
    })
}
fn same_cgroup_identity(pinned: Identity, current: Identity) -> bool {
    // Creating/removing our owned child group changes the parent's directory
    // timestamps (and potentially its size). Those are not object identity.
    // Preserve exact inode/device/type/mode/ownership; process membership and
    // cgroup2 mount provenance are checked independently before accepting it.
    (pinned.dev, pinned.ino, pinned.mode, pinned.uid, pinned.gid)
        == (
            current.dev,
            current.ino,
            current.mode,
            current.uid,
            current.gid,
        )
}
fn fs_type(fd: impl AsFd, magic: i64) -> Result<()> {
    if fstatfs(fd).map_err(|_| Error::UnsupportedPlatform)?.f_type as i64 != magic {
        return Err(Error::UnsupportedPlatform);
    }
    Ok(())
}
fn read_at(fd: impl AsFd, name: &str, limit: usize) -> Result<String> {
    let file = openat(fd, name, RD, Mode::empty()).map_err(|_| Error::ProcessUnavailable)?;
    let mut bytes = Vec::new();
    File::from(file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::ProcessUnavailable)?;
    if bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    String::from_utf8(bytes).map_err(|_| Error::ProcessChanged)
}
/// Fixed relative paths only. Each component is opened without following links;
/// unlike openat2, the read-only inspector can enforce these scalar flags in BPF.
pub(super) fn readonly_path(root: impl AsFd, path: &str) -> Result<OwnedFd> {
    let parts: Vec<_> = path.split('/').collect();
    if parts.is_empty()
        || parts
            .iter()
            .any(|p| p.is_empty() || matches!(*p, "." | ".."))
    {
        return Err(Error::UnsafeInput);
    }
    let mut directory = None;
    for (index, part) in parts.iter().enumerate() {
        let fd = openat(
            directory.as_ref().map_or(root.as_fd(), AsFd::as_fd),
            *part,
            if index + 1 == parts.len() { RD } else { DIR },
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeInput)?;
        directory = Some(fd);
    }
    directory.ok_or(Error::UnsafeInput)
}
fn trusted_root() -> Result<OwnedFd> {
    let fd = open("/", DIR, Mode::empty()).map_err(|_| Error::UnsafeInput)?;
    check_directory(&fd)?;
    Ok(fd)
}
fn check_directory(fd: impl AsFd) -> Result<()> {
    let s = fstat(fd).map_err(|_| Error::UnsafeInput)?;
    if s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o022 != 0
        || FileType::from_raw_mode(s.st_mode) != FileType::Directory
    {
        return Err(Error::UnsafeInput);
    }
    Ok(())
}
fn protected_path(path: &Path) -> Result<OwnedFd> {
    if !safe_absolute(path) {
        return Err(Error::UnsafeInput);
    }
    let mut fd = trusted_root()?;
    let parts: Vec<_> = path.components().skip(1).collect();
    for (n, part) in parts.iter().enumerate() {
        check_directory(&fd)?;
        let flags = if n + 1 == parts.len() { RD } else { DIR };
        fd = openat(&fd, part.as_os_str(), flags, Mode::empty()).map_err(|_| Error::UnsafeInput)?;
    }
    Ok(fd)
}

pub(super) fn single_threaded() -> Result<()> {
    super::kernel_base::single_threaded()
}
pub(super) fn stat_start(s: &str, pid: u32) -> Result<u64> {
    // comm may contain spaces, parentheses and newlines. Final ') ' ends comm;
    // remaining kernel fields have no parentheses. Never split the whole line.
    let (head, tail) = s.rsplit_once(") ").ok_or(Error::ProcessChanged)?;
    if !head.starts_with(&format!("{pid} (")) {
        return Err(Error::ProcessChanged);
    }
    let parts: Vec<_> = tail.split_whitespace().collect();
    if parts.len() < 20 || parts[0].len() != 1 || matches!(parts[0], "Z" | "X" | "x") {
        return Err(Error::ProcessUnavailable);
    }
    parts[19]
        .parse::<u64>()
        .ok()
        .filter(|s| *s > 0)
        .ok_or(Error::ProcessChanged)
}
pub(super) fn stat_stopped(text: &str, pid: u32, start: u64) -> Result<()> {
    if stat_start(text, pid)? != start
        || text
            .rsplit_once(") ")
            .and_then(|(_, tail)| tail.split_whitespace().next())
            != Some("T")
    {
        return Err(Error::ProcessChanged);
    }
    Ok(())
}
pub(super) fn initial_map(s: &str) -> bool {
    let parts: Vec<_> = s.split_whitespace().collect();
    parts == ["0", "0", "4294967295"]
}
// Fixed setup operations: chown, protected file/cgroup access, signal, UID/GID/
// capability reduction, network administration, private root/proc inspection,
// and namespace/mount setup. No worker inherits this host setup mask.
const HOST_SETUP_CAPS: u64 = (1 << 0)
    | (1 << 1)
    | (1 << 3)
    | (1 << 5)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 12)
    | (1 << 18)
    | (1 << 19)
    | (1 << 21);
#[derive(Clone, Copy)]
enum HostRole {
    Setup,
    Guard,
}
#[cfg(test)]
fn host_credentials(status: &str, uid_map: &str, gid_map: &str, lsm: &str) -> Result<()> {
    role_credentials(status, uid_map, gid_map, lsm, HostRole::Setup)
}
fn role_credentials(
    status: &str,
    uid_map: &str,
    gid_map: &str,
    lsm: &str,
    role: HostRole,
) -> Result<()> {
    if !initial_map(uid_map) || !initial_map(gid_map) || lsm.trim() != "unconfined" {
        return Err(Error::UnsupportedPlatform);
    }
    let field = |name: &str| {
        let mut values = status.lines().filter_map(|l| l.strip_prefix(name));
        let value = values.next().ok_or(Error::UnsupportedPlatform)?.trim();
        if values.next().is_some() {
            return Err(Error::UnsupportedPlatform);
        }
        Ok(value)
    };
    for name in ["Uid:", "Gid:"] {
        if field(name)?.split_whitespace().collect::<Vec<_>>() != ["0"; 4] {
            return Err(Error::UnsupportedPlatform);
        }
    }
    for (name, expected) in [
        (
            "NoNewPrivs:",
            match role {
                HostRole::Setup => "0",
                HostRole::Guard => "1",
            },
        ),
        ("Seccomp:", "0"),
        ("Threads:", "1"),
    ] {
        if field(name)? != expected {
            return Err(Error::UnsupportedPlatform);
        }
    }
    for name in ["CapPrm:", "CapEff:", "CapBnd:"] {
        let mask = u64::from_str_radix(field(name)?, 16).map_err(|_| Error::UnsupportedPlatform)?;
        let needed = match role {
            HostRole::Setup => HOST_SETUP_CAPS,
            HostRole::Guard => HOST_SETUP_CAPS & !(1 << 19),
        };
        if mask & needed != needed || matches!(role, HostRole::Guard) && mask & (1 << 19) != 0 {
            return Err(Error::UnsupportedPlatform);
        }
    }
    Ok(())
}
/// Read-only host checks before durable installation/namespace/network intent.
/// This explicitly supports initial user namespace + unfiltered/unconfined
/// root setup, not arbitrary inherited host seccomp or LSM domains.
pub(super) fn host_preflight() -> Result<()> {
    role_preflight(HostRole::Setup)
}
pub(super) fn guard_preflight() -> Result<()> {
    role_preflight(HostRole::Guard)
}
pub(super) fn publisher_preflight() -> Result<()> {
    // Two explicit native roles; neither path changes launch/journal authority.
    host_preflight().or_else(|_| guard_preflight())
}
fn role_preflight(role: HostRole) -> Result<()> {
    single_threaded()?;
    let proc = open(
        "/proc/self",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::UnsupportedPlatform)?;
    fs_type(&proc, PROC)?;
    role_credentials(
        &read_at(&proc, "status", 65536)?,
        &read_at(&proc, "uid_map", 4096)?,
        &read_at(&proc, "gid_map", 4096)?,
        &read_at(&proc, "attr/current", 256)?,
        role,
    )?;
    let hierarchy =
        open("/sys/fs/cgroup", DIR, Mode::empty()).map_err(|_| Error::UnsupportedPlatform)?;
    fs_type(hierarchy, CGROUP2)
}
pub(super) fn cgroup_path(s: &str, id: &str) -> Result<String> {
    let path = s
        .strip_suffix('\n')
        .unwrap_or(s)
        .strip_prefix("0::")
        .ok_or(Error::CgroupMismatch)?;
    // One exact, explicitly supported Docker systemd cgroup v2 layout.
    if path != format!("/system.slice/docker-{id}.scope") {
        return Err(Error::CgroupMismatch);
    }
    Ok(path.to_owned())
}
#[derive(Clone, Copy)]
struct MountId {
    major: u32,
    minor: u32,
}
fn mount_fields(line: &str) -> Result<(Vec<&str>, Vec<&str>)> {
    let (left, right) = line.split_once(" - ").ok_or(Error::RootMismatch)?;
    let l: Vec<_> = left.split_whitespace().collect();
    let r: Vec<_> = right.split_whitespace().collect();
    if l.len() < 6 || r.len() < 3 {
        return Err(Error::RootMismatch);
    }
    Ok((l, r))
}
fn root_mount(mountinfo: &str, root: Identity) -> Result<()> {
    let mut matches = 0;
    for line in mountinfo.lines() {
        let (l, r) = mount_fields(line)?;
        if l[4] != "/" {
            continue;
        }
        let (maj, min) = l[2].split_once(':').ok_or(Error::RootMismatch)?;
        if l[3] != "/"
            || !l[5].split(',').any(|v| v == "ro")
            || r[0] != "overlay"
            || maj.parse::<u32>().ok() != Some(fs::major(root.dev))
            || min.parse::<u32>().ok() != Some(fs::minor(root.dev))
        {
            return Err(Error::RootMismatch);
        }
        matches += 1;
    }
    if matches != 1 {
        return Err(Error::RootMismatch);
    }
    Ok(())
}
fn cgroup_mount(mountinfo: &str) -> Result<MountId> {
    let mut selected = None;
    for line in mountinfo.lines() {
        let (l, r) = mount_fields(line)?;
        if l[4] != "/sys/fs/cgroup" {
            continue;
        }
        if selected.is_some() || l[3] != "/" || r[0] != "cgroup2" {
            return Err(Error::CgroupMismatch);
        }
        let (major, minor) = l[2].split_once(':').ok_or(Error::CgroupMismatch)?;
        selected = Some(MountId {
            major: major.parse().map_err(|_| Error::CgroupMismatch)?,
            minor: minor.parse().map_err(|_| Error::CgroupMismatch)?,
        });
    }
    selected.ok_or(Error::CgroupMismatch)
}
fn same_object(a: impl AsFd, b: impl AsFd) -> Result<bool> {
    let a = identity(a)?;
    let b = identity(b)?;
    Ok((a.dev, a.ino) == (b.dev, b.ino))
}
fn namespace(dir: impl AsFd, name: &str) -> Result<OwnedFd> {
    // These are deliberate procfs magic links, only after numeric PID directory,
    // pidfd and start-time binding. fstatfs/fstat establish actual nsfs objects.
    let fd = openat(dir, name, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| Error::NamespaceMismatch)?;
    fs_type(&fd, NSFS)?;
    let s = fstat(&fd).map_err(|_| Error::NamespaceMismatch)?;
    if s.st_ino == 0 || FileType::from_raw_mode(s.st_mode) != FileType::RegularFile {
        return Err(Error::NamespaceMismatch);
    }
    Ok(fd)
}
const NAMES: [&str; 8] = ["mnt", "net", "pid", "user", "uts", "ipc", "cgroup", "time"];
pub(super) struct PinnedProcess {
    _inventory: Option<super::inventory::Registration>,
    proc: OwnedFd,
    pidfd: OwnedFd,
    namespaces: Vec<OwnedFd>,
    root: OwnedFd,
    root_identity: Identity,
    cgroup_root: OwnedFd,
    cgroup: OwnedFd,
    cgroup_identity: Identity,
    executable: OwnedFd,
    executable_identity: Identity,
    artifact: OwnedFd,
    artifact_identity: Identity,
    pid: u32,
    started_at: String,
}
impl PinnedProcess {
    pub(super) fn open(
        spec: &LaunchSpec,
        stage: &StagingEvidence,
        c: &LaunchContainer,
    ) -> Result<Self> {
        Self::open_pid(spec, stage, c.state.pid, &c.state.started_at)
    }
    pub(super) fn open_query(query: &super::kernel::docker_query::Accepted) -> Result<Self> {
        query.require()?;
        let request = query.request();
        let pinned = Self::open_pid(
            &request.spec,
            &request.staging,
            query.facts().pid,
            &request.spec.started_at,
        )?;
        query.require()?;
        Ok(pinned)
    }
    fn open_pid(
        spec: &LaunchSpec,
        stage: &StagingEvidence,
        pid: u32,
        started_at: &str,
    ) -> Result<Self> {
        if pid <= 1 || pid > i32::MAX as u32 || started_at != spec.started_at {
            return Err(Error::ProcessChanged);
        }
        let proc_root = protected_path(Path::new("/proc"))?;
        fs_type(&proc_root, PROC)?;
        let proc = openat(&proc_root, pid.to_string(), DIR, Mode::empty())
            .map_err(|_| Error::ProcessUnavailable)?;
        fs_type(&proc, PROC)?;
        let pidfd = pidfd_open(
            Pid::from_raw(pid as i32).ok_or(Error::ProcessUnavailable)?,
            PidfdFlags::NONBLOCK,
        )
        .map_err(|_| Error::ProcessUnavailable)?;
        alive(&pidfd)?;
        if stat_start(&read_at(&proc, "stat", 64 * 1024)?, pid)? != spec.process_start_time {
            return Err(Error::ProcessChanged);
        }
        maps(&proc)?;
        let ns_dir =
            openat(&proc, "ns", DIR, Mode::empty()).map_err(|_| Error::NamespaceMismatch)?;
        let mut namespaces = Vec::new();
        for name in NAMES {
            namespaces.push(namespace(&ns_dir, name)?);
        }
        let init = openat(&proc_root, "1", DIR, Mode::empty())
            .map_err(|_| Error::UnsupportedUserNamespace)?;
        let init_ns =
            openat(&init, "ns", DIR, Mode::empty()).map_err(|_| Error::UnsupportedUserNamespace)?;
        if !same_object(&namespaces[3], namespace(&init_ns, "user")?)? {
            return Err(Error::UnsupportedUserNamespace);
        }
        let own = openat(
            &proc_root,
            std::process::id().to_string(),
            DIR,
            Mode::empty(),
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        let own_ns =
            openat(&own, "ns", DIR, Mode::empty()).map_err(|_| Error::NamespaceMismatch)?;
        // Required Docker-created isolation; user/time may legitimately match.
        for (index, name) in NAMES.iter().enumerate() {
            if matches!(*name, "mnt" | "net" | "pid" | "uts" | "ipc" | "cgroup")
                && same_object(&namespaces[index], namespace(&own_ns, name)?)?
            {
                return Err(Error::NamespaceMismatch);
            }
        }
        // proc root is a deliberate kernel magic link. No caller path is used.
        let root = openat(
            &proc,
            "root",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::RootMismatch)?;
        check_directory(&root)?;
        let root_identity = identity(&root)?;
        root_mount(&read_at(&proc, "mountinfo", 1024 * 1024)?, root_identity)?;
        let own_mountinfo = read_at(&own, "mountinfo", 1024 * 1024)?;
        let mounted = cgroup_mount(&own_mountinfo)?;
        let cgroup_root = protected_path(Path::new("/sys/fs/cgroup"))?;
        check_directory(&cgroup_root)?;
        fs_type(&cgroup_root, CGROUP2)?;
        let cgst = identity(&cgroup_root)?;
        if fs::major(cgst.dev) != mounted.major || fs::minor(cgst.dev) != mounted.minor {
            return Err(Error::CgroupMismatch);
        }
        let cgpath = cgroup_path(&read_at(&proc, "cgroup", 4096)?, &spec.container_id)?;
        let cgroup = openat2(
            &cgroup_root,
            &cgpath[1..],
            DIR,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(|_| Error::CgroupMismatch)?;
        check_directory(&cgroup)?;
        fs_type(&cgroup, CGROUP2)?;
        let cgroup_identity = identity(&cgroup)?;
        if cgroup_identity.dev != cgst.dev {
            return Err(Error::CgroupMismatch);
        }
        membership(&cgroup, pid)?;
        let artifact = protected_path(&stage.artifact_path)?;
        let artifact_identity = verify_executable(&artifact, stage)?;
        // openat2 forbids symlink/magiclink escape even inside pinned rootfs.
        let executable = openat2(
            &root,
            &WORKER[1..],
            RD,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::ExecutableMismatch)?;
        let executable_identity = verify_executable(&executable, stage)?;
        let mut pinned = Self {
            _inventory: None,
            proc,
            pidfd,
            namespaces,
            root,
            root_identity,
            cgroup_root,
            cgroup,
            cgroup_identity,
            executable,
            executable_identity,
            artifact,
            artifact_identity,
            pid,
            started_at: started_at.to_owned(),
        };
        let mut fds = vec![
            pinned.proc.as_fd(),
            pinned.pidfd.as_fd(),
            pinned.root.as_fd(),
            pinned.cgroup_root.as_fd(),
            pinned.cgroup.as_fd(),
            pinned.executable.as_fd(),
            pinned.artifact.as_fd(),
        ];
        fds.extend(pinned.namespaces.iter().map(AsFd::as_fd));
        pinned._inventory = Some(super::inventory::Registration::owned(&fds)?);
        pinned.revalidate(spec, stage)?;
        Ok(pinned)
    }
    #[cfg(test)]
    pub(super) fn reject_wrong_retained_handles(
        &mut self,
        spec: &LaunchSpec,
        stage: &StagingEvidence,
    ) -> Result<()> {
        let proc_root = protected_path(Path::new("/proc"))?;
        let own = openat(
            &proc_root,
            std::process::id().to_string(),
            DIR,
            Mode::empty(),
        )
        .map_err(|_| Error::ProcessUnavailable)?;
        let ns = openat(&own, "ns", DIR, Mode::empty()).map_err(|_| Error::NamespaceMismatch)?;
        let wrong_net = namespace(&ns, "net")?;
        let correct_net = std::mem::replace(&mut self.namespaces[1], wrong_net);
        let refused = self.revalidate(spec, stage).err() == Some(Error::NamespaceMismatch);
        self.namespaces[1] = correct_net;
        if !refused {
            return Err(Error::NamespaceMismatch);
        }
        let wrong_cgroup = rustix::io::dup(&self.cgroup_root).map_err(|_| Error::CgroupMismatch)?;
        let correct_cgroup = std::mem::replace(&mut self.cgroup, wrong_cgroup);
        let refused = self.revalidate(spec, stage).err() == Some(Error::CgroupMismatch);
        self.cgroup = correct_cgroup;
        if !refused {
            return Err(Error::CgroupMismatch);
        }
        self.revalidate(spec, stage)
    }
    pub(super) fn root(&self) -> std::os::fd::BorrowedFd<'_> {
        self.root.as_fd()
    }
    pub(super) fn cgroup_parent(&self) -> std::os::fd::BorrowedFd<'_> {
        self.cgroup.as_fd()
    }
    /// Original admitted hierarchy only. The new operation supplies its own
    /// current clock and policy query; these pins do not renew the admission.
    pub(super) fn producer_ancestry(
        &self,
        spec: &LaunchSpec,
        stage: &StagingEvidence,
    ) -> Result<[OwnedFd; 2]> {
        self.revalidate(spec, stage)?;
        let root = self
            .cgroup_root
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| Error::DescriptorDuplicate)?;
        let system = openat2(
            &root,
            "system.slice",
            DIR,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )
        .map_err(|_| Error::CgroupMismatch)?;
        self.verify_producer_ancestry(spec, stage, root.as_fd(), system.as_fd())?;
        Ok([root, system])
    }
    pub(super) fn verify_producer_ancestry(
        &self,
        spec: &LaunchSpec,
        stage: &StagingEvidence,
        root: std::os::fd::BorrowedFd<'_>,
        system: std::os::fd::BorrowedFd<'_>,
    ) -> Result<()> {
        self.revalidate(spec, stage)?;
        if !same_object(root, &self.cgroup_root)? {
            return Err(Error::CgroupMismatch);
        }
        check_directory(root)?;
        check_directory(system)?;
        fs_type(root, CGROUP2)?;
        fs_type(system, CGROUP2)?;
        for (parent, name, expected) in [
            (root, "..".to_owned(), root),
            (root, "system.slice".to_owned(), system),
            (
                system,
                format!("docker-{}.scope", spec.container_id),
                self.cgroup.as_fd(),
            ),
        ] {
            let at = fs::statat(parent, &name, fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| Error::CgroupMismatch)?;
            let st = fstat(expected).map_err(|_| Error::CgroupMismatch)?;
            if (at.st_dev, at.st_ino, at.st_mode, at.st_uid, at.st_gid)
                != (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid)
            {
                return Err(Error::CgroupMismatch);
            }
        }
        self.revalidate(spec, stage)
    }
    pub(super) fn launch_fds(&self) -> super::kernel::ContainerFds<'_> {
        super::kernel::ContainerFds {
            mount: self.namespaces[0].as_fd(),
            pid: self.namespaces[2].as_fd(),
            network: self.namespaces[1].as_fd(),
            ipc: self.namespaces[5].as_fd(),
            uts: self.namespaces[4].as_fd(),
            cgroup_ns: self.namespaces[6].as_fd(),
            root: self.root.as_fd(),
            executable: self.executable.as_fd(),
        }
    }
    #[allow(dead_code)]
    pub(super) fn base_network(&self) -> std::os::fd::BorrowedFd<'_> {
        self.namespaces[1].as_fd()
    }

    pub(super) fn place(&self, pid: u32, spec: &LaunchSpec) -> Result<()> {
        use std::io::Write;
        let fd = openat(
            &self.cgroup,
            "cgroup.procs",
            OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::PlacementFailed)?;
        std::fs::File::from(fd)
            .write_all(pid.to_string().as_bytes())
            .map_err(|_| Error::PlacementFailed)?;
        self.verify_placement(pid, spec)
    }
    pub(super) fn verify_placement(&self, pid: u32, spec: &LaunchSpec) -> Result<()> {
        membership(&self.cgroup, pid).map_err(|_| Error::PlacementFailed)?;
        let dir =
            open(format!("/proc/{pid}"), DIR, Mode::empty()).map_err(|_| Error::PlacementFailed)?;
        cgroup_path(&read_at(&dir, "cgroup", 4096)?, &spec.container_id)
            .map_err(|_| Error::PlacementFailed)?;
        alive(&self.pidfd)
    }
    pub(super) fn bind_container(&self, c: &LaunchContainer) -> Result<()> {
        if c.state.pid != self.pid || c.state.started_at != self.started_at {
            return Err(Error::ProcessChanged);
        }
        Ok(())
    }
    pub(super) fn revalidate(&self, s: &LaunchSpec, stage: &StagingEvidence) -> Result<()> {
        alive(&self.pidfd)?;
        if stat_start(&read_at(&self.proc, "stat", 64 * 1024)?, self.pid)? != s.process_start_time {
            return Err(Error::ProcessChanged);
        }
        maps(&self.proc)?;
        let ns =
            openat(&self.proc, "ns", DIR, Mode::empty()).map_err(|_| Error::NamespaceMismatch)?;
        for (name, pinned) in NAMES.iter().zip(&self.namespaces) {
            if !same_object(pinned, namespace(&ns, name)?)? {
                return Err(Error::NamespaceMismatch);
            }
        }
        let root = openat(
            &self.proc,
            "root",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::RootMismatch)?;
        if !same_object(&root, &self.root)? || identity(&self.root)? != self.root_identity {
            return Err(Error::RootMismatch);
        }
        root_mount(
            &read_at(&self.proc, "mountinfo", 1024 * 1024)?,
            self.root_identity,
        )?;
        cgroup_path(&read_at(&self.proc, "cgroup", 4096)?, &s.container_id)?;
        if !same_cgroup_identity(self.cgroup_identity, identity(&self.cgroup)?)
            || identity(&self.cgroup_root)?.dev != self.cgroup_identity.dev
        {
            return Err(Error::CgroupMismatch);
        }
        membership(&self.cgroup, self.pid)?;
        if identity(&self.executable)? != self.executable_identity
            || identity(&self.artifact)? != self.artifact_identity
        {
            return Err(Error::ExecutableMismatch);
        }
        // Reopen the fixed rootfs path: replacement/unlink does not inherit the
        // original executable FD's approval. Hash reads are bounded each time.
        let current =
            readonly_path(&self.root, &WORKER[1..]).map_err(|_| Error::ExecutableMismatch)?;
        if verify_executable(&current, stage)? != self.executable_identity {
            return Err(Error::ExecutableMismatch);
        }
        if stat_start(&read_at(&self.proc, "stat", 64 * 1024)?, self.pid)? != s.process_start_time {
            return Err(Error::ProcessChanged);
        }
        membership(&self.cgroup, self.pid)?;
        alive(&self.pidfd)
    }
    pub(super) fn select_guard(&self, inputs: &mut super::inventory::GuardInputs) -> Result<()> {
        inputs.include(
            self._inventory.as_ref().ok_or(Error::DescriptorPolicy)?,
            super::inventory::GuardAuthority::SelectedMember,
        )
    }
    pub(super) fn inspection_fds(&self) -> Vec<std::os::fd::BorrowedFd<'_>> {
        let mut fds = vec![
            self.proc.as_fd(),
            self.pidfd.as_fd(),
            self.root.as_fd(),
            self.cgroup_root.as_fd(),
            self.cgroup.as_fd(),
            self.executable.as_fd(),
            self.artifact.as_fd(),
        ];
        fds.extend(self.namespaces.iter().map(AsFd::as_fd));
        fds
    }
}
fn maps(proc: impl AsFd) -> Result<()> {
    if !initial_map(&read_at(&proc, "uid_map", 4096)?)
        || !initial_map(&read_at(&proc, "gid_map", 4096)?)
    {
        return Err(Error::UnsupportedUserNamespace);
    }
    Ok(())
}
fn alive(fd: impl AsFd) -> Result<()> {
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    if poll(
        &mut fds,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .map_err(|_| Error::ProcessUnavailable)?
        != 0
    {
        return Err(Error::ProcessUnavailable);
    }
    Ok(())
}
fn membership(fd: impl AsFd, pid: u32) -> Result<()> {
    let procs = read_at(fd, "cgroup.procs", 64 * 1024)?;
    if procs
        .lines()
        .filter(|v| v.parse::<u32>().ok() == Some(pid))
        .count()
        != 1
    {
        return Err(Error::CgroupMismatch);
    }
    Ok(())
}
pub(super) fn elf(bytes: &[u8], arch: &str) -> Result<()> {
    if bytes.len() < 64
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || !matches!(u16::from_le_bytes([bytes[16], bytes[17]]), 2 | 3)
        || u32::from_le_bytes(
            bytes[20..24]
                .try_into()
                .map_err(|_| Error::ExecutableMismatch)?,
        ) != 1
    {
        return Err(Error::ExecutableMismatch);
    }
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if machine
        != match arch {
            "amd64" => 62,
            "arm64" => 183,
            _ => return Err(Error::UnsupportedPlatform),
        }
    {
        return Err(Error::ExecutableMismatch);
    }
    let offset = u64::from_le_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| Error::ExecutableMismatch)?,
    );
    let size = u16::from_le_bytes([bytes[54], bytes[55]]) as u64;
    let count = u16::from_le_bytes([bytes[56], bytes[57]]) as u64;
    if size != 56
        || count == 0
        || count > 256
        || offset
            .checked_add(size * count)
            .is_none_or(|end| end > bytes.len() as u64)
    {
        return Err(Error::ExecutableMismatch);
    }
    let mut load = false;
    for n in 0..count {
        let start = (offset + n * size) as usize;
        let kind = u32::from_le_bytes(
            bytes[start..start + 4]
                .try_into()
                .map_err(|_| Error::ExecutableMismatch)?,
        );
        if matches!(kind, 2 | 3) {
            return Err(Error::ExecutableMismatch);
        }
        if kind == 1 {
            load = true;
        }
    }
    if !load {
        return Err(Error::ExecutableMismatch);
    }
    Ok(())
}
fn verify_executable(fd: impl AsFd, stage: &StagingEvidence) -> Result<Identity> {
    let before = identity(&fd)?;
    if FileType::from_raw_mode(before.mode) != FileType::RegularFile
        || before.uid != 0
        || before.gid != 0
        || before.mode & 0o7222 != 0
        || before.mode & 0o111 == 0
        || before.size < 64
        || before.size as u64 != stage.artifact_size
        || before.size as usize > LIMIT
    {
        return Err(Error::ExecutableMismatch);
    }
    // pread avoids shared file-offset changes between checks.
    let mut bytes = Vec::with_capacity(before.size as usize);
    let mut buf = [0; 16384];
    loop {
        let n = rustix::io::pread(&fd, &mut buf, bytes.len() as u64)
            .map_err(|_| Error::ExecutableMismatch)?;
        if n == 0 {
            break;
        }
        if n > LIMIT - bytes.len() {
            return Err(Error::TooLarge);
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    elf(&bytes, &stage.architecture)?;
    if Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        != stage.artifact_sha256
        || identity(&fd)? != before
    {
        return Err(Error::ExecutableMismatch);
    }
    Ok(before)
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn inspector_readonly_walk_refuses_absolute_parent_and_symlink_components() {
        let directory =
            std::env::temp_dir().join(format!("vprouter-inspection-walk-{}", std::process::id()));
        std::fs::create_dir_all(directory.join("inner")).unwrap();
        std::fs::write(directory.join("inner/value"), b"fixed").unwrap();
        std::os::unix::fs::symlink("inner", directory.join("redirect")).unwrap();
        let root = open(&directory, DIR, Mode::empty()).unwrap();
        assert!(readonly_path(&root, "inner/value").is_ok());
        for path in [
            "",
            "/inner/value",
            "../value",
            "inner/../value",
            "inner//value",
            "redirect/value",
        ] {
            assert!(readonly_path(&root, path).is_err(), "{path}");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn fixed_guard_native_role_requires_no_ptrace_and_no_new_privileges() {
        let status = format!(
            "Uid: 0 0 0 0\nGid: 0 0 0 0\nNoNewPrivs: 1\nSeccomp: 0\nThreads: 1\nCapPrm: {:x}\nCapEff: {:x}\nCapBnd: {:x}\n",
            HOST_SETUP_CAPS & !(1 << 19),
            HOST_SETUP_CAPS & !(1 << 19),
            HOST_SETUP_CAPS & !(1 << 19)
        );
        assert!(
            role_credentials(
                &status,
                "0 0 4294967295",
                "0 0 4294967295",
                "unconfined",
                HostRole::Guard
            )
            .is_ok()
        );
        assert!(
            host_credentials(&status, "0 0 4294967295", "0 0 4294967295", "unconfined").is_err()
        );
        assert!(
            role_credentials(
                &status.replace("NoNewPrivs: 1", "NoNewPrivs: 0"),
                "0 0 4294967295",
                "0 0 4294967295",
                "unconfined",
                HostRole::Guard
            )
            .is_err()
        );
        for field in ["CapPrm", "CapEff", "CapBnd"] {
            let changed = status.replace(
                &format!("{field}: {:x}", HOST_SETUP_CAPS & !(1 << 19)),
                &format!("{field}: {HOST_SETUP_CAPS:x}"),
            );
            assert!(
                role_credentials(
                    &changed,
                    "0 0 4294967295",
                    "0 0 4294967295",
                    "unconfined",
                    HostRole::Guard
                )
                .is_err()
            );
        }
    }
    #[test]
    fn stopped_witness_requires_exact_start_and_actual_stop_not_sleep() {
        let stopped = format!("24 (tricky) name) T {}7", "0 ".repeat(18));
        stat_stopped(&stopped, 24, 7).unwrap();
        assert!(stat_stopped(&stopped, 24, 8).is_err());
        assert!(stat_stopped(&stopped, 25, 7).is_err());
        for state in ["S", "R", "Z", "X", "t"] {
            assert!(
                stat_stopped(&stopped.replacen(") T ", &format!(") {state} "), 1), 24, 7).is_err()
            );
        }
    }
    #[test]
    fn host_setup_preflight_refuses_missing_caps_maps_lsm_filters_or_root_before_mutation() {
        let status = format!(
            "Uid: 0 0 0 0\nGid: 0 0 0 0\nNoNewPrivs: 0\nSeccomp: 0\nThreads: 1\nCapPrm: {HOST_SETUP_CAPS:x}\nCapEff: {HOST_SETUP_CAPS:x}\nCapBnd: {HOST_SETUP_CAPS:x}\n"
        );
        let map = "0 0 4294967295\n";
        assert!(host_credentials(&status, map, map, "unconfined\n").is_ok());
        for (old, new) in [
            ("Uid: 0", "Uid: 65534"),
            ("Gid: 0", "Gid: 65534"),
            ("NoNewPrivs: 0", "NoNewPrivs: 1"),
            ("Seccomp: 0", "Seccomp: 2"),
            ("Threads: 1", "Threads: 2"),
        ] {
            assert!(host_credentials(&status.replace(old, new), map, map, "unconfined").is_err());
        }
        for bit in 0..64 {
            if HOST_SETUP_CAPS & (1 << bit) == 0 {
                continue;
            }
            for field in ["CapPrm:", "CapEff:", "CapBnd:"] {
                let changed = status.replace(
                    &format!("{field} {HOST_SETUP_CAPS:x}"),
                    &format!("{field} {:x}", HOST_SETUP_CAPS & !(1 << bit)),
                );
                assert!(host_credentials(&changed, map, map, "unconfined").is_err());
            }
        }
        assert!(host_credentials(&status, "0 1000 65536", map, "unconfined").is_err());
        assert!(host_credentials(&status, map, map, "docker-default (enforce)").is_err());
        assert!(host_credentials(&(status + "Seccomp: 0\n"), map, map, "unconfined").is_err());
    }
    #[test]
    fn owned_subgroup_directory_updates_preserve_only_exact_parent_identity() {
        let pinned = Identity {
            dev: 24,
            ino: 20,
            mode: 0o040755,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 1,
            mtime_ns: 2,
            ctime: 3,
            ctime_ns: 4,
        };
        let mut changed = pinned;
        changed.size = 1;
        changed.mtime = 5;
        changed.mtime_ns = 6;
        changed.ctime = 7;
        changed.ctime_ns = 8;
        assert!(same_cgroup_identity(pinned, changed));
        for field in 0..5 {
            let mut foreign = changed;
            match field {
                0 => foreign.dev += 1,
                1 => foreign.ino += 1,
                2 => foreign.mode ^= 0o002,
                3 => foreign.uid = 65534,
                _ => foreign.gid = 65534,
            }
            assert!(!same_cgroup_identity(pinned, foreign));
        }
        let mut foreign_type = changed;
        foreign_type.mode = 0o100755;
        assert!(!same_cgroup_identity(pinned, foreign_type));
    }
    #[test]
    fn executable_hash_size_limit_and_metadata_changes_are_checked() {
        // Synthetic files only. Positive root ownership is tested in the owned
        // guest; this ordinary test exercises actual bounded pread/hash failures.
        let (_, mut stage) = super::super::tests::fixture();
        let path =
            std::env::temp_dir().join(format!("vprouter-launch-exec-{}", std::process::id()));
        let mut bytes = vec![0; 120];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16] = 2;
        bytes[18] = 62;
        bytes[20] = 1;
        bytes[32] = 64;
        bytes[54] = 56;
        bytes[56] = 1;
        bytes[64] = 1;
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).unwrap();
        let file = File::open(&path).unwrap();
        stage.artifact_size = bytes.len() as u64;
        assert!(matches!(
            verify_executable(&file, &stage),
            Err(Error::ExecutableMismatch)
        ));
        stage.artifact_sha256 = vprouter_linux::sha256(&bytes);
        if rustix::process::geteuid().as_raw() == 0 {
            assert!(verify_executable(&file, &stage).is_ok());
        }
        stage.artifact_size = LIMIT as u64 + 1;
        assert!(verify_executable(&file, &stage).is_err());
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn pidfd_liveness_and_single_thread_task_inventory_use_kernel_evidence() {
        let fd = pidfd_open(
            Pid::from_raw(std::process::id() as i32).unwrap(),
            PidfdFlags::NONBLOCK,
        )
        .unwrap();
        assert!(alive(&fd).is_ok());
        let (tx, rx) = std::sync::mpsc::channel();
        let (finish, done) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send(()).unwrap();
            done.recv().unwrap();
        });
        rx.recv().unwrap();
        assert_eq!(single_threaded(), Err(Error::NotSingleThreaded));
        finish.send(()).unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn root_mount_and_cgroup_mount_identity_are_exact() {
        let root = Identity {
            dev: rustix::fs::makedev(0, 12),
            ino: 1,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            mtime_ns: 0,
            ctime: 0,
            ctime_ns: 0,
        };
        let good = "1 2 0:12 / / ro,relatime - overlay overlay rw\n";
        assert!(root_mount(good, root).is_ok());
        assert!(root_mount(&good.replace("ro,", "rw,"), root).is_err());
        assert!(root_mount(&good.replace("0:12", "0:13"), root).is_err());
        assert!(root_mount(&(good.to_owned() + good), root).is_err());
        assert!(cgroup_mount("2 1 0:24 / /sys/fs/cgroup ro - cgroup2 cgroup rw\n").is_ok());
        assert!(cgroup_mount("2 1 0:24 /foreign /sys/fs/cgroup ro - cgroup2 cgroup rw\n").is_err());
    }
}
