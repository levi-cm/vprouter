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
    let proc = open("/proc", DIR, Mode::empty()).map_err(|_| Error::UnsupportedPlatform)?;
    fs_type(&proc, PROC)?;
    // Deliberate kernel procfs self link remains valid across PID namespaces;
    // procfs was validated, and no caller path component is accepted.
    let own = openat(
        &proc,
        "self",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::ProcessUnavailable)?;
    let task = openat(&own, "task", DIR, Mode::empty()).map_err(|_| Error::ProcessUnavailable)?;
    let mut entries = fs::Dir::read_from(&task).map_err(|_| Error::ProcessUnavailable)?;
    let mut count = 0;
    for entry in &mut entries {
        let entry = entry.map_err(|_| Error::ProcessUnavailable)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if !name.iter().all(u8::is_ascii_digit) {
            return Err(Error::ProcessChanged);
        }
        count += 1;
        if count > 1 {
            return Err(Error::NotSingleThreaded);
        }
    }
    if count != 1 {
        return Err(Error::NotSingleThreaded);
    }
    Ok(())
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
pub(super) fn initial_map(s: &str) -> bool {
    let parts: Vec<_> = s.split_whitespace().collect();
    parts == ["0", "0", "4294967295"]
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
        let proc_root = protected_path(Path::new("/proc"))?;
        fs_type(&proc_root, PROC)?;
        let proc = openat(&proc_root, c.state.pid.to_string(), DIR, Mode::empty())
            .map_err(|_| Error::ProcessUnavailable)?;
        fs_type(&proc, PROC)?;
        let pidfd = pidfd_open(
            Pid::from_raw(c.state.pid as i32).ok_or(Error::ProcessUnavailable)?,
            PidfdFlags::NONBLOCK,
        )
        .map_err(|_| Error::ProcessUnavailable)?;
        alive(&pidfd)?;
        if stat_start(&read_at(&proc, "stat", 64 * 1024)?, c.state.pid)? != spec.process_start_time
        {
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
        membership(&cgroup, c.state.pid)?;
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
        let pinned = Self {
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
            pid: c.state.pid,
            started_at: c.state.started_at.clone(),
        };
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
        if identity(&self.cgroup)? != self.cgroup_identity
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
        let current = openat2(
            &self.root,
            &WORKER[1..],
            RD,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::ExecutableMismatch)?;
        if verify_executable(&current, stage)? != self.executable_identity {
            return Err(Error::ExecutableMismatch);
        }
        alive(&self.pidfd)
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
