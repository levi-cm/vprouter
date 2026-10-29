#![forbid(unsafe_code)]
//! Fixed reviewed program bytes. This binding does not certify Go confinement,
//! an init/rootfs, release staging, or production launch authority.
use super::{Error, Result};
use rustix::fs::{self, FileType, Mode, OFlags};
use serde::Deserialize;
use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
};
use vprouter_worker::bootstrap::{MAX_PROGRAM, digest};

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Role {
    WorkerObserver,
    WorkerMonitor,
    Tailscaled,
    GatewayInit,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    role: Role,
    path: String,
    sha256: String,
    bytes: u64,
    policy: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema: u32,
    architecture: String,
    base_index: String,
    base_platform: String,
    programs: Vec<Entry>,
}
pub(super) struct ReviewedBundle {
    bundle: Bundle,
    digest: String,
}
pub(super) struct Program {
    fd: OwnedFd,
    role: Role,
    sha256: String,
    bytes: u64,
}
impl ReviewedBundle {
    pub fn current() -> Result<Self> {
        let bytes = if cfg!(target_arch = "x86_64") {
            include_bytes!("../../../docs/rust-v2/programs-amd64.json").as_slice()
        } else if cfg!(target_arch = "aarch64") {
            include_bytes!("../../../docs/rust-v2/programs-arm64.json").as_slice()
        } else {
            return Err(Error::UnsupportedPlatform);
        };
        Self::decode(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let b: Bundle = serde_json::from_slice(bytes).map_err(|_| Error::ExecutableMismatch)?;
        let arch = if cfg!(target_arch = "x86_64") {
            "amd64"
        } else {
            "arm64"
        };
        if b.schema != 1
            || b.architecture != arch
            || b.base_index
                != "tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065"
            || b.base_platform
                != if arch == "amd64" {
                    "sha256:08a1bc6c82fee62d1a135788fb67fefa9d22deea3830e8a45ebe1a3cb116e325"
                } else {
                    "sha256:472c549d2ef8cebc000de2c8a94061bbdc864d2454177b2ada713262475449ef"
                }
            || !(3..=4).contains(&b.programs.len())
        {
            return Err(Error::ExecutableMismatch);
        }
        let mut roles = vec![Role::WorkerObserver, Role::Tailscaled, Role::GatewayInit];
        if b.programs.len() == 4 {
            roles.push(Role::WorkerMonitor);
        }
        for role in roles {
            let entries: Vec<_> = b.programs.iter().filter(|p| p.role == role).collect();
            if entries.len() != 1 {
                return Err(Error::ExecutableMismatch);
            }
            let p = entries[0];
            let (path, policy) = match role {
                Role::WorkerObserver => (
                    "/usr/local/bin/vprouter-worker-observe",
                    "observation-only-zero-caps-private-root-v2",
                ),
                Role::WorkerMonitor => (
                    "/usr/local/bin/vprouter-worker-monitor",
                    "guard-bound-monitor-zero-caps-private-root-v1",
                ),
                Role::GatewayInit => (
                    "/usr/local/bin/vprouter-worker",
                    "inert-image-pid1-caps0-v1",
                ),
                Role::Tailscaled => (
                    "/usr/local/bin/tailscaled",
                    "tailscale-1.102.5;fixed-go-netadmin-private-root-v1",
                ),
            };
            if p.path != path
                || p.policy != policy
                || !super::spec::digest(&p.sha256)
                || p.bytes < 64
                || p.bytes > MAX_PROGRAM
            {
                return Err(Error::ExecutableMismatch);
            }
        }
        Ok(Self {
            bundle: b,
            digest: digest(bytes),
        })
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    fn entry(&self, role: Role) -> Result<&Entry> {
        self.bundle
            .programs
            .iter()
            .find(|p| p.role == role)
            .ok_or(Error::ExecutableMismatch)
    }
    /// Fixed admitted root only. No arbitrary path, argv, role policy or bytes.
    pub fn open(&self, root: impl AsFd, role: Role) -> Result<Program> {
        let p = self.entry(role)?;
        let fd = fs::openat2(
            root,
            Path::new(&p.path[1..]),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            fs::ResolveFlags::BENEATH | fs::ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| Error::ExecutableMismatch)?;
        self.verify(&fd, role)?;
        Ok(Program {
            fd,
            role,
            sha256: p.sha256.clone(),
            bytes: p.bytes,
        })
    }
    pub fn verify(&self, fd: impl AsFd, role: Role) -> Result<()> {
        let p = self.entry(role)?;
        verify(fd, p, &self.bundle.architecture)
    }
    /// One fresh hash covers these two descriptors only after exact native
    /// object/metadata equality. Nothing is cached across inspection jobs.
    pub fn verify_pinned(&self, current: impl AsFd, retained: impl AsFd, role: Role) -> Result<()> {
        let pair = ExecutablePair::new(current.as_fd(), retained.as_fd())?;
        self.verify(current.as_fd(), role)?;
        pair.finish()
    }
    #[cfg(test)]
    pub fn init(&self) -> Result<(&str, u64)> {
        let e = self.entry(Role::GatewayInit)?;
        Ok((&e.sha256, e.bytes))
    }
    pub fn monitor_digest(&self) -> Result<&str> {
        Ok(&self.entry(Role::WorkerMonitor)?.sha256)
    }
    pub fn worker_digest(&self) -> Result<&str> {
        Ok(&self.entry(Role::WorkerObserver)?.sha256)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileFingerprint([u64; 14]);
impl FileFingerprint {
    fn read(fd: impl AsFd) -> Result<Self> {
        let s = fs::fstat(fd).map_err(|_| Error::ExecutableMismatch)?;
        // atime is deliberately excluded: our own fresh pread can update it.
        // All identity, ownership, permission, size, allocation and modification
        // metadata are bound for BOTH descriptors before and after hashing.
        Ok(Self([
            s.st_dev,
            s.st_ino,
            s.st_mode as u64,
            s.st_uid as u64,
            s.st_gid as u64,
            s.st_nlink as u64,
            s.st_size as u64,
            s.st_rdev,
            s.st_blocks as u64,
            s.st_blksize as u64,
            s.st_mtime as u64,
            s.st_mtime_nsec as u64,
            s.st_ctime as u64,
            s.st_ctime_nsec as u64,
        ]))
    }
}
struct ExecutablePair<'a> {
    current: BorrowedFd<'a>,
    retained: BorrowedFd<'a>,
    fingerprint: FileFingerprint,
}
impl<'a> ExecutablePair<'a> {
    fn new(current: BorrowedFd<'a>, retained: BorrowedFd<'a>) -> Result<Self> {
        let fingerprint = FileFingerprint::read(current)?;
        if FileFingerprint::read(retained)? != fingerprint {
            return Err(Error::ExecutableMismatch);
        }
        Ok(Self {
            current,
            retained,
            fingerprint,
        })
    }
    fn finish(self) -> Result<()> {
        if FileFingerprint::read(self.current)? != self.fingerprint
            || FileFingerprint::read(self.retained)? != self.fingerprint
        {
            return Err(Error::ExecutableMismatch);
        }
        Ok(())
    }
}

fn verify(fd: impl AsFd, p: &Entry, architecture: &str) -> Result<()> {
    let before = fs::fstat(&fd).map_err(|_| Error::ExecutableMismatch)?;
    if before.st_uid != 0
        || before.st_gid != 0
        || before.st_mode & 0o7222 != 0
        || before.st_mode & 0o111 == 0
        || FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_size as u64 != p.bytes
    {
        return Err(Error::ExecutableMismatch);
    }
    let mut bytes = vec![0; p.bytes as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let n = rustix::io::pread(&fd, &mut bytes[offset..], offset as u64)
            .map_err(|_| Error::ExecutableMismatch)?;
        if n == 0 {
            return Err(Error::ExecutableMismatch);
        }
        offset += n;
    }
    super::process::elf(&bytes, architecture)?;
    if digest(&bytes) != p.sha256 {
        return Err(Error::ExecutableMismatch);
    }
    let after = fs::fstat(fd).map_err(|_| Error::ExecutableMismatch)?;
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        before.st_mtime,
        before.st_mtime_nsec,
        before.st_ctime,
        before.st_ctime_nsec,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mode,
        after.st_mtime,
        after.st_mtime_nsec,
        after.st_ctime,
        after.st_ctime_nsec,
    ) {
        return Err(Error::ExecutableMismatch);
    }
    Ok(())
}
impl Program {
    pub fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }
    pub fn revalidate(&self, bundle: &ReviewedBundle) -> Result<()> {
        if self.sha256 != bundle.entry(self.role)?.sha256
            || self.bytes != bundle.entry(self.role)?.bytes
        {
            return Err(Error::ExecutableMismatch);
        }
        bundle.verify(&self.fd, self.role)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn pair_file() -> OwnedFd {
        let fd =
            fs::memfd_create(c"vprouter-executable-pair-test", fs::MemfdFlags::CLOEXEC).unwrap();
        rustix::io::pwrite(&fd, b"same contents", 0).unwrap();
        fd
    }
    #[test]
    fn executable_pair_accepts_same_native_inode_and_rejects_identical_bytes_in_another_inode() {
        let current = pair_file();
        let retained = rustix::io::fcntl_dupfd_cloexec(&current, 3).unwrap();
        let pair = ExecutablePair::new(current.as_fd(), retained.as_fd()).unwrap();
        pair.finish().unwrap();
        let foreign = pair_file();
        assert!(ExecutablePair::new(current.as_fd(), foreign.as_fd()).is_err());
    }
    #[test]
    fn executable_pair_rejects_native_metadata_mutation_through_either_descriptor() {
        for mutate_current in [true, false] {
            for resize in [true, false] {
                let current = pair_file();
                let retained = rustix::io::fcntl_dupfd_cloexec(&current, 3).unwrap();
                let pair = ExecutablePair::new(current.as_fd(), retained.as_fd()).unwrap();
                let changed = if mutate_current { &current } else { &retained };
                if resize {
                    fs::ftruncate(changed, 99).unwrap();
                } else {
                    fs::fchmod(changed, Mode::RUSR).unwrap();
                }
                assert_eq!(pair.finish(), Err(Error::ExecutableMismatch));
            }
        }
    }
    #[test]
    fn fixed_monitor_role_is_separate_and_rejects_observer_or_argv_substitution() {
        if !cfg!(target_arch = "x86_64") {
            return;
        }
        let mut v: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../docs/rust-v2/programs-amd64.json"))
                .unwrap();
        v["programs"]
            .as_array_mut()
            .unwrap()
            .retain(|e| e["role"] != "worker_monitor");
        let entry = serde_json::json!({"role":"worker_monitor","path":"/usr/local/bin/vprouter-worker-monitor",
            "sha256":"a".repeat(64),"bytes":128,"policy":"guard-bound-monitor-zero-caps-private-root-v1"});
        v["programs"].as_array_mut().unwrap().push(entry);
        assert!(ReviewedBundle::decode(&serde_json::to_vec(&v).unwrap()).is_ok());
        for (field, value) in [
            (
                "path",
                serde_json::json!("/usr/local/bin/vprouter-worker-observe"),
            ),
            (
                "policy",
                serde_json::json!("observation-only-zero-caps-private-root-v2"),
            ),
            ("argv", serde_json::json!(["/bin/sh"])),
        ] {
            let mut changed = v.clone();
            changed["programs"][3][field] = value;
            assert!(ReviewedBundle::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let duplicate = v["programs"][3].clone();
        v["programs"].as_array_mut().unwrap().push(duplicate);
        assert!(ReviewedBundle::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    #[test]
    fn fixed_bundle_rejects_program_policy_platform_and_duplicate_substitution() {
        let original = include_bytes!("../../../docs/rust-v2/programs-amd64.json");
        if !cfg!(target_arch = "x86_64") {
            return;
        }
        assert!(ReviewedBundle::current().is_ok());
        let mut v: serde_json::Value = serde_json::from_slice(original).unwrap();
        for key in ["path", "policy"] {
            let saved = v["programs"][0][key].clone();
            v["programs"][0][key] = "substitute".into();
            assert!(ReviewedBundle::decode(&serde_json::to_vec(&v).unwrap()).is_err());
            v["programs"][0][key] = saved;
        }
        v["programs"][0]["argv"] = serde_json::json!(["/bin/sh"]);
        assert!(ReviewedBundle::decode(&serde_json::to_vec(&v).unwrap()).is_err());
        v["programs"][0].as_object_mut().unwrap().remove("argv");
        v["programs"][1]["role"] = "worker_observer".into();
        assert!(ReviewedBundle::decode(&serde_json::to_vec(&v).unwrap()).is_err());
        let mut v: serde_json::Value = serde_json::from_slice(original).unwrap();
        v["base_platform"] = format!("sha256:{}", "a".repeat(64)).into();
        assert!(ReviewedBundle::decode(&serde_json::to_vec(&v).unwrap()).is_err());
    }
}
