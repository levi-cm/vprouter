//! Descriptor-relative ownership/type checks, with no path-creation side effects.
use crate::{Error, Result};
use rustix::fs::{FileType, Mode, OFlags, fstat, fsync, open, openat};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path},
};

#[derive(Clone, Copy)]
pub enum Kind {
    PublicFile,
    SecretFile,
    PrivateDirectory,
    ReleaseDirectory,
    DockerSocket,
    TunDevice,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub uid: u32,
    pub mode: u32,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub modified_seconds: i64,
}
fn components(path: &Path) -> Result<Vec<&std::ffi::OsStr>> {
    let text = path.to_str().ok_or(Error::UnsafePath)?;
    if !path.is_absolute()
        || text.contains('\0')
        || text != "/"
            && text
                .split('/')
                .skip(1)
                .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(Error::UnsafePath);
    }
    path.components()
        .filter_map(|p| match p {
            Component::RootDir => None,
            Component::Normal(s) => Some(Ok(s)),
            _ => Some(Err(Error::UnsafePath)),
        })
        .collect()
}
fn check(fd: &OwnedFd, kind: Kind, uid: u32) -> Result<Metadata> {
    let st = fstat(fd).map_err(|_| Error::Unavailable)?;
    let ty = FileType::from_raw_mode(st.st_mode);
    let expected = match kind {
        Kind::PrivateDirectory | Kind::ReleaseDirectory => FileType::Directory,
        Kind::DockerSocket => FileType::Socket,
        Kind::TunDevice => FileType::CharacterDevice,
        _ => FileType::RegularFile,
    };
    if st.st_uid != uid
        || ty != expected
        || !matches!(kind, Kind::DockerSocket | Kind::TunDevice) && st.st_mode & 0o022 != 0
        || st.st_mode & 0o7000 != 0
        || matches!(kind, Kind::TunDevice) && st.st_rdev != rustix::fs::makedev(10, 200)
        || matches!(kind, Kind::SecretFile) && st.st_mode & 0o177 != 0
        || matches!(kind, Kind::PrivateDirectory) && st.st_mode & 0o077 != 0
        || matches!(kind, Kind::SecretFile | Kind::PublicFile) && st.st_nlink != 1
    {
        return Err(Error::UnsafePath);
    }
    Ok(Metadata {
        uid: st.st_uid,
        mode: st.st_mode & 0o7777,
        device: st.st_dev,
        inode: st.st_ino,
        size: st.st_size.try_into().map_err(|_| Error::UnsafePath)?,
        modified_seconds: st.st_mtime,
    })
}
fn descend(mut dir: OwnedFd, parts: &[&std::ffi::OsStr], kind: Kind, uid: u32) -> Result<OwnedFd> {
    check(&dir, Kind::ReleaseDirectory, uid)?;
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        let directory = !last || matches!(kind, Kind::PrivateDirectory | Kind::ReleaseDirectory);
        let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        if last && matches!(kind, Kind::DockerSocket | Kind::TunDevice) {
            flags = OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW;
        }
        if directory {
            flags |= OFlags::DIRECTORY;
        }
        let next = openat(&dir, *part, flags, Mode::empty()).map_err(|_| Error::UnsafePath)?;
        check(&next, if last { kind } else { Kind::ReleaseDirectory }, uid)?;
        dir = next;
    }
    if parts.is_empty() {
        check(&dir, kind, uid)?;
    }
    Ok(dir)
}
fn root() -> Result<OwnedFd> {
    open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::Unavailable)
}
fn checked_open(path: &Path, kind: Kind) -> Result<OwnedFd> {
    descend(root()?, &components(path)?, kind, 0)
}
pub fn metadata(path: &Path, kind: Kind) -> Result<Metadata> {
    check(&checked_open(path, kind)?, kind, 0)
}
pub fn read(path: &Path, kind: Kind, limit: usize) -> Result<Vec<u8>> {
    read_fd(checked_open(path, kind)?, limit)
}
fn read_fd(fd: OwnedFd, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::from(fd)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() > limit {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}
fn write_new(parent: OwnedFd, name: &std::ffi::OsStr, bytes: &[u8], uid: u32) -> Result<()> {
    check(&parent, Kind::ReleaseDirectory, uid)?;
    let fd = openat(
        &parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| Error::OutputExistsOrUnsafe)?;
    check(&fd, Kind::SecretFile, uid)?;
    let mut file = File::from(fd);
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::OutputDurabilityUncertain)?;
    fsync(&parent).map_err(|_| Error::OutputDurabilityUncertain)
}
/// Only explicit plan artifacts use this API; it never creates parent directories.
pub fn write_plan(path: &Path, bytes: &[u8]) -> Result<()> {
    let parts = components(path)?;
    let (name, parents) = parts.split_last().ok_or(Error::UnsafePath)?;
    let parent = descend(root()?, parents, Kind::ReleaseDirectory, 0)?;
    write_new(parent, name, bytes, 0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, fs::symlink},
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    pub(crate) struct Temp(pub PathBuf);
    impl Temp {
        pub(crate) fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "vprouter-host-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn root(&self) -> OwnedFd {
            open(
                &self.0,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .unwrap()
        }
        pub(crate) fn uid(&self) -> u32 {
            fstat(self.root()).unwrap().st_uid
        }
        fn get(&self, part: &str, kind: Kind) -> Result<OwnedFd> {
            descend(self.root(), &[std::ffi::OsStr::new(part)], kind, self.uid())
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn rejects_symlink_components_permissions_types_and_hardlinks() {
        let t = Temp::new();
        fs::write(t.0.join("secret"), b"synthetic").unwrap();
        fs::set_permissions(t.0.join("secret"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(t.get("secret", Kind::SecretFile).is_ok());
        assert!(
            descend(
                t.root(),
                &[std::ffi::OsStr::new("secret")],
                Kind::SecretFile,
                t.uid().wrapping_add(1)
            )
            .is_err()
        );
        assert!(t.get("secret", Kind::PrivateDirectory).is_err());
        fs::set_permissions(t.0.join("secret"), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(t.get("secret", Kind::SecretFile).is_err());
        fs::set_permissions(t.0.join("secret"), fs::Permissions::from_mode(0o600)).unwrap();
        symlink("secret", t.0.join("alias")).unwrap();
        assert!(t.get("alias", Kind::SecretFile).is_err());
        fs::create_dir(t.0.join("dir")).unwrap();
        symlink("dir", t.0.join("linkdir")).unwrap();
        assert!(
            descend(
                t.root(),
                &[std::ffi::OsStr::new("linkdir"), std::ffi::OsStr::new("x")],
                Kind::PublicFile,
                t.uid()
            )
            .is_err()
        );
        fs::hard_link(t.0.join("secret"), t.0.join("hardlink")).unwrap();
        assert!(t.get("secret", Kind::SecretFile).is_err());
        assert!(t.get("missing", Kind::PublicFile).is_err());
        assert!(!t.0.join("missing").exists());
    }
    #[test]
    fn output_is_exclusive_private_and_durable() {
        let t = Temp::new();
        let name = std::ffi::OsStr::new("plan");
        write_new(t.root(), name, b"first", t.uid()).unwrap();
        assert_eq!(
            fs::metadata(t.0.join("plan")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            write_new(t.root(), name, b"second", t.uid()),
            Err(Error::OutputExistsOrUnsafe)
        );
        assert_eq!(fs::read(t.0.join("plan")).unwrap(), b"first");
        symlink("plan", t.0.join("alias")).unwrap();
        assert_eq!(
            write_new(t.root(), std::ffi::OsStr::new("alias"), b"second", t.uid()),
            Err(Error::OutputExistsOrUnsafe)
        );
    }
    #[test]
    fn bounded_reads_and_lexical_paths() {
        let t = Temp::new();
        fs::write(t.0.join("file"), b"abcd").unwrap();
        fs::set_permissions(t.0.join("file"), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_fd(t.get("file", Kind::PublicFile).unwrap(), 3),
            Err(Error::TooLarge)
        );
        for p in ["relative", "/tmp/../x", "/tmp//x", "/tmp/./x", "/tmp/x/"] {
            assert!(components(Path::new(p)).is_err());
        }
    }
}
