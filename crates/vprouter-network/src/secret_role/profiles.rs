//! Original input descriptors are held without reading in the parent. Only the
//! installed fixed WireGuard child reloads them and compares the entire public
//! validation result, including disabled exits and clamped duplicate-key rules.
use crate::{Error, Result};
use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Path, PathBuf},
};
use vprouter_core::{
    config::{Configuration, Mode, PublicConfiguration, ValidatedConfiguration},
    profile::{MAX_PROFILE_BYTES, Profile},
};
use vprouter_native_role::ConfinedWireguard;

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    size: i64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    modified: (i64, u64),
    changed: (i64, u64),
}
impl Stamp {
    fn capture(fd: BorrowedFd<'_>) -> Result<Self> {
        let s = rustix::fs::fstat(fd).map_err(|_| Error::Foreign)?;
        if s.st_uid != 0
            || s.st_gid != 0
            || s.st_nlink != 1
            || s.st_size < 0
            || s.st_size as usize > MAX_PROFILE_BYTES
            || !matches!(s.st_mode & 0o7777, 0o400 | 0o600)
            || rustix::fs::FileType::from_raw_mode(s.st_mode) != rustix::fs::FileType::RegularFile
            || !rustix::io::fcntl_getfd(fd)
                .map_err(|_| Error::Foreign)?
                .contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(Error::Foreign);
        }
        // Linux stat nlink is u32 on aarch64 and u64 on x86_64.
        #[allow(clippy::useless_conversion)]
        let nlink = u64::from(s.st_nlink);
        Ok(Self {
            dev: s.st_dev,
            ino: s.st_ino,
            size: s.st_size,
            mode: s.st_mode,
            uid: s.st_uid,
            gid: s.st_gid,
            nlink,
            modified: (s.st_mtime, s.st_mtime_nsec),
            changed: (s.st_ctime, s.st_ctime_nsec),
        })
    }
    fn verify(&self, fd: BorrowedFd<'_>) -> Result<()> {
        if Self::capture(fd)? != *self {
            return Err(Error::Drifted);
        }
        Ok(())
    }
}
struct Input {
    member: String,
    path: PathBuf,
    original: Stamp,
    fd: OwnedFd,
}
pub(super) struct Profiles {
    creator: u32,
    configuration: Configuration,
    expected: Vec<u8>,
    inputs: Vec<Input>,
    member: String,
}
impl Profiles {
    /// Caller supplies original protected pins in configuration order. Launch
    /// must check its original admitted InputIdentity before and after this
    /// metadata-only preparation; no profile hash/read is used by the parent.
    pub(super) fn pin(
        public: &PublicConfiguration,
        member: &str,
        profiles: &[(String, BorrowedFd<'_>)],
    ) -> Result<Self> {
        if !vprouter_core::secret_boundary::pristine() {
            return Err(Error::NamespaceUnverified);
        }
        let configuration = public.configuration().clone();
        let expected = public
            .public_report()
            .and_then(|r| r.encode())
            .map_err(|_| Error::InvalidInput)?;
        if !public
            .exits()
            .iter()
            .any(|e| e.exit().id == member && e.profile().is_some())
        {
            return Err(Error::InvalidInput);
        }
        let requested: Vec<_> = configuration
            .exits
            .iter()
            .filter_map(|e| match &e.mode {
                Mode::Mullvad { profile, .. } => Some((&e.id, profile)),
                Mode::Direct {} => None,
            })
            .collect();
        if requested.len() != profiles.len() {
            return Err(Error::Foreign);
        }
        let mut inputs = Vec::with_capacity(profiles.len());
        for ((id, path), (given, fd)) in requested.into_iter().zip(profiles) {
            if id != given {
                return Err(Error::Foreign);
            }
            let original = Stamp::capture(*fd)?;
            let fd = fd.try_clone_to_owned().map_err(|_| Error::Io)?;
            original.verify(fd.as_fd())?;
            inputs.push(Input {
                member: id.clone(),
                path: path.clone(),
                original,
                fd,
            });
        }
        Ok(Self {
            creator: std::process::id(),
            configuration,
            expected,
            inputs,
            member: member.to_owned(),
        })
    }
    pub(super) fn descriptors(&self) -> Result<Vec<BorrowedFd<'_>>> {
        self.verify_parent()?;
        Ok(self.inputs.iter().map(|i| i.fd.as_fd()).collect())
    }
    pub(super) fn verify_parent(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::NamespaceUnverified);
        }
        for input in &self.inputs {
            input.original.verify(input.fd.as_fd())?;
        }
        Ok(())
    }
    pub(super) fn member(&self) -> &str {
        &self.member
    }
    pub(super) fn load(&self, role: &ConfinedWireguard) -> Result<ValidatedConfiguration> {
        role.require().map_err(super::mapped)?;
        if self.creator == std::process::id() {
            return Err(Error::NamespaceUnverified);
        }
        let fds = role.profile_descriptors().map_err(super::mapped)?;
        if fds.len() != self.inputs.len() {
            return Err(Error::Foreign);
        }
        let mut next = self.inputs.iter().zip(fds);
        // The marker is supplemental. The role's fixed kernel filter is already
        // installed and rejects fork/exec before the FIRST protected pread.
        vprouter_core::secret_boundary::mark_ingress();
        let error =
            || vprouter_core::reason::Error::new(vprouter_core::reason::Reason::ProfileUnavailable);
        let validated = self
            .configuration
            .clone()
            .validate_with(|path, server| {
                let (input, fd) = next.next().ok_or_else(error)?;
                if path != input.path
                    || !self
                        .configuration
                        .exits
                        .iter()
                        .any(|e| e.id == input.member)
                {
                    return Err(error());
                }
                role.require().map_err(|_| error())?;
                input.original.verify(fd).map_err(|_| error())?;
                let mut bytes = zeroize::Zeroizing::new(vec![0u8; MAX_PROFILE_BYTES + 1]);
                let mut length = 0;
                loop {
                    role.require().map_err(|_| error())?;
                    let n = rustix::io::pread(fd, &mut bytes[length..], length as u64)
                        .map_err(|_| error())?;
                    role.require().map_err(|_| error())?;
                    if n == 0 {
                        break;
                    }
                    length += n;
                    if length > MAX_PROFILE_BYTES {
                        return Err(error());
                    }
                }
                input.original.verify(fd).map_err(|_| error())?;
                reload_profile(&bytes[..length], server, path)
            })
            .map_err(|_| Error::InvalidInput)?;
        if next.next().is_some() {
            return Err(Error::Foreign);
        }
        let report = validated
            .public_report()
            .and_then(|r| r.encode())
            .map_err(|_| Error::InvalidInput)?;
        if report != self.expected {
            return Err(Error::Drifted);
        }
        role.require().map_err(super::mapped)?;
        Ok(validated)
    }
}

// Kept as the exact reload parser seam so report parity includes source hints.
fn reload_profile(
    bytes: &[u8],
    server: &str,
    path: &Path,
) -> vprouter_core::reason::Result<Profile> {
    Profile::parse(bytes, server, Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    const PROFILE: &str = "[Interface]\nPrivateKey=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress=10.64.0.2/32\n[Peer]\nPublicKey=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint=185.66.0.1:51820\nAllowedIPs=0.0.0.0/0\n";
    fn configuration() -> Configuration {
        Configuration::parse(&serde_json::to_vec(&serde_json::json!({
            "schema_version":2,"deployment_id":"reloadlab","site":"debdev",
            "gateway_image":format!("sha256:{}","a".repeat(64)),
            "exits":[
                {"id":"primary","enabled":true,"state_dir":"/state/primary","mode":{"kind":"mullvad","profile":"/profiles/primary/de-fra-wg-404.conf","expected_server":"de-fra-wg-404"}},
                {"id":"disabled","enabled":false,"state_dir":"/state/disabled","mode":{"kind":"mullvad","profile":"/profiles/disabled/de-fra-wg-404.conf","expected_server":"de-fra-wg-404"}}
            ],"dependency_adapters":[],"client_policies":[]
        })).unwrap()).unwrap()
    }
    fn input(path: &Path, comment: bool) -> String {
        let mut value = PROFILE.to_owned();
        if path.to_string_lossy().contains("/disabled/") {
            value = value.replace(
                "PrivateKey=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "PrivateKey=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            );
        }
        if comment {
            value.push_str("# Server: de-fra-wg-404\n");
        }
        value
    }
    #[test]
    fn reload_preserves_initial_whole_report_with_filename_only_and_disabled_profile() {
        for comment in [false, true] {
            let cfg = configuration();
            let original = cfg
                .clone()
                .validate_with(|path, server| {
                    Profile::parse(input(path, comment).as_bytes(), server, Some(path))
                })
                .unwrap();
            let reloaded = cfg
                .validate_with(|path, server| {
                    reload_profile(input(path, comment).as_bytes(), server, path)
                })
                .unwrap();
            assert!(
                original
                    .exits()
                    .iter()
                    .all(|e| e.profile().unwrap().has_matching_server_hint())
            );
            assert_eq!(
                original.public_report().unwrap().encode().unwrap(),
                reloaded.public_report().unwrap().encode().unwrap()
            );
        }
    }
    #[test]
    fn reload_rejects_conflicting_protected_filename_even_with_matching_comment() {
        let path = Path::new("/profiles/de-fra-wg-405.conf");
        for comment in [false, true] {
            let bytes = input(path, comment);
            assert!(Profile::parse(bytes.as_bytes(), "de-fra-wg-404", Some(path)).is_err());
            assert!(reload_profile(bytes.as_bytes(), "de-fra-wg-404", path).is_err());
        }
    }
}
