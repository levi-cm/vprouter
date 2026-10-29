//! Authored full generation baseline, distinct from the WAN-only selector.
//! A parsed shape is a declaration; it never supplies a completed native read.
use super::super::{inventory, kernel};
use super::{Error, Identity, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    os::fd::{AsFd, AsRawFd, OwnedFd},
    path::Path,
    rc::Rc,
};
use vprouter_core::allocation::AllocationRecord;

const MAX_BASELINE_BYTES: u64 = 256 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Shape {
    namespace: (u64, u64),
    links: Vec<vprouter_network::Link>,
    addresses: Vec<vprouter_network::Address>,
    routes: Vec<vprouter_network::Route>,
    rules: Vec<vprouter_network::Rule>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    schema_version: u8,
    deployment_id: String,
    generation: u64,
    allocation_digest: String,
    host_namespace: Identity,
    baseline: Shape,
}
impl Declaration {
    fn observation(&self) -> Result<vprouter_network::HostObservation> {
        let bytes = serde_json::to_vec(&self.baseline).map_err(|_| Error::InvalidSpec)?;
        vprouter_network::HostObservation::decode(&bytes).map_err(|_| Error::InvalidSpec)
    }
    fn verify(&self, record: &AllocationRecord, host: Identity) -> Result<()> {
        record
            .validate(&record.deployment_id, &[])
            .map_err(|_| Error::InvalidSpec)?;
        if self.schema_version != 1
            || self.deployment_id != record.deployment_id
            || self.generation != record.generation
            || self.allocation_digest
                != vprouter_worker::bootstrap::digest(
                    &serde_json::to_vec(record).map_err(|_| Error::InvalidSpec)?,
                )
            || self.host_namespace != host
            || host.dev == 0
            || host.ino == 0
            || self.baseline.namespace != (host.dev, host.ino)
            || self.baseline.links.iter().any(|l| {
                l.alias
                    .starts_with(&format!("vprouter-v2:{}:", record.deployment_id))
            })
        {
            return Err(Error::OwnershipMismatch);
        }
        self.observation()?;
        Ok(())
    }
}

/// Separate public-file stamp: its larger limit does not change secret/profile
/// input limits. Every comparison includes original ctime/mtime and permissions.
#[derive(PartialEq, Eq)]
struct Stamp {
    identity: Identity,
    size: u64,
    mode: u32,
    modified: (i64, u64),
    changed: (i64, u64),
}
impl Stamp {
    fn capture(fd: &OwnedFd) -> Result<Self> {
        let s = rustix::fs::fstat(fd).map_err(|_| Error::UnsafeInput)?;
        if rustix::fs::FileType::from_raw_mode(s.st_mode) != rustix::fs::FileType::RegularFile
            || s.st_uid != 0
            || s.st_gid != 0
            || s.st_nlink != 1
            || s.st_mode & 0o7777 != 0o600
            || s.st_ino == 0
            || s.st_size <= 0
            || s.st_size as u64 > MAX_BASELINE_BYTES
            || !kernel::descriptor_cloexec(fd.as_raw_fd())?
        {
            return Err(Error::UnsafeInput);
        }
        Ok(Self {
            identity: Identity {
                dev: s.st_dev,
                ino: s.st_ino,
            },
            size: s.st_size as u64,
            mode: s.st_mode,
            modified: (s.st_mtime, s.st_mtime_nsec),
            changed: (s.st_ctime, s.st_ctime_nsec),
        })
    }
}
pub(super) struct PinnedBaseline {
    creator: u32,
    declaration: Declaration,
    digest: [u8; 32],
    stamp: Stamp,
    registration: inventory::Registration,
    file: OwnedFd,
}
impl PinnedBaseline {
    pub(super) fn load(path: &Path, record: &AllocationRecord, host: Identity) -> Result<Rc<Self>> {
        if !vprouter_core::secret_boundary::pristine() {
            return Err(Error::ConfinementPolicy);
        }
        let file = vprouter_linux::storage::pin_secret(path).map_err(|_| Error::UnsafeInput)?;
        let registration = inventory::Registration::owned(&[file.as_fd()])?;
        let stamp = Stamp::capture(&file)?;
        let mut bytes = vec![0; stamp.size as usize + 1];
        let size = rustix::io::pread(&file, &mut bytes, 0).map_err(|_| Error::UnsafeInput)?;
        if stamp != Stamp::capture(&file)? || size != stamp.size as usize {
            return Err(Error::OwnershipMismatch);
        }
        bytes.truncate(size);
        let declaration: Declaration =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidSpec)?;
        declaration.verify(record, host)?;
        Ok(Rc::new(Self {
            creator: std::process::id(),
            declaration,
            digest: sha2::Sha256::digest(&bytes).into(),
            stamp,
            registration,
            file,
        }))
    }
    pub(super) fn verify(&self, record: &AllocationRecord, host: Identity) -> Result<()> {
        if self.creator != std::process::id()
            || !vprouter_core::secret_boundary::pristine()
            || !self.registration.contains(self.file.as_fd())
            || self.stamp != Stamp::capture(&self.file)?
        {
            return Err(Error::OwnershipMismatch);
        }
        self.declaration.verify(record, host)
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(super) fn observation(
        &self,
        record: &AllocationRecord,
        host: Identity,
    ) -> Result<vprouter_network::HostObservation> {
        self.verify(record, host)?;
        self.declaration.observation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authored_host_baseline_binds_complete_generation_and_both_namespace_fields() {
        let record = crate::tests::record();
        let host = Identity { dev: 4, ino: 99 };
        let value = serde_json::json!({"schema_version":1,
            "deployment_id":record.deployment_id,"generation":record.generation,
            "allocation_digest":vprouter_worker::bootstrap::digest(&serde_json::to_vec(&record).unwrap()),
            "host_namespace":host,"baseline":{"namespace":[4,99],"links":[],"addresses":[],"routes":[],"rules":[]}});
        let declaration: Declaration = serde_json::from_value(value.clone()).unwrap();
        declaration.verify(&record, host).unwrap();
        for field in [
            "schema_version",
            "deployment_id",
            "generation",
            "allocation_digest",
            "host_namespace",
            "baseline",
            "extra",
        ] {
            let mut changed = value.clone();
            changed[field] = match field {
                "schema_version" | "generation" => serde_json::json!(999),
                "deployment_id" => serde_json::json!("another"),
                "allocation_digest" => serde_json::json!("0".repeat(64)),
                "host_namespace" => serde_json::json!({"dev":4,"ino":100}),
                "baseline" => {
                    let mut b = changed["baseline"].clone();
                    b["namespace"] = serde_json::json!([4, 100]);
                    b
                }
                _ => serde_json::json!(true),
            };
            let parsed = serde_json::from_value::<Declaration>(changed);
            assert!(
                parsed.is_err() || parsed.unwrap().verify(&record, host).is_err(),
                "{field}"
            );
        }
        let mut changed_record = record.clone();
        changed_record.exits[0].state_dir = "/different".into();
        assert!(declaration.verify(&changed_record, host).is_err());
        let mut unknown = value.clone();
        unknown["baseline"]["wireguard"] = serde_json::json!({});
        assert!(serde_json::from_value::<Declaration>(unknown).is_err());
        let text = serde_json::to_string(&value).unwrap().replacen(
            "\"namespace\":[4,99]",
            "\"namespace\":[4,99],\"namespace\":[4,99]",
            1,
        );
        assert!(serde_json::from_str::<Declaration>(&text).is_err());
    }
}
