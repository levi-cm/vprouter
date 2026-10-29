//! Protected, authored public uplink selection. Neither the declaration nor a
//! matching observation supplies resource ownership, a host model, or a permit.
use super::super::{inventory, secret::InputIdentity};
use super::{Error, Identity, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    os::fd::{AsFd, OwnedFd},
    path::Path,
    rc::Rc,
};
use vprouter_core::allocation::AllocationRecord;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Wan {
    pub(super) name: String,
    pub(super) index: u32,
    pub(super) address: [u8; 6],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Declaration {
    schema_version: u8,
    deployment_id: String,
    generation: u64,
    member: String,
    allocation_digest: String,
    host_namespace: Identity,
    wan: Wan,
}
impl Declaration {
    fn verify(&self, allocation: &AllocationRecord, member: &str, host: Identity) -> Result<()> {
        let encoded = serde_json::to_vec(allocation).map_err(|_| Error::InvalidSpec)?;
        if self.schema_version != 1
            || self.deployment_id != allocation.deployment_id
            || self.generation != allocation.generation
            || self.member != member
            || !allocation.exits.iter().any(|a| a.exit_id == member)
            || self.allocation_digest != vprouter_worker::bootstrap::digest(&encoded)
            || self.host_namespace != host
            || host.ino == 0
            || self.wan.index == 0
            || self.wan.name.is_empty()
            || self.wan.name.len() > 15
            || !self
                .wan
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || matches!(self.wan.name.as_str(), "lo" | "tailscale0")
            || self.wan.address == [0; 6]
            || self.wan.address[0] & 1 != 0
            || allocation.exits.iter().any(|a| {
                a.host_interface == self.wan.name
                    || a.data_interface == self.wan.name
                    || a.wireguard_interface.as_deref() == Some(self.wan.name.as_str())
            })
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
pub(super) struct PinnedDeclaration {
    creator: u32,
    declaration: Declaration,
    digest: [u8; 32],
    identity: InputIdentity,
    registration: inventory::Registration,
    file: OwnedFd,
}
impl PinnedDeclaration {
    pub(super) fn load(
        path: &Path,
        allocation: &AllocationRecord,
        member: &str,
        host: Identity,
    ) -> Result<Self> {
        if !vprouter_core::secret_boundary::pristine() {
            return Err(Error::ConfinementPolicy);
        }
        let file = vprouter_linux::storage::pin_secret(path).map_err(|_| Error::UnsafeInput)?;
        let registration = inventory::Registration::owned(&[file.as_fd()])?;
        let identity = InputIdentity::capture(&file, 0)?;
        if identity.size == 0 || identity.size > 4096 {
            return Err(Error::TooLarge);
        }
        let mut bytes = vec![0; identity.size as usize + 1];
        let count =
            rustix::io::pread(&file, bytes.as_mut_slice(), 0).map_err(|_| Error::UnsafeInput)?;
        identity.verify(&file)?;
        if count != identity.size as usize {
            return Err(Error::UnsafeInput);
        }
        bytes.truncate(count);
        let declaration: Declaration =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidSpec)?;
        declaration.verify(allocation, member, host)?;
        let digest = sha2::Sha256::digest(&bytes).into();
        Ok(Self {
            creator: std::process::id(),
            declaration,
            digest,
            identity,
            registration,
            file,
        })
    }
    pub(super) fn verify(
        &self,
        allocation: &AllocationRecord,
        member: &str,
        host: Identity,
    ) -> Result<()> {
        if self.creator != std::process::id()
            || !vprouter_core::secret_boundary::pristine()
            || !self.registration.contains(self.file.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        self.identity.verify(&self.file)?;
        self.declaration.verify(allocation, member, host)
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(super) fn wan(&self) -> &Wan {
        &self.declaration.wan
    }
    fn verify_wan_input(&self, observer: &vprouter_network::RouteObserver) -> Result<()> {
        if self.creator != std::process::id()
            || !vprouter_core::secret_boundary::pristine()
            || !self.registration.contains(self.file.as_fd())
        {
            return Err(Error::OwnershipMismatch);
        }
        self.identity.verify(&self.file)?;
        let host = self.declaration.host_namespace;
        if observer.namespace_identity() != (host.dev, host.ino) {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn begin_wan(
        self: &Rc<Self>,
        observer: &mut vprouter_network::RouteObserver,
        end: f64,
    ) -> Result<PendingWan> {
        self.verify_wan_input(observer)?;
        let w = self.wan();
        let read = observer
            .start_declared_wan_read(&w.name, w.index, w.address, end)
            .map_err(|_| Error::NetworkOperation)?;
        Ok(PendingWan {
            declaration: self.clone(),
            read,
            end,
            verified_at: None,
        })
    }
}
/// Holds the exact original protected declaration through the entire read.
/// A successful comparison is not a host resource or activation capability.
pub(super) struct PendingWan {
    declaration: Rc<PinnedDeclaration>,
    read: vprouter_network::DeclaredWanRead,
    end: f64,
    verified_at: Option<f64>,
}
impl PendingWan {
    pub(super) fn accepted(&self) -> Result<Rc<VerifiedWan>> {
        let at = self.verified_at.ok_or(Error::OwnershipMismatch)?;
        let value = Rc::new(VerifiedWan {
            declaration: self.declaration.clone(),
            end: self.end,
            at,
        });
        value.verify(&self.declaration, self.end)?;
        Ok(value)
    }
    pub(super) fn poll(&mut self, observer: &mut vprouter_network::RouteObserver) -> Result<bool> {
        self.declaration.verify_wan_input(observer)?;
        let done = observer
            .poll_declared_wan_read(&mut self.read)
            .map_err(|_| Error::NetworkOperation)?;
        self.declaration.verify_wan_input(observer)?;
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now >= self.end {
            return Err(Error::Deadline);
        }
        if done {
            self.verified_at = Some(now);
        }
        Ok(done)
    }
}

/// Authored identity observed by one original bounded route read. No resource
/// ownership, host model or activation permission is represented here.
pub(super) struct VerifiedWan {
    declaration: Rc<PinnedDeclaration>,
    end: f64,
    at: f64,
}
impl VerifiedWan {
    pub(super) fn verify(&self, declaration: &Rc<PinnedDeclaration>, end: f64) -> Result<()> {
        let now = vprouter_core::health::boot_seconds();
        if !Rc::ptr_eq(&self.declaration, declaration)
            || self.end != end
            || !self.at.is_finite()
            || self.at < end - 2.
            || self.at >= end
            || !now.is_finite()
            || now < self.at
            || now >= end
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
impl PendingWan {
    pub(super) fn lab_evidence(
        &self,
        observer: &vprouter_network::RouteObserver,
    ) -> Result<serde_json::Value> {
        self.declaration.verify_wan_input(observer)?;
        let at = self.verified_at.ok_or(Error::OwnershipMismatch)?;
        if !at.is_finite() || at < self.end - 2. || at >= self.end {
            return Err(Error::OwnershipMismatch);
        }
        let w = self.declaration.wan();
        Ok(
            serde_json::json!({"declaration_digest":self.declaration.digest(),"host_namespace":self.declaration.declaration.host_namespace,
            "name":w.name,"index":w.index,"address":w.address,"requested_at":self.end-2.,"deadline":self.end,"verified_at":at,"original_observer_retained":true}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_host_declaration_binds_exact_allocation_member_and_original_namespace() {
        let allocation = crate::tests::record();
        let host = Identity { dev: 4, ino: 99 };
        let d = Declaration {
            schema_version: 1,
            deployment_id: allocation.deployment_id.clone(),
            generation: allocation.generation,
            member: allocation.exits[0].exit_id.clone(),
            allocation_digest: vprouter_worker::bootstrap::digest(
                &serde_json::to_vec(&allocation).unwrap(),
            ),
            host_namespace: host,
            wan: Wan {
                name: "ens2".into(),
                index: 2,
                address: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
            },
        };
        assert!(d.verify(&allocation, &d.member, host).is_ok());
        assert!(d.verify(&allocation, "another", host).is_err());
        assert!(
            d.verify(&allocation, &d.member, Identity { dev: 4, ino: 100 })
                .is_err()
        );
        for changed in [
            "schema_version",
            "generation",
            "allocation_digest",
            "host_namespace",
            "extra",
        ] {
            let mut value = serde_json::to_value(&d).unwrap();
            value[changed] = match changed {
                "schema_version" | "generation" => serde_json::json!(2),
                "allocation_digest" => serde_json::json!("0".repeat(64)),
                "host_namespace" => serde_json::json!({"dev":4,"ino":100}),
                _ => serde_json::json!(true),
            };
            let result = serde_json::from_value::<Declaration>(value);
            assert!(
                result.is_err()
                    || result
                        .unwrap()
                        .verify(&allocation, &d.member, host)
                        .is_err()
            );
        }
        for name in [
            "lo",
            "tailscale0",
            "../ens2",
            &allocation.exits[0].host_interface,
        ] {
            let mut bad = d.clone();
            bad.wan.name = name.into();
            assert!(bad.verify(&allocation, &d.member, host).is_err());
        }
        let mut bad = d.clone();
        bad.wan.address[0] |= 1;
        assert!(bad.verify(&allocation, &d.member, host).is_err());
    }
}
