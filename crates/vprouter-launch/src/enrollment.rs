#![forbid(unsafe_code)]
//! Protected authorization for ONE preserved enrollment and exact live allocation.
//! Public node/address data is never inferred from a daemon's current state.
use super::{Error, LaunchSpec, Result, programs::ReviewedBundle};
use serde::{Deserialize, Serialize};
use vprouter_worker::{bootstrap::digest, operation::Enrollment};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    container_id: String,
    allocation_sha256: String,
    manifest_sha256: String,
    enrollment: Enrollment,
}
pub(super) struct AuthorizedEnrollment {
    value: Enrollment,
    digest: String,
}
impl Document {
    fn bind(
        &self,
        spec: &LaunchSpec,
        bundle: &ReviewedBundle,
        expected: &vprouter_core::health::Binding,
    ) -> Result<()> {
        self.enrollment
            .validate(expected)
            .map_err(|_| Error::InvalidSpec)?;
        let allocation = serde_json::to_vec(&spec.allocation).map_err(|_| Error::InvalidSpec)?;
        if self.version != 1
            || self.container_id != spec.container_id
            || self.allocation_sha256 != digest(&allocation)
            || self.manifest_sha256 != bundle.digest()
            || expected.deployment_id != spec.allocation.deployment_id
            || expected.generation != spec.generation
            || expected.exit_id != spec.exit.exit_id
            || expected.mode != spec.exit.mode
        {
            return Err(Error::AllocationMismatch);
        }
        Ok(())
    }
}
impl AuthorizedEnrollment {
    pub fn load(
        spec: &LaunchSpec,
        bundle: &ReviewedBundle,
        expected: &vprouter_core::health::Binding,
    ) -> Result<Self> {
        let bytes = Self::read(spec)?;
        let document: Document = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidSpec)?;
        document.bind(spec, bundle, expected)?;
        Ok(Self {
            value: document.enrollment,
            digest: digest(&bytes),
        })
    }
    fn read(spec: &LaunchSpec) -> Result<Vec<u8>> {
        vprouter_linux::storage::read(
            &spec.exit.state_dir.join("enrollment.json"),
            vprouter_linux::storage::Kind::SecretFile,
            65536,
        )
        .map_err(|_| Error::UnsafeInput)
    }
    pub fn verify(&self, spec: &LaunchSpec) -> Result<()> {
        if digest(&Self::read(spec)?) != self.digest {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub fn value(&self) -> &Enrollment {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_document_binds_full_allocation_container_manifest_and_enrollment() {
        let (mut spec, _) = super::super::tests::fixture();
        spec.exit.mode = vprouter_core::config::ExitMode::Mullvad;
        spec.allocation.exits[0] = spec.exit.clone();
        let binding = vprouter_core::health::Binding {
            deployment_id: spec.allocation.deployment_id.clone(),
            exit_id: spec.exit.exit_id.clone(),
            mode: spec.exit.mode,
            generation: spec.generation,
            display_name: "test-exit".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "node-self".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        };
        let bundle = ReviewedBundle::current().unwrap();
        let value = Document {
            version: 1,
            container_id: spec.container_id.clone(),
            allocation_sha256: digest(&serde_json::to_vec(&spec.allocation).unwrap()),
            manifest_sha256: bundle.digest().into(),
            enrollment: Enrollment {
                version: 1,
                binding: binding.clone(),
                ips: vec!["100.64.0.7".parse().unwrap()],
                peers: vec![],
            },
        };
        value.bind(&spec, &bundle, &binding).unwrap();
        let encoded = serde_json::to_value(&value).unwrap();
        for field in [
            "version",
            "container_id",
            "allocation_sha256",
            "manifest_sha256",
        ] {
            let mut wrong = encoded.clone();
            wrong[field] = if field == "version" {
                serde_json::json!(2)
            } else {
                serde_json::json!("b".repeat(64))
            };
            let wrong: Document = serde_json::from_value(wrong).unwrap();
            assert!(wrong.bind(&spec, &bundle, &binding).is_err(), "{field}");
        }
        for key in ["node_id", "config_fingerprint", "boot_id", "exit_id"] {
            let mut wrong = encoded.clone();
            wrong["enrollment"]["binding"][key] = serde_json::json!("foreign");
            let wrong: Document = serde_json::from_value(wrong).unwrap();
            assert!(wrong.bind(&spec, &bundle, &binding).is_err(), "{key}");
        }
        let mut moved = spec;
        moved.allocation.exits[0].state_dir = "/var/lib/foreign/one".into();
        assert!(value.bind(&moved, &bundle, &binding).is_err());
        assert!(serde_json::from_slice::<Document>(br#"{"version":1,"version":1}"#).is_err());
    }
}
