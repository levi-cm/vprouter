use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddrV4};
use vprouter_core::{
    allocation::{AllocationRecord, ExitAllocation},
    config::ExitMode,
    profile::{Profile, PublicProfile},
};

/// Public facts only. No private key, arbitrary names, or JSON constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub(crate) allocation: ExitAllocation,
    pub(crate) alias: String,
    pub(crate) endpoint: SocketAddrV4,
    pub(crate) address: Ipv4Addr,
    pub(crate) peer: [u8; 32],
    pub(crate) public_key: [u8; 32],
}
impl Plan {
    /// Public structural plan only. The launch owner separately binds its
    /// original secret-role receipt; this cannot create a native DOWN token.
    pub fn from_public(
        record: &AllocationRecord,
        deployment: &str,
        exit: &ExitAllocation,
        profile: &PublicProfile,
    ) -> Result<Self> {
        record
            .validate(deployment, &[])
            .map_err(|_| Error::InvalidInput)?;
        profile.validate().map_err(|_| Error::InvalidInput)?;
        if !record.exits.contains(exit) {
            return Err(Error::Foreign);
        }
        if exit.mode != ExitMode::Mullvad {
            return Err(Error::DirectUnsupported);
        }
        Ok(Self {
            allocation: exit.clone(),
            alias: format!(
                "vprouter-v2:{deployment}:{}:{}",
                record.generation, exit.exit_id
            ),
            endpoint: profile.endpoint(),
            address: profile.address(),
            peer: *profile.peer_public_key(),
            public_key: profile.device_public_key(),
        })
    }
    pub fn new(
        record: &AllocationRecord,
        deployment: &str,
        exit: &ExitAllocation,
        profile: &Profile,
    ) -> Result<Self> {
        record
            .validate(deployment, &[])
            .map_err(|_| Error::InvalidInput)?;
        if !record.exits.contains(exit) {
            return Err(Error::Foreign);
        }
        if exit.mode != ExitMode::Mullvad {
            return Err(Error::DirectUnsupported);
        }
        Ok(Self {
            allocation: exit.clone(),
            alias: format!(
                "vprouter-v2:{deployment}:{}:{}",
                record.generation, exit.exit_id
            ),
            endpoint: profile.endpoint(),
            address: profile.address(),
            peer: *profile.peer_public_key(),
            public_key: profile.with_private_key(|key| {
                x25519_dalek::x25519(*key, x25519_dalek::X25519_BASEPOINT_BYTES)
            }),
        })
    }
    pub fn wireguard_name(&self) -> &str {
        self.allocation
            .wireguard_interface
            .as_deref()
            .expect("validated Mullvad allocation")
    }
    pub fn host_name(&self) -> &str {
        &self.allocation.host_interface
    }
    /// This is the transport-side veth name; never installed in the data namespace.
    pub fn transport_name(&self) -> &str {
        &self.allocation.data_interface
    }
    pub fn ownership_alias(&self) -> &str {
        &self.alias
    }
    pub fn endpoint(&self) -> SocketAddrV4 {
        self.endpoint
    }
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }
    pub fn device_public_key(&self) -> [u8; 32] {
        self.public_key
    }
    pub fn transport_addresses(&self) -> (Ipv4Addr, Ipv4Addr) {
        let ip: Ipv4Addr = self
            .allocation
            .transport_subnet
            .split('/')
            .next()
            .expect("validated subnet")
            .parse()
            .expect("validated subnet");
        (
            Ipv4Addr::from(u32::from(ip) + 1),
            Ipv4Addr::from(u32::from(ip) + 2),
        )
    }
    pub(crate) fn matches_profile(&self, p: &Profile) -> bool {
        self.endpoint == p.endpoint()
            && self.address == p.address()
            && self.peer == *p.peer_public_key()
            && self.public_key
                == p.with_private_key(|key| {
                    x25519_dalek::x25519(*key, x25519_dalek::X25519_BASEPOINT_BYTES)
                })
    }
}

/// Public monitoring facts only: never a WG private key or activation authority.
/// Restoring this projection cannot certify the current kernel structure.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitoringPlan {
    endpoint: SocketAddrV4,
    address: Ipv4Addr,
    peer: [u8; 32],
    public_key: [u8; 32],
}
impl Plan {
    pub fn monitoring(&self) -> MonitoringPlan {
        MonitoringPlan {
            endpoint: self.endpoint,
            address: self.address,
            peer: self.peer,
            public_key: self.public_key,
        }
    }
    /// Reconstitute an observational plan from protected public monitoring data.
    /// This grants neither confinement, namespace placement nor guarded activation.
    pub fn from_monitoring(
        record: &AllocationRecord,
        exit: &ExitAllocation,
        monitoring: MonitoringPlan,
    ) -> Result<Self> {
        record
            .validate(&record.deployment_id, &[])
            .map_err(|_| Error::InvalidInput)?;
        if !record.exits.contains(exit) || exit.mode != ExitMode::Mullvad {
            return Err(Error::Foreign);
        }
        if !vprouter_core::profile::public_ipv4(*monitoring.endpoint.ip())
            || monitoring.endpoint.port() == 0
            || !monitoring.address.is_private()
            || monitoring.peer == [0; 32]
            || monitoring.public_key == [0; 32]
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            allocation: exit.clone(),
            alias: format!(
                "vprouter-v2:{}:{}:{}",
                record.deployment_id, record.generation, exit.exit_id
            ),
            endpoint: monitoring.endpoint,
            address: monitoring.address,
            peer: monitoring.peer,
            public_key: monitoring.public_key,
        })
    }
}

#[cfg(test)]
mod monitoring_tests {
    use super::*;
    #[test]
    fn public_monitoring_roundtrip_preserves_exact_plan_without_private_profile() {
        let (record, profile) = crate::tests::fixture();
        let plan = Plan::new(&record, "networklab", &record.exits[0], &profile).unwrap();
        let bytes = serde_json::to_vec(&plan.monitoring()).unwrap();
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("private"));
        let restored = Plan::from_monitoring(
            &record,
            &record.exits[0],
            serde_json::from_slice(&bytes).unwrap(),
        )
        .unwrap();
        assert_eq!(restored, plan);
        let mut projection: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        projection["endpoint"] = "127.0.0.1:51820".into();
        assert!(
            Plan::from_monitoring(
                &record,
                &record.exits[0],
                serde_json::from_value(projection).unwrap()
            )
            .is_err()
        );
        let mut foreign = record.exits[0].clone();
        foreign.exit_id = "foreign".into();
        assert!(Plan::from_monitoring(&record, &foreign, plan.monitoring()).is_err());
    }
}
