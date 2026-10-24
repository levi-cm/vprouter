use crate::{Error, Result};
use std::net::{Ipv4Addr, SocketAddrV4};
use vprouter_core::{
    allocation::{AllocationRecord, ExitAllocation},
    config::ExitMode,
    profile::Profile,
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
