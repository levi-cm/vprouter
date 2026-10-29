//! Authenticated operational messages. Wire data is never placement authority.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use vprouter_core::health::{Binding, HealthMessage, Snapshot};

/// Observational wire values, never native policy or readiness authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Offline,
    Bootstrap,
    Ready,
}
impl PolicyState {
    /// Expected policy after a validated publication, not permission to apply it.
    /// A failed sample has no recovery evidence and must remain fully offline.
    pub fn publication(snapshot: &Snapshot) -> Self {
        use vprouter_core::state::HealthState;
        match snapshot.state {
            HealthState::Ready => Self::Ready,
            HealthState::Stopping | HealthState::Failed => Self::Offline,
            HealthState::Blocked if snapshot.evidence.is_none() || snapshot.reason.is_some() => {
                Self::Offline
            }
            _ => Self::Bootstrap,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReceipt {
    pub binding: Binding,
    pub state: PolicyState,
}
impl PolicyReceipt {
    pub(crate) fn validate(&self, binding: &Binding, state: PolicyState) -> Result<()> {
        if &self.binding != binding || self.state != state {
            return Err(Error::GuardUnavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub version: u32,
    pub binding: Binding,
    pub ips: Vec<std::net::IpAddr>,
    pub peers: Vec<EnrolledPeer>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolledPeer {
    pub node_id: String,
    pub ips: Vec<std::net::IpAddr>,
    pub expired: bool,
    pub in_network_map: bool,
}
fn ipv4(ips: &[std::net::IpAddr]) -> Result<std::net::Ipv4Addr> {
    if ips.is_empty()
        || ips.len() > 2
        || ips.iter().enumerate().any(|(i, ip)| {
            ips[..i].contains(ip)
                || match ip {
                    std::net::IpAddr::V4(ip) => (u32::from(*ip) & 0xffc00000) != 0x64400000,
                    std::net::IpAddr::V6(ip) => ip.segments()[..3] != [0xfd7a, 0x115c, 0xa1e0],
                }
        })
    {
        return Err(Error::Identity);
    }
    let values: Vec<_> = ips
        .iter()
        .filter_map(|ip| {
            if let std::net::IpAddr::V4(ip) = ip {
                Some(*ip)
            } else {
                None
            }
        })
        .collect();
    if values.len() != 1 {
        return Err(Error::Identity);
    }
    Ok(values[0])
}
impl Enrollment {
    pub fn validate(&self, binding: &Binding) -> Result<()> {
        binding
            .validate()
            .map_err(|_| Error::InvalidConfiguration)?;
        if self.version != 1
            || &self.binding != binding
            || binding.mode != vprouter_core::config::ExitMode::Mullvad
        {
            return Err(Error::Identity);
        }
        self.declaration()?;
        Ok(())
    }
    pub fn declaration(&self) -> Result<vprouter_network::DaemonDeclaration> {
        let mut addresses = std::collections::HashSet::new();
        for ip in self
            .ips
            .iter()
            .chain(self.peers.iter().flat_map(|peer| &peer.ips))
        {
            if !addresses.insert(*ip) {
                return Err(Error::Identity);
            }
        }
        let peers = self
            .peers
            .iter()
            .map(|peer| {
                Ok(vprouter_network::DaemonPeer {
                    node_id: peer.node_id.clone(),
                    address: ipv4(&peer.ips)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // Validate IDs/IPs across the COMPLETE declared identity set first.
        vprouter_network::DaemonDeclaration::new(
            self.binding.node_id.clone(),
            ipv4(&self.ips)?,
            peers.clone(),
        )
        .map_err(|_| Error::Identity)?;
        // Online is deliberately irrelevant: offline, unexpired map peers retain
        // routes. Expired/not-in-map peers remain in LocalAPI identity matching.
        let eligible = peers
            .into_iter()
            .zip(&self.peers)
            .filter_map(|(peer, expected)| {
                (expected.in_network_map && !expected.expired).then_some(peer)
            })
            .collect();
        vprouter_network::DaemonDeclaration::new(
            self.binding.node_id.clone(),
            ipv4(&self.ips)?,
            eligible,
        )
        .map_err(|_| Error::Identity)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub version: u32,
    pub lifecycle: String,
    pub sequence: u64,
    pub sent_at: f64,
}
impl Frame {
    pub fn validate(&self, lifecycle: &str, sequence: u64, now: f64) -> Result<()> {
        if self.version != 1
            || self.lifecycle != lifecycle
            || self.sequence != sequence
            || !self.sent_at.is_finite()
            || !now.is_finite()
            || self.sent_at < 0.
            || now < self.sent_at
            || now - self.sent_at >= 2.
        {
            return Err(Error::GuardUnavailable);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralEvidence {
    /// First check's original BOOTTIME; never response serialization time.
    pub checked_at: f64,
    /// Age at checked_at is conservative: guard measures it after native GET.
    pub handshake_age: f64,
}
impl StructuralEvidence {
    pub fn validate(&self, requested_at: f64, now: f64) -> Result<()> {
        if !now.is_finite()
            || !requested_at.is_finite()
            || requested_at < 0.
            || !self.checked_at.is_finite()
            || !self.handshake_age.is_finite()
            || self.checked_at < requested_at
            || self.checked_at > now
            || now - self.checked_at >= 2.
            || !(0.0..180.).contains(&self.handshake_age)
            || self.handshake_age + now - self.checked_at >= 180.
        {
            return Err(Error::Structural);
        }
        Ok(())
    }
    pub fn matches(&self, message: &HealthMessage) -> Result<()> {
        let e = message
            .snapshot
            .as_ref()
            .and_then(|s| s.evidence.as_ref())
            .ok_or(Error::Structural)?;
        if e.structural_at != self.checked_at || e.handshake_age_seconds != Some(self.handshake_age)
        {
            return Err(Error::Structural);
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Structure {
        frame: Frame,
    },
    Heartbeat {
        frame: Frame,
    },
    Prepare {
        frame: Frame,
        message: Box<HealthMessage>,
    },
    Persist {
        frame: Frame,
        snapshot_sequence: u64,
    },
    Commit {
        frame: Frame,
        snapshot_sequence: u64,
    },
}
impl Request {
    pub fn frame(&self) -> &Frame {
        match self {
            Self::Structure { frame }
            | Self::Heartbeat { frame }
            | Self::Prepare { frame, .. }
            | Self::Persist { frame, .. }
            | Self::Commit { frame, .. } => frame,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Structure {
        frame: Frame,
        evidence: StructuralEvidence,
    },
    Alive {
        frame: Frame,
    },
    Prepared {
        frame: Frame,
        policy: PolicyReceipt,
    },
    Persisted {
        frame: Frame,
    },
    Enforced {
        frame: Frame,
        state: vprouter_core::state::HealthState,
        policy: PolicyReceipt,
    },
}
impl Reply {
    pub fn frame(&self) -> &Frame {
        match self {
            Self::Structure { frame, .. }
            | Self::Alive { frame }
            | Self::Prepared { frame, .. }
            | Self::Persisted { frame }
            | Self::Enforced { frame, .. } => frame,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn structural_receipt_cannot_retimestamp_replay_or_extend_handshake() {
        let e = StructuralEvidence {
            checked_at: 100.,
            handshake_age: 179.,
        };
        assert!(e.validate(100., 100.5).is_ok());
        for (request, now) in [
            (100.1, 100.5),
            (99., 101.),
            (99., 102.),
            (99., 99.),
            (100., f64::NAN),
        ] {
            assert!(e.validate(request, now).is_err());
        }
        let f = Frame {
            version: 1,
            lifecycle: "bound".into(),
            sequence: 2,
            sent_at: 100.,
        };
        assert!(f.validate("bound", 2, 101.).is_ok());
        for (life, seq, now) in [("other", 2, 101.), ("bound", 1, 101.), ("bound", 2, 102.)] {
            assert!(f.validate(life, seq, now).is_err());
        }
    }
}

pub(crate) struct Channel {
    stream: tokio::net::UnixStream,
    lifecycle: String,
    sequence: u64,
    poisoned: bool,
}
impl Channel {
    pub(crate) fn new(stream: std::os::unix::net::UnixStream, lifecycle: String) -> Result<Self> {
        crate::bootstrap::nonblocking(&stream).map_err(|_| Error::GuardUnavailable)?;
        Ok(Self {
            stream: tokio::net::UnixStream::from_std(stream)
                .map_err(|_| Error::GuardUnavailable)?,
            lifecycle,
            sequence: 0,
            poisoned: false,
        })
    }
    pub(crate) async fn exchange(
        &mut self,
        request: impl FnOnce(Frame) -> Request,
    ) -> Result<Reply> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if self.poisoned {
            return Err(Error::GuardUnavailable);
        }
        // Cancellation cannot roll a half-sent frame back into a reusable channel.
        self.poisoned = true;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::GuardUnavailable)?;
        let frame = Frame {
            version: 1,
            lifecycle: self.lifecycle.clone(),
            sequence: self.sequence,
            sent_at: vprouter_core::health::boot_seconds(),
        };
        let request = request(frame.clone());
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let bytes = serde_json::to_vec(&request).map_err(|_| Error::GuardUnavailable)?;
            if bytes.is_empty() || bytes.len() > 4096 {
                return Err(Error::GuardUnavailable);
            }
            self.stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .await
                .map_err(|_| Error::GuardUnavailable)?;
            self.stream
                .write_all(&bytes)
                .await
                .map_err(|_| Error::GuardUnavailable)?;
            let size = self
                .stream
                .read_u32()
                .await
                .map_err(|_| Error::GuardUnavailable)? as usize;
            if size == 0 || size > 4096 {
                return Err(Error::GuardUnavailable);
            }
            let mut bytes = vec![0; size];
            self.stream
                .read_exact(&mut bytes)
                .await
                .map_err(|_| Error::GuardUnavailable)?;
            let reply: Reply = crate::json::decode(&bytes)?;
            let received = reply.frame();
            received.validate(
                &frame.lifecycle,
                frame.sequence,
                vprouter_core::health::boot_seconds(),
            )?;
            if received.sent_at != frame.sent_at {
                return Err(Error::GuardUnavailable);
            }
            Ok(reply)
        })
        .await
        .map_err(|_| Error::GuardUnavailable)??;
        self.poisoned = false;
        Ok(response)
    }
    pub(crate) async fn heartbeat(&mut self) -> Result<()> {
        match self.exchange(|frame| Request::Heartbeat { frame }).await? {
            Reply::Alive { .. } => Ok(()),
            _ => Err(Error::GuardUnavailable),
        }
    }
    pub(crate) async fn structure(&mut self) -> Result<StructuralEvidence> {
        match self.exchange(|frame| Request::Structure { frame }).await? {
            Reply::Structure { frame, evidence } => {
                evidence.validate(frame.sent_at, vprouter_core::health::boot_seconds())?;
                Ok(evidence)
            }
            _ => Err(Error::GuardUnavailable),
        }
    }
}
#[cfg(test)]
mod channel_tests {
    use super::*;
    use std::{os::unix::net::UnixStream, time::Duration};
    #[tokio::test]
    async fn actual_framed_structural_channel_refuses_replay_and_cancellation() {
        for fault in 0..4 {
            let (client, mut server) = UnixStream::pair().unwrap();
            let peer = std::thread::spawn(move || {
                let request: Request = crate::bootstrap::read_message(&mut server).unwrap();
                let mut frame = request.frame().clone();
                if fault == 1 {
                    frame.sequence += 1;
                }
                if fault == 2 {
                    frame.lifecycle = "foreign".into();
                }
                if fault == 3 {
                    std::thread::sleep(Duration::from_millis(50));
                }
                let reply = Reply::Structure {
                    frame,
                    evidence: StructuralEvidence {
                        checked_at: vprouter_core::health::boot_seconds(),
                        handshake_age: 1.,
                    },
                };
                let _ = crate::bootstrap::write_message(&mut server, &reply);
            });
            let mut channel = Channel::new(client, "bound".into()).unwrap();
            if fault == 3 {
                assert!(
                    tokio::time::timeout(Duration::from_millis(10), channel.structure())
                        .await
                        .is_err()
                );
                assert!(
                    channel.structure().await.is_err(),
                    "cancelled partial frame was reused"
                );
            } else {
                assert_eq!(channel.structure().await.is_ok(), fault == 0);
                if fault != 0 {
                    assert!(channel.structure().await.is_err());
                }
            }
            peer.join().unwrap();
        }
    }
    #[test]
    fn expired_and_not_in_map_identities_remain_declared_but_do_not_require_native_routes() {
        let binding = Binding {
            deployment_id: "test".into(),
            exit_id: "one".into(),
            mode: vprouter_core::config::ExitMode::Mullvad,
            generation: 1,
            display_name: "test-exit".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "self".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        };
        let mut enrollment = Enrollment {
            version: 1,
            binding,
            ips: vec!["100.64.0.7".parse().unwrap()],
            peers: vec![
                EnrolledPeer {
                    node_id: "offline-unexpired".into(),
                    ips: vec!["100.64.0.8".parse().unwrap()],
                    expired: false,
                    in_network_map: true,
                },
                EnrolledPeer {
                    node_id: "expired".into(),
                    ips: vec!["100.64.0.9".parse().unwrap()],
                    expired: true,
                    in_network_map: true,
                },
                EnrolledPeer {
                    node_id: "outside-map".into(),
                    ips: vec!["100.64.0.10".parse().unwrap()],
                    expired: false,
                    in_network_map: false,
                },
            ],
        };
        let declaration = enrollment.declaration().unwrap();
        assert_eq!(enrollment.peers.len(), 3);
        assert_eq!(declaration.peers().len(), 1);
        assert_eq!(declaration.peers()[0].node_id, "offline-unexpired");
        enrollment.peers[1].expired = false;
        assert_eq!(enrollment.declaration().unwrap().peers().len(), 2);
        enrollment.peers[1].expired = true;
        enrollment.peers[1].node_id = "offline-unexpired".into();
        assert!(
            enrollment.declaration().is_err(),
            "ineligible peers still require globally unique identity"
        );
    }
    #[test]
    fn enrollment_cannot_enable_direct_or_mismatch_any_binding_field() {
        let binding = Binding {
            deployment_id: "test".into(),
            exit_id: "one".into(),
            mode: vprouter_core::config::ExitMode::Mullvad,
            generation: 1,
            display_name: "test-exit".into(),
            expected_server: Some("de-fra-wg-404".into()),
            node_id: "node-self".into(),
            config_fingerprint: "a".repeat(64),
            boot_id: "01234567-1234-1234-1234-0123456789ab".into(),
        };
        let enrollment = Enrollment {
            version: 1,
            binding: binding.clone(),
            ips: vec!["100.64.0.7".parse().unwrap()],
            peers: vec![],
        };
        enrollment.validate(&binding).unwrap();
        let mut direct = enrollment.clone();
        direct.binding.mode = vprouter_core::config::ExitMode::Direct;
        direct.binding.expected_server = None;
        assert!(direct.validate(&direct.binding).is_err());
        for field in 0..5 {
            let mut wrong = binding.clone();
            match field {
                0 => wrong.generation += 1,
                1 => wrong.node_id = "foreign".into(),
                2 => wrong.config_fingerprint = "b".repeat(64),
                3 => wrong.exit_id = "other".into(),
                _ => wrong.boot_id = "11234567-1234-1234-1234-0123456789ab".into(),
            }
            assert!(enrollment.validate(&wrong).is_err());
        }
    }
}
