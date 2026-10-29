//! Bounded public ROUTE metadata. This wire value carries no readiness authority.
use crate::{Error, Result, Snapshot};

pub const HOST_OBSERVATION_BYTES: usize = 128 * 1024;
pub const HOST_OBSERVATION_RECORDS: usize = 4096;

/// This value is public metadata, NOT a verified host capability. Only the
/// owner may accept it, from its fixed child channel after exact clean exit.
#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    pub(crate) namespace: (u64, u64),
    #[serde(deserialize_with = "records")]
    links: Vec<crate::Link>,
    #[serde(deserialize_with = "records")]
    addresses: Vec<crate::Address>,
    #[serde(deserialize_with = "records")]
    routes: Vec<crate::Route>,
    #[serde(deserialize_with = "records")]
    rules: Vec<crate::Rule>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireObservation {
    namespace: (u64, u64),
    #[serde(deserialize_with = "records")]
    links: Vec<crate::Link>,
    #[serde(deserialize_with = "records")]
    addresses: Vec<crate::Address>,
    #[serde(deserialize_with = "records")]
    routes: Vec<crate::Route>,
    #[serde(deserialize_with = "records")]
    rules: Vec<crate::Rule>,
}
fn records<'de, D: serde::Deserializer<'de>, T: serde::Deserialize<'de>>(
    d: D,
) -> std::result::Result<Vec<T>, D::Error> {
    struct Bounded<T>(std::marker::PhantomData<T>);
    impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded metadata records")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut a: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(value) = a.next_element()? {
                if out.len() == HOST_OBSERVATION_RECORDS {
                    return Err(serde::de::Error::custom("metadata record limit"));
                }
                out.push(value);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Bounded(std::marker::PhantomData))
}
impl HostObservation {
    pub(crate) fn from_snapshot(namespace: (u64, u64), s: Snapshot) -> Self {
        Self {
            namespace,
            links: s.links,
            addresses: s.addresses,
            routes: s.routes,
            rules: s.rules,
        }
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            links: self.links.clone(),
            addresses: self.addresses.clone(),
            routes: self.routes.clone(),
            rules: self.rules.clone(),
            wireguard: None,
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.namespace.0 == 0 || self.namespace.1 == 0 {
            return Err(Error::NamespaceUnverified);
        }
        if self.links.len() + self.addresses.len() + self.routes.len() + self.rules.len()
            > HOST_OBSERVATION_RECORDS
            || self.links.iter().any(|l| {
                l.name.is_empty()
                    || l.name.len() > 15
                    || l.alias.len() > 255
                    || l.kind.len() > 64
                    || l.port_kind.len() > 64
                    || l.alternate_names.len() > 64
                    || l.alternate_names
                        .iter()
                        .any(|s| s.is_empty() || s.len() > 127)
                    || l.tun_info.len() > 64
                    || l.tun_info.iter().any(|(_, v)| v.len() > 256)
            })
        {
            return Err(Error::Oversized);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        // Streaming limit avoids first allocating an unbounded serialization.
        struct Limited(Vec<u8>);
        impl std::io::Write for Limited {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0.len() + bytes.len() > HOST_OBSERVATION_BYTES {
                    return Err(std::io::ErrorKind::OutOfMemory.into());
                }
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut out = Limited(Vec::new());
        serde_json::to_writer(&mut out, self).map_err(|_| Error::Oversized)?;
        Ok(out.0)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > HOST_OBSERVATION_BYTES {
            return Err(Error::Oversized);
        }
        let wire: WireObservation = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
        let result = Self {
            namespace: wire.namespace,
            links: wire.links,
            addresses: wire.addresses,
            routes: wire.routes,
            rules: wire.rules,
        };
        result.validate()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_roundtrip_preserves_every_public_field_and_excludes_wireguard() {
        let mut snapshot = crate::tests::snapshot(&crate::tests::plan());
        snapshot.links[0].tun_info = vec![(1, vec![0, 1, 255])];
        snapshot.links[0].alternate_names = vec!["alternate".into()];
        snapshot.links[0].headroom = Some(12);
        snapshot.links[0].tailroom = Some(0);
        snapshot.links[0].max_pacing_offload_horizon = Some(0);
        snapshot.rules.push(snapshot.rules[0].clone());
        let projection = HostObservation::from_snapshot((8, 19), snapshot.clone());
        let bytes = projection.encode().unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .unwrap()
                .get("wireguard")
                .is_none()
        );
        let decoded = HostObservation::decode(&bytes).unwrap();
        snapshot.wireguard = None;
        assert_eq!(decoded.snapshot(), snapshot);
        assert_eq!(decoded.namespace, (8, 19));
        let mut unknown = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
        unknown["wireguard"] = serde_json::json!({});
        assert!(HostObservation::decode(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
    #[test]
    fn bounded_projection_refuses_count_strings_total_bytes_and_malformed_input() {
        let snapshot = crate::tests::snapshot(&crate::tests::plan());
        let mut projection = HostObservation::from_snapshot((8, 19), snapshot);
        projection.links[0].alias = "a".repeat(256);
        assert!(projection.encode().is_err());
        projection.links.clear();
        projection.addresses.clear();
        projection.routes.clear();
        projection.rules = vec![crate::Rule::default(); HOST_OBSERVATION_RECORDS + 1];
        assert!(projection.encode().is_err());
        assert!(HostObservation::decode(&vec![b' '; HOST_OBSERVATION_BYTES + 1]).is_err());
        assert!(HostObservation::decode(b"{}").is_err());
        assert!(HostObservation::decode(b"null").is_err());
    }
}
