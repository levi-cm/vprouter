use crate::{Error, Result, client, json, placement::Placed};
use serde::Deserialize;
use std::{net::IpAddr, path::PathBuf, rc::Rc};
const LIMIT: usize = 65536;
#[derive(Deserialize)]
pub(crate) struct DaemonStatus {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "BackendState")]
    pub backend_state: String,
    #[serde(rename = "Self")]
    pub self_node: Option<Node>,
    #[serde(rename = "TailscaleIPs", default)]
    ips: Vec<IpAddr>,
    #[serde(rename = "Peer", default)]
    peers: Option<std::collections::BTreeMap<String, PeerIdentity>>,
}
#[derive(Deserialize)]
struct PeerIdentity {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "TailscaleIPs")]
    ips: Vec<IpAddr>,
    #[serde(rename = "Expired", deserialize_with = "nullable_boolean")]
    expired: bool,
    #[serde(rename = "InNetworkMap")]
    in_network_map: bool,
}
fn nullable_boolean<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<bool, D::Error> {
    Ok(Option::<bool>::deserialize(d)?.unwrap_or(false))
}
#[derive(Deserialize)]
pub(crate) struct Node {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Online")]
    pub online: bool,
    #[serde(rename = "ExitNodeOption")]
    approved: bool,
    #[serde(rename = "TailscaleIPs")]
    ips: Vec<IpAddr>,
}
impl DaemonStatus {
    pub fn version_pinned(&self) -> bool {
        self.version == "1.102.5" || self.version == "1.102.5-1-t5fb2a81b0"
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct Prefs {
    want_running: bool,
    logged_out: bool,
    route_all: bool,
    #[serde(rename = "CorpDNS")]
    corp_dns: bool,
    #[serde(deserialize_with = "nullable_routes")]
    pub advertise_routes: Vec<String>,
    pub netfilter_mode: u8,
    #[serde(rename = "ExitNodeID")]
    exit_node_id: String,
    #[serde(rename = "ExitNodeIP")]
    exit_node_ip: String,
    no_stateful_filtering: bool,
    #[serde(rename = "RunSSH")]
    run_ssh: bool,
    #[serde(rename = "NoSNAT")]
    no_snat: bool,
}
fn nullable_routes<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}
pub(crate) fn parse_status(bytes: &[u8]) -> Result<DaemonStatus> {
    json::decode(bytes)
}
pub(crate) fn parse_prefs(bytes: &[u8]) -> Result<Prefs> {
    json::decode(bytes)
}
// StatusWithoutPeers creates a zero Self object even without a network map.
// Its nil IP slices encode as null. These separate observation-only types
// deliberately leave the production Ready status/node decoder unchanged.
#[derive(Deserialize)]
struct UnenrolledStatus {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "BackendState")]
    backend: String,
    #[serde(rename = "Self")]
    node: Option<UnenrolledNode>,
    #[serde(rename = "TailscaleIPs", deserialize_with = "nullable_ips")]
    ips: Vec<IpAddr>,
}
#[derive(Deserialize)]
struct UnenrolledNode {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Online")]
    online: bool,
    #[serde(rename = "ExitNodeOption")]
    approved: bool,
    #[serde(rename = "TailscaleIPs", deserialize_with = "nullable_ips")]
    ips: Vec<IpAddr>,
}
fn nullable_ips<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<IpAddr>, D::Error> {
    Ok(Option::<Vec<IpAddr>>::deserialize(d)?.unwrap_or_default())
}
impl UnenrolledStatus {
    fn node_predicates(&self) -> [bool; 4] {
        self.node.as_ref().map_or([true; 4], |node| {
            [
                node.id.is_empty(),
                !node.online,
                !node.approved,
                node.ips.is_empty(),
            ]
        })
    }
    fn predicates(&self) -> [bool; 4] {
        [
            self.version == "1.102.5" || self.version == "1.102.5-1-t5fb2a81b0",
            matches!(self.backend.as_str(), "NeedsLogin" | "Stopped" | "NoState"),
            self.node_predicates().into_iter().all(|v| v),
            self.ips.is_empty(),
        ]
    }
}
// Fixed observation-only diagnostic alphabet. No field value, string, length,
// identifier, URL, state or arbitrary key is emitted. This cannot grant access.
#[cfg(test)]
fn diagnostic_type(value: Option<&serde_json::Value>) -> u8 {
    match value {
        None => 0,
        Some(serde_json::Value::Null) => 1,
        Some(serde_json::Value::Bool(_)) => 2,
        Some(serde_json::Value::Number(_)) => 3,
        Some(serde_json::Value::String(_)) => 4,
        Some(serde_json::Value::Array(_)) => 5,
        Some(serde_json::Value::Object(_)) => 6,
    }
}
#[cfg(test)]
fn observation_types(bytes: &[u8], fields: &[&str]) -> Result<Vec<u8>> {
    let value: serde_json::Value = json::decode(bytes)?;
    let object = value.as_object().ok_or(Error::Malformed)?;
    Ok(fields
        .iter()
        .map(|field| diagnostic_type(object.get(*field)))
        .collect())
}
pub(crate) fn require_unenrolled(status: &[u8], prefs: &[u8]) -> Result<()> {
    let status: UnenrolledStatus =
        json::decode(status).inspect_err(|_| eprintln!("observation_status_parse_refused"))?;
    let status_predicates = status.predicates();
    let prefs = parse_prefs(prefs).inspect_err(|_| eprintln!("observation_prefs_parse_refused"))?;
    if !status_predicates.into_iter().all(|v| v) || !prefs.unenrolled() {
        return Err(Error::Identity);
    }
    Ok(())
}
#[cfg(test)]
mod diagnostic_tests {
    #[test]
    fn no_network_map_zero_self_is_observation_only_and_each_identity_bit_refuses() {
        use super::*;
        let baseline = serde_json::json!({
            "Version":"1.102.5-1-t5fb2a81b0", "BackendState":"Stopped",
            "TailscaleIPs":null,
            "Self":{"ID":"", "Online":false, "ExitNodeOption":false,"TailscaleIPs":null}
        });
        let bytes = serde_json::to_vec(&baseline).unwrap();
        let status: UnenrolledStatus = json::decode(&bytes).unwrap();
        assert_eq!(status.node_predicates(), [true; 4]);
        assert_eq!(status.predicates(), [true; 4]);
        // The production Ready decoder still rejects null IP arrays, and an
        // arbitrary Self object cannot satisfy the observation-only decoder.
        assert!(parse_status(&bytes).is_err());
        for change in 0..10 {
            let mut value = baseline.clone();
            match change {
                0 => value["Self"]["ID"] = "enrolled-id".into(),
                1 => value["Self"]["Online"] = true.into(),
                2 => value["Self"]["ExitNodeOption"] = true.into(),
                3 => value["Self"]["TailscaleIPs"] = serde_json::json!(["100.64.0.7"]),
                4 => value["TailscaleIPs"] = serde_json::json!(["100.64.0.7"]),
                5 => value["Version"] = "unreviewed-version".into(),
                6 => value["BackendState"] = "Running".into(),
                7 => value["Self"] = serde_json::json!({}),
                8 => {
                    value["Self"].as_object_mut().unwrap().remove("Online");
                }
                _ => value["Self"]["TailscaleIPs"] = serde_json::json!(["invalid-ip"]),
            }
            assert!(
                !json::decode::<UnenrolledStatus>(&serde_json::to_vec(&value).unwrap())
                    .is_ok_and(|status| status.predicates().into_iter().all(|v| v)),
                "change{change}"
            );
        }
    }
    #[test]
    fn fixed_diagnostic_alphabet_retains_types_without_values_or_foreign_keys() {
        use super::*;
        let fields = ["Version", "BackendState", "Self", "TailscaleIPs"];
        let a = br#"{"Version":"secret-a","BackendState":"state-a","Self":{"ID":"identity-a"},"TailscaleIPs":[],"foreign":"secret"}"#;
        let b = br#"{"Version":"different-length-secret","BackendState":"state-b","Self":{"ID":"identity-b","other":false},"TailscaleIPs":["100.64.0.1"]}"#;
        assert_eq!(observation_types(a, &fields).unwrap(), [4, 4, 6, 5]);
        assert_eq!(observation_types(a, &fields), observation_types(b, &fields));
        assert_eq!(
            observation_types(br#"{"Self":null}"#, &fields).unwrap(),
            [0, 0, 1, 0]
        );
        assert!(observation_types(br#"{"Self":null,"Self":{}}"#, &fields).is_err());
        assert!(observation_types(b"[]", &fields).is_err());
    }
}
#[derive(Clone)]
pub(crate) struct Identity {
    pub node_id: String,
    pub ips: Vec<IpAddr>,
    pub routes: Vec<String>,
}
impl Identity {
    pub fn validate(&self) -> Result<()> {
        if self.node_id.is_empty()
            || self.node_id.len() > 128
            || self.ips.is_empty()
            || self.ips.len() > 2
            || !same(&self.routes, &["0.0.0.0/0".into(), "::/0".into()])
            || self.ips.iter().enumerate().any(|(i, ip)| {
                self.ips[..i].contains(ip)
                    || !match ip {
                        IpAddr::V4(ip) => (u32::from(*ip) & 0xffc00000) == 0x64400000,
                        IpAddr::V6(ip) => ip.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
                    }
            })
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(())
    }
}
fn same<T: Eq>(a: &[T], b: &[T]) -> bool {
    a.len() == b.len()
        && a.iter()
            .all(|x| a.iter().filter(|y| *y == x).count() == b.iter().filter(|y| *y == x).count())
}
impl Prefs {
    pub(crate) fn unenrolled(&self) -> bool {
        !self.want_running
            && !self.route_all
            && !self.corp_dns
            && self.netfilter_mode == 0
            && !self.run_ssh
            && self.no_snat
            && self.exit_node_id.is_empty()
            && self.exit_node_ip.is_empty()
            && self.no_stateful_filtering
            && self.advertise_routes.is_empty()
    }
    fn safe(&self) -> bool {
        self.want_running
            && !self.logged_out
            && !self.route_all
            && !self.corp_dns
            && self.netfilter_mode == 0
            && !self.run_ssh
            && self.no_snat
            && self.exit_node_id.is_empty()
            && self.exit_node_ip.is_empty()
            && self.no_stateful_filtering
    }
}
fn match_peers(status: &DaemonStatus, expected: &[crate::operation::EnrolledPeer]) -> Result<()> {
    let peers = status.peers.as_ref().ok_or(Error::Identity)?;
    if peers.len() != expected.len() {
        return Err(Error::Identity);
    }
    let mut seen = std::collections::HashSet::new();
    for peer in peers.values() {
        if !seen.insert(&peer.id)
            || !expected.iter().any(|want| {
                want.node_id == peer.id
                    && same(&want.ips, &peer.ips)
                    && want.expired == peer.expired
                    && want.in_network_map == peer.in_network_map
            })
        {
            return Err(Error::Identity);
        }
    }
    Ok(())
}
pub(crate) struct Observation {
    pub advertised: bool,
    pub approved: bool,
}
pub(crate) struct LocalApi {
    placed: Rc<Placed>,
    socket: PathBuf,
    identity: Identity,
    expected_peers: Option<Vec<crate::operation::EnrolledPeer>>,
    http: tokio::sync::Mutex<Option<client::Http>>,
}
impl LocalApi {
    pub fn new(placed: Rc<Placed>, identity: Identity) -> Result<Self> {
        placed.check()?;
        identity.validate()?;
        Ok(Self {
            placed,
            socket: "/run/tailscale/tailscaled.sock".into(),
            identity,
            expected_peers: None,
            http: tokio::sync::Mutex::new(None),
        })
    }
    pub fn new_enrolled(
        placed: Rc<Placed>,
        enrollment: &crate::operation::Enrollment,
    ) -> Result<Self> {
        enrollment.validate(&enrollment.binding)?;
        let mut api = Self::new(
            placed,
            Identity {
                node_id: enrollment.binding.node_id.clone(),
                ips: enrollment.ips.clone(),
                routes: vec!["0.0.0.0/0".into(), "::/0".into()],
            },
        )?;
        api.expected_peers = Some(enrollment.peers.clone());
        Ok(api)
    }
    async fn status(&self) -> Result<DaemonStatus> {
        let path = if self.expected_peers.is_some() {
            "/localapi/v0/status?peers=true"
        } else {
            "/localapi/v0/status?peers=false"
        };
        let status = parse_status(&self.request("GET", path, b"").await?)?;
        if let Some(expected) = &self.expected_peers {
            match_peers(&status, expected)?;
        }
        Ok(status)
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    async fn request(&self, method: &str, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        self.placed.check()?;
        let result = tokio::time::timeout(client::LOCAL, async {
            let mut http = self.http.lock().await;
            if http.as_ref().is_some_and(client::Http::is_closed) {
                *http = None;
            }
            if http.is_none() {
                let stream = tokio::net::UnixStream::connect(&self.socket)
                    .await
                    .map_err(|_| Error::Transport)?;
                *http = Some(client::Http::connect(stream).await?);
            }
            http.as_mut()
                .ok_or(Error::Transport)?
                .request(method, path, "local-tailscaled.sock", body, LIMIT)
                .await
        })
        .await
        .map_err(|_| Error::Deadline)
        .and_then(|r| r);
        if result.is_err() {
            self.cancel();
        }
        self.placed.check()?;
        result.map(|r| r.body)
    }
    pub fn cancel(&self) {
        if let Ok(mut http) = self.http.try_lock() {
            *http = None;
        }
    }
    /// Always withdraw stale advertisements before ANY healthy observation.
    /// No identity reset/auth key/hostname/default preferences are written.
    pub async fn initialize(&self) -> Result<()> {
        self.withdraw().await?;
        self.verify_identity().await?;
        self.request("PATCH","/localapi/v0/prefs",br#"{"NetfilterMode":0,"NetfilterModeSet":true,"RunSSH":false,"RunSSHSet":true,"NoSNAT":true,"NoSNATSet":true}"#).await?;
        let prefs = parse_prefs(&self.request("GET", "/localapi/v0/prefs", b"").await?)?;
        if !prefs.safe() || !prefs.advertise_routes.is_empty() {
            return Err(Error::Preferences);
        }
        Ok(())
    }
    pub async fn withdraw(&self) -> Result<()> {
        self.verify_identity().await?;
        self.request(
            "PATCH",
            "/localapi/v0/prefs",
            br#"{"AdvertiseRoutes":[],"AdvertiseRoutesSet":true}"#,
        )
        .await?;
        let prefs = parse_prefs(&self.request("GET", "/localapi/v0/prefs", b"").await?)?;
        if !prefs.advertise_routes.is_empty() {
            return Err(Error::Preferences);
        }
        Ok(())
    }
    pub async fn advertise(&self) -> Result<()> {
        self.verify_identity().await?;
        let body = serde_json::to_vec(
            &serde_json::json!({"AdvertiseRoutes":self.identity.routes,"AdvertiseRoutesSet":true}),
        )
        .map_err(|_| Error::Preferences)?;
        self.request("PATCH", "/localapi/v0/prefs", &body).await?;
        Ok(())
    }
    async fn verify_identity(&self) -> Result<()> {
        self.match_identity(&self.status().await?, false)
    }
    fn match_identity(&self, status: &DaemonStatus, require_online: bool) -> Result<()> {
        let node = status.self_node.as_ref().ok_or(Error::Identity)?;
        if !status.version_pinned()
            || !matches!(status.backend_state.as_str(), "Running" | "Stopped")
            || require_online && (status.backend_state != "Running" || !node.online)
            || node.id != self.identity.node_id
            || !same(&node.ips, &self.identity.ips)
            || !same(&status.ips, &self.identity.ips)
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub async fn observe(&self) -> Result<Observation> {
        let s = self.status().await?;
        let p = parse_prefs(&self.request("GET", "/localapi/v0/prefs", b"").await?)?;
        if !s.version_pinned() || s.backend_state != "Running" {
            return Err(Error::Identity);
        }
        let node = s.self_node.ok_or(Error::Identity)?;
        if !node.online
            || node.id != self.identity.node_id
            || !same(&node.ips, &self.identity.ips)
            || !same(&s.ips, &self.identity.ips)
        {
            return Err(Error::Identity);
        }
        if !p.safe()
            || !(p.advertise_routes.is_empty() || same(&p.advertise_routes, &self.identity.routes))
        {
            return Err(Error::Preferences);
        }
        Ok(Observation {
            advertised: same(&p.advertise_routes, &self.identity.routes),
            approved: node.approved,
        })
    }
    #[cfg(test)]
    pub fn synthetic(placed: Rc<Placed>, socket: PathBuf, identity: Identity) -> Self {
        Self {
            placed,
            socket,
            identity,
            expected_peers: None,
            http: tokio::sync::Mutex::new(None),
        }
    }
}
#[cfg(test)]
mod enrolled_tests {
    #[test]
    fn full_peer_identity_matches_ids_and_all_logical_ips_without_enabling_ipv6_routes() {
        use super::*;
        let expected = vec![crate::operation::EnrolledPeer {
            node_id: "peer-one".into(),
            expired: false,
            in_network_map: true,
            ips: vec![
                "100.64.0.8".parse().unwrap(),
                "fd7a:115c:a1e0::8".parse().unwrap(),
            ],
        }];
        let value = serde_json::json!({"Version":"1.102.5","BackendState":"Running","TailscaleIPs":["100.64.0.7","fd7a:115c:a1e0::7"],
            "Self":{"ID":"node-self","Online":true,"ExitNodeOption":false,"TailscaleIPs":["100.64.0.7","fd7a:115c:a1e0::7"]},
            "Peer":{"synthetic-public-key":{"ID":"peer-one","Expired":null,"InNetworkMap":true,"Online":false,"TailscaleIPs":["100.64.0.8","fd7a:115c:a1e0::8"]}}});
        let parse = |v: &serde_json::Value| parse_status(&serde_json::to_vec(v).unwrap()).unwrap();
        match_peers(&parse(&value), &expected).unwrap();
        for fault in 0..8 {
            let mut wrong = value.clone();
            match fault {
                0 => wrong["Peer"]["synthetic-public-key"]["ID"] = "foreign-node-same-ip".into(),
                1 => {
                    wrong["Peer"]["synthetic-public-key"]["TailscaleIPs"] =
                        serde_json::json!(["100.64.0.9", "fd7a:115c:a1e0::8"])
                }
                2 => {
                    wrong["Peer"]["synthetic-public-key"]["TailscaleIPs"] =
                        serde_json::json!(["100.64.0.8", "fd7a:115c:a1e0::9"])
                }
                3 => {
                    wrong["Peer"]["synthetic-public-key"]["TailscaleIPs"] =
                        serde_json::json!(["100.64.0.8"])
                }
                4 => wrong["Peer"] = serde_json::json!({}),
                5 => {
                    wrong.as_object_mut().unwrap().remove("Peer");
                }
                6 => wrong["Peer"]["synthetic-public-key"]["Expired"] = true.into(),
                _ => wrong["Peer"]["synthetic-public-key"]["InNetworkMap"] = false.into(),
            }
            assert!(
                match_peers(&parse(&wrong), &expected).is_err(),
                "fault{fault}"
            );
        }
    }
}
