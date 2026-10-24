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
    pub(crate) fn unenrolled(&self) -> bool {
        self.version_pinned()
            && matches!(
                self.backend_state.as_str(),
                "NeedsLogin" | "Stopped" | "NoState"
            )
            && self.self_node.is_none()
            && self.ips.is_empty()
    }
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
pub(crate) struct Observation {
    pub advertised: bool,
    pub approved: bool,
}
pub(crate) struct LocalApi {
    placed: Rc<Placed>,
    socket: PathBuf,
    identity: Identity,
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
            http: tokio::sync::Mutex::new(None),
        })
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
        self.request("PATCH","/localapi/v0/prefs",br#"{"NetfilterMode":0,"NetfilterModeSet":true,"RunSSH":false,"RunSSHSet":true,"NoSNAT":true,"NoSNATSet":true}"#).await?;
        let prefs = parse_prefs(&self.request("GET", "/localapi/v0/prefs", b"").await?)?;
        if !prefs.safe() || !prefs.advertise_routes.is_empty() {
            return Err(Error::Preferences);
        }
        Ok(())
    }
    pub async fn withdraw(&self) -> Result<()> {
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
        let body = serde_json::to_vec(
            &serde_json::json!({"AdvertiseRoutes":self.identity.routes,"AdvertiseRoutesSet":true}),
        )
        .map_err(|_| Error::Preferences)?;
        self.request("PATCH", "/localapi/v0/prefs", &body).await?;
        Ok(())
    }
    pub async fn observe(&self) -> Result<Observation> {
        let s = parse_status(
            &self
                .request("GET", "/localapi/v0/status?peers=false", b"")
                .await?,
        )?;
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
            http: tokio::sync::Mutex::new(None),
        }
    }
}
