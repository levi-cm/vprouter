//! GET-only Docker API. External response data is projected through typed fields.
pub mod fixed;
mod host_config;
mod http;
#[cfg(test)]
mod http_tests;
mod managed_json;
mod managed_value;
mod transport;
use crate::{Error, Result};
pub use managed_value::{InputString, InputValue};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::timeout;

const LIMIT: usize = 1024 * 1024;
const API: &str = "/v1.45";
const STAGE: Duration = Duration::from_secs(3);
#[derive(Clone)]
pub struct DockerClient {
    socket: PathBuf,
    stage: Duration,
    #[cfg(test)]
    injected_test_socket: bool,
}
impl Default for DockerClient {
    fn default() -> Self {
        Self {
            socket: "/run/docker.sock".into(),
            stage: STAGE,
            #[cfg(test)]
            injected_test_socket: false,
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Version {
    version: InputString,
    api_version: InputString,
    #[serde(rename = "MinAPIVersion")]
    min_api_version: InputString,
}
#[derive(Clone, Debug, Serialize)]
pub struct DockerVersion {
    pub engine_minimum: &'static str,
    pub requested_api: &'static str,
    pub compatible: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Listing {
    id: InputString,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Inspect {
    id: InputString,
    name: InputString,
    image: InputString,
    restart_count: u64,
    state: ContainerState,
    config: ContainerConfig,
    host_config: HostConfig,
    #[serde(default)]
    mounts: Vec<Mount>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerConfig {
    #[serde(default)]
    labels: Option<BTreeMap<InputString, InputString>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContainerState {
    status: InputString,
    pid: u32,
    started_at: InputString,
    #[serde(rename = "OOMKilled")]
    oom_killed: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
    network_mode: InputString,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Mount {
    #[serde(rename = "Type")]
    kind: InputString,
    source: InputString,
    destination: InputString,
    #[serde(rename = "RW")]
    rw: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct MountReference {
    pub kind: String,
    pub source: Option<PathBuf>,
    pub destination: Option<PathBuf>,
    pub writable: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Container {
    pub id: String,
    pub name: Option<String>,
    pub image: String,
    pub pid: u32,
    pub started_at: Option<String>,
    pub state: &'static str,
    pub restarts: u64,
    pub oom_killed: bool,
    pub ownership: BTreeMap<String, String>,
    pub mounts: Vec<MountReference>,
    pub network_mode: Option<String>,
}
fn version(s: &str) -> Option<(u32, u32)> {
    let mut parts = s.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}
fn id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub(crate) fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}
fn scoped_value(s: &str) -> bool {
    s.len() <= 63 && name(s)
}
fn clean_path(s: &str) -> Option<PathBuf> {
    (s.len() <= 4096
        && s.starts_with('/')
        && s != "/"
        && !s.chars().any(char::is_control)
        && s.split('/')
            .skip(1)
            .all(|s| !s.is_empty() && s != "." && s != ".."))
    .then(|| s.into())
}
impl TryFrom<Inspect> for Container {
    type Error = Error;
    fn try_from(i: Inspect) -> Result<Self> {
        if !id(&i.id) || !i.image.strip_prefix("sha256:").is_some_and(id) || i.mounts.len() > 256 {
            return Err(Error::InvalidInventory);
        }
        let ownership = i
            .config
            .labels
            .unwrap_or_default()
            .into_iter()
            .filter(|(k, v)| {
                matches!(
                    k.as_str(),
                    "io.vprouter.deployment" | "io.vprouter.exit" | "io.vprouter.role"
                ) && scoped_value(v)
            })
            .map(|(k, v)| (k.as_str().to_owned(), v.as_str().to_owned()))
            .collect();
        let state = match i.state.status.as_str() {
            "created" => "created",
            "running" => "running",
            "paused" => "paused",
            "restarting" => "restarting",
            "removing" => "removing",
            "exited" => "exited",
            "dead" => "dead",
            _ => "unknown",
        };
        let started = &i.state.started_at;
        let started_at = (!started.is_empty()
            && started.len() <= 64
            && started
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b'T' | b'Z' | b'.' | b':')))
        .then(|| started.as_str().to_owned());
        let network_mode = if matches!(
            i.host_config.network_mode.as_str(),
            "none" | "bridge" | "host" | "default"
        ) || i
            .host_config
            .network_mode
            .strip_prefix("container:")
            .is_some_and(|s| id(s) || name(s))
        {
            Some(i.host_config.network_mode.as_str().to_owned())
        } else {
            None
        };
        Ok(Self {
            id: i.id.as_str().to_owned(),
            name: i
                .name
                .strip_prefix('/')
                .filter(|s| name(s))
                .map(str::to_owned),
            image: i.image.as_str().to_owned(),
            pid: i.state.pid,
            started_at,
            state,
            restarts: i.restart_count,
            oom_killed: i.state.oom_killed,
            ownership,
            network_mode,
            mounts: i
                .mounts
                .into_iter()
                .map(|m| MountReference {
                    kind: match m.kind.as_str() {
                        "bind" => "bind",
                        "volume" => "volume",
                        "tmpfs" => "tmpfs",
                        _ => "unknown",
                    }
                    .into(),
                    source: clean_path(&m.source),
                    destination: clean_path(&m.destination),
                    writable: m.rw,
                })
                .collect(),
        })
    }
}
/// Dedicated enforcement projection. Unlike observational inventory, every
/// required functional field is mandatory and retains its exact Docker value.
/// Unknown Config fields are skipped; HostConfig extras (including logging)
/// are retained as wiping input values until the exact policy rejects/accepts them.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LaunchContainer {
    pub id: InputString,
    pub image: InputString,
    pub state: LaunchState,
    pub config: LaunchConfig,
    pub host_config: LaunchHostConfig,
    pub mounts: Vec<LaunchMount>,
    #[serde(rename = "AppArmorProfile")]
    pub app_armor_profile: InputString,
    pub process_label: InputString,
    pub mount_label: InputString,
}
impl LaunchContainer {
    /// Decode untrusted Docker metadata only; this does not grant admission.
    /// Ingress permanently taints the calling process even on a parse error.
    pub fn decode_json(bytes: &[u8]) -> Result<Self> {
        vprouter_core::secret_boundary::mark_ingress();
        managed_json::decode(bytes).map_err(|_| Error::DockerProtocol)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LaunchState {
    pub running: bool,
    pub paused: bool,
    pub restarting: bool,
    pub dead: bool,
    pub pid: u32,
    pub started_at: InputString,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LaunchConfig {
    pub labels: BTreeMap<InputString, InputString>,
    pub user: InputString,
    #[serde(deserialize_with = "required_option")]
    pub volumes: Option<BTreeMap<InputString, InputValue>>,
}
pub struct LaunchHostConfig {
    pub network_mode: InputString,
    pub privileged: bool,
    pub readonly_rootfs: bool,
    pub pid_mode: InputString,
    pub userns_mode: InputString,
    pub cgroupns_mode: InputString,
    pub ipc_mode: InputString,
    pub uts_mode: InputString,
    pub cap_add: Option<Vec<InputString>>,
    pub cap_drop: Option<Vec<InputString>>,
    pub security_opt: Option<Vec<InputString>>,
    pub binds: Option<Vec<InputString>>,
    // Docker 26 omits this field when the option is inactive.
    pub mounts: Option<Vec<InputValue>>,
    pub devices: Vec<InputValue>,
    pub device_requests: Option<Vec<InputValue>>,
    pub device_cgroup_rules: Option<Vec<InputString>>,
    pub volumes_from: Option<Vec<InputString>>,
    // Docker 26 omits this field when the option is inactive.
    pub tmpfs: Option<BTreeMap<InputString, InputString>>,
    // Docker 26 omits this field when the option is inactive.
    pub sysctls: Option<BTreeMap<InputString, InputString>>,
    pub group_add: Option<Vec<InputString>>,
    pub cgroup_parent: InputString,
    pub runtime: InputString,
    // Docker 26 omits this field when the option is inactive.
    pub init: Option<bool>,
    pub masked_paths: Option<Vec<InputString>>,
    pub readonly_paths: Option<Vec<InputString>>,
    pub additional: BTreeMap<InputString, InputValue>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LaunchMount {
    #[serde(rename = "Type")]
    pub kind: InputString,
    pub source: InputString,
    pub destination: InputString,
    #[serde(rename = "RW")]
    pub writable: bool,
    pub propagation: InputString,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LaunchImage {
    pub id: InputString,
    pub repo_digests: Vec<InputString>,
    pub os: InputString,
    pub architecture: InputString,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LaunchDaemon {
    pub security_options: Vec<InputString>,
    pub cgroup_driver: InputString,
    pub cgroup_version: InputString,
    #[serde(rename = "OSType")]
    pub os_type: InputString,
}
fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
impl DockerClient {
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        // Every caller uses static endpoint syntax and validated hex IDs.
        if path.len() > 256 {
            return Err(Error::DockerProtocol);
        }
        timeout(Duration::from_secs(9), async {
            let bytes = transport::receive(&self.socket, path, self.stage).await?;
            managed_json::decode(&bytes)
        })
        .await
        .map_err(|_| Error::DockerTimeout)?
    }
    pub async fn version(&self) -> Result<DockerVersion> {
        #[cfg(test)]
        let check_socket = !self.injected_test_socket;
        #[cfg(not(test))]
        let check_socket = true;
        if check_socket {
            crate::storage::metadata(self.socket_path(), crate::storage::Kind::DockerSocket)?;
        }
        let v: Version = self.get("/version").await?;
        if !version(&v.version).is_some_and(|v| v >= (26, 0))
            || !version(&v.api_version).is_some_and(|v| v >= (1, 45))
            || !version(&v.min_api_version).is_some_and(|v| v <= (1, 45))
        {
            return Err(Error::DockerIncompatible);
        }
        Ok(DockerVersion {
            engine_minimum: "26.0",
            requested_api: "1.45",
            compatible: true,
        })
    }
    /// Bounded full inventory permits NetworkMode dependents to be identified.
    pub async fn inventory(&self) -> Result<Vec<Container>> {
        timeout(Duration::from_secs(9), async {
            self.version().await?;
            let listing: Vec<Listing> = self.get(&format!("{API}/containers/json?all=1")).await?;
            if listing.len() > 128 {
                return Err(Error::TooLarge);
            }
            let mut containers: Vec<Container> = Vec::new();
            for item in listing {
                if !id(&item.id) {
                    return Err(Error::InvalidInventory);
                }
                let inspect: Inspect = self
                    .get(&format!("{API}/containers/{}/json", item.id.as_str()))
                    .await?;
                if inspect.id != item.id {
                    return Err(Error::InvalidInventory);
                }
                containers.push(inspect.try_into()?);
            }
            containers.sort_by(|a, b| a.id.cmp(&b.id));
            Ok(containers)
        })
        .await
        .map_err(|_| Error::DockerTimeout)?
    }
    /// Root/socket checks and native compatibility negotiation precede use.
    /// IDs are always complete content IDs; names/short IDs are refused.
    pub async fn launch_container(&self, expected_id: &str) -> Result<LaunchContainer> {
        if !id(expected_id) {
            return Err(Error::InvalidInventory);
        }
        self.version().await?;
        let value: LaunchContainer = self
            .get(&format!("{API}/containers/{expected_id}/json"))
            .await?;
        if value.id != expected_id {
            return Err(Error::InvalidInventory);
        }
        Ok(value)
    }
    pub async fn launch_image(&self, content_id: &str) -> Result<LaunchImage> {
        if !content_id.strip_prefix("sha256:").is_some_and(id) {
            return Err(Error::InvalidInventory);
        }
        self.version().await?;
        self.get(&format!("{API}/images/{content_id}/json")).await
    }
    pub async fn launch_daemon(&self) -> Result<LaunchDaemon> {
        self.version().await?;
        self.get(&format!("{API}/info")).await
    }
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::Temp;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };
    #[test]
    fn raw_http_ingress_taints_before_invalid_response_is_parsed() {
        const CHILD: &str = "VPROUTER_DOCKER_INGRESS_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "docker::tests::raw_http_ingress_taints_before_invalid_response_is_parsed",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }
        assert!(vprouter_core::secret_boundary::pristine());
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (result, _) = response(b"not HTTP DO_NOT_PRINT_SECRET".to_vec(), false).await;
                assert!(result.is_err());
                assert!(!vprouter_core::secret_boundary::pristine());
            });
        // Neither HTTP/parser failure nor runtime/buffer Drop clears ingress.
        assert!(!vprouter_core::secret_boundary::pristine());
    }
    async fn response(raw: Vec<u8>, delay: bool) -> (Result<serde_json::Value>, Vec<u8>) {
        let t = Temp::new();
        let p = t.0.join("docker.sock");
        let listener = UnixListener::bind(&p).unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = vec![0; 4096];
            let n = s.read(&mut b).await.unwrap();
            b.truncate(n);
            if delay {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let _ = s.write_all(&raw).await;
            b
        });
        let client = DockerClient {
            socket: p,
            stage: Duration::from_millis(50),
            injected_test_socket: true,
        };
        let r = client.get("/v1.45/test").await;
        (r, task.await.unwrap())
    }
    #[tokio::test(flavor = "current_thread")]
    async fn chunked_http_is_parsed_without_external_data_leaks() {
        let (r,request) = response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n2\r\n1}\r\n0\r\n\r\n".to_vec(),false).await;
        assert_eq!(r.unwrap()["a"], 1);
        assert!(request.starts_with(b"GET /v1.45/test HTTP/1.1"));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn header_success_cannot_hide_a_stalled_body() {
        let t = Temp::new();
        let socket = t.0.join("body.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let received = stream.read(&mut request).await.unwrap();
            assert!(received > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
        });
        let client = DockerClient {
            socket,
            stage: Duration::from_millis(50),
            injected_test_socket: true,
        };
        assert_eq!(
            client.get::<serde_json::Value>("/version").await,
            Err(Error::DockerTimeout)
        );
        server.await.unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn version_and_inspection_use_compatible_explicit_get_only_api() {
        let t = Temp::new();
        let socket = t.0.join("inventory.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in [
                serde_json::json!({"Version":"26.0.0","ApiVersion":"1.45","MinAPIVersion":"1.24","UnknownFutureField":{"env":"DO_NOT_PRINT_SECRET"}}),
                serde_json::json!([{"Id":"a".repeat(64),"Names":["/primary"],"Env":["DO_NOT_PRINT_SECRET"]}]),
                serde_json::json!({"Id":"a".repeat(64),"Name":"/primary","Image":format!("sha256:{}","b".repeat(64)),"RestartCount":0,
                    "State":{"Status":"running","Pid":42,"StartedAt":"2026-10-24T00:00:00Z","OOMKilled":false},
                    "Config":{"Env":["DO_NOT_PRINT_SECRET"],"Labels":null},"HostConfig":{"NetworkMode":"none"},"Mounts":[]}),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let n = stream.read(&mut request).await.unwrap();
                request.truncate(n);
                requests.push(request);
                let body = serde_json::to_vec(&body).unwrap();
                let mut reply =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                        .into_bytes();
                reply.extend(body);
                stream.write_all(&reply).await.unwrap();
            }
            requests
        });
        let client = DockerClient {
            socket,
            stage: Duration::from_secs(1),
            injected_test_socket: true,
        };
        let inventory = client.inventory().await.unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].pid, 42);
        assert!(
            !serde_json::to_string(&inventory)
                .unwrap()
                .contains("DO_NOT_PRINT_SECRET")
        );
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with(b"GET /version "));
        assert!(requests[1].starts_with(b"GET /v1.45/containers/json?all=1 "));
        assert!(
            requests[2]
                .starts_with(format!("GET /v1.45/containers/{}/json ", "a".repeat(64)).as_bytes())
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn launch_image_and_daemon_native_http_keep_fixed_get_paths() {
        let t = Temp::new();
        let socket = t.0.join("launch.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let content = format!("sha256:{}", "b".repeat(64));
        let expected = content.clone();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for body in [
                serde_json::json!({"Version":"26.1.5","ApiVersion":"1.45","MinAPIVersion":"1.24"}),
                serde_json::json!({"Id":expected,"RepoDigests":[format!("tailscale/tailscale@sha256:{}","a".repeat(64))],"Os":"linux","Architecture":"amd64","Config":{"Env":["DO_NOT_PRINT_SECRET"]}}),
                serde_json::json!({"Version":"26.1.5","ApiVersion":"1.45","MinAPIVersion":"1.24"}),
                serde_json::json!({"SecurityOptions":["name=seccomp,profile=builtin"],"CgroupDriver":"systemd","CgroupVersion":"2","OSType":"linux"}),
                serde_json::json!({"Version":"26.1.5","ApiVersion":"1.45","MinAPIVersion":"1.24"}),
                serde_json::json!({"Env":["DO_NOT_PRINT_SECRET"]}),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4096];
                let n = stream.read(&mut request).await.unwrap();
                request.truncate(n);
                requests.push(request);
                let body = serde_json::to_vec(&body).unwrap();
                let mut reply =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                        .into_bytes();
                reply.extend(body);
                stream.write_all(&reply).await.unwrap();
            }
            requests
        });
        let client = DockerClient {
            socket,
            stage: Duration::from_secs(1),
            injected_test_socket: true,
        };
        let image = client.launch_image(&content).await.unwrap();
        assert_eq!(image.id, content);
        assert_eq!(
            client.launch_daemon().await.unwrap().cgroup_driver,
            "systemd"
        );
        let container_id = "a".repeat(64);
        assert!(matches!(
            client.launch_container(&container_id).await,
            Err(Error::DockerProtocol)
        ));
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with(b"GET /version "));
        assert!(requests[1].starts_with(format!("GET /v1.45/images/{content}/json ").as_bytes()));
        assert!(requests[2].starts_with(b"GET /version "));
        assert!(requests[3].starts_with(b"GET /v1.45/info "));
        assert!(requests[4].starts_with(b"GET /version "));
        assert!(
            requests[5]
                .starts_with(format!("GET /v1.45/containers/{container_id}/json ").as_bytes())
        );
        assert!(matches!(
            client.launch_container("short").await,
            Err(Error::InvalidInventory)
        ));
        assert!(matches!(
            client.launch_image("sha256:short").await,
            Err(Error::InvalidInventory)
        ));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn incompatible_version_never_proceeds_to_container_api() {
        let t = Temp::new();
        let socket = t.0.join("old.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let received = stream.read(&mut request).await.unwrap();
            assert!(received > 0);
            let body = br#"{"Version":"25.0.0","ApiVersion":"1.44","MinAPIVersion":"1.24"}"#;
            let mut raw =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
            raw.extend_from_slice(body);
            stream.write_all(&raw).await.unwrap();
        });
        let client = DockerClient {
            socket,
            stage: Duration::from_secs(1),
            injected_test_socket: true,
        };
        assert!(matches!(
            client.inventory().await,
            Err(Error::DockerIncompatible)
        ));
        server.await.unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn rejects_oversize_malformed_denied_redirect_and_deadline() {
        for (raw, error) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n".to_vec(),
                Error::TooLarge,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nBAD_SECRET".to_vec(),
                Error::DockerProtocol,
            ),
            (
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
                Error::DockerHttpFailure,
            ),
            (
                b"HTTP/1.1 302 Found\r\nLocation: http://secret/\r\nContent-Length: 0\r\n\r\n"
                    .to_vec(),
                Error::DockerHttpFailure,
            ),
            (b"not http SECRET".to_vec(), Error::DockerProtocol),
        ] {
            assert_eq!(response(raw, false).await.0, Err(error));
        }
        assert_eq!(
            response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
                true
            )
            .await
            .0,
            Err(Error::DockerTimeout)
        );
        let body = vec![b' '; LIMIT + 1];
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n".to_vec();
        raw.extend(body);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(response(raw, false).await.0, Err(Error::TooLarge));
    }
    #[test]
    fn projected_inventory_never_serializes_env_or_foreign_labels() {
        let input = serde_json::json!({"Id":"a".repeat(64),"Name":"/bad\nSECRET","Image":format!("sha256:{}","b".repeat(64)),"RestartCount":2,
            "State":{"Status":"running","Pid":42,"StartedAt":"2026-10-24T00:00:00Z","OOMKilled":false,"Error":"SECRET"},
            "Config":{"Env":["TOKEN=SECRET"],"Labels":{"foreign":"SECRET","io.vprouter.exit":"primary"}},
            "HostConfig":{"NetworkMode":"none"},"Mounts":[]});
        let projected: Container = serde_json::from_value::<Inspect>(input)
            .unwrap()
            .try_into()
            .unwrap();
        let text = serde_json::to_string(&projected).unwrap();
        assert!(!text.contains("SECRET"));
        assert_eq!(projected.name, None);
        assert_eq!(projected.ownership.len(), 1);
    }
}
