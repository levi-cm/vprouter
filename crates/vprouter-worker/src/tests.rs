use crate::{Error, client, localapi, placement::Placed, provider};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{
    net::SocketAddr,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    task::JoinHandle,
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
pub(crate) fn temp() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "vprouter-worker-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&p).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p
}
pub(crate) async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> (String, String, Vec<u8>) {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        assert!(head.len() < 8192);
    }
    let head = String::from_utf8(head).unwrap();
    let mut first = head.lines().next().unwrap().split_whitespace();
    let method = first.next().unwrap().into();
    let path = first.next().unwrap().into();
    let len = head
        .lines()
        .find_map(|s| {
            s.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|s| s.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; len];
    stream.read_exact(&mut body).await.unwrap();
    (method, path, body)
}
pub(crate) fn response(code: u16, body: &[u8]) -> Vec<u8> {
    let mut result = format!(
        "HTTP/1.1 {code} test\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n",
        body.len()
    )
    .into_bytes();
    result.extend_from_slice(body);
    result
}
pub(crate) struct UnixMock {
    pub path: PathBuf,
    dir: PathBuf,
    task: JoinHandle<()>,
}
impl Drop for UnixMock {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
impl UnixMock {
    pub fn scripted(
        script: Vec<(
            &'static str,
            &'static str,
            Option<serde_json::Value>,
            Vec<u8>,
        )>,
    ) -> Self {
        let dir = temp();
        let path = dir.join("api.sock");
        let server = UnixListener::bind(&path).unwrap();
        let task = tokio::spawn(async move {
            for (method, path, body, response) in script {
                let (mut stream, _) = server.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                assert_eq!((request.0.as_str(), request.1.as_str()), (method, path));
                if let Some(body) = body {
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&request.2).unwrap(),
                        body
                    );
                } else {
                    assert!(request.2.is_empty());
                }
                let mut response = response;
                if let Some(index) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                    response.splice(
                        index + 2..index + 2,
                        b"Connection: close\r\n".iter().copied(),
                    );
                }
                stream.write_all(&response).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        Self { path, dir, task }
    }
    pub async fn finished(&mut self) {
        (&mut self.task).await.unwrap();
    }
}
pub(crate) const PROVIDER: &[u8] =
    br#"{"mullvad_exit_ip":true,"ip":"1.2.3.4","mullvad_exit_ip_hostname":"de-fra-wg-404"}"#;
fn certificates(name: &str) -> (rustls::RootCertStore, rustls::ServerConfig) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let leaf = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = leaf.signed_by(&key, &issuer).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    (roots, server)
}
pub(crate) struct TlsMock {
    address: SocketAddr,
    roots: rustls::RootCertStore,
    task: JoinHandle<()>,
    pub(crate) connections: Arc<AtomicUsize>,
}
impl Drop for TlsMock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl TlsMock {
    pub(crate) async fn new(name: &str, replies: Vec<Vec<u8>>, connections: usize) -> Self {
        let (roots, config) = certificates(name);
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let task = tokio::spawn(async move {
            let per_connection = replies.len() / connections;
            let mut replies = replies.into_iter();
            for _ in 0..connections {
                let (stream, _) = listener.accept().await.unwrap();
                c.fetch_add(1, Ordering::Relaxed);
                let Ok(mut stream) = accept.accept(stream).await else {
                    return;
                };
                for _ in 0..per_connection {
                    let r = read_request(&mut stream).await;
                    assert_eq!((&*r.0, &*r.1, r.2.is_empty()), ("GET", "/json", true));
                    stream.write_all(&replies.next().unwrap()).await.unwrap();
                    stream.flush().await.unwrap();
                }
                // Graceful TLS close_notify avoids an accidental EOF oracle.
                let _ = stream.shutdown().await;
            }
        });
        Self {
            address,
            roots,
            task,
            connections: counter,
        }
    }
    pub(crate) fn provider(&self) -> provider::Provider {
        provider::Provider::synthetic(
            Rc::new(Placed::synthetic()),
            self.roots.clone(),
            self.address,
        )
    }
}
#[test]
fn production_has_no_authority_bypass() {
    assert_eq!(crate::start(), Err(Error::StructuralGap));
}
#[test]
fn provider_strict_shape_negative_server_duplicate_types_and_ip() {
    assert!(provider::parse(PROVIDER, "de-fra-wg-404").is_ok());
    for bytes in [
        br#"{"mullvad_exit_ip":true,"mullvad_exit_ip":false,"ip":"1.2.3.4","mullvad_exit_ip_hostname":"de-fra-wg-404"}"#.as_slice(),
        br#"{"mullvad_exit_ip":"true","ip":"1.2.3.4","mullvad_exit_ip_hostname":"de-fra-wg-404"}"#,
        br#"{"mullvad_exit_ip":true,"ip":123,"mullvad_exit_ip_hostname":"de-fra-wg-404"}"#,
        br#"{"mullvad_exit_ip":true,"ip":"1.2.3.4","mullvad_exit_ip_hostname":null}"#,
        br#"{"mullvad_exit_ip":true,"ip":"1.2.3.4","mullvad_exit_ip_hostname":"de-fra-wg-404","other":{"k":1,"k":2}}"#,
    ] {assert_eq!(provider::parse(bytes,"de-fra-wg-404"),Err(Error::Malformed));}
    for ip in [
        "127.0.0.1",
        "10.1.2.3",
        "100.64.0.1",
        "192.0.2.1",
        "0.0.0.0",
        "::1",
    ] {
        let bytes=serde_json::to_vec(&serde_json::json!({"mullvad_exit_ip":true,"ip":ip,"mullvad_exit_ip_hostname":"de-fra-wg-404"})).unwrap();
        assert!(provider::parse(&bytes, "de-fra-wg-404").is_err());
    }
    assert_eq!(
        provider::parse(PROVIDER, "de-fra-wg-405"),
        Err(Error::WrongServer)
    );
    let bytes = String::from_utf8(PROVIDER.to_vec())
        .unwrap()
        .replace("true", "false");
    assert_eq!(
        provider::parse(bytes.as_bytes(), "de-fra-wg-404"),
        Err(Error::ProviderNegative)
    );
}
#[tokio::test]
async fn actual_tls_verified_fixed_hostname_and_reused_connection() {
    let server = TlsMock::new(
        "am.i.mullvad.net",
        vec![response(200, PROVIDER), response(200, PROVIDER)],
        1,
    )
    .await;
    let mut p = server.provider();
    assert!(p.confirm().await.is_ok());
    assert!(p.confirm().await.is_ok());
    assert_eq!(server.connections.load(Ordering::Relaxed), 1);
}
#[tokio::test]
async fn actual_tls_unknown_ca_and_hostname_mismatch_are_permanent() {
    let server = TlsMock::new("am.i.mullvad.net", vec![response(200, PROVIDER)], 1).await;
    let mut p = provider::Provider::synthetic(
        Rc::new(Placed::synthetic()),
        rustls::RootCertStore::empty(),
        server.address,
    );
    assert_eq!(p.confirm().await, Err(Error::Tls));
    let server = TlsMock::new("wrong.invalid", vec![response(200, PROVIDER)], 1).await;
    assert_eq!(server.provider().confirm().await, Err(Error::Tls));
}
#[tokio::test]
async fn actual_tls_http_status_compression_malformed_chunk_and_oversize() {
    for (raw, expected) in [
        (response(503, b"SECRET ERROR"), Error::HttpTransient),
        (response(429, b"SECRET"), Error::HttpTransient),
        (response(408, b"SECRET"), Error::HttpTransient),
        (response(403, b"SECRET"), Error::HttpPermanent),
        (response(302, b"SECRET"), Error::HttpPermanent),
        (
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx".to_vec(),
            Error::Malformed,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nbad\r\n".to_vec(),
            Error::Malformed,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n".to_vec(),
            Error::Oversized,
        ),
        (response(200, &vec![b'x'; 16385]), Error::Oversized),
        (
            format!(
                "HTTP/1.1 200 OK\r\nX-Oversize: {}\r\n\r\n",
                "a".repeat(9000)
            )
            .into_bytes(),
            Error::Malformed,
        ),
    ] {
        let server = TlsMock::new("am.i.mullvad.net", vec![raw], 1).await;
        assert_eq!(server.provider().confirm().await, Err(expected));
    }
    let chunk = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        PROVIDER.len(),
        std::str::from_utf8(PROVIDER).unwrap()
    )
    .into_bytes();
    assert!(
        TlsMock::new("am.i.mullvad.net", vec![chunk], 1)
            .await
            .provider()
            .confirm()
            .await
            .is_ok()
    );
}
pub(crate) fn identity() -> localapi::Identity {
    localapi::Identity {
        node_id: "n123".into(),
        ips: vec!["100.64.0.7".parse().unwrap()],
        routes: vec!["0.0.0.0/0".into(), "::/0".into()],
    }
}
pub(crate) fn status() -> serde_json::Value {
    serde_json::json!({"Version":"1.102.5-1-t5fb2a81b0","BackendState":"Running","TailscaleIPs":["100.64.0.7"],"Self":{"ID":"n123","Online":true,"ExitNodeOption":false,"TailscaleIPs":["100.64.0.7"]},"AuthURL":"SYNTHETIC_SECRET_NOT_TO_LOG"})
}
pub(crate) fn prefs(routes: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"WantRunning":true,"LoggedOut":false,"RouteAll":false,"CorpDNS":false,"AdvertiseRoutes":routes,"NetfilterMode":0,"ExitNodeID":"","ExitNodeIP":"","NoStatefulFiltering":true,"RunSSH":false,"NoSNAT":true})
}
pub(crate) fn json_response(v: serde_json::Value) -> Vec<u8> {
    response(200, &serde_json::to_vec(&v).unwrap())
}
#[tokio::test]
async fn actual_unix_initialize_withdraws_first_and_only_writes_masked_preferences() {
    let empty = prefs(serde_json::Value::Null);
    let mut server = UnixMock::scripted(vec![
        (
            "PATCH",
            "/localapi/v0/prefs",
            Some(serde_json::json!({"AdvertiseRoutes":[],"AdvertiseRoutesSet":true})),
            json_response(empty.clone()),
        ),
        (
            "GET",
            "/localapi/v0/prefs",
            None,
            json_response(empty.clone()),
        ),
        (
            "PATCH",
            "/localapi/v0/prefs",
            Some(
                serde_json::json!({"NetfilterMode":0,"NetfilterModeSet":true,"RunSSH":false,"RunSSHSet":true,"NoSNAT":true,"NoSNATSet":true}),
            ),
            json_response(empty.clone()),
        ),
        (
            "GET",
            "/localapi/v0/prefs",
            None,
            json_response(empty.clone()),
        ),
        (
            "GET",
            "/localapi/v0/status?peers=false",
            None,
            json_response(status()),
        ),
        ("GET", "/localapi/v0/prefs", None, json_response(empty)),
        (
            "PATCH",
            "/localapi/v0/prefs",
            Some(
                serde_json::json!({"AdvertiseRoutes":["0.0.0.0/0","::/0"],"AdvertiseRoutesSet":true}),
            ),
            json_response(prefs(serde_json::json!(["0.0.0.0/0", "::/0"]))),
        ),
    ]);
    let api = localapi::LocalApi::synthetic(
        Rc::new(Placed::synthetic()),
        server.path.clone(),
        identity(),
    );
    api.initialize().await.unwrap();
    assert!(!api.observe().await.unwrap().advertised);
    api.advertise().await.unwrap();
    server.finished().await;
}
#[tokio::test]
async fn actual_unix_refuses_identity_approval_version_ip_and_preferences_drift() {
    let mut cases = Vec::new();
    for (field, value) in [
        ("Online", serde_json::json!(false)),
        ("ID", serde_json::json!("other")),
        ("TailscaleIPs", serde_json::json!(["100.64.0.8"])),
    ] {
        let mut s = status();
        s["Self"][field] = value;
        cases.push((s, prefs(serde_json::json!([])), Error::Identity));
    }
    for (field, value) in [
        ("Version", serde_json::json!("1.102.6")),
        ("BackendState", serde_json::json!("NeedsLogin")),
        ("TailscaleIPs", serde_json::json!([])),
    ] {
        let mut s = status();
        s[field] = value;
        cases.push((s, prefs(serde_json::json!([])), Error::Identity));
    }
    for (field, value) in [
        ("NetfilterMode", serde_json::json!(2)),
        ("RunSSH", serde_json::json!(true)),
        ("NoSNAT", serde_json::json!(false)),
        ("RouteAll", serde_json::json!(true)),
        ("CorpDNS", serde_json::json!(true)),
        ("ExitNodeID", serde_json::json!("other")),
        ("ExitNodeIP", serde_json::json!("100.64.0.8")),
        ("AdvertiseRoutes", serde_json::json!(["10.0.0.0/8"])),
        ("LoggedOut", serde_json::json!(true)),
        ("WantRunning", serde_json::json!(false)),
    ] {
        let mut p = prefs(serde_json::json!([]));
        p[field] = value;
        cases.push((status(), p, Error::Preferences));
    }
    for (s, p, e) in cases {
        let mut server = UnixMock::scripted(vec![
            (
                "GET",
                "/localapi/v0/status?peers=false",
                None,
                json_response(s),
            ),
            ("GET", "/localapi/v0/prefs", None, json_response(p)),
        ]);
        let api = localapi::LocalApi::synthetic(
            Rc::new(Placed::synthetic()),
            server.path.clone(),
            identity(),
        );
        assert!(matches!(api.observe().await,Err(error) if error==e));
        server.finished().await;
    }
}
#[tokio::test]
async fn unix_parser_rejects_bad_frames_deadline_and_cancellation_closes_connection() {
    let mut server = UnixMock::scripted(vec![(
        "GET",
        "/localapi/v0/status?peers=false",
        None,
        b"BAD RESPONSE\r\n\r\n".to_vec(),
    )]);
    assert!(matches!(
        client::unix_request(
            &server.path,
            "GET",
            "/localapi/v0/status?peers=false",
            b"",
            65536
        )
        .await,
        Err(Error::Malformed)
    ));
    server.finished().await;
    let dir = temp();
    let path = dir.join("slow.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        read_request(&mut s).await;
        // Real EOF proves the connection driver did not survive timeout.
        let mut b = [0];
        assert_eq!(s.read(&mut b).await.unwrap(), 0);
    });
    let before = tokio::time::Instant::now();
    assert!(matches!(
        client::unix_request(&path, "GET", "/localapi/v0/status?peers=false", b"", 65536).await,
        Err(Error::Deadline)
    ));
    assert!(
        before.elapsed() >= Duration::from_secs(2) && before.elapsed() < Duration::from_secs(3)
    );
    task.await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn actual_tls_slow_headers_and_slow_body_obey_twelve_second_attempt_limit() {
    async fn case(partial_body: bool) {
        let (roots, config) = certificates("am.i.mullvad.net");
        let server = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = server.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(stream)
                .await
                .unwrap();
            read_request(&mut tls).await;
            if partial_body {
                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
                    .await
                    .unwrap();
                tls.flush().await.unwrap();
            }
            let mut byte = [0];
            let result = tls.read(&mut byte).await;
            assert!(matches!(result, Ok(0)) || result.is_err());
        });
        let mut p = provider::Provider::synthetic(Rc::new(Placed::synthetic()), roots, address);
        let now = tokio::time::Instant::now();
        assert_eq!(p.confirm().await, Err(Error::Deadline));
        assert!(
            now.elapsed() >= Duration::from_secs(12) && now.elapsed() < Duration::from_secs(14)
        );
        task.await.unwrap();
    }
    tokio::join!(case(false), case(true));
}
#[tokio::test]
async fn localapi_reuses_one_namespace_local_unix_connection() {
    let dir = temp();
    let path = dir.join("reused.sock");
    let server = UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.unwrap();
        for (path, body) in [
            ("/localapi/v0/status?peers=false", status()),
            ("/localapi/v0/prefs", prefs(serde_json::json!([]))),
            ("/localapi/v0/status?peers=false", status()),
            ("/localapi/v0/prefs", prefs(serde_json::json!([]))),
        ] {
            let request = read_request(&mut stream).await;
            assert_eq!((request.0.as_str(), request.1.as_str()), ("GET", path));
            stream.write_all(&json_response(body)).await.unwrap();
        }
    });
    let api = localapi::LocalApi::synthetic(Rc::new(Placed::synthetic()), path, identity());
    assert!(!api.observe().await.unwrap().approved);
    assert!(!api.observe().await.unwrap().approved);
    task.await.unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn localapi_duplicate_and_invalid_relevant_types_never_supply_approval() {
    let bytes = serde_json::to_vec(&status()).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let duplicate = text.replacen("\"Online\":true", "\"Online\":true,\"Online\":false", 1);
    assert!(matches!(
        localapi::parse_status(duplicate.as_bytes()),
        Err(Error::Malformed)
    ));
    for value in [
        serde_json::Value::Null,
        serde_json::json!("true"),
        serde_json::json!(1),
    ] {
        let mut s = status();
        s["Self"]["Online"] = value;
        assert!(matches!(
            localapi::parse_status(&serde_json::to_vec(&s).unwrap()),
            Err(Error::Malformed)
        ));
    }
    let mut p = prefs(serde_json::Value::Null);
    p.as_object_mut().unwrap().remove("AdvertiseRoutes");
    assert!(matches!(
        localapi::parse_prefs(&serde_json::to_vec(&p).unwrap()),
        Err(Error::Malformed)
    ));
}
#[tokio::test]
async fn health_file_is_atomic_private_and_refuses_symlink_hardlink_and_pending_collision() {
    use rustix::fs::{self, Mode, OFlags};
    use std::os::unix::fs::MetadataExt;
    let dir = temp();
    let fd = fs::open(
        &dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let publisher = crate::publish::Publisher::synthetic(fd);
    let machine = vprouter_core::state::HealthMachine::new(
        vprouter_core::config::ExitMode::Mullvad,
        Some("de-fra-wg-404"),
        "n123",
    )
    .unwrap();
    let status = machine.status(0.0).unwrap();
    publisher.write(&status).await.unwrap();
    publisher.write(&status).await.unwrap();
    let path = dir.join("health.json");
    let m = std::fs::symlink_metadata(&path).unwrap();
    assert_eq!(m.mode() & 0o7777, 0o600);
    assert_eq!(m.nlink(), 1);
    assert!(!dir.join(".health.json.pending").exists());
    std::fs::hard_link(&path, dir.join("hard")).unwrap();
    assert_eq!(publisher.write(&status).await, Err(Error::Storage));
    std::fs::remove_file(dir.join("hard")).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("target", &path).unwrap();
    assert_eq!(publisher.write(&status).await, Err(Error::Storage));
    std::fs::remove_file(&path).unwrap();
    std::fs::write(dir.join(".health.json.pending"), b"untrusted").unwrap();
    assert_eq!(publisher.write(&status).await, Err(Error::Storage));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn stalled_health_writer_has_bounded_one_in_flight_queue() {
    use rustix::fs::{self, Mode, OFlags};
    let path = temp();
    let fd = fs::open(
        &path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let (release, stall) = std::sync::mpsc::channel();
    let p = crate::publish::Publisher::synthetic_stall(fd, Some(stall));
    let machine = vprouter_core::state::HealthMachine::new(
        vprouter_core::config::ExitMode::Mullvad,
        Some("de-fra-wg-404"),
        "n123",
    )
    .unwrap();
    let status = machine.status(0.0).unwrap();
    let before = tokio::time::Instant::now();
    assert_eq!(p.write(&status).await, Err(Error::Storage));
    assert!(
        before.elapsed() >= Duration::from_secs(2) && before.elapsed() < Duration::from_secs(3)
    );
    let before = tokio::time::Instant::now();
    assert_eq!(p.write(&status).await, Err(Error::Storage));
    assert!(before.elapsed() < Duration::from_millis(100));
    release.send(()).unwrap();
    for _ in 0..100 {
        if path.join("health.json").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Bounded caller returned while the one actor was stalled; no second task,
    // queue expansion or monitor/event-loop block was introduced.
    assert!(path.join("health.json").exists());
    drop(p);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn changed_namespace_refuses_before_any_client_or_socket_is_created() {
    let placed = Rc::new(Placed::wrong_namespace());
    assert!(matches!(
        provider::Provider::new(
            placed.clone(),
            "10.64.0.1".parse().unwrap(),
            "de-fra-wg-404"
        ),
        Err(Error::NamespaceChanged)
    ));
    assert!(matches!(
        localapi::LocalApi::new(placed, identity()),
        Err(Error::NamespaceChanged)
    ));
    let placed = Rc::new(Placed::synthetic());
    assert!(matches!(
        provider::Provider::new(placed, "1.1.1.1".parse().unwrap(), "de-fra-wg-404"),
        Err(Error::InvalidConfiguration)
    ));
}
