use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use vprouter_core::{
    config::{Action as AdapterAction, DependencyAdapter, Mode},
    migration::{contract::*, *},
};
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static SEQ: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "vpr-migrate-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn file(p: impl AsRef<Path>, s: &str) {
    fs::write(&p, s).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
}
fn digest(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn identity() -> Identity {
    Identity {
        node_id: "fixture-node-1".into(),
        ips: vec!["100.64.0.7".into()],
        approved_routes: vec!["0.0.0.0/0".into()],
        expected_server: "de-fra-wg-404".into(),
    }
}
fn provenance() -> Provenance {
    Provenance {
        source_sha256: "a".repeat(64),
        image_sha256: "b".repeat(64),
        release_format: 1,
        state_format: 1,
    }
}
fn assets(layout: Layout) -> Bundle {
    let runtime = match layout {
        Layout::CurrentMain => "# synthetic main: provider check once; return provider data\n",
        _ => {
            "# synthetic retry: 408/429/5xx/transport; wait 1s; structural recheck; one retry; return provider data\n"
        }
    };
    Bundle {
        files: BTreeMap::from([
            (
                "image.fixture".into(),
                "synthetic legacy OCI artifact placeholder\n".into(),
            ),
            ("router_runtime.py".into(), runtime.into()),
            ("router.nft".into(), "# synthetic default drop\n".into()),
            ("Dockerfile".into(), "# synthetic pinned base\n".into()),
            (
                "docker-compose.yaml".into(),
                "# synthetic network none; primary names\n".into(),
            ),
            (
                "host/orchestrate.py".into(),
                "# synthetic quarantine before cleanup; real directory activation\n".into(),
            ),
            (
                "host/vprouter@.service".into(),
                "# synthetic primary service\n".into(),
            ),
            (
                "host/collector_services.py".into(),
                "# synthetic stop; start; stop\n".into(),
            ),
            (
                "host/collector-services.conf".into(),
                "# synthetic pre-start stop; post-start start; post-stop stop\n".into(),
            ),
        ]),
    }
}
fn fixture(layout: Layout) -> (Temp, Request) {
    let temp = Temp::new();
    let root = &temp.0;
    for d in ["current", "current/host", "opaque", "opaque/state"] {
        fs::create_dir(root.join(d)).unwrap();
        fs::set_permissions(root.join(d), fs::Permissions::from_mode(0o700)).unwrap();
    }
    file(
        root.join("offline-migration.fixture"),
        "synthetic-only-v1\n",
    );
    file(root.join(".allocations.lock"), "");
    file(
        root.join("opaque/state/tailscaled.state"),
        "SYNTHETIC IDENTITY BYTES - MUST NOT OPEN\n",
    );
    file(
        root.join("opaque/profile.wg"),
        "SYNTHETIC CREDENTIAL BYTES - MUST NOT OPEN\n",
    );
    let mut inventory = Inventory {
        schema_version: 1,
        hostname_users: HostnameUsers::CompleteFixtureDeclaration,
        layout: layout.clone(),
        host: Host::Debian13Systemd,
        ownership: Ownership::DeclaredFixture,
        provenance: provenance(),
        identity: identity(),
        service: "fixture-router".into(),
        container: "fixture-router".into(),
        uplink: "fixture-router-uplink".into(),
        dependencies: vec![],
    };
    inventory.provenance.source_sha256 =
        digest(serde_json::to_vec(&assets(layout.clone())).unwrap());
    inventory.provenance.image_sha256 =
        digest(assets(layout.clone()).files["image.fixture"].as_bytes());
    file(
        root.join("inventory.json"),
        &serde_json::to_string(&inventory).unwrap(),
    );
    let mut old = assets(layout);
    let legacy = LegacyConfig {
        name: "fixture-router".into(),
        profile: "/synthetic/profile.wg".into(),
        state_dir: "/synthetic/state".into(),
        image_ref: format!("sha256:{}", inventory.provenance.image_sha256),
        compose_dir: "/synthetic/release".into(),
        tailscale_hostname: Some("fixture-router".into()),
    };
    old.files.insert(
        "config.json".into(),
        serde_json::to_string(&legacy).unwrap(),
    );
    for (path, data) in old.files {
        file(root.join("current").join(path), &data);
    }
    let mut configuration = vprouter_core::config::Configuration::parse(include_bytes!(
        "../../../examples/v2/one.json"
    ))
    .unwrap();
    configuration.exits[0].id = "primary".into();
    configuration.exits[0].state_dir = "/synthetic/state".into();
    configuration.exits[0].mode = Mode::Mullvad {
        profile: "/synthetic/profile.wg".into(),
        expected_server: "de-fra-wg-404".into(),
    };
    configuration.gateway_image = format!("sha256:{}", "c".repeat(64));
    let mut release = assets(Layout::Retry84fb353);
    release.files.insert(
        "router_runtime.py".into(),
        "# synthetic Rust compatibility release\n".into(),
    );
    release.files.insert(
        "image.fixture".into(),
        "synthetic Rust OCI artifact placeholder\n".into(),
    );
    let mut pin = provenance();
    pin.release_format = 2;
    pin.image_sha256 = digest(release.files["image.fixture"].as_bytes());
    pin.source_sha256 = digest(serde_json::to_vec(&release).unwrap());
    configuration.gateway_image = format!("sha256:{}", pin.image_sha256);
    (
        temp,
        Request {
            configuration,
            release,
            provenance: pin,
        },
    )
}
fn inventory_edit(root: &Path, edit: impl FnOnce(&mut Inventory)) {
    let mut i: Inventory =
        serde_json::from_slice(&fs::read(root.join("inventory.json")).unwrap()).unwrap();
    edit(&mut i);
    file(
        root.join("inventory.json"),
        &serde_json::to_string(&i).unwrap(),
    );
}
struct Driver {
    actions: Vec<Action>,
    pins: BTreeMap<String, Pin>,
    release: String,
    fail: Option<Action>,
    running: bool,
    stopped_verified: bool,
    restored: bool,
}
impl Driver {
    fn new(i: &Inspection, p: &Plan) -> Self {
        Self {
            actions: vec![],
            pins: i.opaque_pins().clone(),
            release: digest(serde_json::to_vec(p.old_bundle()).unwrap()),
            fail: None,
            running: true,
            stopped_verified: false,
            restored: false,
        }
    }
}
impl FixtureDriver for Driver {
    fn perform(&mut self, o: &Obligation) -> Result<Receipt> {
        self.actions.push(o.action.clone());
        match &o.action {
            Action::StopService {} => {
                self.running = false;
                self.restored = false;
                self.stopped_verified = false;
            }
            Action::AllIdentityUsersStopped {} => {
                assert!(!self.running);
                self.stopped_verified = true;
            }
            Action::StoppedStateRetained {} | Action::CompatibleReleaseAndState {} => {
                assert!(self.stopped_verified && !self.running)
            }
            Action::RestoreSameIdentity {} => {
                assert!(self.stopped_verified && !self.running);
                self.restored = true;
            }
            Action::RenameExisting { .. } => assert!(self.restored && !self.running),
            Action::StartService {} => {
                assert!(
                    self.restored && self.stopped_verified && !self.running,
                    "duplicate/unverified identity start"
                );
                self.running = true;
            }
            _ => {}
        }
        if self.fail.as_ref() == Some(&o.action) {
            return Err(Error::Offline);
        }
        let observation = match &o.action {
            Action::IndependentQuarantine {} => Observation::Quarantine {
                enforcer: "independent-fixture-guard".into(),
                old_supervisor: "fixture-router".into(),
            },
            Action::AllIdentityUsersStopped {} => Observation::Stopped {
                identity_users: vec![],
            },
            Action::StoppedStateRetained {} | Action::CompatibleReleaseAndState {} => {
                Observation::Retained {
                    opaque: self.pins.clone(),
                    state_format: 1,
                    identity: identity(),
                    release_sha256: self.release.clone(),
                }
            }
            Action::RestoreSameIdentity {} => Observation::Identity {
                identity: identity(),
            },
            Action::RenameExisting { hostname } => Observation::Renamed {
                identity: identity(),
                hostname: hostname.clone(),
            },
            Action::Drain { adapter }
            | Action::PreStartStop { adapter }
            | Action::PostStopStop { adapter }
            | Action::Rebind { adapter }
            | Action::PostStartStart { adapter }
            | Action::HealthCheck { adapter } => Observation::Adapter {
                adapter: adapter.clone(),
                node_id: "fixture-node-1".into(),
            },
            _ => Observation::FixtureOnly {},
        };
        Ok(Receipt {
            obligation: o.clone(),
            observation,
        })
    }
}
fn read_bundle(root: &Path) -> Bundle {
    fn scan(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
        let mut entries = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                scan(root, &p, out)
            } else {
                out.insert(
                    p.strip_prefix(root).unwrap().to_str().unwrap().into(),
                    fs::read_to_string(p).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    scan(root, root, &mut files);
    Bundle { files }
}
fn assert_preserved(root: &Path) {
    assert_eq!(
        fs::read(root.join("opaque/state/tailscaled.state")).unwrap(),
        b"SYNTHETIC IDENTITY BYTES - MUST NOT OPEN\n"
    );
    assert_eq!(
        fs::read(root.join("opaque/profile.wg")).unwrap(),
        b"SYNTHETIC CREDENTIAL BYTES - MUST NOT OPEN\n"
    );
}
fn prepared() -> (Temp, FixtureTree, Inspection, Plan) {
    let (t, r) = with_adapter();
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree.inspect().unwrap();
    let p = i.plan(r).unwrap();
    (t, tree, i, p)
}
#[test]
fn inspect_plan_is_read_only_deterministic_and_handles_both_legacy_lines() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for layout in [
        Layout::CurrentMain,
        Layout::Retry528fece,
        Layout::Retry84fb353,
    ] {
        let (t, r) = fixture(layout);
        let before = read_bundle(&t.0.join("current"));
        let tree = FixtureTree::open(&t.0).expect("fixture inspection missing");
        let i = tree.inspect().unwrap();
        let p = i.plan(r.clone()).unwrap();
        assert_eq!(i.plan(r).unwrap().encode().unwrap(), p.encode().unwrap());
        assert_eq!(read_bundle(&t.0.join("current")), before);
        assert_eq!(
            Plan::parse(&p.encode().unwrap()).unwrap().fingerprint(),
            p.fingerprint()
        );
        assert_preserved(&t.0);
    }
}
#[test]
fn apply_resume_rollback_select_complete_bundles_and_never_touch_opaque_bytes() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    assert_eq!(
        tree.apply(&p, &mut d, &mut NoFault).unwrap(),
        Outcome::CommittedFixture
    );
    assert_eq!(read_bundle(&t.0.join("current")), *p.new_bundle());
    let before = fs::read(t.0.join("journal.json")).unwrap();
    assert_eq!(
        tree.resume(&p, &mut d, &mut NoFault).unwrap(),
        Outcome::CommittedFixture
    );
    assert_eq!(fs::read(t.0.join("journal.json")).unwrap(), before);
    assert_eq!(
        tree.rollback(&p, &mut d, &mut NoFault).unwrap(),
        Outcome::RolledBackFixture
    );
    assert_eq!(read_bundle(&t.0.join("current")), *p.old_bundle());
    let before = fs::read(t.0.join("journal.json")).unwrap();
    assert_eq!(
        tree.rollback(&p, &mut d, &mut NoFault).unwrap(),
        Outcome::RolledBackFixture
    );
    assert!(tree.apply(&p, &mut d, &mut NoFault).is_err());
    assert_eq!(before, fs::read(t.0.join("journal.json")).unwrap());
    assert_preserved(&t.0);
}
#[test]
fn preconditions_host_provenance_ownership_state_and_adapters_fail_closed() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for case in 0..10 {
        let (t, mut r) = fixture(Layout::CurrentMain);
        match case {
            0 => inventory_edit(&t.0, |i| i.host = Host::Unsupported),
            1 => inventory_edit(&t.0, |i| i.ownership = Ownership::Unknown),
            2 => inventory_edit(&t.0, |i| i.provenance.source_sha256.clear()),
            3 => inventory_edit(&t.0, |i| {
                i.dependencies.push(Dependency {
                    id: "custom".into(),
                    hook: "host/custom-hook.json".into(),
                    adapter: "missing".into(),
                    selector: Selector::Unknown,
                })
            }),
            4 => r.provenance.state_format = 2,
            5 => r.configuration.exits[0].state_dir = "/other/state".into(),
            6 => r.configuration.exits[0].id = "renamed".into(),
            7 => r.configuration.gateway_image = "latest".into(),
            8 => r.provenance.image_sha256 = "d".repeat(64),
            9 => r
                .release
                .files
                .insert("../escape".into(), "x".into())
                .map(|_| ())
                .unwrap_or(()),
            _ => unreachable!(),
        };
        let tree = FixtureTree::open(&t.0).unwrap();
        let i = tree.inspect();
        assert!(i.and_then(|i| i.plan(r)).is_err(), "case {case}");
        assert!(!t.0.join("journal.json").exists());
        assert_preserved(&t.0);
    }
}
#[test]
fn drift_refuses_before_any_lifecycle_action() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, tree, i, p) = prepared();
    file(t.0.join("current/router.nft"), "changed");
    let mut d = Driver::new(&i, &p);
    assert_eq!(tree.apply(&p, &mut d, &mut NoFault), Err(Error::Drift));
    assert!(d.actions.is_empty());
    assert!(!t.0.join("journal.json").exists());
}
#[test]
fn wrappers_are_observational_primary_shims_with_unknown_dns_ipv6() {
    let shims = wrappers("/synthetic/bin/vprouter", "primary").expect("wrappers missing");
    assert_eq!(shims.len(), 4);
    assert_eq!(shims[0].legacy_argv, vec!["router-runtime", "--status"]);
    assert_eq!(shims[0].stdout, "");
    for s in &shims {
        assert!(
            !s.rust_argv
                .iter()
                .any(|a| ["apply", "cleanup", "serve"].contains(&a.as_str()))
        );
    }
    let probe: serde_json::Value = serde_json::from_str(&shims[1].stdout).unwrap();
    assert_eq!(probe["dns_guard"], "not_tested");
    assert_eq!(probe["ipv6_guard"], "not_tested");
    for p in ["/a/../x", "/a//x", "/a/%2e/x", "/a/é", "relative"] {
        assert!(wrappers(p, "primary").is_err());
    }
}
#[test]
fn parser_rejects_encoding_growth_and_time_bearing_declarations() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, r) = fixture(Layout::CurrentMain);
    let bytes = fs::read(t.0.join("inventory.json")).unwrap();
    assert!(Inventory::parse(&bytes).is_ok());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["unknown"] = true.into();
    assert!(Inventory::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    for name in ["..", "a/b", "a%2fb", "a\\b", "a\0b", "é", "A", ""] {
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        v["container"] = name.into();
        assert!(Inventory::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree.inspect().unwrap();
    for timeout in ["-1", "NaN", "1.5", "0", "301", "18446744073709551616"] {
        let mut rr = serde_json::to_value(&r).unwrap();
        rr["configuration"]["dependency_adapters"] = serde_json::json!([{"id":"collector","drain":{"executable":"/synthetic/collector","argv":[],"timeout_seconds":1,"idempotent":true},"stop":{"executable":"/synthetic/collector","argv":[],"timeout_seconds":1,"idempotent":true},"start":{"executable":"/synthetic/collector","argv":[],"timeout_seconds":1,"idempotent":true},"rebind":{"executable":"/synthetic/collector","argv":[],"timeout_seconds":1,"idempotent":true},"health_check":{"executable":"/synthetic/collector","argv":[],"timeout_seconds":1,"idempotent":true}}]);
        let text = serde_json::to_string(&rr).unwrap().replace(
            "\"timeout_seconds\":1",
            &format!("\"timeout_seconds\":{timeout}"),
        );
        assert!(
            serde_json::from_str::<Request>(&text)
                .map_err(|_| Error::Invalid)
                .and_then(|r| i.plan(r))
                .is_err()
        );
    }
    assert!(Inventory::parse(&vec![b' '; 1024 * 1024 + 1]).is_err());
}
#[test]
fn missing_marker_alias_hardlink_or_permissions_never_admit_tree() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use std::os::unix::fs::symlink;
    for case in 0..7 {
        let (t, _) = fixture(Layout::CurrentMain);
        match case {
            0 => {
                fs::remove_file(t.0.join("offline-migration.fixture")).unwrap();
            }
            1 => {
                let p = t.0.join("current/router.nft");
                fs::remove_file(&p).unwrap();
                symlink("../../opaque/profile.wg", p).unwrap();
            }
            2 => {
                fs::hard_link(t.0.join("current/router.nft"), t.0.join("alias")).unwrap();
            }
            3 => {
                fs::set_permissions(t.0.join("current"), fs::Permissions::from_mode(0o755)).unwrap()
            }
            4 => {
                file(t.0.join("current/private-key"), "MUST NOT READ");
            }
            5 => {
                let p = t.0.join(".allocations.lock");
                fs::remove_file(&p).unwrap();
                symlink("opaque/profile.wg", p).unwrap();
            }
            6 => {
                fs::set_permissions(
                    t.0.join("opaque/profile.wg"),
                    fs::Permissions::from_mode(0o640),
                )
                .unwrap();
            }
            _ => unreachable!(),
        };
        assert!(
            FixtureTree::open(&t.0).and_then(|s| s.inspect()).is_err(),
            "case {case}"
        );
    }
}
fn with_adapter() -> (Temp, Request) {
    let (t, mut r) = fixture(Layout::Retry84fb353);
    inventory_edit(&t.0, |i| {
        i.dependencies.push(Dependency {
            id: "collector".into(),
            hook: "host/custom-hook.json".into(),
            adapter: "collector".into(),
            selector: Selector::DeclaredHostname,
        })
    });
    file(
        t.0.join("current/host/custom-hook.json"),
        "{\"synthetic\":\"custom collector\"}",
    );
    let action = AdapterAction {
        executable: "/synthetic/bin/collector-adapter".into(),
        argv: vec!["--node".into(), "fixture-node-1".into()],
        timeout_seconds: 30,
        idempotent: true,
    };
    r.configuration.dependency_adapters.push(DependencyAdapter {
        id: "collector".into(),
        drain: action.clone(),
        stop: action.clone(),
        rebind: action.clone(),
        start: action.clone(),
        health_check: action,
    });
    (t, r)
}
#[test]
fn declared_bounded_adapters_obey_collector_order_and_rollback_verifies_identity() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, r) = with_adapter();
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree.inspect().unwrap();
    let p = i.plan(r).unwrap();
    let mut d = Driver::new(&i, &p);
    tree.apply(&p, &mut d, &mut NoFault).unwrap();
    let pos = |a| d.actions.iter().position(|x| x == &a).unwrap();
    assert_eq!(pos(Action::IndependentQuarantine {}), 0);
    assert!(
        pos(Action::Drain {
            adapter: "collector".into()
        }) < pos(Action::PreStartStop {
            adapter: "collector".into()
        })
    );
    assert!(
        pos(Action::PreStartStop {
            adapter: "collector".into()
        }) < pos(Action::StopService {})
    );
    assert!(pos(Action::StopService {}) < pos(Action::AllIdentityUsersStopped {}));
    assert!(pos(Action::AllIdentityUsersStopped {}) < pos(Action::StoppedStateRetained {}));
    assert!(
        pos(Action::RestoreSameIdentity {})
            < pos(Action::RenameExisting {
                hostname: "mullvad-debdev-exit-de-fra-wg-404".into()
            })
    );
    assert!(
        pos(Action::StartService {})
            < pos(Action::PostStartStart {
                adapter: "collector".into()
            })
    );
    d.actions.clear();
    d.fail = Some(Action::CompatibleReleaseAndState {});
    assert_eq!(
        tree.rollback(&p, &mut d, &mut NoFault).unwrap(),
        Outcome::Offline
    );
    assert_eq!(d.actions.first(), Some(&Action::IndependentQuarantine {}));
    assert!(!d.actions.contains(&Action::StartService {}));
    let bytes = fs::read(t.0.join("journal.json")).unwrap();
    let count = d.actions.len();
    assert_eq!(
        tree.resume(&p, &mut d, &mut NoFault).unwrap(),
        Outcome::Offline
    );
    assert_eq!(d.actions.len(), count);
    assert_eq!(tree.apply(&p, &mut d, &mut NoFault), Err(Error::Terminal));
    assert_eq!(fs::read(t.0.join("journal.json")).unwrap(), bytes);
    assert_preserved(&t.0);
}
#[test]
fn every_receipt_field_is_mandatory_and_identity_cannot_start_twice() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct Bad<'a> {
        inner: &'a mut Driver,
        which: usize,
    }
    impl FixtureDriver for Bad<'_> {
        fn perform(&mut self, o: &Obligation) -> Result<Receipt> {
            let mut r = self.inner.perform(o)?;
            match (&mut r.observation, self.which) {
                (
                    Observation::Quarantine {
                        enforcer,
                        old_supervisor,
                    },
                    0,
                ) => *enforcer = old_supervisor.clone(),
                (Observation::Stopped { identity_users }, 1) => {
                    identity_users.push("legacy-still-running".into())
                }
                (Observation::Retained { state_format, .. }, 2) => *state_format = 99,
                (Observation::Retained { release_sha256, .. }, 3) => release_sha256.clear(),
                (Observation::Retained { opaque, .. }, 4) => opaque.clear(),
                (Observation::Identity { identity }, 5) => identity.node_id = "wrong".into(),
                (Observation::Identity { identity }, 6) => identity.ips = vec!["100.64.0.8".into()],
                (Observation::Identity { identity }, 7) => identity.approved_routes.clear(),
                (Observation::Identity { identity }, 8) => {
                    identity.expected_server = "de-fra-wg-003".into()
                }
                (Observation::Renamed { identity, .. }, 9) => identity.node_id = "recreated".into(),
                (_, 10) => r.obligation.ordinal += 1,
                _ => {}
            }
            Ok(r)
        }
    }
    for which in 0..11 {
        let (t, tree, i, p) = prepared();
        let mut d = Driver::new(&i, &p);
        let result = tree.apply(
            &p,
            &mut Bad {
                inner: &mut d,
                which,
            },
            &mut NoFault,
        );
        if [0, 1, 10].contains(&which) {
            // Invalid quarantine/all-user receipts also fail cleanup. This used
            // to assert terminal Offline despite the unproved stop barrier.
            assert_eq!(result, Err(Error::Offline), "mutation {which}");
            let j: serde_json::Value =
                serde_json::from_slice(&fs::read(t.0.join("journal.json")).unwrap()).unwrap();
            assert!(j["journal"]["terminal"].is_null());
            assert_eq!(tree.resume(&p, &mut d, &mut NoFault), Ok(Outcome::Offline));
        } else {
            assert_eq!(result, Ok(Outcome::Offline), "mutation {which}");
        }
        assert!(!d.actions.contains(&Action::StartService {}));
        let n = d.actions.len();
        assert_eq!(
            tree.resume(&p, &mut d, &mut NoFault).unwrap(),
            Outcome::Offline
        );
        assert_eq!(d.actions.len(), n);
        assert_preserved(&t.0);
    }
}
#[derive(Default)]
struct Injection {
    at: Option<usize>,
    count: usize,
    trace: Vec<(IoStep, Edge)>,
    abrupt: bool,
}
impl Fault for Injection {
    fn boundary(&mut self, s: IoStep, e: Edge) -> Result<()> {
        let n = self.count;
        self.count += 1;
        self.trace.push((s, e));
        if self.at == Some(n) {
            if self.abrupt {
                rustix::process::kill_process(
                    rustix::process::getpid(),
                    rustix::process::Signal::KILL,
                )
                .unwrap();
                unreachable!()
            }
            return Err(Error::Interrupted);
        }
        Ok(())
    }
}
fn trace(direction: Direction) -> Vec<(IoStep, Edge)> {
    let (_t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    let mut f = Injection::default();
    match direction {
        Direction::Forward => {
            tree.apply(&p, &mut d, &mut f).unwrap();
        }
        Direction::Reverse => {
            tree.apply(&p, &mut d, &mut NoFault).unwrap();
            tree.rollback(&p, &mut d, &mut f).unwrap();
        }
    }
    f.trace
}
fn coverage(label: &str, trace: &[(IoStep, Edge)]) {
    let mut counts = BTreeMap::<String, usize>::new();
    for (step, edge) in trace {
        *counts.entry(format!("{step:?}/{edge:?}")).or_default() += 1;
    }
    eprintln!(
        "MIGRATION_IO_COVERAGE {label} {}",
        serde_json::to_string(&counts).unwrap()
    );
}
#[test]
fn every_io_boundary_recovers_to_a_complete_bundle_and_replays_identically() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for direction in [Direction::Forward, Direction::Reverse] {
        let boundaries = trace(direction);
        coverage(&format!("{direction:?}"), &boundaries);
        assert!(!boundaries.is_empty());
        for recovery in [Direction::Forward, Direction::Reverse] {
            for (n, _) in boundaries.iter().enumerate() {
                let (t, tree, i, p) = prepared();
                let mut d = Driver::new(&i, &p);
                if direction == Direction::Reverse {
                    tree.apply(&p, &mut d, &mut NoFault).unwrap();
                }
                let mut f = Injection {
                    at: Some(n),
                    ..Default::default()
                };
                let result = match direction {
                    Direction::Forward => tree.apply(&p, &mut d, &mut f),
                    Direction::Reverse => tree.rollback(&p, &mut d, &mut f),
                };
                assert_eq!(
                    result,
                    Err(Error::Interrupted),
                    "{direction:?} boundary {n} {:?}",
                    boundaries[n]
                );
                let active = read_bundle(&t.0.join("current"));
                assert!(active == *p.old_bundle() || active == *p.new_bundle());
                let outcome = match recovery {
                    Direction::Forward => tree.resume(&p, &mut d, &mut NoFault),
                    Direction::Reverse => tree.rollback(&p, &mut d, &mut NoFault),
                }
                .unwrap_or_else(|e| {
                    panic!(
                        "{direction:?}/{recovery:?} boundary {n} {:?}: {e:?}",
                        boundaries[n]
                    )
                });
                let expected = if outcome == Outcome::CommittedFixture {
                    p.new_bundle()
                } else {
                    p.old_bundle()
                };
                assert_ne!(outcome, Outcome::Offline);
                assert_eq!(read_bundle(&t.0.join("current")), *expected);
                let journal = fs::read(t.0.join("journal.json")).unwrap();
                assert_eq!(tree.resume(&p, &mut d, &mut NoFault).unwrap(), outcome);
                assert_eq!(tree.resume(&p, &mut d, &mut NoFault).unwrap(), outcome);
                assert_eq!(journal, fs::read(t.0.join("journal.json")).unwrap());
                assert_preserved(&t.0);
            }
        }
        eprintln!(
            "{direction:?}: {} before/after I/O checkpoints x 2 recovery directions",
            boundaries.len()
        );
    }
}
#[test]
fn lock_inode_never_replaced_and_concurrent_entrants_cannot_start() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use rustix::fs::{FlockOperation, flock};
    let (t, tree, i, p) = prepared();
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(t.0.join(".allocations.lock"))
        .unwrap();
    flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    let mut d = Driver::new(&i, &p);
    assert_eq!(tree.apply(&p, &mut d, &mut NoFault), Err(Error::Busy));
    assert!(d.actions.is_empty());
    drop(lock);
    fs::remove_file(t.0.join(".allocations.lock")).unwrap();
    assert!(tree.apply(&p, &mut d, &mut NoFault).is_err());
    assert!(!t.0.join(".allocations.lock").exists());
}
#[test]
fn corrupt_journal_cannot_reset_a_transaction_or_overwrite_foreign_state() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    tree.apply(&p, &mut d, &mut NoFault).unwrap();
    file(t.0.join("journal.json"), "{torn");
    let actions = d.actions.len();
    assert!(tree.resume(&p, &mut d, &mut NoFault).is_err());
    assert!(tree.rollback(&p, &mut d, &mut NoFault).is_err());
    assert!(tree.apply(&p, &mut d, &mut NoFault).is_err());
    assert_eq!(d.actions.len(), actions);
    assert_eq!(read_bundle(&t.0.join("current")), *p.new_bundle());
    assert_preserved(&t.0);
}
#[test]
fn resume_after_recorded_start_repeats_the_entire_stopped_identity_contract() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct Running {
        inner: Driver,
        running: bool,
    }
    impl FixtureDriver for Running {
        fn perform(&mut self, o: &Obligation) -> Result<Receipt> {
            match &o.action {
                Action::StopService {} => self.running = false,
                Action::AllIdentityUsersStopped {} => assert!(!self.running),
                Action::StartService {} => {
                    assert!(!self.running, "duplicate identity start");
                    self.running = true;
                }
                _ => {}
            }
            self.inner.perform(o)
        }
    }
    struct AfterStart {
        root: PathBuf,
        target: usize,
    }
    impl Fault for AfterStart {
        fn boundary(&mut self, s: IoStep, e: Edge) -> Result<()> {
            if (s, e) == (IoStep::PublishJournal, Edge::After) {
                let v: serde_json::Value =
                    serde_json::from_slice(&fs::read(self.root.join("journal.json")).unwrap())
                        .unwrap();
                if v["journal"]["completed"].as_u64() == Some(self.target as u64) {
                    return Err(Error::Interrupted);
                }
            }
            Ok(())
        }
    }
    let (t, tree, i, p) = prepared();
    let start = p
        .obligations(Direction::Forward)
        .iter()
        .position(|o| matches!(o.action, Action::StartService {}))
        .unwrap();
    let mut d = Running {
        inner: Driver::new(&i, &p),
        running: true,
    };
    assert_eq!(
        tree.apply(
            &p,
            &mut d,
            &mut AfterStart {
                root: t.0.clone(),
                target: start + 3
            }
        ),
        Err(Error::Interrupted)
    );
    assert!(d.running);
    assert_eq!(
        tree.resume(&p, &mut d, &mut NoFault).unwrap(),
        Outcome::CommittedFixture
    );
    assert!(
        d.running,
        "resume stopped the service but skipped its recorded start"
    );
}
#[test]
fn terminal_reads_refuse_tree_drift_without_rewriting_terminal_journal() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    tree.apply(&p, &mut d, &mut NoFault).unwrap();
    let before = fs::read(t.0.join("journal.json")).unwrap();
    file(t.0.join("current/router.nft"), "drift");
    assert_eq!(tree.apply(&p, &mut d, &mut NoFault), Err(Error::Drift));
    assert_eq!(tree.resume(&p, &mut d, &mut NoFault), Err(Error::Drift));
    assert_eq!(before, fs::read(t.0.join("journal.json")).unwrap());
}
#[test]
fn legacy_optional_hostname_defaults_to_the_existing_instance() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, r) = fixture(Layout::CurrentMain);
    let path = t.0.join("current/config.json");
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    v.as_object_mut().unwrap().remove("tailscale_hostname");
    file(&path, &v.to_string());
    let tree = FixtureTree::open(&t.0).unwrap();
    assert!(tree.inspect().unwrap().plan(r).is_ok());
}
#[test]
fn json_dispatch_is_fixture_only_strict_and_has_no_activation_switch() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    let value: serde_json::Value = serde_json::from_slice(
        &tree
            .execute_json(b"{\"operation\":\"inspect\"}", &mut d, &mut NoFault)
            .expect("JSON inspection missing"),
    )
    .unwrap();
    assert_eq!(value["scope"], "synthetic_fixture_only");
    for raw in [
        r#"{"operation":"inspect","verify":false}"#,
        r#"{"operation":"inspect","activate":true}"#,
        r#"{"operation":"inspect","operation":"inspect"}"#,
        r#"{"operation":"resume","plan":{}}"#,
    ] {
        assert!(
            tree.execute_json(raw.as_bytes(), &mut d, &mut NoFault)
                .is_err()
        );
    }
    assert!(d.actions.is_empty());
    let (_request_fixture, request) = with_adapter();
    let raw =
        serde_json::to_vec(&serde_json::json!({"operation":"plan","request":request})).unwrap();
    let planned: serde_json::Value =
        serde_json::from_slice(&tree.execute_json(&raw, &mut d, &mut NoFault).unwrap()).unwrap();
    assert_eq!(planned["data"]["fingerprint"], p.fingerprint());
    for (operation, expected) in [
        ("apply", "committed_fixture"),
        ("resume", "committed_fixture"),
        ("rollback", "rolled_back_fixture"),
    ] {
        let raw = serde_json::to_vec(&serde_json::json!({"operation":operation,"plan":p})).unwrap();
        let result: serde_json::Value =
            serde_json::from_slice(&tree.execute_json(&raw, &mut d, &mut NoFault).unwrap())
                .unwrap();
        assert_eq!(result["data"], expected);
        assert_eq!(result["client_coverage"], "unverified");
        assert_eq!(result["quarantine"], "required");
    }
    assert_preserved(&t.0);
}
#[test]
fn abrupt_fault_worker() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Ok(root) = std::env::var("VPR_MIGRATION_KILL_ROOT") else {
        return;
    };
    let p = Plan::parse(std::env::var("VPR_MIGRATION_KILL_PLAN").unwrap().as_bytes()).unwrap();
    let tree = FixtureTree::open(Path::new(&root)).unwrap();
    let i = tree.inspect().unwrap();
    let mut d = Driver::new(&i, &p);
    let mut f = Injection {
        at: Some(
            std::env::var("VPR_MIGRATION_KILL_AT")
                .unwrap()
                .parse()
                .unwrap(),
        ),
        abrupt: true,
        ..Default::default()
    };
    let direction = std::env::var("VPR_MIGRATION_KILL_DIRECTION").unwrap();
    if direction == "offline" {
        d.fail = Some(Action::HealthCheck {
            adapter: "collector".into(),
        });
    }
    if direction == "recovery" {
        tree.resume(&p, &mut d, &mut f).unwrap();
    } else if direction != "reverse" {
        tree.apply(&p, &mut d, &mut f).unwrap();
    } else {
        tree.rollback(&p, &mut d, &mut f).unwrap();
    }
    panic!("kill boundary was not reached");
}
#[test]
fn sigkill_at_every_apply_and_rollback_io_boundary_preserves_atomicity() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Command as Process, Stdio},
    };
    for direction in [Direction::Forward, Direction::Reverse] {
        let trace = trace(direction);
        for (n, _) in trace.iter().enumerate() {
            let (t, tree, i, p) = prepared();
            let mut d = Driver::new(&i, &p);
            if direction == Direction::Reverse {
                tree.apply(&p, &mut d, &mut NoFault).unwrap();
            }
            let status = Process::new(std::env::current_exe().unwrap())
                .args(["--exact", "abrupt_fault_worker", "--nocapture"])
                .env("VPR_MIGRATION_KILL_ROOT", &t.0)
                .env(
                    "VPR_MIGRATION_KILL_PLAN",
                    String::from_utf8(p.encode().unwrap()).unwrap(),
                )
                .env("VPR_MIGRATION_KILL_AT", n.to_string())
                .env(
                    "VPR_MIGRATION_KILL_DIRECTION",
                    if direction == Direction::Forward {
                        "forward"
                    } else {
                        "reverse"
                    },
                )
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(
                status.signal(),
                Some(9),
                "{direction:?} checkpoint {n}: {:?}",
                trace[n]
            );
            let current = read_bundle(&t.0.join("current"));
            assert!(current == *p.old_bundle() || current == *p.new_bundle());
            let outcome = tree
                .resume(&p, &mut d, &mut NoFault)
                .unwrap_or_else(|e| panic!("SIGKILL {direction:?}/{n} {:?}: {e:?}", trace[n]));
            if direction == Direction::Forward {
                assert_eq!(outcome, Outcome::CommittedFixture);
            } else {
                assert!(matches!(
                    outcome,
                    Outcome::CommittedFixture | Outcome::RolledBackFixture
                ));
                assert_eq!(
                    tree.rollback(&p, &mut d, &mut NoFault).unwrap(),
                    Outcome::RolledBackFixture
                );
            }
            assert_preserved(&t.0);
        }
        eprintln!("SIGKILL {direction:?}: {} checkpoints", trace.len());
    }
}
fn interrupted_staging() -> (Temp, FixtureTree, Inspection, Plan) {
    struct Partial {
        root: PathBuf,
    }
    impl Fault for Partial {
        fn boundary(&mut self, s: IoStep, e: Edge) -> Result<()> {
            if (s, e) == (IoStep::Write, Edge::After)
                && self.root.join("staged/config.json").exists()
            {
                return Err(Error::Interrupted);
            }
            Ok(())
        }
    }
    let (t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    assert_eq!(
        tree.apply(&p, &mut d, &mut Partial { root: t.0.clone() }),
        Err(Error::Interrupted)
    );
    file(t.0.join("staged/config.json"), "{\"");
    (t, tree, i, p)
}
#[test]
fn recovery_cleanup_and_torn_stage_have_fault_coverage_too() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_t, tree, i, p) = interrupted_staging();
    let mut d = Driver::new(&i, &p);
    let mut trace = Injection::default();
    tree.resume(&p, &mut d, &mut trace).unwrap();
    assert!(trace.trace.contains(&(IoStep::RemoveFile, Edge::Before)));
    assert!(
        trace
            .trace
            .contains(&(IoStep::RemoveDirectory, Edge::After))
    );
    for n in 0..trace.count {
        let (t, tree, i, p) = interrupted_staging();
        let mut d = Driver::new(&i, &p);
        let mut f = Injection {
            at: Some(n),
            ..Default::default()
        };
        assert_eq!(
            tree.resume(&p, &mut d, &mut f),
            Err(Error::Interrupted),
            "recovery checkpoint {n}"
        );
        let outcome = tree
            .resume(&p, &mut d, &mut NoFault)
            .unwrap_or_else(|e| panic!("recovery checkpoint {n} {:?}: {e:?}", trace.trace[n]));
        assert_eq!(outcome, Outcome::CommittedFixture);
        assert_eq!(read_bundle(&t.0.join("current")), *p.new_bundle());
        assert_preserved(&t.0);
    }
    coverage("Recovery", &trace.trace);
    eprintln!("recovery cleanup: {} error checkpoints", trace.count);
}
#[test]
fn recovery_never_deletes_an_opaque_inode_renamed_over_a_pending_file() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    fs::rename(t.0.join("opaque/profile.wg"), t.0.join(".journal.pending")).unwrap();
    file(t.0.join("opaque/profile.wg"), "replacement");
    assert!(tree.resume(&p, &mut d, &mut NoFault).is_err());
    assert_eq!(
        fs::read(t.0.join(".journal.pending")).expect("opaque inode must survive"),
        b"SYNTHETIC CREDENTIAL BYTES - MUST NOT OPEN\n"
    );
}
#[test]
fn shape_valid_provenance_is_bound_to_the_actual_fixture_release() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, mut r) = fixture(Layout::CurrentMain);
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree.inspect().unwrap();
    r.provenance.source_sha256 = "d".repeat(64);
    assert!(i.plan(r).is_err(), "shape-only source provenance accepted");
}
#[test]
fn every_name_path_and_parser_boundary_rejects_ambiguous_encodings() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, r) = with_adapter();
    let raw = fs::read(t.0.join("inventory.json")).unwrap();
    let inv: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    for invalid in [
        "", ".", "..", "a/b", "a//b", "a%2fb", "a\\b", "a\0b", "a\nb", "é", "A", " a", "a ",
    ] {
        for field in ["service", "container", "uplink"] {
            let mut v = inv.clone();
            v[field] = invalid.into();
            assert!(
                Inventory::parse(&serde_json::to_vec(&v).unwrap()).is_err(),
                "{field} {invalid:?}"
            );
        }
        for field in ["id", "adapter", "hook"] {
            let mut v = inv.clone();
            v["dependencies"][0][field] = invalid.into();
            assert!(
                Inventory::parse(&serde_json::to_vec(&v).unwrap()).is_err(),
                "dep {field} {invalid:?}"
            );
        }
        let mut v = inv.clone();
        v["identity"]["node_id"] = invalid.into();
        assert!(Inventory::parse(&serde_json::to_vec(&v).unwrap()).is_err());
        assert!(wrappers("/synthetic/bin/vprouter", invalid).is_err());
    }
    let tree = FixtureTree::open(&t.0).unwrap();
    let original = tree.inspect().unwrap();
    for invalid in [
        "relative", "/", "/a//b", "/a/../b", "/a/./b", "/a/%2f", "/a\\b", "/a/é", "/a/\0", "/a/\n",
        "/a/",
    ] {
        for field in ["profile", "state_dir", "compose_dir"] {
            let config = t.0.join("current/config.json");
            let before = fs::read(&config).unwrap();
            let mut v: serde_json::Value = serde_json::from_slice(&before).unwrap();
            v[field] = invalid.into();
            file(&config, &v.to_string());
            assert!(
                tree.inspect().unwrap().plan(r.clone()).is_err(),
                "legacy {field} {invalid:?}"
            );
            file(&config, std::str::from_utf8(&before).unwrap());
        }
        for field in ["drain", "stop", "rebind", "start", "health_check"] {
            let mut rr = serde_json::to_value(&r).unwrap();
            rr["configuration"]["dependency_adapters"][0][field]["executable"] = invalid.into();
            let req = serde_json::from_value(rr).unwrap();
            assert!(original.plan(req).is_err(), "adapter {field} {invalid:?}");
        }
        assert!(wrappers(invalid, "primary").is_err());
    }
    let p = original.plan(r).unwrap();
    let encoded = String::from_utf8(p.encode().unwrap()).unwrap();
    let duplicate = encoded.replacen("\"files\":{", "\"files\":{\"router.nft\":\"duplicate\",", 1);
    assert!(Plan::parse(duplicate.as_bytes()).is_err());
    for mutation in ["fingerprint", "scope", "containment", "client_coverage"] {
        let mut v: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        v[mutation] = "forged".into();
        assert!(Plan::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    }
}
#[test]
fn growth_limits_and_unknown_dependencies_refuse_before_writing() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, r) = fixture(Layout::CurrentMain);
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree.inspect().unwrap();
    for n in [128 * 1024 + 1, 512 * 1024 + 1] {
        let mut rr = r.clone();
        rr.release.files.insert("router.nft".into(), "x".repeat(n));
        rr.provenance.source_sha256 = digest(serde_json::to_vec(&rr.release).unwrap());
        assert!(i.plan(rr).is_err());
    }
    inventory_edit(&t.0, |i| i.hostname_users = HostnameUsers::Unknown);
    assert!(tree.inspect().unwrap().plan(r).is_err());
    assert!(!t.0.join("journal.json").exists());
}
#[test]
fn two_actual_migrations_racing_have_only_one_lifecycle_executor() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_t, tree, i, p) = prepared();
    let (admitted_tx, admitted_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    struct Hold {
        inner: Driver,
        admitted: Option<std::sync::mpsc::Sender<()>>,
        release: std::sync::mpsc::Receiver<()>,
    }
    impl FixtureDriver for Hold {
        fn perform(&mut self, o: &Obligation) -> Result<Receipt> {
            if let Some(s) = self.admitted.take() {
                s.send(()).unwrap();
                self.release.recv().unwrap();
            }
            self.inner.perform(o)
        }
    }
    std::thread::scope(|s| {
        let t = s.spawn(|| {
            tree.apply(
                &p,
                &mut Hold {
                    inner: Driver::new(&i, &p),
                    admitted: Some(admitted_tx),
                    release: release_rx,
                },
                &mut NoFault,
            )
        });
        admitted_rx.recv().unwrap();
        let mut d = Driver::new(&i, &p);
        assert_eq!(tree.apply(&p, &mut d, &mut NoFault), Err(Error::Busy));
        assert!(d.actions.is_empty());
        release_tx.send(()).unwrap();
        assert_eq!(t.join().unwrap().unwrap(), Outcome::CommittedFixture);
    });
}
#[test]
fn before_mutation_path_swaps_refuse_and_preserve_foreign_bytes() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use std::os::unix::fs::symlink;
    for attack in 0..4 {
        let (t, tree, i, p) = prepared();
        let mut d = Driver::new(&i, &p);
        struct Attack {
            root: PathBuf,
            attack: u8,
            done: bool,
        }
        impl Fault for Attack {
            fn boundary(&mut self, s: IoStep, e: Edge) -> Result<()> {
                if !self.done && (s, e) == (IoStep::ExchangeRelease, Edge::Before) {
                    self.done = true;
                    match self.attack {
                        0 => {
                            fs::rename(
                                self.root.join("staged"),
                                self.root.join("foreign-retained"),
                            )
                            .unwrap();
                            symlink("opaque/state", self.root.join("staged")).unwrap();
                        }
                        1 => {
                            fs::remove_file(self.root.join(".allocations.lock")).unwrap();
                            file(self.root.join(".allocations.lock"), "foreign lock");
                        }
                        2 => {
                            fs::hard_link(
                                self.root.join("staged/config.json"),
                                self.root.join("foreign-retained"),
                            )
                            .unwrap();
                        }
                        3 => fs::set_permissions(
                            self.root.join("current"),
                            fs::Permissions::from_mode(0o755),
                        )
                        .unwrap(),
                        _ => unreachable!(),
                    }
                }
                Ok(())
            }
        }
        let result = tree.apply(
            &p,
            &mut d,
            &mut Attack {
                root: t.0.clone(),
                attack,
                done: false,
            },
        );
        assert!(result.is_err());
        assert_eq!(read_bundle(&t.0.join("current")), *p.old_bundle());
        assert_preserved(&t.0);
    }
}
#[test]
fn directly_deserialized_plan_cannot_panic_or_emit_lifecycle_obligations() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_t, _tree, _i, p) = prepared();
    let mut v = serde_json::to_value(&p).unwrap();
    v["configuration"]["site"] = "invalid site".into();
    let bad: Plan = serde_json::from_value(v).unwrap();
    let result = std::panic::catch_unwind(|| bad.obligations(Direction::Forward));
    assert!(result.is_ok(), "unvalidated public Plan panicked");
    assert!(
        result.unwrap().is_empty(),
        "invalid plan emitted obligations"
    );
}
#[test]
fn explicit_empty_legacy_hostname_is_invalid_rather_than_missing() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, r) = fixture(Layout::CurrentMain);
    let config = t.0.join("current/config.json");
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    v["tailscale_hostname"] = "".into();
    file(&config, &v.to_string());
    let tree = FixtureTree::open(&t.0).unwrap();
    assert!(tree.inspect().unwrap().plan(r).is_err());
}
#[test]
fn legacy_tailnet_ipv6_metadata_and_approvals_are_preserved_without_forwarding_authority() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, r) = fixture(Layout::CurrentMain);
    inventory_edit(&t.0, |i| {
        i.identity.ips.push("fd7a:115c:a1e0::7".into());
        i.identity.approved_routes.push("::/0".into());
    });
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree
        .inspect()
        .expect("tailnet identity IPv6 metadata refused");
    let p = i.plan(r).unwrap();
    assert_eq!(p.identity().ips, vec!["100.64.0.7", "fd7a:115c:a1e0::7"]);
    assert_eq!(p.identity().approved_routes, vec!["0.0.0.0/0", "::/0"]);
}
#[test]
fn failure_after_service_start_quarantines_first_then_stops_and_never_restarts() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, r) = with_adapter();
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree.inspect().unwrap();
    let p = i.plan(r).unwrap();
    let mut d = Driver::new(&i, &p);
    d.fail = Some(Action::HealthCheck {
        adapter: "collector".into(),
    });
    assert_eq!(
        tree.apply(&p, &mut d, &mut NoFault).unwrap(),
        Outcome::Offline
    );
    assert!(!d.running, "late failure left new identity running");
    let failed = d
        .actions
        .iter()
        .position(|a| matches!(a, Action::HealthCheck { .. }))
        .unwrap();
    assert_eq!(d.actions[failed + 1], Action::IndependentQuarantine {});
    assert!(d.actions[failed + 2..].contains(&Action::StopService {}));
    assert!(!d.actions[failed + 2..].contains(&Action::StartService {}));
}
#[test]
fn configured_client_selection_cannot_change_the_preserved_primary_node() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, mut r) = fixture(Layout::CurrentMain);
    r.configuration
        .client_policies
        .push(vprouter_core::config::ClientPolicy {
            id: "client".into(),
            exit_id: "primary".into(),
            selected_node_id: "different-node".into(),
            mode: vprouter_core::config::ClientMode::Protected,
            dependency_adapters: vec![],
        });
    let i = FixtureTree::open(&t.0).unwrap().inspect().unwrap();
    assert!(i.plan(r).is_err());
}
#[test]
fn terminal_publication_cannot_hide_a_late_active_tree_change() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct Late {
        root: PathBuf,
        done: bool,
    }
    impl Fault for Late {
        fn boundary(&mut self, s: IoStep, e: Edge) -> Result<()> {
            if !self.done && (s, e) == (IoStep::PublishJournal, Edge::After) {
                let v: serde_json::Value =
                    serde_json::from_slice(&fs::read(self.root.join("journal.json")).unwrap())
                        .unwrap();
                if v["journal"]["terminal"] == "committed_fixture" {
                    self.done = true;
                    file(self.root.join("current/router.nft"), "foreign late change");
                }
            }
            Ok(())
        }
    }
    let (t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    assert_eq!(
        tree.apply(
            &p,
            &mut d,
            &mut Late {
                root: t.0.clone(),
                done: false
            }
        ),
        Err(Error::Drift)
    );
    assert!(tree.resume(&p, &mut d, &mut NoFault).is_err());
    assert_preserved(&t.0);
}
#[test]
fn short_write_worker() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Ok(root) = std::env::var("VPR_MIGRATION_SHORT_ROOT") else {
        return;
    };
    let p = Plan::parse(
        std::env::var("VPR_MIGRATION_SHORT_PLAN")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let tree = FixtureTree::open(Path::new(&root)).unwrap();
    let i = tree.inspect().unwrap();
    let mut d = Driver::new(&i, &p);
    // Only this exact child process lowers its file-size limit. No disk filling,
    // parent resource changes, signal handlers, privileges or foreign processes.
    rustix::process::setrlimit(
        rustix::process::Resource::Fsize,
        rustix::process::Rlimit {
            current: Some(1024),
            maximum: Some(1024),
        },
    )
    .unwrap();
    assert_eq!(
        tree.apply(&p, &mut d, &mut NoFault),
        Err(Error::Interrupted)
    );
}
#[test]
fn actual_kernel_short_write_leaves_only_a_recoverable_pending_prefix() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, tree, i, p) = prepared();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "short_write_worker", "--nocapture"])
        .env("VPR_MIGRATION_SHORT_ROOT", &t.0)
        .env(
            "VPR_MIGRATION_SHORT_PLAN",
            String::from_utf8(p.encode().unwrap()).unwrap(),
        )
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(
        fs::metadata(t.0.join(".journal.pending")).unwrap().len(),
        1024
    );
    assert_eq!(read_bundle(&t.0.join("current")), *p.old_bundle());
    let mut d = Driver::new(&i, &p);
    assert_eq!(
        tree.resume(&p, &mut d, &mut NoFault).unwrap(),
        Outcome::CommittedFixture
    );
    assert_eq!(read_bundle(&t.0.join("current")), *p.new_bundle());
    assert_preserved(&t.0);
}
#[test]
fn legacy_instance_grammar_is_compatible_with_both_retained_parsers() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for invalid in ["a".to_string(), "1a".to_string(), "a".repeat(51)] {
        let (t, r) = fixture(Layout::CurrentMain);
        inventory_edit(&t.0, |i| {
            i.service = invalid.clone();
            i.container = invalid.clone();
            i.uplink = format!("{invalid}-uplink");
        });
        let config = t.0.join("current/config.json");
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        v["name"] = invalid.clone().into();
        v["tailscale_hostname"] = invalid.clone().into();
        file(&config, &v.to_string());
        let tree = FixtureTree::open(&t.0).unwrap();
        assert!(
            tree.inspect().unwrap().plan(r).is_err(),
            "legacy name {invalid:?} admitted"
        );
    }
}

// Review round 1: reviewer witnesses converted to behavioural correctness REDs.
#[test]
fn review_round1_state_identity_pending_is_preserved_and_refused() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use std::os::unix::fs::MetadataExt;
    let (t, tree, i, p) = prepared();
    let original = t.0.join("opaque/state/tailscaled.state");
    let pending = t.0.join(".journal.pending");
    let inode = fs::metadata(&original).unwrap().ino();
    fs::rename(&original, &pending).unwrap();
    file(&original, "REPLACED SYNTHETIC IDENTITY");
    let mut d = Driver::new(&i, &p);
    assert!(
        tree.resume(&p, &mut d, &mut NoFault).is_err(),
        "must refuse identity replacement before pending cleanup"
    );
    assert_eq!(fs::metadata(&pending).unwrap().ino(), inode);
    assert!(d.actions.is_empty());
}

#[test]
fn review_round1_inspection_never_discloses_relocated_state() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, tree, _, _) = prepared();
    let original = t.0.join("opaque/state/tailscaled.state");
    fs::rename(&original, t.0.join("current/router_runtime.py")).unwrap();
    file(&original, "REPLACED SYNTHETIC IDENTITY");
    assert!(
        tree.inspect().is_err(),
        "inspection must retain admitted identity inode custody"
    );
}

#[test]
fn review_round1_nested_state_replacement_blocks_cutover_and_rollback() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct ReplaceState {
        inner: Driver,
        root: PathBuf,
        replaced: bool,
    }
    impl FixtureDriver for ReplaceState {
        fn perform(&mut self, o: &Obligation) -> Result<Receipt> {
            let receipt = self.inner.perform(o)?;
            if matches!(o.action, Action::StoppedStateRetained {}) && !self.replaced {
                self.replaced = true;
                fs::rename(
                    self.root.join("opaque/state/nested/identity"),
                    self.root.join("original-state-retained"),
                )
                .unwrap();
                file(
                    self.root.join("opaque/state/nested/identity"),
                    "REPLACED SYNTHETIC IDENTITY",
                );
            }
            Ok(receipt)
        }
    }
    use std::os::unix::fs::MetadataExt;
    let (t, r) = with_adapter();
    fs::create_dir(t.0.join("opaque/state/nested")).unwrap();
    fs::set_permissions(
        t.0.join("opaque/state/nested"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    file(
        t.0.join("opaque/state/nested/identity"),
        "SYNTHETIC NESTED IDENTITY",
    );
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree.inspect().unwrap();
    let p = i.plan(r).unwrap();
    let inode = fs::metadata(t.0.join("opaque/state/nested/identity"))
        .unwrap()
        .ino();
    let mut d = ReplaceState {
        inner: Driver::new(&i, &p),
        root: t.0.clone(),
        replaced: false,
    };
    assert!(tree.apply(&p, &mut d, &mut NoFault).is_err());
    assert_eq!(
        fs::metadata(t.0.join("original-state-retained"))
            .unwrap()
            .ino(),
        inode
    );
    assert!(!d.inner.actions.contains(&Action::StartService {}));
    assert!(tree.rollback(&p, &mut d, &mut NoFault).is_err());
    assert_eq!(read_bundle(&t.0.join("current")), *p.old_bundle());
}

#[test]
fn review_round1_state_leaf_admission_rejects_alias_permissions_and_special_files() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use std::os::unix::fs::symlink;
    for case in 0..5 {
        let (t, _) = with_adapter();
        let state = t.0.join("opaque/state/tailscaled.state");
        match case {
            0 => {
                fs::rename(&state, t.0.join("retained-state")).unwrap();
                symlink("../../retained-state", &state).unwrap();
            }
            1 => fs::hard_link(&state, t.0.join("retained-state")).unwrap(),
            2 => fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap(),
            3 => {
                fs::remove_file(&state).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &state,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    0,
                )
                .unwrap();
            }
            4 => {
                fs::remove_file(&state).unwrap();
                let _socket = std::os::unix::net::UnixListener::bind(&state).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            FixtureTree::open(&t.0).is_err(),
            "unsafe state leaf admitted: {case}"
        );
    }
}

#[test]
fn review_round1_failed_cleanup_drain_still_stops_and_remains_retryable() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct FailingCleanup {
        inner: Driver,
        late_failure: bool,
        fail_drain: bool,
    }
    impl FixtureDriver for FailingCleanup {
        fn perform(&mut self, o: &Obligation) -> Result<Receipt> {
            if matches!(o.action, Action::HealthCheck { .. }) {
                self.late_failure = true;
                self.inner.actions.push(o.action.clone());
                return Err(Error::Offline);
            }
            if self.late_failure && self.fail_drain && matches!(o.action, Action::Drain { .. }) {
                self.inner.actions.push(o.action.clone());
                return Err(Error::Offline);
            }
            self.inner.perform(o)
        }
    }
    let (t, tree, i, p) = prepared();
    let mut d = FailingCleanup {
        inner: Driver::new(&i, &p),
        late_failure: false,
        fail_drain: true,
    };
    assert!(
        tree.apply(&p, &mut d, &mut NoFault).is_err(),
        "unresolved drain must not publish terminal offline"
    );
    assert!(
        !d.inner.running,
        "adapter failure must not suppress service stop"
    );
    let j: serde_json::Value =
        serde_json::from_slice(&fs::read(t.0.join("journal.json")).unwrap()).unwrap();
    assert!(j["journal"]["terminal"].is_null());
    let count = d.inner.actions.len();
    assert!(tree.resume(&p, &mut d, &mut NoFault).is_err());
    assert!(d.inner.actions.len() > count);
    assert!(!d.inner.actions[count..].contains(&Action::StartService {}));
    d.fail_drain = false;
    assert_eq!(
        tree.rollback(&p, &mut d, &mut NoFault),
        Ok(Outcome::Offline)
    );
    assert!(!d.inner.running);
    let count = d.inner.actions.len();
    assert_eq!(tree.resume(&p, &mut d, &mut NoFault), Ok(Outcome::Offline));
    assert_eq!(d.inner.actions.len(), count);
}

#[test]
fn review_round1_partial_utf8_stage_recovers_forward_and_backward() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct SplitUtf8 {
        root: PathBuf,
        hit: bool,
    }
    impl Fault for SplitUtf8 {
        fn boundary(&mut self, step: IoStep, edge: Edge) -> Result<()> {
            let path = self.root.join("staged/router_runtime.py");
            if !self.hit
                && (step, edge) == (IoStep::Write, Edge::After)
                && path.exists()
                && fs::metadata(path).unwrap().len() == 4096
            {
                self.hit = true;
                return Err(Error::Interrupted);
            }
            Ok(())
        }
    }
    for reverse in [false, true] {
        let (t, mut request) = with_adapter();
        request.release.files.insert(
            "router_runtime.py".into(),
            format!("{}é\n", "#".repeat(4095)),
        );
        request.provenance.source_sha256 = digest(serde_json::to_vec(&request.release).unwrap());
        let tree = FixtureTree::open(&t.0).unwrap();
        let i = tree.inspect().unwrap();
        let p = i.plan(request).unwrap();
        let mut d = Driver::new(&i, &p);
        let mut fault = SplitUtf8 {
            root: t.0.clone(),
            hit: false,
        };
        assert_eq!(tree.apply(&p, &mut d, &mut fault), Err(Error::Interrupted));
        assert!(fault.hit);
        let partial = fs::read(t.0.join("staged/router_runtime.py")).unwrap();
        assert_eq!(partial.len(), 4096);
        assert!(std::str::from_utf8(&partial).is_err());
        let expected = if reverse {
            Outcome::RolledBackFixture
        } else {
            Outcome::CommittedFixture
        };
        let result = if reverse {
            tree.rollback(&p, &mut d, &mut NoFault)
        } else {
            tree.resume(&p, &mut d, &mut NoFault)
        };
        assert_eq!(result, Ok(expected));
        let journal = fs::read(t.0.join("journal.json")).unwrap();
        for _ in 0..2 {
            assert_eq!(tree.resume(&p, &mut d, &mut NoFault), Ok(expected));
        }
        assert_eq!(journal, fs::read(t.0.join("journal.json")).unwrap());
        assert_preserved(&t.0);
    }
}

#[test]
fn review_round1_unplanned_staging_or_pending_is_retained_not_deleted() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for pending in [true, false] {
        let (t, tree, i, p) = if pending {
            prepared()
        } else {
            interrupted_staging()
        };
        let path = t.0.join(if pending {
            ".journal.pending"
        } else {
            "staged/config.json"
        });
        file(&path, "UNRELATED PUBLIC FILE - NOT ENGINE OUTPUT");
        let mut d = Driver::new(&i, &p);
        assert!(tree.resume(&p, &mut d, &mut NoFault).is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "UNRELATED PUBLIC FILE - NOT ENGINE OUTPUT"
        );
        assert_preserved(&t.0);
    }
}

#[test]
fn review_round1_generated_protected_tree_rename_permutations() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use std::os::unix::fs::MetadataExt;
    struct BeforeExchange;
    impl Fault for BeforeExchange {
        fn boundary(&mut self, s: IoStep, e: Edge) -> Result<()> {
            if (s, e) == (IoStep::ExchangeRelease, Edge::Before) {
                Err(Error::Interrupted)
            } else {
                Ok(())
            }
        }
    }
    let protected = [
        "opaque",
        "opaque/profile.wg",
        "opaque/state",
        "opaque/state/tailscaled.state",
        "opaque/state/nested",
        "opaque/state/nested/token",
    ];
    let (_t, _, _, sample) = prepared();
    let mut destinations = vec![
        "offline-migration.fixture".to_string(),
        "inventory.json".into(),
        ".allocations.lock".into(),
        "journal.json".into(),
        ".journal.pending".into(),
    ];
    for slot in ["current", "staged"] {
        destinations.push(slot.into());
        destinations.push(format!("{slot}/host"));
        for name in sample
            .old_bundle()
            .files
            .keys()
            .chain(sample.new_bundle().files.keys())
        {
            let path = format!("{slot}/{name}");
            if !destinations.contains(&path) {
                destinations.push(path);
            }
        }
    }
    let mut cases = Vec::new();
    for retained in [false, true] {
        for src in protected {
            for dest in &destinations {
                cases.push((retained, src, dest.clone()));
            }
        }
    }
    // Fixed-seed generated permutation: reproducible random order, exhaustive pairs.
    let mut seed = 0x5eed_c057_0d12_u64;
    for n in (1..cases.len()).rev() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        cases.swap(n, seed as usize % (n + 1));
    }
    for (retained, src, dest) in &cases {
        let (t, r) = with_adapter();
        fs::create_dir(t.0.join("opaque/state/nested")).unwrap();
        fs::set_permissions(
            t.0.join("opaque/state/nested"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        file(
            t.0.join("opaque/state/nested/token"),
            "SYNTHETIC NESTED IDENTITY",
        );
        let tree = FixtureTree::open(&t.0).unwrap();
        let i = tree.inspect().unwrap();
        let p = i.plan(r).unwrap();
        let mut d = Driver::new(&i, &p);
        if *retained {
            tree.apply(&p, &mut d, &mut NoFault).unwrap();
        } else {
            assert_eq!(
                tree.apply(&p, &mut d, &mut BeforeExchange),
                Err(Error::Interrupted)
            );
        }
        let source = t.0.join(src);
        let target = t.0.join(dest);
        if !target.exists() {
            file(&target, "");
        }
        let pin = fs::symlink_metadata(&source).unwrap();
        let watch = if pin.is_file() {
            use rustix::fs::inotify;
            let fd = inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC)
                .unwrap();
            inotify::add_watch(
                &fd,
                &source,
                inotify::WatchFlags::OPEN
                    | inotify::WatchFlags::ACCESS
                    | inotify::WatchFlags::MODIFY,
            )
            .unwrap();
            Some(fd)
        } else {
            None
        };
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &source,
            rustix::fs::CWD,
            &target,
            rustix::fs::RenameFlags::EXCHANGE,
        )
        .unwrap();
        let n = d.actions.len();
        assert!(
            tree.inspect().is_err(),
            "inspect disclosed {src} via {dest}, retained={retained}"
        );
        assert!(tree.apply(&p, &mut d, &mut NoFault).is_err());
        assert!(tree.resume(&p, &mut d, &mut NoFault).is_err());
        assert!(tree.rollback(&p, &mut d, &mut NoFault).is_err());
        // Recovery on a fresh engine must also bind the ORIGINAL plan before any read.
        if let Ok(reopened) = FixtureTree::open(&t.0) {
            assert!(reopened.resume(&p, &mut d, &mut NoFault).is_err());
            assert!(reopened.rollback(&p, &mut d, &mut NoFault).is_err());
        }
        assert_eq!(d.actions.len(), n);
        let after = fs::symlink_metadata(&target).unwrap();
        assert_eq!(
            (
                after.dev(),
                after.ino(),
                after.mode(),
                after.uid(),
                after.gid(),
                after.nlink(),
                after.len()
            ),
            (
                pin.dev(),
                pin.ino(),
                pin.mode(),
                pin.uid(),
                pin.gid(),
                pin.nlink(),
                pin.len()
            ),
            "protected inode changed: {src} -> {dest}"
        );
        if let Some(watch) = watch {
            let mut events = [0u8; 256];
            assert_eq!(
                rustix::io::read(&watch, &mut events),
                Err(rustix::io::Errno::AGAIN),
                "engine opened/read/wrote protected inode: {src} -> {dest}"
            );
            // Positive control follows the inode across rename and sees an open.
            let _control = fs::File::open(&target).unwrap();
            assert!(rustix::io::read(&watch, &mut events).unwrap() > 0);
        }
    }
    eprintln!(
        "OPAQUE_RENAME_PERMUTATIONS: {} exhaustive pairs, seed=0x5eedc0570d12, {} protected inodes x {} destinations x staged/retained",
        cases.len(),
        protected.len(),
        destinations.len()
    );
}

#[test]
fn review_round1_opaque_admission_bounds_entire_tree_and_every_leaf() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for attack in 0..6 {
        let (t, _) = with_adapter();
        let mut dir = t.0.join("opaque/state");
        match attack {
            0 => {
                for _ in 0..18 {
                    dir.push("deep");
                    fs::create_dir(&dir).unwrap();
                    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            1 => {
                for n in 0..33 {
                    file(dir.join(format!("leaf{n}")), "SYNTHETIC");
                }
            }
            2 => file(dir.join("x".repeat(64)), "SYNTHETIC"),
            3 => {
                fs::create_dir(dir.join("nested")).unwrap();
                fs::set_permissions(dir.join("nested"), fs::Permissions::from_mode(0o755)).unwrap();
            }
            4 => {
                file(dir.join("second"), "SYNTHETIC");
                fs::hard_link(dir.join("second"), dir.join("third")).unwrap();
            }
            5 => {
                file(dir.join("second"), "SYNTHETIC");
                fs::set_permissions(dir.join("second"), fs::Permissions::from_mode(0o660)).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            FixtureTree::open(&t.0).is_err(),
            "unprotectable tree admitted: {attack}"
        );
    }
}

#[test]
fn review_round1_each_lifecycle_failure_quarantines_without_premature_commit() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct FailOnce {
        inner: Driver,
        ordinal: u32,
        style: usize,
        fired: bool,
    }
    impl FixtureDriver for FailOnce {
        fn perform(&mut self, o: &Obligation) -> Result<Receipt> {
            if !self.fired && o.ordinal == self.ordinal {
                self.fired = true;
                if self.style == 0 {
                    self.inner.actions.push(o.action.clone());
                    return Err(Error::Offline);
                }
                let mut r = self.inner.perform(o)?;
                if self.style == 1 {
                    return Err(Error::Offline);
                }
                r.obligation.ordinal += 1;
                return Ok(r);
            }
            self.inner.perform(o)
        }
    }
    let mut count = 0;
    for direction in [Direction::Forward, Direction::Reverse] {
        let (_sample, _, _, plan) = prepared();
        for obligation in plan.obligations(direction) {
            for style in 0..3 {
                let (t, tree, i, p) = prepared();
                let mut inner = Driver::new(&i, &p);
                if direction == Direction::Reverse {
                    tree.apply(&p, &mut inner, &mut NoFault).unwrap();
                }
                let mut d = FailOnce {
                    inner,
                    ordinal: obligation.ordinal,
                    style,
                    fired: false,
                };
                let result = if direction == Direction::Forward {
                    tree.apply(&p, &mut d, &mut NoFault)
                } else {
                    tree.rollback(&p, &mut d, &mut NoFault)
                };
                assert_eq!(
                    result,
                    Ok(Outcome::Offline),
                    "{direction:?} {:?} style={style}",
                    obligation.action
                );
                assert!(d.fired);
                assert!(!d.inner.running);
                let j: serde_json::Value =
                    serde_json::from_slice(&fs::read(t.0.join("journal.json")).unwrap()).unwrap();
                assert_eq!(j["journal"]["terminal"], "offline");
                assert_eq!(j["journal"]["cleanup"], true);
                let n = d.inner.actions.len();
                assert_eq!(tree.resume(&p, &mut d, &mut NoFault), Ok(Outcome::Offline));
                assert_eq!(d.inner.actions.len(), n);
                assert_preserved(&t.0);
                count += 1;
            }
        }
    }
    eprintln!(
        "LIFECYCLE_FAILURES: {count} apply/rollback obligations x before-effect/after-effect/wrong-receipt cases"
    );
}

#[test]
fn review_round1_every_cleanup_failure_is_retry_only_until_all_barriers_pass() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct Cleanup {
        inner: Driver,
        failed: Action,
        style: usize,
        cleaning: bool,
        broken: bool,
    }
    impl FixtureDriver for Cleanup {
        fn perform(&mut self, o: &Obligation) -> Result<Receipt> {
            if !self.cleaning && matches!(o.action, Action::HealthCheck { .. }) {
                self.cleaning = true;
                self.inner.actions.push(o.action.clone());
                return Err(Error::Offline);
            }
            // A failed StopService BEFORE its side effect can leave users running.
            if matches!(o.action, Action::AllIdentityUsersStopped {}) && self.inner.running {
                self.inner.actions.push(o.action.clone());
                return Ok(Receipt {
                    obligation: o.clone(),
                    observation: Observation::Stopped {
                        identity_users: vec!["still-running".into()],
                    },
                });
            }
            if self.cleaning && self.broken && o.action == self.failed {
                if self.style == 0 {
                    self.inner.actions.push(o.action.clone());
                    return Err(Error::Offline);
                }
                let mut r = self.inner.perform(o)?;
                if self.style == 1 {
                    return Err(Error::Offline);
                }
                r.obligation.ordinal += 1;
                return Ok(r);
            }
            self.inner.perform(o)
        }
    }
    let failures = [
        Action::IndependentQuarantine {},
        Action::Drain {
            adapter: "collector".into(),
        },
        Action::PreStartStop {
            adapter: "collector".into(),
        },
        Action::StopService {},
        Action::PostStopStop {
            adapter: "collector".into(),
        },
        Action::AllIdentityUsersStopped {},
    ];
    let mut count = 0;
    for direction in [Direction::Forward, Direction::Reverse] {
        for failed in &failures {
            for style in 0..3 {
                let (t, tree, i, p) = prepared();
                let mut inner = Driver::new(&i, &p);
                if direction == Direction::Reverse {
                    tree.apply(&p, &mut inner, &mut NoFault).unwrap();
                }
                let mut d = Cleanup {
                    inner,
                    failed: failed.clone(),
                    style,
                    cleaning: false,
                    broken: true,
                };
                let result = if direction == Direction::Forward {
                    tree.apply(&p, &mut d, &mut NoFault)
                } else {
                    tree.rollback(&p, &mut d, &mut NoFault)
                };
                assert_eq!(
                    result,
                    Err(Error::Offline),
                    "{direction:?} {failed:?}/{style}"
                );
                let j: serde_json::Value =
                    serde_json::from_slice(&fs::read(t.0.join("journal.json")).unwrap()).unwrap();
                assert_eq!(j["journal"]["cleanup"], true);
                assert!(j["journal"]["terminal"].is_null());
                let pos = d
                    .inner
                    .actions
                    .iter()
                    .rposition(|a| matches!(a, Action::HealthCheck { .. }))
                    .unwrap();
                assert_eq!(d.inner.actions[pos + 1], Action::IndependentQuarantine {});
                if !matches!(failed, Action::IndependentQuarantine {}) {
                    assert!(d.inner.actions[pos + 2..].contains(&Action::StopService {}));
                    assert!(
                        d.inner.actions[pos + 2..].contains(&Action::AllIdentityUsersStopped {})
                    );
                } else {
                    assert_eq!(d.inner.actions.len(), pos + 2);
                }
                let n = d.inner.actions.len();
                // Reopen to prove retry intent survives loss of in-memory state.
                let reopened = FixtureTree::open(&t.0).unwrap();
                assert_eq!(
                    reopened.resume(&p, &mut d, &mut NoFault),
                    Err(Error::Offline)
                );
                assert_eq!(
                    reopened.rollback(&p, &mut d, &mut NoFault),
                    Err(Error::Offline)
                );
                assert!(!d.inner.actions[n..].contains(&Action::StartService {}));
                d.broken = false;
                assert_eq!(
                    reopened.resume(&p, &mut d, &mut NoFault),
                    Ok(Outcome::Offline)
                );
                assert!(!d.inner.running);
                assert!(!d.inner.actions[n..].contains(&Action::StartService {}));
                let n = d.inner.actions.len();
                let journal = fs::read(t.0.join("journal.json")).unwrap();
                assert_eq!(
                    reopened.rollback(&p, &mut d, &mut NoFault),
                    Ok(Outcome::Offline)
                );
                assert_eq!(
                    reopened.resume(&p, &mut d, &mut NoFault),
                    Ok(Outcome::Offline)
                );
                assert_eq!(d.inner.actions.len(), n);
                assert_eq!(journal, fs::read(t.0.join("journal.json")).unwrap());
                assert_preserved(&t.0);
                count += 1;
            }
        }
    }
    eprintln!(
        "CLEANUP_FAILURES: {count} apply/rollback x all six barriers x before-effect/after-effect/wrong-receipt cases"
    );
}

fn cleanup_trace() -> Vec<(IoStep, Edge)> {
    let (_t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    d.fail = Some(Action::HealthCheck {
        adapter: "collector".into(),
    });
    let mut f = Injection::default();
    assert_eq!(tree.apply(&p, &mut d, &mut f), Ok(Outcome::Offline));
    f.trace
}

#[test]
fn review_round1_cleanup_intent_and_terminal_publication_io_errors_are_recoverable() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let boundaries = cleanup_trace();
    coverage("CleanupOffline", &boundaries);
    for recovery in [Direction::Forward, Direction::Reverse] {
        for (at, _) in boundaries.iter().enumerate() {
            let (t, tree, i, p) = prepared();
            let mut d = Driver::new(&i, &p);
            d.fail = Some(Action::HealthCheck {
                adapter: "collector".into(),
            });
            assert_eq!(
                tree.apply(
                    &p,
                    &mut d,
                    &mut Injection {
                        at: Some(at),
                        ..Default::default()
                    }
                ),
                Err(Error::Interrupted)
            );
            let cleanup_durable = t.0.join("journal.json").exists() && {
                let j: serde_json::Value =
                    serde_json::from_slice(&fs::read(t.0.join("journal.json")).unwrap()).unwrap();
                j["journal"]["cleanup"] == true
            };
            let active = read_bundle(&t.0.join("current"));
            assert!(active == *p.old_bundle() || active == *p.new_bundle());
            let n = d.actions.len();
            let result = if recovery == Direction::Forward {
                tree.resume(&p, &mut d, &mut NoFault)
            } else {
                tree.rollback(&p, &mut d, &mut NoFault)
            };
            assert_eq!(
                result,
                Ok(Outcome::Offline),
                "cleanup {recovery:?} at {at} {:?}",
                boundaries[at]
            );
            if cleanup_durable {
                assert!(!d.actions[n..].contains(&Action::StartService {}));
            }
            assert!(!d.running);
            let journal = fs::read(t.0.join("journal.json")).unwrap();
            assert_eq!(tree.resume(&p, &mut d, &mut NoFault), Ok(Outcome::Offline));
            assert_eq!(
                tree.rollback(&p, &mut d, &mut NoFault),
                Ok(Outcome::Offline)
            );
            assert_eq!(journal, fs::read(t.0.join("journal.json")).unwrap());
            assert_preserved(&t.0);
        }
    }
    eprintln!(
        "CLEANUP_OFFLINE_ERRORS: {} checkpoints x two recovery directions",
        boundaries.len()
    );
}

#[test]
fn review_round1_sigkill_cleanup_intent_and_terminal_publication() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use std::os::unix::process::ExitStatusExt;
    let boundaries = cleanup_trace();
    for (at, _) in boundaries.iter().enumerate() {
        let (t, tree, i, p) = prepared();
        let mut d = Driver::new(&i, &p);
        d.fail = Some(Action::HealthCheck {
            adapter: "collector".into(),
        });
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "abrupt_fault_worker", "--nocapture"])
            .env("VPR_MIGRATION_KILL_ROOT", &t.0)
            .env(
                "VPR_MIGRATION_KILL_PLAN",
                String::from_utf8(p.encode().unwrap()).unwrap(),
            )
            .env("VPR_MIGRATION_KILL_AT", at.to_string())
            .env("VPR_MIGRATION_KILL_DIRECTION", "offline")
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(
            status.signal(),
            Some(9),
            "cleanup SIGKILL {at} {:?}",
            boundaries[at]
        );
        let active = read_bundle(&t.0.join("current"));
        assert!(active == *p.old_bundle() || active == *p.new_bundle());
        assert_eq!(
            tree.resume(&p, &mut d, &mut NoFault),
            Ok(Outcome::Offline),
            "cleanup SIGKILL {at}"
        );
        let journal = fs::read(t.0.join("journal.json")).unwrap();
        assert_eq!(tree.resume(&p, &mut d, &mut NoFault), Ok(Outcome::Offline));
        assert_eq!(
            tree.rollback(&p, &mut d, &mut NoFault),
            Ok(Outcome::Offline)
        );
        assert_eq!(journal, fs::read(t.0.join("journal.json")).unwrap());
        assert_preserved(&t.0);
    }
    eprintln!("SIGKILL CleanupOffline: {} checkpoints", boundaries.len());
}

#[test]
fn review_round1_staging_short_write_worker() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Ok(root) = std::env::var("VPR_MIGRATION_STAGE_SHORT_ROOT") else {
        return;
    };
    struct LimitStaging {
        root: PathBuf,
        limited: bool,
    }
    impl Fault for LimitStaging {
        fn boundary(&mut self, step: IoStep, edge: Edge) -> Result<()> {
            if !self.limited
                && (step, edge) == (IoStep::Write, Edge::Before)
                && self.root.join("staged/router_runtime.py").exists()
            {
                self.limited = true;
                rustix::process::setrlimit(
                    rustix::process::Resource::Fsize,
                    rustix::process::Rlimit {
                        current: Some(1024),
                        maximum: Some(1024),
                    },
                )
                .unwrap();
            }
            Ok(())
        }
    }
    let p = Plan::parse(
        std::env::var("VPR_MIGRATION_STAGE_SHORT_PLAN")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let tree = FixtureTree::open(Path::new(&root)).unwrap();
    let i = tree.inspect().unwrap();
    let mut d = Driver::new(&i, &p);
    let mut f = LimitStaging {
        root: root.into(),
        limited: false,
    };
    assert_eq!(tree.apply(&p, &mut d, &mut f), Err(Error::Interrupted));
    assert!(f.limited);
}

#[test]
fn review_round1_actual_short_staging_write_split_utf8_is_recoverable() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for reverse in [false, true] {
        let (t, mut r) = with_adapter();
        r.release.files.insert(
            "router_runtime.py".into(),
            format!("{}é{}\n", "#".repeat(1023), "#".repeat(5000)),
        );
        r.provenance.source_sha256 = digest(serde_json::to_vec(&r.release).unwrap());
        let tree = FixtureTree::open(&t.0).unwrap();
        let i = tree.inspect().unwrap();
        let p = i.plan(r).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "review_round1_staging_short_write_worker",
                "--nocapture",
            ])
            .env("VPR_MIGRATION_STAGE_SHORT_ROOT", &t.0)
            .env(
                "VPR_MIGRATION_STAGE_SHORT_PLAN",
                String::from_utf8(p.encode().unwrap()).unwrap(),
            )
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        let raw = fs::read(t.0.join("staged/router_runtime.py")).unwrap();
        assert_eq!(raw.len(), 1024);
        assert!(std::str::from_utf8(&raw).is_err());
        let mut d = Driver::new(&i, &p);
        let expected = if reverse {
            Outcome::RolledBackFixture
        } else {
            Outcome::CommittedFixture
        };
        let result = if reverse {
            tree.rollback(&p, &mut d, &mut NoFault)
        } else {
            tree.resume(&p, &mut d, &mut NoFault)
        };
        assert_eq!(result, Ok(expected));
        assert_eq!(
            read_bundle(&t.0.join("current")),
            if reverse {
                p.old_bundle().clone()
            } else {
                p.new_bundle().clone()
            }
        );
        assert_preserved(&t.0);
    }
}

#[test]
fn review_round1_all_staging_files_accept_only_planned_raw_prefixes() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct BeforeExchange;
    impl Fault for BeforeExchange {
        fn boundary(&mut self, s: IoStep, e: Edge) -> Result<()> {
            if (s, e) == (IoStep::ExchangeRelease, Edge::Before) {
                Err(Error::Interrupted)
            } else {
                Ok(())
            }
        }
    }
    let (_sample, _, _, sample) = prepared();
    let mut count = 0;
    for name in sample.new_bundle().files.keys() {
        for cut in [0, 1, 2, 3] {
            for reverse in [false, true] {
                let (t, tree, i, p) = prepared();
                let mut d = Driver::new(&i, &p);
                assert_eq!(
                    tree.apply(&p, &mut d, &mut BeforeExchange),
                    Err(Error::Interrupted)
                );
                let full = p.new_bundle().files[name].as_bytes();
                let n = match cut {
                    0 => 0,
                    1 => 1,
                    2 => full.len() / 2,
                    _ => full.len() - 1,
                };
                fs::write(t.0.join("staged").join(name), &full[..n]).unwrap();
                let expected = if reverse {
                    Outcome::RolledBackFixture
                } else {
                    Outcome::CommittedFixture
                };
                let result = if reverse {
                    tree.rollback(&p, &mut d, &mut NoFault)
                } else {
                    tree.resume(&p, &mut d, &mut NoFault)
                };
                assert_eq!(result, Ok(expected), "{name} prefix={n} reverse={reverse}");
                assert_eq!(tree.resume(&p, &mut d, &mut NoFault), Ok(expected));
                assert_preserved(&t.0);
                count += 1;
            }
        }
    }
    eprintln!(
        "STAGING_PREFIXES: {count} every planned public file x four truncations x forward/reverse"
    );
}

#[test]
fn review_round1_sigkill_each_recovery_cleanup_boundary() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use std::os::unix::process::ExitStatusExt;
    let (_t, tree, i, p) = interrupted_staging();
    let mut d = Driver::new(&i, &p);
    let mut trace = Injection::default();
    assert_eq!(
        tree.resume(&p, &mut d, &mut trace),
        Ok(Outcome::CommittedFixture)
    );
    for (at, _) in trace.trace.iter().enumerate() {
        let (t, tree, i, p) = interrupted_staging();
        let mut d = Driver::new(&i, &p);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "abrupt_fault_worker", "--nocapture"])
            .env("VPR_MIGRATION_KILL_ROOT", &t.0)
            .env(
                "VPR_MIGRATION_KILL_PLAN",
                String::from_utf8(p.encode().unwrap()).unwrap(),
            )
            .env("VPR_MIGRATION_KILL_AT", at.to_string())
            .env("VPR_MIGRATION_KILL_DIRECTION", "recovery")
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(
            status.signal(),
            Some(9),
            "recovery SIGKILL {at} {:?}",
            trace.trace[at]
        );
        let active = read_bundle(&t.0.join("current"));
        assert!(active == *p.old_bundle() || active == *p.new_bundle());
        assert_eq!(
            tree.resume(&p, &mut d, &mut NoFault),
            Ok(Outcome::CommittedFixture),
            "recovery SIGKILL {at}"
        );
        let journal = fs::read(t.0.join("journal.json")).unwrap();
        assert_eq!(
            tree.resume(&p, &mut d, &mut NoFault),
            Ok(Outcome::CommittedFixture)
        );
        assert_eq!(
            tree.resume(&p, &mut d, &mut NoFault),
            Ok(Outcome::CommittedFixture)
        );
        assert_eq!(journal, fs::read(t.0.join("journal.json")).unwrap());
        assert_preserved(&t.0);
    }
    eprintln!("SIGKILL RecoveryCleanup: {} checkpoints", trace.trace.len());
}

#[test]
fn review_round1_opaque_leaf_custody_uses_no_data_open_through_whole_transaction() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use rustix::fs::inotify;
    let (t, r) = with_adapter();
    let watch =
        inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC).unwrap();
    let path = t.0.join("opaque/state/tailscaled.state");
    inotify::add_watch(
        &watch,
        &path,
        inotify::WatchFlags::OPEN | inotify::WatchFlags::ACCESS | inotify::WatchFlags::MODIFY,
    )
    .unwrap();
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree.inspect().unwrap();
    let p = i.plan(r).unwrap();
    let mut d = Driver::new(&i, &p);
    assert_eq!(
        tree.apply(&p, &mut d, &mut NoFault),
        Ok(Outcome::CommittedFixture)
    );
    assert_eq!(
        tree.resume(&p, &mut d, &mut NoFault),
        Ok(Outcome::CommittedFixture)
    );
    assert_eq!(
        tree.rollback(&p, &mut d, &mut NoFault),
        Ok(Outcome::RolledBackFixture)
    );
    let mut events = [0u8; 256];
    assert_eq!(
        rustix::io::read(&watch, &mut events),
        Err(rustix::io::Errno::AGAIN)
    );
    let _control = fs::File::open(path).unwrap();
    assert!(rustix::io::read(&watch, &mut events).unwrap() > 0);
}

#[test]
fn review_round1_active_drift_before_terminal_publish_cannot_commit() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    struct Late {
        root: PathBuf,
        fired: bool,
    }
    impl Fault for Late {
        fn boundary(&mut self, step: IoStep, edge: Edge) -> Result<()> {
            if !self.fired && (step, edge) == (IoStep::PublishJournal, Edge::Before) {
                let j: serde_json::Value =
                    serde_json::from_slice(&fs::read(self.root.join(".journal.pending")).unwrap())
                        .unwrap();
                if j["journal"]["terminal"] == "committed_fixture" {
                    self.fired = true;
                    file(self.root.join("current/router.nft"), "SYNTHETIC LATE DRIFT");
                }
            }
            Ok(())
        }
    }
    let (t, tree, i, p) = prepared();
    let mut d = Driver::new(&i, &p);
    let mut fault = Late {
        root: t.0.clone(),
        fired: false,
    };
    assert_eq!(tree.apply(&p, &mut d, &mut fault), Err(Error::Drift));
    assert!(fault.fired);
    let journal: serde_json::Value =
        serde_json::from_slice(&fs::read(t.0.join("journal.json")).unwrap()).unwrap();
    assert!(
        journal["journal"]["terminal"].is_null(),
        "active drift must be checked at publication, not after committing"
    );
    assert_preserved(&t.0);
}

#[test]
fn review_round1_protected_identity_over_lock_never_gets_data_opened() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use rustix::fs::inotify;
    let (t, tree, i, p) = prepared();
    let source = t.0.join("opaque/state/tailscaled.state");
    let watch =
        inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC).unwrap();
    inotify::add_watch(
        &watch,
        &source,
        inotify::WatchFlags::OPEN | inotify::WatchFlags::ACCESS | inotify::WatchFlags::MODIFY,
    )
    .unwrap();
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &source,
        rustix::fs::CWD,
        t.0.join(".allocations.lock"),
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .unwrap();
    assert!(tree.inspect().is_err());
    let mut d = Driver::new(&i, &p);
    assert!(tree.resume(&p, &mut d, &mut NoFault).is_err());
    let mut events = [0u8; 256];
    assert_eq!(
        rustix::io::read(&watch, &mut events),
        Err(rustix::io::Errno::AGAIN),
        "lock acquisition opened a protected inode before checking custody"
    );
}

#[test]
fn review_round1_largest_admitted_plan_fits_all_journal_records() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (t, mut request) = fixture(Layout::Retry84fb353);
    for name in ["Dockerfile", "router_runtime.py"] {
        request
            .release
            .files
            .insert(name.into(), "\u{1}".repeat(128 * 1024));
    }
    let tree = FixtureTree::open(&t.0).unwrap();
    let i = tree.inspect().unwrap();
    let (mut low, mut high) = (0, 128 * 1024 + 1);
    let mut best = None;
    while low < high {
        let middle = low + (high - low) / 2;
        let mut candidate = request.clone();
        candidate
            .release
            .files
            .insert("router.nft".into(), "\u{1}".repeat(middle));
        candidate.provenance.source_sha256 =
            digest(serde_json::to_vec(&candidate.release).unwrap());
        match i.plan(candidate) {
            Ok(plan) => {
                best = Some(plan);
                low = middle + 1;
            }
            Err(_) => high = middle,
        }
    }
    let p = best.expect("bounded large fixture admits some public plan");
    eprintln!(
        "CAPACITY_PROBE: accepted plan bytes={}",
        p.encode().unwrap().len()
    );
    let mut d = Driver::new(&i, &p);
    let mut f = Injection {
        at: Some(0),
        ..Default::default()
    };
    assert_eq!(
        tree.apply(&p, &mut d, &mut f),
        Err(Error::Interrupted),
        "accepted plan must fit its initial journal and reach its first I/O checkpoint"
    );
    assert_eq!(f.count, 1);
    assert_eq!(
        tree.resume(&p, &mut d, &mut NoFault),
        Ok(Outcome::CommittedFixture)
    );
    assert_eq!(
        tree.rollback(&p, &mut d, &mut NoFault),
        Ok(Outcome::RolledBackFixture)
    );
    assert_preserved(&t.0);
}

#[test]
fn custody_map_admission_bound_matches_the_strict_decoder() {
    let _serial = TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // 4 original opaque entries + 4 added directories + n leaves = total custody.
    for (leaves, admitted) in [(119_usize, true), (120, true), (121, false), (123, false)] {
        let (t, r) = with_adapter();
        for d in 0..4 {
            let dir = t.0.join(format!("opaque/state/d{d}"));
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        for n in 0..leaves {
            let leaf = t.0.join(format!("opaque/state/d{}/l{n}", n % 4));
            fs::write(&leaf, b"SYNTHETIC OPAQUE").unwrap();
            fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let prepared = FixtureTree::open(&t.0)
            .and_then(|tree| tree.inspect().map(|i| (tree, i)))
            .and_then(|(tree, i)| i.plan(r).map(|p| (tree, i, p)));
        if !admitted {
            assert!(
                prepared.is_err(),
                "{leaves} leaves must be refused at admission"
            );
            continue;
        }
        let (tree, i, p) = prepared.unwrap_or_else(|e| panic!("{leaves} leaves refused: {e:?}"));
        // An admitted plan must round-trip through the real decoder...
        let encoded = p.encode().unwrap();
        assert_eq!(
            Plan::parse(&encoded).unwrap().fingerprint(),
            p.fingerprint()
        );
        // ...and the journal it publishes must be recoverable in both directions.
        let mut d = Driver::new(&i, &p);
        assert_eq!(
            tree.apply(&p, &mut d, &mut NoFault).unwrap(),
            Outcome::CommittedFixture
        );
        assert_eq!(
            tree.resume(&p, &mut d, &mut NoFault).unwrap(),
            Outcome::CommittedFixture
        );
        assert_eq!(
            tree.rollback(&p, &mut d, &mut NoFault).unwrap(),
            Outcome::RolledBackFixture
        );
    }
}
