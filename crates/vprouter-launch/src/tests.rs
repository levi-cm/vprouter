#![forbid(unsafe_code)]
use super::*;
use serde_json::{Value, json};
use vprouter_core::{allocation::AllocationRecord, config::Configuration};
use vprouter_linux::docker::{LaunchContainer, LaunchImage};

pub(super) fn record() -> AllocationRecord {
    let cfg = Configuration::parse(serde_json::to_vec(&json!({"schema_version":2,"deployment_id":"launchlab","site":"debdev","gateway_image":format!("sha256:{}","a".repeat(64)),"exits":[{"id":"one","enabled":true,"state_dir":"/var/lib/launchlab/one","mode":{"kind":"direct"}}],"dependency_adapters":[],"client_policies":[]})).unwrap().as_slice()).unwrap();
    let cfg = cfg.validate_with(|_, _| panic!("no profile read")).unwrap();
    AllocationRecord::from_configuration(&cfg, 1).unwrap()
}
pub(super) fn fixture() -> (LaunchSpec, StagingEvidence) {
    let allocation = record();
    let exit = allocation.exits[0].clone();
    let spec = LaunchSpec {
        schema_version: 1,
        allocation,
        generation: 1,
        exit,
        container_id: "a".repeat(64),
        started_at: "2026-10-24T12:00:00.000000001Z".into(),
        process_start_time: 123,
        image_ref: format!("tailscale/tailscale@sha256:{}", "b".repeat(64)),
        worker_sha256: "c".repeat(64),
    };
    let stage = StagingEvidence {
        schema_version: 1,
        image_ref: spec.image_ref.clone(),
        content_id: format!("sha256:{}", "d".repeat(64)),
        os: "linux".into(),
        architecture: if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "amd64"
        }
        .into(),
        artifact_kind: "synthetic_static_probe_v1".into(),
        artifact_path: "/var/lib/vprouter-v2-lab/probe".into(),
        artifact_sha256: spec.worker_sha256.clone(),
        artifact_size: 128,
        worker_path: spec::WORKER.into(),
        execution_policy_sha256: None,
    };
    (spec, stage)
}
pub(super) fn container_value(s: &LaunchSpec, stage: &StagingEvidence) -> Value {
    json!({"Id":s.container_id,"Image":stage.content_id,"State":{"Running":true,"Paused":false,"Restarting":false,"Dead":false,"Pid":42,"StartedAt":s.started_at},
        "Config":{"Labels":{"io.vprouter.deployment":"launchlab","io.vprouter.role":"gateway","io.vprouter.exit":"other-exit"},"User":"","Volumes":null,"Env":["DO_NOT_PRINT_SECRET"]},
        "AppArmorProfile":"","ProcessLabel":"","MountLabel":"",
        "Mounts":[{"Type":"bind","Source":stage.artifact_path,"Destination":spec::WORKER,"RW":false,"Propagation":"rprivate"}],
        "HostConfig":{"NetworkMode":"none","Privileged":false,"ReadonlyRootfs":true,"PidMode":"","UsernsMode":"","CgroupnsMode":"private","IpcMode":"private","UTSMode":"","CapAdd":null,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Binds":[format!("{}:{}:ro",stage.artifact_path.display(),spec::WORKER)],"Mounts":null,"Devices":[],"DeviceRequests":null,"DeviceCgroupRules":null,"VolumesFrom":null,"Tmpfs":null,"Sysctls":null,"GroupAdd":null,"CgroupParent":"","Runtime":"runc","Init":null,
        "MaskedPaths":["/proc/asound","/proc/acpi","/proc/interrupts","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware","/sys/devices/virtual/powercap"],"ReadonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]}})
}
#[test]
fn strict_specs_validate_full_record_generation_and_exit() {
    let (s, stage) = fixture();
    let value = serde_json::to_value(&s).unwrap();
    assert!(LaunchSpec::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
    for (field, value, error) in [
        ("schema_version", json!(2), Error::InvalidSpec),
        ("generation", json!(2), Error::AllocationMismatch),
        ("process_start_time", json!(0), Error::InvalidSpec),
        ("container_id", json!("short"), Error::InvalidSpec),
        ("argv", json!(["DO_NOT_PRINT_SECRET"]), Error::InvalidSpec),
    ] {
        let mut v = serde_json::to_value(&s).unwrap();
        v[field] = value;
        let e = LaunchSpec::parse(&serde_json::to_vec(&v).unwrap())
            .err()
            .unwrap();
        assert_eq!(e, error);
        assert!(!format!("{e:?} {e}").contains("SECRET"));
    }
    let mut v = value.clone();
    v["exit"]["state_dir"] = json!("/var/lib/launchlab/wrong");
    assert!(matches!(
        LaunchSpec::parse(&serde_json::to_vec(&v).unwrap()),
        Err(Error::AllocationMismatch)
    ));
    let mut v = value;
    v["allocation"]["exits"][0]["nft_table"] = json!("foreign");
    assert!(matches!(
        LaunchSpec::parse(&serde_json::to_vec(&v).unwrap()),
        Err(Error::AllocationMismatch)
    ));
    let bytes = serde_json::to_vec(&stage).unwrap();
    assert!(matches!(
        StagingEvidence::parse(&bytes),
        Err(Error::ExecutableMismatch)
    ));
    let mut v = serde_json::to_value(&stage).unwrap();
    v["artifact_kind"] = json!("vprouter_worker_v1");
    assert!(matches!(
        StagingEvidence::parse(&serde_json::to_vec(&v).unwrap()),
        Err(Error::LaunchUnavailable)
    ));
    for (key, value) in [
        ("schema_version", json!(2)),
        ("image_ref", json!("tailscale/tailscale:latest")),
        ("worker_path", json!("/bin/sh")),
        ("artifact_path", json!("/a/../secret")),
        ("env", json!({"key":"SECRET"})),
        ("artifact_size", json!(u64::MAX)),
    ] {
        let mut v = serde_json::to_value(&stage).unwrap();
        v[key] = value;
        assert!(StagingEvidence::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    }
}
#[test]
fn actual_gateway_staging_is_bound_to_compiled_inert_program_only() {
    let (_, mut stage) = fixture();
    let bundle = super::programs::ReviewedBundle::current().unwrap();
    let (sha, size) = bundle.init().unwrap();
    stage.artifact_kind = "actual_gateway_lab_v1".into();
    stage.image_ref = format!("vprouter-v2-lab@{}", stage.content_id);
    stage.artifact_path = format!("/var/lib/vprouter-v2-lab/task8b2-{sha}.gateway-init").into();
    stage.artifact_sha256 = sha.into();
    stage.artifact_size = size;
    stage.execution_policy_sha256 = None;
    let value = serde_json::to_value(&stage).unwrap();
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(StagingEvidence::parse_actual_gateway(&bytes).is_ok());
    assert!(matches!(
        StagingEvidence::parse(&bytes),
        Err(Error::ExecutableMismatch)
    ));
    for (key, replacement) in [
        ("artifact_kind", json!("vprouter_worker_v1")),
        ("artifact_sha256", json!("a".repeat(64))),
        ("artifact_size", json!(size + 1)),
        (
            "artifact_path",
            json!("/var/lib/vprouter-v2-lab/foreign-init"),
        ),
        ("execution_policy_sha256", json!("a".repeat(64))),
        ("image_ref", json!(format!("foreign@{}", stage.content_id))),
    ] {
        let mut bad = value.clone();
        bad[key] = replacement;
        assert!(StagingEvidence::parse_actual_gateway(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}
#[test]
fn docker_functional_projection_fails_closed_and_gateway_is_shared() {
    let (s, stage) = fixture();
    let value = container_value(&s, &stage);
    let c: LaunchContainer = serde_json::from_value(value.clone()).unwrap();
    assert!(evidence::container(&s, &stage, &c).is_ok());
    let mut docker26 = value.clone();
    docker26["HostConfig"]["MaskedPaths"]
        .as_array_mut()
        .unwrap()
        .retain(|p| p != "/proc/interrupts");
    assert!(
        evidence::container(
            &s,
            &stage,
            &serde_json::from_value(docker26.clone()).unwrap()
        )
        .is_ok()
    );
    docker26["HostConfig"]["MaskedPaths"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert_eq!(
        evidence::container(&s, &stage, &serde_json::from_value(docker26).unwrap()),
        Err(Error::UnsupportedConfiguration)
    );
    let mut omitted = value.clone();
    for key in ["Mounts", "Init", "Tmpfs", "Sysctls"] {
        omitted["HostConfig"].as_object_mut().unwrap().remove(key);
    }
    let c: LaunchContainer = serde_json::from_value(omitted).unwrap();
    assert!(evidence::container(&s, &stage, &c).is_ok());
    let mut unknown = value.clone();
    unknown["HostConfig"]["UnknownFunctionalOption"] = json!(false);
    assert_eq!(
        evidence::container(&s, &stage, &serde_json::from_value(unknown).unwrap()),
        Err(Error::UnsupportedConfiguration)
    );
    for field in [
        "Privileged",
        "ReadonlyRootfs",
        "NetworkMode",
        "PidMode",
        "UsernsMode",
        "CgroupnsMode",
        "CapDrop",
        "SecurityOpt",
        "Devices",
        "Runtime",
        "MaskedPaths",
    ] {
        let mut v = value.clone();
        v["HostConfig"].as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<LaunchContainer>(v).is_err(),
            "{field}"
        );
    }
    for (field, wrong) in [
        ("Privileged", json!(true)),
        ("ReadonlyRootfs", json!(false)),
        ("NetworkMode", json!("host")),
        ("PidMode", json!("host")),
        ("UsernsMode", json!("host")),
        ("CgroupnsMode", json!("host")),
        ("CapAdd", json!(["SYS_ADMIN"])),
        ("CapDrop", json!([])),
        ("SecurityOpt", json!(["seccomp=unconfined"])),
        ("Devices", json!([{"PathOnHost":"/dev/net/tun"}])),
        ("Runtime", json!("unknown")),
        ("MaskedPaths", json!([])),
    ] {
        let mut v = value.clone();
        v["HostConfig"][field] = wrong;
        let c = serde_json::from_value(v).unwrap();
        assert_eq!(
            evidence::container(&s, &stage, &c),
            Err(Error::UnsupportedConfiguration),
            "{field}"
        );
    }
    for (path, wrong) in [
        ("/State/Pid", json!(0)),
        ("/State/StartedAt", json!("stale")),
        ("/Config/Labels/io.vprouter.deployment", json!("foreign")),
        ("/Image", json!("sha256:wrong")),
    ] {
        let mut v = value.clone();
        *v.pointer_mut(path).unwrap() = wrong;
        let c = serde_json::from_value(v).unwrap();
        assert_eq!(
            evidence::container(&s, &stage, &c),
            Err(Error::ContainerMismatch)
        );
    }
}
#[test]
fn manifests_bind_platform_and_content_without_multiarch_confusion() {
    let (s, stage) = fixture();
    let mut i = LaunchImage {
        id: stage.content_id.clone().into(),
        repo_digests: vec![s.image_ref.clone().into()],
        os: "linux".into(),
        architecture: stage.architecture.clone().into(),
    };
    assert!(evidence::image(&s, &stage, &i).is_ok());
    i.id = s.image_ref.split('@').nth(1).unwrap().into();
    assert_eq!(evidence::image(&s, &stage, &i), Err(Error::ImageMismatch));
    i.id = stage.content_id.clone().into();
    i.architecture = "foreign".into();
    assert_eq!(evidence::image(&s, &stage, &i), Err(Error::ImageMismatch));
    i.architecture = stage.architecture.clone().into();
    i.repo_digests.push(s.image_ref.clone().into());
    assert_eq!(evidence::image(&s, &stage, &i), Err(Error::ImageMismatch));
}
#[test]
fn proc_stat_handles_tricky_comm_and_refuses_reuse_zombies() {
    let tail = (0..18).map(|_| "0").collect::<Vec<_>>().join(" ");
    let s = format!("42 (odd ) comm\n(end)) S {tail} 321 0");
    assert_eq!(process::stat_start(&s, 42), Ok(321));
    assert!(process::stat_start(&s, 43).is_err());
    assert!(process::stat_start(&s.replace(") S ", ") Z "), 42).is_err());
    assert!(process::stat_start("42 (no fields) S", 42).is_err());
}
#[test]
fn uidmap_cgroup_paths_and_static_elf_are_exact() {
    assert!(process::initial_map("         0          0 4294967295\n"));
    assert!(!process::initial_map("0 100000 65536\n"));
    assert!(!process::initial_map("0 0 4294967295\n1 1 1"));
    let id = "a".repeat(64);
    assert_eq!(
        process::cgroup_path(&format!("0::/system.slice/docker-{id}.scope\n"), &id).unwrap(),
        format!("/system.slice/docker-{id}.scope")
    );
    for p in [
        format!("0::/foreign/docker-{id}.scope"),
        format!("0::/system.slice/docker-{id}.scope/extra"),
        format!("0::/system.slice/docker-{id}.scope\n1:x:/other"),
    ] {
        assert!(process::cgroup_path(&p, &id).is_err());
    }
    let mut b = vec![0; 120];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16] = 2;
    b[18] = 62;
    b[20] = 1;
    b[32] = 64;
    b[54] = 56;
    b[56] = 1;
    b[64] = 1;
    assert!(process::elf(&b, "amd64").is_ok());
    assert!(process::elf(&b, "arm64").is_err());
    b[64] = 3;
    assert!(process::elf(&b, "amd64").is_err());
    b[64] = 2;
    assert!(process::elf(&b, "amd64").is_err());
    b[64] = 1;
    b[32] = 200;
    assert!(process::elf(&b, "amd64").is_err());
}

#[test]
fn inherited_daemon_security_profiles_are_exact_and_bind_container_apparmor() {
    use evidence::DaemonSecurity;
    use vprouter_linux::docker::LaunchDaemon;
    let make = |options: Vec<&str>| LaunchDaemon {
        security_options: options.into_iter().map(Into::into).collect(),
        cgroup_driver: "systemd".into(),
        cgroup_version: "2".into(),
        os_type: "linux".into(),
    };
    // Two exact supported sets, independent of native daemon serialization order.
    for options in [
        vec!["name=seccomp,profile=builtin", "name=cgroupns"],
        vec!["name=cgroupns", "name=seccomp,profile=builtin"],
    ] {
        assert_eq!(
            evidence::daemon(&make(options)),
            Ok(DaemonSecurity::BuiltinSeccomp)
        );
    }
    for options in [
        vec![
            "name=apparmor,profile=default",
            "name=seccomp,profile=builtin",
            "name=cgroupns",
        ],
        vec![
            "name=apparmor",
            "name=seccomp,profile=builtin",
            "name=cgroupns",
        ],
        vec![
            "name=cgroupns",
            "name=apparmor",
            "name=seccomp,profile=builtin",
        ],
        vec![
            "name=seccomp,profile=builtin",
            "name=cgroupns",
            "name=apparmor",
        ],
    ] {
        assert_eq!(
            evidence::daemon(&make(options)),
            Ok(DaemonSecurity::AppArmorBuiltinSeccomp)
        );
    }
    for options in [
        vec![
            "name=apparmor,profile=custom",
            "name=seccomp,profile=builtin",
            "name=cgroupns",
        ],
        vec![
            "name=apparmor,profile=unconfined",
            "name=seccomp,profile=builtin",
            "name=cgroupns",
        ],
        vec![
            "name=apparmor,profile=default,extra=unknown",
            "name=seccomp,profile=builtin",
            "name=cgroupns",
        ],
        vec![
            "name=apparmor",
            "name=apparmor,profile=default",
            "name=seccomp,profile=builtin",
            "name=cgroupns",
        ],
        vec![
            "name=apparmor,profile=default",
            "name=apparmor,profile=default",
            "name=seccomp,profile=builtin",
            "name=cgroupns",
        ],
        vec![],
        vec!["name=cgroupns"],
        vec!["name=seccomp,profile=builtin"],
        vec!["name=apparmor", "name=cgroupns"],
        vec!["name=cgroupns", "name=cgroupns"],
        vec![
            "name=cgroupns",
            "name=seccomp,profile=builtin",
            "name=cgroupns",
        ],
        vec![
            "name=cgroupns",
            "name=seccomp,profile=builtin",
            "name=seccomp,profile=builtin",
        ],
        vec![
            "name=apparmor",
            "name=apparmor",
            "name=cgroupns",
            "name=seccomp,profile=builtin",
        ],
        vec!["name=cgroupns", "name=seccomp,profile=unconfined"],
        vec![
            "name=cgroupns",
            "name=seccomp,profile=/DO_NOT_PRINT_SECRET/custom.json",
        ],
        vec![
            "name=cgroupns",
            "name=seccomp,profile=builtin,extra=unknown",
        ],
        vec![
            "name=cgroupns",
            "name=seccomp,profile=builtin",
            "name=seccomp,profile=unconfined",
        ],
        vec![
            "name=cgroupns",
            "name=seccomp,profile=builtin",
            "name=rootless",
        ],
        vec![
            "name=cgroupns",
            "name=seccomp,profile=builtin",
            "name=userns",
        ],
        vec![
            "name=cgroupns",
            "name=seccomp,profile=builtin",
            "name=selinux",
        ],
        vec![
            "name=cgroupns",
            "name=seccomp,profile=builtin",
            "name=unknown",
        ],
    ] {
        let error = evidence::daemon(&make(options)).unwrap_err();
        assert_eq!(error, Error::UnsupportedConfiguration);
        assert!(!format!("{error:?} {error}").contains("SECRET"));
    }
    // Native /info projection never silently defaults a missing/malformed list.
    for value in [
        json!({}),
        json!({"SecurityOptions":null}),
        json!({"SecurityOptions":"name=cgroupns"}),
    ] {
        let mut v = json!({"CgroupDriver":"systemd","CgroupVersion":"2","OSType":"linux"});
        v.as_object_mut()
            .unwrap()
            .extend(value.as_object().unwrap().clone());
        assert!(serde_json::from_value::<LaunchDaemon>(v).is_err());
    }
    let (s, stage) = fixture();
    let mut c: LaunchContainer = serde_json::from_value(container_value(&s, &stage)).unwrap();
    let absent =
        evidence::daemon(&make(vec!["name=cgroupns", "name=seccomp,profile=builtin"])).unwrap();
    let apparmor = evidence::daemon(&make(vec![
        "name=cgroupns",
        "name=seccomp,profile=builtin",
        "name=apparmor",
    ]))
    .unwrap();
    assert!(absent.bind_container(&c).is_ok());
    assert_eq!(
        apparmor.bind_container(&c),
        Err(Error::UnsupportedConfiguration)
    );
    c.app_armor_profile = "docker-default".into();
    assert!(apparmor.bind_container(&c).is_ok());
    assert_eq!(
        absent.bind_container(&c),
        Err(Error::UnsupportedConfiguration)
    );
    c.app_armor_profile = "unconfined".into();
    assert_eq!(
        apparmor.bind_container(&c),
        Err(Error::UnsupportedConfiguration)
    );
    assert_eq!(
        absent.bind_container(&c),
        Err(Error::UnsupportedConfiguration)
    );
}
