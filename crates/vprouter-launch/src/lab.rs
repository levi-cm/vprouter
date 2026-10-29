#![forbid(unsafe_code)]
//! Test-only owned-guest harness. Not linked into the production library/helper.
use super::{Admission, Error, LaunchSpec, Result, StagingEvidence, process, tests};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
use vprouter_linux::docker::DockerClient;
// Only explicitly validated public metadata may leave wiping Docker DTOs.
pub(super) fn public_started_at(value: &str) -> Result<String> {
    if !super::spec::valid_start(value) {
        return Err(Error::ContainerMismatch);
    }
    Ok(value.to_owned())
}
pub(super) fn public_content_id(value: &str, expected: &str) -> Result<String> {
    if value != expected
        || !value
            .strip_prefix("sha256:")
            .is_some_and(super::spec::digest)
    {
        return Err(Error::ImageMismatch);
    }
    Ok(value.to_owned())
}
#[test]
fn docker_public_metadata_projection_refuses_unvalidated_fields() {
    for value in [
        "DOCKER_PRIVATE_PAYLOAD_9bc7a1fd",
        "",
        "2026-10-28T06:00:00Z-private",
        "2026-10-28T06:00:00\n",
    ] {
        assert!(public_started_at(value).is_err());
    }
    assert_eq!(
        public_started_at("2026-10-28T06:00:00.123456789Z").unwrap(),
        "2026-10-28T06:00:00.123456789Z"
    );
    let expected = format!("sha256:{}", "a".repeat(64));
    for value in [
        "DOCKER_PRIVATE_PAYLOAD_9bc7a1fd".to_owned(),
        format!("sha256:{}", "b".repeat(64)),
        "sha256:short".to_owned(),
    ] {
        assert!(public_content_id(&value, &expected).is_err());
    }
    assert_eq!(public_content_id(&expected, &expected).unwrap(), expected);
}
pub(super) const IMAGE: &str =
    "tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065";
const PROBE: &str = "/var/lib/vprouter-v2-lab/launch-probe";
pub(super) fn admit_lab() -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(Error::LabRequired);
    }
    let own = fs::metadata("/proc/self/ns/net").map_err(|_| Error::LabRequired)?;
    let init = fs::metadata("/proc/1/ns/net").map_err(|_| Error::LabRequired)?;
    if (own.dev(), own.ino()) == (init.dev(), init.ino()) {
        return Err(Error::LabRequired);
    }
    let mut dir = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::LabRequired)?;
    for name in ["var", "lib", "vprouter-v2-lab"] {
        let st = fstat(&dir).map_err(|_| Error::LabRequired)?;
        if st.st_uid != 0 || st.st_mode & 0o022 != 0 {
            return Err(Error::LabRequired);
        }
        dir = openat(
            &dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::LabRequired)?;
    }
    let st = fstat(&dir).map_err(|_| Error::LabRequired)?;
    if st.st_uid != 0 || st.st_gid != 0 || st.st_mode & 0o7777 != 0o700 {
        return Err(Error::LabRequired);
    }
    let marker = openat(
        &dir,
        "isolated-acceptance",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::LabRequired)?;
    let st = fstat(&marker).map_err(|_| Error::LabRequired)?;
    if st.st_uid != 0
        || st.st_gid != 0
        || st.st_mode & 0o7777 != 0o600
        || st.st_nlink != 1
        || FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
    {
        return Err(Error::LabRequired);
    }
    process::single_threaded()?;
    Ok(())
}
pub(super) fn docker(args: &[&str]) -> Result<Vec<u8>> {
    // Fixed test-only native argv, never a shell. Output is never printed.
    let output = Command::new("docker")
        .args(args)
        .output()
        .map_err(|_| Error::DockerUnavailable)?;
    if !output.status.success() {
        return Err(Error::DockerUnavailable);
    }
    if output.stdout.len() > 1024 * 1024 {
        return Err(Error::TooLarge);
    }
    Ok(output.stdout)
}
struct Disposable {
    id: String,
    dir: PathBuf,
}
impl Drop for Disposable {
    fn drop(&mut self) {
        if !self.id.is_empty() {
            let _ = docker(&["rm", "--force", &self.id]);
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}
pub(super) fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| Error::UnsafeInput)?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| Error::UnsafeInput)
}
pub(super) fn case(s: &str) {
    println!("{{\"case\":\"{s}\",\"result\":\"pass\"}}");
}
pub(super) fn stage(s: &str) {
    eprintln!("LAB_STAGE {s}");
}
pub fn run() -> Result<()> {
    admit_lab()?; // Before subprocesses, API requests, or mutation.
    stage("admitted_owned_isolated_guest");
    let dir = PathBuf::from(format!(
        "/var/lib/vprouter-v2-lab/task6-{}",
        std::process::id()
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|_| Error::UnsafeInput)?;
    let mut disposable = Disposable {
        id: String::new(),
        dir,
    };
    let bytes = vprouter_linux::storage::read(
        Path::new(PROBE),
        vprouter_linux::storage::Kind::PublicFile,
        super::spec::LIMIT,
    )
    .map_err(|_| Error::UnsafeInput)?;
    let digest = vprouter_linux::sha256(&bytes);
    process::elf(
        &bytes,
        if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "amd64"
        },
    )?;
    let bind = format!("{PROBE}:{}:ro", super::spec::WORKER);
    stage("create_new_disposable_pinned_container");
    let out = docker(&[
        "run",
        "--detach",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--label",
        "io.vprouter.deployment=launchlab",
        "--label",
        "io.vprouter.role=gateway",
        "--volume",
        &bind,
        "--entrypoint",
        super::spec::WORKER,
        IMAGE,
    ])?;
    let id = String::from_utf8(out)
        .map_err(|_| Error::DockerUnavailable)?
        .trim()
        .to_string();
    if !super::spec::digest(&id) {
        return Err(Error::DockerUnavailable);
    }
    disposable.id = id.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| Error::UnsupportedPlatform)?;
    runtime.block_on(async {
        let docker_client=DockerClient::default();
        stage("native_container_inspect");
        let c=docker_client.launch_container(&id).await.map_err(|e| { eprintln!("LAB_NATIVE_REASON container {e:?}"); Error::DockerUnavailable })?;
        stage("native_image_inspect");
        let i=docker_client.launch_image(&c.image).await.map_err(|e| { eprintln!("LAB_NATIVE_REASON image {e:?}"); Error::DockerUnavailable })?;
        let (mut spec,mut staging)=tests::fixture();
        spec.container_id=id.clone();spec.started_at=public_started_at(&c.state.started_at)?;spec.image_ref=IMAGE.into();spec.worker_sha256=digest.clone();
        spec.process_start_time=process::stat_start(&fs::read_to_string(format!("/proc/{}/stat",c.state.pid)).map_err(|_|Error::ProcessUnavailable)?,c.state.pid)?;
        staging.image_ref=IMAGE.into();staging.content_id=public_content_id(&i.id,&c.image)?;staging.artifact_path=PROBE.into();staging.artifact_sha256=digest;staging.artifact_size=bytes.len() as u64;
        let spec_path=disposable.dir.join("spec.json");let staging_path=disposable.dir.join("staging.json");
        write(&spec_path,&serde_json::to_vec(&spec).map_err(|_|Error::InvalidSpec)?)?;write(&staging_path,&serde_json::to_vec(&staging).map_err(|_|Error::InvalidSpec)?)?;
        stage("positive_native_docker_proc_fd_admission");
        let mut admitted=Admission::inspect_evidence(LaunchSpec::load(&spec_path)?,StagingEvidence::load_probe(&staging_path)?).await?;
        admitted.revalidate().await?;case("native_docker_proc_root_cgroup_namespaces_static_executable_admitted");
        admitted.process.reject_wrong_retained_handles(&admitted.spec, &admitted.staging)?;
        case("real_wrong_namespace_and_cgroup_descriptors_refused");
        let mut wrong_spec = LaunchSpec::load(&spec_path)?;
        let mut wrong_stage = StagingEvidence::load_probe(&staging_path)?;
        wrong_spec.worker_sha256 = "e".repeat(64);
        wrong_stage.artifact_sha256 = wrong_spec.worker_sha256.clone();
        if Admission::inspect_evidence(wrong_spec, wrong_stage).await.err() != Some(Error::ExecutableMismatch) { return Err(Error::ExecutableMismatch); }
        case("actual_artifact_bytes_hash_mismatch_refused");

        let mut altered=serde_json::to_value(&spec).map_err(|_|Error::InvalidSpec)?;
        for (field,value,expected) in [("process_start_time",serde_json::json!(spec.process_start_time+1),Error::ProcessChanged),("started_at",serde_json::json!("2026-10-24T00:00:00Z"),Error::ContainerMismatch),("container_id",serde_json::json!("f".repeat(64)),Error::DockerUnavailable),("worker_sha256",serde_json::json!("f".repeat(64)),Error::ImageMismatch),("image_ref",serde_json::json!(format!("tailscale/tailscale@sha256:{}","f".repeat(64))),Error::ImageMismatch)] {
            altered[field]=value;
            let wrong=LaunchSpec::parse(&serde_json::to_vec(&altered).map_err(|_|Error::InvalidSpec)?)?;
            if Admission::inspect_evidence(wrong,StagingEvidence::load_probe(&staging_path)?).await.err()!=Some(expected){return Err(Error::ProcessChanged);}
            altered=serde_json::to_value(&spec).map_err(|_|Error::InvalidSpec)?;
        }
        case("changed_starttime_container_manifest_hash_refused");
        // Native inspect data from the real container is projected, then each
        // independent bound check is exercised against an explicit wrong value.
        // Container labels are immutable: create a separate real foreign one.
        stage("foreign_labeled_container_refused");
        let foreign_out=docker(&["run","--detach","--network","none","--read-only","--cap-drop","ALL","--security-opt","no-new-privileges","--label","io.vprouter.deployment=foreign","--label","io.vprouter.role=gateway","--volume",&bind,"--entrypoint",super::spec::WORKER,IMAGE])?;
        let foreign=String::from_utf8(foreign_out).map_err(|_|Error::DockerUnavailable)?.trim().to_string();
        if !super::spec::digest(&foreign){return Err(Error::DockerUnavailable);}
        let foreign_guard=Disposable{id:foreign.clone(),dir:disposable.dir.join("unused")};
        let mut foreign_spec=LaunchSpec::parse(&serde_json::to_vec(&spec).map_err(|_|Error::InvalidSpec)?)?;foreign_spec.container_id=foreign;
        let foreign_c=docker_client.launch_container(&foreign_spec.container_id).await.map_err(|_|Error::DockerUnavailable)?;foreign_spec.started_at=public_started_at(&foreign_c.state.started_at)?;
        if Admission::inspect_evidence(foreign_spec,StagingEvidence::load_probe(&staging_path)?).await.err()!=Some(Error::ContainerMismatch){return Err(Error::ContainerMismatch);}
        drop(foreign_guard);case("real_foreign_deployment_container_refused");
        stage("test_owned_container_pause_then_stop_stale_handles");
        docker(&["pause",&id])?;if admitted.revalidate().await.err()!=Some(Error::ContainerMismatch){return Err(Error::ProcessChanged);}docker(&["unpause",&id])?;admitted.revalidate().await?;
        docker(&["kill",&id])?;
        if admitted.revalidate().await.is_ok(){return Err(Error::ProcessChanged);}case("paused_and_dead_container_stale_handles_refused");
        if admitted.launch()!=Err(Error::LaunchUnavailable){return Err(Error::LaunchUnavailable);}
        println!("{{\"case\":\"launch_admission_isolated_acceptance\",\"result\":\"pass\",\"guard_runtime\":false,\"activation\":false}}");
        Ok(())
    })
}
use std::os::unix::fs::DirBuilderExt;
