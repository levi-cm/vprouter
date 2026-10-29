#![forbid(unsafe_code)]
//! Ignored kernel oracle: creates ONLY new disposable synthetic resources.
use super::{
    Admission, Error, LaunchSpec, Result, StagingEvidence, execution, kernel, lab, owned, process,
    tests,
};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use vprouter_core::{
    allocation::{AllocationRecord, AllocationStore},
    config::Configuration,
};
use vprouter_linux::docker::DockerClient;
const PROBE: &str = "/var/lib/vprouter-v2-lab/launch-execution-probe";
struct Resources {
    id: String,
    dir: PathBuf,
}
impl Drop for Resources {
    fn drop(&mut self) {
        if !self.id.is_empty() {
            let _ = lab::docker(&["rm", "--force", &self.id]);
        } /* mounted ownership records deliberately survive failed attempts */
    }
}
fn private(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| Error::UnsafeInput)
}
fn allocation(dir: &Path) -> Result<AllocationRecord> {
    let exits=["one","two"].into_iter().map(|id|serde_json::json!({"id":id,"enabled":true,"state_dir":dir.join(id),"mode":{"kind":"direct"}})).collect::<Vec<_>>();
    let value = serde_json::json!({"schema_version":2,"deployment_id":"launchlab","site":"debdev","gateway_image":format!("sha256:{}","a".repeat(64)),"exits":exits,"dependency_adapters":[],"client_policies":[]});
    let cfg = Configuration::parse(&serde_json::to_vec(&value).map_err(|_| Error::InvalidSpec)?)
        .map_err(|_| Error::InvalidSpec)?
        .validate_with(|_, _| panic!("no profile reads"))
        .map_err(|_| Error::InvalidSpec)?;
    AllocationRecord::from_configuration(&cfg, 1).map_err(|_| Error::AllocationMismatch)
}
pub(super) fn inspect(
    id: &str,
    allocation: &AllocationRecord,
    exit: usize,
    digest: &str,
    size: u64,
) -> Result<Admission> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| Error::UnsupportedPlatform)?;
    let result = rt.block_on(async {
        let docker = DockerClient::default();
        let c = docker
            .launch_container(id)
            .await
            .map_err(|_| Error::DockerUnavailable)?;
        let i = docker
            .launch_image(&c.image)
            .await
            .map_err(|_| Error::DockerUnavailable)?;
        let (mut spec, mut stage) = tests::fixture();
        spec.allocation = serde_json::from_slice(
            &serde_json::to_vec(allocation).map_err(|_| Error::InvalidSpec)?,
        )
        .map_err(|_| Error::InvalidSpec)?;
        spec.exit = allocation.exits[exit].clone();
        spec.container_id = id.into();
        spec.started_at = lab::public_started_at(&c.state.started_at)?;
        spec.image_ref = lab::IMAGE.into();
        spec.worker_sha256 = digest.into();
        spec.process_start_time = process::stat_start(
            &fs::read_to_string(format!("/proc/{}/stat", c.state.pid))
                .map_err(|_| Error::ProcessUnavailable)?,
            c.state.pid,
        )?;
        stage.image_ref = spec.image_ref.clone();
        stage.content_id = lab::public_content_id(&i.id, &c.image)?;
        stage.artifact_path = PROBE.into();
        stage.artifact_sha256 = digest.into();
        stage.artifact_size = size;
        stage.execution_policy_sha256 = Some(kernel::policy_digest());
        // Exact same protected staging decoder as admission; synthetic kind is
        // unavailable outside cfg(test), no production feature or bypass flag.
        let probe_file = allocation.exits[exit].state_dir.join("staging.json");
        lab::write(
            &probe_file,
            &serde_json::to_vec(&stage).map_err(|_| Error::InvalidSpec)?,
        )?;
        let spec_file = allocation.exits[exit].state_dir.join("spec.json");
        lab::write(
            &spec_file,
            &serde_json::to_vec(&spec).map_err(|_| Error::InvalidSpec)?,
        )?;
        Admission::inspect_evidence(
            LaunchSpec::load(&spec_file)?,
            StagingEvidence::load_probe(&probe_file)?,
        )
        .await
    });
    drop(rt);
    process::single_threaded()?;
    result
}
pub(super) fn inspect_actual(
    id: &str,
    allocation: &AllocationRecord,
    image: &str,
) -> Result<Admission> {
    inspect_actual_member(id, allocation, image, 0)
}
pub(super) fn inspect_actual_member(
    id: &str,
    allocation: &AllocationRecord,
    image: &str,
    member: usize,
) -> Result<Admission> {
    let bundle = super::programs::ReviewedBundle::current()?;
    let (digest, size) = bundle.init()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| Error::UnsupportedPlatform)?;
    let result = rt.block_on(async {
        let c = DockerClient::default()
            .launch_container(id)
            .await
            .map_err(|_| Error::DockerUnavailable)?;
        if c.image != image {
            return Err(Error::ImageMismatch);
        }
        let (mut spec, mut stage) = tests::fixture();
        spec.allocation = allocation.clone();
        spec.exit = allocation
            .exits
            .get(member)
            .ok_or(Error::AllocationMismatch)?
            .clone();
        spec.container_id = id.into();
        spec.started_at = lab::public_started_at(&c.state.started_at)?;
        spec.image_ref = format!("vprouter-v2-lab@{image}");
        spec.worker_sha256 = digest.into();
        spec.process_start_time = process::stat_start(
            &fs::read_to_string(format!("/proc/{}/stat", c.state.pid))
                .map_err(|_| Error::ProcessUnavailable)?,
            c.state.pid,
        )?;
        stage.image_ref = spec.image_ref.clone();
        stage.content_id = image.into();
        stage.artifact_kind = "actual_gateway_lab_v1".into();
        stage.artifact_path =
            format!("/var/lib/vprouter-v2-lab/task8b2-{digest}.gateway-init").into();
        stage.artifact_sha256 = digest.into();
        stage.artifact_size = size;
        stage.execution_policy_sha256 = None;
        Admission::inspect_evidence(spec, stage).await
    });
    drop(rt);
    process::single_threaded()?;
    result
}
fn container_pids(id: &str) -> Result<Vec<u32>> {
    let path = format!("/sys/fs/cgroup/system.slice/docker-{id}.scope/cgroup.procs");
    fs::read_to_string(path)
        .map_err(|_| Error::CgroupMismatch)?
        .lines()
        .map(|s| s.parse().map_err(|_| Error::CgroupMismatch))
        .collect()
}
fn workers(id: &str) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    for pid in container_pids(id)? {
        let s = fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|_| Error::ProcessUnavailable)?;
        let n = s
            .lines()
            .find_map(|s| s.strip_prefix("NSpid:"))
            .ok_or(Error::NamespaceMismatch)?
            .split_whitespace()
            .collect::<Vec<_>>();
        if n.len() == 3 && n[2] == "2" {
            out.push(pid);
        }
    }
    Ok(out)
}
fn verify_worker(a: &Admission, pid: u32, data: &owned::OwnedNamespaces) -> Result<()> {
    a.process.verify_placement(pid, &a.spec)?;
    let actual_state =
        fs::metadata(format!("/proc/{pid}/root/state")).map_err(|_| Error::MountIsolation)?;
    let selected_state =
        fs::metadata(a.spec.exit.state_dir.join("worker")).map_err(|_| Error::MountIsolation)?;
    if (actual_state.dev(), actual_state.ino()) != (selected_state.dev(), selected_state.ino()) {
        return Err(Error::MountIsolation);
    }
    let mountinfo =
        fs::read_to_string(format!("/proc/{pid}/mountinfo")).map_err(|_| Error::MountIsolation)?;
    for (path, readonly) in [
        ("/", true),
        ("/bin/vprouter-worker", true),
        ("/state", false),
    ] {
        let fields = mountinfo
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .find(|fields| fields.get(4) == Some(&path))
            .ok_or(Error::MountIsolation)?;
        let flags = fields.get(5).ok_or(Error::MountIsolation)?;
        if flags.split(',').any(|flag| flag == "ro") != readonly
            || flags.split(',').any(|flag| flag == "rw") == readonly
        {
            return Err(Error::MountIsolation);
        }
    }
    let net = fs::metadata(format!("/proc/{pid}/ns/net")).map_err(|_| Error::NamespaceMismatch)?;
    if (owned::Identity {
        dev: net.dev(),
        ino: net.ino(),
    }) != owned::Identity::network(&data.data)?
    {
        return Err(Error::NamespaceMismatch);
    }
    kernel::verify_pid_parent(pid, a.process.launch_fds().pid)?;
    let s =
        fs::read_to_string(format!("/proc/{pid}/status")).map_err(|_| Error::ProcessUnavailable)?;
    let init = s
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse::<u32>().ok())
        .ok_or(Error::NamespaceMismatch)?;
    let init_status = fs::read_to_string(format!("/proc/{init}/status"))
        .map_err(|_| Error::ProcessUnavailable)?;
    let init_ids = init_status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .ok_or(Error::NamespaceMismatch)?
        .split_whitespace()
        .collect::<Vec<_>>();
    if init_ids.len() != 3 || init_ids[2] != "1" {
        return Err(Error::NamespaceMismatch);
    }
    for component in ["root", "ns/mnt", "ns/pid"] {
        let worker =
            fs::metadata(format!("/proc/{pid}/{component}")).map_err(|_| Error::MountIsolation)?;
        let supervisor =
            fs::metadata(format!("/proc/{init}/{component}")).map_err(|_| Error::MountIsolation)?;
        if (worker.dev(), worker.ino()) != (supervisor.dev(), supervisor.ino()) {
            return Err(Error::MountIsolation);
        }
    }
    if !s
        .lines()
        .any(|l| l.starts_with("Uid:") && l.split_whitespace().skip(1).all(|s| s == "65534"))
        || !s.contains("NoNewPrivs:\t1")
        || !s.contains("Seccomp:\t2")
    {
        return Err(Error::CapabilityPolicy);
    }
    let lsm = fs::read_to_string(format!("/proc/{pid}/attr/current"))
        .map_err(|_| Error::ConfinementPolicy)?;
    if lsm.trim() != "docker-default (enforce)" {
        return Err(Error::ConfinementPolicy);
    }
    let mut fds = fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|_| Error::DescriptorPolicy)?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| Error::DescriptorPolicy)?;
    fds.sort();
    if fds != ["0", "1", "2", "3"] {
        return Err(Error::DescriptorPolicy);
    }
    Ok(())
}
fn verify_launch_tree(id: &str) -> Result<()> {
    let pids = container_pids(id)?;
    let mut wrappers = 0;
    let mut mount_views = std::collections::BTreeSet::new();
    let mut root_views = std::collections::BTreeSet::new();
    for pid in pids {
        let base = PathBuf::from(format!("/proc/{pid}"));
        let status =
            fs::read_to_string(base.join("status")).map_err(|_| Error::ProcessUnavailable)?;
        let ids: Vec<_> = status
            .lines()
            .find_map(|s| s.strip_prefix("NSpid:"))
            .ok_or(Error::NamespaceMismatch)?
            .split_whitespace()
            .collect();
        if ids.len() == 2 && ids[1] == "1" {
            continue;
        } // admitted container init
        if ids.len() < 3 || ids.len() == 3 && ids[2] == "1" {
            let mount = fs::metadata(base.join("ns/mnt")).map_err(|_| Error::MountIsolation)?;
            let root = fs::metadata(base.join("root")).map_err(|_| Error::MountIsolation)?;
            if !mount_views.insert((mount.dev(), mount.ino()))
                || !root_views.insert((root.dev(), root.ino()))
            {
                return Err(Error::MountIsolation);
            }
        }
        for key in ["Uid:", "Gid:"] {
            if !status
                .lines()
                .find_map(|s| s.strip_prefix(key))
                .is_some_and(|s| s.split_whitespace().eq(["65534"; 4]))
            {
                return Err(Error::CapabilityPolicy);
            }
        }
        if !status
            .lines()
            .find_map(|s| s.strip_prefix("Groups:"))
            .is_some_and(|s| s.trim().is_empty())
        {
            return Err(Error::CapabilityPolicy);
        }
        for key in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
            if status
                .lines()
                .find_map(|s| s.strip_prefix(key))
                .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
                != Some(0)
            {
                return Err(Error::CapabilityPolicy);
            }
        }
        if !status.contains("NoNewPrivs:\t1") || !status.contains("Seccomp:\t2") {
            return Err(Error::ConfinementPolicy);
        }
        if fs::read_to_string(base.join("attr/current"))
            .map_err(|_| Error::ConfinementPolicy)?
            .trim()
            != "docker-default (enforce)"
        {
            return Err(Error::ConfinementPolicy);
        }
        let mut fds = fs::read_dir(base.join("fd"))
            .map_err(|_| Error::DescriptorPolicy)?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| Error::DescriptorPolicy)?;
        fds.sort();
        for fd in 0..3 {
            let dev =
                fs::metadata(base.join(format!("fd/{fd}"))).map_err(|_| Error::DescriptorPolicy)?;
            if !std::os::unix::fs::FileTypeExt::is_char_device(&dev.file_type())
                || rustix::fs::major(dev.rdev()) != 1
                || rustix::fs::minor(dev.rdev()) != 3
            {
                return Err(Error::DescriptorStdio);
            }
        }
        if ids.len() < 3 {
            wrappers += 1;
            if fds != ["0", "1", "2", "3"]
                || fs::read_link(base.join("fd/3")).map_err(|_| Error::DescriptorPolicy)?
                    != Path::new("anon_inode:[pidfd]")
            {
                return Err(Error::DescriptorPolicy);
            }
            for fd in 0..4 {
                let info = fs::read_to_string(base.join(format!("fdinfo/{fd}")))
                    .map_err(|_| Error::DescriptorFlags)?;
                let flags = info
                    .lines()
                    .find_map(|s| s.strip_prefix("flags:"))
                    .and_then(|s| u32::from_str_radix(s.trim(), 8).ok())
                    .ok_or(Error::DescriptorFlags)?;
                if (flags & libc::O_CLOEXEC as u32 != 0) != (fd == 3) {
                    return Err(Error::DescriptorFlags);
                }
            }
            let root = fs::metadata(base.join("root")).map_err(|_| Error::MountIsolation)?;
            let cwd = fs::metadata(base.join("cwd")).map_err(|_| Error::MountIsolation)?;
            if (root.dev(), root.ino()) != (cwd.dev(), cwd.ino())
                || fs::read_dir(base.join("root"))
                    .map_err(|_| Error::MountIsolation)?
                    .next()
                    .is_some()
            {
                return Err(Error::MountIsolation);
            }
            let mounts =
                fs::read_to_string(base.join("mountinfo")).map_err(|_| Error::MountIsolation)?;
            let lines: Vec<_> = mounts.lines().collect();
            let fields: Vec<_> = lines
                .first()
                .ok_or(Error::MountIsolation)?
                .split_whitespace()
                .collect();
            if lines.len() != 1
                || fields.get(4) != Some(&"/")
                || !fields
                    .get(5)
                    .is_some_and(|s| s.split(',').any(|f| f == "ro"))
                || !lines[0].contains(" - tmpfs ")
            {
                return Err(Error::MountIsolation);
            }
        } else if fds != ["0", "1", "2"] && fds != ["0", "1", "2", "3"] {
            return Err(Error::DescriptorPolicy);
        }
    }
    if wrappers != 4 || mount_views.len() != 6 || root_views.len() != 6 {
        return Err(Error::ChildFailed);
    }
    Ok(())
}
fn wait_absent(pids: &[u32]) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(4);
    loop {
        let mut absent = true;
        for pid in pids {
            match fs::metadata(format!("/proc/{pid}")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => absent = false,
                Err(_) => return Err(Error::ChildFailed),
            }
        }
        if absent {
            return Ok(());
        }
        if Instant::now() > end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(30));
    }
}
fn prove_frozen_descendants(id: &str, workers: &[u32]) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(1);
    loop {
        let mut stopped_parents = std::collections::BTreeSet::new();
        for pid in container_pids(id)? {
            let status = fs::read_to_string(format!("/proc/{pid}/status"))
                .map_err(|_| Error::ProcessUnavailable)?;
            let parent = status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .and_then(|value| value.trim().parse::<u32>().ok())
                .ok_or(Error::ProcessUnavailable)?;
            if !workers.contains(&parent) {
                continue;
            }
            let ids = status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .ok_or(Error::NamespaceMismatch)?
                .split_whitespace()
                .collect::<Vec<_>>();
            if ids.len() != 3 || ids[2] != "3" {
                return Err(Error::NamespaceMismatch);
            }
            if status
                .lines()
                .find_map(|line| line.strip_prefix("State:"))
                .and_then(|state| state.split_whitespace().next())
                == Some("T")
                && !stopped_parents.insert(parent)
            {
                return Err(Error::ChildFailed);
            }
        }
        if stopped_parents.len() == workers.len() {
            return Ok(());
        }
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn state_witness(path: &Path, expected: &[u8]) -> Result<bool> {
    match fs::read(path) {
        Ok(bytes) if bytes == expected => Ok(true),
        // Creation and the one small write are separate syscalls. An empty
        // transient file is not evidence and remains subject to the same bound.
        Ok(bytes) if bytes.is_empty() => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        _ => Err(Error::ChildFailed),
    }
}
fn signal_and_wait_naturally(
    one: &mut execution::Running,
    two: &mut execution::Running,
    record: &AllocationRecord,
) -> Result<()> {
    let start = Instant::now();
    let mut done = [false; 2];
    let mut forwarded = false;
    let mut iteration = 0;
    loop {
        // Every signal goes through the actual outer/intermediate/PID1 chain.
        // Keep delivering faster than every grace period until natural exit.
        let signal = if !forwarded {
            libc::SIGTERM
        } else {
            [libc::SIGTERM, libc::SIGINT, libc::SIGHUP][iteration % 3]
        };
        for (index, child) in [&mut *one, &mut *two].into_iter().enumerate() {
            if !done[index] {
                done[index] = child.try_wait_success()?;
                if !done[index]
                    && let Err(error) = child.signal(signal)
                {
                    if child.try_wait_success()? {
                        done[index] = true;
                    } else {
                        return Err(error);
                    }
                }
            }
        }
        forwarded = record
            .exits
            .iter()
            .map(|exit| state_witness(&exit.state_dir.join("worker/forwarded-signal"), b"TERM"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .all(|seen| seen);
        if start.elapsed() >= Duration::from_secs(2) {
            return Err(Error::Deadline);
        }
        if done == [true, true] {
            if !forwarded {
                return Err(Error::ChildFailed);
            }
            for exit in &record.exits {
                if !state_witness(&exit.state_dir.join("worker/reaped-descendant"), b"reaped")? {
                    return Err(Error::ChildFailed);
                }
            }
            eprintln!(
                "LAB_SIGNAL_PROOF stopped_forwarded_reaped_natural repeated_signals elapsed_ms={}",
                start.elapsed().as_millis()
            );
            return Ok(());
        }
        iteration += 1;
        std::thread::sleep(Duration::from_millis(25));
    }
}
pub fn run() -> Result<()> {
    lab::admit_lab()?;
    lab::stage("execution_lab_admitted_owned_guest");
    let dir = PathBuf::from(format!(
        "/var/lib/vprouter-v2-lab/task6b-{}",
        std::process::id()
    ));
    private(&dir)?;
    let mut resources = Resources {
        id: String::new(),
        dir: dir.clone(),
    };
    let record = allocation(&dir)?;
    for exit in &record.exits {
        private(&exit.state_dir)?;
        let p = exit.state_dir.join("worker");
        private(&p)?;
        let fd = owned::directory(&p)?;
        rustix::fs::fchown(
            &fd,
            Some(rustix::process::Uid::from_raw(65534)),
            Some(rustix::process::Gid::from_raw(65534)),
        )
        .map_err(|_| Error::UnsafeInput)?;
    }
    let records = dir.join("records");
    private(&records)?;
    let store = AllocationStore::open(&records, "launchlab").map_err(|_| Error::UnsafeInput)?;
    store
        .lock()
        .map_err(|_| Error::LockBusy)?
        .commit(None, &record)
        .map_err(|_| Error::AllocationMismatch)?;
    let bytes = vprouter_linux::storage::read(
        Path::new(PROBE),
        vprouter_linux::storage::Kind::PublicFile,
        super::spec::LIMIT,
    )
    .map_err(|_| Error::UnsafeInput)?;
    let digest = vprouter_linux::sha256(&bytes);
    let bind = format!("{PROBE}:{}:ro", super::spec::WORKER);
    let out = lab::docker(&[
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
        lab::IMAGE,
        "--test-probe-container",
    ])?;
    let id = String::from_utf8(out)
        .map_err(|_| Error::DockerUnavailable)?
        .trim()
        .to_string();
    if !super::spec::digest(&id) {
        return Err(Error::DockerUnavailable);
    }
    resources.id = id.clone();
    let one = inspect(&id, &record, 0, &digest, bytes.len() as u64)?;
    let two = inspect(&id, &record, 1, &digest, bytes.len() as u64)?;
    let mut tx = owned::Transaction::open(
        &store,
        &records,
        &one.spec,
        "one",
        one.process.base_network(),
    )?;
    let first = tx.acquire(&one.spec, one.process.base_network())?;
    if tx.for_exit(&one.spec).err() != Some(Error::LockBusy) {
        return Err(Error::OwnershipMismatch);
    }
    let mut second_tx = tx.for_exit(&two.spec)?;
    let second = second_tx.acquire(&two.spec, two.process.base_network())?;
    // A live second exit shares the same journal and does not reacquire flock.
    // The external allocation store must remain excluded while either lives.
    if store.lock().is_ok() {
        return Err(Error::LockBusy);
    }
    if tx.acquire(&two.spec, two.process.base_network()).err() != Some(Error::OwnershipMismatch) {
        return Err(Error::OwnershipMismatch);
    }
    lab::case("shared_deployment_journal_unique_exit_leases_external_flock_retained");
    if owned::Identity::network(&first.data)?
        != owned::Identity::network(one.process.base_network())?
        || owned::Identity::network(&first.data)? == owned::Identity::network(&second.data)?
    {
        return Err(Error::NamespaceMismatch);
    }
    lab::case("owned_generation_locked_primary_base_and_independent_extra_namespaces");
    if execution::launch(&one, &tx, &second, execution::VerifiedProgram::probe(&one)?).err()
        != Some(Error::NamespaceMismatch)
    {
        return Err(Error::NamespaceMismatch);
    }
    lab::case("wrong_selected_exit_namespace_token_executes_nothing");
    for kind in 0..3 {
        let directory = if kind == 0 {
            Some(fs::File::open("/").map_err(|_| Error::DescriptorPolicy)?)
        } else {
            None
        };
        let peer = if kind == 1 {
            Some(rustix::io::dup(&second.data).map_err(|_| Error::DescriptorPolicy)?)
        } else {
            None
        };
        let socket = if kind == 2 {
            Some(std::os::unix::net::UnixStream::pair().map_err(|_| Error::DescriptorPolicy)?)
        } else {
            None
        };
        if execution::launch(&one, &tx, &first, execution::VerifiedProgram::probe(&one)?).err()
            != Some(Error::DescriptorPolicy)
        {
            return Err(Error::DescriptorPolicy);
        }
        drop((directory, peer, socket));
    }
    lab::case("unexpected_host_directory_peer_namespace_socket_execute_nothing");
    if execution::lab_failed_placement(&one, &tx, &first).err() != Some(Error::PlacementFailed)
        || container_pids(&id)?.len() != 1
    {
        return Err(Error::PlacementFailed);
    }
    for exit in &record.exits {
        match fs::metadata(exit.state_dir.join("worker/probe")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(Error::PlacementFailed),
        }
    }
    lab::case("killed_placement_gated_child_never_released_or_executed");
    lab::stage("launch_first_private_probe");
    let mut running_one =
        execution::launch(&one, &tx, &first, execution::VerifiedProgram::probe(&one)?)?;
    lab::stage("launch_second_private_probe");
    let mut running_two = execution::launch(
        &two,
        &second_tx,
        &second,
        execution::VerifiedProgram::probe(&two)?,
    )?;
    let pids = workers(&id)?;
    if pids.len() != 2 {
        return Err(Error::NamespaceMismatch);
    }
    for pid in &pids {
        let net =
            fs::metadata(format!("/proc/{pid}/ns/net")).map_err(|_| Error::NamespaceMismatch)?;
        if (net.dev(), net.ino())
            == (
                owned::Identity::network(&first.data)?.dev,
                owned::Identity::network(&first.data)?.ino,
            )
        {
            verify_worker(&one, *pid, &first)?;
        } else {
            verify_worker(&two, *pid, &second)?;
        }
    }
    let root_one =
        fs::metadata(format!("/proc/{}/root", pids[0])).map_err(|_| Error::MountIsolation)?;
    let root_two =
        fs::metadata(format!("/proc/{}/root", pids[1])).map_err(|_| Error::MountIsolation)?;
    if (root_one.dev(), root_one.ino()) == (root_two.dev(), root_two.ino()) {
        return Err(Error::MountIsolation);
    }
    for exit in &record.exits {
        if fs::read(exit.state_dir.join("worker/probe")).map_err(|_| Error::MountIsolation)?
            != b"selected-exit-only"
        {
            return Err(Error::MountIsolation);
        }
    }
    lab::case("actual_cgroup_nested_pid_proc_private_root_state_fd_cap_seccomp_apparmor");
    lab::case("post_exec_adversarial_proc_root_and_two_exit_state_isolation");
    verify_launch_tree(&id)?;
    lab::case("all_surviving_wrappers_empty_ro_roots_cwd_exact_pidfd_null_caps_lsm_seccomp");
    let old = container_pids(&id)?;
    prove_frozen_descendants(&id, &pids)?;
    // On failure Child::drop remains emergency cleanup. No terminate/SIGKILL
    // from the harness is permitted before successful natural completion proof.
    signal_and_wait_naturally(&mut running_one, &mut running_two, &record)?;
    let after = container_pids(&id)?;
    if after.len() != 1 {
        return Err(Error::ChildFailed);
    }
    wait_absent(
        &old.into_iter()
            .filter(|p| !after.contains(p))
            .collect::<Vec<_>>(),
    )?;
    lab::case("signal_forwarding_pid1_reaping_frozen_descendants");
    lab::stage("parent_loss_kills_actual_launch_tree");
    let lost = kernel::lab_parent_loss(&one, &tx, &first)?;
    let tree = container_pids(&id)?;
    lost.terminate()?;
    wait_absent(
        &tree
            .into_iter()
            .filter(|p| !after.contains(p))
            .collect::<Vec<_>>(),
    )?;
    if container_pids(&id)?.len() != 1 {
        return Err(Error::ChildFailed);
    }
    lab::case("launcher_parent_death_kills_and_reaps_namespace_descendants");
    lab::stage("container_death_kills_actual_launch_tree");
    let final_run = execution::launch(&one, &tx, &first, execution::VerifiedProgram::probe(&one)?)?;
    let all = container_pids(&id)?;
    // Fixed test-only command. Docker kill must include host-launched cgroup tasks.
    lab::docker(&["kill", &id])?;
    final_run.terminate()?;
    wait_absent(&all)?;
    lab::case("container_death_kills_all_launch_children");
    drop(first);
    drop(second);
    drop(one);
    drop(two);
    drop(second_tx);
    // Test-only exact-record cleanup, only after the cgroup's processes are gone.
    lab::stage("cleanup_exact_namespace_pins");
    tx.lab_unpin()?;
    drop(tx);
    drop(store);
    lab::stage("cleanup_exact_container");
    lab::docker(&["rm", "--force", &id])?;
    resources.id.clear();
    lab::stage("cleanup_exact_synthetic_directory");
    fs::remove_dir_all(&resources.dir).map_err(|_| Error::OwnershipMismatch)?;
    println!(
        "{{\"case\":\"launch_execution_isolated_acceptance\",\"result\":\"pass\",\"guard_runtime\":false,\"activation\":false}}"
    );
    Ok(())
}

/// Fixed producer-placement kernel oracle only. No usable transport, daemon,
/// actual observer worker, enrollment or production readiness is created.
pub fn run_producer() -> Result<()> {
    use std::os::fd::AsFd;
    lab::admit_lab()?;
    let own = fs::metadata("/proc/self/ns/net").map_err(|_| Error::LabRequired)?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Marker {
        artifact_sha256: String,
        network_dev: u64,
        network_ino: u64,
    }
    let marker: Marker = serde_json::from_slice(
        &vprouter_linux::storage::read(
            Path::new("/var/lib/vprouter-v2-lab/task8b1-producer-acceptance"),
            vprouter_linux::storage::Kind::SecretFile,
            4096,
        )
        .map_err(|_| Error::LabRequired)?,
    )
    .map_err(|_| Error::LabRequired)?;
    let exe = fs::read(std::env::current_exe().map_err(|_| Error::LabRequired)?)
        .map_err(|_| Error::LabRequired)?;
    if marker.artifact_sha256 != vprouter_linux::sha256(&exe)
        || (marker.network_dev, marker.network_ino) != (own.dev(), own.ino())
    {
        return Err(Error::LabRequired);
    }
    lab::stage("producer_exact_hash_owned_guest_admitted");
    let dir = PathBuf::from(format!(
        "/var/lib/vprouter-v2-lab/task8b1-{}",
        std::process::id()
    ));
    private(&dir)?;
    let mut resources = Resources {
        id: String::new(),
        dir: dir.clone(),
    };
    let record = allocation(&dir)?;
    for exit in &record.exits {
        private(&exit.state_dir)?;
        let path = exit.state_dir.join("worker");
        private(&path)?;
        let fd = owned::directory(&path)?;
        rustix::fs::fchown(
            &fd,
            Some(rustix::process::Uid::from_raw(65534)),
            Some(rustix::process::Gid::from_raw(65534)),
        )
        .map_err(|_| Error::UnsafeInput)?;
    }
    let records = dir.join("records");
    private(&records)?;
    let store =
        AllocationStore::open(&records, "launchlab").map_err(|_| Error::OwnershipMismatch)?;
    store
        .lock()
        .map_err(|_| Error::LockBusy)?
        .commit(None, &record)
        .map_err(|_| Error::AllocationMismatch)?;
    let bytes = vprouter_linux::storage::read(
        Path::new(PROBE),
        vprouter_linux::storage::Kind::PublicFile,
        super::spec::LIMIT,
    )
    .map_err(|_| Error::UnsafeInput)?;
    let digest = vprouter_linux::sha256(&bytes);
    let bind = format!("{PROBE}:{}:ro", super::spec::WORKER);
    let id = String::from_utf8(lab::docker(&[
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
        lab::IMAGE,
        "--test-probe-container",
    ])?)
    .map_err(|_| Error::DockerUnavailable)?
    .trim()
    .to_string();
    if !super::spec::digest(&id) {
        return Err(Error::DockerUnavailable);
    }
    resources.id = id.clone();
    lab::write(&dir.join("resources.json"), &serde_json::to_vec(&serde_json::json!({"container":id,"records":records,"allocation":record,"transport_created":false,"observer_executed":false})).map_err(|_| Error::InvalidSpec)?)?;
    let a = inspect(&id, &record, 0, &digest, bytes.len() as u64)?;
    let mut tx =
        owned::Transaction::open(&store, &records, &a.spec, "one", a.process.base_network())?;
    let ns = tx.acquire(&a.spec, a.process.base_network())?;
    let other = inspect(&id, &record, 1, &digest, bytes.len() as u64)?;
    let mut other_tx = tx.for_exit(&other.spec)?;
    let other_ns = other_tx.acquire(&other.spec, other.process.base_network())?;
    tx.begin_transport(&a.spec, &ns)?;
    let producer = super::producer::ProducerGroup::create(&a, &ns, &mut tx)?;
    let parent_path = format!("/sys/fs/cgroup/system.slice/docker-{id}.scope");
    let group_path = format!(
        "{parent_path}/{}",
        vprouter_netfilter::SocketProducer::group_name(&record, &record.exits[0])
    );
    let parent_pids = fs::read_to_string(format!("{parent_path}/cgroup.procs"))
        .map_err(|_| Error::CgroupMismatch)?;
    let controls: Vec<_> = ["cgroup.subtree_control", "cpu.max", "memory.max"]
        .into_iter()
        .map(|n| {
            fs::read_to_string(format!("{parent_path}/{n}"))
                .map(|s| (n, s))
                .map_err(|_| Error::CgroupMismatch)
        })
        .collect::<Result<_>>()?;
    let killed = execution::lab_producer(&a, &tx, &ns, &producer, true).err();
    if killed != Some(Error::PlacementFailed) {
        eprintln!("LAB_PRODUCER_UNEXPECTED killed_gated={killed:?}");
        return Err(Error::PlacementFailed);
    }
    if fs::metadata(a.spec.exit.state_dir.join("worker/probe")).is_ok() {
        return Err(Error::PlacementFailed);
    }
    lab::case("producer_killed_gated_child_never_released_or_executes");
    if execution::lab_producer(&a, &tx, &other_ns, &producer, false).err()
        != Some(Error::NamespaceMismatch)
    {
        return Err(Error::NamespaceMismatch);
    }
    lab::case("producer_wrong_exit_namespace_refuses_before_fork_and_exec");
    let mut running = execution::lab_producer(&a, &tx, &ns, &producer, false)?;
    let pids: Vec<u32> = fs::read_to_string(format!("{group_path}/cgroup.procs"))
        .map_err(|_| Error::CgroupMismatch)?
        .lines()
        .map(|s| s.parse().map_err(|_| Error::CgroupMismatch))
        .collect::<Result<_>>()?;
    if pids.len() != 5 || !pids.contains(&running.pid()) {
        return Err(Error::PlacementFailed);
    }
    let mut workers = 0;
    for pid in &pids {
        producer.verify_child(*pid, &tx, &a.spec)?;
        let status = fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|_| Error::ProcessUnavailable)?;
        let nspid: Vec<_> = status
            .lines()
            .find_map(|l| l.strip_prefix("NSpid:"))
            .ok_or(Error::NamespaceMismatch)?
            .split_whitespace()
            .collect();
        if nspid.len() == 3 && nspid[2] == "2" {
            workers += 1;
            let state = fs::metadata(format!("/proc/{pid}/root/state"))
                .map_err(|_| Error::MountIsolation)?;
            let selected = fs::metadata(a.spec.exit.state_dir.join("worker"))
                .map_err(|_| Error::MountIsolation)?;
            if (state.dev(), state.ino()) != (selected.dev(), selected.ino()) {
                return Err(Error::MountIsolation);
            }
            let net = fs::metadata(format!("/proc/{pid}/ns/net"))
                .map_err(|_| Error::NamespaceMismatch)?;
            let expected = owned::Identity::network(ns.data.as_fd())?;
            if (net.dev(), net.ino()) != (expected.dev, expected.ino) {
                return Err(Error::NamespaceMismatch);
            }
        }
    }
    if workers != 1
        || fs::read_to_string(format!("{parent_path}/cgroup.procs"))
            .map_err(|_| Error::CgroupMismatch)?
            != parent_pids
    {
        return Err(Error::PlacementFailed);
    }
    lab::case("producer_exact_subgroup_pre_exec_four_roles_frozen_descendant_private_worker_state");
    running.signal(libc::SIGTERM)?;
    let end = Instant::now() + Duration::from_secs(4);
    while !running.try_wait_success()? {
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(running);
    if !fs::read_to_string(format!("{group_path}/cgroup.procs"))
        .map_err(|_| Error::CgroupMismatch)?
        .trim()
        .is_empty()
    {
        return Err(Error::PlacementFailed);
    }
    for (name, before) in controls {
        if fs::read_to_string(format!("{parent_path}/{name}")).map_err(|_| Error::CgroupMismatch)?
            != before
        {
            return Err(Error::CgroupMismatch);
        }
    }
    lab::case("producer_bounded_signal_reap_empty_group_parent_controls_unchanged");
    producer.cleanup(&tx, &a.spec)?;
    if fs::metadata(&group_path).is_ok() {
        return Err(Error::OwnershipMismatch);
    }
    tx.transport_cleaned(&a.spec)?;
    lab::case("producer_normal_owned_group_cleanup_offline_record");
    tx.begin_transport(&a.spec, &ns)?;
    let producer = super::producer::ProducerGroup::create(&a, &ns, &mut tx)?;
    let running = execution::lab_producer(&a, &tx, &ns, &producer, false)?;
    let death_pids: Vec<u32> = fs::read_to_string(format!("{group_path}/cgroup.procs"))
        .map_err(|_| Error::CgroupMismatch)?
        .lines()
        .map(|s| s.parse().map_err(|_| Error::CgroupMismatch))
        .collect::<Result<_>>()?;
    lab::docker(&["kill", &id])?;
    running.terminate()?;
    let end = Instant::now() + Duration::from_secs(4);
    for pid in death_pids {
        loop {
            match fs::metadata(format!("/proc/{pid}")) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Ok(_) if Instant::now() < end => std::thread::sleep(Duration::from_millis(10)),
                _ => return Err(Error::ChildFailed),
            }
        }
    }
    lab::case("producer_container_death_all_confined_roles_gone_bounded_reap");
    drop(other_tx);
    let retained = if producer.cleanup(&tx, &a.spec).is_ok() {
        tx.transport_cleaned(&a.spec)?;
        drop(ns);
        drop(other_ns);
        tx.lab_unpin()?;
        false
    } else {
        // Docker may remove its parent cgroup on death. Never manufacture a
        // replacement cgroup to satisfy cleanup; retain durable Activating pins.
        drop(ns);
        drop(other_ns);
        drop(tx);
        let mut reopened =
            owned::Transaction::open(&store, &records, &a.spec, "one", a.process.base_network())?;
        if !matches!(
            reopened.acquire(&a.spec, a.process.base_network()),
            Err(Error::Interrupted)
        ) {
            return Err(Error::OwnershipMismatch);
        }
        lab::case("producer_container_cgroup_loss_retains_intent_and_refuses_adoption");
        true
    };
    lab::docker(&["rm", "--force", &id])?;
    resources.id.clear();
    eprintln!("LAB_PRODUCER_CLEANUP interrupted_pins_retained={retained}");
    lab::write(&dir.join("result.json"), b"{\"result\":\"pass_partial_producer_placement\",\"actual_observer_execution\":\"NOT_RUN\",\"go_execution\":\"NOT_RUN\",\"production_readiness\":false}\n")?;
    lab::case("producer_exact_owned_cleanup_terminal_acceptance");
    Ok(())
}
