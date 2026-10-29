#![forbid(unsafe_code)]
//! Native service-manager placement for exact, still-gated lifecycle children.
//! No public path/PID constructor, and no scope kill or cleanup on Drop.
use super::owned::Identity;
use super::{Error, Result};
use rustix::fs::{self, FileType, Mode, OFlags};
use std::{
    fs::File,
    io::Read,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Guard,
    ExpiryHost,
    ExpiryTransport,
    ExpiryData,
}
impl Role {
    fn suffix(self) -> &'static str {
        match self {
            Self::Guard => "guard",
            Self::ExpiryHost => "expiry-host",
            Self::ExpiryTransport => "expiry-transport",
            Self::ExpiryData => "expiry-data",
        }
    }
}
/// Durable evidence of the original preplacement domain. Deserializing this
/// record never grants a native capability or permits adopting its processes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OwnerDomainRecord {
    pub(super) boot: String,
    pub(super) unit: String,
    pub(super) invocation: String,
    pub(super) pid: u32,
    pub(super) start: u64,
    pub(super) cgroup: Identity,
}
impl OwnerDomainRecord {
    pub(super) fn validate(&self, domains: &Domains) -> Result<()> {
        if self.unit != domains.owner_unit()
            || self.pid <= 1
            || self.start == 0
            || self.cgroup.ino == 0
            || !uuid(&self.boot)
            || self.invocation.len() != 32
            || !self
                .invocation
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || self.invocation.bytes().all(|c| c == b'0')
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
/// Captured once before servicing members; retained, creator-only, and never
/// constructed from the durable record. Every use rechecks native identity.
pub(super) struct OwnerDomain {
    record: OwnerDomainRecord,
    namespaces: [Identity; 4],
    group: OwnedFd,
    _inventory: super::inventory::Registration,
}
impl OwnerDomain {
    pub(super) fn capture(domains: &Domains) -> Result<Self> {
        domains.verify_owner()?;
        let (pid, start) = super::kernel::current_process_identity()?;
        let namespaces = host_namespace_identities()?;
        let unit = domains.owner_unit();
        let pinned = group(&unit)?;
        // Nested manager calls inspect the complete native inventory. Retain
        // this trusted pin before any such call or other fallible preparation.
        let inventory = super::inventory::Registration::owned(&[pinned.as_fd()])?;
        let cgroup = Identity::of(&pinned)?;
        let boot = boot_id()?;
        let requested = unit.clone();
        let invocation = manager(|connection| {
            Box::pin(async move {
                let path = unit_path(connection, &requested).await?;
                let invocation: Vec<u8> = property(
                    connection,
                    &path,
                    "org.freedesktop.systemd1.Unit",
                    "InvocationID",
                )
                .await?;
                let main: u32 = property(
                    connection,
                    &path,
                    "org.freedesktop.systemd1.Service",
                    "MainPID",
                )
                .await?;
                if invocation.len() != 16 || main != pid {
                    return Err(Error::OwnershipMismatch);
                }
                Ok(invocation
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>())
            })
        })?;
        let value = Self {
            record: OwnerDomainRecord {
                boot,
                unit,
                invocation,
                pid,
                start,
                cgroup,
            },
            namespaces,
            group: pinned,
            _inventory: inventory,
        };
        value.verify(domains)?;
        Ok(value)
    }
    pub(super) fn verify(&self, domains: &Domains) -> Result<()> {
        super::process::host_preflight()?;
        self.record.validate(domains)?;
        if host_namespace_identities()? != self.namespaces {
            return Err(Error::NamespaceMismatch);
        }
        if super::kernel::current_process_identity()? != (self.record.pid, self.record.start)
            || boot_id()? != self.record.boot
            || Identity::of(&self.group)? != self.record.cgroup
            || Identity::of(group(&self.record.unit)?)? != self.record.cgroup
            || std::fs::read_to_string("/proc/self/cgroup").map_err(|_| Error::CgroupMismatch)?
                != format!("0::/system.slice/{}\n", self.record.unit)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(super) fn record(&self, domains: &Domains) -> Result<OwnerDomainRecord> {
        self.verify(domains)?;
        Ok(self.record.clone())
    }
}
fn host_namespace_identities() -> Result<[Identity; 4]> {
    let mut identities = Vec::new();
    for name in ["mnt", "net", "user", "pid"] {
        let current = fs::open(
            format!("/proc/self/ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        let host = fs::open(
            format!("/proc/1/ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::NamespaceMismatch)?;
        let identity = Identity::network(current)?;
        if identity != Identity::network(host)? {
            return Err(Error::NamespaceMismatch);
        }
        identities.push(identity);
    }
    identities.try_into().map_err(|_| Error::NamespaceMismatch)
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}
fn boot_id() -> Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| Error::OwnershipMismatch)?;
    let value = value.strip_suffix('\n').ok_or(Error::OwnershipMismatch)?;
    if !uuid(value) {
        return Err(Error::OwnershipMismatch);
    }
    Ok(value.to_owned())
}
#[derive(Clone)]
pub(super) struct Domains {
    deployment: String,
    allocation: String,
    exit_id: String,
    lifecycle: String,
}
impl Domains {
    pub(super) fn from_record(
        allocation: &vprouter_core::allocation::AllocationRecord,
        exit_id: &str,
        lifecycle: &str,
    ) -> Result<Self> {
        if !super::spec::digest(lifecycle)
            || !allocation
                .exits
                .iter()
                .any(|entry| entry.exit_id == exit_id)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(Self {
            deployment: allocation.deployment_id.clone(),
            allocation: vprouter_worker::bootstrap::digest(
                &serde_json::to_vec(allocation).map_err(|_| Error::OwnershipMismatch)?,
            ),
            exit_id: exit_id.into(),
            lifecycle: lifecycle.into(),
        })
    }
    pub fn new(spec: &super::LaunchSpec, lifecycle: &str) -> Result<Self> {
        spec.validate()?;
        if !super::spec::digest(lifecycle) {
            return Err(Error::InvalidSpec);
        }
        Ok(Self {
            deployment: spec.allocation.deployment_id.clone(),
            exit_id: spec.exit.exit_id.clone(),
            allocation: vprouter_worker::bootstrap::digest(
                &serde_json::to_vec(&spec.allocation).map_err(|_| Error::InvalidSpec)?,
            ),
            lifecycle: lifecycle.into(),
        })
    }
    pub fn owner_unit(&self) -> String {
        // Owner identity survives allocation generations; each guard request
        // and sibling scope still binds its complete immutable allocation.
        let identity = vprouter_worker::bootstrap::digest(
            format!("vprouter-v2-deployment-owner-v1:{}", self.deployment).as_bytes(),
        );
        format!("vprouter-v2-owner@{identity}.service")
    }
    pub fn exit_id(&self) -> &str {
        &self.exit_id
    }
    pub fn allocation(&self) -> &str {
        &self.allocation
    }
    pub fn lifecycle(&self) -> &str {
        &self.lifecycle
    }
    pub fn verify_guard(&self) -> Result<()> {
        super::process::guard_preflight()?;
        if std::fs::read_to_string("/proc/self/cgroup").map_err(|_| Error::CgroupMismatch)?
            != format!("0::/system.slice/{}\n", self.unit(Role::Guard))
        {
            return Err(Error::CgroupMismatch);
        }
        group(&self.unit(Role::Guard))?;
        Ok(())
    }
    pub fn unit(&self, role: Role) -> String {
        format!(
            "vprouter-v2-{}-{}-{}.scope",
            self.allocation,
            self.lifecycle,
            role.suffix()
        )
    }
    fn membership(&self, role: Role, pid: u32, cgroup: &str, members: &str) -> Result<()> {
        if pid <= 1
            || cgroup != format!("0::/system.slice/{}\n", self.unit(role))
            || members != format!("{pid}\n")
        {
            return Err(Error::CgroupMismatch);
        }
        Ok(())
    }
    /// Requires the fixed owner service in the real host mount/network namespace.
    /// These checks precede namespace pins and every lifecycle fork.
    pub fn verify_owner(&self) -> Result<()> {
        super::process::host_preflight()?;
        if std::fs::read_to_string("/proc/1/comm").map_err(|_| Error::UnsupportedPlatform)?
            != "systemd\n"
            || std::fs::read_to_string("/proc/self/cgroup").map_err(|_| Error::CgroupMismatch)?
                != format!("0::/system.slice/{}\n", self.owner_unit())
        {
            return Err(Error::UnsupportedPlatform);
        }
        for ns in ["mnt", "net", "user", "pid"] {
            let a = fs::open(
                format!("/proc/self/ns/{ns}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::NamespaceMismatch)?;
            let b = fs::open(
                format!("/proc/1/ns/{ns}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::NamespaceMismatch)?;
            if Identity::network(a)? != Identity::network(b)? {
                return Err(Error::NamespaceMismatch);
            }
        }
        let unit = self.owner_unit();
        manager(|connection| {
            Box::pin(async move {
                let path = unit_path(connection, &unit).await?;
                let group: String = property(
                    connection,
                    &path,
                    "org.freedesktop.systemd1.Service",
                    "ControlGroup",
                )
                .await?;
                let pid: u32 = property(
                    connection,
                    &path,
                    "org.freedesktop.systemd1.Service",
                    "MainPID",
                )
                .await?;
                let kill: String = property(
                    connection,
                    &path,
                    "org.freedesktop.systemd1.Service",
                    "KillMode",
                )
                .await?;
                if group != format!("/system.slice/{unit}")
                    || pid != std::process::id()
                    || kill != "control-group"
                {
                    return Err(Error::CgroupMismatch);
                }
                Ok(())
            })
        })
    }
    /// Only an exact retained fork child may be submitted to PID1. The child is
    /// still behind its private release gate; a successful D-Bus reply is never
    /// sufficient without independent native cgroup membership readback.
    pub fn place(&self, child: &super::kernel::Survivor, role: Role) -> Result<Scope> {
        let mut scope = None;
        self.place_retained(child, role, &mut scope)?;
        scope.ok_or(Error::CgroupMismatch)
    }
    pub(super) fn place_retained(
        &self,
        child: &super::kernel::Survivor,
        role: Role,
        retained: &mut Option<Scope>,
    ) -> Result<()> {
        if retained.is_some() {
            return Err(Error::OwnershipMismatch);
        }

        child.require_live()?;
        #[cfg(test)]
        let pid = child.pid();
        let start = child.start_time()?;
        let unit = self.unit(role);
        #[cfg(test)]
        eprintln!(
            "LAB_GUARD_SCOPE_INTENT {}",
            serde_json::json!({"unit":unit,"lifecycle":self.lifecycle,"exit_id":self.exit_id,"role":role.suffix(),"allocation_digest":self.allocation,"pid":pid,"start_time":start})
        );
        let requested = unit.clone();
        // PID1 receives the kernel process reference, not a numeric PID that
        // could be reused after a cancelled asynchronous placement. Unsupported
        // managers fail closed; there is deliberately no PIDs fallback.
        let pidfd = std::rc::Rc::new(
            child
                .pidfd()
                .try_clone_to_owned()
                .map_err(|_| Error::DescriptorDuplicate)?,
        );
        let _pidfd_inventory = super::inventory::Registration::owned(&[pidfd.as_ref().as_fd()])?;
        let request_pidfd = std::rc::Rc::clone(&pidfd);
        manager(move |connection| {
            Box::pin(async move {
                let unit = requested;
                use zbus::{OwnedObjectPath, Variant as Value};
                let properties = transient_scope_properties(request_pidfd.as_ref().as_fd());
                let auxiliary: Vec<(&str, Vec<(&str, Value<'_>)>)> = Vec::new();
                let _: OwnedObjectPath = connection
                    .call_method(
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit",
                        &(&unit, "fail", properties, auxiliary),
                    )
                    .await
                    .map_err(|_| Error::CgroupMismatch)?
                    .body()
                    .deserialize()
                    .map_err(|_| Error::CgroupMismatch)?;
                let path = unit_path(connection, &unit).await?;
                // StartTransientUnit returns a job, not completed placement.
                // Keep this inside the SAME original manager deadline.
                loop {
                    let state: String = property(
                        connection,
                        &path,
                        "org.freedesktop.systemd1.Unit",
                        "ActiveState",
                    )
                    .await?;
                    if state == "active" {
                        break;
                    }
                    if state == "failed" {
                        return Err(Error::CgroupMismatch);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let unit_properties =
                    all_properties(connection, &path, "org.freedesktop.systemd1.Unit").await?;
                let scope_properties =
                    all_properties(connection, &path, "org.freedesktop.systemd1.Scope").await?;
                verify_scope_properties(&unit, unit_properties, scope_properties)
            })
        })?;
        child.require_live()?;
        if child.start_time()? != start {
            return Err(Error::ProcessChanged);
        }
        let group = group(&unit)?;
        let identity = Identity::of(&group)?;
        *retained = Some(Scope {
            creator: std::process::id(),
            group,
            identity,
            unit,
            role,
            domains: self.clone(),
            _inventory: None,
            population: None,
        });
        let scope = retained.as_mut().ok_or(Error::CgroupMismatch)?;
        scope._inventory = Some(super::inventory::Registration::owned(&[scope
            .group
            .as_fd()])?);
        scope.verify(child)?;
        scope.capture_population(child)
    }
}

fn transient_scope_properties(
    pidfd: std::os::fd::BorrowedFd<'_>,
) -> Vec<(&'static str, zbus::Variant<'_>)> {
    use zbus::Variant as Value;
    vec![
        ("Description", Value::from("vprouter-v2 isolated lifecycle")),
        ("PIDFDs", Value::from(vec![zbus::Fd::from(pidfd)])),
        ("Slice", Value::from("system.slice")),
        ("Delegate", Value::from(false)),
        ("KillMode", Value::from("control-group")),
        ("KillSignal", Value::from(libc::SIGKILL)),
        ("TimeoutStopUSec", Value::from(2_000_000u64)),
        ("SendSIGHUP", Value::from(false)),
        ("SendSIGKILL", Value::from(true)),
    ]
}

pub(super) fn verify_executor(
    domains: &Domains,
    identity: &super::owned::ExecutorIdentity,
) -> Result<()> {
    pin_executor(domains, identity).map(|_| ())
}
pub(super) fn pin_executor(
    domains: &Domains,
    identity: &super::owned::ExecutorIdentity,
) -> Result<(super::kernel::Survivor, Scope)> {
    let role = match identity.scope {
        0 => Role::ExpiryHost,
        1 => Role::ExpiryTransport,
        2 => Role::ExpiryData,
        _ => return Err(Error::OwnershipMismatch),
    };
    let child = super::kernel::pin_recorded_executor(identity)?;
    let ns = fs::open(
        format!("/proc/{}/ns/net", identity.pid),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::NamespaceMismatch)?;
    if Identity::network(ns)? != identity.namespace {
        return Err(Error::NamespaceMismatch);
    }
    let unit = domains.unit(role);
    let group = group(&unit)?;
    let stat = Identity::of(&group)?;
    let inventory = super::inventory::Registration::owned(&[group.as_fd()])?;
    let scope = Scope {
        creator: std::process::id(),
        group,
        identity: stat,
        unit,
        role,
        domains: domains.clone(),
        _inventory: Some(inventory),
        population: None,
    };
    scope.verify(&child)?;
    Ok((child, scope))
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlacementReceipt {
    identity: Identity,
    unit: String,
}
impl Domains {
    pub(super) fn complete_placement(
        &self,
        child: &super::kernel::Survivor,
        role: Role,
        receipt: PlacementReceipt,
    ) -> Result<Scope> {
        let mut retained = None;
        self.complete_placement_retained(child, role, receipt, &mut retained)?;
        retained.ok_or(Error::CgroupMismatch)
    }
    pub(super) fn complete_placement_retained(
        &self,
        child: &super::kernel::Survivor,
        role: Role,
        receipt: PlacementReceipt,
        retained: &mut Option<Scope>,
    ) -> Result<()> {
        if retained.is_some() || receipt.unit != self.unit(role) {
            return Err(Error::CgroupMismatch);
        }
        let group = group(&receipt.unit)?;
        if Identity::of(&group)? != receipt.identity {
            return Err(Error::CgroupMismatch);
        }
        *retained = Some(Scope {
            creator: std::process::id(),
            group,
            identity: receipt.identity,
            unit: receipt.unit,
            role,
            domains: self.clone(),
            _inventory: None,
            population: None,
        });
        let scope = retained.as_mut().ok_or(Error::CgroupMismatch)?;
        scope._inventory = Some(super::inventory::Registration::owned(&[scope
            .group
            .as_fd()])?);
        scope.verify(child)?;
        scope.capture_population(child)
    }
}
/// Exact retained scope population, never a cleanup/reuse capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ScopePopulation {
    Populated,
    LiveEmpty,
    RemovedOriginal,
}
#[derive(Debug, PartialEq, Eq)]
enum OriginalPopulation {
    Live(ScopePopulation),
    Offline,
}
#[cfg(test)]
struct PopulationTrace {
    scope: u8,
    group: Identity,
    phase: &'static str,
    values: std::collections::BTreeMap<String, serde_json::Value>,
    success: bool,
}
#[cfg(test)]
thread_local! {
    static POPULATION_TRACE: std::cell::RefCell<Option<PopulationTrace>> = const { std::cell::RefCell::new(None) };
    static POPULATION_TRACE_COUNT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
struct PopulationTraceGuard {
    active: bool,
}
#[cfg(test)]
impl PopulationTraceGuard {
    fn new(scope: &Scope) -> Self {
        // A copied foreign Scope must fail its original creator predicate without
        // touching diagnostic TLS or emitting from a confined child.
        if scope.creator != std::process::id() {
            return Self { active: false };
        }
        POPULATION_TRACE.with(|trace| {
            *trace.borrow_mut() = Some(PopulationTrace {
                scope: match scope.role {
                    Role::Guard => 3,
                    Role::ExpiryHost => 0,
                    Role::ExpiryTransport => 1,
                    Role::ExpiryData => 2,
                },
                group: scope.identity,
                phase: "begin",
                values: Default::default(),
                success: false,
            })
        });
        Self { active: true }
    }
    fn success(&self) {
        if !self.active {
            return;
        }
        POPULATION_TRACE.with(|trace| {
            if let Some(trace) = trace.borrow_mut().as_mut() {
                trace.success = true;
            }
        });
    }
}
#[cfg(test)]
impl Drop for PopulationTraceGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let trace = POPULATION_TRACE.with(|trace| trace.borrow_mut().take());
        if let Some(trace) = trace
            && !trace.success
            && POPULATION_TRACE_COUNT.with(|count| {
                let before = count.get();
                count.set(before.saturating_add(1));
                before < 4
            })
        {
            eprintln!(
                "LAB_SCOPE_POPULATION_FAILURE {}",
                serde_json::json!({"scope":trace.scope,"group":trace.group,"phase":trace.phase,"observations":trace.values})
            );
        }
    }
}
#[cfg(test)]
fn population_phase(phase: &'static str) {
    POPULATION_TRACE.with(|trace| {
        if let Some(trace) = trace.borrow_mut().as_mut() {
            trace.phase = phase;
        }
    });
}
#[cfg(test)]
fn population_value(name: &'static str, value: impl Into<serde_json::Value>) {
    POPULATION_TRACE.with(|trace| {
        if let Some(trace) = trace.borrow_mut().as_mut()
            && trace.values.len() < 48
        {
            trace
                .values
                .insert(format!("{}:{name}", trace.phase), value.into());
        }
    });
}
#[cfg(test)]
fn population_error(error: rustix::io::Errno) {
    population_value("errno", error.raw_os_error());
}
fn original_population(
    events: std::result::Result<String, rustix::io::Errno>,
    procs: std::result::Result<String, rustix::io::Errno>,
) -> Result<OriginalPopulation> {
    match (events, procs) {
        (Ok(events), Ok(procs)) => {
            let values: Vec<_> = events
                .lines()
                .filter_map(|s| s.strip_prefix("populated "))
                .collect();
            match values.as_slice() {
                ["0"] if procs.is_empty() => {
                    Ok(OriginalPopulation::Live(ScopePopulation::LiveEmpty))
                }
                ["1"] => Ok(OriginalPopulation::Live(ScopePopulation::Populated)),
                _ => Err(Error::CgroupMismatch),
            }
        }
        (Err(rustix::io::Errno::NODEV), Err(rustix::io::Errno::NODEV)) => {
            Ok(OriginalPopulation::Offline)
        }
        _ => Err(Error::CgroupMismatch),
    }
}
fn require_absent(value: std::result::Result<OwnedFd, rustix::io::Errno>) -> Result<()> {
    #[cfg(test)]
    population_value(
        "open_errno",
        value.as_ref().err().map(|error| error.raw_os_error()),
    );
    match value {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        _ => Err(Error::CgroupMismatch),
    }
}
fn require_fd_target(fd: &OwnedFd, expected: &str) -> Result<()> {
    let target =
        fs::readlink(format!("/proc/self/fd/{}", fd.as_raw_fd()), Vec::new()).map_err(|error| {
            #[cfg(test)]
            population_error(error);
            #[cfg(not(test))]
            let _ = error;
            Error::CgroupMismatch
        })?;
    #[cfg(test)]
    {
        population_value("target_matches", target.as_bytes() == expected.as_bytes());
        let live = expected.strip_suffix(" (deleted)").unwrap_or(expected);
        population_value(
            "target_matches_generated_live",
            target.as_bytes() == live.as_bytes(),
        );
        population_value(
            "target_matches_generated_deleted",
            target.as_bytes() == format!("{live} (deleted)").as_bytes(),
        );
    }
    if target.as_bytes() != expected.as_bytes() {
        return Err(Error::CgroupMismatch);
    }
    Ok(())
}
fn removed_scope_contract() -> Result<bool> {
    // Bound to the characterized distribution/kernel contract. Other kernels
    // retain offline scopes until their native/source contract is verified.
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_err(|_| Error::UnsupportedPlatform)?;
    Ok(matches!(
        release.trim_end_matches('\n'),
        "6.12.113+deb13-cloud-amd64" | "6.12.113+deb13-cloud-arm64" | "7.2.9-arch1-1"
    ))
}
#[derive(Default)]
struct PopulationPins {
    parent: Option<PopulationPin>,
    events: Option<PopulationPin>,
    procs: Option<PopulationPin>,
}
struct PopulationPin {
    fd: OwnedFd,
    identity: Option<Identity>,
    mode: Option<u32>,
    inventory: Option<super::inventory::Registration>,
}
impl PopulationPin {
    fn capture(slot: &mut Option<Self>, fd: OwnedFd) -> Result<()> {
        if slot.is_some() {
            return Err(Error::CgroupMismatch);
        }
        *slot = Some(Self {
            fd,
            identity: None,
            mode: None,
            inventory: None,
        });
        let pin = slot.as_mut().ok_or(Error::CgroupMismatch)?;
        pin.inventory = Some(super::inventory::Registration::owned(&[pin.fd.as_fd()])?);
        pin.identity = Some(Identity::of(&pin.fd)?);
        pin.mode = Some(
            fs::fstat(&pin.fd)
                .map_err(|_| Error::CgroupMismatch)?
                .st_mode,
        );
        Ok(())
    }
    fn verify(&self, directory: bool) -> Result<()> {
        let stat = fs::fstat(&self.fd).map_err(|error| {
            #[cfg(test)]
            population_error(error);
            #[cfg(not(test))]
            let _ = error;
            Error::CgroupMismatch
        })?;
        #[cfg(test)]
        {
            population_value(
                "stored_identity_matches",
                self.identity
                    == Some(Identity {
                        dev: stat.st_dev,
                        ino: stat.st_ino,
                    }),
            );
            population_value("stored_mode_matches", self.mode == Some(stat.st_mode));
        }
        if !self.inventory.as_ref().is_some_and(|i| {
            let present = i.contains(self.fd.as_fd());
            #[cfg(test)]
            population_value("token_native_matches", present);
            present
        }) || Some(Identity::of(&self.fd)?) != self.identity
            || Some(stat.st_mode) != self.mode
            || fs::fstatfs(&self.fd)
                .inspect(|value| {
                    #[cfg(test)]
                    population_value("fstype", value.f_type as u64);
                    #[cfg(not(test))]
                    let _ = value;
                })
                .map_err(|error| {
                    #[cfg(test)]
                    population_error(error);
                    #[cfg(not(test))]
                    let _ = error;
                    Error::CgroupMismatch
                })?
                .f_type as u64
                != 0x63677270
            || stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_mode & 0o022 != 0
            || FileType::from_raw_mode(stat.st_mode)
                != if directory {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                }
        {
            return Err(Error::CgroupMismatch);
        }
        Ok(())
    }
}
impl PopulationPins {
    fn verify(&self, group: Identity) -> Result<()> {
        let parent = self.parent.as_ref().ok_or(Error::CgroupMismatch)?;
        #[cfg(test)]
        population_phase("parent_pin");
        parent.verify(true)?;
        #[cfg(test)]
        population_phase("parent_current");
        if Some(Identity::of(group_parent()?)?) != parent.identity {
            return Err(Error::CgroupMismatch);
        }
        let events = self.events.as_ref().ok_or(Error::CgroupMismatch)?;
        let procs = self.procs.as_ref().ok_or(Error::CgroupMismatch)?;
        #[cfg(test)]
        population_phase("events_pin");
        events.verify(false)?;
        #[cfg(test)]
        population_phase("procs_pin");
        procs.verify(false)?;
        #[cfg(test)]
        population_phase("pin_relationships");
        let identities = [parent.identity, events.identity, procs.identity];
        if identities
            .iter()
            .any(|id| id.is_none_or(|id| id.dev != group.dev || id == group))
            || events.identity == procs.identity
        {
            return Err(Error::CgroupMismatch);
        }
        Ok(())
    }
    fn require_targets(&self, unit: &str, removed: bool) -> Result<()> {
        #[cfg(test)]
        {
            population_phase("parent_target");
            population_value("removed", removed);
        }
        require_fd_target(
            &self.parent.as_ref().ok_or(Error::CgroupMismatch)?.fd,
            "/sys/fs/cgroup/system.slice",
        )?;
        let suffix = if removed { " (deleted)" } else { "" };
        for (pin, name) in [
            (&self.events, "cgroup.events"),
            (&self.procs, "cgroup.procs"),
        ] {
            #[cfg(test)]
            population_phase(if name == "cgroup.events" {
                "events_target"
            } else {
                "procs_target"
            });
            require_fd_target(
                &pin.as_ref().ok_or(Error::CgroupMismatch)?.fd,
                &format!("/sys/fs/cgroup/system.slice/{unit}/{name}{suffix}"),
            )?;
        }
        Ok(())
    }
}
fn read_population(
    pin: &PopulationPin,
    limit: usize,
) -> std::result::Result<String, rustix::io::Errno> {
    let mut bytes = vec![0; limit + 1];
    let n = rustix::io::pread(&pin.fd, &mut bytes, 0).inspect_err(|error| {
        #[cfg(test)]
        population_value(
            if limit == 4096 {
                "events_pread_errno"
            } else {
                "procs_pread_errno"
            },
            error.raw_os_error(),
        );
        #[cfg(not(test))]
        let _ = error;
    })?;
    #[cfg(test)]
    {
        population_value(
            if limit == 4096 {
                "events_pread_len"
            } else {
                "procs_pread_len"
            },
            n as u64,
        );
        population_value(
            if limit == 4096 {
                "events_pread_errno"
            } else {
                "procs_pread_errno"
            },
            0,
        );
    }
    if n > limit {
        return Err(rustix::io::Errno::OVERFLOW);
    }
    bytes.truncate(n);
    String::from_utf8(bytes).map_err(|_| rustix::io::Errno::ILSEQ)
}
fn group_parent() -> Result<OwnedFd> {
    let root = fs::open(
        "/sys/fs/cgroup",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::CgroupMismatch)?;
    fs::openat2(
        root,
        "system.slice",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        fs::ResolveFlags::BENEATH | fs::ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| Error::CgroupMismatch)
}
pub(super) struct Scope {
    creator: u32,
    group: OwnedFd,
    identity: Identity,
    unit: String,
    role: Role,
    domains: Domains,
    _inventory: Option<super::inventory::Registration>,
    population: Option<PopulationPins>,
}
impl Scope {
    /// No-live-userspace observation only. Root actual waitpid, producer, expiry,
    /// journal and canonical retirement are independent requirements.
    pub(super) fn population(&self) -> Result<ScopePopulation> {
        #[cfg(test)]
        let trace = PopulationTraceGuard::new(self);
        #[cfg(test)]
        if trace.active {
            population_phase("group_pin");
        }
        self.require_pin()?;
        let pins = self.population.as_ref().ok_or(Error::CgroupMismatch)?;
        pins.verify(self.identity)?;
        let events = pins.events.as_ref().ok_or(Error::CgroupMismatch)?;
        let procs = pins.procs.as_ref().ok_or(Error::CgroupMismatch)?;
        #[cfg(test)]
        population_phase("first_population_pair");
        let observed =
            original_population(read_population(events, 4096), read_population(procs, 65536))?;
        match observed {
            OriginalPopulation::Live(value) => {
                // A same-name replacement is never an original object's proof.
                #[cfg(test)]
                {
                    population_phase("live_name");
                    population_value("population", format!("{value:?}"));
                }
                if Identity::of(group(&self.unit)?)? != self.identity {
                    return Err(Error::CgroupMismatch);
                }
                pins.require_targets(&self.unit, false)?;
                #[cfg(test)]
                population_phase("live_group_recheck");
                self.require_pin()?;
                pins.verify(self.identity)?;
                #[cfg(test)]
                trace.success();
                Ok(value)
            }
            OriginalPopulation::Offline => {
                #[cfg(test)]
                population_phase("offline_contract");
                if !removed_scope_contract()? {
                    return Err(Error::UnsupportedPlatform);
                }
                let parent = pins.parent.as_ref().ok_or(Error::CgroupMismatch)?;
                for name in ["cgroup.events", "cgroup.procs"] {
                    #[cfg(test)]
                    population_phase(if name == "cgroup.events" {
                        "offline_events_open"
                    } else {
                        "offline_procs_open"
                    });
                    require_absent(fs::openat(
                        &self.group,
                        name,
                        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    ))?;
                }
                // On the characterized Debian kernfs, retained file dentries
                // can keep their live spelling after both original reads return
                // NODEV. Revalidate BOTH children through the original directory
                // before requiring their deleted targets. All original-object
                // predicates, including the second NODEV pair, remain required.
                pins.require_targets(&self.unit, true)?;
                #[cfg(test)]
                population_phase("offline_name_absence");
                require_absent(fs::openat(
                    &parent.fd,
                    self.unit.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                ))?;
                let expected = format!("/sys/fs/cgroup/system.slice/{} (deleted)", self.unit);
                #[cfg(test)]
                population_phase("offline_group_target");
                require_fd_target(&self.group, &expected)?;
                // Re-read BOTH original files at offset zero after the directory
                // checks. EOF, missing new opens, or names alone cannot grant it.
                #[cfg(test)]
                population_phase("second_population_pair");
                if !matches!(
                    original_population(
                        read_population(events, 4096),
                        read_population(procs, 65536)
                    )?,
                    OriginalPopulation::Offline
                ) {
                    return Err(Error::CgroupMismatch);
                }
                #[cfg(test)]
                population_phase("offline_group_recheck");
                self.require_pin()?;
                pins.verify(self.identity)?;
                pins.require_targets(&self.unit, true)?;
                #[cfg(test)]
                population_phase("offline_final_group_target");
                require_fd_target(&self.group, &expected)?;
                #[cfg(test)]
                population_phase("offline_final_name_absence");
                require_absent(fs::openat(
                    &parent.fd,
                    self.unit.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                ))?;
                #[cfg(test)]
                trace.success();
                Ok(ScopePopulation::RemovedOriginal)
            }
        }
    }
    pub(super) fn quiescent(&self) -> Result<bool> {
        Ok(matches!(
            self.population()?,
            ScopePopulation::LiveEmpty | ScopePopulation::RemovedOriginal
        ))
    }
    fn capture_population(&mut self, child: &super::kernel::Survivor) -> Result<()> {
        self.verify(child)?;
        if self.population.is_some() {
            return Err(Error::CgroupMismatch);
        }
        // Store partial captures before fallible registration/verification. The
        // surrounding constructor retains this Scope on every failure.
        self.population = Some(PopulationPins::default());
        let pins = self.population.as_mut().ok_or(Error::CgroupMismatch)?;
        PopulationPin::capture(&mut pins.parent, group_parent()?)?;
        for (slot, name) in [
            (&mut pins.events, "cgroup.events"),
            (&mut pins.procs, "cgroup.procs"),
        ] {
            let fd = fs::openat(
                &self.group,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| Error::CgroupMismatch)?;
            PopulationPin::capture(slot, fd)?;
        }
        pins.verify(self.identity)?;
        pins.require_targets(&self.unit, false)?;
        self.verify(child)
    }
    fn require_pin(&self) -> Result<()> {
        if self.creator != std::process::id()
            || !self._inventory.as_ref().is_some_and(|i| {
                let present = i.contains(self.group.as_fd());
                #[cfg(test)]
                population_value("token_native_matches", present);
                present
            })
            || Identity::of(&self.group)? != self.identity
            || fs::fstatfs(&self.group)
                .map_err(|_| Error::CgroupMismatch)?
                .f_type as u64
                != 0x63677270
        {
            return Err(Error::CgroupMismatch);
        }
        let stat = fs::fstat(&self.group).map_err(|_| Error::CgroupMismatch)?;
        if stat.st_uid != 0
            || stat.st_gid != 0
            || stat.st_mode & 0o022 != 0
            || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        {
            return Err(Error::CgroupMismatch);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn lab_require_inert(&self) -> Result<()> {
        self._inventory
            .as_ref()
            .ok_or(Error::DescriptorInventory)?
            .lab_require_inert()
    }
    pub(super) fn retained_identity(&self) -> Result<Identity> {
        self.require_pin()?;
        Ok(self.identity)
    }
    pub(super) fn retained_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.group.as_fd()
    }
    pub(super) fn registered(&self) -> bool {
        self._inventory.is_some()
    }
    pub(super) fn receipt(&self) -> PlacementReceipt {
        PlacementReceipt {
            identity: self.identity,
            unit: self.unit.clone(),
        }
    }
    pub fn verify(&self, child: &super::kernel::Survivor) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        child.require_live()?;
        if Identity::of(&self.group)? != self.identity
            || Identity::of(group(&self.unit)?)? != self.identity
        {
            return Err(Error::CgroupMismatch);
        }
        let fd = fs::openat(
            &self.group,
            "cgroup.procs",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::CgroupMismatch)?;
        let mut members = String::new();
        File::from(fd)
            .take(65537)
            .read_to_string(&mut members)
            .map_err(|_| Error::CgroupMismatch)?;
        let current = std::fs::read_to_string(format!("/proc/{}/cgroup", child.pid()))
            .map_err(|_| Error::CgroupMismatch)?;
        self.domains
            .membership(self.role, child.pid(), &current, &members)?;
        child.require_live()
    }
}
fn group(unit: &str) -> Result<OwnedFd> {
    let root = fs::open(
        "/sys/fs/cgroup",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        #[cfg(test)]
        population_error(error);
        #[cfg(not(test))]
        let _ = error;
        Error::CgroupMismatch
    })?;
    if fs::fstatfs(&root)
        .map_err(|error| {
            #[cfg(test)]
            population_error(error);
            #[cfg(not(test))]
            let _ = error;
            Error::CgroupMismatch
        })?
        .f_type as u64
        != 0x63677270
    {
        return Err(Error::CgroupMismatch);
    }
    let group = fs::openat2(
        root,
        format!("system.slice/{unit}"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        fs::ResolveFlags::BENEATH | fs::ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| {
        #[cfg(test)]
        population_error(error);
        #[cfg(not(test))]
        let _ = error;
        Error::CgroupMismatch
    })?;
    let stat = fs::fstat(&group).map_err(|error| {
        #[cfg(test)]
        population_error(error);
        #[cfg(not(test))]
        let _ = error;
        Error::CgroupMismatch
    })?;
    if stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o022 != 0
        || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
    {
        return Err(Error::CgroupMismatch);
    }
    Ok(group)
}
// The protected root-owned endpoint may be socket-activated by PID1; its peer
// credentials identify the listener creator, not the eventual bus dispatcher.
// Resolve the manager's unique connection and authenticate that connection's
// bus credentials separately. Never address a mutable well-known name for work.
struct Manager<'a> {
    connection: &'a zbus::Connection,
    owner: zbus::names::OwnedUniqueName,
}
impl Manager<'_> {
    async fn call_method<B: serde::Serialize + zbus::wire::DynamicType>(
        &self,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
    ) -> Result<zbus::Message> {
        let reply = self
            .connection
            .call_method(
                Some(self.owner.as_str()),
                path,
                Some(interface),
                method,
                body,
            )
            .await
            .map_err(|_| Error::CgroupMismatch)?;
        if reply.header().sender().map(|name| name.as_str()) != Some(self.owner.as_str()) {
            return Err(Error::ProcessChanged);
        }
        Ok(reply)
    }
}
async fn bus_method<B: serde::Serialize + zbus::wire::DynamicType>(
    connection: &zbus::Connection,
    method: &str,
    body: &B,
) -> Result<zbus::Message> {
    let reply = connection
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            method,
            body,
        )
        .await
        .map_err(|_| Error::UnsupportedPlatform)?;
    if reply.header().sender().map(|name| name.as_str()) != Some("org.freedesktop.DBus") {
        return Err(Error::ProcessChanged);
    }
    Ok(reply)
}
fn manager_credentials(credentials: &zbus::fdo::ConnectionCredentials) -> Result<()> {
    if credentials.process_id() != Some(1) || credentials.unix_user_id() != Some(0) {
        return Err(Error::ProcessChanged);
    }
    Ok(())
}
async fn systemd_owner(connection: &zbus::Connection) -> Result<zbus::names::OwnedUniqueName> {
    let owner: zbus::names::OwnedUniqueName =
        bus_method(connection, "GetNameOwner", &("org.freedesktop.systemd1",))
            .await?
            .body()
            .deserialize()
            .map_err(|_| Error::ProcessChanged)?;
    let credentials: zbus::fdo::ConnectionCredentials =
        bus_method(connection, "GetConnectionCredentials", &(owner.as_str(),))
            .await?
            .body()
            .deserialize()
            .map_err(|_| Error::ProcessChanged)?;
    manager_credentials(&credentials)?;
    Ok(owner)
}
type ManagerFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + 'a>>;
fn manager<T>(call: impl for<'a> FnOnce(&'a Manager<'a>) -> ManagerFuture<'a, T>) -> Result<T> {
    super::process::single_threaded()?;
    super::inventory::verify()?;
    let end = std::time::Instant::now() + Duration::from_secs(2);
    let result = {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| Error::UnsupportedPlatform)?;
        runtime.block_on(async {
            tokio::time::timeout_at(tokio::time::Instant::from_std(end), async {
                let before = vprouter_linux::storage::metadata(
                    std::path::Path::new("/run/dbus/system_bus_socket"),
                    vprouter_linux::storage::Kind::DockerSocket,
                )
                .map_err(|_| Error::UnsafeInput)?;
                let stream = tokio::net::UnixStream::connect("/run/dbus/system_bus_socket")
                    .await
                    .map_err(|_| Error::UnsupportedPlatform)?;
                let peer = stream.peer_cred().map_err(|_| Error::UnsupportedPlatform)?;
                let after = vprouter_linux::storage::metadata(
                    std::path::Path::new("/run/dbus/system_bus_socket"),
                    vprouter_linux::storage::Kind::DockerSocket,
                )
                .map_err(|_| Error::UnsafeInput)?;
                if (before.device, before.inode) != (after.device, after.inode)
                    || peer.pid() != Some(1)
                    || peer.uid() != 0
                    || peer.gid() != 0
                {
                    return Err(Error::UnsupportedPlatform);
                }
                let connection = zbus::connection::Builder::unix_stream(
                    stream.into_std().map_err(|_| Error::UnsupportedPlatform)?,
                )
                .build()
                .await
                .map_err(|_| Error::UnsupportedPlatform)?;
                let owner = systemd_owner(&connection).await?;
                let manager = Manager {
                    connection: &connection,
                    owner,
                };
                let result = call(&manager).await;
                let current = systemd_owner(&connection).await?;
                if current != manager.owner {
                    return Err(Error::ProcessChanged);
                }
                let final_endpoint = vprouter_linux::storage::metadata(
                    std::path::Path::new("/run/dbus/system_bus_socket"),
                    vprouter_linux::storage::Kind::DockerSocket,
                )
                .map_err(|_| Error::UnsafeInput)?;
                if (before.device, before.inode) != (final_endpoint.device, final_endpoint.inode) {
                    return Err(Error::ProcessChanged);
                }
                connection
                    .close()
                    .await
                    .map_err(|_| Error::UnsupportedPlatform)?;
                result
            })
            .await
            .unwrap_or(Err(Error::Deadline))
        })
    };
    super::process::single_threaded()?;
    super::inventory::verify()?;
    if std::time::Instant::now() >= end {
        return Err(Error::Deadline);
    }
    result
}
async fn unit_path(connection: &Manager<'_>, unit: &str) -> Result<zbus::wire::OwnedObjectPath> {
    connection
        .call_method(
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "GetUnit",
            &(unit,),
        )
        .await
        .map_err(|_| Error::CgroupMismatch)?
        .body()
        .deserialize()
        .map_err(|_| Error::CgroupMismatch)
}
type Properties = std::collections::HashMap<String, zbus::OwnedVariant>;
async fn all_properties(
    connection: &Manager<'_>,
    path: &zbus::OwnedObjectPath,
    interface: &str,
) -> Result<Properties> {
    connection
        .call_method(
            path.as_str(),
            "org.freedesktop.DBus.Properties",
            "GetAll",
            &(interface,),
        )
        .await?
        .body()
        .deserialize()
        .map_err(|_| Error::CgroupMismatch)
}
fn required<T: TryFrom<zbus::OwnedVariant>>(properties: &mut Properties, name: &str) -> Result<T> {
    properties
        .remove(name)
        .ok_or(Error::CgroupMismatch)?
        .try_into()
        .map_err(|_| Error::CgroupMismatch)
}
fn verify_scope_properties(
    unit: &str,
    mut common: Properties,
    mut scope: Properties,
) -> Result<()> {
    let group: String = required(&mut scope, "ControlGroup")?;
    let id: String = required(&mut common, "Id")?;
    let transient: bool = required(&mut common, "Transient")?;
    let bound: Vec<String> = required(&mut common, "BindsTo")?;
    let part: Vec<String> = required(&mut common, "PartOf")?;
    let kill_mode: String = required(&mut scope, "KillMode")?;
    let kill_signal: i32 = required(&mut scope, "KillSignal")?;
    let stop_usec: u64 = required(&mut scope, "TimeoutStopUSec")?;
    let send_hup: bool = required(&mut scope, "SendSIGHUP")?;
    let delegate: bool = required(&mut scope, "Delegate")?;
    let slice: String = required(&mut scope, "Slice")?;
    let send_kill: bool = required(&mut scope, "SendSIGKILL")?;
    if group != format!("/system.slice/{unit}")
        || id != unit
        || !transient
        || !bound.is_empty()
        || !part.is_empty()
        || kill_mode != "control-group"
        || kill_signal != libc::SIGKILL
        || stop_usec != 2_000_000
        || send_hup
        || delegate
        || slice != "system.slice"
        || !send_kill
    {
        return Err(Error::CgroupMismatch);
    }
    #[cfg(test)]
    eprintln!(
        "LAB_SCOPE_POLICY_READBACK {}",
        serde_json::json!({
            "Id":id, "ControlGroup":group, "Transient":transient, "BindsTo":bound, "PartOf":part,
            "KillMode":kill_mode, "KillSignal":kill_signal, "TimeoutStopUSec":stop_usec,
            "SendSIGHUP":send_hup, "Delegate":delegate, "Slice":slice, "SendSIGKILL":send_kill,
        })
    );
    Ok(())
}
async fn property<T>(
    connection: &Manager<'_>,
    path: &zbus::wire::OwnedObjectPath,
    interface: &str,
    name: &str,
) -> Result<T>
where
    T: TryFrom<zbus::OwnedVariant>,
{
    let value: zbus::OwnedVariant = connection
        .call_method(
            path.as_str(),
            "org.freedesktop.DBus.Properties",
            "Get",
            &(interface, name),
        )
        .await
        .map_err(|_| Error::CgroupMismatch)?
        .body()
        .deserialize()
        .map_err(|_| Error::CgroupMismatch)?;
    value.try_into().map_err(|_| Error::CgroupMismatch)
}

#[cfg(test)]
pub(super) fn lab_descriptor() -> Result<String> {
    let (spec, _) = super::tests::fixture();
    let domains = Domains::new(&spec, &"a".repeat(64))?;
    serde_json::to_string(&serde_json::json!({"owner_unit": domains.owner_unit(), "guard_role": "lifecycle_scope", "component_only": true})).map_err(|_| Error::InvalidSpec)
}
#[cfg(test)]
pub(super) fn lab_run() -> Result<()> {
    use rustix::net::{self, RecvFlags};
    let bytes = vprouter_linux::storage::read(
        std::path::Path::new("/var/lib/vprouter-v2-lab/owner-domain-nonce"),
        vprouter_linux::storage::Kind::SecretFile,
        64,
    )
    .map_err(|_| Error::LabRequired)?;
    let lifecycle = std::str::from_utf8(&bytes).map_err(|_| Error::LabRequired)?;
    let (spec, _) = super::tests::fixture();
    let domains = Domains::new(&spec, lifecycle)?;
    domains.verify_owner()?;
    let child_domains = domains.clone();
    let child = super::kernel::spawn_owned_guard(
        &domains,
        super::inventory::GuardInputs::for_domains(&domains)?,
        |channel| {
            child_domains.verify_guard()?;
            net::send(channel, b"gated", net::SendFlags::NOSIGNAL)
                .map_err(|_| Error::DescriptorPolicy)?;
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        },
    )?;
    let end = std::time::Instant::now() + Duration::from_secs(3);
    let mut ready = [0; 6];
    loop {
        if std::time::Instant::now() >= end {
            return Err(Error::Deadline);
        }
        match net::recv(
            &child.channel,
            &mut ready,
            RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        ) {
            Ok((5, 5)) if &ready[..5] == b"gated" => break,
            Err(rustix::io::Errno::AGAIN) => std::thread::sleep(Duration::from_millis(5)),
            _ => return Err(Error::DescriptorPolicy),
        }
    }
    let start = child.child.lab_stop_and_witness()?;
    child.child.lab_require_stopped(start)?;
    let pid = child.child.pid();
    println!(
        "{}",
        serde_json::json!({"case":"actual_authenticated_system_bus_pid1_exact_guard_sibling_scope_gated_release_and_stopped_witness", "guard_pid":pid,"guard_start":start,"owner_unit":domains.owner_unit(),"guard_unit":domains.unit(Role::Guard),"component_only":true})
    );
    child.child.lab_signal(libc::SIGKILL)?;
    child.child.lab_wait_killed()?;
    super::process::single_threaded()?;
    super::inventory::verify()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_population_requires_complete_native_pair_and_exact_live_shape() {
        use rustix::io::Errno;
        let text = |s: &str| Ok(s.to_owned());
        assert_eq!(
            original_population(text("populated 0\nfrozen 0\n"), text("")),
            Ok(OriginalPopulation::Live(ScopePopulation::LiveEmpty))
        );
        assert_eq!(
            original_population(text("populated 1\n"), text("123\n")),
            Ok(OriginalPopulation::Live(ScopePopulation::Populated))
        );
        assert_eq!(
            original_population(Err(Errno::NODEV), Err(Errno::NODEV)),
            Ok(OriginalPopulation::Offline)
        );
        for (events, procs) in [
            (text(""), text("")), // EOF is not a kernel offline observation.
            (text("populated 0\n"), text("123\n")),
            (text("populated 0\npopulated 0\n"), text("")),
            (text("populated 2\n"), text("")),
            (Err(Errno::NODEV), text("")),
            (text("populated 0\n"), Err(Errno::NODEV)),
            (Err(Errno::NOENT), Err(Errno::NOENT)),
            (Err(Errno::IO), Err(Errno::NODEV)),
        ] {
            assert_eq!(
                original_population(events, procs),
                Err(Error::CgroupMismatch)
            );
        }
    }
    #[test]
    fn ordinary_deleted_files_and_forged_names_cannot_supply_scope_population_pins() {
        let directory =
            std::env::temp_dir().join(format!("vprouter-scope-population-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let file = directory.join("cgroup.events");
        std::fs::write(&file, "populated 0\n").unwrap();
        let fd = fs::open(&file, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).unwrap();
        let mut pin = None;
        PopulationPin::capture(&mut pin, fd).unwrap();
        let pin = pin.unwrap();
        assert!(pin.verify(false).is_err());
        std::fs::remove_file(&file).unwrap();
        assert!(pin.verify(false).is_err());
        assert!(
            require_fd_target(
                &pin.fd,
                "/sys/fs/cgroup/system.slice/fake.scope/cgroup.events (deleted)"
            )
            .is_err()
        );
        std::fs::remove_dir(directory).unwrap();
    }
    fn scope_fixture() -> (String, Properties, Properties) {
        use zbus::Variant as V;
        let (spec, _) = super::super::tests::fixture();
        let unit = Domains::new(&spec, &"a".repeat(64))
            .unwrap()
            .unit(Role::Guard);
        let common = [
            ("Id", V::from(unit.as_str())),
            ("Transient", V::from(true)),
            ("BindsTo", V::from(Vec::<String>::new())),
            ("PartOf", V::from(Vec::<String>::new())),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.try_into().unwrap()))
        .collect();
        let group = format!("/system.slice/{unit}");
        let scope = [
            ("ControlGroup", V::from(group.as_str())),
            ("KillMode", V::from("control-group")),
            ("KillSignal", V::from(libc::SIGKILL)),
            ("TimeoutStopUSec", V::from(2_000_000u64)),
            ("SendSIGHUP", V::from(false)),
            ("Delegate", V::from(false)),
            ("Slice", V::from("system.slice")),
            ("SendSIGKILL", V::from(true)),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.try_into().unwrap()))
        .collect();
        (unit, common, scope)
    }
    #[test]
    fn actual_scope_policy_readback_rejects_wrong_missing_and_mistyped_properties() {
        use zbus::Variant as V;
        let (unit, common, scope) = scope_fixture();
        assert_eq!(verify_scope_properties(&unit, common, scope), Ok(()));
        for (name, value) in [
            ("KillMode", V::from("process")),
            ("KillSignal", V::from(libc::SIGTERM)),
            ("TimeoutStopUSec", V::from(90_000_000u64)),
            ("SendSIGHUP", V::from(true)),
            ("Delegate", V::from(true)),
            ("Slice", V::from("user.slice")),
            ("SendSIGKILL", V::from(false)),
        ] {
            let (unit, common, mut scope) = scope_fixture();
            scope.insert(name.into(), value.try_into().unwrap());
            assert_eq!(
                verify_scope_properties(&unit, common, scope),
                Err(Error::CgroupMismatch),
                "{name}"
            );
            let (unit, common, mut scope) = scope_fixture();
            scope.remove(name);
            assert_eq!(
                verify_scope_properties(&unit, common, scope),
                Err(Error::CgroupMismatch),
                "missing {name}"
            );
            let (unit, common, mut scope) = scope_fixture();
            scope.insert(
                name.into(),
                V::from(Vec::<String>::new()).try_into().unwrap(),
            );
            assert_eq!(
                verify_scope_properties(&unit, common, scope),
                Err(Error::CgroupMismatch),
                "mistyped {name}"
            );
        }
        for (name, value) in [
            ("Id", V::from("foreign.scope")),
            ("Transient", V::from(false)),
            ("BindsTo", V::from(vec!["foreign.service"])),
            ("PartOf", V::from(vec!["foreign.service"])),
        ] {
            let (unit, mut common, scope) = scope_fixture();
            common.insert(name.into(), value.try_into().unwrap());
            assert_eq!(
                verify_scope_properties(&unit, common, scope),
                Err(Error::CgroupMismatch),
                "{name}"
            );
        }
        let (unit, mut common, mut scope) = scope_fixture();
        // ControlGroup belongs to Scope, not generic Unit; wrong-interface
        // replies must never accidentally supply this authority.
        common.insert("ControlGroup".into(), scope.remove("ControlGroup").unwrap());
        assert_eq!(
            verify_scope_properties(&unit, common, scope),
            Err(Error::CgroupMismatch)
        );
    }
    #[test]
    fn transient_scope_request_transfers_exact_pidfd_and_never_numeric_pid() {
        let pidfd = rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(std::process::id() as i32).unwrap(),
            rustix::process::PidfdFlags::NONBLOCK,
        )
        .unwrap();
        let properties = transient_scope_properties(pidfd.as_fd());
        assert!(properties.iter().all(|(name, _)| *name != "PIDs"));
        let fds = properties
            .iter()
            .find(|(name, _)| *name == "PIDFDs")
            .unwrap();
        assert_eq!(fds.1.value_signature().to_string(), "ah");
        let auxiliary: Vec<(&str, Vec<(&str, zbus::Variant<'_>)>)> = vec![];
        let message = zbus::Message::method_call("/org/freedesktop/systemd1", "StartTransientUnit")
            .build(&("vpr-test.scope", "fail", properties, auxiliary))
            .unwrap();
        assert_eq!(message.header().unix_fds(), Some(1));
        assert_eq!(message.data().fds().len(), 1);
        assert_eq!(
            Identity::of(&pidfd).unwrap(),
            Identity::of(&message.data().fds()[0]).unwrap()
        );
        let fd = message.data().fds()[0].as_fd();
        use std::os::fd::AsRawFd;
        let info =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
        assert!(
            info.lines()
                .any(|line| line == format!("Pid:\t{}", std::process::id()))
        );
    }
    #[test]
    fn manager_connection_requires_both_pid1_and_root_bus_credentials() {
        use zbus::fdo::ConnectionCredentials;
        assert_eq!(
            manager_credentials(
                &ConnectionCredentials::default()
                    .set_process_id(1)
                    .set_unix_user_id(0)
            ),
            Ok(())
        );
        for credentials in [
            ConnectionCredentials::default(),
            ConnectionCredentials::default().set_process_id(1),
            ConnectionCredentials::default().set_unix_user_id(0),
            ConnectionCredentials::default()
                .set_process_id(2)
                .set_unix_user_id(0),
            ConnectionCredentials::default()
                .set_process_id(1)
                .set_unix_user_id(1),
        ] {
            assert_eq!(
                manager_credentials(&credentials),
                Err(Error::ProcessChanged)
            );
        }
    }
    #[test]
    fn owner_identity_is_deployment_stable_while_guard_binding_changes_generation() {
        let (mut spec, _) = super::super::tests::fixture();
        let before = Domains::new(&spec, &"a".repeat(64)).unwrap();
        spec.generation += 1;
        spec.allocation.generation += 1;
        let next = Domains::new(&spec, &"b".repeat(64)).unwrap();
        assert_eq!(
            before.owner_unit(),
            next.owner_unit(),
            "generation transition cannot restart healthy guards' owner"
        );
        assert_ne!(before.allocation(), next.allocation());
        assert_ne!(before.unit(Role::Guard), next.unit(Role::Guard));
    }
    #[test]
    fn role_scopes_bind_exact_allocation_lifecycle_pid_and_exclude_sibling_kill_domains() {
        let (spec, _) = super::super::tests::fixture();
        let domains = Domains::new(&spec, &"a".repeat(64)).unwrap();
        let later = Domains::new(&spec, &"b".repeat(64)).unwrap();
        let mut paths = std::collections::HashSet::new();
        for role in [
            Role::Guard,
            Role::ExpiryHost,
            Role::ExpiryTransport,
            Role::ExpiryData,
        ] {
            let path = format!("0::/system.slice/{}\n", domains.unit(role));
            assert!(paths.insert(path.clone()));
            assert_eq!(domains.membership(role, 123, &path, "123\n"), Ok(()));
            for foreign in [
                format!("0::/system.slice/{}\n", domains.owner_unit()),
                format!("0::/system.slice/{}\n", later.unit(role)),
                path.trim_end().to_owned() + "/child\n",
                path.clone() + &path,
                path.replace("system.slice", "user.slice"),
            ] {
                assert_eq!(
                    domains.membership(role, 123, &foreign, "123\n"),
                    Err(Error::CgroupMismatch)
                );
            }
            for members in ["", "124\n", "123\n124\n", "123\n123\n", "0123\n"] {
                assert_eq!(
                    domains.membership(role, 123, &path, members),
                    Err(Error::CgroupMismatch)
                );
            }
        }
        assert_eq!(paths.len(), 4);
    }
}
