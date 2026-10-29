#![forbid(unsafe_code)]
//! Protected inputs held without reading by the owner. Only the fixed installed
//! no-fork role may turn these descriptors into key-bearing parser state.
use super::{Error, Result, inventory, kernel};
use rustix::fs::{self, FileType};
use serde::{Deserialize, Serialize};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use vprouter_core::{
    allocation::AllocationRecord,
    config::{Mode, StructuredConfiguration},
    profile::{MAX_PROFILE_BYTES, Profile},
};

/// Public original-file identity, never content validation or a read permit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InputIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) size: u64,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) modified: (i64, u64),
    pub(super) changed: (i64, u64),
}
impl InputIdentity {
    pub(super) fn validate(&self) -> Result<()> {
        if self.uid != 0
            || self.gid != 0
            || self.inode == 0
            || self.size > MAX_PROFILE_BYTES as u64
            || FileType::from_raw_mode(self.mode) != FileType::RegularFile
            || !matches!(self.mode & 0o7777, 0o400 | 0o600)
            || self.modified.1 >= 1_000_000_000
            || self.changed.1 >= 1_000_000_000
        {
            return Err(Error::UnsafeInput);
        }
        Ok(())
    }
    pub(super) fn capture(fd: impl AsFd, owner: u32) -> Result<Self> {
        let stat = fs::fstat(&fd).map_err(|_| Error::UnsafeInput)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != owner
            || stat.st_gid != owner
            || !matches!(stat.st_mode & 0o7777, 0o400 | 0o600)
            || stat.st_nlink != 1
            || stat.st_size < 0
            || stat.st_size as u64 > MAX_PROFILE_BYTES as u64
            || stat.st_ino == 0
            || !kernel::descriptor_cloexec(fd.as_fd().as_raw_fd())?
        {
            return Err(Error::UnsafeInput);
        }
        Ok(Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            size: stat.st_size as u64,
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
            modified: (stat.st_mtime, stat.st_mtime_nsec),
            changed: (stat.st_ctime, stat.st_ctime_nsec),
        })
    }
    pub(super) fn verify(&self, fd: impl AsFd) -> Result<()> {
        if Self::capture(fd, self.uid)? != *self {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
}
struct Input {
    member: String,
    identity: InputIdentity,
    // Register immediately after opening; no subsequent nested preflight sees
    // an unclassified descriptor. These are default parent-private authority.
    inventory: inventory::Registration,
    fd: OwnedFd,
}
pub(super) struct Inputs {
    creator: u32,
    configuration: StructuredConfiguration,
    digest: [u8; 32],
    profiles: Vec<Input>,
    started_at: f64,
}
impl Inputs {
    pub(super) fn pin(configuration: StructuredConfiguration) -> Result<Self> {
        super::process::single_threaded()?;
        kernel::secret::seal_parent()?;
        if !vprouter_core::secret_boundary::pristine() {
            return Err(Error::ConfinementPolicy);
        }
        let started_at = vprouter_core::health::boot_seconds();
        if !started_at.is_finite() || started_at <= 0. {
            return Err(Error::Deadline);
        }
        let digest = configuration.digest().map_err(|_| Error::InvalidSpec)?;
        let mut profiles = Vec::new();
        // Include disabled profiles: whole-candidate validation preserves the
        // existing exact-server and normalized-private-key duplicate rules.
        for exit in &configuration.configuration().exits {
            if vprouter_core::health::boot_seconds() >= started_at + 2. {
                return Err(Error::Deadline);
            }
            if let Mode::Mullvad { profile, .. } = &exit.mode {
                let fd =
                    vprouter_linux::storage::pin_secret(profile).map_err(|_| Error::UnsafeInput)?;
                let inventory = inventory::Registration::owned(&[fd.as_fd()])?;
                let identity = InputIdentity::capture(&fd, 0)?;
                profiles.push(Input {
                    member: exit.id.clone(),
                    identity,
                    inventory,
                    fd,
                });
            }
        }
        Ok(Self {
            creator: std::process::id(),
            configuration,
            digest,
            profiles,
            started_at,
        })
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(super) fn started_at(&self) -> f64 {
        self.started_at
    }
    pub(super) fn deadline(&self) -> f64 {
        self.started_at + 2.
    }
    pub(super) fn allocation(&self, generation: u64) -> Result<AllocationRecord> {
        AllocationRecord::from_structure(&self.configuration, generation)
            .map_err(|_| Error::AllocationMismatch)
    }
    pub(super) fn identities(&self) -> Vec<(String, InputIdentity)> {
        self.profiles
            .iter()
            .map(|p| (p.member.clone(), p.identity.clone()))
            .collect()
    }
    pub(super) fn verify_parent(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::OwnershipMismatch);
        }
        for input in &self.profiles {
            if !input.inventory.contains(input.fd.as_fd()) {
                return Err(Error::DescriptorInventory);
            }
            input.identity.verify(&input.fd)?;
        }
        Ok(())
    }
    /// Kernel setup receives only this internally created descriptor set. No
    /// caller-supplied FD or parser callback participates in the role.
    pub(super) fn descriptors(&self) -> Vec<i32> {
        self.profiles.iter().map(|p| p.fd.as_raw_fd()).collect()
    }
    pub(super) fn owner(&self) -> u32 {
        self.creator
    }
    pub(super) fn provision_descriptors(
        &self,
    ) -> Result<Vec<(String, std::os::fd::BorrowedFd<'_>)>> {
        self.verify_parent()?;
        Ok(self
            .profiles
            .iter()
            .map(|p| (p.member.clone(), p.fd.as_fd()))
            .collect())
    }
    pub(super) fn report(&self, role: &kernel::secret::NoFork) -> Result<Vec<u8>> {
        role.require(self)?;
        // Read attempts taint even if metadata/read/parsing subsequently fails.
        // This follows the installed kernel no-fork capability, never precedes it.
        vprouter_core::secret_boundary::mark_ingress();
        let mut next = self.profiles.iter();
        let validated = self
            .configuration
            .configuration()
            .clone()
            .validate_with(|path, server| {
                let error = || {
                    vprouter_core::reason::Error::new(
                        vprouter_core::reason::Reason::ProfileUnavailable,
                    )
                };
                let input = next.next().ok_or_else(error)?;
                role.check_deadline().map_err(|_| error())?;
                input.identity.verify(&input.fd).map_err(|_| error())?;
                // One fixed allocation; no growth/reallocation with secret content.
                let mut bytes = zeroize::Zeroizing::new(vec![0u8; MAX_PROFILE_BYTES + 1]);
                let mut length = 0;
                loop {
                    role.check_deadline().map_err(|_| error())?;
                    let read = rustix::io::pread(&input.fd, &mut bytes[length..], length as u64)
                        .map_err(|_| error())?;
                    role.check_deadline().map_err(|_| error())?;
                    if read == 0 {
                        break;
                    }
                    length += read;
                    if length > MAX_PROFILE_BYTES {
                        return Err(error());
                    }
                }
                input.identity.verify(&input.fd).map_err(|_| error())?;
                if length as u64 != input.identity.size {
                    return Err(error());
                }
                let profile = Profile::parse(&bytes[..length], server, Some(path))?;
                role.check_deadline().map_err(|_| error())?;
                Ok(profile)
            })
            .map_err(|_| Error::UnsafeInput)?;
        if next.next().is_some() {
            return Err(Error::OwnershipMismatch);
        }
        role.check_deadline()?;
        let report = validated.public_report().map_err(|_| Error::UnsafeInput)?;
        // All owned private keys are dropped before serialization/sending. Error
        // unwinding also drops them; abrupt process death destroys this address
        // space, and is not reported as a Rust Drop/zeroization observation.
        drop(validated);
        let bytes = report.encode().map_err(|_| Error::TooLarge)?;
        role.check_deadline()?;
        Ok(bytes)
    }
    pub(super) fn bind_report(
        &self,
        bytes: &[u8],
    ) -> Result<vprouter_core::config::PublicConfiguration> {
        self.verify_parent()?;
        self.configuration
            .configuration()
            .clone()
            .validate_structure()
            .map_err(|_| Error::InvalidSpec)?
            .bind_public_report(bytes)
            .map_err(|_| Error::OwnershipMismatch)
    }
}

/// The connected owner state machine retains every constructor outcome before
/// the next fallible operation. Existing owners must be polled independently;
/// this does not create a runtime or monopolize an owner RPC while IO runs.
pub(super) struct PendingValidation {
    native: Option<PendingNative>,
}
#[derive(Clone, Copy)]
enum Step {
    Intent,
    Birth,
    Reading,
    Result,
    Complete,
}
struct PendingNative {
    creator: u32,
    transaction: super::owned::Transaction,
    service: super::owned::preparation::Server,
    child: Option<kernel::secret::ValidationChild>,
    report: Option<kernel::secret::Verified>,
    validated: Option<kernel::secret::Validated>,
    step: Step,
    failure: Option<Error>,
    #[cfg(test)]
    lab_anchor: std::rc::Rc<()>,
    #[cfg(test)]
    lab_mismatch_receipt: bool,
}
pub(super) struct PreparedValidation {
    transaction: super::owned::Transaction,
    service: super::owned::preparation::Server,
    profiles: kernel::secret::Validated,
}
impl PreparedValidation {
    pub(super) fn provision_descriptors(
        &self,
    ) -> Result<Vec<(String, std::os::fd::BorrowedFd<'_>)>> {
        self.profiles.bind_current(&self.service)?;
        self.profiles.provision_descriptors()
    }
    pub(super) fn inspection_service(&self) -> &super::owned::preparation::Server {
        &self.service
    }
    pub(super) fn service(&mut self) -> &mut super::owned::preparation::Server {
        &mut self.service
    }
    pub(super) fn configuration(&self) -> &vprouter_core::config::PublicConfiguration {
        self.profiles.configuration()
    }
}
thread_local! { static RETAINED_VALIDATIONS: std::cell::RefCell<Vec<PendingNative>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl Drop for PendingValidation {
    fn drop(&mut self) {
        if let Some(mut native) = self.native.take() {
            if native.creator != std::process::id() {
                return;
            }
            native.fail(Error::Interrupted);
            RETAINED_VALIDATIONS.with(|retained| retained.borrow_mut().push(native));
        }
    }
}
pub(super) fn poll_retained() {
    RETAINED_VALIDATIONS.with(|retained| {
        for native in retained.borrow_mut().iter_mut() {
            if native.creator == std::process::id() {
                native.collect();
            }
        }
    });
}
pub(super) fn retained_children_reaped() -> bool {
    RETAINED_VALIDATIONS.with(|retained| {
        retained.borrow().iter().all(|native| {
            native.creator != std::process::id()
                || native.service.children_reaped()
                    && native
                        .child
                        .as_ref()
                        .is_none_or(kernel::secret::ValidationChild::reaped)
        })
    })
}
impl PendingValidation {
    /// Initial owner only. Protected FD opening and initial owner-epoch fsync
    /// precede all established members. Dynamic pin acquisition still needs its
    /// own retained asynchronous metadata role before this can serve hot-add.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn initial(
        store: &vprouter_core::allocation::AllocationStore,
        path: &std::path::Path,
        allocation: &AllocationRecord,
        member: &str,
        primary: &str,
        configuration: StructuredConfiguration,
        owner: std::rc::Rc<super::supervision::OwnerDomain>,
        domains: super::supervision::Domains,
    ) -> Result<Self> {
        let inputs = Inputs::pin(configuration)?;
        let (transaction, service) = super::owned::preparation::Server::initial(
            store, path, allocation, member, primary, inputs, owner, domains,
        )?;
        let mut value = Self {
            native: Some(PendingNative {
                creator: std::process::id(),
                transaction,
                service,
                child: None,
                report: None,
                validated: None,
                step: Step::Intent,
                failure: None,
                #[cfg(test)]
                lab_anchor: std::rc::Rc::new(()),
                #[cfg(test)]
                lab_mismatch_receipt: false,
            }),
        };
        // Store the service before start(): even a constructor error retains the
        // unique canonical reservation and every already-created native job.
        value
            .native
            .as_mut()
            .ok_or(Error::Interrupted)?
            .service
            .start()?;
        Ok(value)
    }
    pub(super) fn poll(&mut self) -> Result<Option<PreparedValidation>> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = native.failure {
            native.collect();
            return Err(error);
        }
        if let Err(error) = native.advance() {
            native.fail(error);
            native.collect();
            return Err(error);
        }
        if !matches!(native.step, Step::Complete) {
            return Ok(None);
        }
        if native.validated.is_none() {
            native.fail(Error::Interrupted);
            native.collect();
            return Err(Error::Interrupted);
        }
        let mut native = self.native.take().ok_or(Error::Interrupted)?;
        Ok(Some(PreparedValidation {
            transaction: native.transaction,
            service: native.service,
            profiles: native.validated.take().ok_or(Error::Interrupted)?,
        }))
    }
}
impl PendingNative {
    fn fail(&mut self, error: Error) {
        self.failure.get_or_insert(error);
        self.service.fail(error);
        if let Some(child) = &mut self.child {
            child.cancel(error);
        }
    }
    fn collect(&mut self) {
        self.service.collect();
        if let Some(child) = &mut self.child {
            child.collect();
        }
    }
    fn advance(&mut self) -> Result<()> {
        kernel::owner_admission_permitted()?;
        match self.step {
            Step::Intent => {
                if let Some((intent, inputs)) = self.service.poll()? {
                    self.child = Some(kernel::secret::spawn(inputs, intent)?);
                    self.service
                        .start_birth(self.child.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::Birth;
                }
            }
            Step::Birth => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(receipt) = self.service.poll_birth(child)? {
                    child.release(receipt)?;
                    self.step = Step::Reading;
                }
            }
            Step::Reading => {
                if let Some(report) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? {
                    self.report = Some(report);
                    self.service
                        .start_result(self.report.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::Result;
                }
            }
            Step::Result => {
                if let Some(receipt) = self
                    .service
                    .poll_result(self.report.as_ref().ok_or(Error::Interrupted)?)?
                {
                    #[cfg(test)]
                    let receipt = if self.lab_mismatch_receipt {
                        receipt.lab_wrong_member()
                    } else {
                        receipt
                    };
                    self.validated =
                        Some(kernel::secret::Verified::accept(&mut self.report, receipt)?);
                    self.child = None;
                    self.step = Step::Complete;
                }
            }
            Step::Complete => {}
        }
        Ok(())
    }
}

#[cfg(test)]
fn lab_inputs() -> Result<(
    String,
    StructuredConfiguration,
    AllocationRecord,
    super::supervision::Domains,
)> {
    lab_inputs_for(false)
}
#[cfg(test)]
pub(super) fn lab_inputs_for(
    attachment: bool,
) -> Result<(
    String,
    StructuredConfiguration,
    AllocationRecord,
    super::supervision::Domains,
)> {
    if super::attachment::lab_stop_before_inputs() {
        return Err(Error::LabRequired);
    }
    use std::path::Path;
    let root = Path::new("/var/lib/vprouter-v2-lab");
    let nonce = vprouter_linux::storage::read(
        &root.join("owner-domain-nonce"),
        vprouter_linux::storage::Kind::SecretFile,
        64,
    )
    .map_err(|_| Error::LabRequired)?;
    let nonce = std::str::from_utf8(&nonce)
        .map_err(|_| Error::LabRequired)?
        .to_owned();
    if !super::spec::digest(&nonce) {
        return Err(Error::LabRequired);
    }
    // This file is schema-bound PUBLIC configuration only. The external test
    // controller, never this parent, creates the separate synthetic profiles.
    let bytes = vprouter_linux::storage::read(
        &root.join(if attachment {
            "secret-attachment.json"
        } else {
            "secret-preparation.json"
        }),
        vprouter_linux::storage::Kind::SecretFile,
        1024 * 1024,
    )
    .map_err(|_| Error::LabRequired)?;
    let config = vprouter_core::config::Configuration::parse(&bytes)
        .map_err(|_| Error::InvalidSpec)?
        .validate_structure()
        .map_err(|_| Error::InvalidSpec)?;
    if config.configuration().deployment_id != format!("secretlab-{}", &nonce[..12]) {
        return Err(Error::LabRequired);
    }
    let mut profiles = 0;
    for exit in &config.configuration().exits {
        if exit.enrollment_key_file.is_some()
            || exit.state_dir
                != root.join(if attachment {
                    format!("secret-gateway-state-{nonce}/{}", exit.id)
                } else {
                    format!("owner-secret-{nonce}/state/{}", exit.id)
                })
        {
            return Err(Error::LabRequired);
        }
        if let Mode::Mullvad {
            profile,
            expected_server,
        } = &exit.mode
        {
            if *profile
                != root.join(format!(
                    "secret-inputs-{nonce}/{}/{expected_server}.conf",
                    exit.id
                ))
            {
                return Err(Error::LabRequired);
            }
            profiles += 1;
        }
    }
    if profiles == 0 {
        return Err(Error::LabRequired);
    }
    let allocation =
        AllocationRecord::from_structure(&config, 1).map_err(|_| Error::AllocationMismatch)?;
    let primary = config
        .configuration()
        .exits
        .iter()
        .find(|exit| exit.enabled)
        .ok_or(Error::InvalidSpec)?
        .id
        .clone();
    let domains = super::supervision::Domains::from_record(&allocation, &primary, &nonce)?;
    Ok((nonce, config, allocation, domains))
}
#[cfg(test)]
pub(super) fn lab_prepare_attachment() -> Result<(String, PreparedValidation, serde_json::Value)> {
    use std::{os::unix::fs::DirBuilderExt, path::Path, rc::Rc, time::Duration};
    let (nonce, config, allocation, domains) = lab_inputs_for(true)?;
    let owner = Rc::new(super::supervision::OwnerDomain::capture(&domains)?);
    let path = Path::new("/var/lib/vprouter-v2-lab").join(format!("owner-secret-{nonce}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| Error::OwnershipMismatch)?;
    let store = vprouter_core::allocation::AllocationStore::open(&path, &allocation.deployment_id)
        .map_err(|_| Error::OwnershipMismatch)?;
    store
        .lock()
        .map_err(|_| Error::LockBusy)?
        .commit(None, &allocation)
        .map_err(|_| Error::OwnershipMismatch)?;
    let primary = domains.exit_id().to_owned();
    let mut pending = PendingValidation::initial(
        &store,
        &path,
        &allocation,
        &primary,
        &primary,
        config,
        owner,
        domains,
    )?;
    let mut validator: Option<kernel::secret::LabReap> = None;
    loop {
        if let Some(prepared) = pending.poll()? {
            let validator = validator.ok_or(Error::OwnershipMismatch)?;
            if validator.status()? != Some(0) {
                return Err(Error::ChildFailed);
            }
            let validator = validator.evidence()?;
            if !vprouter_core::secret_boundary::pristine() || prepared.profiles.lab_pins()? == 0 {
                return Err(Error::ConfinementPolicy);
            }
            return Ok((nonce, prepared, validator));
        }
        if validator.is_none()
            && let Some(child) = &pending.native.as_ref().ok_or(Error::Interrupted)?.child
        {
            // Keep the constructor receipt itself until the result's actual
            // completion, then serialize the current original status below.
            let receipt = child.lab_reap()?;
            validator = Some(receipt);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[cfg(test)]
pub(super) fn lab_descriptor() -> Result<String> {
    let (nonce, _, allocation, domains) = lab_inputs()?;
    serde_json::to_string(&serde_json::json!({"schema_version": 1, "nonce": nonce,
        "owner_unit": domains.owner_unit(), "deployment_id": allocation.deployment_id,
        "primary": domains.exit_id(), "configuration": "/var/lib/vprouter-v2-lab/secret-preparation.json",
        "profile_contents_read": false, "container_required": false, "network_mutations": false}))
        .map_err(|_| Error::InvalidSpec)
}
#[cfg(test)]
pub(super) fn lab_run(fault: u8) -> Result<()> {
    use std::{os::unix::fs::DirBuilderExt, path::Path, rc::Rc, time::Duration};
    if fault > 5 || !vprouter_core::secret_boundary::pristine() {
        return Err(Error::LabRequired);
    }
    let (nonce, config, allocation, domains) = lab_inputs()?;
    let owner = Rc::new(super::supervision::OwnerDomain::capture(&domains)?);
    let path = Path::new("/var/lib/vprouter-v2-lab").join(format!("owner-secret-{nonce}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| Error::OwnershipMismatch)?;
    let store = vprouter_core::allocation::AllocationStore::open(&path, &allocation.deployment_id)
        .map_err(|_| Error::OwnershipMismatch)?;
    store
        .lock()
        .map_err(|_| Error::LockBusy)?
        .commit(None, &allocation)
        .map_err(|_| Error::OwnershipMismatch)?;
    let primary = domains.exit_id().to_owned();
    let mut pending = PendingValidation::initial(
        &store,
        &path,
        &allocation,
        &primary,
        &primary,
        config,
        owner,
        domains,
    )?;
    let native = pending.native.as_mut().ok_or(Error::Interrupted)?;
    let weak = Rc::downgrade(&native.lab_anchor);
    native.lab_mismatch_receipt = fault == 5;
    if let Some(phase) = match fault {
        2 => Some("intent"),
        3 => Some("birth"),
        4 => Some("result"),
        _ => None,
    } {
        native.service.lab_hold(phase)?;
    }
    let original = native.service.lab_evidence()?;
    let deadline = original["deadline"].as_f64().ok_or(Error::Deadline)?;
    let mut validator = None;
    let mut held = false;
    let mut held_native_drain_false = false;
    let mut expired_native_writer_status = None;
    let result = loop {
        match pending.poll() {
            Ok(Some(prepared)) => break Ok(prepared),
            Err(error) => break Err(error),
            Ok(None) => {}
        }
        let native = pending.native.as_mut().ok_or(Error::Interrupted)?;
        if validator.is_none()
            && let Some(child) = &native.child
        {
            validator = Some(child.lab_reap()?);
        }
        if (2..=4).contains(&fault) && native.service.lab_checkpoint()? {
            held = true;
            held_native_drain_false |= !native.service.children_reaped();
            if fault == 4 {
                native.fail(Error::ChildFailed);
            } else {
                while vprouter_core::health::boot_seconds() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
                expired_native_writer_status = Some(native.service.lab_release_expired_writer()?);
            }
        }
        if vprouter_core::health::boot_seconds() >= deadline + 1. {
            return Err(Error::Deadline);
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let label = match fault {
        0 => "actual_secret_free_parent_durable_validation_result_and_original_reaps",
        1 => "actual_secret_validation_rejection_retains_context",
        2 => "actual_secret_validation_intent_writer_original_deadline_retained",
        3 => "actual_secret_validation_birth_writer_original_deadline_retained",
        4 => "actual_secret_validation_result_writer_failure_retains_context",
        5 => "actual_secret_validation_mismatched_result_receipt_retains_original_report",
        _ => return Err(Error::InvalidSpec),
    };
    match result {
        Ok(prepared) => {
            if fault != 0
                || !vprouter_core::secret_boundary::pristine()
                || validator
                    .as_ref()
                    .ok_or(Error::OwnershipMismatch)?
                    .status()?
                    != Some(0)
            {
                return Err(Error::OwnershipMismatch);
            }
            let evidence = prepared.service.lab_evidence()?;
            let profile_count = prepared.profiles.lab_pins()?;
            let writers = evidence["writers"]
                .as_array()
                .ok_or(Error::OwnershipMismatch)?;
            if writers.len() != 3
                || !evidence["canonical_result_present"]
                    .as_bool()
                    .unwrap_or(false)
                || !evidence["service_reserved"].as_bool().unwrap_or(false)
                || !prepared.service.children_reaped()
                || !evidence["base_network_absent"].as_bool().unwrap_or(false)
                || evidence["member_native_jobs_collected"].as_bool() != Some(true)
                || profile_count == 0
            {
                return Err(Error::OwnershipMismatch);
            }
            for (writer, phase) in writers.iter().zip(["intent", "birth", "result"]) {
                if writer["phase"] != phase
                    || writer["actual_wait_status"] != 0
                    || writer["io_deadline"].as_f64() != Some(deadline)
                    || writer["parent_deadline"].as_f64() != Some(deadline)
                    || !writer["verified_at"].as_f64().is_some_and(|t| t < deadline)
                {
                    return Err(Error::OwnershipMismatch);
                }
            }
            println!("{}", serde_json::json!({"case": label, "result": "PASS"}));
            println!(
                "LAB_SECRET_PREPARATION {}",
                serde_json::json!({"schema":1,"fault":fault,"preparation":evidence,
                "validator":validator.as_ref().ok_or(Error::Interrupted)?.evidence()?,"parent_pristine":true,
                "whole_configuration_members":prepared.configuration().exits().len(),"same_service_retained":true,
                "profile_pins_retained":true,"profile_pin_count":profile_count,
                "namespace_or_link_authority":false,"requirement8_complete":false})
            );
            // Canonical ownership and protected pins remain retained even after
            // the fixture has collected its evidence; no reuse/cleanup grant.
            LAB_PREPARED.with(|retained| retained.borrow_mut().push(prepared));
        }
        Err(error) => {
            let expected = if fault == 2 || fault == 3 {
                Error::Deadline
            } else if fault == 5 {
                Error::OwnershipMismatch
            } else {
                Error::ChildFailed
            };
            if fault == 0
                || error != expected
                || (2..=4).contains(&fault) && (!held || !held_native_drain_false)
            {
                eprintln!(
                    "LAB_SECRET_PREPARATION_FAILURE fault={fault} reason={error:?} held={held}"
                );
                return Err(error);
            }
            let end = vprouter_core::health::boot_seconds() + 2.;
            loop {
                let native = pending.native.as_mut().ok_or(Error::Interrupted)?;
                native.collect();
                if native.service.children_reaped()
                    && native
                        .child
                        .as_ref()
                        .is_none_or(kernel::secret::ValidationChild::reaped)
                {
                    break;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let native = pending.native.as_ref().ok_or(Error::Interrupted)?;
            let evidence = native.service.lab_evidence()?;
            if !vprouter_core::secret_boundary::pristine()
                || !evidence["service_reserved"].as_bool().unwrap_or(false)
                || evidence["canonical_result_present"].as_bool() != Some(fault == 5)
                || fault == 5 && native.report.is_none()
                || fault == 4 && native.report.is_none()
                || (fault == 2 || fault == 3) && expired_native_writer_status != Some(122 << 8)
                || evidence["canonical_pending"].as_bool() != Some((2..=4).contains(&fault))
                || evidence["mutation_fenced"].as_bool() != Some((2..=4).contains(&fault))
                || fault == 4
                    && evidence["writers"]
                        .as_array()
                        .and_then(|rows| rows.last())
                        .and_then(|row| row["actual_wait_status"].as_i64())
                        != Some(9)
                || fault == 1
                    && validator
                        .as_ref()
                        .ok_or(Error::OwnershipMismatch)?
                        .status()?
                        != Some(122 << 8)
            {
                return Err(Error::OwnershipMismatch);
            }
            drop(pending);
            if weak.upgrade().is_none() {
                return Err(Error::OwnershipMismatch);
            }
            println!("{}", serde_json::json!({"case": label, "result":"PASS"}));
            println!(
                "LAB_SECRET_PREPARATION {}",
                serde_json::json!({"schema":1,"fault":fault,"preparation":evidence,
                "validator":validator.as_ref().map(kernel::secret::LabReap::evidence).transpose()?,"parent_pristine":true,
                "held_real_writer":held,"unreaped_writer_reported_not_drained":held_native_drain_false,
                "expired_native_writer_status":expired_native_writer_status,
                "mismatched_receipt_retained_original_report":fault == 5,
                "whole_failed_driver_retained_after_drop":true,"same_service_retained":true,
                "namespace_or_link_authority":false,"requirement8_complete":false})
            );
        }
    }
    Ok(())
}
#[cfg(test)]
thread_local! { static LAB_PREPARED: std::cell::RefCell<Vec<PreparedValidation>> = const { std::cell::RefCell::new(Vec::new()) }; }

impl PreparedValidation {
    pub(super) fn bind_public(&self) -> Result<super::owned::preparation::PublicBinding> {
        self.profiles.bind_current(&self.service)
    }
    pub(super) fn verify_initial_binding(
        &self,
        binding: &super::owned::preparation::PublicBinding,
        spec: &super::LaunchSpec,
    ) -> Result<()> {
        self.profiles.bind_current(&self.service)?;
        binding.verify_initial(&self.service, spec)
    }
}
