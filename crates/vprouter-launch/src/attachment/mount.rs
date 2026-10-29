//! One separately anchored attachment of an already admitted original namespace.
//! A path, parsed history, or caller-supplied identity cannot construct Request.
use super::*;
use rustix::fs::{self, FileType};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

pub(crate) struct Request {
    creator: u32,
    admission: Rc<Admission>,
    binding: super::super::owned::preparation::PublicBinding,
    origin: Origin,
    source: OwnedFd,
    source_token: super::super::inventory::Registration,
    directory: OwnedFd,
    directory_token: super::super::inventory::Registration,
    directory_identity: Identity,
    name: String,
    source_identity: Identity,
    requested_at: f64,
    digest: [u8; 32],
}
impl Request {
    pub(super) fn new(value: &mut InspectedPreparation) -> Result<Rc<Self>> {
        #[cfg(test)]
        let mut trace = lab_trace::Trace::new(
            value.gateway.creator,
            "attachment_constructor",
            "creator_preflight",
            value.gateway.requested_at,
            value.gateway.requested_at + 2.,
        );
        super::super::process::single_threaded()?;
        super::super::kernel::owner_admission_permitted()?;
        if value.gateway.creator != std::process::id()
            || !vprouter_core::secret_boundary::pristine()
        {
            return Err(Error::OwnershipMismatch);
        }
        #[cfg(test)]
        trace.step("old_queries_entry");
        value.gateway._queries.0.require()?;
        value.gateway._queries.1.require()?;
        #[cfg(test)]
        trace.step("initial_binding");
        value
            .prepared
            .verify_initial_binding(&value.gateway.binding, &value.gateway.admission.spec)?;
        #[cfg(test)]
        trace.step("new_attachment_anchor");
        let requested_at = vprouter_core::health::boot_seconds();
        if !requested_at.is_finite() || requested_at < value.gateway.verified_at {
            return Err(Error::Deadline);
        }
        #[cfg(test)]
        trace.step("native_process_revalidate");
        let admission = value.gateway.admission.clone();
        admission
            .process
            .revalidate(&admission.spec, &admission.staging)?;
        #[cfg(test)]
        trace.step("public_binding");
        let binding = value.prepared.bind_public()?;
        #[cfg(test)]
        trace.step("original_directory_and_namespace_pins");
        let (directory, name) = value.prepared.service().mount_target(&admission.spec)?;
        let directory_token = super::super::inventory::Registration::owned(&[directory.as_fd()])?;
        let directory_identity = Identity::of(&directory)?;
        let source = rustix::io::fcntl_dupfd_cloexec(admission.process.base_network(), 3)
            .map_err(|_| Error::DescriptorDuplicate)?;
        let source_token = super::super::inventory::Registration::owned(&[source.as_fd()])?;
        let source_identity = Identity::network(&source)?;
        if !matches!(&value.gateway.origin, Origin::ExistingAdmitted { network, public_result, .. }
            if *network == source_identity && *public_result == binding.public_result())
        {
            return Err(Error::OwnershipMismatch);
        }
        #[cfg(test)]
        trace.step("original_origin_binding_and_hash");
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                &value.gateway.origin,
                directory_identity,
                &name,
                source_identity,
                requested_at,
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let request = Rc::new(Self {
            creator: std::process::id(),
            admission,
            binding,
            origin: value.gateway.origin.clone(),
            source,
            source_token,
            directory,
            directory_token,
            directory_identity,
            name,
            source_identity,
            requested_at,
            digest,
        });
        // The old inspection is consumed only while it remains valid. This new
        // anchor never changes the timestamps or acceptance of either old query.
        #[cfg(test)]
        trace.step("native_pin_verification");
        request.verify_native()?;
        #[cfg(test)]
        trace.step("final_old_queries_require");
        value.gateway._queries.0.require()?;
        value.gateway._queries.1.require()?;
        #[cfg(test)]
        trace.finish();
        Ok(request)
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::ConfinementPolicy);
        }
        super::super::kernel::owner_admission_permitted()?;
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now < self.requested_at || now >= self.deadline() {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(crate) fn verify_native(&self) -> Result<()> {
        self.check()?;
        self.verify_retained_pins()?;
        self.check()
    }
    /// Fresh original custody, not re-acceptance of an expired operation/query.
    pub(crate) fn verify_retained_pins(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        let s = fs::fstat(&self.directory).map_err(|_| Error::OwnershipMismatch)?;
        if !self.directory_token.contains(self.directory.as_fd())
            || !self.source_token.contains(self.source.as_fd())
            || Identity::of(&self.directory)? != self.directory_identity
            || FileType::from_raw_mode(s.st_mode) != FileType::Directory
            || s.st_uid != 0
            || s.st_gid != 0
            || s.st_mode & 0o7777 != 0o700
            || Identity::network(&self.source)? != self.source_identity
            || Identity::network(self.admission.process.base_network())? != self.source_identity
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn revalidate_process(&self) -> Result<()> {
        self.verify_native()?;
        self.admission
            .process
            .revalidate(&self.admission.spec, &self.admission.staging)?;
        self.check()
    }
    /// Fresh process/pin facts only. A caller performing a new operation must
    /// bracket this with that operation's current end and fresh policy query.
    pub(crate) fn revalidate_retained_process(&self) -> Result<()> {
        self.verify_retained_pins()?;
        self.admission
            .process
            .revalidate(&self.admission.spec, &self.admission.staging)?;
        self.verify_retained_pins()
    }
    pub(crate) fn original_cgroup_parent(&self) -> Result<BorrowedFd<'_>> {
        self.revalidate_retained_process()?;
        Ok(self.admission.process.cgroup_parent())
    }
    pub(crate) fn original_producer_ancestry(&self) -> Result<[OwnedFd; 2]> {
        self.verify_retained_pins()?;
        self.admission
            .process
            .producer_ancestry(&self.admission.spec, &self.admission.staging)
    }
    pub(crate) fn verify_producer_ancestry(
        &self,
        root: BorrowedFd<'_>,
        system: BorrowedFd<'_>,
    ) -> Result<()> {
        self.verify_retained_pins()?;
        self.admission.process.verify_producer_ancestry(
            &self.admission.spec,
            &self.admission.staging,
            root,
            system,
        )
    }
    pub(crate) fn spec(&self) -> &super::super::LaunchSpec {
        &self.admission.spec
    }
    pub(crate) fn staging(&self) -> &super::super::StagingEvidence {
        &self.admission.staging
    }
    pub(crate) fn binding(&self) -> &super::super::owned::preparation::PublicBinding {
        &self.binding
    }
    pub(crate) fn origin(&self) -> &Origin {
        &self.origin
    }
    pub(crate) fn source(&self) -> BorrowedFd<'_> {
        self.source.as_fd()
    }
    pub(crate) fn directory(&self) -> BorrowedFd<'_> {
        self.directory.as_fd()
    }
    pub(crate) fn directory_identity(&self) -> Identity {
        self.directory_identity
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn source_identity(&self) -> Identity {
        self.source_identity
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn requested_at(&self) -> f64 {
        self.requested_at
    }
    pub(crate) fn deadline(&self) -> f64 {
        self.requested_at + 2.
    }
}

/// Whole consuming attachment driver. Every post-consumption error and Drop
/// retains canonical/service ownership plus all native mount/query contexts.
pub(super) struct PendingAttachment {
    native: Option<Native>,
}
pub(super) struct AttachedPrimary {
    native: Option<Native>,
}
impl AttachedPrimary {
    pub(super) fn configuration(&self) -> Result<&vprouter_core::config::PublicConfiguration> {
        self.service_ref()?;
        Ok(self
            .native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .input
            .prepared
            .configuration())
    }
    pub(super) fn provision_descriptors(&self) -> Result<Vec<(String, BorrowedFd<'_>)>> {
        self.service_ref()?;
        self.native
            .as_ref()
            .ok_or(Error::Interrupted)?
            .input
            .prepared
            .provision_descriptors()
    }
    pub(super) fn service(&mut self) -> Result<&mut super::super::owned::preparation::Server> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(n.input.prepared.service())
    }
    pub(super) fn service_ref(&self) -> Result<&super::super::owned::preparation::Server> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id()
            || n.failure.is_some()
            || !matches!(n.step, Step::Complete)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(n.input.prepared.inspection_service())
    }
    pub(super) fn retained_data(
        &self,
    ) -> Result<Rc<super::super::kernel::namespace_attachment::Mounted>> {
        let n = self.native.as_ref().ok_or(Error::Interrupted)?;
        let mounted = n.mounted.as_ref().ok_or(Error::OwnershipMismatch)?;
        self.service_ref()?.verify_attached(mounted)?;
        mounted.verify_retained()?;
        Ok(mounted.clone())
    }
}
struct Native {
    creator: u32,
    input: InspectedPreparation,
    request: Rc<Request>,
    child: Option<super::super::kernel::namespace_attachment::Child>,
    mounted: Option<Rc<super::super::kernel::namespace_attachment::Mounted>>,
    query: Option<Rc<InspectionRequest>>,
    query_child: Option<super::super::kernel::docker_query::Child>,
    query_verified: Option<super::super::kernel::docker_query::Verified>,
    query_accepted: Option<super::super::kernel::docker_query::Accepted>,
    step: Step,
    failure: Option<Error>,
    #[cfg(test)]
    lab_anchor: Rc<()>,
}
#[derive(Clone, Copy)]
enum Step {
    Intent,
    Birth,
    Placeholder,
    PlaceholderWriting,
    Mounting,
    MountedWriting,
    QueryIntent,
    QueryBirth,
    QueryReading,
    QueryWriting,
    Publishing,
    Complete,
}
thread_local! { static RETAINED: std::cell::RefCell<Vec<Native>> = const { std::cell::RefCell::new(Vec::new()) }; }
fn retain(mut native: Native) {
    if native.creator != std::process::id() {
        return;
    }
    native.fail(Error::Interrupted);
    RETAINED.with(|retained| retained.borrow_mut().push(native));
}
impl Drop for PendingAttachment {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            retain(native);
        }
    }
}
impl Drop for AttachedPrimary {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            retain(native);
        }
    }
}
pub(super) fn poll_retained() {
    RETAINED.with(|retained| {
        for native in retained.borrow_mut().iter_mut() {
            if native.creator == std::process::id() {
                native.collect();
            }
        }
    });
}
pub(super) fn children_reaped() -> bool {
    RETAINED.with(|retained| {
        retained.borrow_mut().iter_mut().all(|n| {
            n.creator != std::process::id()
                || n.input.prepared.service().children_reaped()
                    && n.child
                        .as_ref()
                        .is_none_or(super::super::kernel::namespace_attachment::Child::reaped)
                    && n.query_child
                        .as_ref()
                        .is_none_or(super::super::kernel::docker_query::Child::reaped)
        })
    })
}
impl PendingAttachment {
    pub(super) fn new(slot: &mut Option<InspectedPreparation>) -> Result<Self> {
        let request = Request::new(slot.as_mut().ok_or(Error::Interrupted)?)?;
        let mut pending = Self {
            native: Some(Native {
                creator: std::process::id(),
                input: slot.take().ok_or(Error::Interrupted)?,
                request,
                child: None,
                mounted: None,
                query: None,
                query_child: None,
                query_verified: None,
                query_accepted: None,
                step: Step::Intent,
                failure: None,
                #[cfg(test)]
                lab_anchor: Rc::new(()),
            }),
        };
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        #[cfg(test)]
        let trace = lab_trace::Trace::new(
            n.creator,
            "attachment_constructor",
            "mount_intent_queue",
            n.request.requested_at(),
            n.request.deadline(),
        );
        n.input.prepared.service().start_mount(&n.request)?;
        #[cfg(test)]
        trace.finish();
        Ok(pending)
    }
    pub(super) fn poll(&mut self) -> Result<Option<AttachedPrimary>> {
        let n = self.native.as_mut().ok_or(Error::Interrupted)?;
        if n.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = n.failure {
            n.collect();
            return Err(error);
        }
        if let Err(error) = n.advance() {
            n.fail(error);
            n.collect();
            return Err(error);
        }
        if !matches!(n.step, Step::Complete) {
            return Ok(None);
        }
        Ok(Some(AttachedPrimary {
            native: self.native.take(),
        }))
    }
}
impl Native {
    fn fail(&mut self, error: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failure.get_or_insert(error);
        self.input.prepared.service().fail(error);
        if let Some(child) = &mut self.child {
            child.cancel(error);
        }
        if let Some(child) = &mut self.query_child {
            child.cancel(error);
        }
    }
    fn collect(&mut self) {
        self.input.prepared.service().collect();
        if let Some(child) = &mut self.child {
            child.collect();
        }
        if let Some(child) = &mut self.query_child {
            child.collect();
        }
    }
    fn advance(&mut self) -> Result<()> {
        self.request.check()?;
        match self.step {
            Step::Intent => {
                if let Some(intent) = self
                    .input
                    .prepared
                    .service()
                    .poll_mount_intent(&self.request)?
                {
                    self.child = Some(super::super::kernel::namespace_attachment::spawn(
                        self.request.clone(),
                        intent,
                    )?);
                    self.input
                        .prepared
                        .service()
                        .start_mount_birth(self.child.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::Birth;
                }
            }
            Step::Birth => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(gate) = self
                    .input
                    .prepared
                    .service()
                    .poll_mount_gate(child, false)?
                {
                    child.release(gate, false)?;
                    self.step = Step::Placeholder;
                }
            }
            Step::Placeholder => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                if child.poll_placeholder()? {
                    self.input
                        .prepared
                        .service()
                        .start_mount_placeholder(child)?;
                    self.step = Step::PlaceholderWriting;
                }
            }
            Step::PlaceholderWriting => {
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(gate) = self.input.prepared.service().poll_mount_gate(child, true)? {
                    child.release(gate, true)?;
                    self.step = Step::Mounting;
                }
            }
            Step::Mounting => {
                if let Some(mounted) = self
                    .child
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .poll_mounted()?
                {
                    self.mounted = Some(mounted);
                    self.input
                        .prepared
                        .service()
                        .start_mounted(self.mounted.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::MountedWriting;
                }
            }
            Step::MountedWriting => {
                let mounted = self.mounted.as_ref().ok_or(Error::Interrupted)?;
                if self.input.prepared.service().poll_mounted(mounted)? {
                    self.request.revalidate_process()?;
                    self.query = Some(InspectionRequest::after_mount(
                        &self.input.prepared,
                        mounted.clone(),
                    )?);
                    self.input
                        .prepared
                        .service()
                        .start_inspection(self.query.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = Step::QueryIntent;
                }
            }
            Step::QueryIntent => {
                let query = self.query.as_ref().ok_or(Error::Interrupted)?;
                if let Some(intent) = self
                    .input
                    .prepared
                    .service()
                    .poll_inspection_intent(query)?
                {
                    self.query_child = Some(super::super::kernel::docker_query::spawn(
                        query.clone(),
                        intent,
                    )?);
                    self.input.prepared.service().start_inspection_birth(
                        self.query_child.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::QueryBirth;
                }
            }
            Step::QueryBirth => {
                let child = self.query_child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(gate) = self.input.prepared.service().poll_inspection_birth(child)? {
                    child.release(gate)?;
                    self.step = Step::QueryReading;
                }
            }
            Step::QueryReading => {
                if let Some(verified) = self
                    .query_child
                    .as_mut()
                    .ok_or(Error::Interrupted)?
                    .poll()?
                {
                    self.query_verified = Some(verified);
                    self.input.prepared.service().start_inspection_result(
                        self.query_verified.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = Step::QueryWriting;
                }
            }
            Step::QueryWriting => {
                if let Some(receipt) = self.input.prepared.service().poll_inspection_result(
                    self.query_verified.as_ref().ok_or(Error::Interrupted)?,
                )? {
                    self.query_accepted =
                        Some(super::super::kernel::docker_query::Verified::accept(
                            &mut self.query_verified,
                            receipt,
                        )?);
                    let accepted = self.query_accepted.as_ref().ok_or(Error::Interrupted)?;
                    if accepted.facts() != self.input.gateway._queries.1.facts() {
                        return Err(Error::OwnershipMismatch);
                    }
                    self.request.revalidate_process()?;
                    self.input.prepared.service().start_primary_publication(
                        self.mounted.as_ref().ok_or(Error::Interrupted)?.clone(),
                        accepted,
                    )?;
                    self.step = Step::Publishing;
                }
            }
            Step::Publishing => {
                let mounted = self.mounted.as_ref().ok_or(Error::Interrupted)?;
                if self
                    .input
                    .prepared
                    .service()
                    .poll_primary_publication(mounted)?
                {
                    self.request.revalidate_process()?;
                    self.step = Step::Complete;
                }
            }
            Step::Complete => {}
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn lab_descriptor() -> Result<String> {
    let (nonce, config, allocation, domains) = super::super::secret::lab_inputs_for(true)?;
    let bundle = super::super::programs::ReviewedBundle::current()?;
    let (digest, size) = bundle.init()?;
    let image_ref = &config.configuration().gateway_image;
    let content_id = image_ref
        .strip_prefix("vprouter-v2-lab@")
        .ok_or(Error::LabRequired)?;
    let staging = serde_json::json!({"schema_version":1,"image_ref":image_ref,"content_id":content_id,
        "os":"linux","architecture":if cfg!(target_arch="x86_64") {"amd64"} else {"arm64"},
        "artifact_kind":"actual_gateway_lab_v1","artifact_path":format!("/var/lib/vprouter-v2-lab/task8b2-{digest}.gateway-init"),
        "artifact_sha256":digest,"artifact_size":size,"worker_path":"/usr/local/bin/vprouter-worker"});
    super::super::StagingEvidence::parse_actual_gateway(
        &serde_json::to_vec(&staging).map_err(|_| Error::InvalidSpec)?,
    )?;
    let allocation_digest = vprouter_worker::bootstrap::digest(
        &serde_json::to_vec(&allocation).map_err(|_| Error::InvalidSpec)?,
    );
    let planned_host_link_index =
        vprouter_network::planned_host_link_index(&allocation, domains.exit_id())
            .map_err(|_| Error::InvalidSpec)?;
    serde_json::to_string(&serde_json::json!({"schema_version":1,"nonce":nonce,"owner_unit":domains.owner_unit(),
        "deployment_id":allocation.deployment_id,"primary":domains.exit_id(),"allocation":allocation,"allocation_digest":allocation_digest,"planned_host_link_index":planned_host_link_index,
        "configuration":"/var/lib/vprouter-v2-lab/secret-attachment.json",
        "spec":"/var/lib/vprouter-v2-lab/secret-attachment-spec.json",
        "staging_path":"/var/lib/vprouter-v2-lab/secret-attachment-staging.json","staging":staging,
        "image_ref":config.configuration().gateway_image,"artifact_kind":"actual_gateway_lab_v1",
        "artifact_path":format!("/var/lib/vprouter-v2-lab/task8b2-{digest}.gateway-init"),
        "artifact_sha256":digest,"artifact_size":size,"execution_policy_sha256":null,
        "worker_path":"/usr/local/bin/vprouter-worker","program_manifest_sha256":bundle.digest(),
        "profile_contents_read":false,"docker_queried":false,"container_required":true,"container_mounts_allowed":false,
        "production_startup_authorized":false})).map_err(|_| Error::InvalidSpec)
}
#[cfg(test)]
fn label(fault: u8) -> Result<&'static str> {
    match fault {
        0 => Ok("actual_secret_free_parent_existing_gateway_namespace_attachment"),
        1 => Ok("actual_namespace_attachment_placeholder_writer_failure_retains_original_context"),
        2 => Ok("actual_namespace_attachment_publication_writer_failure_retains_original_mount"),
        _ => Err(Error::InvalidSpec),
    }
}
#[cfg(test)]
pub(crate) fn lab_run(fault: u8) -> Result<()> {
    lab_run_inner(fault, false).map(|_| ())
}
#[cfg(test)]
pub(super) fn lab_attached() -> Result<(AttachedPrimary, serde_json::Value)> {
    lab_run_inner(0, true)?.ok_or(Error::OwnershipMismatch)
}
#[cfg(test)]
fn lab_run_inner(
    fault: u8,
    continue_transport: bool,
) -> Result<Option<(AttachedPrimary, serde_json::Value)>> {
    use std::{path::Path, time::Duration};
    let label = label(fault)?;
    let (_, prepared, validator) = super::super::secret::lab_prepare_attachment()?;
    let mut prepared = Some(prepared);
    lab_trace::arm();
    let mut inspection = PendingInspection::lab_initial(
        &mut prepared,
        Path::new("/var/lib/vprouter-v2-lab/secret-attachment-spec.json"),
        Path::new("/var/lib/vprouter-v2-lab/secret-attachment-staging.json"),
    )?;
    let inspected = loop {
        match inspection.poll() {
            Ok(Some(value)) => break value,
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(error) => {
                eprintln!("LAB_ATTACHMENT_FAILURE phase=inspection reason={error:?}");
                if let Some(n) = &mut inspection.native
                    && let Some(prepared) = &mut n.prepared
                {
                    lab_preparation_evidence(prepared);
                }
                return Err(error);
            }
        }
    };
    let mut handoff_trace = lab_trace::Trace::new(
        inspected.gateway.creator,
        "fixture_handoff",
        "query_receipt_evidence",
        inspected.gateway.requested_at,
        inspected.gateway.requested_at + 2.,
    );
    let first_query = inspected.gateway._queries.0.lab_evidence()?;
    let second_query = inspected.gateway._queries.1.lab_evidence()?;
    let inspection_requested_at = inspected.gateway.requested_at;
    let inspection_verified_at = inspected.gateway.verified_at;
    let mut inspected = Some(inspected);
    handoff_trace.step("pending_attachment_new");
    let mut pending = match PendingAttachment::new(&mut inspected) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("LAB_ATTACHMENT_FAILURE phase=pending_attachment_new reason={error:?}");
            eprintln!(
                "LAB_ATTACHMENT_ORIGINAL_QUERIES {}",
                serde_json::json!({
                "first": first_query, "second":second_query,
                "inspection_requested_at":inspection_requested_at,
                "inspection_verified_at":inspection_verified_at})
            );
            if let Some(value) = &mut inspected {
                lab_preparation_evidence(&mut value.prepared);
            }
            return Err(error);
        }
    };
    handoff_trace.finish();
    let native = pending.native.as_mut().ok_or(Error::Interrupted)?;
    let weak = Rc::downgrade(&native.lab_anchor);
    if fault != 0 {
        native
            .input
            .prepared
            .service()
            .lab_hold_attachment(if fault == 1 {
                "attachment_placeholder"
            } else {
                "attachment_primary"
            })?;
    }
    let mut held = false;
    let mut normal_ack_ready_preserved = false;
    let mut normal_ack_original = None;
    let tested_non_target_phase = match fault {
        1 => Some("attachment_birth"),
        2 => Some("attachment_placeholder"),
        _ => None,
    };
    let result = loop {
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        if !normal_ack_ready_preserved
            && (fault == 1 && matches!(n.step, Step::Birth)
                || fault == 2 && matches!(n.step, Step::PlaceholderWriting))
        {
            // Force the formerly racy interleaving: an ordinary ACK is already
            // readable BEFORE the checkpoint probe. No byte is consumed here.
            // The original writer/attachment end still bounds this wait.
            let ready = (|| -> Result<bool> {
                let Some(original) = n.input.prepared.service().lab_pending_writer_identity()?
                else {
                    return Ok(false); // The original continuation is still queued.
                };
                loop {
                    n.request.check()?;
                    if n.input.prepared.service().lab_ack_ready()? {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                if n.lab_target_checkpoint(fault)? {
                    return Err(Error::OwnershipMismatch);
                }
                if n.input.prepared.service().lab_pending_writer_identity()? != Some(original) {
                    return Err(Error::OwnershipMismatch);
                }
                normal_ack_original = Some(original);
                Ok(true)
            })();
            match ready {
                Err(error) => break Err(error),
                Ok(true) => normal_ack_ready_preserved = true,
                Ok(false) => {}
            }
        }
        match pending.poll() {
            Ok(Some(value)) => break Ok(value),
            Err(error) => break Err(error),
            Ok(None) => {}
        }
        let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
        match n.lab_target_checkpoint(fault) {
            Ok(false) => {}
            Ok(true) if !n.input.prepared.service().children_reaped() => {
                held = true;
                n.fail(Error::ChildFailed);
            }
            Ok(true) => break Err(Error::OwnershipMismatch),
            Err(error) => break Err(error),
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let (mut completed, mut failure) = match result {
        Ok(value) if fault == 0 => (Some(value), None),
        Ok(_) => return Err(Error::OwnershipMismatch),
        Err(error) => {
            let n = pending.native.as_mut().ok_or(Error::Interrupted)?;
            eprintln!(
                "LAB_ATTACHMENT_FAILURE phase={} reason={error:?} requested_at={} deadline={} now={}",
                n.lab_phase(),
                n.request.requested_at(),
                n.request.deadline(),
                vprouter_core::health::boot_seconds()
            );
            lab_preparation_evidence(&mut n.input.prepared);
            if fault == 0 || !held || error != Error::ChildFailed {
                return Err(error);
            }
            // Drain only. This separate fixture envelope grants no mutation,
            // successful receipt, or renewal of any original operation end.
            let end = vprouter_core::health::boot_seconds() + 2.;
            loop {
                n.collect();
                if n.input.prepared.service().children_reaped()
                    && n.child
                        .as_ref()
                        .is_none_or(super::super::kernel::namespace_attachment::Child::reaped)
                    && n.query_child
                        .as_ref()
                        .is_none_or(super::super::kernel::docker_query::Child::reaped)
                {
                    break;
                }
                if vprouter_core::health::boot_seconds() >= end {
                    return Err(Error::Deadline);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            (None, Some(error))
        }
    };
    let n = if let Some(value) = &mut completed {
        value.native.as_mut().ok_or(Error::Interrupted)?
    } else {
        pending.native.as_mut().ok_or(Error::Interrupted)?
    };
    let preparation = n.input.prepared.service().lab_evidence()?;
    let mount = if let Some(mounted) = &n.mounted {
        mounted.lab_evidence()?
    } else {
        n.child.as_ref().ok_or(Error::Interrupted)?.lab_evidence()?
    };
    let post_query = n
        .query_accepted
        .as_ref()
        .map(super::super::kernel::docker_query::Accepted::lab_evidence)
        .transpose()?;
    let (expected_status, expected_writers) = if fault == 1 { (9, 12) } else { (0, 17) };
    if !vprouter_core::secret_boundary::pristine()
        || mount["actual_wait_status"] != expected_status
        || mount["original_placeholder_retained"] != true
        || mount["original_mounted_namespace_retained"] != (fault != 1)
        || preparation["service_reserved"] != true
        || preparation["native_children_reaped"] != true
        || preparation["canonical_pending"] != (fault != 0)
        || preparation["mutation_fenced"] != (fault != 0)
        || preparation["base_network_absent"] != (fault != 0)
        || !preparation["transport_network"].is_null()
        || n.mounted.is_some() != (fault != 1)
        || post_query.is_some() != (fault != 1)
        || preparation["writers"]
            .as_array()
            .is_none_or(|writers| writers.len() != expected_writers)
    {
        return Err(Error::OwnershipMismatch);
    }
    let writers = preparation["writers"]
        .as_array()
        .ok_or(Error::OwnershipMismatch)?;
    let phases = [
        "intent",
        "birth",
        "result",
        "inspection_intent",
        "inspection_birth",
        "inspection_result",
        "inspection_intent",
        "inspection_birth",
        "inspection_result",
        "attachment_intent",
        "attachment_birth",
        "attachment_placeholder",
        "attachment_mounted",
        "attachment_query_intent",
        "attachment_query_birth",
        "attachment_query_result",
        "attachment_primary",
    ];
    for (index, writer) in writers.iter().enumerate() {
        let expected_end = if index < 3 {
            preparation["deadline"].as_f64()
        } else if index < 9 {
            Some(inspection_requested_at + 2.)
        } else {
            Some(n.request.deadline())
        };
        let end = expected_end.ok_or(Error::OwnershipMismatch)?;
        let queued = writer["queued_at"]
            .as_f64()
            .ok_or(Error::OwnershipMismatch)?;
        let failed_last = fault != 0 && index + 1 == writers.len();
        let timing_ok = if failed_last {
            writer["verified_at"].is_null()
        } else {
            writer["verified_at"]
                .as_f64()
                .is_some_and(|at| at.is_finite() && at >= queued && at < end)
        };
        if writer["phase"] != phases[index]
            || !end.is_finite()
            || !queued.is_finite()
            || queued < end - 2.
            || queued >= end
            || !timing_ok
            || writer["io_deadline"].as_f64() != expected_end
            || writer["parent_deadline"].as_f64() != expected_end
            || writer["actual_wait_status"]
                != if fault != 0 && index + 1 == writers.len() {
                    9
                } else {
                    0
                }
            || !(fault != 0 && index + 1 == writers.len())
                && !writer["verified_at"]
                    .as_f64()
                    .is_some_and(|t| t < expected_end.unwrap_or(0.))
        {
            return Err(Error::OwnershipMismatch);
        }
    }
    if fault == 0
        && (preparation["base_network"] != mount["original_source"]
            || preparation["data_network"] != mount["original_source"]
            || preparation["attachment"]["published_at"].is_null())
    {
        return Err(Error::OwnershipMismatch);
    }
    if fault != 0 && !normal_ack_ready_preserved {
        return Err(Error::OwnershipMismatch);
    }
    let normal_ack_writer = if let Some((index, pid, start)) = normal_ack_original {
        let writer = writers.get(index).ok_or(Error::OwnershipMismatch)?;
        if writer["pid"] != pid
            || writer["start"] != start
            || writer["phase"] != tested_non_target_phase.ok_or(Error::OwnershipMismatch)?
            || writer["actual_wait_status"] != 0
            || writer["verified_at"].is_null()
        {
            return Err(Error::OwnershipMismatch);
        }
        Some(serde_json::json!({"index":index,"pid":pid,"start":start}))
    } else {
        None
    };
    let witness = serde_json::json!({"schema":1,"fault":fault,"validator":validator,"preparation":preparation,
        "inspection_requested_at":inspection_requested_at,"inspection_deadline":inspection_requested_at+2.,
        "inspection_verified_at":inspection_verified_at,"first_query":first_query,"second_query":second_query,
        "mount":mount,"postmount_query":post_query,"parent_pristine":true,"same_service_retained":true,
        "held_real_writer":held,"whole_failed_driver_retained_after_drop":fault!=0,
        "normal_ack_ready_preserved":normal_ack_ready_preserved,
        "tested_non_target_phase":tested_non_target_phase,
        "normal_ack_writer":normal_ack_writer,
        "original_mount_retained":fault!=1,"base_published":fault==0,
        "namespace_cleanup_or_operational_reuse_authorized":false,"requirement8_complete":false});
    if continue_transport {
        if fault != 0 || failure.is_some() {
            return Err(Error::OwnershipMismatch);
        }
        return Ok(Some((completed.take().ok_or(Error::Interrupted)?, witness)));
    }
    if failure.take().is_some() {
        drop(pending);
        if weak.upgrade().is_none() {
            return Err(Error::OwnershipMismatch);
        }
    } else {
        // Keep the complete successful custody as well; this fixture grants no
        // cleanup/unmount/reuse and does not yet construct transport resources.
        drop(completed.take());
        if weak.upgrade().is_none() {
            return Err(Error::OwnershipMismatch);
        }
    }
    println!("{}", serde_json::json!({"case":label,"result":"PASS"}));
    println!("LAB_SECRET_ATTACHMENT {witness}");
    Ok(None)
}
#[cfg(test)]
impl Native {
    fn lab_target_checkpoint(&mut self, fault: u8) -> Result<bool> {
        // The checkpoint byte belongs only to the deliberately held writer.
        // This guard must precede IO: a normal ready ACK is not byte127.
        if fault == 1 && matches!(self.step, Step::PlaceholderWriting)
            || fault == 2 && matches!(self.step, Step::Publishing)
        {
            self.input.prepared.service().lab_checkpoint()
        } else {
            Ok(false)
        }
    }
    fn lab_phase(&self) -> &'static str {
        match self.step {
            Step::Intent => "intent",
            Step::Birth => "birth",
            Step::Placeholder => "placeholder",
            Step::PlaceholderWriting => "placeholder_writing",
            Step::Mounting => "mounting",
            Step::MountedWriting => "mounted_writing",
            Step::QueryIntent => "query_intent",
            Step::QueryBirth => "query_birth",
            Step::QueryReading => "query_reading",
            Step::QueryWriting => "query_writing",
            Step::Publishing => "publishing",
            Step::Complete => "complete",
        }
    }
}

#[cfg(test)]
fn lab_preparation_evidence(prepared: &mut PreparedValidation) {
    // The first scalar failure marker is already emitted. Evidence failure may
    // not suppress it or replace the original operation's failure reason.
    match prepared.service().lab_evidence() {
        Ok(value) => eprintln!("LAB_ATTACHMENT_PREPARATION {value}"),
        Err(error) => eprintln!("LAB_ATTACHMENT_PREPARATION_ERROR reason={error:?}"),
    }
}
