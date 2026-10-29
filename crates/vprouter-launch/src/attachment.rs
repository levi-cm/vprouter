#![forbid(unsafe_code)]
//! Existing admitted gateway attachment is a distinct origin from fresh native
//! container creation. Neither parsed history nor an observed namespace creates
//! a placement or mount capability here.
use super::{Admission, Error, Result, owned::Identity, secret::PreparedValidation};
use serde::{Deserialize, Serialize};
use std::{path::Path, rc::Rc};
pub(crate) mod assembly;
pub(crate) mod host_addition;
mod host_baseline;
mod host_declaration;
pub(crate) mod mount;
pub(crate) mod movement;
pub(crate) mod operational;
pub(crate) mod producer_binding;
pub(crate) mod provision;
pub(crate) mod quarantine;
pub(crate) mod transport;

// A unit-test-only stop at the first fixture input boundary. It can only refuse
// work, never supply an input, receipt, clock or native authority. Ordinary lab
// invocations leave it unarmed and execute the existing path unchanged.
#[cfg(test)]
thread_local! {
    static ENTRY_PROBE: std::cell::Cell<(Option<u32>, bool)> = const { std::cell::Cell::new((None, false)) };
}
#[cfg(test)]
pub(super) fn lab_stop_before_inputs() -> bool {
    ENTRY_PROBE.with(|state| {
        let armed = state.get().0 == Some(std::process::id());
        if armed {
            state.set((Some(std::process::id()), true));
        }
        armed
    })
}

#[cfg(test)]
#[test]
fn nested_host_fixture_reaches_input_boundary_on_bounded_stack() {
    std::thread::Builder::new()
        .name("bounded-host-entry".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            struct Disarm;
            impl Drop for Disarm {
                fn drop(&mut self) {
                    ENTRY_PROBE.with(|state| state.set((None, false)));
                }
            }
            assert!(!lab_stop_before_inputs());
            let guard = Disarm;
            ENTRY_PROBE.with(|state| state.set((Some(std::process::id()), false)));
            let result = host_addition::lab_run(3);
            let reached = ENTRY_PROBE.with(|state| state.get().1);
            assert!(
                reached,
                "the original deepest fixture input boundary was not reached"
            );
            assert!(matches!(result, Err(Error::LabRequired)));
            drop(guard);
            assert!(!lab_stop_before_inputs());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(test)]
#[test]
fn nested_bootstrap_fixture_reaches_input_boundary_on_bounded_stack() {
    std::thread::Builder::new()
        .name("bounded-bootstrap-entry".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(|| {
            struct Disarm;
            impl Drop for Disarm {
                fn drop(&mut self) {
                    ENTRY_PROBE.with(|state| state.set((None, false)));
                }
            }
            assert!(!lab_stop_before_inputs());
            let guard = Disarm;
            ENTRY_PROBE.with(|state| state.set((Some(std::process::id()), false)));
            let result = operational::bootstrap::lab_run(0);
            let reached = ENTRY_PROBE.with(|state| state.get().1);
            assert!(
                reached,
                "the original deepest fixture input boundary was not reached"
            );
            assert!(matches!(result, Err(Error::LabRequired)));
            drop(guard);
            assert!(!lab_stop_before_inputs());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[cfg(test)]
#[test]
fn continuation_handles_do_not_inline_the_retained_owner_chain() {
    // Each continuation moves exclusive ownership of its complete retained
    // bundle. Embedding the predecessor inline compounds every caller frame.
    let sizes = [
        (
            "operational",
            std::mem::size_of::<operational::OperationalOwner>(),
        ),
        (
            "pending bootstrap",
            std::mem::size_of::<operational::bootstrap::PendingBootstrap>(),
        ),
        (
            "bootstrap",
            std::mem::size_of::<operational::bootstrap::BootstrappedOwner>(),
        ),
        (
            "provision",
            std::mem::size_of::<provision::ProvisionedTransport>(),
        ),
        (
            "pending provision",
            std::mem::size_of::<provision::PendingProvision>(),
        ),
        ("movement", std::mem::size_of::<movement::MovedPrimary>()),
        (
            "pending movement",
            std::mem::size_of::<movement::PendingMovement>(),
        ),
        (
            "quarantine",
            std::mem::size_of::<quarantine::QuarantinedPrimary>(),
        ),
        (
            "pending quarantine",
            std::mem::size_of::<quarantine::PendingQuarantine>(),
        ),
        (
            "producer",
            std::mem::size_of::<quarantine::producer::PreparedProducer>(),
        ),
        ("assembly", std::mem::size_of::<assembly::Assembly>()),
        (
            "binding",
            std::mem::size_of::<producer_binding::ProducerBoundAssembly>(),
        ),
        (
            "pending binding",
            std::mem::size_of::<producer_binding::PendingBinding>(),
        ),
        (
            "baseline",
            std::mem::size_of::<host_addition::ObservedHostAssembly>(),
        ),
        (
            "pending baseline",
            std::mem::size_of::<host_addition::PendingHostBaseline>(),
        ),
        (
            "host",
            std::mem::size_of::<host_addition::HostAddedPrimary>(),
        ),
    ];
    for (name, size) in sizes {
        assert_eq!(
            size,
            std::mem::size_of::<usize>(),
            "{name} retains {size} inline bytes"
        );
    }
    assert!(std::mem::size_of::<host_addition::PendingHostAddition>() <= 64);
}

// Parent-only bounded fixture diagnostics. No diagnostic clock supplies authority.
#[cfg(test)]
pub(crate) mod lab_trace {
    use std::cell::Cell;
    thread_local! {
        static OWNER: Cell<Option<u32>> = const { Cell::new(None) };
        static LEFT: Cell<u8> = const { Cell::new(48) };
    }
    pub(super) fn arm() {
        OWNER.with(|owner| owner.set(Some(std::process::id())));
    }
    fn enabled(creator: u32) -> bool {
        creator == std::process::id() && OWNER.with(|owner| owner.get() == Some(creator))
    }
    fn emit(creator: u32, value: serde_json::Value) {
        if !enabled(creator) {
            return;
        }
        if LEFT.with(|left| {
            let n = left.get();
            left.set(n.saturating_sub(1));
            n != 0
        }) {
            eprintln!("LAB_ATTACHMENT_PHASE {value}");
        }
    }
    pub(super) fn failure(
        creator: u32,
        scope: &'static str,
        phase: &'static str,
        requested_at: f64,
        deadline: f64,
        reason: super::Error,
    ) {
        if !enabled(creator) {
            return;
        }
        emit(
            creator,
            serde_json::json!({"scope":scope,"phase":phase,"ok":false,
            "reason":format!("{reason:?}"),"original_requested_at":requested_at,
            "original_deadline":deadline,"finished_at":vprouter_core::health::boot_seconds()}),
        );
    }
    pub(crate) struct Trace {
        creator: u32,
        scope: &'static str,
        phase: &'static str,
        requested_at: f64,
        deadline: f64,
        started_at: f64,
        active: bool,
    }
    impl Trace {
        pub(crate) fn new(
            creator: u32,
            scope: &'static str,
            phase: &'static str,
            requested_at: f64,
            deadline: f64,
        ) -> Self {
            let active = enabled(creator);
            Self {
                creator,
                scope,
                phase,
                requested_at,
                deadline,
                started_at: if active {
                    vprouter_core::health::boot_seconds()
                } else {
                    0.
                },
                active,
            }
        }
        fn record(&mut self, ok: bool) {
            if !self.active || !enabled(self.creator) {
                return;
            }
            let now = vprouter_core::health::boot_seconds();
            emit(
                self.creator,
                serde_json::json!({"scope":self.scope,"phase":self.phase,"ok":ok,
                "original_requested_at":self.requested_at,"original_deadline":self.deadline,
                "started_at":self.started_at,"finished_at":now}),
            );
            self.started_at = now;
        }
        pub(crate) fn step(&mut self, phase: &'static str) {
            self.record(true);
            self.phase = phase;
        }
        pub(crate) fn finish(mut self) {
            self.record(true);
            self.active = false;
        }
    }
    impl Drop for Trace {
        fn drop(&mut self) {
            self.record(false);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Origin {
    ExistingAdmitted {
        launch: String,
        staging: String,
        container: String,
        process_start: u64,
        network: Identity,
        public_result: [u8; 32],
    },
}
impl Origin {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::ExistingAdmitted {
                launch,
                staging,
                container,
                process_start,
                network,
                public_result,
            } if super::spec::digest(launch)
                && super::spec::digest(staging)
                && super::spec::digest(container)
                && *process_start > 0
                && network.ino > 0
                && *public_result != [0; 32] =>
            {
                Ok(())
            }
            _ => Err(Error::OwnershipMismatch),
        }
    }
}
/// Retains the exact Admission and constructor-origin public-result binding.
/// This only finishes read-only admission; a durable attachment intent and fixed
/// native receipt are still required before the primary base can be published.
pub(super) struct ExistingGateway {
    creator: u32,
    admission: Rc<Admission>,
    binding: super::owned::preparation::PublicBinding,
    origin: Origin,
    requested_at: f64,
    verified_at: f64,
    _queries: (
        super::kernel::docker_query::Accepted,
        super::kernel::docker_query::Accepted,
    ),
}
/// Public request custody before the first Docker byte is read. The raw query
/// executes only in the fixed no-fork role; a deserialized scalar response never
/// creates ExistingGateway or Admission.
pub(crate) struct InspectionRequest {
    creator: u32,
    pub(crate) spec: super::LaunchSpec,
    pub(crate) staging: super::StagingEvidence,
    binding: super::owned::preparation::PublicBinding,
    requested_at: f64,
    digest: [u8; 32],
    kind: QueryKind,
    mounted: Option<Rc<super::kernel::namespace_attachment::Mounted>>,
    movement: Option<Rc<super::owned::preparation::movement::Binding>>,
    quarantine: Option<Rc<super::owned::preparation::quarantine::Binding>>,
}

pub(super) struct PendingInspection {
    native: Option<InspectionNative>,
}
struct InspectionNative {
    creator: u32,
    prepared: Option<PreparedValidation>,
    request: Rc<InspectionRequest>,
    child: Option<super::kernel::docker_query::Child>,
    verified: Option<super::kernel::docker_query::Verified>,
    initial: Option<super::kernel::docker_query::Accepted>,
    recheck: Option<super::kernel::docker_query::Accepted>,
    process: Option<super::process::PinnedProcess>,
    gateway: Option<ExistingGateway>,
    step: InspectionStep,
    failure: Option<Error>,
    #[cfg(test)]
    lab_phase: &'static str,
}
#[derive(Clone, Copy)]
enum InspectionStep {
    Intent,
    Birth,
    Reading,
    Result,
    Complete,
}
pub(super) struct InspectedPreparation {
    prepared: PreparedValidation,
    gateway: ExistingGateway,
}
thread_local! { static RETAINED: std::cell::RefCell<Vec<InspectionNative>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl Drop for PendingInspection {
    fn drop(&mut self) {
        if let Some(mut native) = self.native.take() {
            if native.creator != std::process::id() {
                return;
            }
            native.fail(Error::Interrupted);
            RETAINED.with(|retained| retained.borrow_mut().push(native));
        }
    }
}
pub(super) fn poll_retained() {
    mount::poll_retained();
    transport::poll_retained();
    provision::poll_retained();
    movement::poll_retained();
    quarantine::poll_retained();
    assembly::poll_retained();
    producer_binding::poll_retained();
    host_addition::poll_retained();
    operational::poll_retained();
    RETAINED.with(|retained| {
        for native in retained.borrow_mut().iter_mut() {
            if native.creator == std::process::id() {
                native.collect();
            }
        }
    });
}
pub(super) fn retained_children_reaped() -> bool {
    mount::children_reaped()
        && transport::children_reaped()
        && provision::children_reaped()
        && movement::children_reaped()
        && quarantine::children_reaped()
        && assembly::children_reaped()
        && producer_binding::children_reaped()
        && host_addition::children_reaped()
        && operational::children_reaped()
        && RETAINED.with(|retained| {
            retained.borrow_mut().iter_mut().all(|native| {
                native.creator != std::process::id()
                    || native
                        .prepared
                        .as_mut()
                        .is_some_and(|p| p.service().children_reaped())
                        && native
                            .child
                            .as_ref()
                            .is_none_or(super::kernel::docker_query::Child::reaped)
            })
        })
}
impl PendingInspection {
    /// Validate all identities before consuming the original preparation. A
    /// startup error after consumption is retained as the complete driver.
    pub(super) fn initial(
        slot: &mut Option<PreparedValidation>,
        spec: &Path,
        staging: &Path,
    ) -> Result<Self> {
        let prepared = slot.as_ref().ok_or(Error::Interrupted)?;
        super::process::host_preflight()?;
        let request = Rc::new(InspectionRequest::initial(prepared, spec, staging)?);
        Self::start(slot, request)
    }
    #[cfg(test)]
    pub(super) fn lab_initial(
        slot: &mut Option<PreparedValidation>,
        spec: &Path,
        staging: &Path,
    ) -> Result<Self> {
        let prepared = slot.as_ref().ok_or(Error::Interrupted)?;
        super::process::host_preflight()?;
        let requested_at = InspectionRequest::start_clock()?;
        let mut trace = lab_trace::Trace::new(
            std::process::id(),
            "initial_load",
            "protected_spec",
            requested_at,
            requested_at + 2.,
        );
        let spec = super::LaunchSpec::load(spec)?;
        trace.step("protected_staging");
        let staging = super::StagingEvidence::load_actual_gateway(staging)?;
        trace.step("initial_request");
        let request = Rc::new(InspectionRequest::from_loaded(
            prepared,
            spec,
            staging,
            requested_at,
        )?);
        trace.step("initial_intent_queue");
        let pending = Self::start(slot, request)?;
        trace.finish();
        Ok(pending)
    }
    fn start(
        slot: &mut Option<PreparedValidation>,
        request: Rc<InspectionRequest>,
    ) -> Result<Self> {
        let mut value = Self {
            native: Some(InspectionNative {
                creator: std::process::id(),
                prepared: slot.take(),
                request,
                child: None,
                verified: None,
                initial: None,
                recheck: None,
                process: None,
                gateway: None,
                step: InspectionStep::Intent,
                failure: None,
                #[cfg(test)]
                lab_phase: "start",
            }),
        };
        let native = value.native.as_mut().ok_or(Error::Interrupted)?;
        native
            .prepared
            .as_mut()
            .ok_or(Error::Interrupted)?
            .service()
            .start_inspection(&native.request)?;
        Ok(value)
    }
    pub(super) fn poll(&mut self) -> Result<Option<InspectedPreparation>> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        if native.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(error) = native.failure {
            native.collect();
            return Err(error);
        }
        if let Err(error) = native.advance() {
            #[cfg(test)]
            lab_trace::failure(
                native.creator,
                if native.request.kind() == QueryKind::Initial {
                    "initial_inspection"
                } else {
                    "recheck_inspection"
                },
                native.lab_phase,
                native.request.requested_at(),
                native.request.deadline(),
                error,
            );
            native.fail(error);
            native.collect();
            return Err(error);
        }
        if !matches!(native.step, InspectionStep::Complete) {
            return Ok(None);
        }
        if native.gateway.is_none() || native.prepared.is_none() {
            native.fail(Error::Interrupted);
            return Err(Error::Interrupted);
        }
        let mut native = self.native.take().ok_or(Error::Interrupted)?;
        Ok(Some(InspectedPreparation {
            prepared: native.prepared.take().ok_or(Error::Interrupted)?,
            gateway: native.gateway.take().ok_or(Error::Interrupted)?,
        }))
    }
}
impl InspectionNative {
    fn fail(&mut self, error: Error) {
        self.failure.get_or_insert(error);
        if let Some(prepared) = &mut self.prepared {
            prepared.service().fail(error);
        }
        if let Some(child) = &mut self.child {
            child.cancel(error);
        }
    }
    fn collect(&mut self) {
        if let Some(prepared) = &mut self.prepared {
            prepared.service().collect();
        }
        if let Some(child) = &mut self.child {
            child.collect();
        }
    }
    fn advance(&mut self) -> Result<()> {
        #[cfg(test)]
        {
            self.lab_phase = "entry_global_stop";
        }
        super::kernel::owner_admission_permitted()?;
        if !vprouter_core::secret_boundary::pristine() {
            return Err(Error::ConfinementPolicy);
        }
        #[cfg(test)]
        {
            self.lab_phase = "entry_deadline";
        }
        self.request.check_deadline()?;
        let prepared = self.prepared.as_mut().ok_or(Error::Interrupted)?;
        match self.step {
            InspectionStep::Intent => {
                #[cfg(test)]
                {
                    self.lab_phase = "intent_poll";
                }
                if let Some(intent) = prepared.service().poll_inspection_intent(&self.request)? {
                    self.child = Some(super::kernel::docker_query::spawn(
                        self.request.clone(),
                        intent,
                    )?);
                    prepared
                        .service()
                        .start_inspection_birth(self.child.as_ref().ok_or(Error::Interrupted)?)?;
                    self.step = InspectionStep::Birth;
                }
            }
            InspectionStep::Birth => {
                #[cfg(test)]
                {
                    self.lab_phase = "birth_poll";
                }
                let child = self.child.as_mut().ok_or(Error::Interrupted)?;
                if let Some(gate) = prepared.service().poll_inspection_birth(child)? {
                    child.release(gate)?;
                    self.step = InspectionStep::Reading;
                }
            }
            InspectionStep::Reading => {
                #[cfg(test)]
                {
                    self.lab_phase = "reading_poll";
                }
                if let Some(verified) = self.child.as_mut().ok_or(Error::Interrupted)?.poll()? {
                    self.verified = Some(verified);
                    prepared.service().start_inspection_result(
                        self.verified.as_ref().ok_or(Error::Interrupted)?,
                    )?;
                    self.step = InspectionStep::Result;
                }
            }
            InspectionStep::Result => {
                #[cfg(test)]
                {
                    self.lab_phase = "result_poll";
                }
                if let Some(receipt) = prepared
                    .service()
                    .poll_inspection_result(self.verified.as_ref().ok_or(Error::Interrupted)?)?
                {
                    #[cfg(test)]
                    let mut trace = lab_trace::Trace::new(
                        self.creator,
                        if self.request.kind() == QueryKind::Initial {
                            "initial_result"
                        } else {
                            "recheck_result"
                        },
                        "accept_original_query",
                        self.request.requested_at(),
                        self.request.deadline(),
                    );
                    let accepted =
                        super::kernel::docker_query::Verified::accept(&mut self.verified, receipt)?;
                    if self.request.kind() == QueryKind::Initial {
                        self.initial = Some(accepted);
                        #[cfg(test)]
                        trace.step("open_native_process");
                        self.process = Some(super::process::PinnedProcess::open_query(
                            self.initial.as_ref().ok_or(Error::Interrupted)?,
                        )?);
                        // Same native checks as Admission::revalidate BEFORE
                        // the second fresh daemon/container policy query.
                        #[cfg(test)]
                        trace.step("native_process_revalidate");
                        self.process
                            .as_ref()
                            .ok_or(Error::Interrupted)?
                            .revalidate(&self.request.spec, &self.request.staging)?;
                        #[cfg(test)]
                        trace.step("recheck_request_binding");
                        self.request = Rc::new(self.request.recheck(prepared)?);
                        #[cfg(test)]
                        trace.step("recheck_intent_queue");
                        prepared.service().start_inspection(&self.request)?;
                        self.step = InspectionStep::Intent;
                    } else {
                        self.recheck = Some(accepted);
                        #[cfg(test)]
                        trace.step("old_queries_require_and_equality");
                        let initial = self.initial.as_ref().ok_or(Error::Interrupted)?;
                        let recheck = self.recheck.as_ref().ok_or(Error::Interrupted)?;
                        initial.require()?;
                        recheck.require()?;
                        if initial.facts() != recheck.facts() {
                            return Err(Error::ProcessChanged);
                        }
                        #[cfg(test)]
                        trace.step("native_process_revalidate");
                        self.process
                            .as_ref()
                            .ok_or(Error::Interrupted)?
                            .revalidate(&self.request.spec, &self.request.staging)?;
                        #[cfg(test)]
                        trace.step("request_binding_verify");
                        self.request.verify(prepared)?;
                        #[cfg(test)]
                        trace.step("network_identity_and_origin_hash");
                        let network = Identity::network(
                            self.process
                                .as_ref()
                                .ok_or(Error::Interrupted)?
                                .base_network(),
                        )?;
                        let origin = Origin::ExistingAdmitted {
                            launch: vprouter_worker::bootstrap::digest(
                                &serde_json::to_vec(&self.request.spec)
                                    .map_err(|_| Error::InvalidSpec)?,
                            ),
                            staging: vprouter_worker::bootstrap::digest(
                                &serde_json::to_vec(&self.request.staging)
                                    .map_err(|_| Error::InvalidSpec)?,
                            ),
                            container: self.request.spec.container_id.clone(),
                            process_start: self.request.spec.process_start_time,
                            network,
                            public_result: self.request.binding.public_result(),
                        };
                        #[cfg(test)]
                        trace.step("staging_copy_and_public_binding");
                        let staging = serde_json::from_slice(
                            &serde_json::to_vec(&self.request.staging)
                                .map_err(|_| Error::InvalidSpec)?,
                        )
                        .map_err(|_| Error::InvalidSpec)?;
                        let binding = prepared.bind_public()?;
                        // Capture only AFTER every policy/native/binding/hash
                        // operation. No earlier timestamp certifies later work.
                        #[cfg(test)]
                        trace.step("final_original_deadline");
                        self.request.check_deadline()?;
                        let verified_at = vprouter_core::health::boot_seconds();
                        if !verified_at.is_finite() || verified_at >= self.request.deadline() {
                            return Err(Error::Deadline);
                        }
                        let security = recheck.facts().security;
                        let admission = Rc::new(Admission {
                            process: self.process.take().ok_or(Error::Interrupted)?,
                            spec: self.request.spec.clone(),
                            staging,
                            daemon_security: security,
                        });
                        self.gateway = Some(ExistingGateway {
                            creator: self.creator,
                            admission,
                            binding,
                            origin,
                            requested_at: self.request.requested_at(),
                            verified_at,
                            _queries: (
                                self.initial.take().ok_or(Error::Interrupted)?,
                                self.recheck.take().ok_or(Error::Interrupted)?,
                            ),
                        });
                        self.step = InspectionStep::Complete;
                    }
                    #[cfg(test)]
                    trace.finish();
                }
            }
            InspectionStep::Complete => {}
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum QueryKind {
    Initial,
    Recheck,
    AttachmentRecheck,
    MovementRecheck,
    QuarantineRecheck,
    ProducerRecheck,
    ProducerBindingRecheck,
    BootstrapHostRecheck,
    BootstrapTransportRecheck,
    BootstrapDataRecheck,
}
impl QueryKind {
    pub(crate) fn bootstrap_index(self) -> Option<usize> {
        match self {
            Self::BootstrapHostRecheck => Some(0),
            Self::BootstrapTransportRecheck => Some(1),
            Self::BootstrapDataRecheck => Some(2),
            _ => None,
        }
    }

    pub(crate) fn includes_image(self) -> bool {
        matches!(
            self,
            Self::Initial
                | Self::MovementRecheck
                | Self::QuarantineRecheck
                | Self::ProducerRecheck
                | Self::ProducerBindingRecheck
                | Self::BootstrapHostRecheck
                | Self::BootstrapTransportRecheck
                | Self::BootstrapDataRecheck
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueryFacts {
    pub(crate) pid: u32,
    pub(crate) security: super::evidence::DaemonSecurity,
}
impl InspectionRequest {
    fn after_mount(
        prepared: &PreparedValidation,
        mounted: Rc<super::kernel::namespace_attachment::Mounted>,
    ) -> Result<Rc<Self>> {
        mounted.verify_current()?;
        let original = mounted.request();
        let binding = prepared.bind_public()?;
        binding.verify_initial_except_mount(
            prepared.inspection_service(),
            original.spec(),
            &mounted,
        )?;
        let staging = serde_json::from_slice(
            &serde_json::to_vec(original.staging()).map_err(|_| Error::InvalidSpec)?,
        )
        .map_err(|_| Error::InvalidSpec)?;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                original.spec(),
                &staging,
                binding.public_result(),
                QueryKind::AttachmentRecheck,
                original.digest(),
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let request = Rc::new(Self {
            creator: std::process::id(),
            spec: original.spec().clone(),
            staging,
            binding,
            requested_at: original.requested_at(),
            digest,
            kind: QueryKind::AttachmentRecheck,
            mounted: Some(mounted),
            movement: None,
            quarantine: None,
        });
        request.verify(prepared)?;
        Ok(request)
    }
    pub(crate) fn matches_mount(
        &self,
        mounted: &super::kernel::namespace_attachment::Mounted,
    ) -> Result<bool> {
        self.check_deadline()?;
        Ok(self.kind == QueryKind::AttachmentRecheck
            && self.mounted.as_ref().is_some_and(|original| {
                std::ptr::eq(original.as_ref(), mounted)
                    && self.requested_at == original.request().requested_at()
            }))
    }
    pub(crate) fn verify_service(&self, server: &super::owned::preparation::Server) -> Result<()> {
        if let Some(quarantine) = &self.quarantine {
            if !matches!(
                self.kind,
                QueryKind::QuarantineRecheck
                    | QueryKind::ProducerRecheck
                    | QueryKind::ProducerBindingRecheck
                    | QueryKind::BootstrapHostRecheck
                    | QueryKind::BootstrapTransportRecheck
                    | QueryKind::BootstrapDataRecheck
            ) || self.mounted.is_some()
                || self.movement.is_some()
            {
                return Err(Error::OwnershipMismatch);
            }
            self.check_deadline()?;
            quarantine.verify(server)?;
            return self.check_deadline();
        }
        if matches!(
            self.kind,
            QueryKind::QuarantineRecheck
                | QueryKind::ProducerRecheck
                | QueryKind::ProducerBindingRecheck
                | QueryKind::BootstrapHostRecheck
                | QueryKind::BootstrapTransportRecheck
                | QueryKind::BootstrapDataRecheck
        ) {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(movement) = &self.movement {
            if self.kind != QueryKind::MovementRecheck || self.mounted.is_some() {
                return Err(Error::OwnershipMismatch);
            }
            self.check_deadline()?;
            movement.verify(server)?;
            return self.check_deadline();
        }
        if self.kind == QueryKind::MovementRecheck {
            return Err(Error::OwnershipMismatch);
        }
        if let Some(mounted) = &self.mounted {
            if !self.matches_mount(mounted)? {
                return Err(Error::OwnershipMismatch);
            }
            self.binding
                .verify_initial_except_mount(server, &self.spec, mounted)
        } else {
            if self.kind == QueryKind::AttachmentRecheck {
                return Err(Error::OwnershipMismatch);
            }
            self.binding.verify_initial(server, &self.spec)
        }
    }
    /// Startup-only, with no established neighbor. Dynamic public metadata pin
    /// acquisition will use retained async admission before it can call this.
    pub(crate) fn initial(
        prepared: &PreparedValidation,
        spec_path: &Path,
        staging_path: &Path,
    ) -> Result<Self> {
        let requested_at = Self::start_clock()?;
        let (spec, staging) = super::load(spec_path, staging_path)?;
        Self::from_loaded(prepared, spec, staging, requested_at)
    }
    fn start_clock() -> Result<f64> {
        super::process::single_threaded()?;
        super::kernel::owner_admission_permitted()?;
        if !vprouter_core::secret_boundary::pristine() {
            return Err(Error::ConfinementPolicy);
        }
        let requested_at = vprouter_core::health::boot_seconds();
        if !requested_at.is_finite() || requested_at <= 0. {
            return Err(Error::Deadline);
        }
        Ok(requested_at)
    }
    fn from_loaded(
        prepared: &PreparedValidation,
        spec: super::LaunchSpec,
        staging: super::StagingEvidence,
        requested_at: f64,
    ) -> Result<Self> {
        #[cfg(test)]
        let mut trace = lab_trace::Trace::new(
            std::process::id(),
            "initial_request",
            "public_binding",
            requested_at,
            requested_at + 2.,
        );
        let binding = prepared.bind_public()?;
        #[cfg(test)]
        trace.step("spec_staging_binding");
        spec.bind_staging(&staging)?;
        #[cfg(test)]
        trace.step("canonical_initial_binding");
        prepared.verify_initial_binding(&binding, &spec)?;
        if spec.image_ref != prepared.configuration().configuration().gateway_image {
            return Err(Error::ImageMismatch);
        }
        #[cfg(test)]
        trace.step("public_request_digest");
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(&spec, &staging, binding.public_result(), QueryKind::Initial))
                .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let request = Self {
            creator: std::process::id(),
            spec,
            staging,
            binding,
            requested_at,
            digest,
            kind: QueryKind::Initial,
            mounted: None,
            movement: None,
            quarantine: None,
        };
        #[cfg(test)]
        trace.step("final_request_binding");
        request.verify(prepared)?;
        #[cfg(test)]
        trace.finish();
        Ok(request)
    }
    pub(crate) fn verify(&self, prepared: &PreparedValidation) -> Result<()> {
        if self.creator != std::process::id() || !vprouter_core::secret_boundary::pristine() {
            return Err(Error::ConfinementPolicy);
        }
        super::kernel::owner_admission_permitted()?;
        prepared.bind_public()?;
        self.verify_service(prepared.inspection_service())?;
        self.check_deadline()
    }
    pub(crate) fn check_deadline(&self) -> Result<()> {
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now < self.requested_at || now >= self.deadline() {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    pub(crate) fn requested_at(&self) -> f64 {
        self.requested_at
    }
    pub(crate) fn deadline(&self) -> f64 {
        self.requested_at + 2.
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn binding(&self) -> &super::owned::preparation::PublicBinding {
        &self.binding
    }
    pub(crate) fn kind(&self) -> QueryKind {
        self.kind
    }
    pub(crate) fn require_quarantine_origin(
        &self,
        binding: &Rc<super::owned::preparation::quarantine::Binding>,
    ) -> Result<()> {
        if self.creator != std::process::id()
            || !matches!(
                self.kind,
                QueryKind::QuarantineRecheck
                    | QueryKind::ProducerBindingRecheck
                    | QueryKind::BootstrapHostRecheck
                    | QueryKind::BootstrapTransportRecheck
                    | QueryKind::BootstrapDataRecheck
            )
            || !self
                .quarantine
                .as_ref()
                .is_some_and(|b| Rc::ptr_eq(b, binding))
        {
            return Err(Error::OwnershipMismatch);
        }
        self.check_deadline()
    }
    fn recheck(&self, prepared: &PreparedValidation) -> Result<Self> {
        self.verify(prepared)?;
        if self.kind != QueryKind::Initial {
            return Err(Error::OwnershipMismatch);
        }
        // Reparse ONLY the already-public protected input. No raw Docker value
        // or caller observation enters this immutable recheck request.
        let staging = serde_json::from_slice(
            &serde_json::to_vec(&self.staging).map_err(|_| Error::InvalidSpec)?,
        )
        .map_err(|_| Error::InvalidSpec)?;
        use sha2::Digest;
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&(
                &self.spec,
                &staging,
                self.binding.public_result(),
                QueryKind::Recheck,
            ))
            .map_err(|_| Error::InvalidSpec)?,
        )
        .into();
        let request = Self {
            creator: self.creator,
            spec: self.spec.clone(),
            staging,
            binding: prepared.bind_public()?,
            requested_at: self.requested_at,
            digest,
            kind: QueryKind::Recheck,
            mounted: None,
            movement: None,
            quarantine: None,
        };
        request.check_deadline()?;
        Ok(request)
    }
}
