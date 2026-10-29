use crate::{
    Error, Result,
    codec::*,
    policy::{Policy, Stage, Table},
    socket::Socket,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reconciliation {
    Absent,
    Owned,
    Matching,
    Drifted,
    Foreign,
    Unknown,
}

/// Operates only within the socket's namespace. Namespace admission and lifecycle
/// belong to the future guard, not this component. No CLI/runtime is activated.
pub struct Actuator {
    pub(crate) socket: Socket,
    policy: Policy,
    quarantine_stage: Stage,
    released: bool,
    permit_stage: Stage,
    namespace: (u64, u64),
    emergency: Socket,
    cooperation: Option<crate::cooperation::Cooperation>,
}
struct Snapshot {
    generation: u32,
    quarantine: Reconciliation,
    permit: Reconciliation,
}
fn original_bootstrap_permit_operations(
    policy: &Policy,
    stage: Stage,
    observed: &Snapshot,
    emergency: Reconciliation,
) -> Result<Vec<(u16, u16, Vec<Attr>)>> {
    if stage != Stage::Offline {
        return Err(Error::QuarantineRequired);
    }
    require(observed.quarantine, Reconciliation::Matching)?;
    require(observed.permit, Reconciliation::Absent)?;
    require(emergency, Reconciliation::Matching)?;
    Ok(policy.permit_stage_table(Stage::Bootstrap).operations())
}
impl Actuator {
    pub(crate) fn bind_cleanup_deadline(
        &mut self,
        deadline: crate::BootDeadline,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        self.socket.bind_cleanup_deadline(deadline, timer.clone())?;
        self.emergency.bind_cleanup_deadline(deadline, timer)
    }
    pub(crate) fn descriptors(&self) -> [std::os::fd::BorrowedFd<'_>; 2] {
        [self.socket.descriptor(), self.emergency.descriptor()]
    }

    // Only our exact pending socket operation can invoke this after storing its
    // original completion. No arbitrary descriptor/parsed report entry point.
    pub(crate) fn from_fixed_creator(
        policy: Policy,
        original: &vprouter_native_role::SocketCompletion,
    ) -> Result<Self> {
        let namespace = original.namespace_identity().map_err(|_| Error::Foreign)?;
        let [(main, main_port), (emergency, emergency_port)] =
            original.netfilter_sockets().map_err(|_| Error::Foreign)?;
        if std::sync::Arc::ptr_eq(&main, &emergency) || main_port == emergency_port {
            return Err(Error::Foreign);
        }
        if let Some(producer) = &policy.producer {
            if policy.scope() != crate::Scope::Data
                || !producer.matches(&policy.binding(), namespace)
            {
                return Err(Error::InvalidAllocation);
            }
            producer.verify()?;
        }
        Ok(Self {
            socket: Socket::from_original_creator(main, main_port)?,
            emergency: Socket::from_original_creator(emergency, emergency_port)?,
            policy,
            quarantine_stage: Stage::Offline,
            released: false,
            permit_stage: Stage::Ready,
            namespace,
            cooperation: None,
        })
    }
    pub(crate) fn matches_original_pair(
        &self,
        pair: &[(std::sync::Arc<std::os::fd::OwnedFd>, u32); 2],
    ) -> bool {
        self.socket.matches_original(&pair[0].0, pair[0].1)
            && self.emergency.matches_original(&pair[1].0, pair[1].1)
    }
    pub(crate) fn confined_initial(
        &self,
        role: &vprouter_native_role::ConfinedNetfilter,
    ) -> Result<Self> {
        if self.policy.producer.is_some()
            || self.cooperation.is_some()
            || self.released
            || self.quarantine_stage != Stage::Offline
            || self.namespace != role.namespace_identity().map_err(|_| Error::Foreign)?
        {
            return Err(Error::Foreign);
        }
        Ok(Self {
            socket: self.socket.confined(role, 0)?,
            emergency: self.emergency.confined(role, 1)?,
            policy: self.policy.clone(),
            quarantine_stage: Stage::Offline,
            released: false,
            permit_stage: Stage::Ready,
            namespace: self.namespace,
            cooperation: None,
        })
    }
    pub(crate) fn confined_producer_observation(
        &self,
        role: &vprouter_native_role::ConfinedProducerNetfilter,
    ) -> Result<Self> {
        if self.policy.producer.is_some()
            || self.cooperation.is_some()
            || self.released
            || self.quarantine_stage != Stage::Offline
            || self.policy.scope() != crate::Scope::Data
            || self.namespace != role.namespace_identity().map_err(|_| Error::Foreign)?
        {
            return Err(Error::Foreign);
        }
        Ok(Self {
            socket: self.socket.confined_producer(role, 0)?,
            emergency: self.emergency.confined_producer(role, 1)?,
            policy: self.policy.clone(),
            quarantine_stage: Stage::Offline,
            released: false,
            permit_stage: Stage::Ready,
            namespace: self.namespace,
            cooperation: None,
        })
    }
    pub(crate) fn confined_bootstrap(
        &self,
        role: &vprouter_native_role::ConfinedProducerBootstrap,
    ) -> Result<Self> {
        if self.policy.producer.is_some()
            || self.cooperation.is_some()
            || self.released
            || self.quarantine_stage != Stage::Offline
            || self.namespace != role.namespace_identity().map_err(|_| Error::Foreign)?
        {
            return Err(Error::Foreign);
        }
        let mut policy = self.policy.clone();
        if policy.scope() == crate::Scope::Data {
            policy.producer = Some(crate::SocketProducer::from_confined_bootstrap(
                role,
                policy.binding(),
            )?);
        }
        Ok(Self {
            socket: self.socket.confined_bootstrap(role, 0)?,
            emergency: self.emergency.confined_bootstrap(role, 1)?,
            policy,
            quarantine_stage: Stage::Offline,
            released: false,
            permit_stage: Stage::Ready,
            namespace: self.namespace,
            cooperation: None,
        })
    }
    pub(crate) fn rebind_initial_bootstrap(
        &mut self,
        original: &vprouter_native_role::NetfilterCompleted,
        seq: [u32; 2],
        end: crate::BootDeadline,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        if self.policy.scope() == crate::Scope::Data
            || self.policy.producer.is_some()
            || self.released
            || self.cooperation.is_some()
            || self.quarantine_stage != Stage::Offline
        {
            return Err(Error::Foreign);
        }
        self.socket
            .rebind_accepted_initial(original, seq[0], end, timer.clone())?;
        self.emergency
            .rebind_accepted_initial(original, seq[1], end, timer)
    }
    pub(crate) fn rebind_observed_bootstrap(
        &mut self,
        original: &vprouter_native_role::ProducerNetfilterCompleted,
        seq: [u32; 2],
        end: crate::BootDeadline,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        if self.policy.scope() != crate::Scope::Data
            || self.policy.producer.is_some()
            || self.released
            || self.cooperation.is_some()
            || self.quarantine_stage != Stage::Offline
        {
            return Err(Error::Foreign);
        }
        self.socket
            .rebind_accepted_producer(original, seq[0], end, timer.clone())?;
        self.emergency
            .rebind_accepted_producer(original, seq[1], end, timer)
    }
    pub(crate) fn accept_bootstrap_sequences(
        &mut self,
        original: &vprouter_native_role::ProducerBootstrapCompleted,
        seq: [u32; 2],
    ) -> Result<()> {
        self.socket.accept_bootstrap_sequence(original, seq[0])?;
        self.emergency.accept_bootstrap_sequence(original, seq[1])
    }
    pub(crate) fn verify_bootstrap_observation(&mut self) -> Result<()> {
        self.socket.require_paired_deadline(&self.emergency)?;
        if self.released
            || self.cooperation.is_some()
            || self.quarantine_stage != Stage::Bootstrap
            || self.permit_stage != Stage::Bootstrap
        {
            return Err(Error::Foreign);
        }
        self.verify_producer()?;
        let end = Self::deadline();
        let snapshot = self.snapshot(end)?;
        require(snapshot.quarantine, Reconciliation::Matching)?;
        require(snapshot.permit, Reconciliation::Matching)?;
        require(
            self.inspect_table(&self.policy.emergency_table(), end)?,
            Reconciliation::Absent,
        )?;
        if self.socket.generation(end)? != snapshot.generation {
            return Err(Error::GenerationChanged);
        }
        Ok(())
    }
    pub(crate) fn rebind_initial_observation(
        &mut self,
        original: &vprouter_native_role::NetfilterCompleted,
        seq: [u32; 2],
        end: crate::BootDeadline,
        timer: std::sync::Arc<std::os::fd::OwnedFd>,
    ) -> Result<()> {
        if self.policy.producer.is_some()
            || self.cooperation.is_some()
            || self.released
            || self.quarantine_stage != Stage::Offline
            || self.policy.scope() != crate::Scope::Data
        {
            return Err(Error::Foreign);
        }
        self.socket
            .rebind_accepted_initial(original, seq[0], end, timer.clone())?;
        self.emergency
            .rebind_accepted_initial(original, seq[1], end, timer)
    }
    pub(crate) fn accept_producer_observation(
        &mut self,
        original: &vprouter_native_role::ProducerNetfilterCompleted,
        seq: [u32; 2],
    ) -> Result<()> {
        self.socket.accept_producer_sequence(original, seq[0])?;
        self.emergency.accept_producer_sequence(original, seq[1])
    }
    pub(crate) fn initial_sequences(&self) -> Result<[u32; 2]> {
        Ok([
            self.socket.original_sequence()?,
            self.emergency.original_sequence()?,
        ])
    }
    pub(crate) fn accept_initial_sequences(
        &mut self,
        c: &vprouter_native_role::NetfilterCompleted,
        seq: [u32; 2],
    ) -> Result<()> {
        self.socket.accept_original_sequence(c, seq[0])?;
        self.emergency.accept_original_sequence(c, seq[1])
    }
    /// Fresh initial creation only: matching existing tables never count as our
    /// original creation. The durable owner retains all ambiguity on error.
    pub(crate) fn install_initial_quarantine(&mut self) -> Result<()> {
        self.socket.require_paired_deadline(&self.emergency)?;
        if self.policy.producer.is_some() || self.released || self.cooperation.is_some() {
            return Err(Error::Foreign);
        }
        let end = Self::deadline();
        let before = self.snapshot(end)?;
        require(before.quarantine, Reconciliation::Absent)?;
        require(before.permit, Reconciliation::Absent)?;
        let emergency = self.policy.emergency_table();
        require(self.inspect_table(&emergency, end)?, Reconciliation::Absent)?;
        if self.socket.generation(end)? != before.generation {
            return Err(Error::GenerationChanged);
        }
        let mut ops = emergency.operations();
        ops.extend(self.policy.table(true).operations());
        self.socket.batch(&ops, before.generation, end)?;
        self.verify_initial_quarantine()
    }
    pub(crate) fn verify_initial_quarantine(&mut self) -> Result<()> {
        self.socket.require_paired_deadline(&self.emergency)?;
        let end = Self::deadline();
        let observed = self.snapshot(end)?;
        require(observed.quarantine, Reconciliation::Matching)?;
        require(observed.permit, Reconciliation::Absent)?;
        require(
            self.inspect_table(&self.policy.emergency_table(), end)?,
            Reconciliation::Matching,
        )?;
        if self.socket.generation(end)? != observed.generation {
            return Err(Error::GenerationChanged);
        }
        Ok(())
    }
    pub fn open(policy: Policy) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let before =
            std::fs::metadata("/proc/thread-self/ns/net").map_err(|_| Error::InvalidInput)?;
        let socket = Socket::open()?;
        let emergency = Socket::open()?;
        let after =
            std::fs::metadata("/proc/thread-self/ns/net").map_err(|_| Error::InvalidInput)?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(Error::InvalidInput);
        }
        if let Some(producer) = &policy.producer {
            if policy.scope() != crate::Scope::Data
                || !producer.matches(&policy.binding(), (before.dev(), before.ino()))
            {
                return Err(Error::InvalidAllocation);
            }
            producer.verify()?;
        }
        Ok(Self {
            socket,
            policy,
            quarantine_stage: Stage::Offline,
            released: false,
            permit_stage: Stage::Ready,
            namespace: (before.dev(), before.ino()),
            emergency,
            cooperation: None,
        })
    }
    /// Kernel feature probe: create+validate+delete one exclusively owned table
    /// in ONE atomic transaction. No table/rule becomes externally installed.
    /// Fails before retained policy/link/cgroup installation, no fallback.
    pub fn preflight_socket_cgroup(policy: &Policy) -> Result<()> {
        let mut socket = Socket::open()?;
        let end = Self::deadline();
        let generation = socket.generation(end)?;
        let mut table = policy.table(true);
        table.name.push_str("_probe");
        table.chains.truncate(1);
        table.chains[0]
            .rules
            .push(crate::policy::flatten(vec![crate::policy::socket_owner(
                0, 3,
            )]));
        let mut ops = table.operations();
        ops.push(delete(&table));
        socket.batch(&ops, generation, end)
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    /// Bounded observational reconciliation. A failed dump is Unknown, never matching.
    pub fn reconcile(&mut self) -> (Reconciliation, Reconciliation) {
        match self.snapshot(Self::deadline()) {
            Ok(s) => (s.quarantine, s.permit),
            Err(_) => (Reconciliation::Unknown, Reconciliation::Unknown),
        }
    }
    pub fn install_quarantine(&mut self) -> Result<()> {
        self.released = false;
        // A failed exchange must not disable independent quarantine restoration.
        // Both descriptors were opened in this exact namespace before activation.
        if self.socket.poisoned() && !self.emergency.poisoned() {
            std::mem::swap(&mut self.socket, &mut self.emergency);
        }
        let end = Self::deadline();
        // A distinct preallocated policy identity restores full containment even
        // if the main quarantine table has been removed, changed, or its last
        // atomic ACK was lost. Never overwrite the changed resource itself.
        let generation = self.socket.generation(end)?;
        let emergency = self.policy.emergency_table();
        match self.inspect_table(&emergency, end)? {
            Reconciliation::Matching => {}
            Reconciliation::Absent => {
                self.socket
                    .batch(&emergency.operations(), generation, end)?
            }
            Reconciliation::Foreign => return Err(Error::Foreign),
            _ => return Err(Error::Drifted),
        }
        require(
            self.inspect_table(&emergency, end)?,
            Reconciliation::Matching,
        )?;
        self.quarantine(end)
    }
    pub(crate) fn install_cooperation(&mut self) -> Result<()> {
        if self.policy.scope() != crate::Scope::Host {
            return Err(Error::InvalidInput);
        }
        if self.quarantine_stage != Stage::Offline || self.reconcile().0 != Reconciliation::Matching
        {
            return Err(Error::QuarantineRequired);
        }
        if self.cooperation.is_some() {
            return self.verify_cooperation();
        }
        self.cooperation = Some(crate::cooperation::Cooperation::install(
            &mut self.socket,
            &self.policy,
            Self::deadline(),
        )?);
        Ok(())
    }
    pub(crate) fn verify_cooperation(&mut self) -> Result<()> {
        self.cooperation
            .as_ref()
            .ok_or(Error::Drifted)?
            .verify(&mut self.socket, Self::deadline())
    }
    pub(crate) fn cleanup_cooperation(&mut self) -> Result<()> {
        if let Some(c) = &self.cooperation {
            c.cleanup(&mut self.socket, Self::deadline())?;
        }
        self.cooperation = None;
        Ok(())
    }
    pub(crate) fn namespace(&self) -> (u64, u64) {
        self.namespace
    }
    pub(crate) fn policy(&self) -> &Policy {
        &self.policy
    }
    pub(crate) fn stage(&self) -> Stage {
        if self.released {
            Stage::Ready
        } else {
            self.quarantine_stage
        }
    }
    pub(crate) fn verify_staged_ready(&mut self) -> Result<()> {
        if self.stage() != Stage::Offline || self.permit_stage != Stage::Ready {
            return Err(Error::QuarantineRequired);
        }
        let end = Self::deadline();
        let snapshot = self.snapshot(end)?;
        require(snapshot.quarantine, Reconciliation::Matching)?;
        require(snapshot.permit, Reconciliation::Matching)?;
        self.verify_emergency()
    }
    pub(crate) fn verify_ready(&mut self) -> Result<()> {
        let end = Self::deadline();
        let snapshot = self.snapshot(end)?;
        let emergency = self.inspect_table(&self.policy.emergency_table(), end)?;
        ready_projection(
            self.stage(),
            snapshot.quarantine,
            snapshot.permit,
            emergency,
        )
    }
    pub(crate) fn verify_emergency(&mut self) -> Result<()> {
        require(
            self.inspect_table(&self.policy.emergency_table(), Self::deadline())?,
            Reconciliation::Matching,
        )
    }
    pub(crate) fn verify_producer(&self) -> Result<()> {
        if let Some(p) = &self.policy.producer {
            p.verify()?;
        }
        Ok(())
    }
    pub(crate) fn install_bootstrap(&mut self) -> Result<()> {
        let end = Self::deadline();
        if self.quarantine_stage != Stage::Offline || self.permit_stage != Stage::Bootstrap {
            return Err(Error::QuarantineRequired);
        }
        let s = self.snapshot(end)?;
        require(s.quarantine, Reconciliation::Matching)?;
        require(s.permit, Reconciliation::Matching)?;
        require(
            self.inspect_table(&self.policy.emergency_table(), end)?,
            Reconciliation::Matching,
        )?;
        let mut ops = vec![
            delete(&self.policy.table(true)),
            delete(&self.policy.emergency_table()),
        ];
        ops.extend(self.policy.bootstrap_table().operations());
        self.socket.batch(&ops, s.generation, end)?;
        self.quarantine_stage = Stage::Bootstrap;
        let s = self.snapshot(end)?;
        require(s.quarantine, Reconciliation::Matching)?;
        require(s.permit, Reconciliation::Matching)
    }
    fn quarantine(&mut self, deadline: Instant) -> Result<()> {
        self.released = false;
        let s = self.snapshot(deadline)?;
        match s.quarantine {
            Reconciliation::Matching if self.quarantine_stage == Stage::Offline => Ok(()),
            Reconciliation::Matching | Reconciliation::Absent => {
                let mut ops = Vec::new();
                if s.quarantine == Reconciliation::Matching {
                    ops.push(delete(&self.policy.stage_table(self.quarantine_stage)));
                }
                ops.extend(self.policy.table(true).operations());
                self.socket.batch(&ops, s.generation, deadline)?;
                self.quarantine_stage = Stage::Offline;
                require(
                    self.snapshot(deadline)?.quarantine,
                    Reconciliation::Matching,
                )
            }
            Reconciliation::Foreign => Err(Error::Foreign),
            _ => Err(Error::Drifted),
        }
    }
    /// Quarantine is installed first and remains on any create/replace/verify error.
    /// Replacing drifted or foreign state is refused; it needs operator investigation.
    pub fn install_permit(&mut self) -> Result<()> {
        self.install_permit_stage(Stage::Ready)
    }
    /// First Bootstrap permit for the retained exclusive initial owner. A
    /// matching table created by another actor is not our creation receipt.
    pub(crate) fn install_original_bootstrap_permit(&mut self) -> Result<()> {
        self.socket.require_paired_deadline(&self.emergency)?;
        let end = Self::deadline();
        let observed = self.snapshot(end)?;
        let emergency = self.inspect_table(&self.policy.emergency_table(), end)?;
        let ops = original_bootstrap_permit_operations(
            &self.policy,
            self.quarantine_stage,
            &observed,
            emergency,
        )?;
        if self.socket.generation(end)? != observed.generation {
            return Err(Error::GenerationChanged);
        }
        self.socket.batch(&ops, observed.generation, end)?;
        self.permit_stage = Stage::Bootstrap;
        let after = self.snapshot(end)?;
        require(after.quarantine, Reconciliation::Matching)?;
        require(after.permit, Reconciliation::Matching)
    }
    pub(crate) fn install_bootstrap_permit(&mut self) -> Result<()> {
        self.install_permit_stage(Stage::Bootstrap)
    }
    fn install_permit_stage(&mut self, stage: Stage) -> Result<()> {
        let deadline = Self::deadline();
        self.quarantine(deadline)?;
        let s = self.snapshot(deadline)?;
        require(s.quarantine, Reconciliation::Matching)?;
        let mut ops = Vec::new();
        match s.permit {
            Reconciliation::Absent => {}
            Reconciliation::Matching => {
                ops.push(delete(&self.policy.permit_stage_table(self.permit_stage)))
            }
            Reconciliation::Foreign => return Err(Error::Foreign),
            _ => return Err(Error::Drifted),
        }
        ops.extend(self.policy.permit_stage_table(stage).operations());
        self.socket.batch(&ops, s.generation, deadline)?;
        self.permit_stage = stage;
        let s = self.snapshot(deadline)?;
        require(s.quarantine, Reconciliation::Matching)?;
        require(s.permit, Reconciliation::Matching)
    }
    /// Change public endpoint/WAN under the same allocation. The old policy must
    /// match the kernel exactly; the caller cannot authorize replacement by name.
    pub fn replace_permit(&mut self, next: Policy) -> Result<()> {
        if self.permit_stage != Stage::Ready || !self.policy.compatible(&next) {
            return Err(Error::InvalidAllocation);
        }
        let deadline = Self::deadline();
        self.quarantine(deadline)?;
        let s = self.snapshot(deadline)?;
        require(s.quarantine, Reconciliation::Matching)?;
        require(s.permit, Reconciliation::Matching)?;
        let mut ops = vec![delete(&self.policy.table(false))];
        ops.extend(next.table(false).operations());
        self.socket.batch(&ops, s.generation, deadline)?;
        // After ACK the desired policy changes even if post-verification fails.
        // Quarantine remains installed and future recovery must reconcile next.
        self.policy = next;
        let s = self.snapshot(deadline)?;
        require(s.quarantine, Reconciliation::Matching)?;
        require(s.permit, Reconciliation::Matching)
    }
    /// Only this API releases quarantine, after an exact policy dump and a
    /// generation-CAS deletion in the same socket/namespace. No public proof token.
    pub fn release_quarantine(&mut self) -> Result<()> {
        let deadline = Self::deadline();
        let s = self.snapshot(deadline)?;
        require(s.permit, Reconciliation::Matching)?;
        if s.quarantine != Reconciliation::Matching {
            return Err(Error::QuarantineRequired);
        }
        if self.quarantine_stage != Stage::Offline
            || self.permit_stage != Stage::Ready
            || self.released
        {
            return Err(Error::QuarantineRequired);
        }
        self.verify_emergency()?;
        self.socket.batch(
            &[
                delete(&self.policy.table(true)),
                delete(&self.policy.emergency_table()),
            ],
            s.generation,
            deadline,
        )?;
        // The desired phase changes only after the actual generation-CAS ACK.
        // Verification checks absence of BOTH independent quarantine tables and
        // exact Ready permit bytes; failure immediately restores quarantine.
        self.released = true;
        if let Err(error) = self.verify_ready() {
            self.install_quarantine()?;
            return Err(error);
        }
        Ok(())
    }
    /// Ordinary shutdown removes only the verified permit table, leaving quarantine.
    /// Final quarantine cleanup intentionally has no API until namespace/link
    /// absence can be natively verified by the later namespace lifecycle component.
    pub fn cleanup_permit(&mut self) -> Result<()> {
        let deadline = Self::deadline();
        self.quarantine(deadline)?;
        let s = self.snapshot(deadline)?;
        require(s.quarantine, Reconciliation::Matching)?;
        match s.permit {
            Reconciliation::Absent => Ok(()),
            Reconciliation::Matching => {
                self.socket
                    .batch(&[delete(&self.policy.table(false))], s.generation, deadline)
            }
            Reconciliation::Foreign => Err(Error::Foreign),
            _ => Err(Error::Drifted),
        }
    }
    #[cfg(test)]
    pub(crate) fn diagnose(&mut self) {
        let deadline = Self::deadline();
        let t = self.policy.permit_stage_table(self.permit_stage);
        let result = (|| -> Result<()> {
            let all = self.socket.dump(1, &[], deadline)?;
            for m in &all {
                let a = nfattrs(m)?;
                if text(get(&a, 1)?)? == t.name {
                    eprintln!("LAB_DIAG table {:?}", a);
                }
            }
            let chains = self.socket.scoped_dump(4, &t.name, deadline)?;
            for m in &chains {
                eprintln!("LAB_DIAG chain {:?}", nfattrs(m)?);
            }
            let rules = self.socket.scoped_dump(7, &t.name, deadline)?;
            let mut positions = BTreeMap::<String, usize>::new();
            let mut budget = 16384usize;
            for m in &rules {
                let a = nfattrs(m)?;
                let name = text(get(&a, 2)?)?;
                let index = positions.entry(name.to_owned()).or_default();
                let got = attrs(get(&a, 4)?)?;
                let want = t
                    .chains
                    .iter()
                    .find(|c| c.name == name)
                    .and_then(|c| c.rules.get(*index));
                if let Some(want) = want {
                    for (ei, (g, w)) in got.iter().zip(want).enumerate() {
                        if canonical_exprs(std::slice::from_ref(g))
                            != canonical_exprs(std::slice::from_ref(w))
                        {
                            let ga = attrs(&g.value)?;
                            let wa = attrs(&w.value)?;
                            let line = format!(
                                "LAB_DIAG chain={name} rule={} expr={ei} got={ga:?} want={wa:?}",
                                *index
                            );
                            if line.len() <= budget {
                                eprintln!("{line}");
                                budget -= line.len();
                            }
                        }
                    }
                    if got.len() != want.len() {
                        eprintln!(
                            "LAB_DIAG chain={name} rule={} expr_count_got={} want={}",
                            *index,
                            got.len(),
                            want.len()
                        );
                    }
                }
                *index += 1;
            }
            Ok(())
        })();
        if let Err(e) = result {
            eprintln!("LAB_DIAG diagnostic_error={e:?}");
        }
    }
    fn inspect_table(&mut self, expected: &Table, deadline: Instant) -> Result<Reconciliation> {
        let tables = self.socket.dump(1, &[], deadline)?;
        self.inspect_table_from(expected, &tables, deadline)
    }
    fn inspect_table_from(
        &mut self,
        expected: &Table,
        tables: &[Message],
        deadline: Instant,
    ) -> Result<Reconciliation> {
        inspect_table_from(&mut self.socket, expected, tables, deadline)
    }
    fn snapshot(&mut self, deadline: Instant) -> Result<Snapshot> {
        let generation = self.socket.generation(deadline)?;
        let tables = self.socket.dump(1, &[], deadline)?;
        let mut states = Vec::new();
        for quarantine in [true, false] {
            let expected = if quarantine {
                self.policy.stage_table(self.quarantine_stage)
            } else {
                self.policy.permit_stage_table(self.permit_stage)
            };
            let state = self.inspect_table_from(&expected, &tables, deadline)?;
            states.push(state);
        }
        if self.socket.generation(deadline)? != generation {
            return Err(Error::GenerationChanged);
        }
        Ok(Snapshot {
            generation,
            quarantine: states[0],
            permit: states[1],
        })
    }
}
pub(crate) fn inspect_table_from(
    socket: &mut Socket,
    expected: &Table,
    tables: &[Message],
    deadline: Instant,
) -> Result<Reconciliation> {
    let mut found = None;
    for m in tables {
        let a = nfattrs(m)?;
        if text(get(&a, 1)?)? == expected.name {
            if found.is_some() {
                return Err(Error::Foreign);
            }
            found = Some(a);
        }
    }
    let Some(a) = found else {
        return Ok(Reconciliation::Absent);
    };
    if get(&a, 6).ok() != Some(expected.marker.as_slice()) {
        return Ok(Reconciliation::Foreign);
    }
    let chains = socket.scoped_dump(4, &expected.name, deadline)?;
    let rules = socket.scoped_dump(7, &expected.name, deadline)?;
    let mut extras = false;
    for op in [10, 19, 23] {
        if !socket.scoped_dump(op, &expected.name, deadline)?.is_empty() {
            extras = true;
        }
    }
    Ok(
        if !extras && verify(expected, &a, &chains, &rules).is_ok() {
            Reconciliation::Matching
        } else {
            Reconciliation::Drifted
        },
    )
}

fn ready_projection(
    stage: Stage,
    quarantine: Reconciliation,
    permit: Reconciliation,
    emergency: Reconciliation,
) -> Result<()> {
    if stage != Stage::Ready {
        return Err(Error::QuarantineRequired);
    }
    require(quarantine, Reconciliation::Absent)?;
    require(permit, Reconciliation::Matching)?;
    require(emergency, Reconciliation::Absent)
}
fn require(actual: Reconciliation, wanted: Reconciliation) -> Result<()> {
    if actual == wanted {
        Ok(())
    } else {
        Err(if actual == Reconciliation::Foreign {
            Error::Foreign
        } else {
            Error::Drifted
        })
    }
}
pub(crate) fn delete(t: &Table) -> (u16, u16, Vec<Attr>) {
    (NFT | 2, 0, vec![string(1, &t.name)])
}
fn allowed(a: &[Attr], kinds: &[u16]) -> Result<()> {
    unique(a)?;
    if a.iter().any(|a| !kinds.contains(&(a.kind & 0x3fff))) {
        return Err(Error::Drifted);
    }
    Ok(())
}
/// Compare a narrow, explicit UAPI semantic model. Ignore only documented kernel
/// bookkeeping: table/chain use counts, handles, alignment pads, base-chain flag,
/// rule position handles. Counters/unknown expression attributes are not ignored.
fn verify(expected: &Table, table: &[Attr], chains: &[Message], rules: &[Message]) -> Result<()> {
    allowed(table, &[1, 2, 3, 4, 5, 6])?;
    if text(get(table, 1)?)? != expected.name
        || be32(get(table, 2)?)? != 0
        || get(table, 6)? != expected.marker
    {
        return Err(Error::Drifted);
    }
    if chains.len() != expected.chains.len() {
        return Err(Error::Drifted);
    }
    let mut got_chains = BTreeMap::new();
    for m in chains {
        let a = nfattrs(m)?;
        allowed(&a, &[1, 2, 3, 4, 5, 6, 7, 9, 10])?;
        if text(get(&a, 1)?)? != expected.name {
            return Err(Error::Drifted);
        }
        let name = text(get(&a, 3)?)?.to_owned();
        if got_chains.insert(name, a).is_some() {
            return Err(Error::Drifted);
        }
    }
    for chain in &expected.chains {
        let a = got_chains.get(&chain.name).ok_or(Error::Drifted)?;
        let hook = attrs(get(a, 4)?)?;
        allowed(&hook, &[1, 2])?;
        if be32(get(&hook, 1)?)? != chain.hook
            || be32(get(&hook, 2)?)? != chain.priority as u32
            || be32(get(a, 5)?)? != chain.policy
            || text(get(a, 7)?)? != chain.kind
        {
            return Err(Error::Drifted);
        }
        if let Ok(flags) = get(a, 10)
            && be32(flags)? != 1
        {
            return Err(Error::Drifted);
        }
    }
    let mut got_rules: BTreeMap<String, Vec<Vec<Attr>>> = BTreeMap::new();
    for m in rules {
        let a = nfattrs(m)?;
        allowed(&a, &[1, 2, 3, 4, 6, 8])?;
        if text(get(&a, 1)?)? != expected.name {
            return Err(Error::Drifted);
        }
        let name = text(get(&a, 2)?)?;
        if !got_chains.contains_key(name) {
            return Err(Error::Drifted);
        }
        got_rules
            .entry(name.into())
            .or_default()
            .push(attrs(get(&a, 4)?)?);
    }
    for c in &expected.chains {
        let empty = Vec::new();
        let actual = got_rules.get(&c.name).unwrap_or(&empty);
        if actual.len() != c.rules.len() {
            return Err(Error::Drifted);
        }
        for (got, want) in actual.iter().zip(&c.rules) {
            if canonical_exprs(got)? != canonical_exprs(want)? {
                return Err(Error::Drifted);
            }
        }
    }
    Ok(())
}
// Attribute order is not semantic; expression and rule order are. Recursion is
// limited to the known expression grammar (depth <=5), never attacker-controlled.
pub(crate) fn canonical_exprs(exprs: &[Attr]) -> Result<Vec<Vec<u8>>> {
    if exprs.len() > 256 {
        return Err(Error::Oversized);
    }
    let mut out = Vec::new();
    for e in exprs {
        if e.kind & 0x3fff != 1 {
            return Err(Error::Drifted);
        }
        let a = attrs(&e.value)?;
        allowed(&a, &[1, 2])?;
        let name = text(get(&a, 1)?)?;
        let data = attrs(get(&a, 2)?)?;
        let schema: &[(u16, u8)] = match name {
            "meta" => &[(1, 0), (2, 0)],
            "ct" => &[(1, 0), (2, 0)],
            "socket" => &[(1, 0), (2, 0), (3, 0)],
            "payload" => &[(1, 0), (2, 0), (3, 0), (4, 0)],
            "cmp" => &[(1, 0), (2, 0), (3, 1)],
            "bitwise" => &[(1, 0), (2, 0), (3, 0), (4, 1), (5, 1), (6, 0)],
            "immediate" => &[(1, 0), (2, 2)],
            "masq" => &[],
            _ => return Err(Error::Drifted),
        };
        let canonical = canonical_data(&data, schema)?;
        out.push(encode_attrs(&[string(1, name), nested(2, &canonical)]));
    }
    Ok(out)
}
fn canonical_data(data: &[Attr], schema: &[(u16, u8)]) -> Result<Vec<Attr>> {
    allowed(data, &schema.iter().map(|(k, _)| *k).collect::<Vec<_>>())?;
    let mut out = Vec::new();
    for (kind, ty) in schema {
        let bytes = get(data, *kind)?;
        out.push(match ty {
            0 => {
                be32(bytes)?;
                attr(*kind, bytes.to_vec())
            }
            1 => {
                let inner = attrs(bytes)?;
                allowed(&inner, &[1])?;
                nested(*kind, &[attr(1, get(&inner, 1)?.to_vec())])
            }
            2 => {
                let inner = attrs(bytes)?;
                allowed(&inner, &[2])?;
                let verdict = attrs(get(&inner, 2)?)?;
                allowed(&verdict, &[1])?;
                nested(*kind, &[nested(2, &[u32a(1, be32(get(&verdict, 1)?)?)])])
            }
            _ => return Err(Error::Malformed),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Scope, fixture};
    #[test]
    fn first_bootstrap_permit_requires_absence_and_uses_exclusive_creation() {
        use Reconciliation::*;
        for scope in [Scope::Host, Scope::Transport, Scope::Data] {
            let policy = fixture(scope);
            for permit in [Absent, Owned, Matching, Drifted, Foreign, Unknown] {
                let observed = Snapshot {
                    generation: 7,
                    quarantine: Matching,
                    permit,
                };
                let result = original_bootstrap_permit_operations(
                    &policy,
                    Stage::Offline,
                    &observed,
                    Matching,
                );
                if permit == Absent {
                    let operations = result.unwrap();
                    assert_eq!(
                        operations,
                        policy.permit_stage_table(Stage::Bootstrap).operations()
                    );
                    assert_eq!(operations[0].0, NFT);
                    assert_eq!(operations[0].1, CREATE | EXCL);
                } else {
                    assert!(result.is_err());
                }
            }
            for q in [Absent, Owned, Drifted, Foreign, Unknown] {
                let observed = Snapshot {
                    generation: 7,
                    quarantine: q,
                    permit: Absent,
                };
                assert!(
                    original_bootstrap_permit_operations(
                        &policy,
                        Stage::Offline,
                        &observed,
                        Matching
                    )
                    .is_err()
                );
                let observed = Snapshot {
                    generation: 7,
                    quarantine: Matching,
                    permit: Absent,
                };
                assert!(
                    original_bootstrap_permit_operations(&policy, Stage::Offline, &observed, q)
                        .is_err()
                );
            }
            let observed = Snapshot {
                generation: 7,
                quarantine: Matching,
                permit: Absent,
            };
            assert!(
                original_bootstrap_permit_operations(
                    &policy,
                    Stage::Bootstrap,
                    &observed,
                    Matching
                )
                .is_err()
            );
        }
    }
    #[test]
    fn ready_projection_requires_permit_and_both_quarantines_absent() {
        use Reconciliation::*;
        assert_eq!(
            ready_projection(Stage::Ready, Absent, Matching, Absent),
            Ok(())
        );
        for (stage, q, permit, emergency) in [
            (Stage::Bootstrap, Absent, Matching, Absent),
            (Stage::Ready, Matching, Matching, Absent),
            (Stage::Ready, Absent, Absent, Absent),
            (Stage::Ready, Absent, Matching, Matching),
            (Stage::Ready, Unknown, Matching, Absent),
            (Stage::Ready, Absent, Drifted, Absent),
            (Stage::Ready, Absent, Matching, Foreign),
        ] {
            assert!(ready_projection(stage, q, permit, emergency).is_err());
        }
    }

    fn fixture_dump(t: &Table) -> (Vec<Attr>, Vec<Message>, Vec<Message>) {
        let mut chains = Vec::new();
        let mut rules = Vec::new();
        for (kind, _, a) in t.operations().into_iter().skip(1) {
            let mut m = messages(&message(kind, 2, 1, INET, 0, &a))
                .unwrap()
                .remove(0);
            let mut attrs = nfattrs(&m).unwrap();
            if kind == NFT | 3 {
                attrs.extend([attr(2, 9u64.to_be_bytes()), u32a(6, 0), u32a(10, 1)]);
            } else {
                attrs.push(attr(3, 13u64.to_be_bytes()));
            }
            attrs.reverse();
            m.payload = vec![INET, 0, 0, 1];
            m.payload.extend(encode_attrs(&attrs));
            if kind == NFT | 3 {
                chains.push(m);
            } else {
                rules.push(m);
            }
        }
        let mut a = t.table_attrs();
        a.extend([u32a(3, t.chains.len() as u32), attr(4, 1u64.to_be_bytes())]);
        (a, chains, rules)
    }
    #[test]
    fn semantic_dump_accepts_only_known_bookkeeping_for_all_scopes() {
        for scope in [Scope::Data, Scope::Transport, Scope::Host] {
            for quarantine in [true, false] {
                let t = fixture(scope).table(quarantine);
                let (a, c, r) = fixture_dump(&t);
                assert!(verify(&t, &a, &c, &r).is_ok());
            }
        }
    }
    #[test]
    fn actual_rules_order_expressions_hooks_policy_and_extra_chains_fail() {
        let t = fixture(Scope::Data).table(false);
        let (a, c, r) = fixture_dump(&t);
        let mut extra = c.clone();
        extra.push(c[0].clone());
        assert!(verify(&t, &a, &extra, &r).is_err());
        let mut extra = r.clone();
        extra.push(r[0].clone());
        assert!(verify(&t, &a, &c, &extra).is_err());
        let mut reordered = r.clone();
        reordered.swap(0, 1);
        assert!(verify(&t, &a, &c, &reordered).is_err());
        for (field, value) in [
            (4, encode_attrs(&[u32a(1, 1), u32a(2, 0)])),
            (5, 1u32.to_be_bytes().to_vec()),
            (7, b"nat\0".to_vec()),
            (10, 3u32.to_be_bytes().to_vec()),
            (99, vec![0]),
        ] {
            let mut changed = c.clone();
            let mut attrs = nfattrs(&changed[0]).unwrap();
            attrs.retain(|a| a.kind & 0x3fff != field);
            attrs.push(attr(field, value));
            changed[0].payload.truncate(4);
            changed[0].payload.extend(encode_attrs(&attrs));
            assert!(verify(&t, &a, &changed, &r).is_err());
        }
        let mut changed = r.clone();
        let mut attrs = nfattrs(&changed[0]).unwrap();
        attrs.push(u32a(99, 1));
        changed[0].payload.truncate(4);
        changed[0].payload.extend(encode_attrs(&attrs));
        assert!(verify(&t, &a, &c, &changed).is_err());
        let mut altered = t.clone();
        altered.chains[0].rules[0].pop();
        assert!(verify(&altered, &a, &c, &r).is_err());
    }
    #[test]
    fn foreign_marker_generation_and_table_flags_refused() {
        let t = fixture(Scope::Host).table(false);
        let (a, c, r) = fixture_dump(&t);
        for field in [1, 2, 6, 99] {
            let mut changed = a.clone();
            changed.retain(|a| a.kind & 0x3fff != field);
            changed.push(if field == 2 {
                u32a(2, 1)
            } else {
                attr(field, b"foreign-marker\0".to_vec())
            });
            assert!(verify(&t, &changed, &c, &r).is_err());
        }
        let mut p = fixture(Scope::Host);
        p.generation += 1;
        assert!(verify(&p.table(false), &a, &c, &r).is_err());
        let mut unknown = t.chains[0].rules[0].clone();
        unknown.push(nested(1, &[string(1, "counter"), nested(2, &[])]));
        assert!(canonical_exprs(&unknown).is_err());
        let mut malformed = t.chains[0].rules[0].clone();
        malformed[0].value.push(0);
        assert!(canonical_exprs(&malformed).is_err());
    }
    #[test]
    fn replacement_compatibility_is_bound_to_full_allocation_scope_generation() {
        let p = fixture(Scope::Data);
        let mut next = p.clone();
        next.wan = "eth1".into();
        assert!(p.compatible(&next));
        next.scope = Scope::Host;
        assert!(!p.compatible(&next));
        next = p.clone();
        next.generation += 1;
        assert!(!p.compatible(&next));
        next = p.clone();
        next.allocation.exit_id = "other".into();
        assert!(!p.compatible(&next));
    }
}
