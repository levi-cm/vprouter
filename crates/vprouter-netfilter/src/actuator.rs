use crate::{
    Error, Result,
    codec::*,
    policy::{Policy, Table},
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
    socket: Socket,
    policy: Policy,
}
struct Snapshot {
    generation: u32,
    quarantine: Reconciliation,
    permit: Reconciliation,
}
impl Actuator {
    pub fn open(policy: Policy) -> Result<Self> {
        Ok(Self {
            socket: Socket::open()?,
            policy,
        })
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
        self.quarantine(Self::deadline())
    }
    fn quarantine(&mut self, deadline: Instant) -> Result<()> {
        let s = self.snapshot(deadline)?;
        match s.quarantine {
            Reconciliation::Matching => Ok(()),
            Reconciliation::Absent => {
                self.socket.batch(
                    &self.policy.table(true).operations(),
                    s.generation,
                    deadline,
                )?;
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
        let deadline = Self::deadline();
        self.quarantine(deadline)?;
        let s = self.snapshot(deadline)?;
        require(s.quarantine, Reconciliation::Matching)?;
        let mut ops = Vec::new();
        match s.permit {
            Reconciliation::Absent => {}
            Reconciliation::Matching => ops.push(delete(&self.policy.table(false))),
            Reconciliation::Foreign => return Err(Error::Foreign),
            _ => return Err(Error::Drifted),
        }
        ops.extend(self.policy.table(false).operations());
        self.socket.batch(&ops, s.generation, deadline)?;
        let s = self.snapshot(deadline)?;
        require(s.quarantine, Reconciliation::Matching)?;
        require(s.permit, Reconciliation::Matching)
    }
    /// Change public endpoint/WAN under the same allocation. The old policy must
    /// match the kernel exactly; the caller cannot authorize replacement by name.
    pub fn replace_permit(&mut self, next: Policy) -> Result<()> {
        if !self.policy.compatible(&next) {
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
        self.socket
            .batch(&[delete(&self.policy.table(true))], s.generation, deadline)
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
        let t = self.policy.table(false);
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
    fn snapshot(&mut self, deadline: Instant) -> Result<Snapshot> {
        let generation = self.socket.generation(deadline)?;
        let tables = self.socket.dump(1, &[], deadline)?;
        let mut states = Vec::new();
        for quarantine in [true, false] {
            let expected = self.policy.table(quarantine);
            let mut found = None;
            for m in &tables {
                let a = nfattrs(m)?;
                if text(get(&a, 1)?)? == expected.name {
                    if found.is_some() {
                        return Err(Error::Foreign);
                    }
                    found = Some(a);
                }
            }
            let state = match found {
                None => Reconciliation::Absent,
                Some(a) => {
                    if get(&a, 6).ok() != Some(expected.marker.as_slice()) {
                        Reconciliation::Foreign
                    } else {
                        let chains = self.socket.scoped_dump(4, &expected.name, deadline)?;
                        let rules = self.socket.scoped_dump(7, &expected.name, deadline)?;
                        // Owned tables never contain sets, stateful objects or flowtables.
                        // Their presence is functional drift even when no current rule uses them.
                        let mut extras = false;
                        for op in [10, 19, 23] {
                            if !self
                                .socket
                                .scoped_dump(op, &expected.name, deadline)?
                                .is_empty()
                            {
                                extras = true;
                            }
                        }
                        if !extras && verify(&expected, &a, &chains, &rules).is_ok() {
                            Reconciliation::Matching
                        } else {
                            Reconciliation::Drifted
                        }
                    }
                }
            };
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
fn delete(t: &Table) -> (u16, u16, Vec<Attr>) {
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
fn canonical_exprs(exprs: &[Attr]) -> Result<Vec<Vec<u8>>> {
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
