//! Narrow IPv4 endpoint exceptions in Docker's later FORWARD/DROP base chain.
//! Never flush, rewrite or decode arbitrary foreign rule actions.
use crate::{Error, Policy, Result, actuator::canonical_exprs, codec::*, socket::Socket};
use std::time::Instant;
const IP: u8 = 2;
const TABLE: &str = "filter";
const CHAIN: &str = "FORWARD";
struct Rule {
    handle: u64,
    marker: Vec<u8>,
    expressions: Vec<Attr>,
}
pub(crate) struct Cooperation {
    table: u64,
    chain: u64,
    rules: Vec<Rule>,
}
fn u64a(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| Error::Malformed)?,
    ))
}
fn scoped(socket: &mut Socket, op: u16, end: Instant) -> Result<Vec<Vec<Attr>>> {
    let mut out = Vec::new();
    for m in socket.dump_family(op, &[string(1, TABLE)], IP, end)? {
        let a = nfattrs(&m)?;
        unique(&a)?;
        if text(get(&a, 1)?)? == TABLE
            && (op == 1 || text(get(&a, if op == 4 { 3 } else { 2 })?)? == CHAIN)
        {
            out.push(a);
        }
    }
    Ok(out)
}
fn identity(socket: &mut Socket, end: Instant) -> Result<(u64, u64)> {
    let tables = scoped(socket, 1, end)?;
    let chains = scoped(socket, 4, end)?;
    if tables.len() != 1 || chains.len() != 1 {
        return Err(Error::Foreign);
    }
    let t = &tables[0];
    let c = &chains[0];
    if be32(get(t, 2)?)? != 0 || text(get(c, 7)?)? != "filter" || be32(get(c, 5)?)? != 0 {
        return Err(Error::Foreign);
    }
    // Supported oracle: IPv4/filter/FORWARD, hook2/prio0/DROP. Counter/use
    // bookkeeping can move; table and chain handles themselves must remain exact.
    if c.iter()
        .any(|a| ![1, 2, 3, 4, 5, 6, 7, 8, 10].contains(&(a.kind & 0x3fff)))
    {
        return Err(Error::Drifted);
    }
    let hook = attrs(get(c, 4)?)?;
    unique(&hook)?;
    if hook.len() != 2
        || be32(get(&hook, 1)?)? != 2
        || be32(get(&hook, 2)?)? != 0
        || be32(get(c, 10)?)? != 1
    {
        return Err(Error::Foreign);
    }
    Ok((u64a(get(t, 4)?)?, u64a(get(c, 2)?)?))
}
impl Cooperation {
    pub fn install(socket: &mut Socket, p: &Policy, end: Instant) -> Result<Self> {
        let generation = socket.generation(end)?;
        let (table, chain) = identity(socket, end)?;
        let prefix = format!("{}:docker-forward:", p.binding()).into_bytes();
        let existing = scoped(socket, 7, end)?;
        // No adoption by name/marker after interrupted creation.
        if existing
            .iter()
            .any(|a| get(a, 7).is_ok_and(|m| m.starts_with(&prefix)))
        {
            return Err(Error::Foreign);
        }
        let mut rules = Vec::new();
        let mut ops = Vec::new();
        for reverse in [false, true] {
            let mut marker = prefix.clone();
            marker.push(u8::from(reverse));
            let expressions = crate::policy::flatten(p.flow(reverse, true));
            ops.push((
                NFT | 6,
                CREATE | EXCL,
                vec![
                    string(1, TABLE),
                    string(2, CHAIN),
                    nested(4, &expressions),
                    attr(7, marker.clone()),
                ],
            ));
            rules.push(Rule {
                handle: 0,
                marker,
                expressions,
            });
        }
        if socket.generation(end)? != generation {
            return Err(Error::GenerationChanged);
        }
        socket.batch_family(&ops, generation, IP, end)?;
        let observed = scoped(socket, 7, end)?;
        for rule in &mut rules {
            let matches: Vec<_> = observed
                .iter()
                .filter(|a| get(a, 7).ok() == Some(rule.marker.as_slice()))
                .collect();
            if matches.len() != 1 {
                return Err(Error::Drifted);
            }
            check_rule(matches[0], rule, false)?;
            rule.handle = u64a(get(matches[0], 3)?)?;
        }
        let result = Self {
            table,
            chain,
            rules,
        };
        result.verify(socket, end)?;
        Ok(result)
    }
    pub fn verify(&self, socket: &mut Socket, end: Instant) -> Result<()> {
        let generation = socket.generation(end)?;
        if identity(socket, end)? != (self.table, self.chain) {
            return Err(Error::Drifted);
        }
        let rows = scoped(socket, 7, end)?;
        for rule in &self.rules {
            let selected: Vec<_> = rows
                .iter()
                .filter(|a| {
                    get(a, 7).ok() == Some(rule.marker.as_slice())
                        || get(a, 3).ok().and_then(|v| u64a(v).ok()) == Some(rule.handle)
                })
                .collect();
            if selected.len() != 1 {
                return Err(Error::Drifted);
            }
            check_rule(selected[0], rule, true)?;
        }
        if socket.generation(end)? != generation {
            return Err(Error::GenerationChanged);
        }
        Ok(())
    }
    pub fn cleanup(&self, socket: &mut Socket, end: Instant) -> Result<()> {
        let generation = socket.generation(end)?;
        self.verify(socket, end)?;
        let ops = self
            .rules
            .iter()
            .map(|r| {
                (
                    NFT | 8,
                    0,
                    vec![
                        string(1, TABLE),
                        string(2, CHAIN),
                        attr(3, r.handle.to_be_bytes()),
                    ],
                )
            })
            .collect::<Vec<_>>();
        socket.batch_family(&ops, generation, IP, end)
    }
}
fn check_rule(a: &[Attr], r: &Rule, handle: bool) -> Result<()> {
    if a.iter()
        .any(|a| ![1, 2, 3, 4, 6, 7, 8].contains(&(a.kind & 0x3fff)))
        || text(get(a, 1)?)? != TABLE
        || text(get(a, 2)?)? != CHAIN
        || get(a, 7)? != r.marker
        || handle && u64a(get(a, 3)?)? != r.handle
        || canonical_exprs(&attrs(get(a, 4)?)?)? != canonical_exprs(&r.expressions)?
    {
        return Err(Error::Drifted);
    }
    Ok(())
}
