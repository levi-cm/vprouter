//! Retained, route-only parent observations. Each poll handles at most one
//! nonblocking netlink datagram; every phase keeps one original operation end.
use super::*;
use crate::socket::RouteRead;

enum Want {
    Absent(String),
    Token { name: String, kind: String },
    Down(Link),
}
#[derive(Clone, Copy)]
enum Phase {
    Links,
    Addresses4,
    Addresses6,
    Routes4,
    Routes6,
    Complete,
}
pub(crate) enum ReadbackResult {
    Absent,
    Token(DownLink),
    Down(Link),
}
pub(crate) struct Readback {
    namespace: NamespaceIdentity,
    plan: Plan,
    want: Want,
    phase: Phase,
    end: Instant,
    boot_end: f64,
    exchange: Option<RouteRead>,
    link: Option<Link>,
    addresses: Vec<Address>,
    routes: Vec<Route>,
}
impl Readback {
    fn check(&self) -> Result<()> {
        crate::secret_role::end_instant(self.boot_end)?;
        if Instant::now() >= self.end {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}
impl NativeNetwork {
    fn start_readback(&self, want: Want, end: f64) -> Result<Readback> {
        let instant = crate::secret_role::end_instant(end)?;
        self.route.sequence()?;
        Ok(Readback {
            namespace: self.namespace,
            plan: self.plan.clone(),
            want,
            phase: Phase::Links,
            end: instant,
            boot_end: end,
            exchange: None,
            link: None,
            addresses: Vec::new(),
            routes: Vec::new(),
        })
    }
    pub(crate) fn start_absent_readback(&self, name: &str, end: f64) -> Result<Readback> {
        self.start_readback(Want::Absent(name.into()), end)
    }
    pub(crate) fn start_token_readback(
        &self,
        name: &str,
        kind: &str,
        end: f64,
    ) -> Result<Readback> {
        self.start_readback(
            Want::Token {
                name: name.into(),
                kind: kind.into(),
            },
            end,
        )
    }
    pub(crate) fn start_down_readback(&self, token: &DownLink, end: f64) -> Result<Readback> {
        if self.namespace != token.namespace {
            return Err(Error::NamespaceUnverified);
        }
        self.start_readback(Want::Down(token.link.clone()), end)
    }
    pub(crate) fn poll_readback(&mut self, r: &mut Readback) -> Result<Option<ReadbackResult>> {
        if r.namespace != self.namespace
            || r.plan != self.plan
            || matches!(r.phase, Phase::Complete)
        {
            return Err(Error::Foreign);
        }
        r.check()?;
        if r.exchange.is_none() {
            let message = match r.phase {
                Phase::Links => N::GetLink(LinkMessage::default()),
                Phase::Addresses4 | Phase::Addresses6 => {
                    let mut m = AddressMessage::default();
                    m.header.family = if matches!(r.phase, Phase::Addresses4) {
                        AddressFamily::Inet
                    } else {
                        AddressFamily::Inet6
                    };
                    N::GetAddress(m)
                }
                Phase::Routes4 | Phase::Routes6 => {
                    let mut m = RouteMessage::default();
                    m.header.address_family = if matches!(r.phase, Phase::Routes4) {
                        AddressFamily::Inet
                    } else {
                        AddressFamily::Inet6
                    };
                    N::GetRoute(m)
                }
                Phase::Complete => return Err(Error::Interrupted),
            };
            r.exchange = Some(self.route.start_route_read(message, r.end)?);
        }
        let Some(data) = self
            .route
            .poll_route_read(r.exchange.as_mut().ok_or(Error::Interrupted)?)?
        else {
            return Ok(None);
        };
        r.exchange.take();
        match r.phase {
            Phase::Links => {
                let mut links = Vec::new();
                for bytes in data {
                    let N::NewLink(m) = project::route_message(&bytes)? else {
                        return Err(Error::Malformed);
                    };
                    links.push(project::link(m)?);
                }
                match &r.want {
                    Want::Absent(name) => {
                        if links.iter().any(|l| &l.name == name) {
                            return Err(Error::Foreign);
                        }
                        r.phase = Phase::Complete;
                        r.check()?;
                        return Ok(Some(ReadbackResult::Absent));
                    }
                    Want::Token { name, kind } => {
                        let l = links
                            .into_iter()
                            .find(|l| &l.name == name)
                            .ok_or(Error::Absent)?;
                        if &l.kind != kind
                            || l.alias != self.plan.alias
                            || l.up
                            || l.mtu != 1420
                            || l.controller != 0
                            || !l.port_kind.is_empty()
                            || l.promiscuity != 0
                            || l.all_multicast != 0
                            || !l.alternate_names.is_empty()
                        {
                            return Err(Error::Drifted);
                        }
                        r.link = Some(l);
                    }
                    Want::Down(token) => {
                        let l = links
                            .into_iter()
                            .find(|l| l.index == token.index)
                            .ok_or(Error::Absent)?;
                        if &l != token
                            || l.alias != self.plan.alias
                            || l.up
                            || l.controller != 0
                            || !l.port_kind.is_empty()
                            || l.promiscuity != 0
                            || l.all_multicast != 0
                            || !l.alternate_names.is_empty()
                            || ![
                                self.plan.wireguard_name(),
                                self.plan.host_name(),
                                self.plan.transport_name(),
                            ]
                            .contains(&l.name.as_str())
                        {
                            return Err(Error::Drifted);
                        }
                        r.link = Some(l);
                    }
                }
                r.phase = Phase::Addresses4;
            }
            Phase::Addresses4 | Phase::Addresses6 => {
                for bytes in data {
                    let N::NewAddress(m) = project::route_message(&bytes)? else {
                        return Err(Error::Malformed);
                    };
                    r.addresses.push(project::address(m)?);
                }
                if matches!(r.phase, Phase::Addresses4) {
                    r.phase = Phase::Addresses6;
                } else {
                    let l = r.link.as_ref().ok_or(Error::Interrupted)?;
                    if r.addresses.iter().any(|a| a.index == l.index) {
                        return Err(Error::Drifted);
                    }
                    if matches!(r.want, Want::Token { .. }) {
                        r.phase = Phase::Complete;
                        r.check()?;
                        return Ok(Some(ReadbackResult::Token(DownLink {
                            link: r.link.take().ok_or(Error::Interrupted)?,
                            namespace: self.namespace,
                        })));
                    }
                    r.phase = Phase::Routes4;
                }
            }
            Phase::Routes4 | Phase::Routes6 => {
                for bytes in data {
                    let N::NewRoute(m) = project::route_message(&bytes)? else {
                        return Err(Error::Malformed);
                    };
                    r.routes.push(project::route(m)?);
                }
                if matches!(r.phase, Phase::Routes4) {
                    r.phase = Phase::Routes6;
                } else {
                    let l = r.link.as_ref().ok_or(Error::Interrupted)?;
                    if r.routes.iter().any(|v| v.output == l.index) {
                        return Err(Error::Drifted);
                    }
                    r.phase = Phase::Complete;
                    r.check()?;
                    return Ok(Some(ReadbackResult::Down(
                        r.link.take().ok_or(Error::Interrupted)?,
                    )));
                }
            }
            Phase::Complete => return Err(Error::Interrupted),
        }
        r.check()?;
        Ok(None)
    }
}
