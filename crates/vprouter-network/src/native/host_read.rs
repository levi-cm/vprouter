//! Seven bounded ROUTE-only dumps retaining one original socket and deadline.
//! These observations are metadata, never a declaration or mutation capability.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Links,
    Addresses4,
    Addresses6,
    Routes4,
    Routes6,
    Rules4,
    Rules6,
}
impl Phase {
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::Links => Self::Addresses4,
            Self::Addresses4 => Self::Addresses6,
            Self::Addresses6 => Self::Routes4,
            Self::Routes4 => Self::Routes6,
            Self::Routes6 => Self::Rules4,
            Self::Rules4 => Self::Rules6,
            Self::Rules6 => return None,
        })
    }
    fn request(self) -> N {
        match self {
            Self::Links => N::GetLink(LinkMessage::default()),
            Self::Addresses4 | Self::Addresses6 => {
                let mut m = AddressMessage::default();
                m.header.family = if self == Self::Addresses4 {
                    AddressFamily::Inet
                } else {
                    AddressFamily::Inet6
                };
                N::GetAddress(m)
            }
            Self::Routes4 | Self::Routes6 => {
                let mut m = RouteMessage::default();
                m.header.address_family = if self == Self::Routes4 {
                    AddressFamily::Inet
                } else {
                    AddressFamily::Inet6
                };
                N::GetRoute(m)
            }
            Self::Rules4 | Self::Rules6 => {
                let mut m = RuleMessage::default();
                m.header.family = if self == Self::Rules4 {
                    AddressFamily::Inet
                } else {
                    AddressFamily::Inet6
                };
                N::GetRule(m)
            }
        }
    }
}

/// Original, non-replaceable read state. Every unfinished phase holds the same
/// socket's transaction lock, including the interval between native dumps.
pub struct HostRead {
    namespace: NamespaceIdentity,
    boot_end: f64,
    end: Instant,
    phase: Phase,
    // Retain the constructor's exact creator/socket identity after links finish.
    origin: RouteRead,
    exchange: Option<RouteRead>,
    snapshot: Snapshot,
    failure: Option<Error>,
    finished: bool,
}
impl HostRead {
    fn check(&self) -> Result<()> {
        let now = vprouter_core::health::boot_seconds();
        if !now.is_finite() || now >= self.boot_end || Instant::now() >= self.end {
            return Err(Error::Deadline);
        }
        Ok(())
    }
    fn append(&mut self, messages: Vec<zeroize::Zeroizing<Vec<u8>>>) -> Result<()> {
        let count = self.snapshot.links.len()
            + self.snapshot.addresses.len()
            + self.snapshot.routes.len()
            + self.snapshot.rules.len();
        if count.saturating_add(messages.len()) > crate::host_observation::HOST_OBSERVATION_RECORDS
        {
            return Err(Error::Oversized);
        }
        for bytes in messages {
            match (self.phase, project::route_message(&bytes)?) {
                (Phase::Links, N::NewLink(m)) => self.snapshot.links.push(project::link(m)?),
                (Phase::Addresses4 | Phase::Addresses6, N::NewAddress(m)) => {
                    self.snapshot.addresses.push(project::address(m)?);
                }
                (Phase::Routes4 | Phase::Routes6, N::NewRoute(m)) => {
                    self.snapshot.routes.push(project::route(m)?);
                }
                (Phase::Rules4 | Phase::Rules6, N::NewRule(m)) => {
                    self.snapshot.rules.push(project::rule(m)?);
                }
                _ => return Err(Error::Malformed),
            }
        }
        Ok(())
    }
}
impl RouteObserver {
    pub fn start_host_read(&mut self, expires_at: f64) -> Result<HostRead> {
        let end = crate::secret_role::end_instant(expires_at)?;
        let origin = self.route.start_route_read(Phase::Links.request(), end)?;
        Ok(HostRead {
            namespace: self.namespace,
            boot_end: expires_at,
            end,
            phase: Phase::Links,
            origin,
            exchange: None,
            snapshot: Snapshot::default(),
            failure: None,
            finished: false,
        })
    }
    /// At most one nonblocking datagram receive per call; never waits for a
    /// response or invokes a GENERIC/WireGuard query on the ordinary owner.
    pub fn poll_host_read(
        &mut self,
        read: &mut HostRead,
    ) -> Result<Option<crate::HostObservation>> {
        if read.namespace != self.namespace
            || !self.route.owns_route_read(&read.origin)
            || read.finished
        {
            return Err(Error::Foreign);
        }
        if let Some(error) = read.failure {
            return Err(error);
        }
        let result = (|| {
            read.check()?;
            let exchange = if read.phase == Phase::Links {
                &mut read.origin
            } else {
                read.exchange.as_mut().ok_or(Error::Interrupted)?
            };
            let Some(messages) = self.route.poll_route_read(exchange)? else {
                read.check()?;
                return Ok(None);
            };
            read.append(messages)?;
            read.check()?;
            if let Some(next) = read.phase.next() {
                // Reserve before yielding: abandonment cannot unlock the socket
                // halfway through this retained multi-dump observation.
                read.exchange = Some(self.route.start_route_read(next.request(), read.end)?);
                read.phase = next;
                return Ok(None);
            }
            let observation = crate::HostObservation::from_snapshot(
                read.namespace,
                std::mem::take(&mut read.snapshot),
            );
            observation.encode()?;
            read.check()?;
            read.finished = true;
            Ok(Some(observation))
        })();
        if let Err(error) = result {
            read.failure = Some(error);
            self.route.reject_route_read(&read.origin);
        }
        result
    }
}

impl NativeNetwork {
    pub(crate) fn start_host_read(&mut self, expires_at: f64) -> Result<HostRead> {
        let end = crate::secret_role::end_instant(expires_at)?;
        let origin = self.route.start_route_read(Phase::Links.request(), end)?;
        Ok(HostRead {
            namespace: self.namespace,
            boot_end: expires_at,
            end,
            phase: Phase::Links,
            origin,
            exchange: None,
            snapshot: Snapshot::default(),
            failure: None,
            finished: false,
        })
    }
    /// At most one nonblocking datagram receive per call; never waits for a
    /// response or invokes a GENERIC/WireGuard query on the ordinary owner.
    pub(crate) fn poll_host_read(
        &mut self,
        read: &mut HostRead,
    ) -> Result<Option<crate::HostObservation>> {
        if read.namespace != self.namespace
            || !self.route.owns_route_read(&read.origin)
            || read.finished
        {
            return Err(Error::Foreign);
        }
        if let Some(error) = read.failure {
            return Err(error);
        }
        let result = (|| {
            read.check()?;
            let exchange = if read.phase == Phase::Links {
                &mut read.origin
            } else {
                read.exchange.as_mut().ok_or(Error::Interrupted)?
            };
            let Some(messages) = self.route.poll_route_read(exchange)? else {
                read.check()?;
                return Ok(None);
            };
            read.append(messages)?;
            read.check()?;
            if let Some(next) = read.phase.next() {
                // Reserve before yielding: abandonment cannot unlock the socket
                // halfway through this retained multi-dump observation.
                read.exchange = Some(self.route.start_route_read(next.request(), read.end)?);
                read.phase = next;
                return Ok(None);
            }
            let observation = crate::HostObservation::from_snapshot(
                read.namespace,
                std::mem::take(&mut read.snapshot),
            );
            observation.encode()?;
            read.check()?;
            read.finished = true;
            Ok(Some(observation))
        })();
        if let Err(error) = result {
            read.failure = Some(error);
            self.route.reject_route_read(&read.origin);
        }
        result
    }
}
