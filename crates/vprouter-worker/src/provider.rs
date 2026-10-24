use crate::{
    Error, Result,
    client::{ATTEMPT, Http},
    dns, json,
    placement::Placed,
};
use serde::Deserialize;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    rc::Rc,
    sync::Arc,
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
const LIMIT: usize = 16384;
#[derive(Deserialize)]
struct Document {
    mullvad_exit_ip: bool,
    ip: Ipv4Addr,
    mullvad_exit_ip_hostname: String,
}
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Confirmation {
    pub ip: Ipv4Addr,
    pub server: String,
}
pub(crate) fn parse(bytes: &[u8], expected: &str) -> Result<Confirmation> {
    if bytes.len() > LIMIT {
        return Err(Error::Oversized);
    }
    let d: Document = json::decode(bytes)?;
    if !d.mullvad_exit_ip || !vprouter_core::profile::public_ipv4(d.ip) {
        return Err(Error::ProviderNegative);
    }
    if d.mullvad_exit_ip_hostname != expected {
        return Err(Error::WrongServer);
    }
    Ok(Confirmation {
        ip: d.ip,
        server: d.mullvad_exit_ip_hostname,
    })
}
/// Reusable HTTPS session belongs to exactly one verified placed worker thread.
/// Fixed URL/SNI; no arbitrary endpoint or root store in the production API.
pub(crate) struct Provider {
    placed: Rc<Placed>,
    connector: TlsConnector,
    dns: SocketAddrV4,
    http: Option<Http>,
    expected: String,
    #[cfg(test)]
    address: Option<std::net::SocketAddr>,
}
impl Provider {
    pub fn new(placed: Rc<Placed>, dns: Ipv4Addr, expected: &str) -> Result<Self> {
        placed.check()?;
        vprouter_core::state::HealthMachine::new(
            vprouter_core::config::ExitMode::Mullvad,
            Some(expected),
            "validation",
        )
        .map_err(|_| Error::InvalidConfiguration)?;
        // Explicit Mullvad DNS must be a private tunnel destination. Public DNS
        // and arbitrary host resolver config are not an accepted policy here.
        if !dns.is_private() {
            return Err(Error::InvalidConfiguration);
        }
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(placed, dns, expected, roots)
    }
    fn with_roots(
        placed: Rc<Placed>,
        dns: Ipv4Addr,
        expected: &str,
        roots: rustls::RootCertStore,
    ) -> Result<Self> {
        placed.check()?;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            placed,
            connector: TlsConnector::from(Arc::new(config)),
            dns: SocketAddrV4::new(dns, 53),
            http: None,
            expected: expected.into(),
            #[cfg(test)]
            address: None,
        })
    }
    pub async fn confirm(&mut self) -> Result<Confirmation> {
        self.placed.check()?;
        let result = timeout(ATTEMPT, self.attempt())
            .await
            .map_err(|_| Error::Deadline)
            .and_then(|r| r);
        if result.is_err() {
            self.http = None;
        }
        self.placed.check()?;
        result
    }
    pub fn cancel(&mut self) {
        self.http = None;
    }
    async fn attempt(&mut self) -> Result<Confirmation> {
        if self.http.is_none() {
            #[cfg(test)]
            let address = match self.address {
                Some(a) => a,
                None => std::net::SocketAddr::from(SocketAddrV4::new(
                    dns::resolve(self.dns).await?,
                    443,
                )),
            };
            #[cfg(not(test))]
            let address = SocketAddrV4::new(dns::resolve(self.dns).await?, 443);
            self.placed.check()?;
            let tcp = TcpStream::connect(address)
                .await
                .map_err(|_| Error::Transport)?;
            let name =
                rustls::pki_types::ServerName::try_from(dns::PROVIDER).map_err(|_| Error::Tls)?;
            let tls = self.connector.connect(name, tcp).await.map_err(|e| {
                if crate::client::transient_io(&e) == Some(true) {
                    Error::Transport
                } else {
                    Error::Tls
                }
            })?;
            self.http = Some(Http::connect(tls).await?);
        }
        let reply = self
            .http
            .as_mut()
            .ok_or(Error::Transport)?
            .request("GET", "/json", dns::PROVIDER, b"", LIMIT)
            .await?;
        parse(&reply.body, &self.expected)
    }
    #[cfg(test)]
    pub fn synthetic(
        placed: Rc<Placed>,
        roots: rustls::RootCertStore,
        address: std::net::SocketAddr,
    ) -> Self {
        let mut p =
            Self::with_roots(placed, "10.64.0.1".parse().unwrap(), "de-fra-wg-404", roots).unwrap();
        p.address = Some(address);
        p
    }
}
