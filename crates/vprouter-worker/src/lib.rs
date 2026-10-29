//! Namespace-local native monitoring; no production launch/guard authority yet.
#![forbid(unsafe_code)]
// The engine is compiled in production, but cannot be constructed until the
// reviewed placement and independent guard bridge exists. No feature bypass.
#![allow(dead_code)]
pub mod bootstrap;
mod client;
mod dns;
mod engine;
mod json;
mod localapi;
pub mod monitor;
pub mod operation;
mod placement;
mod provider;
mod publish;

use serde::Serialize;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    StructuralGap,
    Bootstrap,
    NamespaceChanged,
    DirectUnsupported,
    InvalidConfiguration,
    Deadline,
    Cancelled,
    Transport,
    Tls,
    Malformed,
    Oversized,
    HttpPermanent,
    HttpTransient,
    ProviderNegative,
    WrongServer,
    Structural,
    Identity,
    Preferences,
    GuardUnavailable,
    InitUnavailable,
    Storage,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

/// Public startup fails before creating ANY client/socket/runtime. Task8 must
/// bind an unforgeable launch+allocation+guard authority before enabling this.
/// There is no caller-supplied namespace ID, boolean quarantine, or test feature.
pub fn start() -> Result<()> {
    Err(Error::StructuralGap)
}

#[cfg(test)]
mod tests;
