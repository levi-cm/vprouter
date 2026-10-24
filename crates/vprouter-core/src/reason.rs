use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable machine-readable codes. No untrusted input is carried by an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    InvalidSchema,
    InvalidLabel,
    InvalidPath,
    InvalidImage,
    InvalidServer,
    StateConflict,
    DuplicateId,
    DuplicatePrivateKey,
    HostnameConflict,
    InvalidReference,
    InvalidAdapter,
    InvalidProfile,
    ProfileServerMismatch,
    ProfileUnavailable,
    InvalidEvidence,
    InvalidTransition,
    StaleEvidence,
    ProviderFailure,
    StructuralFailure,
    PolicyUnapproved,
    Stopping,
    AllocationConflict,
    ForeignAllocation,
    InvalidAllocation,
    StorageUnavailable,
    StorageUnsafe,
    LockBusy,
    GenerationConflict,
    DurabilityUncertain,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(Reason);
impl Error {
    pub const fn new(reason: Reason) -> Self {
        Self(reason)
    }
    pub const fn reason(self) -> Reason {
        self.0
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This debug representation is a fixed authored enum, never external text.
        write!(f, "vprouter validation failed: {:?}", self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
pub(crate) fn err(reason: Reason) -> Error {
    Error::new(reason)
}
