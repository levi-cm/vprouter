use crate::{Error, Result};
use std::{marker::PhantomData, os::unix::fs::MetadataExt, rc::Rc};
/// !Send/!Sync; a worker and all clients stay on its dedicated placed thread.
/// Private fields and no production constructor: observed namespace metadata
/// alone must never authorize an arbitrary host namespace.
pub(crate) struct Placed {
    identity: (u64, u64),
    _thread: PhantomData<Rc<()>>,
}
impl Placed {
    pub(crate) fn authenticated(admission: &crate::bootstrap::MonitorAdmission) -> Result<Self> {
        let result = Self {
            identity: admission.namespace()?,
            _thread: PhantomData,
        };
        result.check()?;
        Ok(result)
    }
    pub fn check(&self) -> Result<()> {
        if identity()? == self.identity {
            Ok(())
        } else {
            Err(Error::NamespaceChanged)
        }
    }
    #[cfg(test)]
    pub fn wrong_namespace() -> Self {
        Self {
            identity: (0, 0),
            _thread: PhantomData,
        }
    }
    #[cfg(test)]
    pub fn synthetic() -> Self {
        Self {
            identity: identity().unwrap(),
            _thread: PhantomData,
        }
    }
}
fn identity() -> Result<(u64, u64)> {
    let m = std::fs::metadata("/proc/thread-self/ns/net").map_err(|_| Error::NamespaceChanged)?;
    Ok((m.dev(), m.ino()))
}
