//! Trusted launch-kernel mechanics. Canonical durable Birth permission remains
//! in launch, whose private wrapper alone owns the parent release endpoint.
//! Network's pending operation receives only the opposite child endpoint.
use crate::{
    Error, Result, linux,
    wireguard::{ReapState, ReapWitness},
};
use rustix::net::{self, SendFlags};
use std::{
    cell::{Cell, RefCell},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    rc::Rc,
};

pub(crate) struct Origin {
    pub(crate) creator: u32,
    pub(crate) request: [u8; 32],
    pub(crate) end: f64,
    pub(crate) reap: RefCell<Option<Rc<ReapState>>>,
    pub(crate) released: Cell<bool>,
}
/// Non-Clone original endpoint. This type is not a durable-write receipt: the
/// launch-private adapter checks its canonical receipt before invoking release.
pub struct WireguardReleaseGate {
    origin: Rc<Origin>,
    channel: Option<OwnedFd>,
    identity: (u64, u64, u32),
}
/// Opposite endpoint only. Writing here cannot release the child: messages go
/// to the retained launch endpoint, which never interprets inbound commands.
pub struct WireguardChildGate {
    origin: Rc<Origin>,
    channel: Option<OwnedFd>,
}
pub fn prepare_wireguard_gate(
    request: [u8; 32],
    end: f64,
) -> Result<(WireguardReleaseGate, WireguardChildGate)> {
    linux::preflight()?;
    linux::deadline(end)?;
    if request == [0; 32] {
        return Err(Error::Protocol);
    }
    let (parent, child) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::Descriptor)?;
    let stat = rustix::fs::fstat(&parent).map_err(|_| Error::Descriptor)?;
    let origin = Rc::new(Origin {
        creator: std::process::id(),
        request,
        end,
        reap: RefCell::new(None),
        released: Cell::new(false),
    });
    Ok((
        WireguardReleaseGate {
            origin: origin.clone(),
            channel: Some(parent),
            identity: (stat.st_dev, stat.st_ino, stat.st_mode),
        },
        WireguardChildGate {
            origin,
            channel: Some(child),
        },
    ))
}
impl WireguardChildGate {
    pub fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        if self.origin.creator != std::process::id() {
            return Err(Error::Creator);
        }
        Ok(self.channel.as_ref().ok_or(Error::Interrupted)?.as_fd())
    }
    pub(crate) fn take(mut self, request: [u8; 32], end: f64) -> Result<(OwnedFd, Rc<Origin>)> {
        if self.origin.creator != std::process::id()
            || request != self.origin.request
            || end != self.origin.end
            || self.origin.reap.borrow().is_some()
            || self.origin.released.get()
        {
            return Err(Error::Creator);
        }
        Ok((
            self.channel.take().ok_or(Error::Interrupted)?,
            self.origin.clone(),
        ))
    }
}
impl WireguardReleaseGate {
    pub fn descriptor(&self) -> Result<BorrowedFd<'_>> {
        if self.origin.creator != std::process::id() {
            return Err(Error::Creator);
        }
        Ok(self.channel.as_ref().ok_or(Error::Interrupted)?.as_fd())
    }
    /// Same original Rc, not equality of caller-controlled PID/digest scalars.
    pub fn matches(&self, child: &ReapWitness) -> Result<bool> {
        if self.origin.creator != std::process::id() {
            return Err(Error::Creator);
        }
        Ok(self
            .origin
            .reap
            .borrow()
            .as_ref()
            .is_some_and(|own| Rc::ptr_eq(own, &child.inner)))
    }
    pub fn release(&mut self, child: &ReapWitness) -> Result<()> {
        if !self.matches(child)?
            || self.origin.released.get()
            || child.original()?.1.is_none()
            || child.actual_status()?.is_some()
        {
            return Err(Error::Creator);
        }
        linux::deadline(self.origin.end)?;
        let fd = self.descriptor()?;
        let stat = rustix::fs::fstat(fd).map_err(|_| Error::Descriptor)?;
        if (stat.st_dev, stat.st_ino, stat.st_mode) != self.identity
            || !rustix::io::fcntl_getfd(fd)
                .map_err(|_| Error::Descriptor)?
                .contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(Error::Descriptor);
        }
        #[cfg(feature = "lab")]
        {
            let count = crate::wireguard::live_count();
            if child.require_completed_capacity() != Err(Error::Native)
                || child.retire_completed_capacity() != Err(Error::Native)
                || crate::wireguard::live_count() != count
            {
                return Err(Error::Capacity);
            }
            child.inner.gated_capacity_refused.set(true);
        }
        // One attempt, including ambiguous/error sends. Never remint authority.
        self.origin.released.set(true);
        if net::send(fd, &[1], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
            .map_err(|_| Error::Native)?
            != 1
        {
            return Err(Error::Protocol);
        }
        linux::deadline(self.origin.end)
    }
    pub fn cancel(&mut self) {
        if self.origin.creator == std::process::id()
            && let Some(fd) = &self.channel
        {
            let _ = net::shutdown(fd, net::Shutdown::Both);
        }
    }
}
impl Drop for WireguardReleaseGate {
    fn drop(&mut self) {
        if self.origin.creator != std::process::id() {
            if let Some(fd) = self.channel.take() {
                std::mem::forget(fd);
            }
        } else {
            self.cancel();
        }
    }
}
impl Drop for WireguardChildGate {
    fn drop(&mut self) {
        if self.origin.creator != std::process::id()
            && let Some(fd) = self.channel.take()
        {
            std::mem::forget(fd);
        }
    }
}
