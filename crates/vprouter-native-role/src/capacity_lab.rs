//! Isolated native eligibility regression. No successful operation or resource
//! authority is produced; the original failed child remains retained until the
//! isolated test process exits.
use crate::{
    Error, ForkOutcome, PreparedWireguard, Result, WireguardDescriptors, linux, wireguard,
};
use rustix::net;
use std::os::fd::AsFd;

#[derive(Clone, Copy)]
pub struct Evidence {
    pub failed_pid: u32,
    pub failed_start: Option<u64>,
    pub charges: usize,
    pub actual_wait_status: i32,
}
pub fn failed_refusal(end: f64) -> Result<Evidence> {
    linux::preflight()?;
    linux::deadline(end)?;
    let namespace = rustix::fs::open(
        "/proc/thread-self/ns/net",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| Error::Descriptor)?;
    let socket = |protocol| {
        let fd = net::socket_with(
            net::AddressFamily::NETLINK,
            net::SocketType::RAW,
            net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
            protocol,
        )
        .map_err(|_| Error::Descriptor)?;
        net::bind(&fd, &net::netlink::SocketAddrNetlink::new(0, 0))
            .map_err(|_| Error::Descriptor)?;
        Ok(fd)
    };
    let route = socket(None)?;
    let generic = socket(Some(net::netlink::GENERIC))?;
    let (mut gate, child_gate) = crate::prepare_wireguard_gate([91; 32], end)?;
    let prepared = PreparedWireguard::new(
        WireguardDescriptors {
            profiles: &[],
            route: route.as_fd(),
            generic: generic.as_fd(),
            namespace: namespace.as_fd(),
        },
        [91; 32],
        end,
        child_gate,
    )?;
    let (mut child, original) = match prepared.birth()? {
        ForkOutcome::Child(role) => role.fail(),
        ForkOutcome::Parent(child, original) => (child, original),
    };
    // With namespace privilege the fixed child waits at its original gate;
    // without it the real fixed setup exits122. Both are failure-only cases.
    if child.identify().is_ok() {
        // Setup can have failed between the original liveness checks and this
        // send. A refused send is not completion; only actual122 below counts.
        let _ = gate.release(&original);
    }
    let before = wireguard::live_count();
    if before != 1 {
        return Err(Error::Capacity);
    }
    loop {
        linux::deadline(end)?;
        if let Some(status) = child.collect()? {
            if status != (122 << 8) {
                return Err(Error::Native);
            }
            break;
        }
        std::thread::yield_now();
    }
    if original.actual_status()? != Some(122 << 8)
        || original.require_completed_capacity() != Err(Error::Native)
        || original.retire_completed_capacity() != Err(Error::Native)
        || wireguard::live_count() != before
    {
        return Err(Error::Capacity);
    }
    // Failed original context is retained by the real Child Drop. It is not
    // accepted, repaired, or counted as a successful resource transfer.
    drop(child);
    if wireguard::live_count() != before {
        return Err(Error::Capacity);
    }
    let (failed_pid, failed_start) = original.original()?;
    Ok(Evidence {
        failed_pid,
        failed_start,
        charges: before,
        actual_wait_status: original.actual_status()?.ok_or(Error::Native)?,
    })
}
