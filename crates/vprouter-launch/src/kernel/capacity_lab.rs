//! Native capacity negatives only. Each fixed isolated child closes all inherited
//! private descriptors before touching a witness or constructing its failed job.
use super::*;
use rustix::net::{self, RecvFlags, SendFlags};
use std::{cell::RefCell, rc::Rc};
use vprouter_native_role::ReapWitness;

struct Native {
    creator: u32,
    pid: u32,
    pidfd: OwnedFd,
    channel: OwnedFd,
    tokens: Vec<super::super::inventory::Registration>,
    reap: Rc<ParentReap>,
    _capacity: ChildCapacity,
}
struct Owner(Option<Native>);
thread_local! { static RETAINED:RefCell<Vec<Native>>=const{RefCell::new(Vec::new())}; }
impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(n) = self.0.take() {
            if n.creator != std::process::id() {
                std::mem::forget(n);
                return;
            }
            let _ = send_or_exited(n.pidfd.as_fd(), libc::SIGKILL);
            RETAINED.with(|r| r.borrow_mut().push(n));
        }
    }
}
pub(super) fn poll_retained() {
    RETAINED.with(|r| {
        for n in r.borrow().iter() {
            if n.creator == std::process::id() {
                let _ = n.reap.poll(n.pid, n.pidfd.as_fd());
            }
        }
    });
}
pub(super) fn children_reaped() -> bool {
    RETAINED.with(|r| {
        r.borrow()
            .iter()
            .all(|n| n.creator != std::process::id() || n.reap.status.get().is_some())
    })
}
// A closed mode: None creates only a failed original constructor; Some checks
// the otherwise eligible original witness inherited from the assembly owner.
fn run(original: Option<&ReapWitness>) -> Result<serde_json::Value> {
    secret::seal_parent()?;
    if let Some(r) = original {
        r.require_completed_capacity()
            .map_err(|_| Error::OwnershipMismatch)?;
    }
    let eligible_original = original
        .map(ReapWitness::original)
        .transpose()
        .map_err(|_| Error::OwnershipMismatch)?;
    let creator = std::process::id();
    let before = [
        live_child_count(),
        vprouter_native_role::lab_live_child_capacity(),
    ];
    let requested_at = vprouter_core::health::boot_seconds();
    let end = requested_at + 2.;
    let (channel, child_channel) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let token = super::super::inventory::Registration::owned(&[channel.as_fd()])?;
    let child_token = super::super::inventory::Registration::owned(&[child_channel.as_fd()])?;
    require_child_capacity()?;
    let (pid, pidfd) = fork_with_pidfd()?;
    if pid == 0 {
        let answer = (|| {
            cv(
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) },
                Error::ChildFailed,
            )?;
            if unsafe { libc::getppid() } != creator as i32 {
                return Err(Error::ChildFailed);
            }
            let null = fs::open("/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                .map_err(|_| Error::DescriptorNull)?;
            let stat = fs::fstat(&null).map_err(|_| Error::DescriptorNull)?;
            if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::CharacterDevice
                || fs::major(stat.st_rdev) != 1
                || fs::minor(stat.st_rdev) != 3
            {
                return Err(Error::DescriptorNull);
            }
            for fd in 0..3 {
                dup_fixed(&null, fd, false)?;
            }
            drop(null);
            secret::non_dumpable()?;
            close_except(&[child_channel.as_raw_fd()])?;
            secret::gate(child_channel.as_fd(), end)?;
            let mut packet = [0u8; 24];
            if let Some(r) = original {
                let count = vprouter_native_role::lab_live_child_capacity();
                if r.require_completed_capacity() != Err(vprouter_native_role::Error::Creator)
                    || r.retire_completed_capacity() != Err(vprouter_native_role::Error::Creator)
                    || vprouter_native_role::lab_live_child_capacity() != count
                {
                    return Err(Error::OwnershipMismatch);
                }
                packet[0] = 2;
            } else {
                let evidence = vprouter_native_role::lab_capacity_refusal_selftest(end)
                    .map_err(|_| Error::ChildFailed)?;
                packet[0] = 1;
                packet[1..5].copy_from_slice(&evidence.failed_pid.to_le_bytes());
                packet[5..13].copy_from_slice(&evidence.failed_start.unwrap_or(0).to_le_bytes());
                packet[13..17].copy_from_slice(&(evidence.charges as u32).to_le_bytes());
                packet[17..21].copy_from_slice(&evidence.actual_wait_status.to_le_bytes());
            }
            if net::send(
                &child_channel,
                &packet,
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            )
            .map_err(|_| Error::ChildFailed)?
                != packet.len()
            {
                return Err(Error::ChildFailed);
            }
            Ok(())
        })();
        die(if answer.is_ok() { 0 } else { 122 });
    }
    let mut owner = Owner(Some(Native {
        creator: std::process::id(),
        pid: pid as u32,
        pidfd: pidfd.expect("original atomic pidfd"),
        channel,
        tokens: vec![token],
        reap: ParentReap::born(pid as u32).expect("original parent"),
        _capacity: ChildCapacity::created(),
    }));
    drop(child_token);
    drop(child_channel);
    let n = owner.0.as_mut().ok_or(Error::Interrupted)?;
    n.tokens
        .push(super::super::inventory::Registration::owned(&[n
            .pidfd
            .as_fd()])?);
    if wait_ready(n.pidfd.as_fd(), Duration::ZERO)? {
        return Err(Error::ChildFailed);
    }
    let start = process::stat_start(
        &std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| Error::ProcessUnavailable)?,
        pid as u32,
    )?;
    if wait_ready(n.pidfd.as_fd(), Duration::ZERO)? {
        return Err(Error::ChildFailed);
    }
    n.reap.start.set(Some(start));
    write_byte(n.channel.as_fd(), 1)?;
    loop {
        namespace_attachment::check(end)?;
        if let Some(status) = n.reap.poll(n.pid, n.pidfd.as_fd())? {
            if status != 0 {
                return Err(Error::ChildFailed);
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut packet = [0u8; 24];
    if net::recv(
        &n.channel,
        &mut packet,
        RecvFlags::DONTWAIT | RecvFlags::TRUNC,
    )
    .map_err(|_| Error::ChildFailed)?
        != (24, 24)
        || net::recv(&n.channel, &mut [0u8; 1], RecvFlags::DONTWAIT)
            .map_err(|_| Error::ChildFailed)?
            != (0, 0)
        || packet[21..] != [0; 3]
        || packet[0] != if original.is_some() { 2 } else { 1 }
    {
        return Err(Error::ChildFailed);
    }
    let failed_pid = u32::from_le_bytes(packet[1..5].try_into().expect("fixed"));
    let failed_start = u64::from_le_bytes(packet[5..13].try_into().expect("fixed"));
    let failed_count = u32::from_le_bytes(packet[13..17].try_into().expect("fixed"));
    let failed_status = i32::from_le_bytes(packet[17..21].try_into().expect("fixed"));
    if original.is_none()
        && (failed_pid == 0
            || failed_pid == pid as u32
            || failed_count != 1
            || failed_status != (122 << 8))
        || original.is_some() && packet[1..] != [0; 23]
    {
        return Err(Error::ChildFailed);
    }
    if let Some(r) = original {
        r.require_completed_capacity()
            .map_err(|_| Error::OwnershipMismatch)?;
    }
    drop(owner.0.take());
    let after = [
        live_child_count(),
        vprouter_native_role::lab_live_child_capacity(),
    ];
    if before != after {
        return Err(Error::OwnershipMismatch);
    }
    let verified_at = vprouter_core::health::boot_seconds();
    namespace_attachment::check(end)?;
    Ok(
        serde_json::json!({"schema":1,"requested_at":requested_at,"deadline":end,"verified_at":verified_at,
        "original_pid":pid,"original_start":start,"actual_wait_status":0,"eof":true,
        "failed_original_pid":if original.is_none(){Some(failed_pid)}else{None},
        "failed_original_start":if failed_start==0{None}else{Some(failed_start)},
        "failed_actual_wait_status":if original.is_none(){Some(failed_status)}else{None},
        "failed_exit_code":if original.is_none(){Some(libc::WEXITSTATUS(failed_status))}else{None},
        "failed_charges_unchanged":if original.is_none(){Some([failed_count,failed_count])}else{None},
        "eligible_original_pid":eligible_original.map(|v|v.0),"eligible_original_start":eligible_original.and_then(|v|v.1),
        "eligible_foreign_refused":original.is_some(),"parent_still_eligible":original.is_some(),
        "parent_counts_before":before,"parent_counts_after":after,
        "canonical_operation":false,"successful_capacity_transfer_proven":false}),
    )
}
pub(super) fn failed_selftest() -> Result<()> {
    let proof = run(None)?;
    println!("LAB_ASSEMBLY_CAPACITY_REFUSALS {proof}");
    Ok(())
}
pub(super) fn eligible_foreign(original: &ReapWitness) -> Result<serde_json::Value> {
    run(Some(original))
}
