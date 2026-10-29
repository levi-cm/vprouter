//! Fixed secret validator. The capability below can only be minted after the
//! actual no-fork/no-exec filter is installed in a dedicated native child.
use super::super::owned::preparation::{
    BirthReceipt, Server, ValidationBirth, ValidationIntent, ValidationReceipt,
};
use super::super::secret::Inputs;
use super::*;
use rustix::net::{self, RecvFlags, SendFlags};

const CHUNK: usize = 16 * 1024;
const REPORT_LIMIT: usize = vprouter_core::config::MAX_PUBLIC_CONFIGURATION_BYTES;
pub(crate) fn seal_parent() -> Result<()> {
    process::single_threaded()?;
    if !vprouter_core::secret_boundary::pristine() {
        return Err(Error::ConfinementPolicy);
    }
    non_dumpable()
}
pub(super) fn non_dumpable() -> Result<()> {
    cv(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) },
        Error::ConfinementPolicy,
    )?;
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(Error::ConfinementPolicy);
    }
    Ok(())
}
pub(crate) struct ValidationChild {
    native: Option<Native>,
}
struct Native {
    creator: u32,
    _capacity: ChildCapacity,
    intent: ValidationIntent,
    inputs: Inputs,
    pid: u32,
    pidfd: OwnedFd,
    reap: std::rc::Rc<ParentReap>,
    pidfd_inventory: Option<super::super::inventory::Registration>,
    channel: OwnedFd,
    _channel_inventory: super::super::inventory::Registration,
    birth: Option<ValidationBirth>,
    deadline: f64,
    released: bool,
    failed: Option<Error>,
    frames: Frames,
}
/// The full original context accompanies public facts until their caller has
/// durably recorded the result. It is neither Clone nor Deserialize.
pub(crate) struct Verified {
    native: Native,
    configuration: vprouter_core::config::PublicConfiguration,
    digest: [u8; 32],
    verified_at: f64,
}
/// Public facts and original protected pins, minted only after this exact
/// native validator and the canonical result writer have both actually reaped.
/// This is not namespace/link mutation or UP authority.
pub(crate) struct Validated {
    inputs: Inputs,
    configuration: vprouter_core::config::PublicConfiguration,
    receipt: ValidationReceipt,
}
impl Validated {
    pub(crate) fn provision_descriptors(&self) -> Result<Vec<(String, BorrowedFd<'_>)>> {
        self.inputs.provision_descriptors()
    }
    pub(crate) fn configuration(&self) -> &vprouter_core::config::PublicConfiguration {
        &self.configuration
    }
}
impl Verified {
    pub(crate) fn configuration(&self) -> &vprouter_core::config::PublicConfiguration {
        &self.configuration
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn verified_at(&self) -> f64 {
        self.verified_at
    }
    pub(crate) fn member_fact(&self, member: &str) -> Result<([u8; 32], Option<[u8; 32]>)> {
        self.native.creator()?;
        let exit = self
            .configuration
            .exits()
            .iter()
            .find(|e| e.exit().id == member)
            .ok_or(Error::OwnershipMismatch)?;
        let bytes = serde_json::to_vec(&(exit.exit(), exit.hostname(), exit.profile()))
            .map_err(|_| Error::OwnershipMismatch)?;
        use sha2::Digest;
        Ok((
            sha2::Sha256::digest(bytes).into(),
            exit.profile().map(|p| p.device_public_key()),
        ))
    }
    pub(crate) fn accept(slot: &mut Option<Self>, receipt: ValidationReceipt) -> Result<Validated> {
        let verified = slot.as_ref().ok_or(Error::Interrupted)?;
        verified.native.creator()?;
        receipt.verify(&verified.native.intent, &verified.birth()?, verified.digest)?;
        verified.native.inputs.verify_parent()?;
        check_deadline(verified.native.deadline)?;
        if verified.native.reap.status.get() != Some(0) {
            return Err(Error::OwnershipMismatch);
        }
        // Every fallible verification precedes taking the original context.
        // A refused receipt leaves the pins/job/lease in the failed driver.
        let verified = slot.take().ok_or(Error::Interrupted)?;
        // The native job ticket/OFD/capacity are released only here, after actual
        // validator reap AND durable result writer ACK/readback/actual reap.
        Ok(Validated {
            inputs: verified.native.inputs,
            configuration: verified.configuration,
            receipt,
        })
    }
    pub(crate) fn bind_service(&self, server: &Server) -> Result<()> {
        self.native.intent.same_service(server)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        self.native.birth.clone().ok_or(Error::OwnershipMismatch)
    }
}
thread_local! { static RETIRED: std::cell::RefCell<Vec<Native>> = const { std::cell::RefCell::new(Vec::new()) }; }
#[derive(PartialEq, Eq)]
enum DrainEnd {
    Empty,
    Closed,
}
struct Frames {
    bytes: Vec<u8>,
    total: Option<usize>,
    sequence: u32,
}
impl Frames {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(REPORT_LIMIT),
            total: None,
            sequence: 0,
        }
    }
    fn complete(&self) -> bool {
        self.total == Some(self.bytes.len()) && !self.bytes.is_empty()
    }
    fn receive(&mut self, channel: impl AsFd) -> Result<DrainEnd> {
        // A bounded read loop makes progress before waiting for process exit;
        // the 256KiB public report need not fit a single socket packet/queue.
        for _ in 0..REPORT_LIMIT.div_ceil(CHUNK) + 1 {
            let mut frame = [0u8; CHUNK + 12];
            let (length, full) =
                match net::recv(&channel, &mut frame, RecvFlags::DONTWAIT | RecvFlags::TRUNC) {
                    Err(rustix::io::Errno::AGAIN) => return Ok(DrainEnd::Empty),
                    Err(_) => return Err(Error::DescriptorPolicy),
                    Ok(value) => value,
                };
            if length == 0 {
                return Ok(DrainEnd::Closed);
            }
            if length != full || !(13..=CHUNK + 12).contains(&length) {
                return Err(Error::TooLarge);
            }
            let sequence = u32::from_le_bytes(
                frame[0..4]
                    .try_into()
                    .map_err(|_| Error::DescriptorPolicy)?,
            );
            let total = u32::from_le_bytes(
                frame[4..8]
                    .try_into()
                    .map_err(|_| Error::DescriptorPolicy)?,
            ) as usize;
            let payload = u32::from_le_bytes(
                frame[8..12]
                    .try_into()
                    .map_err(|_| Error::DescriptorPolicy)?,
            ) as usize;
            if sequence != self.sequence
                || total == 0
                || total > REPORT_LIMIT
                || payload != length - 12
                || self.total.is_some_and(|old| old != total)
                || self.bytes.len() + payload > total
                || payload != (total - self.bytes.len()).min(CHUNK)
            {
                return Err(Error::OwnershipMismatch);
            }
            self.total = Some(total);
            self.bytes.extend_from_slice(&frame[12..length]);
            self.sequence = self.sequence.checked_add(1).ok_or(Error::TooLarge)?;
        }
        Err(Error::TooLarge)
    }
}
impl Native {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    fn cancel(&mut self, reason: Error) {
        if self.creator != std::process::id() {
            return;
        }
        self.failed.get_or_insert(reason);
        let _ = net::shutdown(&self.channel, net::Shutdown::Both);
        let _ = send_or_exited(self.pidfd.as_fd(), libc::SIGKILL);
    }
    fn poll_reap(&mut self) -> Result<Option<i32>> {
        self.creator()?;
        if self.pidfd_inventory.is_none() {
            self.pidfd_inventory = Some(super::super::inventory::Registration::owned(&[self
                .pidfd
                .as_fd()])?);
        }
        self.reap.poll(self.pid, self.pidfd.as_fd())
    }
}
impl Drop for ValidationChild {
    fn drop(&mut self) {
        if let Some(mut native) = self.native.take() {
            if native.creator != std::process::id() || native.reap.status.get().is_some() {
                return;
            }
            native.cancel(Error::Interrupted);
            RETIRED.with(|retired| retired.borrow_mut().push(native));
        }
    }
}
pub(super) fn poll_retired() {
    RETIRED.with(|retired| {
        retired.borrow_mut().retain_mut(|native| {
            if native.creator != std::process::id() {
                return true;
            }
            native.cancel(Error::Interrupted);
            native.poll_reap().ok().flatten().is_none()
        })
    });
}
pub(super) fn retired_drained() -> bool {
    RETIRED.with(|retired| {
        retired
            .borrow()
            .iter()
            .all(|native| native.creator != std::process::id())
    })
}
impl ValidationChild {
    pub(crate) fn cancel(&mut self, error: Error) {
        if let Some(native) = &mut self.native {
            native.cancel(error);
        }
    }
    pub(crate) fn collect(&mut self) {
        if let Some(native) = &mut self.native
            && native.creator == std::process::id()
        {
            let _ = native.poll_reap();
        }
    }
    pub(crate) fn reaped(&self) -> bool {
        self.native.as_ref().is_none_or(|native| {
            native.creator == std::process::id() && native.reap.status.get().is_some()
        })
    }
    pub(crate) fn bind_service(&self, server: &Server) -> Result<()> {
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.creator()?;
        native.intent.same_service(server)
    }
    pub(crate) fn birth(&self) -> Result<ValidationBirth> {
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.creator()?;
        native.birth.clone().ok_or(Error::OwnershipMismatch)
    }
    pub(crate) fn release(&mut self, receipt: BirthReceipt) -> Result<()> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.creator()?;
        let result = (|| {
            if native.failed.is_some() || native.released {
                return Err(Error::Interrupted);
            }
            receipt.verify(
                &native.intent,
                native.birth.as_ref().ok_or(Error::OwnershipMismatch)?,
            )?;
            check_deadline(native.deadline)?;
            if net::send(
                &native.channel,
                &[1],
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            )
            .map_err(|_| Error::DescriptorPolicy)?
                != 1
            {
                return Err(Error::DescriptorPolicy);
            }
            native.released = true;
            check_deadline(native.deadline)
        })();
        if let Err(error) = result {
            native.cancel(error);
        }
        result
    }
    pub(crate) fn poll(&mut self) -> Result<Option<Verified>> {
        let native = self.native.as_mut().ok_or(Error::Interrupted)?;
        native.creator()?;
        if let Some(error) = native.failed {
            let _ = native.poll_reap();
            return Err(error);
        }
        let result = (|| {
            if !native.released {
                return Err(Error::OwnershipMismatch);
            }
            check_deadline(native.deadline)?;
            native.frames.receive(&native.channel)?;
            check_deadline(native.deadline)?;
            let Some(status) = native.poll_reap()? else {
                return Ok(None);
            };
            // EAGAIN above can race the final send+exit. The actual terminal
            // receipt closes the producer; drain its remaining bounded packets
            // under the SAME deadline, also rejecting any trailing packet.
            if native.frames.receive(&native.channel)? != DrainEnd::Closed {
                return Err(Error::DescriptorPolicy);
            }
            check_deadline(native.deadline)?;
            if !libc::WIFEXITED(status)
                || libc::WEXITSTATUS(status) != 0
                || !native.frames.complete()
            {
                return Err(Error::ChildFailed);
            }
            let configuration = native.inputs.bind_report(&native.frames.bytes)?;
            check_deadline(native.deadline)?;
            use sha2::Digest;
            let verified_at = vprouter_core::health::boot_seconds();
            check_deadline(native.deadline)?;
            Ok(Some((
                configuration,
                sha2::Sha256::digest(&native.frames.bytes).into(),
                verified_at,
            )))
        })();
        match result {
            Ok(Some((configuration, digest, verified_at))) => Ok(Some(Verified {
                native: self.native.take().ok_or(Error::Interrupted)?,
                configuration,
                digest,
                verified_at,
            })),
            Ok(None) => Ok(None),
            Err(error) => {
                native.cancel(error);
                Err(error)
            }
        }
    }
}

pub(crate) fn spawn(inputs: Inputs, mut intent: ValidationIntent) -> Result<ValidationChild> {
    process::single_threaded()?;
    if !vprouter_core::secret_boundary::pristine() {
        return Err(Error::ConfinementPolicy);
    }
    intent.prepare(&inputs)?;
    let deadline = inputs.deadline();
    check_deadline(deadline)?;
    let (parent_channel, child_channel) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let parent_inventory = super::super::inventory::Registration::owned(&[parent_channel.as_fd()])?;
    let child_inventory = super::super::inventory::Registration::owned(&[child_channel.as_fd()])?;
    super::super::inventory::verify()?;
    let born_at = vprouter_core::health::boot_seconds();
    check_deadline(deadline)?;
    let parent = std::process::id() as i32;
    let (pid, pidfd) = fork_with_pidfd()?;
    if pid == 0 {
        let result = (|| {
            parent_death(parent)?;
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            let null = fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                .map_err(|_| Error::DescriptorNull)?;
            for number in 0..3 {
                dup_fixed(&null, number, false)?;
            }
            // Stdio owns its duplicated OFD references. Do not leave a stale
            // OwnedFd alive across close_except's raw descriptor revocation.
            drop(null);
            // No owner journal/directory/namespace endpoints survive into this
            // fixed role. The original OFD lease remains held but is unreadable
            // under the filter; only selected profiles support pread/fstat.
            let mut retained = inputs.descriptors();
            retained.extend([child_channel.as_raw_fd(), intent.lease().fd().as_raw_fd()]);
            close_except(&retained)?;
            drop_identity(0)?;
            parent_death(parent)?;
            let role = NoFork::install(&inputs, child_channel.as_raw_fd(), deadline)?;
            gate(&child_channel, deadline)?;
            // FIRST profile byte is read only below, after installed no-fork and
            // an exact durable native-birth receipt released the private gate.
            let bytes = inputs.report(&role)?;
            send_report(&child_channel, &bytes, deadline)
        })();
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32).expect("successful native clone is a direct child");
    intent
        .lease()
        .native_job_mut()
        .born(NativeJobKind::SecretValidation, &Some(reap.clone()));
    drop(child_inventory);
    drop(child_channel);
    let mut native = Native {
        creator: std::process::id(),
        _capacity: ChildCapacity::created(),
        intent,
        inputs,
        pid: pid as u32,
        pidfd: pidfd.ok_or(Error::ChildFailed)?,
        reap,
        pidfd_inventory: None,
        channel: parent_channel,
        _channel_inventory: parent_inventory,
        birth: None,
        deadline,
        released: false,
        failed: None,
        frames: Frames::new(),
    };
    let result = (|| {
        native.pidfd_inventory = Some(super::super::inventory::Registration::owned(&[native
            .pidfd
            .as_fd()])?);
        if wait_ready(&native.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| Error::ProcessUnavailable)?;
        let start = process::stat_start(&stat, pid as u32)?;
        if wait_ready(&native.pidfd, Duration::ZERO)? {
            return Err(Error::ChildFailed);
        }
        native.reap.start.set(Some(start));
        native.birth = Some(ValidationBirth {
            pid: pid as u32,
            start,
            born_at,
            deadline,
        });
        check_deadline(deadline)
    })();
    if let Err(error) = result {
        native.cancel(error);
        RETIRED.with(|retired| retired.borrow_mut().push(native));
        return Err(error);
    }
    Ok(ValidationChild {
        native: Some(native),
    })
}
fn ready(fd: impl AsFd, events: rustix::event::PollFlags, deadline: f64) -> Result<()> {
    check_deadline(deadline)?;
    let remaining = deadline - vprouter_core::health::boot_seconds();
    if remaining <= 0. {
        return Err(Error::Deadline);
    }
    let timeout = rustix::event::Timespec::try_from(Duration::from_secs_f64(remaining))
        .map_err(|_| Error::Deadline)?;
    let mut descriptors = [rustix::event::PollFd::new(&fd, events)];
    rustix::event::poll(&mut descriptors, Some(&timeout)).map_err(|_| Error::Deadline)?;
    check_deadline(deadline)?;
    if !descriptors[0].revents().contains(events) {
        return Err(Error::Interrupted);
    }
    Ok(())
}
pub(super) fn gate(channel: impl AsFd, deadline: f64) -> Result<()> {
    ready(&channel, rustix::event::PollFlags::IN, deadline)?;
    let mut byte = [0u8; 1];
    if net::recv(&channel, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
        .map_err(|_| Error::DescriptorPolicy)?
        != (1, 1)
        || byte != [1]
    {
        return Err(Error::OwnershipMismatch);
    }
    check_deadline(deadline)
}
fn send_report(channel: impl AsFd, bytes: &[u8], deadline: f64) -> Result<()> {
    if bytes.is_empty() || bytes.len() > REPORT_LIMIT {
        return Err(Error::TooLarge);
    }
    for (sequence, chunk) in bytes.chunks(CHUNK).enumerate() {
        let mut frame = [0u8; CHUNK + 12];
        frame[..4].copy_from_slice(&(sequence as u32).to_le_bytes());
        frame[4..8].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        frame[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        frame[12..12 + chunk.len()].copy_from_slice(chunk);
        loop {
            check_deadline(deadline)?;
            match net::send(
                &channel,
                &frame[..chunk.len() + 12],
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            ) {
                Ok(length) if length == chunk.len() + 12 => break,
                Err(rustix::io::Errno::AGAIN) => {
                    ready(&channel, rustix::event::PollFlags::OUT, deadline)?
                }
                _ => return Err(Error::DescriptorPolicy),
            }
        }
    }
    check_deadline(deadline)
}

pub(crate) struct NoFork {
    pid: u32,
    parent: u32,
    configuration: [u8; 32],
    descriptors: Vec<i32>,
    deadline: f64,
}
impl NoFork {
    fn install(inputs: &Inputs, channel: i32, deadline: f64) -> Result<Self> {
        let pid = std::process::id();
        if pid == inputs.owner() || pid <= 1 {
            return Err(Error::OwnershipMismatch);
        }
        let descriptors = inputs.descriptors();
        if channel < 3
            || descriptors.iter().any(|fd| *fd < 3 || *fd == channel)
            || descriptors
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != descriptors.len()
        {
            return Err(Error::DescriptorPolicy);
        }
        check_deadline(deadline)?;
        // Credential changes can change dumpability; establish this after the
        // final UID/GID/capability transition and before any input byte is read.
        non_dumpable()?;
        cv(
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            Error::ConfinementPolicy,
        )?;
        apply_filter(&secret_filter(&descriptors, channel))?;
        let value = Self {
            pid,
            parent: inputs.owner(),
            configuration: inputs.digest(),
            descriptors,
            deadline,
        };
        value.require(inputs)?;
        #[cfg(test)]
        lab_denials()?;
        Ok(value)
    }
    pub(crate) fn require(&self, inputs: &Inputs) -> Result<()> {
        if std::process::id() != self.pid
            || self.pid == self.parent
            || self.parent != inputs.owner()
            || self.configuration != inputs.digest()
            || self.descriptors != inputs.descriptors()
            || unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } != 2
        {
            return Err(Error::OwnershipMismatch);
        }
        self.check_deadline()
    }
    pub(crate) fn check_deadline(&self) -> Result<()> {
        check_deadline(self.deadline)
    }
}
fn check_deadline(deadline: f64) -> Result<()> {
    let now = vprouter_core::health::boot_seconds();
    if !deadline.is_finite() || !now.is_finite() || now >= deadline || deadline - now > 2. {
        return Err(Error::Deadline);
    }
    Ok(())
}
pub(super) fn secret_filter(inputs: &[i32], channel: i32) -> Vec<libc::sock_filter> {
    fixed_read_filter(inputs, &[channel])
}
pub(super) fn fixed_read_filter(inputs: &[i32], channels: &[i32]) -> Vec<libc::sock_filter> {
    let mut out = filter()[..4].to_vec();
    let descriptors: Vec<u32> = inputs.iter().map(|fd| *fd as u32).collect();
    for nr in [libc::SYS_fstat, libc::SYS_pread64] {
        selected_fd_call(&mut out, nr, &descriptors, None);
    }
    selected_fd_call(
        &mut out,
        libc::SYS_fcntl,
        &descriptors,
        Some(libc::F_GETFD as u32),
    );
    if !channels.is_empty() {
        for nr in [libc::SYS_sendto, libc::SYS_recvfrom] {
            allow_fixed_args(
                &mut out,
                nr,
                0,
                &channels.iter().map(|fd| *fd as u32).collect::<Vec<_>>(),
            );
        }
    }
    fixed_runtime_tail(&mut out);
    out
}
/// Runtime-only suffix: no earlier empty FD dispatch can shadow a new role's
/// exact descriptor rules. Existing read-role instruction order is unchanged.
pub(super) fn fixed_runtime_filter() -> Vec<libc::sock_filter> {
    let mut out = filter()[..4].to_vec();
    fixed_runtime_tail(&mut out);
    out
}
fn fixed_runtime_tail(out: &mut Vec<libc::sock_filter>) {
    out.extend(exact_args(
        libc::SYS_prctl,
        &[
            (0, libc::PR_GET_SECCOMP as u64),
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
        ],
    ));
    for nr in [
        libc::SYS_ppoll,
        libc::SYS_getpid,
        libc::SYS_getrandom,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        allow_syscall(out, nr);
    }
    // Only anonymous, non-executable private allocation. No descriptor-backed
    // mapping can read another file, and executable memory cannot bypass exec.
    out.push(libc::sock_filter {
        code: 0x15,
        jt: 0,
        jf: 13,
        k: libc::SYS_mmap as u32,
    });
    for (offset, expected) in [
        (52, u32::MAX),
        (48, u32::MAX),
        (44, 0),
        (40, (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u32),
    ] {
        out.extend([
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: offset,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: expected,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050001,
            },
        ]);
    }
    out.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    });
    for nr in [libc::SYS_mmap, libc::SYS_mprotect] {
        out.extend([
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 5,
                k: nr as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 32,
            },
            libc::sock_filter {
                code: 0x45,
                jt: 0,
                jf: 1,
                k: !(libc::PROT_READ | libc::PROT_WRITE) as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050001,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff0000,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ]);
    }
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
}

// A long jump handles the complete MAX_EXITS set without truncating cBPF's
// 8-bit conditional offsets. All inputs belong to one selected native set.
pub(super) fn selected_fd_call(
    out: &mut Vec<libc::sock_filter>,
    nr: libc::c_long,
    fds: &[u32],
    command: Option<u32>,
) {
    let mut body = Vec::new();
    for (offset, expected) in
        std::iter::once((20, 0)).chain(command.into_iter().flat_map(|value| [(28, 0), (24, value)]))
    {
        body.extend([
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: offset,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: expected,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050001,
            },
        ]);
    }
    body.push(libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 16,
    });
    for fd in fds {
        body.extend([
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: *fd,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff0000,
            },
        ]);
    }
    body.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: nr as u32,
        },
        libc::sock_filter {
            code: 0x05,
            jt: 0,
            jf: 0,
            k: body.len() as u32,
        },
    ]);
    out.extend(body);
}

#[cfg(test)]
pub(super) fn lab_denials() -> Result<()> {
    for nr in [
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_execve,
        libc::SYS_execveat,
    ] {
        if unsafe { libc::syscall(nr, 0, 0, 0, 0, 0, 0) } != -1
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
        {
            return Err(Error::ConfinementPolicy);
        }
    }
    #[cfg(target_arch = "x86_64")]
    for nr in [libc::SYS_fork, libc::SYS_vfork] {
        if unsafe { libc::syscall(nr) } != -1
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
        {
            return Err(Error::ConfinementPolicy);
        }
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != -1
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
    {
        return Err(Error::ConfinementPolicy);
    }
    Ok(())
}

/// Native syscall/protocol proof only. Public generated payloads exercise the
/// real EAGAIN -> final-send -> actual-exit interleaving and maximum framing;
/// this is not a secret-free-parent or durable preparation acceptance fixture.
#[cfg(test)]
pub(super) fn lab_filter_selftest() -> Result<()> {
    for case in 0..3 {
        let (parent_channel, child_channel) = net::socketpair(
            net::AddressFamily::UNIX,
            net::SocketType::SEQPACKET,
            net::SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        let parent_inventory =
            super::super::inventory::Registration::owned(&[parent_channel.as_fd()])?;
        let child_inventory =
            super::super::inventory::Registration::owned(&[child_channel.as_fd()])?;
        let deadline = vprouter_core::health::boot_seconds() + 2.;
        let size = if case == 1 { REPORT_LIMIT } else { CHUNK + 1 };
        let (pid, pinned) = fork_with_pidfd()?;
        if pid == 0 {
            let result = (|| {
                close_except(&[child_channel.as_raw_fd()])?;
                cv(
                    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                    Error::ConfinementPolicy,
                )?;
                non_dumpable()?;
                apply_filter(&secret_filter(&[], child_channel.as_raw_fd()))?;
                gate(&child_channel, deadline)?;
                vprouter_core::secret_boundary::mark_ingress();
                if vprouter_core::secret_boundary::pristine() {
                    return Err(Error::ConfinementPolicy);
                }
                lab_denials()?;
                let bytes = vec![b'p'; size];
                send_report(&child_channel, &bytes, deadline)?;
                if case == 2 {
                    // A second report is trailing data, never a replacement.
                    send_report(&child_channel, b"trailing", deadline)?;
                }
                Ok(())
            })();
            die(if result.is_ok() { 0 } else { 122 });
        }
        let reap = ParentReap::born(pid as u32);
        drop(child_inventory);
        drop(child_channel);
        let pinned = pinned.ok_or(Error::ChildFailed)?;
        let registration = match super::super::inventory::Registration::owned(&[pinned.as_fd()]) {
            Ok(value) => value,
            Err(error) => {
                retain_fork_bundle_with_reap(
                    pid,
                    pinned,
                    parent_channel,
                    None,
                    vec![parent_inventory],
                    Vec::new(),
                    None,
                    None,
                    None,
                    reap,
                    None,
                );
                return Err(error);
            }
        };
        let child = Survivor {
            pid: pid as u32,
            pinned,
            _inventory: registration,
            reap,
        };
        let result = (|| {
            let mut frames = Frames::new();
            // Child cannot send until this observed empty receive has happened.
            if frames.receive(&parent_channel)? != DrainEnd::Empty || !frames.bytes.is_empty() {
                return Err(Error::DescriptorPolicy);
            }
            if net::send(
                &parent_channel,
                &[1],
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            )
            .map_err(|_| Error::DescriptorPolicy)?
                != 1
            {
                return Err(Error::DescriptorPolicy);
            }
            let status = loop {
                check_deadline(deadline)?;
                if case == 1 {
                    frames.receive(&parent_channel)?;
                }
                if let Some(status) = child.reap_status()? {
                    break status;
                }
                let mut fds = [rustix::event::PollFd::new(
                    &child.pinned,
                    rustix::event::PollFlags::IN,
                )];
                rustix::event::poll(
                    &mut fds,
                    Some(&rustix::event::Timespec {
                        tv_sec: 0,
                        tv_nsec: 1_000_000,
                    }),
                )
                .map_err(|_| Error::Deadline)?;
            };
            if status != 0 {
                return Err(Error::ChildFailed);
            }
            let drained = frames.receive(&parent_channel);
            check_deadline(deadline)?;
            if case == 2 {
                if drained != Err(Error::OwnershipMismatch) {
                    return Err(Error::DescriptorPolicy);
                }
            } else if drained != Ok(DrainEnd::Closed)
                || !frames.complete()
                || frames.bytes != vec![b'p'; size]
            {
                return Err(Error::DescriptorPolicy);
            }
            Ok(())
        })();
        if let Err(error) = result {
            retain_survivor(
                child,
                parent_channel,
                None,
                vec![parent_inventory],
                Vec::new(),
            );
            return Err(error);
        }
    }
    super::super::inventory::verify()?;
    eprintln!(
        "LAB_SECRET_ROLE_PROTOCOL cases=3 original_deadline=true actual_waitpid_zero=true late_frames_after_empty_and_exit=true maximum_public_bytes=262144 trailing_report_refused=true native_fork_exec_denied_after_ingress=true secret_free_parent_proven=false"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) struct LabReap {
    creator: u32,
    birth: ValidationBirth,
    original: std::rc::Rc<ParentReap>,
}
#[cfg(test)]
impl LabReap {
    pub(crate) fn evidence(&self) -> Result<serde_json::Value> {
        if self.creator != std::process::id()
            || self.original.creator != self.creator
            || self.original.pid != self.birth.pid
            || self.original.start.get() != Some(self.birth.start)
        {
            return Err(Error::OwnershipMismatch);
        }
        Ok(
            serde_json::json!({"birth": self.birth, "actual_wait_status": self.original.status.get()}),
        )
    }
    pub(crate) fn status(&self) -> Result<Option<i32>> {
        self.evidence()?;
        Ok(self.original.status.get())
    }
}
#[cfg(test)]
impl ValidationChild {
    pub(crate) fn lab_reap(&self) -> Result<LabReap> {
        let native = self.native.as_ref().ok_or(Error::Interrupted)?;
        native.creator()?;
        Ok(LabReap {
            creator: native.creator,
            birth: native.birth.clone().ok_or(Error::Interrupted)?,
            original: native.reap.clone(),
        })
    }
}
#[cfg(test)]
impl Validated {
    pub(crate) fn lab_pins(&self) -> Result<usize> {
        self.inputs.verify_parent()?;
        Ok(self.inputs.identities().len())
    }
}

impl Validated {
    pub(crate) fn bind_current(
        &self,
        server: &Server,
    ) -> Result<super::super::owned::preparation::PublicBinding> {
        self.inputs.verify_parent()?;
        self.receipt.bind_current(server)
    }
}
