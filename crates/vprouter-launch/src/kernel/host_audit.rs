//! One fixed ROUTE-only child; response authority is retained pidfd + clean exit.
use super::*;
use rustix::net::{self, RecvFlags, SendFlags};

pub(crate) struct HostAuditChild {
    native: Option<HostAuditNative>,
}
pub(crate) struct HostAuditNative {
    creator: u32,
    _capacity: ChildCapacity,
    _lease: super::super::owned::MutatorLease,
    _directory: OwnedFd,
    _namespace: OwnedFd,
    _context_inventory: super::super::inventory::Registration,
    child: Survivor,
    channel: OwnedFd,
    _inventory: super::super::inventory::Registration,
    deadline: f64,
    reaped: bool,
    killed: bool,
    #[cfg(test)]
    pause: bool,
    #[cfg(test)]
    pause_links: bool,
    #[cfg(test)]
    checkpoint_start: Option<u64>,
}
impl std::ops::Deref for HostAuditChild {
    type Target = HostAuditNative;
    fn deref(&self) -> &Self::Target {
        self.native.as_ref().expect("retained host audit")
    }
}
impl std::ops::DerefMut for HostAuditChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.native.as_mut().expect("retained host audit")
    }
}
thread_local! { static RETIRED: std::cell::RefCell<Vec<HostAuditNative>> = const { std::cell::RefCell::new(Vec::new()) }; }
impl Drop for HostAuditChild {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            if native.creator != std::process::id() || native.reaped {
                return;
            }
            let _ = send_or_exited(native.child.pidfd(), libc::SIGKILL);
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
            let _ = send_or_exited(native.child.pidfd(), libc::SIGKILL);
            // Fixed route-only profile cannot create descendants. Only the native
            // parent's exact waitpid receipt releases this entire context bundle.
            native.child.reap_exited() != Ok(true)
        })
    });
}
pub(crate) fn retired_drained() -> bool {
    RETIRED.with(|retired| {
        retired
            .borrow()
            .iter()
            .all(|native| native.creator != std::process::id())
    })
}
impl HostAuditChild {
    fn creator(&self) -> Result<()> {
        if self.creator != std::process::id() {
            return Err(Error::OwnershipMismatch);
        }
        Ok(())
    }
    pub(crate) fn cancel(&mut self) -> Result<()> {
        self.creator()?;
        if !self.reaped && !self.killed {
            send_or_exited(self.child.pidfd(), libc::SIGKILL)?;
            self.killed = true;
        }
        Ok(())
    }
    pub(crate) fn drained(&self) -> bool {
        self.creator == std::process::id() && self.reaped
    }
    pub(crate) fn poll(&mut self) -> Result<Option<vprouter_network::HostObservation>> {
        self.creator()?;
        if self.reaped {
            return Err(Error::Interrupted);
        }
        let Some(status) = self.child.reap_status()? else {
            return Ok(None);
        };
        self.reaped = true;
        #[cfg(test)]
        eprintln!(
            "LAB_HOST_AUDIT_CHILD status={status} killed={} deadline={}",
            self.killed, self.deadline
        );
        if self.killed || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            #[cfg(test)]
            {
                let mut d = [0u8; 3];
                let result = net::recv(&self.channel, &mut d, RecvFlags::DONTWAIT);
                eprintln!("LAB_HOST_AUDIT_FAILURE diagnostic={d:?} received={result:?}");
            }
            return Err(Error::ChildFailed);
        }
        check_deadline(self.deadline)?;
        let mut bytes = vec![0; vprouter_network::HOST_OBSERVATION_BYTES + 1];
        let (n, full) = net::recv(
            &self.channel,
            &mut bytes,
            RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        )
        .map_err(|_| Error::DescriptorPolicy)?;
        if n == 0 || n != full || n > vprouter_network::HOST_OBSERVATION_BYTES {
            return Err(Error::TooLarge);
        }
        #[cfg(test)]
        eprintln!(
            "LAB_HOST_AUDIT_NATIVE bytes={n} route_only=true caps_zero=true nnp=true forbidden_route_mutation=EPERM descriptors=0,1,2,3,4,5,6"
        );
        let result = vprouter_network::HostObservation::decode(&bytes[..n])
            .map_err(|_| Error::NetworkOperation)?;
        check_deadline(self.deadline)?;
        Ok(Some(result))
    }
}
fn check_deadline(deadline: f64) -> Result<()> {
    let now = vprouter_core::health::boot_seconds();
    if !deadline.is_finite() || !now.is_finite() || now >= deadline || deadline - now > 2. {
        return Err(Error::Deadline);
    }
    Ok(())
}
#[cfg(test)]
thread_local! { static FAIL_PARENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn lab_fail_next_parent() -> Result<()> {
    if FAIL_PARENT.with(|flag| flag.replace(true)) {
        return Err(Error::Interrupted);
    }
    Ok(())
}
/// No callback, program, path, PID, expected observation or caller namespace.
/// The current owner host namespace is pinned before the fixed socket is opened.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn(
    directory: OwnedFd,
    mut lease: super::super::owned::MutatorLease,
    window: Option<std::rc::Rc<std::cell::RefCell<vprouter_network::HostAuditTicket>>>,
    deadline: f64,
    #[cfg(test)] pause: bool,
    #[cfg(test)] hold_before_isolation: bool,
    #[cfg(test)] pause_links: bool,
) -> Result<HostAuditChild> {
    process::single_threaded()?;
    // The exact job lease owns the window before native birth. Every postclone
    // failure and retired Drop already carries this lease to actual collection.
    if let Some(window) = window {
        lease.retain_host_window(window)?;
    } else if !cfg!(test) {
        return Err(Error::OwnershipMismatch);
    }
    lease.prepare_native_job(NativeJobKind::HostAudit)?;
    check_deadline(deadline)?;
    let namespace = network()?;
    let context_inventory =
        super::super::inventory::Registration::owned(&[directory.as_fd(), namespace.as_fd()])?;
    super::super::inventory::verify()?;
    let (parent_socket, child_socket) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let inventory = super::super::inventory::Registration::owned(&[parent_socket.as_fd()])?;
    let child_inventory = super::super::inventory::Registration::owned(&[child_socket.as_fd()])?;
    let parent = std::process::id() as i32;
    // Atomic pidfd birth; every subsequent error retains the exact native child.
    let (pid, pinned) = fork_with_pidfd()?;
    if pid == 0 {
        #[cfg(test)]
        let diagnostic = std::cell::Cell::new(1u8);
        #[cfg(test)]
        let diagnostic_fd = std::cell::Cell::new(child_socket.as_raw_fd());
        let result = (|| {
            parent_death(parent)?;
            check_deadline(deadline)?;
            #[cfg(test)]
            if hold_before_isolation {
                // Exact rootless constructor/drop proof. Never release this
                // fixture into privileged isolation or the route observer.
                write_byte(&child_socket, 126)?;
                let remaining = deadline - vprouter_core::health::boot_seconds();
                if remaining <= 0.
                    || !wait_ready(&child_socket, Duration::from_secs_f64(remaining))?
                {
                    return Err(Error::Deadline);
                }
                return Err(Error::Interrupted);
            }
            cv(unsafe { libc::clearenv() }, Error::ChildFailed)?;
            let directory = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&directory, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let channel = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&child_socket, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let namespace = std::mem::ManuallyDrop::new(
                rustix::io::fcntl_dupfd_cloexec(&namespace, 110)
                    .map_err(|_| Error::DescriptorDuplicate)?,
            );
            let pin = super::super::owned::Identity::network(&*namespace)?;
            let null = std::mem::ManuallyDrop::new(
                fs::open(c"/dev/null", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
                    .map_err(|_| Error::DescriptorNull)?,
            );
            for number in 0..3 {
                dup_fixed(&*null, number, false)?;
            }
            dup_fixed(&*channel, 3, true)?;
            #[cfg(test)]
            diagnostic_fd.set(3);
            dup_fixed(&*directory, 4, true)?;
            dup_fixed(&*namespace, 5, true)?;
            #[cfg(test)]
            diagnostic.set(2);
            close_except(&[3, 4, 5])?;
            // Socket is native to the pinned namespace. It is opened before
            // chroot; mutation also requires the sender's current NET_ADMIN.
            #[cfg(test)]
            diagnostic.set(3);
            let mut observer =
                vprouter_network::RouteObserver::open().map_err(|_| Error::NetworkOperation)?;
            if observer.descriptor().as_raw_fd() != 6
                || observer.namespace_identity() != (pin.dev, pin.ino)
                || descriptor_inventory()? != [0, 1, 2, 3, 4, 5, 6].into()
            {
                return Err(Error::DescriptorInventory);
            }
            #[cfg(test)]
            diagnostic.set(4);
            cv(unsafe { libc::fchdir(4) }, Error::MountIsolation)?;
            cv(
                unsafe { libc::chroot(c".".as_ptr()) },
                Error::MountIsolation,
            )?;
            cv(unsafe { libc::chdir(c"/".as_ptr()) }, Error::MountIsolation)?;
            #[cfg(test)]
            diagnostic.set(5);
            drop_identity(0)?;
            parent_death(parent)?;
            #[cfg(test)]
            lab_caps()?;
            #[cfg(test)]
            diagnostic.set(6);
            apply_filter(&host_filter())?;
            check_deadline(deadline)?;
            #[cfg(test)]
            diagnostic.set(7);
            #[cfg(not(test))]
            let observation = observer
                .observe_until(deadline)
                .map_err(|_| Error::NetworkOperation)?;
            #[cfg(test)]
            let observation = if pause_links {
                observer.observe_until_checkpoint(deadline, || {
                    lab_links_gate(deadline).map_err(|_| vprouter_network::Error::Deadline)
                })
            } else {
                observer.observe_until(deadline)
            }
            .map_err(|_| Error::NetworkOperation)?;
            #[cfg(test)]
            diagnostic.set(8);
            let bytes = observation.encode().map_err(|_| Error::TooLarge)?;
            #[cfg(test)]
            {
                #[cfg(test)]
                diagnostic.set(9);
                lab_negative(&bytes, deadline)?;
                #[cfg(test)]
                diagnostic.set(10);
                if pause {
                    let channel = unsafe { BorrowedFd::borrow_raw(3) };
                    net::send(channel, &[127], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
                        .map_err(|_| Error::DescriptorPolicy)?;
                    let remaining = deadline - vprouter_core::health::boot_seconds();
                    if remaining <= 0. || !wait_ready(channel, Duration::from_secs_f64(remaining))?
                    {
                        return Err(Error::Deadline);
                    }
                    let mut reply = [0; 1];
                    if net::recv(channel, &mut reply, RecvFlags::DONTWAIT)
                        .map_err(|_| Error::DescriptorPolicy)?
                        != (1, 1)
                        || reply != [1]
                    {
                        return Err(Error::DescriptorPolicy);
                    }
                }
            }
            check_deadline(deadline)?;
            if net::send(
                unsafe { BorrowedFd::borrow_raw(3) },
                &bytes,
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            )
            .map_err(|_| Error::DescriptorPolicy)?
                != bytes.len()
            {
                return Err(Error::DescriptorPolicy);
            }
            check_deadline(deadline)
        })();
        #[cfg(test)]
        if let Err(error) = result {
            let _ = net::send(
                unsafe { BorrowedFd::borrow_raw(diagnostic_fd.get()) },
                &[254, diagnostic.get(), stage_byte(error)],
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            );
        }
        die(if result.is_ok() { 0 } else { 122 });
    }
    let reap = ParentReap::born(pid as u32);
    lease.native_job_mut().born(NativeJobKind::HostAudit, &reap);
    drop(child_inventory);
    drop(child_socket);
    let pinned = pinned.ok_or(Error::ChildFailed)?;
    let register = || super::super::inventory::Registration::owned(&[pinned.as_fd()]);
    #[cfg(test)]
    let registration = if FAIL_PARENT.with(|flag| flag.replace(false)) {
        Err(Error::DescriptorInventory)
    } else {
        register()
    };
    #[cfg(not(test))]
    let registration = register();
    let registration = match registration {
        Ok(registration) => registration,
        Err(error) => {
            retain_fork_bundle_with_reap(
                pid,
                pinned,
                parent_socket,
                None,
                vec![inventory, context_inventory],
                vec![directory, namespace],
                None,
                None,
                Some(lease),
                reap,
                None,
            );
            return Err(error);
        }
    };
    let child = Survivor {
        pid: pid as u32,
        reap,
        pinned,
        _inventory: registration,
    };
    Ok(HostAuditChild {
        native: Some(HostAuditNative {
            creator: std::process::id(),
            _capacity: ChildCapacity::created(),
            _lease: lease,
            _directory: directory,
            _namespace: namespace,
            _context_inventory: context_inventory,
            child,
            channel: parent_socket,
            _inventory: inventory,
            deadline,
            reaped: false,
            killed: false,
            #[cfg(test)]
            pause,
            #[cfg(test)]
            pause_links,
            #[cfg(test)]
            checkpoint_start: None,
        }),
    })
}
pub(super) fn host_filter() -> Vec<libc::sock_filter> {
    let mut out = filter()[..4].to_vec();
    // apply_filter verifies successful installation using this readonly getter.
    // Admit only its exact 64-bit command; all PR_SET_* operations remain denied.
    out.extend([
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 7,
            k: libc::SYS_prctl as u32,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 20,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 3,
            k: 0,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 16,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: libc::PR_GET_SECCOMP as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050001,
        },
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ]);
    // Two fixed private/native sockets only. No open/socket/exec/setns or files.
    for nr in [libc::SYS_sendto, libc::SYS_recvfrom] {
        out.extend([
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 8,
                k: nr as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 20,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 4,
                k: 0,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 16,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: 3,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: 6,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff0000,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050001,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ]);
    }
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
    for nr in [
        libc::SYS_close,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_ppoll,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        allow_syscall(&mut out, nr);
    }
    #[cfg(target_arch = "x86_64")]
    allow_syscall(&mut out, libc::SYS_poll);
    out.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x00050001,
    });
    out
}

#[cfg(test)]
fn lab_links_gate(deadline: f64) -> Result<()> {
    check_deadline(deadline)?;
    let channel = unsafe { BorrowedFd::borrow_raw(3) };
    if net::send(channel, &[125], SendFlags::DONTWAIT | SendFlags::NOSIGNAL)
        .map_err(|_| Error::DescriptorPolicy)?
        != 1
    {
        return Err(Error::DescriptorPolicy);
    }
    let remaining = deadline - vprouter_core::health::boot_seconds();
    if remaining <= 0. {
        return Err(Error::Deadline);
    }
    let mut polls = [rustix::event::PollFd::new(
        &channel,
        rustix::event::PollFlags::IN,
    )];
    if rustix::event::poll(
        &mut polls,
        Some(
            &rustix::event::Timespec::try_from(Duration::from_secs_f64(remaining))
                .map_err(|_| Error::Deadline)?,
        ),
    )
    .map_err(|_| Error::DescriptorPolicy)?
        == 0
    {
        return Err(Error::Deadline);
    }
    let mut byte = [0; 2];
    if net::recv(channel, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
        .map_err(|_| Error::DescriptorPolicy)?
        != (1, 1)
        || byte[0] != 2
    {
        return Err(Error::DescriptorPolicy);
    }
    check_deadline(deadline)
}
#[cfg(test)]
impl HostAuditChild {
    pub(crate) fn lab_links_checkpoint(&self) -> Result<Option<(u32, u64, f64)>> {
        self.creator()?;
        if !self.pause_links || self.reaped {
            return Ok(None);
        }
        check_deadline(self.deadline)?;
        let mut byte = [0; 2];
        match net::recv(
            &self.channel,
            &mut byte,
            RecvFlags::PEEK | RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        ) {
            Ok((1, 1)) if byte[0] == 125 => {
                self.child.require_live()?;
                Ok(Some((
                    self.child.pid(),
                    self.child.start_time()?,
                    self.deadline,
                )))
            }
            Err(rustix::io::Errno::AGAIN) => Ok(None),
            _ => Err(Error::DescriptorPolicy),
        }
    }
    pub(crate) fn lab_release_links(&mut self) -> Result<()> {
        if self.lab_links_checkpoint()?.is_none() {
            return Err(Error::OwnershipMismatch);
        }
        let mut byte = [0; 2];
        if net::recv(
            &self.channel,
            &mut byte,
            RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        )
        .map_err(|_| Error::DescriptorPolicy)?
            != (1, 1)
            || byte[0] != 125
        {
            return Err(Error::DescriptorPolicy);
        }
        check_deadline(self.deadline)?;
        write_byte(&self.channel, 2)?;
        self.pause_links = false;
        Ok(())
    }
    pub(crate) fn lab_native_handle(&self) -> Result<Survivor> {
        self.creator()?;
        self.child.lab_clone_native()
    }
    pub(crate) fn lab_pre_isolation_handle(&self) -> Result<Survivor> {
        self.creator()?;
        let remaining = self.deadline - vprouter_core::health::boot_seconds();
        if remaining <= 0.
            || !wait_ready(&self.channel, Duration::from_secs_f64(remaining))?
            || read_byte(&self.channel)? != 126
        {
            return Err(Error::Deadline);
        }
        self.child.require_live()?;
        self.child.lab_clone_native()
    }
    pub(crate) fn lab_checkpoint(&mut self) -> Result<Option<(u32, u64, f64)>> {
        self.creator()?;
        if !self.pause || self.reaped {
            return Ok(None);
        }
        if let Some(start) = self.checkpoint_start {
            // SIGSTOP delivery is asynchronous. Keep polling the exact pidfd /
            // start identity beside other members until the kernel proves T.
            // No shared-loop sleep, deadline reset or SIGCONT is permitted.
            check_deadline(self.deadline)?;
            self.child.require_live()?;
            if self.child.start_time()? != start {
                return Err(Error::ProcessChanged);
            }
            if self.child.lab_require_stopped(start).is_ok() {
                self.pause = false;
                return Ok(Some((self.child.pid(), start, self.deadline)));
            }
            return Ok(None);
        }
        let mut bytes = [0; 1];
        match net::recv(
            &self.channel,
            &mut bytes,
            RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        ) {
            Err(rustix::io::Errno::AGAIN) => Ok(None),
            Ok((1, 1)) if bytes == [127] => {
                let start = self.child.start_time()?;
                self.child.lab_signal(libc::SIGSTOP)?;
                self.checkpoint_start = Some(start);
                Ok(None)
            }
            _ => Err(Error::DescriptorPolicy),
        }
    }
}
#[cfg(test)]
pub(crate) fn lab_retained(witness: &Survivor) -> Result<(f64, usize)> {
    let receipt = witness.reap.as_ref().ok_or(Error::OwnershipMismatch)?;
    if receipt.creator != std::process::id() {
        return Err(Error::OwnershipMismatch);
    }
    RETIRED.with(|retired| {
        let retired = retired.borrow();
        let native = retired
            .iter()
            .find(|native| {
                native.creator == std::process::id()
                    && native
                        .child
                        .reap
                        .as_ref()
                        .is_some_and(|r| std::rc::Rc::ptr_eq(r, receipt))
            })
            .ok_or(Error::OwnershipMismatch)?;
        if !native
            .child
            ._inventory
            .contains(native.child.pinned.as_fd())
            || !native._inventory.contains(native.channel.as_fd())
            || !native
                ._context_inventory
                .contains(native._directory.as_fd())
            || !native
                ._context_inventory
                .contains(native._namespace.as_fd())
        {
            return Err(Error::DescriptorInventory);
        }
        Ok((native.deadline, native._lease.lab_count()?))
    })
}
#[cfg(test)]
fn lab_caps() -> Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let mut data = [Data::default(), Data::default()];
    // SAFETY: kernel writes only these fixed initialized capability structures.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0
        || data
            .iter()
            .any(|d| d.effective != 0 || d.permitted != 0 || d.inheritable != 0)
        || unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
        || unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) } != 0xef
    {
        return Err(Error::CapabilityPolicy);
    }
    for cap in 0..=40 {
        if unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, cap, 0, 0) }
                != 0
        {
            return Err(Error::CapabilityPolicy);
        }
    }
    Ok(())
}
#[cfg(test)]
fn lab_negative(bytes: &[u8], deadline: f64) -> Result<()> {
    // Native mutation request on the SAME preopened ROUTE socket and exact
    // caps0/seccomp role that just completed the successful full dumps.
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Error::DescriptorPolicy)?;
    let index = value["links"]
        .as_array()
        .ok_or(Error::DescriptorPolicy)?
        .iter()
        .find(|l| {
            l["alias"]
                .as_str()
                .is_some_and(|a| a.starts_with("vprouter-v2:"))
        })
        .and_then(|l| l["index"].as_u64())
        .and_then(|i| u32::try_from(i).ok())
        .ok_or(Error::OwnershipMismatch)?;
    let packet = mutation_packet(index);
    let route = unsafe { BorrowedFd::borrow_raw(6) };
    net::sendto(
        route,
        &packet,
        SendFlags::DONTWAIT,
        &net::netlink::SocketAddrNetlink::new(0, 0),
    )
    .map_err(|_| Error::NetworkOperation)?;
    let remaining = deadline - vprouter_core::health::boot_seconds();
    if remaining <= 0. || !wait_ready(route, Duration::from_secs_f64(remaining))? {
        return Err(Error::Deadline);
    }
    let mut reply = [0u8; 256];
    let (n, full, from) = net::recvfrom(route, &mut reply, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
        .map_err(|_| Error::NetworkOperation)?;
    let from = net::netlink::SocketAddrNetlink::try_from(from.ok_or(Error::DescriptorPolicy)?)
        .map_err(|_| Error::DescriptorPolicy)?;
    if n != full
        || n < 20
        || from.pid() != 0
        || u16::from_ne_bytes(reply[4..6].try_into().unwrap()) != 2
        || u32::from_ne_bytes(reply[8..12].try_into().unwrap()) != 0xfeed
        || i32::from_ne_bytes(reply[16..20].try_into().unwrap()) != -libc::EPERM
    {
        return Err(Error::CapabilityPolicy);
    }
    // Socket creation is forbidden, including GENERIC and ordinary network.
    if unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_GENERIC) } != -1 {
        return Err(Error::CapabilityPolicy);
    }
    Ok(())
}
#[cfg(test)]
fn mutation_packet(index: u32) -> [u8; 40] {
    let mut p = [0; 40];
    p[..4].copy_from_slice(&40u32.to_ne_bytes());
    p[4..6].copy_from_slice(&16u16.to_ne_bytes()); // RTM_NEWLINK
    p[6..8].copy_from_slice(&5u16.to_ne_bytes()); // REQUEST | ACK
    p[8..12].copy_from_slice(&0xfeedu32.to_ne_bytes());
    p[20..24].copy_from_slice(&index.to_ne_bytes());
    p[32..34].copy_from_slice(&8u16.to_ne_bytes());
    p[34..36].copy_from_slice(&4u16.to_ne_bytes()); // IFLA_MTU
    p[36..40].copy_from_slice(&1499u32.to_ne_bytes());
    p
}
#[cfg(test)]
pub(crate) fn lab_owned_link_drift(index: u32) -> Result<()> {
    let fd = net::socket_with(
        net::AddressFamily::NETLINK,
        net::SocketType::RAW,
        net::SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|_| Error::NetworkOperation)?;
    net::bind(&fd, &net::netlink::SocketAddrNetlink::new(0, 0))
        .map_err(|_| Error::NetworkOperation)?;
    net::sendto(
        &fd,
        &mutation_packet(index),
        SendFlags::empty(),
        &net::netlink::SocketAddrNetlink::new(0, 0),
    )
    .map_err(|_| Error::NetworkOperation)?;
    if !wait_ready(&fd, Duration::from_secs(1))? {
        return Err(Error::Deadline);
    }
    let mut reply = [0u8; 256];
    let (n, full) = net::recv(&fd, &mut reply, RecvFlags::DONTWAIT | RecvFlags::TRUNC)
        .map_err(|_| Error::NetworkOperation)?;
    if n != full
        || n < 20
        || u16::from_ne_bytes(reply[4..6].try_into().unwrap()) != 2
        || i32::from_ne_bytes(reply[16..20].try_into().unwrap()) != 0
    {
        return Err(Error::NetworkOperation);
    }
    Ok(())
}
