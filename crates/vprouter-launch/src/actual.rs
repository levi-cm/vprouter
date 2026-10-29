#![forbid(unsafe_code)]
//! Private fixed execution, downstream of retained allocation/producer authority.
//! These functions provide neither production CLI entry nor ready/Placed tokens.
use super::{
    Admission, Error, Result, inventory,
    kernel::{self, ActualRole},
    owned::{self, OwnedNamespaces, Transaction},
    producer::ProducerGroup,
    programs::{ReviewedBundle, Role},
};
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use std::{
    net::Ipv4Addr,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

fn open(root: impl AsFd, path: &str, flags: OFlags) -> Result<OwnedFd> {
    fs::openat2(
        root,
        path,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| Error::ExecutableMismatch)
}
fn ca(root: impl AsFd) -> Result<OwnedFd> {
    let fd = open(root, "etc/ssl/certs/ca-certificates.crt", OFlags::RDONLY)?;
    let s = fs::fstat(&fd).map_err(|_| Error::ExecutableMismatch)?;
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o7222 != 0
        || s.st_size != 181724
    {
        return Err(Error::ExecutableMismatch);
    }
    let mut bytes = vec![0; 181724];
    let mut offset = 0;
    while offset < bytes.len() {
        let n = rustix::io::pread(&fd, &mut bytes[offset..], offset as u64)
            .map_err(|_| Error::ExecutableMismatch)?;
        if n == 0 {
            return Err(Error::ExecutableMismatch);
        }
        offset += n;
    }
    if vprouter_worker::bootstrap::digest(&bytes)
        != "028fca5150ee1915c4474489985d55c54fceaa680c754cc8d1301734f01b2232"
    {
        return Err(Error::ExecutableMismatch);
    }
    Ok(fd)
}
fn state(a: &Admission, role: ActualRole) -> Result<OwnedFd> {
    let root = owned::directory(&a.spec.exit.state_dir)?;
    let fd = open(
        root,
        if role == ActualRole::Daemon {
            "daemon"
        } else {
            "worker"
        },
        OFlags::RDONLY | OFlags::DIRECTORY,
    )?;
    let s = fs::fstat(&fd).map_err(|_| Error::UnsafeInput)?;
    if s.st_uid != 65534 || s.st_gid != 65534 || s.st_mode & 0o7777 != 0o700 {
        return Err(Error::UnsafeInput);
    }
    // A nested mount could project another exit or host directory into the
    // selected writable view. Reject all descendants before cloning the tree.
    let selected = a.spec.exit.state_dir.join(if role == ActualRole::Daemon {
        "daemon"
    } else {
        "worker"
    });
    for line in std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| Error::MountIsolation)?
        .lines()
    {
        let mount = line
            .split_whitespace()
            .nth(4)
            .ok_or(Error::MountIsolation)?;
        if mount.contains('\\')
            || (std::path::Path::new(mount).starts_with(&selected)
                && std::path::Path::new(mount) != selected)
        {
            return Err(Error::MountIsolation);
        }
    }
    Ok(fd)
}
fn tun(a: &Admission) -> Result<OwnedFd> {
    let fd = open(a.process.root(), "dev/net/tun", OFlags::PATH)?;
    let s = fs::fstat(&fd).map_err(|_| Error::CapabilityPolicy)?;
    if FileType::from_raw_mode(s.st_mode) != FileType::CharacterDevice
        || fs::major(s.st_rdev) != 10
        || fs::minor(s.st_rdev) != 200
    {
        return Err(Error::CapabilityPolicy);
    }
    Ok(fd)
}
fn localapi(a: &Admission) -> Result<OwnedFd> {
    let state = state(a, ActualRole::Daemon)?;
    let fd = open(state, "tailscaled.sock", OFlags::PATH)?;
    let s = fs::fstat(&fd).map_err(|_| Error::DescriptorPolicy)?;
    if FileType::from_raw_mode(s.st_mode) != FileType::Socket
        || s.st_uid != 65534
        || s.st_gid != 65534
    {
        return Err(Error::DescriptorPolicy);
    }
    Ok(fd)
}
/// Native socket credentials are a PID hint ONLY. This cannot mint LiveDaemon,
/// permission, readiness or a cached inspection result.
fn connect_pinned_socket(socket: impl AsFd, end: Instant) -> Result<rustix::net::UCred> {
    use rustix::{event, net};
    if Instant::now() >= end {
        return Err(Error::Deadline);
    }
    let stream = net::socket_with(
        net::AddressFamily::UNIX,
        net::SocketType::STREAM,
        net::SocketFlags::CLOEXEC | net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::DescriptorPolicy)?;
    let _inventory = inventory::Registration::owned(&[stream.as_fd()])?;
    let address = net::SocketAddrUnix::new(format!("/proc/self/fd/{}", socket.as_fd().as_raw_fd()))
        .map_err(|_| Error::DescriptorPolicy)?;
    match net::connect(&stream, &address) {
        Ok(()) => {}
        Err(rustix::io::Errno::INPROGRESS) => {
            let mut descriptors = [event::PollFd::new(&stream, event::PollFlags::OUT)];
            let remaining = end.saturating_duration_since(Instant::now());
            if remaining.is_zero()
                || event::poll(
                    &mut descriptors,
                    Some(&event::Timespec::try_from(remaining).map_err(|_| Error::Deadline)?),
                )
                .map_err(|_| Error::DescriptorPolicy)?
                    == 0
            {
                return Err(Error::Deadline);
            }
            net::sockopt::socket_error(&stream)
                .map_err(|_| Error::DescriptorPolicy)?
                .map_err(|_| Error::DescriptorPolicy)?;
        }
        // In particular, UNIX EAGAIN means no connection was initiated. A zero
        // SO_ERROR after polling it would not prove a successful connection.
        Err(_) => return Err(Error::DescriptorPolicy),
    }
    let peer = net::sockopt::socket_peercred(&stream).map_err(|_| Error::DescriptorPolicy)?;
    if Instant::now() >= end {
        return Err(Error::Deadline);
    }
    Ok(peer)
}
pub(super) fn daemon_pid_hint(a: &Admission, child: &kernel::Child, end: Instant) -> Result<u32> {
    let state = state(a, ActualRole::Daemon)?;
    let _state_inventory = inventory::Registration::owned(&[state.as_fd()])?;
    // Only absence during fixed daemon startup is retryable. Unexpected path
    // types, ownership, symlinks and connect/identity failures are terminal.
    loop {
        child.require_live()?;
        if Instant::now() >= end {
            return Err(Error::Deadline);
        }
        match fs::statat(&state, "tailscaled.sock", fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(_) => return Err(Error::DescriptorPolicy),
            Ok(_) => break,
        }
    }
    let socket = localapi(a)?;
    let _socket_inventory = inventory::Registration::owned(&[socket.as_fd()])?;
    let identity = owned::Identity::of(&socket)?;
    let state_identity = owned::Identity::of(&state)?;
    let peer = connect_pinned_socket(&socket, end)?;
    if peer.uid.as_raw() != 65534
        || peer.gid.as_raw() != 65534
        || peer.pid.as_raw_pid() <= 1
        || owned::Identity::of(localapi(a)?)? != identity
        || owned::Identity::of(self::state(a, ActualRole::Daemon)?)? != state_identity
        || owned::Identity::of(&socket)? != identity
    {
        return Err(Error::DescriptorPolicy);
    }
    child.require_live()?;
    if Instant::now() >= end {
        return Err(Error::Deadline);
    }
    Ok(peer.pid.as_raw_pid() as u32)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn launch(
    a: &Admission,
    tx: &Transaction,
    ns: &OwnedNamespaces,
    producer: &ProducerGroup,
    bundle: &ReviewedBundle,
    role: ActualRole,
    resolver: Ipv4Addr,
    placement: Option<BorrowedFd<'_>>,
    enrollment: Option<&super::enrollment::AuthorizedEnrollment>,
    before_release: impl FnOnce(ActualRole) -> Result<()>,
) -> Result<kernel::Child> {
    super::process::single_threaded()?;
    tx.inspect_container(a)?;
    tx.revalidate(&a.spec)?;
    ns.bind(&a.spec)?;
    producer.verify(tx, &a.spec)?;
    if !resolver.is_private() {
        return Err(Error::ResolverUnavailable);
    }
    if (role != ActualRole::Daemon) != placement.is_some() {
        return Err(Error::DescriptorPolicy);
    }
    let daemon_configuration = if let Some(enrollment) = enrollment {
        enrollment.verify(&a.spec)?;
        if !matches!(role, ActualRole::Daemon | ActualRole::OperationalMonitor) {
            return Err(Error::DescriptorPolicy);
        }
        kernel::DaemonConfiguration::PreservedEnrollment
    } else {
        if role == ActualRole::OperationalMonitor {
            return Err(Error::DescriptorPolicy);
        }
        kernel::DaemonConfiguration::Unenrolled
    };
    let program = bundle.open(
        a.process.root(),
        match role {
            ActualRole::Observer => Role::WorkerObserver,
            ActualRole::Monitor | ActualRole::OperationalMonitor => Role::WorkerMonitor,
            ActualRole::Daemon => Role::Tailscaled,
        },
    )?;
    let ca = ca(a.process.root())?;
    let state = state(a, role)?;
    let tun = if role == ActualRole::Daemon {
        Some(tun(a)?)
    } else {
        None
    };
    let localapi = if role != ActualRole::Daemon {
        Some(localapi(a)?)
    } else {
        None
    };
    let mut fds = vec![program.fd(), ca.as_fd(), state.as_fd()];
    fds.extend(tun.iter().map(AsFd::as_fd));
    fds.extend(localapi.iter().map(AsFd::as_fd));
    let _owned = inventory::Registration::owned(&fds)?;
    // No async reactor spans fork/setns. Native control sockets are exact owned
    // registrations and will be closed in every wrapper and exec child.
    inventory::verify()?;
    program.revalidate(bundle)?;
    let mut child = kernel::spawn_actual(
        a.process.launch_fds(),
        ns.data.as_fd(),
        state.as_fd(),
        kernel::Actual {
            role,
            daemon_configuration,
            executable: program.fd(),
            ca: ca.as_fd(),
            placement,
            localapi: localapi.as_ref().map(AsFd::as_fd),
            tun: tun.as_ref().map(AsFd::as_fd),
            resolver,
        },
    )?;
    #[cfg(test)]
    super::lab::stage("actual_fixed_child_created_at_placement_gate");
    // Only the private guard caller supplies this bound verification. It runs
    // in the host parent while this exact child remains at the existing fixed
    // placement gate, before any executable or worker handshake timer starts.
    if let Err(error) = before_release(role) {
        child.terminate()?;
        return Err(error);
    }
    if producer
        .release_child(
            &mut child,
            a,
            tx,
            ns,
            Some(match role {
                ActualRole::Daemon => super::inspection::PeerRole::Daemon,
                ActualRole::Observer => super::inspection::PeerRole::Observer,
                ActualRole::Monitor | ActualRole::OperationalMonitor => {
                    super::inspection::PeerRole::Monitor
                }
            }),
        )
        .is_err()
    {
        child.terminate()?;
        return Err(Error::PlacementFailed);
    }
    #[cfg(test)]
    super::lab::stage("actual_fixed_child_placed_released_waiting_setup");
    child.setup_complete()?;
    #[cfg(test)]
    super::lab::stage("actual_fixed_child_setup_completed");
    #[cfg(test)]
    child.require_actual_negative(role)?;
    #[cfg(test)]
    super::lab::stage("actual_fixed_child_negative_profile_confirmed");
    producer.verify_child(child.pid(), tx, &a.spec)?;
    Ok(child)
}
#[cfg(test)]
mod discovery_tests {
    use super::*;
    #[test]
    fn pinned_native_socket_connect_is_bounded_and_exposes_only_peer_hint() {
        use std::os::unix::{fs::DirBuilderExt, net::UnixListener};
        let directory = std::env::temp_dir().join(format!(
            "vprouter-localapi-hint-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("tailscaled.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let socket = fs::open(
            &path,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let peer = connect_pinned_socket(&socket, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(peer.pid.as_raw_pid() as u32, std::process::id());
        assert_eq!(peer.uid, rustix::process::getuid());
        assert!(matches!(
            connect_pinned_socket(&socket, Instant::now()),
            Err(Error::Deadline)
        ));
        let not_socket =
            fs::open(&directory, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap();
        assert!(matches!(
            connect_pinned_socket(&not_socket, Instant::now() + Duration::from_secs(1)),
            Err(Error::DescriptorPolicy)
        ));
        // Replacement cannot change the already pinned native socket. The
        // production path separately reopens and compares this exact identity.
        std::fs::rename(&path, directory.join("old.sock")).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        let current = fs::open(
            &path,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert_ne!(
            owned::Identity::of(&socket).unwrap(),
            owned::Identity::of(current).unwrap()
        );
        drop((socket, not_socket, replacement, listener));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(directory.join("old.sock")).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
