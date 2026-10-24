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
    os::fd::{AsFd, BorrowedFd, OwnedFd},
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
#[allow(clippy::too_many_arguments)]
pub(super) fn launch(
    a: &Admission,
    tx: &Transaction<'_>,
    ns: &OwnedNamespaces,
    producer: &ProducerGroup,
    bundle: &ReviewedBundle,
    role: ActualRole,
    resolver: Ipv4Addr,
    placement: Option<BorrowedFd<'_>>,
) -> Result<kernel::Child> {
    super::process::single_threaded()?;
    a.process.revalidate(&a.spec, &a.staging)?;
    tx.revalidate(&a.spec)?;
    ns.bind(&a.spec)?;
    producer.verify(tx, &a.spec)?;
    if !resolver.is_private() {
        return Err(Error::ResolverUnavailable);
    }
    if (role == ActualRole::Observer) != placement.is_some() {
        return Err(Error::DescriptorPolicy);
    }
    let program = bundle.open(
        a.process.root(),
        if role == ActualRole::Observer {
            Role::WorkerObserver
        } else {
            Role::Tailscaled
        },
    )?;
    let ca = ca(a.process.root())?;
    let state = state(a, role)?;
    let tun = if role == ActualRole::Daemon {
        Some(tun(a)?)
    } else {
        None
    };
    let localapi = if role == ActualRole::Observer {
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
            executable: program.fd(),
            ca: ca.as_fd(),
            placement,
            localapi: localapi.as_ref().map(AsFd::as_fd),
            tun: tun.as_ref().map(AsFd::as_fd),
            resolver,
        },
    )?;
    if producer.release_child(&mut child, a, tx, ns).is_err() {
        child.terminate()?;
        return Err(Error::PlacementFailed);
    }
    child.setup_complete()?;
    producer.verify_child(child.pid(), tx, &a.spec)?;
    Ok(child)
}
