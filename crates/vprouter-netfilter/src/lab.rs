//! Only compiled into the explicitly ignored disposable-kernel integration test.
use crate::{Error, Result};
use rustix::fs::{FileType, Mode, OFlags, fstat, open, openat};
use std::{fs, os::unix::fs::MetadataExt};

pub(crate) fn admit() -> Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(Error::LabRequired);
    }
    let own = fs::metadata("/proc/self/ns/net").map_err(|_| Error::LabRequired)?;
    let init = fs::metadata("/proc/1/ns/net").map_err(|_| Error::LabRequired)?;
    if (own.dev(), own.ino()) == (init.dev(), init.ino()) {
        return Err(Error::LabRequired);
    }
    let mut dir = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| Error::LabRequired)?;
    for name in ["var", "lib", "vprouter-v2-lab"] {
        let st = fstat(&dir).map_err(|_| Error::LabRequired)?;
        if st.st_uid != 0 || st.st_mode & 0o022 != 0 {
            return Err(Error::LabRequired);
        }
        dir = openat(
            &dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::LabRequired)?;
    }
    let st = fstat(&dir).map_err(|_| Error::LabRequired)?;
    if st.st_uid != 0 || st.st_mode & 0o7777 != 0o700 {
        return Err(Error::LabRequired);
    }
    let marker = openat(
        &dir,
        "isolated-acceptance",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::LabRequired)?;
    let st = fstat(&marker).map_err(|_| Error::LabRequired)?;
    if st.st_uid != 0
        || st.st_gid != 0
        || st.st_mode & 0o7777 != 0o600
        || st.st_nlink != 1
        || FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
    {
        return Err(Error::LabRequired);
    }
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    use crate::{
        Reconciliation as R,
        actuator::Actuator,
        codec::*,
        policy::{Scope, fixture},
        socket::Socket,
    };
    admit()?; // MUST precede even opening the mutating netfilter socket.
    fn deadline() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(5)
    }
    fn raw(ops: &[(u16, u16, Vec<Attr>)]) -> Result<()> {
        let mut s = Socket::open()?;
        let g = s.generation(deadline())?;
        s.batch(ops, g, deadline())
    }
    let sentinel = "vprouter_lab_unrelated_sentinel";
    raw(&[(
        NFT,
        CREATE | EXCL,
        vec![string(1, sentinel), attr(6, b"unrelated-sentinel".to_vec())],
    )])?;
    for scope in [Scope::Data, Scope::Transport, Scope::Host] {
        let policy = fixture(scope);
        let mut a = Actuator::open(policy.clone())?;
        if a.reconcile() != (R::Absent, R::Absent) {
            return Err(Error::Drifted);
        }
        a.install_quarantine()?;
        if a.reconcile() != (R::Matching, R::Absent) {
            return Err(Error::Drifted);
        }
        println!("{{\"case\":\"quarantine_exact\",\"scope\":\"{scope:?}\",\"result\":\"pass\"}}");
        // Same scoped table name with foreign userdata must never be replaced.
        raw(&[(
            NFT,
            CREATE | EXCL,
            vec![
                string(1, &policy.permit_table_name()),
                attr(6, b"foreign-owner".to_vec()),
            ],
        )])?;
        if a.install_permit() != Err(Error::Foreign) || a.reconcile() != (R::Matching, R::Foreign) {
            return Err(Error::Foreign);
        }
        raw(&[(NFT | 2, 0, vec![string(1, &policy.permit_table_name())])])?; // test fault only
        if let Err(e) = a.install_permit() {
            eprintln!("LAB_STAGE install_permit {scope:?} error={e:?}");
            a.diagnose();
            return Err(e);
        }
        if a.reconcile() != (R::Matching, R::Matching) {
            return Err(Error::Drifted);
        }
        let mut next = policy.clone();
        next.endpoint = crate::Endpoint::new(
            "185.65.134.89:51821"
                .parse()
                .map_err(|_| Error::InvalidInput)?,
        )?;
        if let Err(e) = a.replace_permit(next.clone()) {
            eprintln!("LAB_STAGE replace_permit {scope:?} error={e:?}");
            a.diagnose();
            return Err(e);
        }
        if a.reconcile() != (R::Matching, R::Matching) {
            return Err(Error::Drifted);
        }
        println!(
            "{{\"case\":\"atomic_replace_and_foreign_refusal\",\"scope\":\"{scope:?}\",\"result\":\"pass\"}}"
        );
        // A stale global generation must reject a batch before any deletion.
        let mut stale = Socket::open()?;
        let old_generation = stale.generation(deadline())?;
        let race_name = "vprouter_lab_generation_race";
        raw(&[(NFT, CREATE | EXCL, vec![string(1, race_name)])])?;
        if stale.batch(
            &[(NFT | 2, 0, vec![string(1, &policy.permit_table_name())])],
            old_generation,
            deadline(),
        ) != Err(Error::GenerationChanged)
            || a.reconcile() != (R::Matching, R::Matching)
        {
            return Err(Error::GenerationChanged);
        }
        raw(&[(NFT | 2, 0, vec![string(1, race_name)])])?;
        println!(
            "{{\"case\":\"stale_generation_refused\",\"scope\":\"{scope:?}\",\"result\":\"pass\"}}"
        );
        // A late invalid operation rolls back the preceding valid table deletion.
        let failed = raw(&[
            (NFT | 2, 0, vec![string(1, &policy.permit_table_name())]),
            (
                NFT | 6,
                CREATE | APPEND,
                vec![
                    string(1, &policy.permit_table_name()),
                    string(2, "missing_chain"),
                    nested(4, &[]),
                ],
            ),
        ]);
        if failed != Err(Error::KernelRejected) || a.reconcile() != (R::Matching, R::Matching) {
            return Err(Error::Drifted);
        }
        println!(
            "{{\"case\":\"failed_batch_retains_policy\",\"scope\":\"{scope:?}\",\"result\":\"pass\"}}"
        );
        // Independent nft CLI rendering is allowed in this TEST harness only.
        let render = std::process::Command::new("nft")
            .args(["list", "table", "inet", &policy.permit_table_name()])
            .output()
            .map_err(|_| Error::Io)?;
        if !render.status.success()
            || !String::from_utf8_lossy(&render.stdout).contains("hook forward")
        {
            return Err(Error::Drifted);
        }
        a.release_quarantine()?;
        if a.reconcile() != (R::Absent, R::Matching) {
            return Err(Error::Drifted);
        }
        a.install_quarantine()?;
        // A real extra functional rule is detected; neither release nor cleanup
        // can use the correct label/marker as a substitute for expression checks.
        let fault = std::process::Command::new("nft")
            .args([
                "add",
                "rule",
                "inet",
                &policy.permit_table_name(),
                "input",
                "accept",
            ])
            .output()
            .map_err(|_| Error::Io)?;
        if !fault.status.success()
            || a.reconcile() != (R::Matching, R::Drifted)
            || a.release_quarantine().is_ok()
            || a.install_permit().is_ok()
            || a.cleanup_permit().is_ok()
        {
            return Err(Error::Drifted);
        }
        println!(
            "{{\"case\":\"actual_drift_extra_rule_refused\",\"scope\":\"{scope:?}\",\"result\":\"pass\"}}"
        );
        // Harness resets only its injected table, then re-establishes desired
        // state under quarantine to exercise normal one-scope cleanup.
        raw(&[(NFT | 2, 0, vec![string(1, &next.permit_table_name())])])?;
        a.install_permit()?;
        a.cleanup_permit()?;
        if a.reconcile() != (R::Matching, R::Absent) {
            return Err(Error::Drifted);
        }
        let mut s = Socket::open()?;
        let tables = s.dump(1, &[], deadline())?;
        let preserved = tables.iter().any(|m| {
            nfattrs(m).is_ok_and(|attrs| {
                get(&attrs, 1).is_ok_and(|name| text(name) == Ok(sentinel))
                    && get(&attrs, 6) == Ok(b"unrelated-sentinel".as_slice())
            })
        });
        if !preserved {
            return Err(Error::Foreign);
        }
        println!(
            "{{\"case\":\"scope_cleanup_and_sentinel_preserved\",\"scope\":\"{scope:?}\",\"result\":\"pass\"}}"
        );
    }
    println!(
        "{{\"case\":\"native_netfilter_isolated_acceptance\",\"result\":\"pass\",\"guard_runtime\":false}}"
    );
    Ok(())
}
