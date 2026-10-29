//! Deny-by-default syscall policy for the fixed socket-bound WireGuard role.
use libc::{c_long, sock_filter as Insn};

const ALLOW: u32 = 0x7fff0000;
const DENY: u32 = 0x00050001;
fn ins(code: u16, jt: u8, jf: u8, k: u32) -> Insn {
    Insn { code, jt, jf, k }
}
fn load(offset: u32) -> Insn {
    ins(0x20, 0, 0, offset)
}
fn jump(count: usize) -> Insn {
    ins(0x05, 0, 0, count as u32)
}
fn ret(value: u32) -> Insn {
    ins(0x06, 0, 0, value)
}

/// An unmatched argument continues to the next alternative for this syscall;
/// every argument comparison covers both halves. Long branches avoid truncating
/// the bounded 128-profile descriptor set into an 8-bit cBPF jump.
fn rule(out: &mut Vec<Insn>, nr: c_long, fds: &[i32], args: &[(u32, u64)]) {
    let mut body = Vec::new();
    let mut misses = Vec::new();
    if !fds.is_empty() {
        body.extend([load(20), ins(0x15, 1, 0, 0)]);
        misses.push(body.len());
        body.push(jump(0));
        body.push(load(16));
        let mut matches = Vec::new();
        for fd in fds {
            body.push(ins(0x15, 0, 1, *fd as u32));
            matches.push(body.len());
            body.push(jump(0));
        }
        misses.push(body.len());
        body.push(jump(0));
        let target = body.len();
        for at in matches {
            body[at] = jump(target - at - 1);
        }
    }
    for (arg, value) in args {
        for (offset, expected) in [
            (16 + arg * 8, *value as u32),
            (20 + arg * 8, (*value >> 32) as u32),
        ] {
            body.extend([load(offset), ins(0x15, 1, 0, expected)]);
            misses.push(body.len());
            body.push(jump(0));
        }
    }
    body.push(ret(ALLOW));
    let end = body.len();
    body.push(load(0));
    for at in misses {
        body[at] = jump(end - at - 1);
    }
    out.extend([ins(0x15, 1, 0, nr as u32), jump(body.len())]);
    out.extend(body);
}
pub(crate) fn wireguard(
    inputs: &[i32],
    sockets: &[i32],
    pins: &[i32],
    channel: i32,
    gate: i32,
) -> Vec<Insn> {
    socket_role(inputs, sockets, pins, channel, gate, &[])
}
fn socket_role(
    inputs: &[i32],
    sockets: &[i32],
    pins: &[i32],
    channel: i32,
    gate: i32,
    ancestry: &[(i32, u64)],
) -> Vec<Insn> {
    #[cfg(target_arch = "x86_64")]
    let arch = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    let arch = 0xc00000b7;
    let mut out = vec![load(4), ins(0x15, 1, 0, arch), ret(0x80000000), load(0)];
    let all: Vec<_> = inputs
        .iter()
        .chain(sockets)
        .chain(pins)
        .copied()
        .chain([channel, gate])
        .collect();
    for nr in [libc::SYS_fstat, libc::SYS_close] {
        rule(&mut out, nr, &all, &[]);
    }
    rule(&mut out, libc::SYS_fstatfs, pins, &[]);
    if !inputs.is_empty() {
        rule(&mut out, libc::SYS_pread64, inputs, &[]);
    }
    rule(
        &mut out,
        libc::SYS_fcntl,
        &all,
        &[(1, libc::F_GETFD as u64)],
    );
    // Netlink endpoints were fixed and verified before clone. The network codec
    // independently requires kernel source pid/groups zero on every reply.
    rule(
        &mut out,
        libc::SYS_sendto,
        sockets,
        &[
            (3, libc::MSG_DONTWAIT as u64),
            (5, std::mem::size_of::<libc::sockaddr_nl>() as u64),
        ],
    );
    rule(
        &mut out,
        libc::SYS_recvfrom,
        sockets,
        &[(3, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64)],
    );
    rule(
        &mut out,
        libc::SYS_sendto,
        &[channel],
        &[
            (3, (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64),
            (4, 0),
            (5, 0),
        ],
    );
    rule(
        &mut out,
        libc::SYS_recvfrom,
        &[gate],
        &[
            (3, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64),
            (4, 0),
            (5, 0),
        ],
    );
    // Fixed names belong to the original immutable selected owner. No arbitrary
    // path, follow-symlink mode, or directory write is permitted.
    #[cfg(target_arch = "x86_64")]
    let stat = libc::SYS_newfstatat;
    #[cfg(target_arch = "aarch64")]
    let stat = libc::SYS_fstatat;
    for &(fd, name) in ancestry {
        rule(
            &mut out,
            stat,
            &[fd],
            &[(1, name), (3, libc::AT_SYMLINK_NOFOLLOW as u64)],
        );
    }
    runtime(&mut out);
    out
}
fn runtime(out: &mut Vec<Insn>) {
    rule(
        out,
        libc::SYS_prctl,
        &[],
        &[
            (0, libc::PR_GET_SECCOMP as u64),
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
        ],
    );
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
        rule(out, nr, &[], &[]);
    }
    // Anonymous private non-executable allocation only; no file mapping or
    // executable memory. No open, socket creation, exec, fork or namespace call.
    for protection in [
        libc::PROT_NONE,
        libc::PROT_READ,
        libc::PROT_WRITE,
        libc::PROT_READ | libc::PROT_WRITE,
    ] {
        rule(
            out,
            libc::SYS_mmap,
            &[],
            &[
                (2, protection as u64),
                (3, (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64),
                (4, u64::MAX),
                (5, 0),
            ],
        );
        rule(out, libc::SYS_mprotect, &[], &[(2, protection as u64)]);
    }
    out.push(ret(DENY));
}

pub(crate) fn producer_bootstrap(
    inputs: &[i32],
    sockets: &[i32],
    pins: &[i32],
    channel: i32,
    gate: i32,
    ancestry: &[(i32, u64)],
) -> Vec<Insn> {
    socket_role(inputs, sockets, pins, channel, gate, ancestry)
}

pub(crate) fn socket_creator(namespace: i32, result: i32, gate: i32) -> Vec<Insn> {
    socket_creator_policy(
        namespace,
        result,
        gate,
        &[libc::NETLINK_ROUTE, libc::NETLINK_GENERIC],
    )
}
pub(crate) fn netfilter_socket_creator(namespace: i32, result: i32, gate: i32) -> Vec<Insn> {
    socket_creator_policy(namespace, result, gate, &[libc::NETLINK_NETFILTER])
}
fn socket_creator_policy(namespace: i32, result: i32, gate: i32, protocols: &[i32]) -> Vec<Insn> {
    #[cfg(target_arch = "x86_64")]
    let arch = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    let arch = 0xc00000b7;
    let mut out = vec![load(4), ins(0x15, 1, 0, arch), ret(0x80000000), load(0)];
    for &protocol in protocols {
        rule(
            &mut out,
            libc::SYS_socket,
            &[],
            &[
                (0, libc::AF_NETLINK as u64),
                (
                    1,
                    (libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64,
                ),
                (2, protocol as u64),
            ],
        );
    }
    rule(
        &mut out,
        libc::SYS_bind,
        &[3, 4],
        &[(2, std::mem::size_of::<libc::sockaddr_nl>() as u64)],
    );
    rule(&mut out, libc::SYS_getsockname, &[3, 4], &[]);
    rule(
        &mut out,
        libc::SYS_sendmsg,
        &[result],
        &[(2, (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64)],
    );
    rule(
        &mut out,
        libc::SYS_recvfrom,
        &[gate],
        &[
            (3, (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64),
            (4, 0),
            (5, 0),
        ],
    );
    rule(
        &mut out,
        libc::SYS_close,
        &[3, 4, namespace, result, gate],
        &[],
    );
    runtime(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_ancestry_is_exact_read_only_and_does_not_expand_old_role() {
        #[cfg(target_arch = "x86_64")]
        let stat = libc::SYS_newfstatat;
        #[cfg(target_arch = "aarch64")]
        let stat = libc::SYS_fstatat;
        let names = [(40, 0x1234), (41, 0x2345), (42, 0x3456), (40, 0x4567)];
        let policy = producer_bootstrap(
            &[44, 45, 46, 47],
            &[30, 31],
            &[40, 41, 42, 43],
            50,
            51,
            &names,
        );
        let old = wireguard(&[44, 45, 46, 47], &[30, 31], &[40, 41, 42, 43], 50, 51);
        for (fd, name) in names {
            let args = [
                fd as u64,
                name,
                0xdead,
                libc::AT_SYMLINK_NOFOLLOW as u64,
                0,
                0,
            ];
            assert_eq!(evaluate(&policy, stat, args), ALLOW);
            assert_eq!(evaluate(&old, stat, args), DENY);
            for (field, value) in [(0, 99), (1, name + 1), (3, 0)] {
                let mut wrong = args;
                wrong[field] = value;
                assert_eq!(evaluate(&policy, stat, wrong), DENY);
            }
        }
        for nr in [
            libc::SYS_openat,
            libc::SYS_write,
            libc::SYS_dup,
            libc::SYS_mkdirat,
            libc::SYS_unlinkat,
            libc::SYS_setns,
        ] {
            assert_eq!(evaluate(&policy, nr, [42, 0x3456, 0, 0, 0, 0]), DENY);
        }
        assert_eq!(
            evaluate(&policy, libc::SYS_pread64, [42, 0, 100, 0, 0, 0]),
            DENY
        );
        assert_eq!(
            evaluate(&policy, libc::SYS_pread64, [47, 0, 100, 0, 0, 0]),
            ALLOW
        );
    }
    fn evaluate(program: &[Insn], nr: c_long, args: [u64; 6]) -> u32 {
        let mut words = [0u32; 16];
        words[0] = nr as u32;
        #[cfg(target_arch = "x86_64")]
        {
            words[1] = 0xc000003e;
        }
        #[cfg(target_arch = "aarch64")]
        {
            words[1] = 0xc00000b7;
        }
        for (i, v) in args.iter().enumerate() {
            words[4 + i * 2] = *v as u32;
            words[5 + i * 2] = (*v >> 32) as u32;
        }
        let mut a = 0;
        let mut pc = 0;
        for _ in 0..program.len() {
            let i = &program[pc];
            pc += 1;
            match i.code {
                0x20 => a = words[i.k as usize / 4],
                0x15 => pc += if a == i.k { i.jt } else { i.jf } as usize,
                0x05 => pc += i.k as usize,
                0x06 => return i.k,
                _ => panic!("unknown instruction"),
            }
        }
        panic!("unterminated policy")
    }
    #[test]
    fn exact_fd_arguments_and_denied_fork_namespace_dumpability() {
        let p = wireguard(&[70, 71], &[80, 81], &[90, 91], 100, 101);
        let private = [
            101,
            0,
            16,
            (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64,
            0,
            0,
        ];
        assert_eq!(evaluate(&p, libc::SYS_recvfrom, private), ALLOW);
        let mut alias = private;
        alias[0] |= 1 << 32;
        assert_eq!(evaluate(&p, libc::SYS_recvfrom, alias), DENY);
        let mut foreign = private;
        foreign[0] = 100; // Result endpoint must not receive release messages.
        assert_eq!(evaluate(&p, libc::SYS_recvfrom, foreign), DENY);
        let send = [80, 1, 32, libc::MSG_DONTWAIT as u64, 2, 12];
        assert_eq!(evaluate(&p, libc::SYS_sendto, send), ALLOW);
        let mut flags = send;
        flags[3] |= 1 << 32;
        assert_eq!(evaluate(&p, libc::SYS_sendto, flags), DENY);
        assert_eq!(evaluate(&p, libc::SYS_pread64, [70, 1, 16, 0, 0, 0]), ALLOW);
        assert_eq!(evaluate(&p, libc::SYS_pread64, [80, 1, 16, 0, 0, 0]), DENY);
        for nr in [
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_socket,
            libc::SYS_openat,
        ] {
            assert_eq!(evaluate(&p, nr, [0; 6]), DENY);
        }
        assert_eq!(
            evaluate(
                &p,
                libc::SYS_prctl,
                [libc::PR_SET_DUMPABLE as u64, 1, 0, 0, 0, 0]
            ),
            DENY
        );
        assert_eq!(
            evaluate(
                &p,
                libc::SYS_fcntl,
                [70, libc::F_DUPFD_CLOEXEC as u64, 64, 0, 0, 0]
            ),
            DENY
        );
    }
    #[test]
    fn socket_creator_is_directional_and_cannot_transact_netlink() {
        let p = socket_creator(70, 71, 72);
        for protocol in [libc::NETLINK_ROUTE, libc::NETLINK_GENERIC] {
            let args = [
                libc::AF_NETLINK as u64,
                (libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64,
                protocol as u64,
                0,
                0,
                0,
            ];
            assert_eq!(evaluate(&p, libc::SYS_socket, args), ALLOW);
            for index in 0..3 {
                let mut bad = args;
                bad[index] ^= 1 << 32;
                assert_eq!(evaluate(&p, libc::SYS_socket, bad), DENY);
            }
        }
        let recv = [
            72,
            0,
            2,
            (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64,
            0,
            0,
        ];
        assert_eq!(evaluate(&p, libc::SYS_recvfrom, recv), ALLOW);
        for fd in [3, 4, 70, 71, 72 | (1 << 32)] {
            let mut bad = recv;
            bad[0] = fd;
            assert_eq!(evaluate(&p, libc::SYS_recvfrom, bad), DENY);
        }
        let send = [
            71,
            0,
            (libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) as u64,
            0,
            0,
            0,
        ];
        assert_eq!(evaluate(&p, libc::SYS_sendmsg, send), ALLOW);
        for fd in [3, 4, 70, 72, 71 | (1 << 32)] {
            let mut bad = send;
            bad[0] = fd;
            assert_eq!(evaluate(&p, libc::SYS_sendmsg, bad), DENY);
        }
        for nr in [
            libc::SYS_sendto,
            libc::SYS_recvmsg,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_clone3,
            libc::SYS_clone,
            libc::SYS_execve,
            libc::SYS_pread64,
        ] {
            assert_eq!(evaluate(&p, nr, [3, 0, 0, 0, 0, 0]), DENY);
        }
    }
    #[test]
    fn netfilter_creator_permits_only_fixed_pair_protocol_and_no_transactions() {
        let p = netfilter_socket_creator(70, 71, 72);
        let args = [
            libc::AF_NETLINK as u64,
            (libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u64,
            libc::NETLINK_NETFILTER as u64,
            0,
            0,
            0,
        ];
        assert_eq!(evaluate(&p, libc::SYS_socket, args), ALLOW);
        for protocol in [libc::NETLINK_ROUTE, libc::NETLINK_GENERIC] {
            let mut wrong = args;
            wrong[2] = protocol as u64;
            assert_eq!(evaluate(&p, libc::SYS_socket, wrong), DENY);
        }
        for index in 0..3 {
            let mut alias = args;
            alias[index] |= 1 << 32;
            assert_eq!(evaluate(&p, libc::SYS_socket, alias), DENY);
        }
        for nr in [
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_recvmsg,
            libc::SYS_setns,
            libc::SYS_clone3,
            libc::SYS_execve,
        ] {
            assert_eq!(
                evaluate(&p, nr, [3, 0, 0, libc::MSG_DONTWAIT as u64, 0, 12]),
                DENY
            );
        }
    }
    #[test]
    fn producer_observation_has_only_four_read_inputs_and_no_group_write_or_alias() {
        let p = wireguard(
            &[54, 55, 56, 57],
            &[60, 61],
            &[50, 51, 52, 53, 54, 55, 56, 57],
            70,
            71,
        );
        for fd in 52..=57 {
            let args = [fd, 1, 16, 0, 0, 0];
            assert_eq!(
                evaluate(&p, libc::SYS_pread64, args),
                if fd >= 54 { ALLOW } else { DENY }
            );
            for nr in [libc::SYS_fstat, libc::SYS_fstatfs] {
                assert_eq!(evaluate(&p, nr, args), ALLOW);
            }
            for nr in [
                libc::SYS_read,
                libc::SYS_write,
                libc::SYS_pwrite64,
                libc::SYS_sendmsg,
                libc::SYS_recvmsg,
            ] {
                assert_eq!(evaluate(&p, nr, args), DENY);
            }
            let mut alias = args;
            alias[0] |= 1 << 32;
            assert_eq!(evaluate(&p, libc::SYS_pread64, alias), DENY);
            assert_eq!(evaluate(&p, libc::SYS_fstat, alias), DENY);
            assert_eq!(
                evaluate(&p, libc::SYS_fcntl, [fd, libc::F_GETFD as u64, 0, 0, 0, 0]),
                ALLOW
            );
            assert_eq!(
                evaluate(&p, libc::SYS_fcntl, [fd, libc::F_SETFD as u64, 0, 0, 0, 0]),
                DENY
            );
        }
        for fd in [3, 4, 50, 51, 60, 61, 70, 71, 99] {
            assert_eq!(evaluate(&p, libc::SYS_pread64, [fd, 1, 16, 0, 0, 0]), DENY);
        }
        for nr in [
            libc::SYS_openat,
            libc::SYS_openat2,
            libc::SYS_mkdirat,
            libc::SYS_unlinkat,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
            libc::SYS_execveat,
        ] {
            assert_eq!(evaluate(&p, nr, [54, 1, 16, 0, 0, 0]), DENY);
        }
    }
    #[test]
    fn veth_policy_denies_generic_transactions_but_keeps_custody() {
        let p = wireguard(&[], &[3], &[4, 67, 68], 65, 66);
        for fd in [3u64, 4] {
            let send = [fd, 1, 1, libc::MSG_DONTWAIT as u64, 1, 12];
            let recv = [
                fd,
                1,
                1,
                (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64,
                0,
                0,
            ];
            let expected = if fd == 3 { ALLOW } else { DENY };
            assert_eq!(evaluate(&p, libc::SYS_sendto, send), expected);
            assert_eq!(evaluate(&p, libc::SYS_recvfrom, recv), expected);
            let mut high = send;
            high[0] |= 1 << 32;
            assert_eq!(evaluate(&p, libc::SYS_sendto, high), DENY);
            assert_eq!(evaluate(&p, libc::SYS_fstat, [fd, 1, 0, 0, 0, 0]), ALLOW);
            assert_eq!(
                evaluate(&p, libc::SYS_fcntl, [fd, libc::F_GETFD as u64, 0, 0, 0, 0]),
                ALLOW
            );
            for nr in [
                libc::SYS_read,
                libc::SYS_write,
                libc::SYS_pread64,
                libc::SYS_sendmsg,
                libc::SYS_recvmsg,
            ] {
                assert_eq!(evaluate(&p, nr, [fd, 1, 1, 0, 0, 0]), DENY);
            }
        }
    }
    #[test]
    fn movement_policy_accepts_exact_four_sockets_and_two_pins_only() {
        let p = wireguard(&[], &[80, 81, 82, 83], &[90, 91, 92], 100, 101);
        for fd in [80, 81, 82, 83] {
            let args = [
                fd,
                1,
                32,
                libc::MSG_DONTWAIT as u64,
                2,
                std::mem::size_of::<libc::sockaddr_nl>() as u64,
            ];
            assert_eq!(evaluate(&p, libc::SYS_sendto, args), ALLOW);
            let mut alias = args;
            alias[0] |= 1 << 32;
            assert_eq!(evaluate(&p, libc::SYS_sendto, alias), DENY);
            let mut foreign = args;
            foreign[0] = 84;
            assert_eq!(evaluate(&p, libc::SYS_sendto, foreign), DENY);
            assert_eq!(
                evaluate(
                    &p,
                    libc::SYS_recvfrom,
                    [
                        fd,
                        1,
                        32,
                        (libc::MSG_DONTWAIT | libc::MSG_TRUNC) as u64,
                        0,
                        0
                    ]
                ),
                ALLOW
            );
            assert_eq!(
                evaluate(
                    &p,
                    libc::SYS_fcntl,
                    [fd, libc::F_DUPFD_CLOEXEC as u64, 0, 0, 0, 0]
                ),
                DENY
            );
        }
        for pin in [90, 91, 92] {
            assert_eq!(evaluate(&p, libc::SYS_fstatfs, [pin, 1, 0, 0, 0, 0]), ALLOW);
            assert_eq!(
                evaluate(
                    &p,
                    libc::SYS_sendto,
                    [pin, 1, 32, libc::MSG_DONTWAIT as u64, 2, 12]
                ),
                DENY
            );
        }
        for nr in [
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_pread64,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_execve,
        ] {
            assert_eq!(evaluate(&p, nr, [80, 0, 0, 0, 0, 0]), DENY);
        }
    }
    #[test]
    fn complete_maximum_profile_set_fits_kernel_program_bound() {
        let profiles: Vec<_> = (64..64 + vprouter_core::config::MAX_EXITS as i32).collect();
        let p = wireguard(&profiles, &[300, 301], &[302, 303], 304, 305);
        assert!(p.len() < 4096);
        for fd in profiles {
            assert_eq!(
                evaluate(&p, libc::SYS_pread64, [fd as u64, 0, 16, 0, 0, 0]),
                ALLOW
            );
        }
        assert_eq!(evaluate(&p, libc::SYS_pread64, [299, 0, 16, 0, 0, 0]), DENY);
    }
}
