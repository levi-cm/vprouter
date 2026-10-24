#![forbid(unsafe_code)]
//! Static test-only payload; never a production worker constructor or feature.
pub fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args == ["--test-probe-container"] {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
    if args != ["--isolated-probe"] {
        std::process::exit(118);
    }
    let result = super::kernel::probe_verify()
        .and_then(|()| super::kernel::probe_descendant())
        .and_then(|()| super::kernel::probe_ready());
    if result.is_err() {
        std::process::exit(117);
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
