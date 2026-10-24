#![forbid(unsafe_code)]
//! Static test-only payload; never a production worker constructor or feature.
pub fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args == ["--test-probe-container"] {
        loop {
            super::kernel::probe_container_reap();
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    if args != ["--isolated-probe"] {
        std::process::exit(118);
    }
    let result = super::kernel::probe_verify()
        .and_then(|()| super::kernel::probe_descendant())
        .and_then(|()| super::kernel::probe_ready());
    if let Err(e) = result {
        super::kernel::probe_failure(e);
        std::process::exit(117);
    }
    if let Err(error) = super::kernel::probe_signal_loop() {
        super::kernel::probe_failure(error);
        std::process::exit(117);
    }
}
