#![forbid(unsafe_code)]
fn main() {
    if std::env::args_os().len() != 1 || vprouter_worker::monitor::start().is_err() {
        eprintln!("monitor_refused");
        std::process::exit(1);
    }
}
