//! Fixed inert base-namespace holder. It never configures networking or starts a daemon.
#![forbid(unsafe_code)]
fn main() {
    if std::env::args_os().len() != 1 || vprouter_launch::gateway_init().is_err() {
        std::process::exit(1);
    }
}
