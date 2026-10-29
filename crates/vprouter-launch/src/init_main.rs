//! Fixed inert base-namespace holder; no host-runtime library linkage.
#![deny(unsafe_code)]
#[allow(dead_code)]
mod error;
use error::{Error, Result};
#[allow(unsafe_code, dead_code)]
mod kernel_base;
fn main() {
    if std::env::args_os().len() != 1 || kernel_base::gateway_init().is_err() {
        std::process::exit(1);
    }
}
