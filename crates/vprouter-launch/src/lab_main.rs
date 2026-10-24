#![forbid(unsafe_code)]
//! Custom test main: libtest's runner would add an extra OS task and defeat the
//! exact-one-task admission invariant. Ordinary `cargo test` skips this lab.
// The harness compiles private admission modules directly so synthetic staging
// constructors never become a feature/public API in the production library.
#[allow(dead_code, unused_imports)]
#[path = "lib.rs"]
mod admission;
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 || args[0] != "--ignored" {
        println!(
            "admission_lab: ignored (explicit --ignored and protected isolated guest required)"
        );
        return;
    }
    if let Err(error) = admission::lab::run() {
        eprintln!("admission_lab: {error}");
        std::process::exit(1);
    }
}
