#![deny(unsafe_code)]
#[allow(dead_code, unused_imports)]
#[path = "lib.rs"]
mod admission;
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.as_slice() != ["--ignored"] {
        println!("actual_lab: ignored (exact-hash owned local guest only)");
        return;
    }
    if let Err(error) = admission::transport_lab::run(admission::transport_lab::Scenario::Actual) {
        eprintln!("actual_lab: {error}");
        std::process::exit(1);
    }
}
