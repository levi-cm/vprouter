#![deny(unsafe_code)]
#[allow(dead_code, unused_imports)]
#[path = "lib.rs"]
mod admission;
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.as_slice() != ["--ignored"] {
        println!("producer_lab: ignored (exact-hash owned local guest only)");
        return;
    }
    if let Err(e) = admission::execution_lab::run_producer() {
        eprintln!("producer_lab: {e}");
        std::process::exit(1);
    }
}
