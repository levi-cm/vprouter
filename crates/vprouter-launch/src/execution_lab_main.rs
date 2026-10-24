#![deny(unsafe_code)]
#[allow(dead_code, unused_imports)]
#[path = "lib.rs"]
mod admission;
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args != ["--ignored"] {
        println!("execution_lab: ignored (protected owned guest only)");
        return;
    }
    if let Err(error) = admission::execution_lab::run() {
        eprintln!("execution_lab: {error}");
        std::process::exit(1);
    }
}
