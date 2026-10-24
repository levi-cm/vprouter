#![deny(unsafe_code)]
#[allow(dead_code, unused_imports)]
#[path = "lib.rs"]
mod admission;
fn main() {
    if std::env::args_os().any(|s| s == "--test-probe-container" || s == "--isolated-probe") {
        admission::probe::main();
    } else {
        println!("execution_probe: ignored (fixed test container invocation only)");
    }
}
