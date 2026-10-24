#![deny(unsafe_code)]
#[allow(dead_code, unused_imports)]
#[path = "lib.rs"]
mod admission;
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let scenario = match args.as_slice() {
        [ignored] if ignored == "--ignored" => Some("reversible"),
        [ignored, flag, value] if ignored == "--ignored" && flag == "--scenario" => value.to_str(),
        _ => None,
    };
    let Some(scenario) = scenario.and_then(admission::transport_lab::Scenario::parse) else {
        println!("transport_lab: ignored (exact-hash owned local guest only)");
        return;
    };
    if let Err(e) = admission::transport_lab::run(scenario) {
        eprintln!("transport_lab: {e}");
        std::process::exit(1);
    }
}
