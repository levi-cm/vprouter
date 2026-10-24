//! Observation only. No production engine, advertisement or ready authority.
#![forbid(unsafe_code)]
fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("bootstrap_refused");
        std::process::exit(2);
    }
    match vprouter_worker::bootstrap::observe() {
        Ok(()) => println!("bootstrap_observed;activation=false;readiness=false"),
        Err(_) => {
            eprintln!("bootstrap_refused");
            std::process::exit(1);
        }
    }
}
