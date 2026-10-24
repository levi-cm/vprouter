#![forbid(unsafe_code)]
//! Synthetic disposable container init only; never production worker evidence.
fn main() {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(600));
    }
}
