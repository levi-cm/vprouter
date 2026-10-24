#![forbid(unsafe_code)]
use std::path::Path;
fn main() {
    // No async macro, signal driver, blocking pool or thread creation. Paths
    // contain only protected public manifests; no argv/env/command secret input.
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = if args.len() != 2 {
        Err(vprouter_launch::Error::InvalidSpec)
    } else {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|_| vprouter_launch::Error::UnsupportedPlatform)
            .and_then(|runtime| {
                runtime.block_on(async {
                    vprouter_launch::Admission::inspect(Path::new(&args[0]), Path::new(&args[1]))
                        .await?
                        .launch()
                })
            })
    };
    let reason = result
        .err()
        .unwrap_or(vprouter_launch::Error::LaunchUnavailable);
    println!(
        "{{\"ok\":false,\"reason\":\"{reason}\",\"guard_runtime\":false,\"activation_ready\":false}}"
    );
    std::process::exit(1);
}
