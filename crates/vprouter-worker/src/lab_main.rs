//! Controller-only static read-only owned-guest harness; no startup authority.
#![forbid(unsafe_code)]
#![allow(dead_code)]
#[path = "bootstrap.rs"]
mod bootstrap;
#[path = "client.rs"]
mod client;
#[path = "json.rs"]
mod json;
#[path = "localapi.rs"]
mod localapi;
#[path = "placement.rs"]
mod placement;
use vprouter_worker::{Error, operation};
type Result<T> = std::result::Result<T, Error>;
fn main() {
    if !std::env::args().any(|a| a == "--ignored") {
        println!("SKIP: requires controller-owned disposable guest and --ignored");
        return;
    }
    // Fixed paths only. Root-owned/single-link marker admits the *lab*, never
    // production readiness; no state/profile or AuthURL is read or printed.
    use std::os::unix::fs::MetadataExt;
    let marker = std::fs::symlink_metadata("/var/lib/vprouter-v2-lab/isolated-acceptance")
        .expect("lab marker absent");
    assert!(
        marker.is_file()
            && marker.uid() == 0
            && marker.gid() == 0
            && marker.mode() & 0o7777 == 0o600
            && marker.nlink() == 1,
        "lab marker unsafe"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let result=rt.block_on(async {
        let socket=std::path::Path::new("/run/tailscale/tailscaled.sock");
        let s=client::unix_request(socket,"GET","/localapi/v0/status?peers=false",b"",65536).await?;
        let s=localapi::parse_status(&s.body)?;
        let p=client::unix_request(socket,"GET","/localapi/v0/prefs",b"",65536).await?;
        let p=localapi::parse_prefs(&p.body)?;
        Ok::<_,Error>(serde_json::json!({"version_pinned":s.version_pinned(),"running":s.backend_state=="Running",
            "online":s.self_node.as_ref().is_some_and(|n|n.online),"netfilter_mode":p.netfilter_mode,
            "advertised_route_count":p.advertise_routes.len(),"guard_runtime":false,"activation_ready":false}))
    });
    match result {
        Ok(value) => println!("{value}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
