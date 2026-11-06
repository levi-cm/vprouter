use std::path::Path;
use vprouter_core::{config::Configuration, profile::Profile, reason::Result};

pub fn configuration(count: usize) -> Configuration {
    let mut cfg =
        Configuration::parse(include_bytes!("../../../../examples/v2/five.json")).unwrap();
    cfg.exits.truncate(count);
    cfg.client_policies.clear();
    cfg
}

pub fn profile(path: &Path, server: &str) -> Result<Profile> {
    let profiles = [
        include_bytes!("../../../../examples/v2/profiles/profile-1.wg.example").as_slice(),
        include_bytes!("../../../../examples/v2/profiles/profile-2.wg.example").as_slice(),
        include_bytes!("../../../../examples/v2/profiles/profile-3.wg.example").as_slice(),
        include_bytes!("../../../../examples/v2/profiles/profile-4.wg.example").as_slice(),
        include_bytes!("../../../../examples/v2/profiles/profile-5.wg.example").as_slice(),
    ];
    let name = path.file_name().unwrap().to_str().unwrap();
    let i = name
        .strip_prefix("profile-")
        .unwrap()
        .strip_suffix(".wg.example")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    Profile::parse(profiles[i - 1], server, None)
}
