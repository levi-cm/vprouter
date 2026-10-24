use std::path::Path;
use vprouter_core::{allocation::AllocationRecord, config::Configuration, profile::Profile};
#[test]
fn documented_fleets_validate_with_only_injected_synthetic_credentials() {
    let examples = [
        (
            include_bytes!("../../../examples/v2/one.json").as_slice(),
            1,
        ),
        (
            include_bytes!("../../../examples/v2/five.json").as_slice(),
            5,
        ),
        (
            include_bytes!("../../../examples/v2/mixed.json").as_slice(),
            6,
        ),
    ];
    let profiles = [
        include_bytes!("../../../examples/v2/profiles/profile-1.wg.example").as_slice(),
        include_bytes!("../../../examples/v2/profiles/profile-2.wg.example").as_slice(),
        include_bytes!("../../../examples/v2/profiles/profile-3.wg.example").as_slice(),
        include_bytes!("../../../examples/v2/profiles/profile-4.wg.example").as_slice(),
        include_bytes!("../../../examples/v2/profiles/profile-5.wg.example").as_slice(),
    ];
    for (bytes, count) in examples {
        let config = Configuration::parse(bytes)
            .unwrap()
            .validate_with(|path, server| {
                let name = path.file_name().unwrap().to_str().unwrap();
                let i = name
                    .strip_prefix("profile-")
                    .unwrap()
                    .strip_suffix(".wg.example")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                Profile::parse(profiles[i - 1], server, Some(Path::new(name)))
            })
            .unwrap();
        assert_eq!(config.exits().len(), count);
        assert!(AllocationRecord::from_configuration(&config, 1).is_ok());
    }
}
