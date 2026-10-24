use vprouter_core::{config::Configuration, profile::Profile, reason::Reason};

fn profile(key: &str) -> String {
    format!(
        "# Server: de-fra-wg-404\n[Interface]\nPrivateKey = {key}\nAddress = 10.64.0.2/32, fd00::2/128\nDNS = 10.64.0.1\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 185.65.134.88:51820\n"
    )
}
const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
fn input(exits: &str) -> String {
    format!(
        r#"{{"schema_version":2,"deployment_id":"fleet","site":"debdev","gateway_image":"sha256:{}","exits":[{}],"dependency_adapters":[],"client_policies":[]}}"#,
        "a".repeat(64),
        exits
    )
}
fn exit(id: &str, state: &str) -> String {
    format!(
        r#"{{"id":"{id}","enabled":true,"state_dir":"{state}","mode":{{"kind":"mullvad","profile":"/profiles/de-fra-wg-404.conf","expected_server":"de-fra-wg-404"}}}}"#
    )
}
fn validate(
    s: &str,
) -> Result<vprouter_core::config::ValidatedConfiguration, vprouter_core::reason::Error> {
    Configuration::parse(s.as_bytes())?
        .validate_with(|_, server| Profile::parse(profile(KEY).as_bytes(), server, None))
}

#[test]
fn one_exit_has_exact_display_name() {
    let config = validate(&input(&exit("primary", "/state/primary"))).unwrap();
    assert_eq!(
        config.exits()[0].hostname(),
        "mullvad-debdev-exit-de-fra-wg-404"
    );
}
#[test]
fn strict_schema_rejects_mode_confusion_unknown_and_duplicate_fields() {
    let s = input(&exit("primary", "/state/primary"));
    for bad in [
        s.replace("\"kind\":\"mullvad\"", "\"kind\":\"direct\""),
        s.replace("\"site\":", "\"fallback\":true,\"site\":"),
        s.replace("\"site\":", "\"site\":\"other\",\"site\":"),
    ] {
        assert_eq!(
            validate(&bad).err().unwrap().reason(),
            Reason::InvalidSchema
        );
    }
}
#[test]
fn disabled_exit_cannot_reuse_identity_or_overlap_state() {
    let two = input(&format!(
        "{},{}",
        exit("a", "/state/a"),
        exit("b", "/state/b").replace("true", "false")
    ));
    assert_eq!(
        validate(&two).err().unwrap().reason(),
        Reason::DuplicatePrivateKey
    );
    let nested = input(&format!(
        "{},{}",
        exit("a", "/state/a"),
        exit("b", "/state/a/nested")
    ));
    assert_eq!(
        validate(&nested).err().unwrap().reason(),
        Reason::StateConflict
    );
}
#[test]
fn profile_rejects_commands_wrong_server_and_nonpublic_endpoint() {
    for bad in [
        profile(KEY).replace("DNS =", "PostUp ="),
        profile(KEY).replace("de-fra-wg-404", "de-fra-wg-405"),
        profile(KEY).replace("185.65.134.88", "127.0.0.1"),
        profile(KEY).replace("[Peer]", "[Peer]\n[Peer]"),
    ] {
        assert!(Profile::parse(bad.as_bytes(), "de-fra-wg-404", None).is_err());
    }
}
#[test]
fn errors_do_not_include_untrusted_values() {
    let bad = input(&exit("primary", "/secret-path/../state"));
    let error = validate(&bad).err().unwrap();
    assert!(!format!("{error:?} {error}").contains("secret-path"));
    assert!(
        Configuration::parse(b"{\"private_key\":\"secret-marker\"}")
            .err()
            .is_some_and(|e| !format!("{e:?} {e}").contains("secret-marker"))
    );
}

#[test]
fn image_digest_and_repository_grammar_are_strict() {
    let base = input(&exit("a", "/state/a"));
    let old = format!("sha256:{}", "a".repeat(64));
    for image in [
        "latest".to_owned(),
        format!("repo:tag@{old}"),
        format!("@{old}"),
        format!("repo//app@{old}"),
        format!("repo..broken/app@{old}"),
        format!("registry:0/repo@{old}"),
        format!("repo@sha256:{}", "A".repeat(64)),
    ] {
        assert!(
            validate(&base.replace(&old, &image)).is_err(),
            "accepted malformed image"
        );
    }
    for image in [
        format!("ghcr.io/example/router@{old}"),
        format!("registry:5000/team/router-v2@{old}"),
    ] {
        assert!(validate(&base.replace(&old, &image)).is_ok());
    }
}
#[test]
fn collision_suffixes_all_names_and_does_not_move_state() {
    let two = input(&format!(
        "{},{}",
        exit("a", "/state/a"),
        exit("b", "/state/b")
    ));
    let mut n = 0;
    let cfg = Configuration::parse(two.as_bytes())
        .unwrap()
        .validate_with(|_, server| {
            n += 1;
            let key = if n == 1 {
                KEY
            } else {
                "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
            };
            Profile::parse(profile(key).as_bytes(), server, None)
        })
        .unwrap();
    assert_eq!(
        cfg.exits()[0].hostname(),
        "mullvad-debdev-exit-de-fra-wg-404-a"
    );
    assert_eq!(
        cfg.exits()[1].hostname(),
        "mullvad-debdev-exit-de-fra-wg-404-b"
    );
    assert_eq!(
        cfg.exits()[0].exit().state_dir,
        std::path::Path::new("/state/a")
    );
}
#[test]
fn lexical_paths_fleet_bounds_and_disabled_ids_are_validated_before_profile_reads() {
    let base = input(&exit("primary", "/state/primary"));
    for s in [
        base.replace("\"schema_version\":2", "\"schema_version\":1"),
        base.replace("debdev", ""),
        base.replace("/state/primary", "/state//primary"),
        base.replace("/state/primary", "/state/./primary"),
        base.replace("/state/primary", "relative"),
        input(""),
        input(&format!(
            "{},{}",
            exit("same", "/state/one"),
            exit("same", "/state/two").replace("true", "false")
        )),
    ] {
        assert!(validate(&s).is_err());
    }
    let many = (0..129)
        .map(|n| exit(&format!("exit{n}"), &format!("/state/exit{n}")))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        validate(&input(&many)).err().unwrap().reason(),
        Reason::InvalidSchema
    );
}
#[test]
fn generic_filename_is_not_server_authentication_but_verifiable_hints_must_match() {
    let p = profile(KEY).replace("# Server: de-fra-wg-404\n", "");
    let generic = Profile::parse(
        p.as_bytes(),
        "de-fra-wg-404",
        Some(std::path::Path::new("/profiles/max-vprouter.conf")),
    )
    .unwrap();
    assert!(!generic.has_matching_server_hint());
    assert!(
        Profile::parse(
            p.as_bytes(),
            "de-fra-wg-404",
            Some(std::path::Path::new("/profiles/de-fra-wg-405.conf"))
        )
        .is_err()
    );
    for bad in [
        p.replace("Address = 10.64.0.2/32", "Address = 255.255.255.255/32"),
        p.replace(KEY, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        p.replace(
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF=",
        ),
        p.replace("0.0.0.0/0", "10.0.0.0/8"),
        p.replace("Endpoint =", "Unknown ="),
        p.replace("[Interface]", "[Interface]\n[Interface]"),
    ] {
        assert!(Profile::parse(bad.as_bytes(), "de-fra-wg-404", None).is_err());
    }
    assert!(Profile::parse(&vec![b' '; 65537], "de-fra-wg-404", None).is_err());
}
#[test]
fn real_zero_padded_mullvad_server_identifiers_are_preserved() {
    let s = input(&exit("primary", "/state/primary")).replace("de-fra-wg-404", "de-fra-wg-003");
    let c = Configuration::parse(s.as_bytes())
        .unwrap()
        .validate_with(|_, server| {
            Profile::parse(
                profile(KEY)
                    .replace("de-fra-wg-404", "de-fra-wg-003")
                    .as_bytes(),
                server,
                None,
            )
        })
        .unwrap();
    assert_eq!(c.exits()[0].hostname(), "mullvad-debdev-exit-de-fra-wg-003");
}
#[test]
fn adapters_and_client_bindings_require_explicit_bounded_actions() {
    let action = serde_json::json!({"executable":"/usr/libexec/router-adapter","argv":["drain","--safe"],"timeout_seconds":30,"idempotent":true});
    let adapter = serde_json::json!({"id":"consumer","drain":action,"stop":action,"rebind":action,"start":action,"health_check":action});
    let policy = serde_json::json!({"id":"desktop","exit_id":"primary","selected_node_id":"node123","mode":"protected","dependency_adapters":["consumer"]});
    let mut raw: serde_json::Value =
        serde_json::from_str(&input(&exit("primary", "/state/primary"))).unwrap();
    raw["dependency_adapters"] = serde_json::json!([adapter]);
    raw["client_policies"] = serde_json::json!([policy]);
    assert!(validate(&raw.to_string()).is_ok());
    for change in 0..10 {
        let mut v = raw.clone();
        match change {
            0 => v["dependency_adapters"][0]["drain"]["idempotent"] = false.into(),
            1 => v["dependency_adapters"][0]["drain"]["timeout_seconds"] = 0.into(),
            2 => v["dependency_adapters"][0]["drain"]["timeout_seconds"] = 301.into(),
            3 => v["dependency_adapters"][0]["drain"]["executable"] = "relative".into(),
            4 => v["dependency_adapters"][0]["drain"]["executable"] = "/bin/sh".into(),
            5 => v["dependency_adapters"][0]["drain"]["argv"] = "do shell stuff".into(),
            6 => v["client_policies"][0]["dependency_adapters"] = serde_json::json!(["missing"]),
            7 => v["client_policies"][0]["mode"] = "direct".into(),
            8 => v["client_policies"][0]["selected_node_id"] = "".into(),
            _ => {
                v["client_policies"][0]["dependency_adapters"] =
                    serde_json::json!(["consumer", "consumer"])
            }
        }
        assert!(validate(&v.to_string()).is_err(), "case {change}");
    }
}
#[test]
fn generated_names_are_never_truncated() {
    let s = input(&exit("primary", "/state/primary")).replace("debdev", &"a".repeat(63));
    assert!(validate(&s).is_err());
}
#[test]
fn device_name_comments_do_not_claim_server_identity() {
    let p = profile(KEY).replace(
        "# Server: de-fra-wg-404",
        "# Name = harmless-device\n# Device: de-fra-wg-405",
    );
    let parsed = Profile::parse(p.as_bytes(), "de-fra-wg-404", None).unwrap();
    assert!(!parsed.has_matching_server_hint());
}

#[test]
fn clamp_equivalent_wireguard_keys_are_one_identity_even_when_disabled() {
    // These synthetic encodings differ only in scalar bits ignored by X25519.
    let variants = [
        "AAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAYE=",
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAUE=",
    ];
    for key in variants {
        for enabled in [true, false] {
            let two = input(&format!(
                "{},{}",
                exit("a", "/state/a"),
                exit("b", "/state/b").replace("true", if enabled { "true" } else { "false" })
            ));
            let mut n = 0;
            let result =
                Configuration::parse(two.as_bytes())
                    .unwrap()
                    .validate_with(|_, server| {
                        n += 1;
                        Profile::parse(
                            profile(if n == 1 { KEY } else { key }).as_bytes(),
                            server,
                            None,
                        )
                    });
            assert_eq!(result.err().unwrap().reason(), Reason::DuplicatePrivateKey);
        }
    }
}

#[test]
fn lowercase_legacy_profile_retains_generic_source_path_and_public_fields() {
    // Synthetic keys and public endpoint; models ConfigParser's lowercased options.
    let legacy = profile(KEY)
        .lines()
        .map(|line| match line.split_once('=') {
            Some((field, value)) => format!("{}={value}", field.to_ascii_lowercase()),
            None => line.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    let generic = "/profiles/max-vprouter.conf";
    let raw =
        input(&exit("primary", "/state/primary")).replace("/profiles/de-fra-wg-404.conf", generic);
    let config = Configuration::parse(raw.as_bytes())
        .unwrap()
        .validate_with(|path, server| {
            assert_eq!(path, std::path::Path::new(generic));
            Profile::parse(legacy.as_bytes(), server, Some(path))
        })
        .unwrap();
    let validated = &config.exits()[0];
    match &validated.exit().mode {
        vprouter_core::config::Mode::Mullvad { profile, .. } => {
            assert_eq!(profile, std::path::Path::new(generic))
        }
        _ => panic!("expected Mullvad fixture"),
    }
    let parsed = validated.profile().unwrap();
    assert_eq!(parsed.endpoint().to_string(), "185.65.134.88:51820");
    assert_eq!(parsed.address().to_string(), "10.64.0.2");
    assert_eq!(parsed.expected_server(), "de-fra-wg-404");
    assert!(parsed.has_matching_server_hint());
}

#[test]
fn profile_known_options_are_ascii_case_insensitive_and_duplicates_still_fail() {
    let base = profile(KEY)
        .replace("DNS =", "MTU = 1420\nDNS =")
        .replace("Endpoint =", "PersistentKeepalive = 25\nEndpoint =");
    let mixed = base
        .replace("PrivateKey", "pRiVaTeKeY")
        .replace("Address", "aDdReSs")
        .replace("DNS", "dNs")
        .replace("MTU", "mTu")
        .replace("PublicKey", "pUbLiCkEy")
        .replace("AllowedIPs", "aLlOwEdIpS")
        .replace("Endpoint", "eNdPoInT")
        .replace("PersistentKeepalive", "pErSiStEnTkEePaLiVe");
    assert!(Profile::parse(mixed.as_bytes(), "de-fra-wg-404", None).is_ok());
    for name in [
        "PrivateKey",
        "Address",
        "DNS",
        "MTU",
        "PublicKey",
        "AllowedIPs",
        "Endpoint",
        "PersistentKeepalive",
    ] {
        let line = base
            .lines()
            .find(|line| line.starts_with(&format!("{name} =")))
            .unwrap();
        let duplicate = format!(
            "{line}\n{}",
            line.replacen(name, &name.to_ascii_lowercase(), 1)
        );
        let invalid = base.replace(line, &duplicate);
        assert_eq!(
            Profile::parse(invalid.as_bytes(), "de-fra-wg-404", None)
                .err()
                .unwrap()
                .reason(),
            Reason::InvalidProfile
        );
    }
    for invalid in [
        mixed.replace("[Interface]", "[interface]"),
        mixed.replace("dNs =", "pOsTuP ="),
        mixed.replace("dNs =", "dNſ ="),
        mixed.replace("de-fra-wg-404", "de-fra-wg-405"),
        mixed.replace("185.65.134.88", "127.0.0.1"),
    ] {
        assert!(Profile::parse(invalid.as_bytes(), "de-fra-wg-404", None).is_err());
    }
}

#[test]
fn profile_dns_retains_metadata_and_derives_only_explicit_private_ipv4_authority() {
    let source = profile(KEY).replace(
        "DNS = 10.64.0.1",
        "DNS = 10.64.0.1, fd00::53, 9.9.9.9, 192.168.2.53",
    );
    let p = Profile::parse(source.as_bytes(), "de-fra-wg-404", None).unwrap();
    assert_eq!(p.dns_metadata().len(), 4);
    assert_eq!(
        p.resolvers(),
        &[
            "10.64.0.1".parse::<std::net::Ipv4Addr>().unwrap(),
            "192.168.2.53".parse().unwrap()
        ]
    );
    for list in [
        "10.64.0.1,10.64.0.1",
        "fd00::53, fd00:0:0::53",
        "10.64.0.1,",
        "not-an-ip",
        "10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8,10.0.0.9",
    ] {
        let bad = profile(KEY).replace("DNS = 10.64.0.1", &format!("DNS = {list}"));
        let e = Profile::parse(bad.as_bytes(), "de-fra-wg-404", None)
            .err()
            .unwrap();
        assert_eq!(e.reason(), Reason::InvalidProfile);
        assert!(!format!("{e:?} {e}").contains(KEY));
        assert!(!format!("{e:?} {e}").contains(list));
    }
    let no_authority = profile(KEY).replace("DNS = 10.64.0.1", "DNS = fd00::53, 9.9.9.9");
    assert!(
        Profile::parse(no_authority.as_bytes(), "de-fra-wg-404", None)
            .unwrap()
            .resolvers()
            .is_empty()
    );
    // Missing DNS metadata preserves existing profile parsing, but yields no
    // authority; guard startup must refuse it before any network mutation.
    let missing = profile(KEY).replace("DNS = 10.64.0.1\n", "");
    assert!(
        Profile::parse(missing.as_bytes(), "de-fra-wg-404", None)
            .unwrap()
            .resolvers()
            .is_empty()
    );
}
