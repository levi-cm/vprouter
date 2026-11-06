mod support;
use support::{configuration, profile};
use vprouter_core::{
    allocation::ResourceClaim,
    config::Mode,
    reason::Reason,
    transaction::{ExitChange, PreparedFleet},
};

#[test]
fn scoped_json_changes_preserve_stable_resources_and_reconcile_all_duplicate_names() {
    let mut cfg = configuration(1);
    // Same server and overlapping inner addresses are legal with distinct keys.
    let mut second = configuration(2).exits.remove(1);
    second.mode = Mode::Mullvad {
        profile: "/synthetic/profile-2.wg.example".into(),
        expected_server: "de-fra-wg-404".into(),
    };
    cfg.exits[0].mode = Mode::Mullvad {
        profile: "/synthetic/profile-1.wg.example".into(),
        expected_server: "de-fra-wg-404".into(),
    };
    let reader = |path: &std::path::Path, server: &str| {
        // Strip the example's untrusted server hint, retaining genuine parser/key validation.
        let bytes = if path.to_str().unwrap().contains("profile-1") {
            include_str!("../../../examples/v2/profiles/profile-1.wg.example")
        } else {
            include_str!("../../../examples/v2/profiles/profile-2.wg.example")
        };
        let bytes = bytes
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        let bytes = bytes
            .replace("10.64.0.2/32", "10.64.0.1/32")
            .replace("185.65.134.82:51820", "185.65.134.81:51820");
        vprouter_core::profile::Profile::parse(bytes.as_bytes(), server, None)
    };
    let initial = PreparedFleet::initial(cfg, reader, &[]).unwrap();
    let original = initial.record().allocations().exits[0].clone();
    let change = ExitChange::parse(
        &serde_json::to_vec(&serde_json::json!({"operation":"add","exit":second})).unwrap(),
    )
    .unwrap();
    let added = initial.record().prepare(change, reader, &[]).unwrap();
    assert_eq!(added.record().generation(), 2);
    assert_eq!(added.record().allocations().exits[0], original);
    let ids: Vec<_> = added
        .configuration()
        .exits()
        .iter()
        .map(|e| e.exit().id.as_str())
        .collect();
    for exit in added.configuration().exits() {
        assert_eq!(
            exit.hostname(),
            format!("mullvad-debdev-exit-de-fra-wg-404-{}", exit.exit().id)
        );
    }
    assert_eq!(added.renames().len(), 2);
    let profiles: Vec<_> = added
        .configuration()
        .exits()
        .iter()
        .map(|e| e.profile().unwrap())
        .collect();
    assert_eq!(profiles[0].address(), profiles[1].address());
    assert_eq!(profiles[0].endpoint(), profiles[1].endpoint());
    assert_ne!(
        profiles[0].public_metadata().device_public_key(),
        profiles[1].public_metadata().device_public_key()
    );

    let disabled = added
        .record()
        .prepare(
            ExitChange::Disable {
                exit_id: ids[1].into(),
            },
            reader,
            &[],
        )
        .unwrap();
    assert_eq!(
        disabled.record().allocations().exits,
        added.record().allocations().exits
    );
    assert!(!disabled.configuration().exits()[1].exit().enabled);
    let enabled = disabled
        .record()
        .prepare(
            ExitChange::Enable {
                exit_id: ids[1].into(),
            },
            reader,
            &[],
        )
        .unwrap();
    assert!(enabled.configuration().exits()[1].exit().enabled);
    let removed = enabled
        .record()
        .prepare(
            ExitChange::Remove {
                exit_id: ids[1].into(),
            },
            reader,
            &[],
        )
        .unwrap();
    assert_eq!(removed.record().allocations().exits, vec![original]);
    assert_eq!(
        removed.configuration().exits()[0].hostname(),
        "mullvad-debdev-exit-de-fra-wg-404"
    );
    assert_eq!(removed.renames().len(), 1);
}

#[test]
fn changes_refuse_duplicate_key_state_identity_resource_and_subnet_before_writes() {
    let cfg = configuration(1);
    let first = cfg.exits[0].clone();
    let initial = PreparedFleet::initial(cfg, profile, &[]).unwrap();
    let baseline = initial.record().encode().unwrap();
    let mut second = configuration(2).exits.remove(1);
    second.mode = first.mode.clone();
    assert_eq!(
        initial
            .record()
            .prepare(
                ExitChange::Add {
                    exit: second.clone()
                },
                profile,
                &[]
            )
            .err()
            .unwrap()
            .reason(),
        Reason::DuplicatePrivateKey
    );
    second = configuration(2).exits.remove(1);
    second.state_dir = first.state_dir.join("nested");
    assert_eq!(
        initial
            .record()
            .prepare(ExitChange::Add { exit: second }, profile, &[])
            .err()
            .unwrap()
            .reason(),
        Reason::StateConflict
    );
    assert_eq!(
        initial
            .record()
            .prepare(ExitChange::Add { exit: first }, profile, &[])
            .err()
            .unwrap()
            .reason(),
        Reason::DuplicateId
    );
    let a = &initial.record().allocations().exits[0];
    for claim in [
        ResourceClaim::Namespace(a.data_namespace.clone()),
        ResourceClaim::Interface(a.host_interface.clone()),
        ResourceClaim::NftTable(a.nft_table.clone()),
        ResourceClaim::Subnet(a.transport_subnet.clone()),
    ] {
        assert_eq!(
            initial
                .record()
                .prepare(
                    ExitChange::Disable {
                        exit_id: a.exit_id.clone()
                    },
                    profile,
                    &[claim]
                )
                .err()
                .unwrap()
                .reason(),
            Reason::AllocationConflict
        );
    }
    assert_eq!(initial.record().encode().unwrap(), baseline);
}

#[test]
fn strict_transactions_reject_direct_unknown_duplicate_fields_missing_exit_and_last_removal() {
    for bytes in [
        br#"{"operation":"disable","exit_id":"a","fallback":true}"#.as_slice(),
        br#"{"operation":"disable","exit_id":"a","exit_id":"b"}"#,
        br#"{"operation":"reset","exit_id":"a"}"#,
    ] {
        assert!(ExitChange::parse(bytes).is_err());
    }
    let initial = PreparedFleet::initial(configuration(1), profile, &[]).unwrap();
    let id = initial.configuration().exits()[0].exit().id.clone();
    assert!(
        initial
            .record()
            .prepare(ExitChange::Remove { exit_id: id }, profile, &[])
            .is_err()
    );
    assert!(
        initial
            .record()
            .prepare(
                ExitChange::Enable {
                    exit_id: "absent".into()
                },
                profile,
                &[]
            )
            .is_err()
    );
    let mut direct = configuration(1);
    direct.exits[0].mode = Mode::Direct {};
    assert!(PreparedFleet::initial(direct, profile, &[]).is_err());
}

#[test]
fn explicit_server_pin_changes_hostname_but_preserves_state_and_allocations() {
    let initial = PreparedFleet::initial(configuration(1), profile, &[]).unwrap();
    let id = initial.record().configuration().exits[0].id.clone();
    let reader = |_: &std::path::Path, server: &str| {
        let bytes = include_str!("../../../examples/v2/profiles/profile-1.wg.example")
            .replace("de-fra-wg-404", server);
        vprouter_core::profile::Profile::parse(bytes.as_bytes(), server, None)
    };
    let json = serde_json::to_vec(&serde_json::json!({"operation":"pin_server","exit_id":id,"profile":"/synthetic/profile-1.wg.example","expected_server":"de-fra-wg-003"})).unwrap();
    let next = initial
        .record()
        .prepare(ExitChange::parse(&json).unwrap(), reader, &[])
        .unwrap();
    assert_eq!(
        next.record().allocations().exits,
        initial.record().allocations().exits
    );
    assert_eq!(
        next.configuration().exits()[0].hostname(),
        "mullvad-debdev-exit-de-fra-wg-003"
    );
    assert_eq!(next.renames().len(), 1);
    assert!(
        initial
            .record()
            .prepare(ExitChange::parse(&json).unwrap(), profile, &[])
            .is_err()
    ); // Old server hint refuses.
}
#[test]
fn decoded_records_refuse_tampering_and_client_node_reuse_and_overlong_duplicate_names() {
    use vprouter_core::transaction::FleetRecord;
    let initial = PreparedFleet::initial(configuration(1), profile, &[]).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&initial.record().encode().unwrap()).unwrap();
    value["allocations"]["exits"][0]["host_interface"] = "foreign".into();
    assert!(FleetRecord::decode(&serde_json::to_vec(&value).unwrap(), "schema-example").is_err());
    let mut cfg = configuration(2);
    cfg.client_policies = serde_json::from_value(serde_json::json!([
        {"id":"client-a","exit_id":"mullvad-1","selected_node_id":"same-node","mode":"protected","dependency_adapters":[]},
        {"id":"client-b","exit_id":"mullvad-2","selected_node_id":"same-node","mode":"protected","dependency_adapters":[]}
    ])).unwrap();
    assert!(PreparedFleet::initial(cfg, profile, &[]).is_err());
    let mut cfg = configuration(1);
    cfg.site = "a".repeat(36); // Exact63 unsuffixed, cannot fit stable-id suffix.
    let initial = PreparedFleet::initial(cfg, profile, &[]).unwrap();
    assert_eq!(initial.configuration().exits()[0].hostname().len(), 63);
    let mut second = configuration(2).exits.remove(1);
    second.mode = initial.record().configuration().exits[0].mode.clone();
    assert_eq!(
        initial
            .record()
            .prepare(ExitChange::Add { exit: second }, profile, &[])
            .err()
            .unwrap()
            .reason(),
        Reason::InvalidLabel
    );
}
