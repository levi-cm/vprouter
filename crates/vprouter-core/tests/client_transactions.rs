mod support;
use support::{configuration, profile};
use vprouter_core::transaction::{ExitChange, PreparedFleet};

#[test]
fn client_install_select_intent_reuses_fleet_generation_and_refuses_mode_fallback() {
    let initial = PreparedFleet::initial(configuration(2), profile, &[]).unwrap();
    let install = ExitChange::parse(br#"{"operation":"install_client","policy":{"id":"desktop","exit_id":"mullvad-1","selected_node_id":"node-primary","mode":"protected","dependency_adapters":[]}}"#);
    assert!(
        install.is_ok(),
        "client installation intent must use existing preparation transaction"
    );
    let installed = initial
        .record()
        .prepare(install.unwrap(), profile, &[])
        .unwrap();
    assert_eq!(installed.record().generation(), 2);
    assert_eq!(installed.record().configuration().client_policies.len(), 1);
    let selection = ExitChange::parse(br#"{"operation":"select_client","client_id":"desktop","exit_id":"mullvad-2","node_id":"node-second","mode":"protected"}"#).unwrap();
    let selected = installed.record().prepare(selection, profile, &[]).unwrap();
    assert_eq!(selected.record().generation(), 3);
    assert_eq!(
        selected.record().configuration().client_policies[0].selected_node_id,
        "node-second"
    );
    let invalid = ExitChange::parse(br#"{"operation":"select_client","client_id":"desktop","exit_id":"mullvad-1","node_id":"node-primary","mode":"direct"}"#).unwrap();
    assert!(selected.record().prepare(invalid, profile, &[]).is_err());
}

#[test]
fn client_transactions_preserve_original_on_duplicates_unknown_identity_and_disabled_exit() {
    let mut cfg = configuration(2);
    cfg.exits[1].enabled = false;
    let initial = PreparedFleet::initial(cfg, profile, &[]).unwrap();
    let install=br#"{"operation":"install_client","policy":{"id":"desktop","exit_id":"mullvad-1","selected_node_id":"node-primary","mode":"protected","dependency_adapters":[]}}"#;
    let installed = initial
        .record()
        .prepare(ExitChange::parse(install).unwrap(), profile, &[])
        .unwrap();
    let before = installed.record().encode().unwrap();
    assert!(
        installed
            .record()
            .prepare(ExitChange::parse(install).unwrap(), profile, &[])
            .is_err()
    );
    for bytes in [
        br#"{"operation":"select_client","client_id":"absent","exit_id":"mullvad-1","node_id":"node-1","mode":"protected"}"#.as_slice(),
        br#"{"operation":"select_client","client_id":"desktop","exit_id":"absent","node_id":"node-1","mode":"protected"}"#,
        br#"{"operation":"select_client","client_id":"desktop","exit_id":"mullvad-1","node_id":"","mode":"protected"}"#,
    ] {assert!(installed.record().prepare(ExitChange::parse(bytes).unwrap(),profile,&[]).is_err());}
    for bytes in [br#"{"operation":"select_client","client_id":"desktop","exit_id":"mullvad-1","node_id":"node-1","mode":"protected","fallback":true}"#.as_slice(),br#"{"operation":"select_client","client_id":"desktop","client_id":"other","exit_id":"mullvad-1","node_id":"node-1","mode":"protected"}"#] {assert!(ExitChange::parse(bytes).is_err());}
    assert_eq!(installed.record().encode().unwrap(), before);
    // Disabled desired references can persist; configured_client_plan/GuardPlan refuse
    // usable planning until the exact selected exit is explicitly enabled.
}
