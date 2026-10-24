use vprouter_core::{
    allocation::{AllocationRecord, ResourceClaim},
    config::Configuration,
    reason::Reason,
};
fn cfg(ids: &[(&str, &str)]) -> vprouter_core::config::ValidatedConfiguration {
    let exits:Vec<_>=ids.iter().map(|(id,_)|serde_json::json!({"id":id,"enabled":true,"state_dir":format!("/state/{id}"),"mode":{"kind":"direct"}})).collect();
    Configuration::parse(serde_json::to_string(&serde_json::json!({"schema_version":2,"deployment_id":"fleet","site":ids[0].1,"gateway_image":format!("sha256:{}","a".repeat(64)),"exits":exits,"dependency_adapters":[],"client_policies":[]})).unwrap().as_bytes()).unwrap().validate().unwrap()
}
#[test]
fn allocation_stays_with_stable_id_after_display_or_order_change() {
    let a =
        AllocationRecord::from_configuration(&cfg(&[("alpha", "x"), ("beta", "x")]), 1).unwrap();
    let b =
        AllocationRecord::from_configuration(&cfg(&[("beta", "y"), ("alpha", "y")]), 2).unwrap();
    assert_eq!(a.exits[0], b.exits[1]);
    assert_ne!(a.exits[0].transport_subnet, b.exits[0].transport_subnet);
    assert!(
        a.exits
            .iter()
            .all(|e| e.host_interface.len() <= 15 && e.data_interface.len() <= 15)
    );
}
#[test]
fn foreign_claims_and_tampered_records_are_rejected() {
    let a = AllocationRecord::from_configuration(&cfg(&[("alpha", "x")]), 1).unwrap();
    assert_eq!(
        a.validate("different", &[]).unwrap_err().reason(),
        Reason::ForeignAllocation
    );
    assert_eq!(
        a.validate(
            "fleet",
            &[ResourceClaim::Interface(a.exits[0].host_interface.clone())]
        )
        .unwrap_err()
        .reason(),
        Reason::AllocationConflict
    );
    assert_eq!(
        a.validate(
            "fleet",
            &[ResourceClaim::Subnet(a.exits[0].transport_subnet.clone())]
        )
        .unwrap_err()
        .reason(),
        Reason::AllocationConflict
    );
    let mut b = a.clone();
    b.exits.push(b.exits[0].clone());
    assert!(b.validate("fleet", &[]).is_err());
    let mut b = a.clone();
    b.exits[0].data_namespace = "foreign".into();
    assert!(b.validate("fleet", &[]).is_err());
    let json = serde_json::to_string(&a)
        .unwrap()
        .replace("\"schema_version\":2", "\"schema_version\":99");
    assert!(AllocationRecord::parse(json.as_bytes(), "fleet", &[]).is_err());
}

#[test]
fn mode_or_state_changes_need_explicit_reconfiguration() {
    let c = cfg(&[("alpha", "x")]);
    let a = AllocationRecord::from_configuration(&c, 1).unwrap();
    assert!(
        a.matches_configuration(&cfg(&[("alpha", "renamed")]))
            .is_ok()
    );
    let mut raw = c.configuration().clone();
    raw.exits[0].state_dir = "/state/changed".into();
    assert!(a.matches_configuration(&raw.validate().unwrap()).is_err());
    let mut changed = a.clone();
    changed.exits[0].mode = vprouter_core::config::ExitMode::Mullvad;
    assert!(changed.validate("fleet", &[]).is_err());
    assert!(
        a.validate("fleet", &[ResourceClaim::Subnet("0.0.0.0/0".into())])
            .is_err()
    );
}
#[test]
fn deterministic_transport_collision_fails_closed_without_reassignment() {
    // Independently found collision in the documented finite transport pool.
    let c = cfg(&[("exit1198", "x"), ("exit1284", "x")]);
    assert_eq!(
        AllocationRecord::from_configuration(&c, 1)
            .err()
            .unwrap()
            .reason(),
        Reason::AllocationConflict
    );
}
