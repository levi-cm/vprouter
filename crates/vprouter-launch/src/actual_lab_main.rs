#![deny(unsafe_code)]
#[allow(dead_code, unused_imports)]
#[path = "lib.rs"]
mod admission;
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.as_slice() == ["--host-route-projection"] {
        match admission::actual_lab::host_route_projection() {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("host_route_projection: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.as_slice() == ["--normal-fixture-descriptor"] {
        println!("{}", admission::transport_lab::normal_fixture_descriptor());
        return;
    }
    if args.as_slice() == ["--inspection-filter-selftest"] {
        match admission::actual_lab::inspection_filter_selftest() {
            Ok(()) => println!(
                "inspection exact filter idle/request/idle/request with native deny checks PASS"
            ),
            Err(error) => {
                eprintln!("inspection_filter_selftest: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.as_slice() == ["--secret-preparation-descriptor"] {
        match admission::transport_lab::secret_preparation_descriptor() {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("secret_preparation_descriptor: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.as_slice() == ["--secret-attachment-descriptor"] {
        match admission::transport_lab::secret_attachment_descriptor() {
            Ok(value) => println!("{value}"),
            Err(error) => {
                eprintln!("secret_attachment_descriptor: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    if let Some(fault) = [
        "--ignored-secret-attachment",
        "--ignored-secret-attachment-placeholder-failure",
        "--ignored-secret-attachment-publication-failure",
    ]
    .iter()
    .position(|flag| args.as_slice() == [*flag])
    {
        if let Err(error) = admission::transport_lab::run_secret_attachment(fault as u8) {
            eprintln!("secret_attachment_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Some(fault) = [
        "--ignored-secret-provision",
        "--ignored-secret-provision-postbirth-failure",
        "--ignored-secret-provision-result-failure",
        "--ignored-secret-provision-registration-failure",
    ]
    .iter()
    .position(|flag| args.as_slice() == [*flag])
    {
        if let Err(error) = admission::transport_lab::run_secret_provision(fault as u8) {
            eprintln!("secret_provision_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Some(fault) = [
        "--ignored-secret-movement",
        "--ignored-secret-movement-postbirth-failure",
        "--ignored-secret-movement-result-failure",
        "--ignored-secret-movement-registration-failure",
    ]
    .iter()
    .position(|flag| args.as_slice() == [*flag])
    {
        if let Err(error) = admission::transport_lab::run_secret_movement(fault as u8) {
            eprintln!("secret_movement_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Some(fault) = [
        "--ignored-secret-quarantine",
        "--ignored-secret-quarantine-postbirth-failure",
        "--ignored-secret-quarantine-result-failure",
        "--ignored-secret-quarantine-registration-failure",
    ]
    .iter()
    .position(|flag| args.as_slice() == [*flag])
    {
        if let Err(error) = admission::transport_lab::run_secret_quarantine(fault as u8) {
            eprintln!("secret_quarantine_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Some(fault) = [
        "--ignored-secret-assembly",
        "--ignored-secret-assembly-pretransfer-failure",
        "--ignored-secret-assembly-partial-transfer-failure",
        "--ignored-secret-assembly-duplicate-transfer",
    ]
    .iter()
    .position(|flag| args.as_slice() == [*flag])
    {
        if let Err(error) = admission::transport_lab::run_secret_assembly(fault as u8) {
            eprintln!("secret_assembly_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Some(fault) = [
        "--ignored-secret-producer-binding",
        "--ignored-secret-producer-binding-postbirth-failure",
        "--ignored-secret-producer-binding-result-failure",
        "--ignored-secret-producer-binding-registration-failure",
    ]
    .iter()
    .position(|flag| args.as_slice() == [*flag])
    {
        if let Err(error) = admission::transport_lab::run_secret_producer_binding(fault as u8) {
            eprintln!("secret_producer_binding_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Some(fault) = [
        "--ignored-secret-host-addition",
        "--ignored-secret-host-addition-postbirth-failure",
        "--ignored-secret-host-addition-result-failure",
        "--ignored-secret-host-addition-registration-failure",
    ]
    .iter()
    .position(|flag| args.as_slice() == [*flag])
    {
        if let Err(error) = admission::transport_lab::run_secret_host_addition(fault as u8) {
            eprintln!("secret_host_addition_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Some(fault) = [
        "--ignored-secret-bootstrap",
        "--ignored-secret-bootstrap-postbirth-failure",
        "--ignored-secret-bootstrap-result-failure",
        "--ignored-secret-bootstrap-registration-failure",
        "--ignored-secret-bootstrap-handoff-fence",
        "--ignored-secret-bootstrap-handoff-partial",
        "--ignored-secret-bootstrap-handoff-duplicate",
    ]
    .iter()
    .position(|flag| args.as_slice() == [*flag])
    {
        if let Err(error) = admission::transport_lab::run_secret_bootstrap(fault as u8) {
            eprintln!("secret_bootstrap_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    let secret_fault = [
        "--ignored-secret-preparation",
        "--ignored-secret-preparation-reject",
        "--ignored-secret-preparation-intent-deadline",
        "--ignored-secret-preparation-birth-deadline",
        "--ignored-secret-preparation-result-failure",
        "--ignored-secret-preparation-result-receipt-mismatch",
    ]
    .iter()
    .position(|flag| args.as_slice() == [*flag]);
    if let Some(fault) = secret_fault {
        if let Err(error) = admission::transport_lab::run_secret_preparation(fault as u8) {
            eprintln!("secret_preparation_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--owner-bootstrap-descriptor"] {
        match admission::transport_lab::owner_bootstrap_descriptor() {
            Ok(value) => println!("{value}"),
            Err(_) => std::process::exit(1),
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-retirement"]
        || args.as_slice() == ["--ignored-owner-retirement-queued-failure"]
        || args.as_slice() == ["--ignored-owner-retirement-writer-failure"]
        || args.as_slice() == ["--ignored-owner-retirement-host-span"]
        || args.as_slice() == ["--ignored-owner-retirement-global-stop"]
    {
        let fault = if args.as_slice() == ["--ignored-owner-retirement-queued-failure"] {
            1
        } else if args.as_slice() == ["--ignored-owner-retirement-writer-failure"] {
            2
        } else if args.as_slice() == ["--ignored-owner-retirement-host-span"] {
            3
        } else if args.as_slice() == ["--ignored-owner-retirement-global-stop"] {
            4
        } else {
            0
        };
        if let Err(error) = admission::transport_lab::run_owner_retirement(fault) {
            eprintln!("owner_retirement_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-expiry-drop"]
        || args.as_slice() == ["--ignored-owner-expiry-partial-drop"]
    {
        if let Err(error) = admission::transport_lab::run_owner_expiry_drop(
            args.as_slice() == ["--ignored-owner-expiry-partial-drop"],
        ) {
            eprintln!("owner_expiry_drop_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-retained-drop"] {
        if let Err(error) = admission::transport_lab::run_owner_retained_drop() {
            eprintln!("owner_retained_drop_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-admission-birth-failure"] {
        if let Err(error) = admission::transport_lab::run_owner_admission_birth_failure() {
            eprintln!("owner_admission_birth_failure_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-admission-stop"] {
        if let Err(error) = admission::transport_lab::run_owner_admission_stop() {
            eprintln!("owner_admission_stop_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-inspection-setup"] {
        if let Err(error) = admission::transport_lab::run_owner_inspection_setup() {
            eprintln!("owner_inspection_setup_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-inspection-held"] {
        if let Err(error) = admission::transport_lab::run_owner_inspection_held() {
            eprintln!("owner_inspection_held_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-expiry-placement"] {
        if let Err(error) = admission::transport_lab::run_owner_expiry_placement() {
            eprintln!("owner_expiry_placement_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-host-audit"] {
        if let Err(error) = admission::transport_lab::run_owner_host_audit() {
            eprintln!("owner_host_audit_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-bootstrap"] {
        if let Err(error) = admission::transport_lab::run_owner_bootstrap() {
            eprintln!("owner_bootstrap_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--owner-domains-descriptor"] {
        match admission::transport_lab::owner_domains_descriptor() {
            Ok(value) => println!("{value}"),
            Err(_) => std::process::exit(1),
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-deployment"] {
        if let Err(error) = admission::transport_lab::run_owner_deployment() {
            eprintln!("owner_deployment_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-journal"] {
        if let Err(error) = admission::transport_lab::run_owner_journal() {
            eprintln!("owner_journal_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-domains"] {
        if let Err(error) = admission::transport_lab::run_owner_domains() {
            eprintln!("owner_domains_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-owner-watchdog"] {
        if let Err(error) = admission::transport_lab::run_owner_watchdog() {
            eprintln!("owner_watchdog_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args.as_slice() == ["--ignored-operational-profile"] {
        if let Err(error) = admission::transport_lab::run_operational_profile() {
            eprintln!("operational_profile_lab: {error}");
            std::process::exit(1);
        }
        return;
    }
    let scenario = if args.as_slice() == ["--ignored-owner-process-inspection"] {
        admission::transport_lab::Scenario::Inspection
    } else if args.as_slice() == ["--ignored-terminal"] {
        admission::transport_lab::Scenario::Terminal
    } else if args.as_slice() == ["--ignored-terminal-death"] {
        admission::transport_lab::Scenario::TerminalDeath
    } else if args.as_slice() == ["--ignored"] {
        admission::transport_lab::Scenario::Actual
    } else {
        println!("actual_lab: ignored (exact-hash owned local guest only)");
        return;
    };
    if let Err(error) = admission::transport_lab::run(scenario) {
        eprintln!("actual_lab: {error}");
        std::process::exit(1);
    }
}
