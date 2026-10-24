use std::process::Command;
fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vprouter"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn invalid_arguments_are_json_and_never_echo_input() {
    for args in [
        vec!["--FAKE_PRIVATE_KEY=DO_NOT_PRINT_SECRET"],
        vec!["migrate", "apply", "DO_NOT_PRINT_SECRET"],
        vec!["validate"],
        vec!["exit", "add"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["reason"], "invalid_arguments");
        assert!(!text.contains("DO_NOT_PRINT_SECRET"));
    }
}
#[test]
fn untrusted_config_path_errors_never_echo_secrets_and_create_no_paths() {
    let path = std::env::temp_dir().join(format!("DO_NOT_PRINT_SECRET-{}", std::process::id()));
    std::fs::write(&path, b"{\"PrivateKey\":\"DO_NOT_PRINT_SECRET\" INVALID").unwrap();
    let output = run(&["validate", "--config", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    let value = serde_json::from_str::<serde_json::Value>(&text).unwrap();
    assert_eq!(value["reason"], "unsafe_path");
    assert!(!text.contains("DO_NOT_PRINT_SECRET"));
    assert!(!path.with_extension("lock").exists());
    std::fs::remove_file(path).unwrap();
}
#[test]
fn malformed_config_content_uses_production_error_mapping_and_redacts_secrets() {
    let input = br#"{"PrivateKey":"DO_NOT_PRINT_SECRET" INVALID"#;
    let error = match vprouter_linux::parse_configuration(input) {
        Err(error) => error,
        Ok(_) => panic!("malformed configuration unexpectedly parsed"),
    };
    assert_eq!(error, vprouter_linux::Error::InvalidConfiguration);
    let output = vprouter_linux::failure(error);
    assert_eq!(output["reason"], "invalid_configuration");
    let text = serde_json::to_string(&output).unwrap();
    assert!(!text.contains("DO_NOT_PRINT_SECRET"));
    assert!(!text.contains("PrivateKey"));
}
#[test]
fn help_lists_only_implemented_operations() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("validate"));
    assert!(text.contains("diagnose"));
    assert!(!text.contains("exit add"));
    let output = run(&["migrate", "--help"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("inspect"));
    assert!(text.contains("plan"));
    assert!(!text.contains("rollback"));
    assert!(!text.contains("apply "));
}
