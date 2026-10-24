#![forbid(unsafe_code)]
use clap::{Parser, Subcommand, error::ErrorKind};
use serde_json::{Value, json};
use std::{path::PathBuf, process::ExitCode};
use vprouter_linux::{
    Error, Result, capabilities, failure, host, load_configuration, migration, status, storage,
};

#[derive(Parser)]
#[command(
    version,
    about = "Read-only native vprouter preparation; activation is unavailable"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Validate schema, protected profiles and observational host prerequisites.
    Validate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Report observational host checks and cached snapshots.
    Status {
        #[arg(long)]
        config: PathBuf,
    },
    /// Observational alias for status; performs no active network probes.
    Probe {
        #[arg(long)]
        config: PathBuf,
    },
    /// Inspect legacy metadata or produce a non-applicable review plan.
    Migrate {
        #[command(subcommand)]
        command: Migration,
    },
    /// Emit a sanitized support report and unperformed acceptance manifest.
    Diagnose {
        #[arg(long)]
        config: PathBuf,
    },
}
#[derive(Subcommand)]
enum Migration {
    Inspect {
        #[arg(long)]
        legacy_config: PathBuf,
    },
    Plan {
        #[arg(long)]
        legacy_config: PathBuf,
        #[arg(long)]
        site: String,
        #[arg(long)]
        expected_server: String,
        #[arg(long)]
        deployment_id: String,
        /// Create a new root-owned 0600 review artifact; never overwrite.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}
async fn execute(cli: Cli) -> Result<(Value, u8)> {
    match cli.command {
        Command::Validate { config } => {
            let cfg = load_configuration(&config)?;
            let preflight = host::preflight(&cfg).await;
            let failed = preflight
                .checks
                .iter()
                .any(|check| check.state == host::CheckState::Fail);
            Ok((
                json!({"ok":!failed,"reason":if failed {Some("preflight_failed")} else {None},"schema_valid":true,"host_supported":preflight.host_supported,"activation_ready":false,"exit_count":cfg.exits().len(),"preflight":preflight,"capabilities":capabilities()}),
                if failed { 2 } else { 0 },
            ))
        }
        Command::Status { config } | Command::Probe { config } => {
            let cfg = load_configuration(&config)?;
            let preflight = host::preflight(&cfg).await;
            Ok((
                json!({"ok":false,"reason":"guard_runtime_unimplemented","source":"observational_and_cached","actively_verified":false,"schema_valid":true,"host_supported":preflight.host_supported,"activation_ready":false,"preflight":preflight,"exits":status::status(&cfg),"capabilities":capabilities()}),
                2,
            ))
        }
        Command::Diagnose { config } => {
            let cfg = load_configuration(&config)?;
            Ok((
                json!({"ok":false,"reason":"verification_incomplete","activation_ready":false,"capabilities":capabilities(),"preflight":host::preflight(&cfg).await,"acceptance":host::acceptance_manifest()}),
                2,
            ))
        }
        Command::Migrate {
            command: Migration::Inspect { legacy_config },
        } => {
            let (legacy, _) = migration::load_legacy(&legacy_config)?;
            let inspection = migration::inspect(legacy).await;
            let complete = inspection.container_inventory_reason.is_none()
                && inspection.release_inventory_reason.is_none()
                && inspection.profile_identity.metadata.is_some()
                && inspection.state_identity.metadata.is_some()
                && inspection.compose_release.directory.metadata.is_some()
                && inspection
                    .compose_release
                    .files
                    .iter()
                    .all(|file| file.sha256.is_some())
                && inspection.releases.iter().all(|release| {
                    release.directory.metadata.is_some()
                        && release.files.iter().all(|file| file.sha256.is_some())
                })
                && inspection.unit_files.iter().any(|f| f.sha256.is_some());
            let mut result = migration::inspection_json(inspection);
            result["ok"] = json!(complete);
            if !complete {
                result["reason"] = json!("inspection_incomplete");
            }
            Ok((result, if complete { 0 } else { 2 }))
        }
        Command::Migrate {
            command:
                Migration::Plan {
                    legacy_config,
                    site,
                    expected_server,
                    deployment_id,
                    output,
                },
        } => {
            let (legacy, bytes) = migration::load_legacy(&legacy_config)?;
            let inspection = migration::inspect(legacy).await;
            let plan = migration::plan(
                &legacy_config,
                &bytes,
                &inspection,
                &site,
                &expected_server,
                &deployment_id,
            )?;
            if let Some(output) = output {
                let bytes =
                    serde_json::to_vec_pretty(&plan).map_err(|_| Error::InvalidConfiguration)?;
                storage::write_plan(&output, &bytes)?;
            }
            Ok((
                json!({"ok":false,"reason":"plan_not_applicable","activation_ready":false,"plan":plan,"capabilities":capabilities()}),
                2,
            ))
        }
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            // This is explicitly requested static help, never invalid argv text.
            print!("{error}");
            return ExitCode::SUCCESS;
        }
        Err(_) => {
            println!("{}", failure(Error::InvalidArguments));
            return ExitCode::from(2);
        }
    };
    let (value, code) = match execute(cli).await {
        Ok(result) => result,
        Err(error) => (failure(error), 2),
    };
    println!("{value}");
    ExitCode::from(code)
}
