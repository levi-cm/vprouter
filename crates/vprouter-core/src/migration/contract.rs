//! Public offline assertions, never native verification receipts.
use super::*;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    IndependentQuarantine {},
    Drain { adapter: String },
    PreStartStop { adapter: String },
    StopService {},
    PostStopStop { adapter: String },
    AllIdentityUsersStopped {},
    StoppedStateRetained {},
    RestoreSameIdentity {},
    RenameExisting { hostname: String },
    StartService {},
    Rebind { adapter: String },
    PostStartStart { adapter: String },
    HealthCheck { adapter: String },
    ModeIsolationClients {},
    CompatibleReleaseAndState {},
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub exit_id: String,
    pub service: String,
    pub container: String,
    pub uplink: String,
    pub node_id: String,
    pub state_path: String,
    pub profile_path: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Obligation {
    pub scope: Scope,
    pub plan: String,
    pub ordinal: u32,
    pub action: Action,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    Quarantine {
        enforcer: String,
        old_supervisor: String,
    },
    Stopped {
        identity_users: Vec<String>,
    },
    Retained {
        opaque: BTreeMap<String, Pin>,
        state_format: u32,
        identity: Identity,
        release_sha256: String,
    },
    Identity {
        identity: Identity,
    },
    Renamed {
        identity: Identity,
        hostname: String,
    },
    Adapter {
        adapter: String,
        node_id: String,
    },
    FixtureOnly {},
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub obligation: Obligation,
    pub observation: Observation,
}
pub trait FixtureDriver {
    fn perform(&mut self, obligation: &Obligation) -> Result<Receipt>;
}
/// Pure wrapper data, not installed and not executable by this module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shim {
    pub legacy_argv: Vec<String>,
    pub rust_argv: Vec<String>,
    pub stdout: String,
    pub exit_code: u8,
}
pub fn wrappers(executable: &str, primary: &str) -> Result<Vec<Shim>> {
    path(executable)?;
    legacy_label(primary)?;
    let definitions=[
        (vec!["router-runtime","--status"],"status","".to_string(),1),
        (vec!["router-runtime","--probe"],"probe",serde_json::json!({"exit_id":"primary","name":primary,"public_exit":"not_tested","relay":"not_tested","tunnel_healthy":"not_tested","dns_guard":"not_tested","ipv6_guard":"not_tested"}).to_string(),1),
        (vec!["host","status"],"status",serde_json::json!({"exit_id":"primary","name":primary,"state":"not_tested","heartbeat":"not_tested"}).to_string(),1),
        (vec!["host","validate"],"validate",serde_json::json!({"exit_id":"primary","name":primary,"validation":"not_tested"}).to_string(),2),
    ];
    Ok(definitions
        .into_iter()
        .map(|(legacy, command, stdout, exit_code)| Shim {
            legacy_argv: legacy.into_iter().map(String::from).collect(),
            rust_argv: vec![
                executable.into(),
                command.into(),
                "--config".into(),
                "/synthetic/current/config.json".into(),
            ],
            stdout,
            exit_code,
        })
        .collect())
}

#[derive(Clone)]
pub(super) enum Operation {
    Observe(Box<Obligation>),
    Stage,
    Exchange,
}
impl Plan {
    /// Invalid values constructed through raw Serde decoding emit no obligations.
    pub fn obligations(&self, direction: Direction) -> Vec<Obligation> {
        if self.validate().is_err() {
            return Vec::new();
        }
        self.operations(direction)
            .into_iter()
            .filter_map(|o| {
                if let Operation::Observe(o) = o {
                    Some(*o)
                } else {
                    None
                }
            })
            .collect()
    }
    pub(super) fn operations(&self, direction: Direction) -> Vec<Operation> {
        let mut result = Vec::new();
        let mut ordinal = 0;
        let legacy = self.inspection.validate().expect("validated private plan");
        let inventory = &self.inspection.inventory;
        let scope = Scope {
            exit_id: "primary".into(),
            service: inventory.service.clone(),
            container: inventory.container.clone(),
            uplink: inventory.uplink.clone(),
            node_id: inventory.identity.node_id.clone(),
            state_path: legacy.state_dir,
            profile_path: legacy.profile,
        };
        let mut add = |action| {
            result.push(Operation::Observe(Box::new(Obligation {
                scope: scope.clone(),
                plan: self.fingerprint.clone(),
                ordinal,
                action,
            })));
            ordinal += 1;
        };
        add(Action::IndependentQuarantine {});
        for d in self.adapters() {
            add(Action::Drain { adapter: d.clone() });
            add(Action::PreStartStop { adapter: d });
        }
        add(Action::StopService {});
        for d in self.adapters() {
            add(Action::PostStopStop { adapter: d });
        }
        add(Action::AllIdentityUsersStopped {});
        add(Action::StoppedStateRetained {});
        if direction == Direction::Reverse {
            add(Action::CompatibleReleaseAndState {});
        }
        add(Action::RestoreSameIdentity {});
        let hostname = if direction == Direction::Reverse {
            self.inspection
                .validate()
                .expect("validated private plan")
                .tailscale_hostname
                .expect("validated hostname")
        } else {
            self.configuration
                .clone()
                .validate_structure()
                .expect("validated private plan")
                .hostnames_by_id()["primary"]
                .clone()
        };
        add(Action::RenameExisting { hostname });
        add(Action::ModeIsolationClients {});
        add(Action::StartService {});
        for d in self.adapters() {
            add(Action::Rebind { adapter: d.clone() });
            add(Action::PostStartStart { adapter: d.clone() });
            add(Action::HealthCheck { adapter: d });
        }
        // Stage before drains, exchange only after stopped-state/compatibility.
        if direction == Direction::Forward {
            result.insert(1, Operation::Stage);
        }
        let exchange_before = result.iter().position(|o| matches!(o, Operation::Observe(o) if matches!(o.action,Action::RestoreSameIdentity{}))).expect("fixed operation list");
        result.insert(exchange_before, Operation::Exchange);
        result
    }
    fn adapters(&self) -> Vec<String> {
        let mut ids = self
            .configuration
            .dependency_adapters
            .iter()
            .map(|d| d.id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }
    pub(super) fn accepts(&self, obligation: &Obligation, receipt: &Receipt) -> bool {
        if obligation != &receipt.obligation {
            return false;
        }
        match (&obligation.action, &receipt.observation) {
            (
                Action::IndependentQuarantine {},
                Observation::Quarantine {
                    enforcer,
                    old_supervisor,
                },
            ) => {
                name(enforcer).is_ok()
                    && enforcer != old_supervisor
                    && old_supervisor == &self.inspection.inventory.service
            }
            (Action::AllIdentityUsersStopped {}, Observation::Stopped { identity_users }) => {
                identity_users.is_empty()
            }
            (
                Action::StoppedStateRetained {} | Action::CompatibleReleaseAndState {},
                Observation::Retained {
                    opaque,
                    state_format,
                    identity,
                    release_sha256,
                },
            ) => {
                opaque == &self.inspection.opaque
                    && *state_format == self.inspection.inventory.provenance.state_format
                    && identity == self.identity()
                    && self
                        .inspection
                        .bundle
                        .fingerprint()
                        .is_ok_and(|h| &h == release_sha256)
            }
            (Action::RestoreSameIdentity {}, Observation::Identity { identity }) => {
                identity == self.identity()
            }
            (
                Action::RenameExisting { hostname },
                Observation::Renamed {
                    identity,
                    hostname: observed,
                },
            ) => identity == self.identity() && observed == hostname,
            (
                Action::Drain { adapter }
                | Action::PreStartStop { adapter }
                | Action::PostStopStop { adapter }
                | Action::Rebind { adapter }
                | Action::PostStartStart { adapter }
                | Action::HealthCheck { adapter },
                Observation::Adapter {
                    adapter: observed,
                    node_id,
                },
            ) => adapter == observed && node_id == &self.identity().node_id,
            (
                Action::StopService {} | Action::StartService {} | Action::ModeIsolationClients {},
                Observation::FixtureOnly {},
            ) => true,
            _ => false,
        }
    }
}
