"""Offline, reviewable spec expansion; emits data only, never acceptance evidence.

Run with python3 -B -I tools/acceptance/build_requirements.py. The explicit
phrase mappings are independent of acceptance.py's source-ledger inventory.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIGURATIONS = ['one_mullvad', 'five_mullvad', 'one_direct', 'five_mullvad_one_direct']

# One line per slash item in the spec; whitespace around a line-wrapped slash
# is normalized. Multiple scenarios split conjunctions within a prose item.
FAILURE_ITEMS = [
    [
        ('deleted', 'tunnel_provider.wireguard_deleted'),
        ('down', 'tunnel_provider.wireguard_down'),
        ('stale', 'tunnel_provider.handshake_stale'),
        ('wrong peer', 'tunnel_provider.peer_wrong'),
        ('key', 'tunnel_provider.peer_key_wrong'),
        ('endpoint', 'tunnel_provider.endpoint_wrong'),
        ('provider responses', 'tunnel_provider.transport_loss tunnel_provider.http_transient tunnel_provider.http_permanent tunnel_provider.provider_malformed tunnel_provider.provider_negative tunnel_provider.server_wrong'),
    ], [
        ('route', 'routing.route_drift'),
        ('default', 'routing.ordinary_default_restored'),
        ('endpoint', 'routing.endpoint_route'),
        ('Docker', 'routing.docker_subnet_route routing.docker_gateway_route'),
        ('IPv6', 'routing.ipv6_route'),
        ('interface', 'routing.unexpected_interface'),
        ('source spoof drift', 'routing.spoofed_source'),
    ], [
        ('firewall removal, failed atomic update and foreign ownership', 'firewall.data_policy_removed firewall.host_guard_removed firewall.data_policy_drift firewall.host_guard_drift firewall.atomic_update_failed firewall.foreign_conflict firewall.bridge_identity_changed'),
    ], [
        ('crashes', 'process.worker_crash process.host_guard_crash process.tailscale_crash process.container_kill'),
        ('freezes', 'process.worker_freeze process.host_guard_freeze process.tailscale_freeze'),
        ('OOM', 'process.oom'),
        ('container', 'process.container_restart'),
        ('Docker restart', 'process.docker_restart process.service_restart'),
    ], [
        ('full disk', 'resources.disk_full resources.tmpfs_full resources.runtime_operation_failure'),
        ('API timeout', 'resources.docker_api_unavailable resources.api_delayed resources.health_malformed'),
        ('reboot', 'resources.host_reboot'),
    ], [
        ('revoked identity', 'identity.identity_revoked identity.credential_revoked identity.credential_expired identity.duplicate_identity'),
        ('control', 'identity.control_revoked identity.control_plane_loss'),
        ('approval', 'identity.approval_revoked'),
        ('name', 'identity.name_revoked identity.name_server_mismatch'),
    ], [
        ('one failed exit beside direct', 'isolation.direct_active_during_mullvad_faults isolation.exit_failure_others_active'),
        ('healthy exits', 'isolation.exit_failure_others_active isolation.exit_restart_others_active isolation.shared_endpoint isolation.overlapping_vpn_addresses'),
    ], [
        ('client disappear', 'clients.exit_disappears'),
        ('select', 'clients.selected_node_changes'),
        ('restart', 'clients.tailscale_restarts'),
        ('route', 'clients.routes_reset'),
        ('DNS', 'clients.dns_cache_empty'),
        ('proxy', 'clients.proxy_upstream_failed clients.proxy_settings_absent'),
        ('bypass', 'clients.proxy_settings_bypassed'),
    ], [
        ('migration kills at every boundary', 'migration.inspect migration.stage migration.plan migration.protect migration.drain migration.stop migration.backup migration.activate migration.restore_identity migration.rename migration.verify migration.commit migration.recover'),
    ],
]

# Exact excerpts from migration-preparation, each independently addressable
# operation expanded to before/after for apply, resume and rollback. A future
# producer must sweep every write/file/journal-generation/adapter ordinal too.
MIGRATION_ITEMS = [
    ('Require independent quarantine', 'quarantine'),
    ('Stage and fsync the complete public release/image/checksums/config/allocations.', 'stage_create stage_write stage_verify stage_file_fsync stage_directory_fsync stage_checksums'),
    ('Drain each sorted adapter; pre-start stop; stop the scoped old service; post-stop stop; verify **all** identity users stopped.', 'adapter_drain adapter_pre_start_stop service_stop adapter_post_stop_stop all_users_stopped'),
    ('Require stopped-state retention metadata, exact old release checksum, original state format and same nodeID/IP/approval/server facts.', 'stopped_state_retention old_release_checksum state_format identity_verify'),
    ('Exchange `current` and `staged` with one `renameat2(RENAME_EXCHANGE)`', 'release_exchange release_parent_fsync'),
    ('Restore/verify same public identity/IP/approvals/exact server, then rename that existing node, never recreate it.', 'restore_identity node_rename'),
    ('Require fixture mode/isolation/client check; scoped service start; sorted adapter rebind/post-start start/health check; durably commit the fixture result.', 'client_verify service_start adapter_rebind adapter_post_start adapter_health'),
    ('Write to an exclusively created mode0600 pending file in bounded4096-byte writes; verify the still-named private file; file fsync; publish by atomic rename; fsync parent.', 'journal_pending_create journal_write journal_verify journal_file_fsync journal_rename journal_parent_fsync'),
    ('Existing journals are checksum/content CAS checked before replacement.', 'journal_cas'),
    ('Partial pending writes are removed only on explicit resume/rollback under the same lock', 'pending_validate pending_unlink'),
    ('Known partial public staging is validated as bounded raw byte prefixes of the planned new files before bounded cleanup/recreation.', 'stage_cleanup_validate stage_cleanup_unlink'),
    ('durably requests cleanup', 'cleanup_intent'),
    ('Terminal `offline` is published only when quarantine and **all** cleanup obligations succeed.', 'cleanup_quarantine cleanup_adapter_stop cleanup_service_stop cleanup_all_users_stopped terminal_publish'),
    ('explicit rollback durably establishes reversal.', 'reversal_intent'),
    ('Committed and rolled-back journals replay without writes or lifecycle calls.', 'terminal_replay'),
]


def requirement(identifier, phrase, scenarios, configurations=None):
    return {'id': identifier, 'phrase': phrase,
            'scenario_ids': scenarios.split() if type(scenarios) is str else scenarios,
            'configurations': CONFIGURATIONS if configurations is None else configurations}


def build():
    spec = (ROOT/'docs/rust-v2/IMPLEMENTATION.md').read_text()
    text = spec.split('## Mandatory acceptance\n', 1)[1].split('\n## ', 1)[0].strip()
    normalized = ' '.join(text.split())
    phrases = normalized.split('Failures cover ', 1)[1].split('. Boot capture', 1)[0].split('; ')
    if len(phrases) != len(FAILURE_ITEMS):
        raise ValueError('spec failure list changed; rederive inventory')
    failures = []
    for i, (phrase, items) in enumerate(zip(phrases, FAILURE_ITEMS), 1):
        if [p.strip() for p in phrase.split('/')] != [p for p, _ in items]:
            raise ValueError('spec failure subitems changed; rederive inventory')
        failures.append({'phrase': phrase, 'requirements': [
            requirement(f'F{i:02d}.{j:02d}', p, ids) for j, (p, ids) in enumerate(items, 1)]})
    migration = ' '.join((ROOT/'docs/rust-v2/migration-preparation.md').read_text().split())
    boundaries = []
    for i, (phrase, operations) in enumerate(MIGRATION_ITEMS, 1):
        if phrase not in migration:
            raise ValueError('migration contract changed; rederive inventory')
        boundaries.append({'phrase': phrase, 'requirements': [
            requirement(f'M{i:02d}.{op}', op, [f'migration.{d}.{op}.{e}'
                for d in ('apply', 'resume', 'rollback') for e in ('before', 'after')])
            for op in operations.split()]})
    others = []
    def add(identifier, phrase, scenarios, configurations=None):
        others.append({'phrase': phrase, 'requirements': [
            requirement(identifier, phrase, scenarios, configurations)]})
    for p in ('ipv4', 'dns', 'ipv6', 'tcp', 'udp'):
        add('A01.'+p, 'Real disposable Tailscale clients generating IPv4, DNS, IPv6, TCP, UDP', 'traffic.'+p)
    for p in ('client_wan', 'host_wan', 'transport', 'data'):
        add('A02.'+p, 'capture at client WAN, host WAN, transports and data.', 'coverage.'+p)
    for c in CONFIGURATIONS:
        add('A03.'+c, 'One Mullvad, five Mullvad, direct, and five+direct configurations.', 'capture.positive_controls', [c])
    add('A04', 'Positive capture controls', 'capture.positive_controls')
    for p in ('forbidden_plaintext', 'cross_exit', 'host_as_mullvad'):
        add('A05.'+p, 'zero forbidden plaintext/cross-exit markers; host IP as Mullvad app egress immediately fails.', 'marker.'+p)
    add('A06', 'Boot capture must be operational BEFORE protected traffic.', 'boot.capture_before_traffic')
    for p in ('skip', 'unknown'):
        add('A07.'+p, 'Skips/unknowns are unverified and block claims.', 'status.'+p)
    add('A08', 'No unmanaged/non-Linux client guarantee.', 'scope.unsupported_clients')
    artifacts = normalized.split('Artifacts: ', 1)[1].split('. Do not publish', 1)[0].split(', ')
    artifact_ids = [
        'schema_examples_one schema_examples_five schema_examples_mixed',
        'agent_migration systemd_migration runit_migration', 'validation_guide recovery_guide rollback_guide',
        'compatibility_matrix', 'redacted_reports', 'security_test_map',
        'workload_benchmarks accounted_benchmarks', 'immutable_artifacts', 'sbom provenance', 'unsupported_environments']
    if len(artifacts) != len(artifact_ids):
        raise ValueError('artifact contract changed; rederive inventory')
    for i, (phrase, ids) in enumerate(zip(artifacts, artifact_ids), 1):
        for identifier in ids.split():
            add(f'D{i:02d}.{identifier}', phrase, 'artifact.'+identifier)
    add('A09', 'Do not publish until all gates pass.', 'scope.release_blocked')
    return {'schema_version': 1, 'source': 'docs/rust-v2/IMPLEMENTATION.md#mandatory-acceptance',
            'mandatory_text': text.splitlines(), 'failure_phrases': failures, 'other_phrases': others,
            'migration_source': 'docs/rust-v2/migration-preparation.md', 'migration_phrases': boundaries,
            'migration_ordinal_contract': 'Every before/after ID requires every actual write chunk, journal generation, staged file and sorted adapter ordinal for that direction. No runtime producer exists; IDs are preparation only.'}


if __name__ == '__main__':
    import sys
    if not sys.flags.isolated or not sys.dont_write_bytecode or sys.flags.optimize:
        raise SystemExit('python3 -B -I required')
    (ROOT/'tools/acceptance/mandatory-requirements.json').write_text(json.dumps(build(), indent=2)+'\n')
