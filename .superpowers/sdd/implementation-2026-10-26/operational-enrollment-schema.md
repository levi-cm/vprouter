# Operational enrollment declaration: v1 (current source, not runtime acceptance)

Root-only controller input at `<LaunchSpec.exit.state_dir>/enrollment.json`.
All ancestors root-owned/non-writable, file root-owned, single-link, no symlinks,
private mode0600 (storage::SecretFile), <=65536 bytes. Re-read exact byte digest
on each Handoff verification. No keys, auth URLs or state-file bodies belong here.
The constructor has no in-memory or caller-boolean authorization alternative.

```json
{
  "version": 1,
  "container_id": "<exact64hex LaunchSpec.container_id>",
  "allocation_sha256": "<SHA256 serde_json::to_vec(LaunchSpec.allocation)>",
  "manifest_sha256": "<ReviewedBundle::current().digest() from frozen4-role manifest>",
  "enrollment": {
    "version": 1,
    "binding": {
      "deployment_id": "<exact allocation>",
      "exit_id": "<exact selected exit>",
      "mode": "mullvad",
      "generation": 1,
      "display_name": "<validated config-derived hostname>",
      "expected_server": "<selected imported profile server>",
      "node_id": "<preserved approved stable node ID>",
      "config_fingerprint": "<vprouter_linux::status::config_fingerprint>",
      "boot_id": "<current VM boot UUID>"
    },
    "ips": ["<exact preserved100.x IPv4>", "<exact preserved fd7a:115c:a1e0 IPv6>"],
    "peers": [
      {"node_id": "<exact declared peer stable ID>", "ips": ["<exact100.x IPv4>", "<exact fd7a:115c:a1e0 IPv6>"], "expired": false, "in_network_map": true}
    ]
  }
}
```

Optional IPv6 identities remain logical Tailscale identity data; native operational
TUN/routes stay IPv4-only with IPv6 disabled and forwarding blocked. Each self/peer
has exactly one CGNAT IPv4 and at most one Tailscale IPv6. No duplicate node ID or
address anywhere. Declare the complete exact peer set, including offline peers
whose routes remain in the network map. Runtime must independently GET full
LocalAPI status and match self+peer IDs/IPs before preference mutation and health.
The complete identity set includes expired peers. Both declared `expired` and
`in_network_map` predicates must independently match live LocalAPI fields (live
Expired:null means false; missing/malformed fields refuse). Native table52 peer
routes are required only for declared !expired && in_network_map peers. Online
never determines eligibility: offline unexpired map peers keep their routes.
The approved fixture currently has48 identities,4expired =>44peer routes+fixedDNS;
root must reverify these public predicates before authorizing a new lifecycle.
A current live daemon cannot mint this declaration. Original approved metadata
is a controller reference, not automatically a current authorization file.

Allocation hash uses compact UTF8 JSON, no newline. Record fields in order:
`schema_version,deployment_id,generation,exits`. Each exit fields in order:
`exit_id,mode,state_dir,data_namespace,transport_namespace,nft_table,host_interface,
data_interface,wireguard_interface,transport_subnet`. Preserve exit array order.
The native serde serializer remains authoritative; raw pretty-printed file hashing
is wrong. Binding must be `status::expected_binding` of the exact validated config,
selected exit, allocation generation and current boot, not derived from a cache.

The protected bootstrap includes an explicit execution_policy string:
`operational-monitor-ipv4-tcp-udp-unix-zero-caps-v1`; it must agree with this enrolled
binding. The pre-release role is OperationalMonitor with its own exact seccomp
profile and same pinned worker_monitor executable. Starting and observer profiles
remain separate and cannot authorize operational networking.

No staged runtime invocation is enabled yet. Root may prepare/review these public
inputs but must not move the approved identity or launch this path before the
external supervisor/reconciliation gates and exact artifact review are complete.
