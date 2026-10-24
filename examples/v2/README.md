# Schema examples — not deployable credentials/artifact

`one.json`, `five.json`, and `mixed.json` illustrate one Mullvad exit, five
independent Mullvad exits, and five Mullvad exits plus an explicitly exposed
direct exit. These are schema examples, not deployment authorization.

The `sha256:aaaa...` value is a syntactically valid digest placeholder, not an
available or approved artifact. Replace it with the verified release digest.
The `.wg.example` files contain obviously synthetic repeated-byte private and
public keys, invented addresses and unverified endpoint associations. They are
not deployable credentials. Never install them or use them on a network.
No actual profile or enrollment key was copied into these examples.

Absolute `/var/lib/vprouter/schema-example/...` paths are illustrative. Tests
inject the synthetic profile bytes; tests do not create or read those paths.
Each Mullvad example has a different synthetic private key. Reusing a key for
different servers, different filenames, or disabled exits is rejected.

The direct entry has no profile, server, automatic fallback or protected claim.
When client policies are configured, they must pin the actual stable Tailscale
node ID and explicitly select `protected` or `direct`; display names do not
select identities. Empty adapter/policy arrays do not authorize migration of
unknown external consumers.
