# Security policy

These policies are authorization controls, so a bypass is a security issue even if
nothing crashes.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` | Yes |
| `v0.1.0-rc.4` (source prerelease) | Yes |
| `v0.1.0-rc.3` (source prerelease) | No. Superseded by `v0.1.0-rc.4`. |
| `v0.1.0-rc.2` (source prerelease) | No. Superseded by `v0.1.0-rc.4`. |
| `v0.1.0-rc.1` (source prerelease) | No. Superseded by `v0.1.0-rc.4`. |
| Anything earlier | No. It was never released. |

## Reporting a vulnerability

Report privately through GitHub:
**[Security → Report a vulnerability](https://github.com/msaleme/agent-governance-policies/security/advisories/new)**.

Don't open a public issue, discussion or pull request for a suspected
vulnerability.

Please include:

- which policy and version or commit, plus the Flex/Omni Gateway and PDK versions;
- the configuration involved, with every secret, key and identifier replaced by a
  placeholder;
- a minimal reproduction using synthetic data, such as the JSON-RPC request and the
  observed and expected results;
- the impact, for example an approval bypass, a budget bypass, an identity confusion,
  or a fail-open on error.

**Never** include real credentials, client secrets, digest keys, registration
material or customer data in a report.

## What to expect

This is a maintainer-run project with no formal SLA. It aims to:

- acknowledge a report within 5 business days;
- confirm or rule out the issue and share a plan;
- fix it on `main`, credit you in the advisory if you want credit, and publish a
  GitHub security advisory once a fix is available.

## In scope

- **Approval binding:** P1, P2, P4, P5 or P6 accept an executed call that doesn't
  match its approval record.
- **Aggregate budget:** an aggregate-risk budget is exceeded within a single
  gateway worker.
- **Identity:** a budget scope is minted or borrowed through a caller-controlled
  value while `identitySource: authentication` is set.
- **Fail-open:** any path that forwards when it should fail closed.
- **Leaks:** a secret, digest key or raw identity leaks into headers, logs or error
  bodies, against the configured `scopeDisclosure`.

## Out of scope

The limits below are documented, so they aren't vulnerabilities. Reports that
extend them are still welcome as issues:

- **P6 replicas:** single use on gateway `local()` storage is per replica, and a
  restart resets it.
- **Per-replica budget:** the aggregate budget is per gateway replica (per worker
  with the opt-in `ledgerBackend: worker`), so `R` replicas admit up to
  `R × aggregateBudget`, and a gateway restart resets it.
- **HMAC attestation:** P5 HMAC gives separation of duties, not non-repudiation.
- **Uninspected inputs:** traffic the policies don't inspect, such as URL paths,
  query strings, arbitrary headers and non-MCP asset types.

See *Scope and known limits* in the [README](README.md#scope-and-known-limits).
