# Agent Governance Policies

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Runtime governance policies for AI agent and Model Context Protocol (MCP)
traffic, built with Rust and WebAssembly for MuleSoft Flex/Omni Gateway.**

Where the [Agent Decoy Policies](https://github.com/msaleme/agent-decoy-policies)
family adds *deception* to agent traffic, this family adds *authorization
integrity*: it proves, at the gateway, that an executed action still matches the
mandate it was approved under, and that individually authorized actions do not
compose past a shared exposure budget across sessions. Both policies are
enforcement boundaries for prior published research corpora — the corpus defines
what a correct check means; the policy is the runtime that performs it.

This repository includes policy source, configuration schemas, vendored
conformance fixtures, and automated checks. It does not publish or deploy a
policy; deployment is gateway- and environment-specific.

## Choose a policy

| Policy | Customer problem it answers | Available behavior |
| --- | --- | --- |
| [Approval-to-Execution Binding](approval-execution-binding/README.md) | "The agent got approval for one action and executed a different one." | MCP `tools/call` only (other methods pass through); monitor or block; verify five ABV predicates (action, canonical arguments, freshness, separate mcp-v1 attester, opt-in single-use) against the approval record; deny with a JSON-RPC `-32008` error or empty `403` |
| [Cross-Session Aggregate-Risk Gate](aggregate-risk-gate/README.md) | "Every call passed its per-session cap, but the totals blew past our exposure budget." | Monitor or block; reserve-then-authorize each call against a shared aggregate budget; deny the composing call |

Each policy README defines its configuration, admission rules, protocol behavior,
framework mapping, and honesty boundaries. These are **independent** WebAssembly
filters: they do not share proxy-WASM state and must not use headers as
cross-policy control state. See the [composition notes](COMPOSITION.md) before
combining them or chaining them with other gateway policies.

A policy decision is an authorization control, not proof of intent or of a
completed compliance obligation. Its meaning depends on local identity, the
approval/exposure signals the gateway already carries, and operational review.

## Quick start

Each policy is an independent Rust project. Native tests and WebAssembly
compilation use the committed generated configuration and require no Anypoint
credentials.

```bash
git clone https://github.com/msaleme/agent-governance-policies.git
cd agent-governance-policies

rustup toolchain install 1.89.0 --profile minimal \
  --component rustfmt --component clippy --target wasm32-wasip1

cd approval-execution-binding          # or aggregate-risk-gate
cargo +1.89.0 test --lib --locked
cargo +1.89.0 build --release --target wasm32-wasip1 --locked
```

Use the same commands in either policy directory. Dependencies require network
access on first use; add `--offline` after they are cached. For schema
regeneration and Anypoint asset tooling, follow the selected policy's Makefile
instructions and replace `REPLACE_WITH_YOUR_ANYPOINT_ORG_ID` in its `Cargo.toml`
before organization-specific asset generation or Exchange publication.

## Validation

The [CI workflow](.github/workflows/verify.yml) runs, for each policy: Rust
library tests, `rustfmt --check`, strict Clippy (`-D warnings`), and
integration-test compilation, all against the committed lockfile and generated
assets. It supplies no gateway identity and runs no authenticated Flex behavior
suites. Local verification per policy:

```bash
cargo +1.89.0 fmt --check
cargo +1.89.0 clippy --lib --locked --offline -- -D warnings
cargo +1.89.0 test --lib --locked --offline
cargo +1.89.0 test --tests --no-run --locked --offline
```

Keep any local Flex registration and other identity material outside version
control. Delete each disposable remote registration before removing its local
fixture.

## Supported scope and known limits

- **Enforcement, not attestation.** Approval-binding checks an approval *record*;
  a record checked only by the party it constrains proves nothing without the
  separate-attester predicate. Its P5 attestation is symmetric-HMAC over a
  versioned, domain-separated `mcp-v1` payload — separation-of-duties, not
  non-repudiation. The executor identity P5 checks against is read from verified
  authentication data, not a caller-asserted header. P6 single-use is enforced
  atomically via gateway data storage (`local()`, per-replica; see the policy
  README's honesty boundaries for the cross-replica/restart limits).
- **Stage A ledger.** The aggregate-risk gate ships a real, atomic, in-process
  reserve-then-authorize ledger, correct under genuine multi-thread contention.
  It is **not** distributed: each gateway worker holds its own independent ledger,
  the `window` field is accepted but not time-enforced, `ledgerEndpoint` is a
  reserved and unimplemented Stage B field, and there is no cryptographic
  non-repudiation of decisions. See the policy README's honesty boundaries.
- **Bounded JSON-RPC.** Inspection targets admitted JSON-RPC envelopes and their
  bodies, not URL paths, query strings, or arbitrary headers. Header values are
  not trusted provenance.
- **Local tests only.** Native tests do not establish general MCP
  interoperability or production effectiveness.

## Documentation map

| Area | Start here |
| --- | --- |
| Policy configuration and behavior | The two policy READMEs linked above |
| Combining policies | [Composition notes](COMPOSITION.md) |
| Attribution, corpora, and license scope | [Attribution](ATTRIBUTION.md) |
| Versions | [Changelog](CHANGELOG.md) |
| Automated verification | [CI workflow](.github/workflows/verify.yml) |

## Contributing

For a bug report, include the policy, mode, gateway/PDK versions, a synthetic
reproduction, and expected versus observed behavior. Exclude credentials and real
sensitive payloads. For a behavior change, add a focused regression and run the
affected policy's library tests, formatting, Clippy, and release build. Keep
source, configuration schemas, generated assets, and documentation consistent.

## License

Project contributions: [MIT](LICENSE). Upstream templates, reference corpora, and
dependencies retain their own notices and terms; see
[attribution and license scope](ATTRIBUTION.md).
