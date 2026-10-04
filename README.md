# Agent Governance Policies

[![Verify policies](https://github.com/msaleme/agent-governance-policies/actions/workflows/verify.yml/badge.svg?branch=main)](https://github.com/msaleme/agent-governance-policies/actions/workflows/verify.yml)
[![Release](https://img.shields.io/github/v/release/msaleme/agent-governance-policies?include_prereleases&sort=semver)](https://github.com/msaleme/agent-governance-policies/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Rust 1.89.0](https://img.shields.io/badge/rust-1.89.0-orange.svg)
![PDK 1.10.0](https://img.shields.io/badge/MuleSoft%20PDK-1.10.0-00A1DF.svg)
![Flex Gateway 1.14.0](https://img.shields.io/badge/Flex%20Gateway-1.14.0%20tested-00A1DF.svg)

**Runtime governance policies for AI agent and Model Context Protocol (MCP)
traffic, built with Rust and WebAssembly for MuleSoft Flex/Omni Gateway.**

AI agents act through tools, and each tool call can be authorized on its own and
still be wrong. These two policies check, at the gateway, two things a per-call
check can't see:

1. **Approval-to-Execution Binding:** is the call the agent is executing the same
   call that was approved?
2. **Cross-Session Aggregate-Risk Gate:** do individually authorized calls, added
   together across sessions, stay within a shared exposure budget?

The [Agent Decoy Policies](https://github.com/msaleme/agent-decoy-policies) family
adds *deception* to agent traffic. This family adds *authorization integrity*. Each
policy is the enforcement point for a separately published research corpus: the
corpus defines what a correct check means, and the policy performs it at runtime
([attribution](ATTRIBUTION.md)).

## Contents

- [Status](#status)
- [The policies](#the-policies)
- [How they fit in a gateway](#how-they-fit-in-a-gateway)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Deploying to a gateway](#deploying-to-a-gateway)
- [Verification](#verification)
- [Scope and known limits](#scope-and-known-limits)
- [Repository layout](#repository-layout)
- [Documentation map](#documentation-map)
- [Contributing, security and citation](#contributing-security-and-citation)
- [License](#license)

## Status

| | |
| --- | --- |
| Repository release | [`v0.1.0-rc.1`](https://github.com/msaleme/agent-governance-policies/releases), a **source prerelease** |
| Policy versions | Both policies are `1.0.0` in their `Cargo.toml`. The repository version is separate from them. |
| Exchange | Both policies have been dev-published to Exchange under disposable ids and deleted again. No ready-for-production Exchange asset is published from this repository. |
| P4A marketplace | Reviewer findings on both policies are resolved and merged. No marketplace acceptance or listing is claimed here. See the [P4A submission pack](P4A-SUBMISSION.md). |
| Open issues | None |

The release ships source only. It includes no compiled WASM, no credentials and no
Exchange deployment.

## The policies

| Policy | The problem it answers | What it does |
| --- | --- | --- |
| [Approval-to-Execution Binding](approval-execution-binding/README.md) | "The agent got approval for one action and executed a different one." | On MCP `tools/call` only (other methods pass through), checks five ABV v0.1 predicates against the approval record: **P1** action, **P2** canonical argument bytes, **P4** valid at execution, **P5** separate attester, and opt-in **P6** single use. Denies with JSON-RPC `-32008` or an empty `403`, in block or monitor mode. |
| [Cross-Session Aggregate-Risk Gate](aggregate-risk-gate/README.md) | "Every call passed its per-session cap, but together they blew past our exposure budget." | On MCP `tools/call` only by default (`governedMethods`; the handshake, pings, notifications and transport requests pass through uncharged), reserves each call's contribution against a shared budget before forwarding it, and refuses the call that would push the total over. The budget is keyed on a verified identity and counted as exact integers, and it uses a fixed accounting window. Reservations whose responses never arrive are reclaimed. Block or monitor mode. |

Each policy README covers that policy's configuration, admission rules, protocol
behavior, framework mapping and honesty boundaries. The two are **independent**
WebAssembly filters. They share no proxy-wasm state and must not pass control
state to each other in headers. Read the [composition notes](COMPOSITION.md)
before you chain them with each other or with other policies.

A policy decision is an authorization control. It is not proof of intent, and it
does not complete a compliance obligation by itself. What a decision means depends
on your identity setup, the approval and exposure signals the gateway carries, and
your operational review.

## How they fit in a gateway

```text
agent ──► Flex/Omni Gateway (MCP API instance) ───────────────────────────► MCP server
             │
             ├─ 1. authentication, e.g. Client ID Enforcement  → verified identity
             ├─ 2. MCP admission: mcp-support, mcp-access-control
             ├─ 3. Approval-to-Execution Binding                → is this the approved call?
             └─ 4. Cross-Session Aggregate-Risk Gate            → does it fit the shared budget?
                   denied → JSON-RPC -32008 (or an empty 403); the upstream is never called
```

Both policies are inbound and inspect the request body, and both declare
`assetTypes: mcp`. Put authentication and the MCP admission policies first, so each
gate keys on an identity the gateway has verified rather than one the caller asserts.
Run approval binding before the aggregate gate, so an altered or unapproved call is
rejected before it consumes any budget.
[COMPOSITION.md](COMPOSITION.md) gives the recommended order and why.

## Requirements

| Tool | Version | Needed for |
| --- | --- | --- |
| Rust | 1.89.0, with `rustfmt`, `clippy` and the `wasm32-wasip1` target (pinned by each `rust-toolchain.toml`) | Building and unit tests |
| Docker | Any recent version | The `#[pdk_test]` integration tests, which start a real Flex Gateway container |
| Anypoint CLI and PDK plugin | PDK 1.10.0, `cargo-anypoint` 1.10.0 | Generating Exchange assets, publishing, running the playground |
| An Anypoint organization | — | Publishing and deploying only. Building and unit tests need no credentials. |

## Quick start

Building and unit testing use the committed generated configuration, so they need
no Anypoint credentials:

```bash
git clone https://github.com/msaleme/agent-governance-policies.git
cd agent-governance-policies

rustup toolchain install 1.89.0 --profile minimal \
  --component rustfmt --component clippy --target wasm32-wasip1

cd approval-execution-binding          # or: cd aggregate-risk-gate
cargo +1.89.0 test --lib --locked
cargo +1.89.0 build --release --target wasm32-wasip1 --locked
```

The first run needs network access to fetch dependencies. After that, add
`--offline`. The WebAssembly binary lands in
`target/wasm32-wasip1/release/approval_execution_binding.wasm` or
`target/wasm32-wasip1/release/aggregate_risk_gate.wasm`.

## Deploying to a gateway

Deployment depends on your gateway and environment, so this repository does not
automate it. In outline:

1. Set your Anypoint organization id as `group_id` in the policy's `Cargo.toml`,
   replacing `REPLACE_WITH_YOUR_ANYPOINT_ORG_ID`. Keep that change out of any public
   fork.
2. Run `make build` to regenerate the Exchange asset files, then `make publish` for
   a development version or `make release` for a production one. The policy README's
   *Make command reference* lists every target.
3. Apply the policy to an **MCP** API instance in API Manager, after an
   authentication policy. Configure it from the policy README's *Configuration*
   section.
4. Do a **UI Save & Apply**. A policy change made only through the API Manager REST
   API is not reliably pushed to a running gateway, so don't count a change as
   enforced until the deployment shows as applied.

To try a policy locally first, `make run` starts the bundled Flex Gateway
playground. It needs a local-mode registration, which stays untracked.

## Verification

### Continuous integration

Every pull request and every push to `main` runs the
[Verify policies](.github/workflows/verify.yml) workflow:

| Job | What it checks |
| --- | --- |
| `policies` | For each policy: `rustfmt --check`, strict Clippy (`-D warnings`), library tests, integration-test compilation and a release WASM build, all against the committed lockfile |
| `exchange-assets` | The full PDK packaging path (`make build`) from a clean checkout. It fails if the generated config drifts from `gcl.yaml`, and it validates the Exchange metadata with `scripts/check_exchange_metadata.py`. |
| `runtime-e2e` | Builds the aggregate-risk gate and runs its `#[pdk_test]` suites against a **real Flex Gateway 1.14.0 container**, using a disposable local-mode identity held in a repository secret. It then scans the evidence for identifiers. |
| `runtime-e2e-approval` | The same for Approval-to-Execution Binding: its `#[pdk_test]` suite on a real Flex Gateway 1.14.0 container, including the check that the `rpc-param` envelope is stripped before the upstream with a correct `content-length`. Both runtime jobs share a `flex-registration` concurrency group, so the one registration is never used by two runners at once, and their full test output goes only to identifier-scanned log files. |

The packaging and runtime jobs need repository secrets, so pull requests from
forks skip them.

Current library test counts: **97** for Approval-to-Execution Binding and **191**
for the aggregate-risk gate.

To run the CI's `policies` checks locally, from a policy directory:

```bash
cargo +1.89.0 fmt --check
cargo +1.89.0 clippy --lib --locked --offline -- -D warnings
cargo +1.89.0 test --lib --locked --offline
cargo +1.89.0 test --tests --no-run --locked --offline
```

### Evidence from real gateways

The behavior that local tests can't show was checked on real, disposable Flex
Gateway deployments. Every resource was deleted afterwards. Each run has a
readable report and a machine-readable JSON file:

| Run | What it showed | Report |
| --- | --- | --- |
| Approval binding, P5/P6 on a connected gateway | **Qualified partial.** Proved P5 with real Client ID Enforcement and same-replica replay rejection. Replays reopen across replicas and after a restart, as expected for `local()`. Shared-store reservations are unproven. | [APPROVAL-P6-CONNECTED-2026-09-25](docs/APPROVAL-P6-CONNECTED-2026-09-25.md) |
| Approval binding, storage unavailable | Why the storage-error branch fails closed, and why it can't be reached on `local()` | [APPROVAL-STORAGE-UNAVAILABLE-2026-09-25](docs/APPROVAL-STORAGE-UNAVAILABLE-2026-09-25.md) |
| Aggregate-risk gate, Exchange publication | The dev publish is accepted: the description fits the 256-character limit and the stored metadata declares `assetTypes: mcp` | [AGGREGATE-RISK-PUBLISH-2026-10-02](docs/AGGREGATE-RISK-PUBLISH-2026-10-02.md) |
| Aggregate-risk gate, real-gateway behavior | 14 case results: 8 pass, 3 qualified, 3 observed, none failed. They cover real Client ID Enforcement on a connected gateway, budget refusal, digest disclosure, reclaim and late settlement, the window reset, restart, and per-worker scope. | [AGGREGATE-RISK-CONNECTED-2026-10-01](docs/AGGREGATE-RISK-CONNECTED-2026-10-01.md) |

The [docs index](docs/README.md) lists every report with its evidence file.

## Scope and known limits

- **Enforcement, not attestation.** Approval binding checks an approval *record*.
  A record checked only by the party it constrains proves nothing without the
  separate-attester predicate (P5). P5 uses symmetric HMAC over a versioned,
  domain-separated `mcp-v1` payload, so it gives separation of duties, not
  non-repudiation. The executor identity P5 checks comes from verified
  authentication data, not from a header the caller sets.
- **P6 single use is per gateway replica, until restart.** The nonce store is gateway
  `local()` storage, so a replay can succeed on a second replica or after a restart.
  Run P6 flows on a single replica. The store is capped at a fixed number of nonces
  per replica (see the policy README). A shared store with a TTL would make single
  use global.
- **The aggregate budget is per gateway replica, and a restart resets it.** By default
  (`ledgerBackend: node`) every worker of a replica shares one ledger in the gateway's
  node-local data, with compare-and-swap writes, so more connections don't multiply the
  budget. Replicas are still independent: with `R` replicas a scope can reach
  `R × aggregateBudget`, so divide by `R` or run one. The ledger is not durable, so a
  gateway process restart resets it. The opt-in `ledgerBackend: worker` keeps one ledger
  per worker, which a caller *can* multiply across `N` workers: divide by `N` or set
  `FLEX_SERVICE_ENVOY_CONCURRENCY=1`. A ledger shared across replicas
  (`ledgerBackend: cluster`) is not implemented and is rejected.
- **Bounded inspection.** Both policies inspect admitted JSON-RPC envelopes and
  bodies. They do not inspect URL paths, query strings or arbitrary headers, and
  they never treat a header as trusted provenance.
- **MCP only.** Both policies declare and are tested on MCP API instances. No
  agent-to-agent or model-proxy coverage is claimed.
- **No certification.** NIST, OWASP, MITRE, EU AI Act and AIUC-1 references in the
  policy READMEs are design context and supporting measures, not certification.

## Repository layout

```text
.
├── approval-execution-binding/   policy: Approval-to-Execution Binding (PDK project)
├── aggregate-risk-gate/          policy: Cross-Session Aggregate-Risk Gate (PDK project)
│   ├── definition/gcl.yaml       configuration schema and Exchange metadata
│   ├── src/                      policy source (src/generated/ is produced by make build)
│   ├── tests/                    pdk_test suites, which run on a real Flex container
│   ├── playground/               local Flex Gateway playground
│   └── docs/                     the real-gateway verification brief
├── docs/                         real-gateway evidence reports, with docs/evidence/*.json
├── scripts/                      check_exchange_metadata.py (the CI metadata gate)
├── licenses/                     upstream license texts (Salesforce PDK)
├── COMPOSITION.md                running both policies, or chaining them with others
├── ATTRIBUTION.md                corpus provenance, dependencies, design references
├── P4A-SUBMISSION.md             P4A marketplace submission pack
├── CHANGELOG.md                  release notes
├── CONTRIBUTING.md               local checks, evidence and redaction rules
├── SECURITY.md                   private vulnerability reporting
└── CITATION.cff                  software citation and the papers it implements
```

Each policy directory is a self-contained PDK project with its own `Cargo.toml`,
lockfile, Makefile and pinned toolchain. There is no workspace-wide build.

## Documentation map

| You want to… | Read |
| --- | --- |
| Configure a policy and understand its behavior | [Approval binding](approval-execution-binding/README.md), [Aggregate-risk gate](aggregate-risk-gate/README.md) |
| Run both policies, or chain them with others | [COMPOSITION.md](COMPOSITION.md) |
| See what was verified on a real gateway | [docs/README.md](docs/README.md) |
| Check provenance, corpora and dependency licenses | [ATTRIBUTION.md](ATTRIBUTION.md) |
| See what changed | [CHANGELOG.md](CHANGELOG.md) |
| Submit to the P4A marketplace | [P4A-SUBMISSION.md](P4A-SUBMISSION.md) |
| Contribute or report a vulnerability | [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) |

## Contributing, security and citation

- **Contributing:** see [CONTRIBUTING.md](CONTRIBUTING.md) for the local checks, the
  evidence rules and the redaction rules that apply because this repository is public.
- **Security:** report vulnerabilities privately, as described in
  [SECURITY.md](SECURITY.md). Don't open a public issue for one.
- **Citation:** [CITATION.cff](CITATION.cff) gives the software citation and the
  papers the policies implement. GitHub shows it as *Cite this repository*.

## License

Project contributions are under the [MIT License](LICENSE). Upstream templates,
reference corpora and dependencies keep their own notices and terms. The Salesforce
PDK is under Salesforce's own terms, which are copied into [licenses/](licenses/).
See [ATTRIBUTION.md](ATTRIBUTION.md) for the full scope.
