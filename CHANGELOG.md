# Changelog

## Unreleased

First source snapshot of the Agent Governance Policies family. Two independent
Rust + PDK 1.10.0 policies for MuleSoft Flex/Omni Gateway, built with Rust 1.89.0
and compiled for `wasm32-wasip1`. No compiled release assets and no Exchange
publication are included.

### Added

- **Approval-to-Execution Binding** — enforces the six `approval-binding-vectors`
  (ABV v0.1) predicates (P1 action, P2 argument bytes, P3 dereferenced-reference
  bytes, P4 valid-at-execution, P5 separate attester, P6 single-use nonce) on
  admitted MCP/A2A JSON-RPC. Vendors the 12-vector ABV corpus (3 positive controls
  + 9 negative predicate cases) as conformance fixtures. Monitor and block modes;
  JSON-RPC `-32008` or empty-`403` denial rendering. Real HMAC-SHA256 attestation
  (P5) over the canonicalized approval scope and real wall-clock freshness (P4).
- **Cross-Session Aggregate-Risk Gate** — a reserve-then-authorize decision engine
  (`ledger.rs`) that holds a shared exposure budget across sessions where each call
  is individually under its cap. PDK-independent engine, unit-tested under genuine
  OS-thread contention: a naive read-then-write counter is shown to breach the
  budget while the atomic reserve-then-authorize ledger holds it. Monitor and block
  modes; per-scope (agent/fabric/tenant) budgets; token-cost, spend-amount, and
  fixed-weight contribution modes with estimate-then-settle commitment (this build
  commits the full estimate; it does not read the response body to reconcile).
- Per-policy PDK project scaffold: config schema (`definition/gcl.yaml`), generated
  `Config`, Makefile, playground, and pinned `rust-toolchain.toml` (1.89.0).
- Repository scaffolding: MIT license, attribution and corpus provenance,
  composition notes, and a credential-free CI workflow.
- Attribution: full research provenance for the aggregate-risk corpus (position
  paper *"Authorized but Composed"*, Zenodo DOI 10.5281/zenodo.21400261, sibling
  DOI 10.5281/zenodo.21263262, and the `red-team-blue-team-agent-fabric` verifier
  harness) and a Protocol specifications section citing the governed wire formats
  (MCP, A2A, JSON-RPC 2.0).

### Known limitations

- Approval-binding P5 attestation is symmetric HMAC in this build; the `sidecar`
  approval source is rejected at startup. A record checked only by the party it
  constrains is not meaningful without the separate-attester predicate.
- The aggregate-risk gate ships the Stage A in-process ledger only: per-worker
  (not distributed) state, `window` accepted but not time-enforced, `ledgerEndpoint`
  reserved and unimplemented, and no cryptographic non-repudiation of decisions.
  Reference concurrency scenarios are synthetic, not production telemetry.
- Inspection targets admitted JSON-RPC envelopes and bodies, not paths, query
  strings, or arbitrary headers. Local tests do not establish general MCP
  interoperability or production effectiveness. Framework references in the policy
  READMEs are design/supporting-measure context, not certification.
