# Changelog

## Unreleased

First source snapshot of the Agent Governance Policies family. Two independent
Rust + PDK 1.10.0 policies for MuleSoft Flex/Omni Gateway, built with Rust 1.89.0
and compiled for `wasm32-wasip1`. No compiled release assets and no Exchange
publication are included.

### Added

- **Approval-to-Execution Binding** — enforces five `approval-binding-vectors`
  (ABV v0.1) predicates (P1 action, P2 canonical argument bytes — reference-shaped
  `$ref` arguments rejected, not dereferenced; P4 valid-at-execution, P5 separate
  attester, P6 opt-in single-use nonce) on admitted MCP **`tools/call`** requests;
  every other JSON-RPC method is forwarded untouched as out-of-scope. (An earlier
  draft's P3 dereference predicate was removed in favor of rejecting reference-shaped
  arguments under P2.) Vendors the ABV corpus as conformance fixtures. Monitor and
  block modes; JSON-RPC `-32008` or empty-`403` denial rendering. Real HMAC-SHA256
  P5 attestation over a versioned, domain-separated `mcp-v1` payload (checked against
  the *verified* executor identity, not a caller-asserted header), real wall-clock P4
  freshness, and atomic P6 single-use via gateway data storage (`StoreMode::Absent`).
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

### Fixed

- **Approval-to-Execution Binding** — the `attesterKeys[].key` sensitive-parameter
  marker now uses the doc-supported JSON-LD form (`"@context": { "@characteristics":
  ["security:sensitive"] }`). The earlier bare `characteristics: [security:sensitive]`
  was rejected by PDK's GCL→JSON-Schema compiler (ajv strict mode: unknown keyword),
  which blocked schema generation and Exchange publication (issue #21). Verified
  locally via `pdk policy-project build-asset-files`; re-confirm on a live Exchange
  publish.

### Known limitations

- Approval-binding P5 attestation is symmetric HMAC in this build (separation-of-
  duties, not non-repudiation); the `sidecar` approval source is rejected at startup.
  A record checked only by the party it constrains is not meaningful without the
  separate-attester predicate. P6's single-use nonce store uses gateway `local()`
  storage, which is per-replica and has no policy-controlled TTL; durable, global
  single-use across replicas/restarts requires a shared store and is validated
  end-to-end separately (`approval-execution-binding/docs/ASTRA-TASK-approval-p6-replay.md`).
- The aggregate-risk gate ships the Stage A in-process ledger only: per-worker
  (not distributed) state, `window` accepted but not time-enforced, `ledgerEndpoint`
  reserved and unimplemented, and no cryptographic non-repudiation of decisions.
  Reference concurrency scenarios are synthetic, not production telemetry.
- Inspection targets admitted JSON-RPC envelopes and bodies, not paths, query
  strings, or arbitrary headers. Local tests do not establish general MCP
  interoperability or production effectiveness. Framework references in the policy
  READMEs are design/supporting-measure context, not certification.
