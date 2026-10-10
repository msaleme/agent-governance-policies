# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this is

**Agent Governance Policies** — two independent MuleSoft Flex/Omni Gateway custom
policies (Rust → `wasm32-wasip1`, PDK 1.10.0), a sibling family to
[`agent-decoy-policies`](https://github.com/msaleme/agent-decoy-policies). Where
that family adds deception, this one adds authorization integrity:

- `approval-execution-binding/` — proves an executed MCP `tools/call` equals the
  action that was approved. It enforces five `approval-binding-vectors` predicates:
  P1, P2, P4, P5 and the opt-in P6. P3 is removed, and reference-shaped arguments are
  denied under P2. MCP only; no A2A.
- `aggregate-risk-gate/` — a reserve-then-authorize ledger that holds a shared
  exposure budget across sessions of individually-authorized calls.

Each subdirectory is a self-contained PDK project. There is no workspace-wide
build; `cd` into a policy and use its own commands.

## Ownership note

Unlike `agent-decoy-policies` (developed by the autonomous agent on Astra; local
edits there are discarded), **this repository is authored and edited directly
here.** Edit it normally. The two policies originated from the Tier 1 build kit in
`~/Projects/claude/llm-gateway/demo/mcp/tier1-policies/` (specs 02 and 03).

## Build / test (per policy — pinned Rust 1.89.0)

```bash
cd approval-execution-binding        # or aggregate-risk-gate
cargo +1.89.0 fmt --check
cargo +1.89.0 clippy --all-targets --locked --offline -- -D warnings
cargo +1.89.0 test --lib --locked --offline
cargo +1.89.0 test --tests --no-run --locked --offline      # integration tests compile (Docker to run)
cargo +1.89.0 build --release --target wasm32-wasip1 --locked
```

The `--lib` test suite is the authoritative gate, at 125 tests for approval binding
and 227 for the aggregate-risk gate. `tests/*.rs` need Docker and aren't part of
those counts. CI's `runtime-e2e` job runs the aggregate-risk `#[pdk_test]` suites
on a real Flex Gateway 1.14.0 container (its `case2c` is run by hand), and the
`runtime-e2e-approval` job does the same for approval binding's `tests/requests.rs`. Regenerate config assets with the
Makefile (`make build-asset-files`) after changing `definition/gcl.yaml`.

## Hard rules (inherited from the parent projects)

- **No mock/fake/placeholder code or data.** Real logic, real crypto, real tests.
- **Never commit credentials, tokens, or Flex registration/identity material.**
  `registration.yaml`, `certificate.yaml`, and `*.pem` are gitignored — keep them
  untracked. Scan before any push.
- **Honesty over polish.** Framework references (NIST/OWASP/MITRE/EU AI Act/AIUC-1)
  are design and supporting-measure context, never certification claims. State
  every limitation plainly: the aggregate ledger is per replica (per worker with
  `ledgerBackend: worker`) and a restart resets it; HMAC-only
  attestation; and P6 single use being per replica on `local()`. Do not weaken a
  test to make a gate pass; do not invent framework IDs, benchmarks, or counts.
- **The repo is PUBLIC.** Never commit org, environment or client ids, hostnames,
  IPs, digest keys or registration material. Run the redaction check in
  `CONTRIBUTING.md` before every commit. `Cargo.toml` keeps the placeholder
  `group_id`.
- Real-gateway evidence goes in `docs/` as a report plus a JSON file (see
  `docs/README.md`). Policy changes count as enforced only after a UI Save & Apply.
- Match the sibling `agent-decoy-policies` README/attribution style and depth.

## Provenance

Scaffolded from the PDK project template; Salesforce copyright notices in scaffold
files are preserved alongside the project's MIT notice. See `ATTRIBUTION.md` for
the corpus provenance (ABV, authorized-but-composed) and dependency license table.
