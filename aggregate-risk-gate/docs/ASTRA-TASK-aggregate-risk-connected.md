# Astra task: end-to-end validation of the aggregate-risk gate on a real Flex Gateway

**Owner:** Astra (an autonomous agent working on a disposable, authorized gateway).

**Why this is handed off:** Tommaso's reviewer findings #14–#18 are fixed and merged in PRs
#35–#39. The verified checkpoint is merge commit **`5b71d80`**. The lib suite has 140 tests and
is green in CI. Everything in it runs in-process under `pdk_unit`. The two `#[pdk_test]` cases
in `tests/requests.rs` compile in CI (`cargo test --tests --no-run`) but **have never been run
against a gateway**. That gap is why #16 lists real-Flex execution as unmet, and why #14's
policy ordering is only unit-tested. This brief lists what a real gateway has to prove.

This document is a task list, not evidence that anything passes. Monitor mode is not
enforcement, and a green unit suite is not a green gateway run.

---

## Already proven in-process (do not re-litigate)

The `src/lib.rs` and `src/ledger.rs` unit suites cover these deterministically:

- **#18 units:** `u64` exact integer amounts. Fractional, exponent, negative, string and
  over-ceiling amounts are denied. Batch overflow is checked. `estimated-token-weight`
  charges the configured estimate and never reads the response body.
- **#14 identity:** the scope comes from `AuthenticationData` by default, and a spoofed header
  is ignored. Identities are canonicalized (trimmed, lowercased). Malformed, oversized or
  duplicated identities fail closed. `maxScopes` evicts only idle scopes. The default
  `scopeDisclosure: digest` never echoes the raw identity.
- **#17 reservations:** every reservation has an id and a TTL. Settlement is idempotent,
  including duplicate, reordered and crossed commit/release. TTL reclaim leaves committed
  totals untouched. Late commit and late release follow the documented rules.
- **#15 windows:** `fixed-period` resets at epoch-aligned `windowMs` boundaries, and in-flight
  reservations carry across a boundary. A clock stepping backwards never resets a total.
  `worker-lifetime` never resets, and `rolling-24h` is rejected. A restart resets the ledger.
- **Concurrency:** reserve-then-authorize holds the budget under real OS-thread contention.

## What only a real gateway can prove (the actual task)

Run every case at commit `5b71d80`. Use Flex/Omni 1.14.0 and an MCP API with an HTTP mock
upstream that counts hits. Unless a case says otherwise, the chain is **Client ID Enforcement →
aggregate-risk-gate**, using `contribution: fixed-weight`, `fixedWeight: 800`,
`aggregateBudget: 3000`, `mode: block` and `onDeny: rpc-error`. With these values, calls 1–3
are admitted and call 4 is refused.

For every case, record the request, the HTTP status, the response body, the
`x-aggregate-risk-gate` header and the upstream hit count.

| # | Case | Expected | Closes |
|---|---|---|---|
| 1 | **Run the committed `#[pdk_test]` cases** in `tests/requests.rs` (`make test`, or `cargo test --tests` with a Flex registration). Use them as they are; do not edit them. | Both pass. Calls 1–3 → 200 with `allowed;…;settlement=committed`. Calls 4–5 → 200 JSON-RPC envelope with `error.code = -32008`. Upstream hit exactly 3 times. A second agent has its own independent budget. | #16 |
| 2 | **Policy ordering with real Client ID Enforcement** (`identitySource: authentication`, `identityField: client_id`). (a) No client credentials. (b) Valid credentials plus a spoofed `x-agent-id` header that changes on every call. | (a) Rejected by Client ID Enforcement before the gate (401), and the upstream is not hit. (b) The spoofed header has no effect: the 4th call from the same client_id is refused with `-32008`. | #14 |
| 3 | **Default disclosure on the wire** (`scopeDisclosure: digest` with a real ≥32-byte `scopeDigestKey`) | The result header carries a digest, never the raw client_id. Grep the gateway logs for the client_id: it should be absent. | #14 |
| 4 | **Monitor mode** (`mode: monitor`, otherwise as in case 2) | Every call reaches the upstream. Calls over budget stamp `monitor;scope=…;reason=budget-exceeded`. Nothing is denied. | core |
| 5 | **Reservation reclaim and late settlement** (`reservationTimeoutMs: 1000`, `aggregateBudget: 1600`). The mock delays the first call. (a) Delay ≈1500 ms, so it settles inside one extra TTL. (b) Delay ≥2500 ms, so it settles after two TTLs. While it is in flight, send two fast calls once 1 s has passed. | The two fast calls are admitted once the slow call's reservation is reclaimed. (a) The slow response stamps `settlement=late-committed` and is charged without a budget check (this is the documented exposure). (b) It stamps `settlement=not-active` and is not charged. Record any gateway upstream timeout that cuts the delay short. | #17 |
| 6 | **Fixed window reset** (`window: fixed-period`, `windowMs: 60000`) | Exhaust the budget, then wait until the next UTC minute boundary (periods are epoch-aligned, not counted from first use). The next call is admitted. Record the timestamps on both sides of the boundary. | #15 |
| 7 | **Restart** | Exhaust the budget and restart the gateway container. The next call is admitted, because the ledger is in-process. This is the documented limitation, not a bug. | #15 |
| 8 | **Per-worker scope** | Record the gateway's worker/concurrency count. Then fire well over `aggregateBudget / fixedWeight` calls in parallel over many connections, and record how many were admitted. The README says up to N × budget for N workers. Record whatever is observed; do not assert a number. | #15 |
| 9 | **Exchange publication** (`make build`, then `make publish`, under cargo-anypoint 1.10.0) | The live Exchange definition and implementation GETs return 200. Exchange accepts `assetTypes: mcp` and the 232-char description. `scripts/check_exchange_metadata.py aggregate-risk-gate --assets` passes on the generated files. | #16 |

## Baseline to build on

- Fetch `origin/main` and branch fresh from `5b71d80`. Confirm that `git rev-parse
  --show-toplevel` points at a checkout of `github.com/msaleme/agent-governance-policies`. See
  `../../docs/CODEX-HANDOFF.md` for authorization and handling.
- Model the run on the approval-binding connected run (`../../docs/APPROVAL-P6-CONNECTED-2026-09-25.md`
  and `../../approval-execution-binding/tests/CONNECTED.md`). It covers the private-fixture
  pattern, the `FLAGS` hook that keeps the checked-in `src/generated/config.rs`, and the
  two-replica composite.
- `Cargo.toml` keeps its `REPLACE_WITH_YOUR_ANYPOINT_ORG_ID` placeholder. Substitute the org id
  only in your private working copy for `make build`/`make publish`, and **never commit it**.

## How to run (disposable, authorized gateway only)

- Use a **disposable, authorized** Flex Gateway, never a shared or customer gateway. Churn is
  expected here.
- **Never churn a live MCP instance** with repeated API PATCH plus Save & Apply. It corrupts
  gateway route state (empty-body 503). If an instance wedges, **delete and recreate** it. For
  cases that change config, prefer one instance per config.
- **An API PATCH does not mean the policy is enforced.** Config reaches the running gateway
  only after a **UI Save & Apply**: watch `deployment.updatedDate` bump and the status go
  Active→Updating→Active. Assert enforcement only after that push, never from the PATCH alone.

## Boundaries (load-bearing)

- **Verification only.** Do not change `src/`, `definition/gcl.yaml` or the committed tests.
  If an expectation fails on a real gateway, **file a GitHub issue with the captured evidence.
  Do not patch the policy to make it pass.**
- Stay inside the explicitly authorized disposable scope. Do not infer authority to use shared
  APIs or mutate production. **Delete every test resource afterwards and confirm it.**
- Do not close, reopen or comment on reviewer issues #14–#18. Link the evidence PR to #16 only.
- **Redact before committing.** The 2026-09-25 approval evidence JSON was committed with the
  real org id, and this repo is **public**. Before staging, replace every org/env/group UUID,
  client_id, client_secret, digest key, registration value, hostname and IP with a
  placeholder (`<org-id>`, `<client-id>`, `<gateway-host>`). Run this and get no output:
  ```bash
  git diff --cached | rg -i '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|client_secret|cloudhub\.io|\b\d{1,3}(\.\d{1,3}){3}\b'
  ```
  A UUID that is clearly not an identifier (e.g. a JSON-RPC test id) is fine; say so in the PR.

## Evidence artifact

Commit a pair:

1. `docs/AGGREGATE-RISK-CONNECTED-<UTC-date>.md`: a human-readable evidence doc. For each case,
   give the config, request, actual wire result, upstream hit count and disposition. For cases
   7 and 8, state the observed behaviour honestly.
2. `docs/evidence/aggregate-risk-connected-<UTC-date>.json`: machine-readable evidence covering
   the source commit, the **WASM SHA-256** of the built policy, the Flex version, the worker
   count, UTC timestamps, per-case HTTP statuses and headers, dispositions
   (`pass` / `fail` / `qualified`) and **resource-deletion status**.

State plainly which cases passed, which are qualified and which failed. Do not present a
partial run as all-green.

## Definition of done

- An evidence-only PR from a fresh topic branch, with CI (`policies` and GitGuardian) green.
- The evidence doc and JSON from a real disposable gateway for cases 1–9, or a GitHub issue
  filed for each case that doesn't hold.
- All disposable resources deleted and the deletion confirmed.
- The redaction grep is clean.

Do **not** merge to this public repo without the maintainer's explicit go.
