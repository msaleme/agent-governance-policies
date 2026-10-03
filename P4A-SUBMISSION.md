# P4A submission package — Agent Governance Policies

Prepared 2026-09-24. Updated 2026-09-25: the visibility blocker was resolved,
reviewer findings #1–#7 were resolved and merged, and connected verification was
complete. Updated 2026-10-03: aggregate-risk findings #14–#18 were resolved and
closed, and source prerelease `v0.1.0-rc.1` was cut. Turnkey pack for submitting the two policies in this repo to the
**P4A (Policies for Agents)** marketplace, mirroring the path the three published
`agent-decoy-policies` siblings took. Submission itself is **UI-gated** (the P4A wizard) —
this doc is everything a human needs to drive it; nothing here submits automatically.

## Submission-fit checklist (verified 2026-09-24)

P4A's [submission guide](https://docs.p4a.ai/docs/guides/submitting-a-policy) checks: public
accessibility, Cargo project structure, a resolvable PDK dependency, PDK >= 1.8.0, and (for
unified project roots) a `.project.yaml`. Status per that list:

| Requirement | approval-execution-binding | aggregate-risk-gate |
|---|---|---|
| Unified Cargo crate (src + Cargo.toml/lock) | OK | OK |
| `.project.yaml` at project root | OK (impl `.`, def `definition`) | OK (same) |
| `definition/gcl.yaml` with title/category/description | OK (Security) | OK (Security) |
| PDK pinned >= 1.8.0 | OK — **1.10.0** | OK — **1.10.0** |
| rust-toolchain pinned | OK — 1.89.0 | OK — 1.89.0 |
| Builds to wasm32-wasip1 | OK (CI) | OK (CI) |
| CI green (fmt/clippy -D warnings/test/wasm build) | OK — green on `main` | OK — green on `main` |
| Lib tests | 46 pass | 140 pass |
| Reviewer findings addressed | OK — Tommaso Bolis #1–#7 resolved & merged (PR #19; publish/build fixes #23, #26) | OK — P4A review #14 (PR #37), #15 (#39), #16 (#35, #42), #17 (#38), #18 (#36); all closed |
| **Public accessibility** | **OK** — repo PUBLIC since 2026-09-24 | **OK** — repo PUBLIC since 2026-09-24 |

### Repo visibility — RESOLVED (2026-09-24)
The repo `github.com/msaleme/agent-governance-policies` is now **public** (`gh repo edit --visibility public`),
so P4A's public-accessibility check is satisfied. The pre-flip secret scan was clean (no real org id —
`group_id` is the placeholder `REPLACE_WITH_YOUR_ANYPOINT_ORG_ID` — no UUIDs/emails/keys; `.gitignore`
excludes all Flex identity material). No further visibility action is required to submit.

## Per-policy submission facts

### 1. Approval-to-Execution Binding
- **Project path:** `/approval-execution-binding` (point the wizard at `/tree/main/approval-execution-binding`)
- **Category / injection point / scope:** Security / inbound / `api,resource`; `metadata/capabilities/assetTypes: mcp` → applicability **MCP `tools/call` only** (all other JSON-RPC methods pass through untouched as out-of-scope).
- **Catalog copy:** use `definition/gcl.yaml` `metadata.labels.description` verbatim (publish-ready;
  P4A catalog copy is **frozen at submission time**, so get it right up front — the description is now
  ≤256 chars). One-line hook for the listing summary: *"Proves the executed MCP `tools/call` is the
  one the accompanying approval actually approved — five ABV v0.1 predicates checked at the gateway."*
- **Config surface:** approvalSource(header|rpc-param) / approvalHeader / approvalRpcField /
  executorHeader / requiredPredicates(P1,P2,P4,P5; P6 opt-in — **no P3**) / attesterKeys(key ≥32 bytes) /
  clockSkewSeconds / expectedAudience / expectedTenant / expectedEnvironment (all required when P5 is
  required) / mode(block|monitor) / onDeny(rpc-error -32008|empty-403) / resultHeader.
- **Reviewer findings #1–#7 (Tommaso Bolis) — resolution:**
  - **#7** MCP `tools/call` profile: only `tools/call` binds; every other method is forwarded
    out-of-scope in both modes; unparseable → fail closed. — DONE
  - **#5** Versioned canonical JSON, fail-closed: RFC 8785 digests; a non-integer/float number denies;
    `arguments` object-or-absent. — DONE
  - **#2** Reject reference-shaped arguments, remove P3: any `$ref`-shaped object denied under P2;
    P3 removed everywhere. — DONE
  - **#4** Authenticate a versioned, domain-separated `mcp-v1` payload; `expected_*` required when P5. — DONE
  - **#6** Executor from **verified** `AuthenticationData` (client_id→principal); absent + P5-required
    fails closed; header is fallback only. — DONE
  - **#3** Atomic single-use via gateway data storage (`StoreMode::Absent`); replay denied; other
    storage error fails closed; monitor does not reserve. Connected run on a real Flex Gateway:
    a **qualified partial**. It proved P5 with real Client ID Enforcement and same-replica replay
    rejection (evidence in `docs/APPROVAL-P6-CONNECTED-2026-09-25.*`). Two items are
    documented qualifications, not defects: cross-replica single-use is unproven on `local()` by design,
    and the storage-unavailable fail-closed branch is correct by inspection but not reachably testable on
    `local()` (pinned proxy-wasm SDK panics on unexpected host statuses; see
    `docs/APPROVAL-STORAGE-UNAVAILABLE-2026-09-25.*`). A shared/remote store closes both — future feature.
    — DONE (unit + connected e2e; two documented `local()` limitations)
  - **#1** Publishability: `attesterKeys[].key` marked `security:sensitive` via the doc-supported JSON-LD
    `@context`/`@characteristics` form (bare `characteristics:` is rejected by the GCL compiler — fix #21/PR #23);
    ≥32-byte key enforced at startup; gcl `description` ≤256 chars; cargo-anypoint 1.10.0; fixture tests
    deserialize every ABV vector; monitor stamps the result header on every forwarded path. `make build`
    reproduces the generated config (fix #24/PR #26), so the standard build/publish pipeline is clean. — DONE
- **Framework refs (supporting-measure, never certification):** NIST SP 800-53 Rev5 AC-3/AC-4/AU-10/AU-2
  (AU-10 supported by separation-of-duties, *not* non-repudiation — symmetric HMAC); OWASP LLM06
  Excessive Agency; MITRE ATLAS + Engage (design vocabulary); EU AI Act Art 14. Full text in README.
- **Honesty boundary to carry into the listing:** the corpus/policy tests whether the RECORD proves
  approved==executed; P5's separate attester (over the `mcp-v1` payload, checked against the *verified*
  executor) is what keeps the check meaningful; HMAC is separation-of-duties, not non-repudiation. P6's
  `local()` store is per-replica. No `.on_response` handler.

### 2. Cross-Session Aggregate-Risk Gate
- **Project path:** `/aggregate-risk-gate` (point the wizard at `/tree/main/aggregate-risk-gate`)
- **Category / injection point / scope:** Security / inbound / `api,resource`; `metadata/capabilities/assetTypes: mcp` → applicability **MCP only**.
- **Dropped targets:** an earlier draft also listed agent-to-agent and model-proxy instances; neither has
  test coverage, so neither is declared (P4A review #16).
- **Catalog copy:** use `definition/gcl.yaml` `metadata.labels.description` verbatim (≤256 chars; the full
  explanation lives in the policy README). One-line hook:
  *"Reserve-then-authorize aggregate-exposure control: refuses the individually-valid call that composes
  past a budget no per-call gate ever sees."*
- **Config surface:** budgetScope(agent|fabric|tenant) / identitySource(authentication|trusted-header) /
  identityField / scopeHeader / maxScopes / reservationTimeoutMs / scopeDisclosure(digest|none|raw) / scopeDigestKey (sensitive) /
  aggregateBudget / window(fixed-period|worker-lifetime, enforced) / windowMs / contribution(estimated-token-weight|spend-amount|fixed-weight) /
  fixedWeight / spendAmountField / spendCurrency / estimatedTokens / mode(block|monitor) /
  onDeny(rpc-error|empty-403) / resultHeader. All amounts are exact integers in 0–2^53−1 (spend amounts
  in ISO 4217 minor units); `resultHeader` stamps `unit=`. `token-cost` was renamed (P4A review #18).
  Identity comes from verified `AuthenticationData` by default; a trusted header is opt-in, identities are
  canonicalized and bounded, and the result header shows a digest, not the raw ID (P4A review #14).
- **Framework refs (supporting-measure):** NIST SP 800-53 Rev5 AC-4/SC-7/AU-2/AU-6/SI-4; OWASP LLM10:2025
  Unbounded Consumption; MITRE ATLAS AML.T0034 Cost Harvesting + Engage; EU AI Act Art 15. Full text in README.
- **Honesty boundary (must be in the listing):** an in-process serialized ledger (real, atomic,
  race-tested) with a real fixed window, **one budget per policy instance per gateway worker**. It is
  not shared across workers or replicas (N workers admit up to N × the budget) and a restart resets it
  (P4A review #15). A shared, durable ledger with signed decision records is future v2 work. Response
  leg is headers-only.

## Wizard steps (HUMAN)
1. No visibility blocker — the repo is public (see above). Proceed.
2. In the P4A dashboard, add a new policy; point it at this repo, subdirectory
   `approval-execution-binding` (then repeat for `aggregate-risk-gate`). Nested/unified roots are
   supported, but **submit and validate each project explicitly** — one root URL does not guarantee
   auto-discovery of both.
3. Set catalog copy from each policy's `gcl.yaml` description + the one-line hook above.
4. Set applicability to **MCP** for both policies (each declares `assetTypes: mcp`).
5. Submit; reviewer **Tommaso Bolis** runs the same review loop the three decoy policies went through.
   His findings #1–#7 on approval-execution-binding are **resolved and merged to `main`** (PR #19, plus
   publish/build fixes #23 and #26; per-finding resolution table above), and the policy has been
   verified connected on a real gateway — so expect fewer round-trips. #1–#7 and #14–#18 are all
   closed. When you resubmit, point him at the tagged `v0.1.0-rc.1` source so he can re-review
   against merged `main`.

## Not claimed
No P4A submission, acceptance, dashboard ID, or publication is asserted here — those come from an actual
wizard run and reviewer action. Framework references are supporting-measure context, not certifications.
