# P4A submission package — Agent Governance Policies

Prepared 2026-09-24. Updated 2026-09-25: the visibility blocker was resolved,
reviewer findings #1–#7 were resolved and merged, and connected verification was
complete. Updated 2026-10-03: aggregate-risk findings #14–#18 were resolved and
closed, and source prerelease `v0.1.0-rc.1` was cut. Updated 2026-10-04: the re-review at
`v0.1.0-rc.1` opened #47–#52; the fixes are described per policy below. #47–#52 were fixed, merged and closed, and source prerelease `v0.1.0-rc.2` was cut. Turnkey pack for submitting the two policies in this repo to the
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
| Lib tests | 97 pass | 205 pass |
| Reviewer findings addressed | OK — Tommaso Bolis #1–#7 resolved & merged (PR #19; publish/build fixes #23, #26). Re-review #50, #51 (claim narrowed + nonce cap) and #52 items 1–3 (canonical form, maximum approval lifetime, `rpc-param` envelope removal) fixed; a charset (UTF-7) bypass found in self-review also fixed | OK — P4A review #14 (PR #37), #15 (#39), #16 (#35, #42), #17 (#38), #18 (#36); all closed. Re-review #47 (blocker) and #49 B fixed, plus a charset (UTF-7) bypass found in self-review; #48 fixed (node-wide ledger, the new default `ledgerBackend: node`) and #49 A fixed (a refusal at the scope cap is O(1)) |
| **Public accessibility** | **OK** — repo PUBLIC since 2026-09-24 | **OK** — repo PUBLIC since 2026-09-24 |

### Repo visibility — RESOLVED (2026-09-24)
The repo `github.com/msaleme/agent-governance-policies` is now **public** (`gh repo edit --visibility public`),
so P4A's public-accessibility check is satisfied. The pre-flip secret scan was clean (no real org id —
`group_id` is the placeholder `REPLACE_WITH_YOUR_ANYPOINT_ORG_ID` — no UUIDs/emails/keys; `.gitignore`
excludes all Flex identity material). No further visibility action is required to submit.

## Per-policy submission facts

### 1. Approval-to-Execution Binding
- **Project path:** `/approval-execution-binding` (point the wizard at `/tree/main/approval-execution-binding`)
- **Category / injection point / scope:** Security / inbound / `api,resource`; `metadata/capabilities/assetTypes: mcp` → applicability **MCP `tools/call` only**. All other JSON-RPC methods, and bodyless non-POST transport requests (the SSE `GET`, the session `DELETE`), pass through untouched as out-of-scope (#50).
- **Catalog copy:** use `definition/gcl.yaml` `metadata.labels.description` verbatim (publish-ready;
  P4A catalog copy is **frozen at submission time**, so get it right up front — the description is now
  ≤256 chars). One-line hook for the listing summary: *"Proves the executed MCP `tools/call` is the
  one the accompanying approval actually approved — five ABV v0.1 predicates checked at the gateway."*
- **Config surface:** approvalSource(header|rpc-param) / approvalHeader / approvalRpcField /
  executorHeader / requiredPredicates(P1,P2,P4,P5; P6 opt-in, single use **per gateway replica, until restart** — **no P3**) / attesterKeys(key ≥32 bytes) /
  clockSkewSeconds (0–3600) / maxApprovalLifetimeSeconds (optional, 0 = off; needs P4) /
  stripApprovalEnvelope (rpc-param only, default true) / expectedAudience / expectedTenant /
  expectedEnvironment (all required when P5 is required) / mode(block|monitor) /
  onDeny(rpc-error -32008|empty-403) / resultHeader.
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
  `local()` store is per replica: an approval authorizes at most one execution **per gateway replica,
  until restart** (#51), so run P6 flows on one replica. A POST without a valid `content-length` is
  denied as framing. Canonical form rejects integers beyond ±(2^53−1) and keys whose UTF-8 and UTF-16
  orders differ (#52). A maximum approval lifetime (`maxApprovalLifetimeSeconds`) is available
  under P4 but off by default; it checks `not_after` against the gateway clock (there is no `iat`),
  and `not_after` is authenticated only when P5 is required. In `rpc-param` mode, the approval
  envelope is stripped from forwarded single-object bodies, with `content-length` rewritten; batch
  and malformed bodies are never forwarded with a rewrite. `clockSkewSeconds` is capped at one hour. No `.on_response` handler.

### 2. Cross-Session Aggregate-Risk Gate
- **Project path:** `/aggregate-risk-gate` (point the wizard at `/tree/main/aggregate-risk-gate`)
- **Category / injection point / scope:** Security / inbound / `api,resource`; `metadata/capabilities/assetTypes: mcp` → applicability **MCP only**. Only methods in `governedMethods`
  (default `["tools/call"]`) are priced; the handshake, `tools/list`, `ping`, notifications, client responses and
  bodyless transport requests pass through uncharged, so an exhausted budget never blocks reconnecting, keepalive,
  cancellation or teardown (P4A review #47).
- **Dropped targets:** an earlier draft also listed agent-to-agent and model-proxy instances; neither has
  test coverage, so neither is declared (P4A review #16).
- **Catalog copy:** use `definition/gcl.yaml` `metadata.labels.description` verbatim (≤256 chars; the full
  explanation lives in the policy README). One-line hook:
  *"Reserve-then-authorize aggregate-exposure control: refuses the individually-valid call that composes
  past a budget no per-call gate ever sees."*
- **Config surface:** budgetScope(agent|fabric|tenant) / identitySource(authentication|trusted-header) /
  identityField / scopeHeader / ledgerBackend(node|worker; cluster rejected) / ledgerNamespace / maxScopes / reservationTimeoutMs / scopeDisclosure(digest|none|raw) / scopeDigestKey (sensitive) /
  aggregateBudget / window(fixed-period|worker-lifetime, enforced) / windowMs / contribution(estimated-token-weight|spend-amount|fixed-weight) /
  fixedWeight / spendAmountField / spendCurrency / estimatedTokens / governedMethods / mode(block|monitor) /
  onDeny(rpc-error|empty-403) / resultHeader. All amounts are exact integers in 0–2^53−1 (spend amounts
  in ISO 4217 minor units); `resultHeader` stamps `unit=`. `token-cost` was renamed (P4A review #18).
  Identity comes from verified `AuthenticationData` by default; a trusted header is opt-in, identities are
  canonicalized and bounded, and the result header shows a digest, not the raw ID (P4A review #14).
- **Framework refs (supporting-measure):** NIST SP 800-53 Rev5 AC-4/SC-7/AU-2/AU-6/SI-4; OWASP LLM10:2025
  Unbounded Consumption; MITRE ATLAS AML.T0034 Cost Harvesting + Engage; EU AI Act Art 15. Full text in README.
- **Honesty boundary (must be in the listing):** a real, atomic reserve-then-authorize ledger with a
  real fixed window. By default (`ledgerBackend: node`, #48) it is **one budget per policy instance per
  gateway replica**, shared by all of the replica's workers through compare-and-swap writes to PDK
  node-local shared data, and **reset when the gateway process restarts** (P4A review #15). Replicas
  are independent (R replicas admit up to R × the budget: divide by R or run one). Contention or a
  storage error fails closed in block mode. The opt-in `ledgerBackend: worker` is one budget per
  worker, which a caller can multiply by opening more connections; with it, divide by N or set
  `FLEX_SERVICE_ENVOY_CONCURRENCY=1`. A cross-replica, durable ledger (`cluster`) is not implemented
  and is rejected at configure time. Response leg is headers-only:
  settlement is by HTTP status (2xx/3xx commit, 4xx/5xx release), so a JSON-RPC error inside an HTTP 200
  is charged (#49).

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
   closed. His re-review at `v0.1.0-rc.1` opened #47–#52; all six are fixed, merged and closed,
   and source prerelease `v0.1.0-rc.2` carries the fixes for his re-review.

## Not claimed
No P4A submission, acceptance, dashboard ID, or publication is asserted here — those come from an actual
wizard run and reviewer action. Framework references are supporting-measure context, not certifications.
