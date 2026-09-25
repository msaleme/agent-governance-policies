# P4A submission package — Agent Governance Policies

Prepared 2026-09-24. Turnkey pack for submitting the two policies in this repo to the
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
| CI green (fmt/clippy -D warnings/test/wasm build) | OK — run 35650711340 success | OK — same run |
| Lib tests | 46 pass | 74 pass |
| Reviewer findings addressed | OK — Tommaso Bolis #1–#7 implemented (see below) | OK (issue #6 wired + tested) |
| **Public accessibility** | **BLOCKER** — repo is PRIVATE | **BLOCKER** — repo is PRIVATE |

### The one open blocker: repo visibility
The repo `github.com/msaleme/agent-governance-policies` is **private** (chosen deliberately).
P4A's guide checks public accessibility of the submitted project. To submit, either:
1. Make the repo public (irreversible/indexable — the published siblings are public MIT), **or**
2. Grant P4A read access to the private repo via the connection flow, if the wizard supports it
   for source ingestion (verify in the wizard; the one-click *deploy* path connects an Anypoint
   org via a Connected App, which is a separate mechanism from source ingestion).

Do not flip visibility without an explicit decision — that call is the maintainer's.

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
    storage error fails closed; monitor does not reserve. Cross-replica / restart / storage-unavailable
    end-to-end validation **handed to Astra** (`docs/ASTRA-TASK-approval-p6-replay.md`). — DONE (unit) / Astra (e2e)
  - **#1** Publishability: `attesterKeys[].key` marked `security:sensitive`; ≥32-byte key enforced at
    startup; gcl `description` ≤256 chars; cargo-anypoint 1.10.0; fixture tests deserialize every ABV
    vector; monitor stamps the result header on every forwarded path. — DONE
- **Framework refs (supporting-measure, never certification):** NIST SP 800-53 Rev5 AC-3/AC-4/AU-10/AU-2
  (AU-10 supported by separation-of-duties, *not* non-repudiation — symmetric HMAC); OWASP LLM06
  Excessive Agency; MITRE ATLAS + Engage (design vocabulary); EU AI Act Art 14. Full text in README.
- **Honesty boundary to carry into the listing:** the corpus/policy tests whether the RECORD proves
  approved==executed; P5's separate attester (over the `mcp-v1` payload, checked against the *verified*
  executor) is what keeps the check meaningful; HMAC is separation-of-duties, not non-repudiation. P6's
  `local()` store is per-replica. No `.on_response` handler.

### 2. Cross-Session Aggregate-Risk Gate
- **Project path:** `/aggregate-risk-gate` (point the wizard at `/tree/main/aggregate-risk-gate`)
- **Category / injection point / scope:** Security / inbound / `api,resource` → applicability **MCP + A2A + LLM-proxy**
- **Catalog copy:** use `definition/gcl.yaml` `metadata.labels.description` verbatim. One-line hook:
  *"Reserve-then-authorize aggregate-exposure control: refuses the individually-valid call that composes
  past a budget no per-call gate ever sees."*
- **Config surface:** budgetScope(agent|fabric|tenant) / scopeHeader / aggregateBudget / window
  (rolling-24h|fixed-period, validated) / contribution(token-cost|spend-amount|fixed-weight) / fixedWeight /
  spendAmountField / estimatedTokens / mode(block|monitor) / onDeny(rpc-error|empty-403) / resultHeader.
- **Framework refs (supporting-measure):** NIST SP 800-53 Rev5 AC-4/SC-7/AU-2/AU-6/SI-4; OWASP LLM10:2025
  Unbounded Consumption; MITRE ATLAS AML.T0034 Cost Harvesting + Engage; EU AI Act Art 15. Full text in README.
- **Honesty boundary (must be in the listing):** ships **Stage A** — an in-process, single-worker
  serialized ledger (real, atomic, race-tested), **not** a distributed multi-region ledger. Stage B
  (distributed, signed decision records) is unshipped roadmap. Response leg is headers-only.

## Wizard steps (HUMAN)
1. Resolve the visibility blocker above.
2. In the P4A dashboard, add a new policy; point it at this repo, subdirectory
   `approval-execution-binding` (then repeat for `aggregate-risk-gate`). Nested/unified roots are
   supported, but **submit and validate each project explicitly** — one root URL does not guarantee
   auto-discovery of both.
3. Set catalog copy from each policy's `gcl.yaml` description + the one-line hook above.
4. Set applicability (MCP/A2A/API-LLM as noted per policy).
5. Submit; reviewer **Tommaso Bolis** runs the same review loop the three decoy policies went through.
   His findings #1–#7 on approval-execution-binding are implemented on branch
   `fix/approval-binding-1-7-reviewer-findings` (see the per-finding resolution table above); expect
   fewer round-trips once that branch is reviewed and merged.

## Not claimed
No P4A submission, acceptance, dashboard ID, or publication is asserted here — those come from an actual
wizard run and reviewer action. Framework references are supporting-measure context, not certifications.
