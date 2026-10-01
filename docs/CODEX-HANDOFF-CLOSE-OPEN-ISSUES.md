# Codex / Astra handoff — close the 12 open P4A reviewer issues

**Created:** 2026-10-01 · **Owner:** @msaleme · **Reviewer:** Tommaso Bolis (`tbolis-at-mulesoft`, P4A)

> **Why this exists (the unblock):** Tommaso has paused the P4A review and will not
> resume until **every open GitHub issue on this repo is closed** (his DM, 2026-10-01:
> *"I see there are still some open github issues, as soon as closed I will resume and
> complete the review."*). This doc is the authorization + task brief to get all 12
> open issues to a defensible **closed** state.
>
> This **supersedes `docs/CODEX-HANDOFF.md` for the issue-closure goal.** That older doc
> is still valid for its narrow connected-mode P5/P6 verification scope; read it for the
> gateway-verification mechanics, but treat *this* doc as the task of record.

## The honest-closure rule (read before touching anything)

Tommaso is the reviewer. **Do not close an issue you cannot substantiate** — he will
reopen it and the review stalls again, worse than before. Every close must be one of:

1. **Evidence close** — current `origin/main` already satisfies the acceptance criteria.
   Post a closing comment that maps each AC bullet to concrete evidence (commit SHA, test
   name, file+line, or CI job), then close. **No hand-waving, no "should be fine."**
2. **Fix-then-close** — implement the change on a fresh branch → PR → merge → close the
   issue *referencing the merged PR* and the AC mapping.
3. **Scope-narrowing close** — where the issue text explicitly offers "*or* narrow the
   claim / rename the mode / remove the unsupported target," do that in code+docs, merge,
   then close with the before/after claim diff. Several issues below offer this path; it
   is legitimate and often the right call for a reference policy. **But narrowing a
   product claim is a maintainer decision — flag it for @msaleme, don't decide alone.**

If a prescribed expectation genuinely does not hold and you cannot fix it, **say so in a
comment with evidence** and leave it open — never fabricate a pass. "Real data, no mocks"
applies to evidence too.

## Load-bearing constraints (same as the prior handoff)

- **`origin/main` is the source of truth.** This repo is authored on the maintainer's
  machine, *not* an Astra worktree — local edits are **not** disposable. `git fetch`,
  branch fresh off `origin/main`, open a PR. **Never force-push or rewrite `main`.**
  (Current local HEAD is on branch `docs/p4a-submission-refresh` — do not assume it equals
  `origin/main`.)
- Confirm `git rev-parse --show-toplevel` resolves to a checkout of
  `github.com/msaleme/agent-governance-policies` before staging anything.
- **CI must stay green:** formatting, `clippy -D warnings`, unit tests, WASM release
  build. Both policies are Rust + PDK **1.10.0**, toolchain **1.89.0**, target
  `wasm32-wasip1`.
- **Any connected-gateway verification** (needed for #3/#4/#5/#6 and #15/#16/#17) uses
  **only a disposable, explicitly-authorized** Flex/Omni gateway + upstream — never a
  shared or customer org. Delete every test resource afterward and confirm deletion.
  Remember **API PATCH ≠ enforcement** (UI Save & Apply pushes to the gateway). Never
  print/log/commit credential or registration material into evidence.
- **Secrets:** scan before every push (GitGuardian runs on PRs). No tokens/keys in
  commits, issues, or evidence files.

## Current state (reconciled 2026-10-01 — do not trust blindly, re-verify)

| Group | Issues | Code status | Likely closure path |
|---|---|---|---|
| **approval-execution-binding** | #1–#7 | Reviewer findings were **code-addressed and merged** (PR #19 "resolve #1–#7", plus #23 sensitive-key, #25/#26 connected P5/P6). **But the issues were never formally closed** with an AC-mapped comment. | Mostly **evidence close** (audit each AC against current `main`, comment, close). Fix only the residual gaps. |
| **aggregate-risk-gate** | #14–#18 | **Genuine open gaps.** The repo's own CHANGELOG admits the ledger is **process-local** (`Mutex<HashMap>`, not durable/shared), `window` is validated-but-not-enforced, reservations have no ID/TTL/idempotency, spend uses **`f64`**, and token mode **commits the estimate without reconciling** actual usage. | **Fix-then-close** or **scope-narrowing close** — most of these were explicitly left as "implement durable/windowed/exact *or* narrow the name & claims." Needs a maintainer scope decision. |

> ⚠️ **Do not repeat the earlier mistake.** A prior pass (`a9431cd`, "harden proactively")
> was mistaken for "all asks addressed." It was *anticipatory* hardening, **not** verified
> against Tommaso's actual findings. For every issue, map **his** acceptance criteria to
> **real** evidence on current `main`.

---

## Per-issue briefs

Each issue's full text is on GitHub; the review source for #1–#7 is P4A policy
`acfec93f-35c9-4582-9d74-934474749a1c`, and for #14–#18 it is `7bc64ece-1ea8-4356-ade1-b11446169089`
at commit `52ff133`. Below is the compressed ask + the closure checklist.

### approval-execution-binding — `approval-execution-binding/src/lib.rs`

**#1 — Secure config, publication & e2e validation.**
Verify on `main`: HMAC key fields carry `security:sensitive` (PR #23) and enforce a documented
min strength (asymmetric preferred); GCL description ≤ 256 chars; `metadata/capabilities/assetTypes`
present and valid; `pdk`/`pdk-unit`/`pdk-test`/`cargo-anypoint` all on compatible 1.10; tests load the
**vendored ABV fixtures** directly (fail on corpus drift) rather than reconstructing cases; Docker
`pdk_test` starts a supported Flex/Omni image and passes allow+deny; monitor mode **always** overwrites
the result header on forwarded paths; logs carry only coarse reason codes/hashes (**no raw nonce**).
CI runs fmt + clippy(-D) + unit + WASM release + integration. → Evidence-close each bullet; fix any gap.

**#2 — P3 dereference.** The CHANGELOG states P3 was **removed** and reference-shaped `$ref`
arguments are now **rejected under P2, not dereferenced**. That is one of the two defensible designs the
issue asks for. → Confirm code + README + GCL + P4A entry all consistently say "references rejected, P3
not claimed," add the forged-digest / changed-bytes / nested-ref / TOCTOU rejection tests, then
**evidence-close** citing the removal commit and tests.

**#3 — P6 atomic single-use across workers/replicas.** Must use PDK `DataStorageBuilder` remote storage
with `StoreMode::Absent` (reserve-before-forward), retention ≥ expiry+skew, **fail-closed** when storage
is unavailable, and defined monitor-mode semantics. CHANGELOG claims "atomic P6 via gateway data storage
(`StoreMode::Absent`)." → Verify the storage path is remote-capable (not per-worker), then prove
cross-request/cross-replica/restart single-use + storage-outage fail-closed on a **disposable connected
gateway** (see `approval-execution-binding/docs/ASTRA-TASK-approval-p6-replay.md` and
`docs/APPROVAL-STORAGE-UNAVAILABLE-2026-09-25.md`). Close with that evidence.

**#4 — Authenticate the full approval payload.** `not_after`, `nonce`, audience/API/server identity,
tenant, environment, subject, protocol version must all be inside the authenticated scope (versioned,
domain-separated). CHANGELOG claims a "versioned, domain-separated `mcp-v1` payload." → Add mutate-each-
claim-keep-signature → assert-deny tests; document `kid` rotation; ensure docs don't imply non-repudiation
for symmetric HMAC. Evidence-close.

**#5 — RFC 8785 / exact argument semantics.** Either use a reviewed JCS impl or a **narrower versioned
canonical profile that rejects unsupported input** (don't silently approximate). Preserve the distinction
between omitted / `null` / `{}` / `[]` / scalar unless a documented profile normalizes them. → Run official
RFC 8785 vectors; add the distinct-shape tests; one cross-impl interop test. Fix if the current
`canonical_json_string()` still approximates; else evidence-close.

**#6 — Executor identity from verified auth context.** P5 must read the executor from PDK
`AuthenticationData`/contract context, **not** a caller-settable header; fail closed when P5 required and
no verified identity exists; any header-compat mode must be documented as chain-dependent with the exact
prerequisite policy named. CHANGELOG claims identity is "checked against the *verified* executor identity,
not a caller-asserted header." → Add a `FilterChainBuilder` test (auth → approval binding) proving spoofed
headers can't change the executor. Evidence-close.

**#7 — Narrow protocol claims / correct profiles.** Narrow v1 to an explicit **MCP `tools/call`
JSON-RPC** profile (the CHANGELOG already scopes to `tools/call`; every other method forwarded) **or** add
real versioned MCP/A2A v0.3/A2A v1 profiles. Ensure `assetTypes` advertises only implemented types; MCP
notifications get no response; `-32008` is **not** reused as a generic A2A denial. → Simplest honest path:
narrow to MCP-only, strip A2A/generic-API claims from metadata+docs, close with the claim diff. **Scope
decision — confirm with @msaleme.**

### aggregate-risk-gate — `aggregate-risk-gate/src/lib.rs`, `src/ledger.rs`, `definition/gcl.yaml`

These are the real engineering lift. Each issue offers an **implement** path and (mostly) a **narrow-the-
claim** path. Recommend bringing a combined plan to @msaleme before building, because the choice changes
the product story.

**#14 — Scope from trusted identity + bounded key cardinality.** Today scope keys come straight from a
configurable header (`x-agent-id`), unauthenticated, with unbounded map growth and raw identity echoed in
the client header. → Derive scope from verified PDK auth/context (or document a strip-and-inject gateway
sequence); canonicalize + length/cardinality/expiry-bound keys; stop echoing raw tenant/agent IDs (opaque
or keyed digest). Tests: spoofed/duplicate/mixed-case/oversized/high-cardinality/missing-identity.

**#15 — One durable windowed budget across workers/replicas.** Today it's an in-process
`Mutex<HashMap>` per instance; `window` is validated but never enforced. → Either implement a shared
durable ledger (PDK Data Storage CAS with bounded retries, atomic check-and-reserve) **and** real
fixed/rolling window accounting with fail-closed on storage error; **or** remove the inactive `window`
field and **rename** the policy to single-instance lifetime accounting and narrow all claims. Tests:
multi-instance shared store, concurrent reserve, restart, window boundary, rolling expiry, storage outage.

**#16 — Exchange metadata + publishable multi-instance integration tests.** GCL description is ~1,982
chars (limit 256); `metadata/capabilities/assetTypes` missing while P4A claims agent/API/LLM/MCP; Docker
tests were never actually executed. → Trim description to ≤256 (full text stays in README), declare only
**validated** asset types, make full asset generation + real Flex Gateway integration part of CI, add a
multi-instance shared-store scenario. (Tightly coupled to #15 — do them together.)

**#17 — Expiring, idempotent, crash-recoverable reservations.** Reservations have no ID/created-at/
deadline/state and only settle in the response hook; a cancelled request strands capacity. → Model
reservations as durable records (collision-resistant ID, TTL, state), idempotent commit/release, atomic
reclaim of expired in-flight reservations, telemetry for active/committed/released/expired/failed. Tests:
duplicate commit, duplicate release, commit-after-release, release-after-commit, expiry, late settlement,
cancellation, restart. (Depends on the storage model from #15.)

**#18 — Exact contribution units + token reconciliation.** Ledger uses `f64` for budgets/spend; token
mode commits `estimatedTokens` without reading actual usage. → Use exact bounded integer units (token
counts, fixed-weight points, minor-currency units or checked decimal); reject fractional/overflow/NaN/inf/
out-of-range at config+request boundaries; **either** reconcile tokens against authenticated actual usage
**or rename** the mode so it can't be mistaken for measured token cost (define over-estimate reconciliation
if true-up is implemented). Tests: decimal boundaries, cumulative rounding, overflow, batch totals, under/
over-estimation, missing/malformed actual usage.

---

## Suggested execution order

1. **approval-binding #1–#7 first** — fastest unblock; mostly evidence-close + small gaps. One PR can carry
   any residual code fixes; close each issue individually with its AC-mapped comment. This alone may be most
   of what Tommaso needs to resume.
2. **Bring @msaleme the aggregate-risk scope decision** (implement durable/windowed/exact vs. narrow the
   name & claims) *before* building #14–#18 — it determines whether this is a day or a week of work.
3. **aggregate-risk #14–#18** per the chosen path. #15/#16/#17 are coupled (shared durable storage) — plan
   them as one workstream; #14 and #18 are more self-contained.
4. After the last close, **comment on each policy's P4A entry** (or ping Tommaso in the DM) that all issues
   are resolved so he resumes the review.

## Definition of done

- All 12 issues (**#1–#7, #14–#18**) are **closed**, each with a substantiating comment (evidence map, PR
  reference, or claim diff).
- `origin/main` CI is green; no credentials in history (GitGuardian clean).
- Any connected-gateway test resources were deleted and deletion confirmed.
- `P4A-SUBMISSION.md`, `README.md`, both `gcl.yaml`, and the CHANGELOG state **only** guarantees backed by
  merged tests/evidence — no claim exceeds what shipped.
- A one-line status back to @msaleme listing each issue → how it closed.
