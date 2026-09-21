# Cross-Session Aggregate-Risk Gate

> Control pattern: **aggregate-risk containment** (reserve-then-authorize composition control) —
> the project's own term for the mechanism, not a primitive attributed to any framework below.
> NIST SP 800-53 Rev 5 **AC-4** (Information Flow Enforcement — the ledger is the enforcement
> point between an individually-valid call and the fabric's aggregate exposure), **SC-7**
> (Boundary Protection — the gateway is the trust boundary where the aggregate budget is checked),
> **AU-2** (Event Logging) and **AU-6** (Audit Review, Analysis, and Reporting — the running-total
> `resultHeader` and the startup/config log lines below), and **SI-4** (System Monitoring) resource-
> and-quota context. OWASP **LLM10:2025** (Unbounded Consumption). MITRE ATLAS (**AML.T0034 Cost
> Harvesting** / resource-hijacking design context — the composed-exhaustion scenario this policy
> closes) and MITRE Engage (the **Expose**/**Affect** vocabulary used for `monitor`/`block` below)
> as design context, not a detection-coverage claim. EU AI Act **Article 9** (risk management
> system) and **Article 15** (accuracy, robustness and cybersecurity — holding a shared budget
> under concurrency is a robustness property). AIUC-1 **Domain B** (security) and **Domain E**
> (accountability / logging).
>
> Every reference above is a supporting technical measure or a piece of enabling evidence toward
> the named control, article, or domain — **none of it is a certification**, and neither a single
> denial nor a passing test run establishes compliance on its own. Design context, not a compliance
> claim; see also the [MuleSoft PDK overview](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview).

## The customer need

A regulated or financial-flavored customer runs an Agent Fabric where brokers hold delegated
spending or data-access authority across many long-lived sessions. Their fear is not one bad
call — every call clears its own per-session cap. Their fear is the **totals**: individually
valid actions that compose, across sessions, past an exposure budget nobody ever handed to a
single decision. It is "death by a thousand authorized cuts" — slow spend drift, distributed
data pulls that sum to an exfiltration, a broker fleet that each stays under its limit while the
fabric as a whole blows the budget.

Per-call gates, rate limits, and per-session caps are structurally blind to this: each of them
only ever sees one call. The `authorized-but-composed` reference work
(`github.com/msaleme/authorized-but-composed`) reproduces the exact finding this policy exists
to close: five sessions of 800 each clear a per-session cap of 1,000, but compose to 4,000
against a 3,000 aggregate budget — and a naive running counter authorizes all five under
concurrency, because every concurrent reader checks the same pre-commit snapshot before anyone
writes. Only **reserve-then-authorize against a serialized ledger** holds the budget.

- **`monitor`** (Expose) — reserve, commit, and log the verdict every call would have received
  against `aggregateBudget`, but always forward the request regardless of composition. Use this to
  characterize how a fabric actually composes before switching anything to enforce.
- **`block`** (Affect) — deny a call whose contribution would push its scope's committed-plus-
  reserved exposure over `aggregateBudget` (per `onDeny`), even though the call is individually,
  locally valid and would have cleared any per-call cap on its own.

## What the policy enforces

On each governed call the policy:

1. **Computes** the call's exposure contribution — token cost, a spend amount read from the
   request body, or a fixed per-call weight (`contribution`).
2. **Reserves** that contribution against a ledger keyed by budget scope (per agent, per fabric,
   per tenant — `budgetScope`) *before* authorizing the call.
3. **Authorizes** only if committed-plus-reserved exposure for that scope, including this call's
   own contribution, stays within `aggregateBudget`; otherwise denies the composing call even
   though it is individually, locally valid (`mode: block`), or records it and forwards anyway
   so composition can be characterized with zero enforcement risk (`mode: monitor`).
4. **Commits** the reservation into the ledger's running total on a successful upstream response;
   **releases** it on an upstream failure, so a call that never completed does not consume
   exposure it never spent.

The reserve-then-authorize *order* is the whole point, and it is why this policy exists rather
than a cheaper read-then-write counter: under concurrency, a read-then-write counter lets every
caller check the same stale total before anyone writes, so N callers can all pass a check that
only one of them should have passed. Serializing the check-and-reserve into one atomic step is
what holds the budget — this is proven directly (see Testing, below) with a unit test that runs
both designs against the same concurrent load and shows the naive counter breach while the
reserve-then-authorize ledger holds.

## Inspection boundary

**What this policy reads.** On the request, exactly two things, both from the JSON-RPC body: the
envelope's `id`(s) (to echo the caller's own id on a `rpc-error` denial) and, when
`contribution=spend-amount`, the numeric value at `spendAmountField`. Alongside those, it reads the
one identity header configured by `scopeHeader` (for `agent`/`tenant` budget scope). It never reads
any other header, the query string, or the request/response path. **On the response, it reads
nothing but headers** — the status code (to decide commit vs. release) — and never the response
body; see the `contribution` and Honesty boundaries sections below for why a `token-cost`
reservation settles at its own pre-flight estimate rather than a real usage figure.

**Inspection exclusions.** A request body is inspected only if ALL of the following hold, checked
at the HEADER phase, before this policy ever buffers the body:

- **Size** — a declared `Content-Length` no larger than **64 KiB** (`MAX_INSPECT_BYTES`). A missing
  or non-numeric `Content-Length` is also excluded, since there is then no safe pre-buffering size
  check at all. (Defense in depth: even with a valid declared length, a body that turns out larger
  than 64 KiB once read is excluded the same way — a Content-Length that undersold the real size
  cannot smuggle an oversized body past this boundary.)
- **Content type** — `Content-Type` must be `application/json` or an `application/*+json` media
  type. This excludes **SSE/streaming** responses and requests (`text/event-stream` and similar),
  and any other non-JSON media type.
- **Compression** — any `Content-Encoding` at all excludes the body; this policy never
  decompresses, so a compressed body's real JSON content is opaque to it.
- **Encoding** — a body that is not valid UTF-8 fails JSON parsing (JSON is a UTF-8-only format),
  so a **non-UTF-8** body is excluded the same way an oversized one is, even though this specific
  case cannot be caught at the header phase.

A body excluded on any of these grounds is never buffered or read; it is treated as unpriceable —
fail-closed in `block` mode (denied, `onDeny` applies), recorded as zero contribution with the gap
flagged on the header in `monitor` mode (see the Configuration table below). None of this is a
security containment boundary the way a tripwire's would be — a call this policy cannot price has
an explicit, safe fallback, not a risk of missing a hidden secret — and none of it substitutes for
Flex/Gateway's own framing and buffering limits.

**Batch (array) requests.** A JSON-RPC batch is never priced as if it were a single call: under
`fixed-weight`/`token-cost` its per-item weight/estimate is multiplied by the number of items in the
array; under `spend-amount` every item's amount is read and summed, and the whole batch fails closed
if any single item is unpriceable. A batch denied for exceeding budget is refused atomically — never
split so that some items land while others don't — and, in `rpc-error` mode, gets back a JSON array
with one `-32008` error per id, echoing every id in the batch.

## Configuration

| Field | Type | Default | Purpose |
|---|---|---|---|
| `budgetScope` | `agent`\|`fabric`\|`tenant` | `agent` | The aggregation dimension. `agent`/`tenant` — one running total per identity value read from `scopeHeader` (a broker session's fleet, or a tenant/org). `fabric` — one running total shared across every request this instance sees, ignoring `scopeHeader`. Ledger key is `"<budgetScope>:<value>"` (`fabric` uses a fixed value). |
| `scopeHeader` | string | `x-agent-id` | Request header carrying the identity value used to key the ledger when `budgetScope` is `agent` or `tenant`. Ignored for `fabric`. Missing when required: fails closed in `block` mode; recorded under a fixed `(missing)` key in `monitor` mode so the gap is visible rather than silently dropped. |
| `aggregateBudget` | number | `3000` | The exposure budget for the scope's current window, in `contribution`'s units. A call is authorized only if committed-plus-reserved exposure for its scope, including its own contribution, would not exceed this. |
| `window` | string | `rolling-24h` | The accounting window `aggregateBudget` nominally applies to. **Accepted but not enforced at Stage A** — see Honesty boundaries below; the ledger accumulates for the life of the gateway worker process, not a real window. |
| `contribution` | `token-cost`\|`spend-amount`\|`fixed-weight` | `fixed-weight` | How the call's contribution is computed. `fixed-weight` — static, from `fixedWeight`. `spend-amount` — numeric field read from the request body at `spendAmountField`. `token-cost` — reserved as `estimatedTokens` before authorizing, then **committed at that same estimate** on a successful response (this build's response handling is headers-only and never reads the response body for a real `usage.total_tokens` figure — see Honesty boundaries below). A JSON-RPC **batch** (array) request's per-item contribution is multiplied/summed across every item, never priced as a single call. |
| `fixedWeight` | number | `1` | Per-call contribution when `contribution=fixed-weight`. |
| `spendAmountField` | string | `params.amount` | Dot-separated path into the parsed JSON-RPC request body read for the numeric spend amount when `contribution=spend-amount`. Missing/unparseable/non-numeric: unpriceable — denied in `block` mode, recorded as zero in `monitor` mode. |
| `estimatedTokens` | number | `500` | Pre-flight reservation estimate (tokens) when `contribution=token-cost`. Set to a conservative upper bound for the traffic this instance governs — this build commits the estimate itself on success (see `contribution` above), so an estimate set too low under-counts real exposure; released outright on upstream failure. |
| `ledgerEndpoint` | string | `""` | **Reserved for Stage B, NOT implemented.** Accepted and validated (a non-empty value is logged as a forward-compatibility notice) but every decision in this build is made by the in-process Stage A ledger regardless of this value. Leave empty. |
| `mode` | `monitor`\|`block` | `monitor` | `monitor` — reserve, commit, and log the verdict every call would have received, but always forward the request regardless of budget; a call that composes past budget still signals a policy violation even though it is forwarded. `block` — deny a call whose contribution would push its scope over `aggregateBudget`, per `onDeny`, and signal a policy violation on that denial. |
| `onDeny` | `rpc-error`\|`empty-403` | `rpc-error` | How a `block`-mode denial is rendered. `rpc-error` — in-band JSON-RPC response reusing the request's own id(s), error code `-32008`, message naming the scope and the budget that would be exceeded (never other sessions' call content); a denied **batch** gets back a matching JSON array with one `-32008` error per id, never a single collapsed error. `empty-403` — HTTP 403, empty body, no JSON-RPC envelope. Either way: a request the policy cannot confidently parse as JSON-RPC with echoable id(s) — including a body with a duplicate JSON object member, where this policy and the upstream tool could legitimately disagree about which id is "the" id — always falls back to `empty-403`; a JSON-RPC notification (no id) always gets an empty HTTP 202 on deny (JSON-RPC forbids responding to a notification). |
| `resultHeader` | string | `x-aggregate-risk-gate` | Header stamped on the **client-facing response** recording the verdict and the running total, e.g. `allowed;scope=agent:broker-7;contribution=800.00;total=2400.00/3000.00` or, on denial, `denied;scope=agent:broker-7;would-be-total=3200.00;budget=3000.00`. Never carries other sessions' call content — only the scope key and numeric totals — so it is safe to forward to downstream logging, SIEM, or a Kill Switch without a further redaction pass. |

```yaml
- policyRef:
    name: aggregate-risk-gate-v1-0-impl
  config:
    budgetScope: agent
    scopeHeader: x-agent-id
    aggregateBudget: 3000
    window: rolling-24h
    contribution: fixed-weight
    fixedWeight: 800
    spendAmountField: params.amount
    estimatedTokens: 500
    ledgerEndpoint: ""
    mode: block
    onDeny: rpc-error
    resultHeader: x-aggregate-risk-gate
```

Reproducing the reference scenario against this config: five 800-unit calls from the same
`x-agent-id` — the first three commit (running total 2400/3000); the fourth is refused in-band
as a JSON-RPC `-32008` error naming a would-be total of 3200/3000; the fifth is refused the same
way. A different `x-agent-id` gets its own independent 3000-unit budget.

On the fourth (denied) call above, the client-facing response carries, e.g.
`x-aggregate-risk-gate: denied;scope=agent:broker-7;would-be-total=3200.00;budget=3000.00`. On an
allowed call it instead carries, e.g.
`x-aggregate-risk-gate: allowed;scope=agent:broker-7;contribution=800.00;total=2400.00/3000.00`.
Neither format carries another session's call content — only the scope key and the numeric
totals — so both are safe to forward downstream to logging, SIEM, or a Kill Switch without a
further redaction pass. At policy start-up the gateway log separately carries a plain diagnostic
line naming the armed configuration, e.g.
`Aggregate Risk Gate armed: budgetScope=agent, aggregateBudget=3000, contribution=fixed-weight, mode=block`
— a one-time informational line, not a per-call structured event; the `resultHeader` above is the
per-call decision record.

## Honesty boundaries (Stage A vs. Stage B)

This build ships **Stage A**: a real, atomic, in-process reserve-then-authorize ledger, scoped to
a single gateway worker, backed by a mutex-serialized map keyed by budget scope. It is genuinely
race-safe — the concurrent-admission unit test proves it holds the budget under contention where
a naive read-then-write counter breaches — but it is **one serialization point in one worker
process**, not a distributed, multi-region, or replay-consistent ledger, and it makes no
cryptographic non-repudiation claim over its decisions. Concretely:

- **No cross-worker/cross-region consistency.** If the gateway runs multiple worker processes or
  instances fronting the same fabric, each gets its *own* Stage A ledger and its own independent
  view of a scope's total — the aggregate budget is only truly aggregate within one worker.
- **`ledgerEndpoint` is a reserved, unimplemented Stage B field.** A distributed ledger service
  this policy calls out to instead of its in-process map is unshipped roadmap work. Setting this
  field to a non-empty URL changes nothing about how decisions are made today.
- **`window` is accepted but not enforced.** The Stage A ledger has no notion of time or expiry —
  a scope's exposure accumulates for the life of the running worker process, not for a rolling or
  fixed accounting window. Real per-window expiry needs a clock-driven eviction policy against a
  real distributed store, not a per-request approximation; it is Stage B roadmap work.
- **`token-cost` contribution is estimate-then-SETTLE, not estimate-then-reconcile, and pre-flight
  token cost is not exactly known.** The reservation made before authorizing a token-cost call is
  `estimatedTokens`, a configured upper bound. This build's response leg is strictly headers-only
  (see Inspection boundary above) — it never buffers or reads the response body, so it never learns
  a real `usage.total_tokens` figure to true up against. On a successful response the reservation is
  therefore **committed at the estimate itself**, unchanged (or released outright on failure). This
  is a more conservative behavior than a real reconcile would be, not a softer one: set the estimate
  conservatively for the traffic this instance governs, since it is what actually lands in the
  ledger, not a placeholder for something more accurate arriving later.
- **No signed decision records.** Every ledger operation happens in-process and is not
  independently attestable outside this policy's own process; this build makes no claim that its
  admit/deny decisions are cryptographically non-repudiable.

A distributed, replay-consistent ledger with signed decision records — matching the full model in
the `authorized-but-composed` reference work — is Stage B: real, valuable, and **not implemented
here**. Do not present this build as shipping it.

## Testing

`cargo +1.89.0 test --lib --locked --offline` runs 74 tests, none of which touch the network or
Docker:

- **`src/ledger.rs` — the pure decision engine** (no PDK dependency, 27 tests): correctness of
  `reserve`/`force_reserve`/`force_reserve_checked`/`commit`/`release`/`record`/`reconcile`/`snapshot`
  in isolation, plus two concurrency tests that are the load-bearing proof for this whole policy —
  `naive_counter_breaches_budget_under_concurrency` (a read-then-write counter admits 5 concurrent
  800-unit calls against a 3000 budget, breaching to 4000) and
  `reserve_then_authorize_holds_budget_under_concurrency` (the real ledger, same concurrent load,
  admits exactly 3 of 5, holding at 2400) — reproducing both the sequential-composition and the
  race scenario from `authorized-but-composed`, plus a broader multi-scope stress variant
  (`reserve_then_authorize_never_exceeds_budget_across_many_concurrent_scopes`). These two headline
  tests, and every other test in this file, are never weakened or skipped — they are the correctness
  proof this whole policy exists to make.
- **`src/lib.rs` — the PDK filter**, exercised end to end through the `pdk-unit` harness (27 tests,
  from `sequential_composition_through_the_real_filter_refuses_the_fourth_call` on): per-mode
  behavior (`monitor` never denies; `block` denies past budget), both `onDeny` renderings and their
  JSON-RPC-notification/non-JSON-RPC fallbacks, all three `contribution` modes including the
  unpriceable and estimate-then-settle edge cases, independent per-scope budgets, the missing-
  scope-header path in both modes, and that the `resultHeader` stamp lands on the client-facing
  response (not the upstream request) in both the allow and deny paths. Also:
  - **Batch (array) accounting** — an over-budget batch is denied atomically with one `-32008`
    error per id (`an_over_budget_batch_is_denied_atomically_with_one_error_per_id`), a
    within-budget batch commits the FULL per-item contribution
    (`a_within_budget_batch_commits_the_full_per_item_contribution`), and `spend-amount` batches
    both sum correctly and fail closed on any single unpriceable item.
  - **Id-echo containment** — a body with a duplicate JSON object member falls back to an empty
    `403` echoing no id at all, even though the underlying denial is a genuine budget-exceeded one
    (`a_duplicate_json_member_falls_back_to_empty_403_without_echoing_any_id`).
  - **PolicyViolations signaling** — a block-mode budget-exceeded denial and a monitor-mode
    over-budget-but-forwarded call both set a policy violation; an admitted call under either mode
    does not.
  - **Response leg is headers-only** — a 10x-oversized response body is never buffered and the
    `resultHeader` still lands (`a_large_response_body_is_never_buffered_and_the_header_still_lands`),
    and a `token-cost` call commits its full pre-flight estimate rather than a smaller real usage
    figure the response body is never read to find
    (`token_cost_contribution_commits_the_full_estimate_and_never_reads_the_response_body`).
- **Direct `Gate::from_config` validation tests** (16): every config-validation rejection path
  (invalid enum values including `window`, non-finite/negative numeric fields, blank required
  strings) and the corresponding accepted cases.
- **`dot_path_value` unit tests** (4): the dotted-path body reader used for `spend-amount`.

`tests/requests.rs` holds two `pdk_test` integration tests that run the same
sequential-composition and independent-scope scenarios through a real, containerized Flex
Gateway — but Docker-based integration coverage was explicitly **out of scope** for this build's
required verification gate (`fmt --check` / `clippy --lib` / `test --lib`, all of which are
native and none of which touch this file), so these were written and confirmed to compile
(`cargo test --no-run`) but were not executed against a live container in this environment.

---

This policy was created with the Flex Gateway Policy Development Kit (PDK). To find the complete PDK documentation, see [PDK Overview](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview) on the Mulesoft documentation site.


## Make command reference
This project has a Makefile that includes different goals that assist the developer during the policy development lifecycle.

*For more information about the Makefile, see [Makefile](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-project#makefile).*

### Setup
The `make setup` goal installs the Policy Development Kit internal dependencies for the rest of the Makefile goals.

*For more information about `make setup`, see [Setup the PDK Build environment](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-project#setup-the-pdk-build-environment).*

### Build asset files
The `make build-asset-files` goal generates all the policy asset files required to build, execute, and publish the policy. This command also updates the `config.rs` source code file with the latest configurations defined in the policy definition.

*For more information about creating a policy definition, see [Defining a Policy Schema Definition](https://docs.mulesoft.com/pdk/latest/policies-pdk-create-schema-definition).*

*For more information about `make build-asset-files`, see [Compiling Custom Policies](https://docs.mulesoft.com/pdk/latest/policies-pdk-compile-policies).*

### Build
The `make build` goal compiles the WebAssembly binary of the policy.
Since the source code must be in sync with the policy definition configurations, this goal runs the `build-asset-files` before compiling.

*For more information about `make build`, see [Compiling Custom Policies](https://docs.mulesoft.com/pdk/latest/policies-pdk-compile-policies).*

### Run
The `make run` goal provides a simple way to execute the current build of the policy in a Docker containerized environment. In order to run this goal, the `playground/config` directory must contain a set of files required for executing the policy in a Flex Gateway instance:
- A `registration.yaml` generated for a **local, disposable** Flex Gateway registration. It contains client-identity material: keep it untracked, do not copy it between projects or machines, and never commit it. If no local registration is available, treat Docker runtime verification as blocked rather than replacing it with a self-signed certificate or claiming a runtime pass.
Otherwise, to complete the registration we recommend using the Anypoint Platform:
    1. Go to `Runtime Manager`
    2. Navigate to the `Flex Gateway` tab
    3. Click the `Add Gateway` button
    4. Select `Docker` as your OS and copy the registration command replacing `--connected=true` to `--connected=false`.
    5. Paste the command and run it in the `playground/config` directory.

- An `api.yaml` file updated with the desired policy configuration. This file also supports adding other policies to be applied along the one being developed.

The `playground/config` directory can also contain other resource definitions, such as accessory services used by the policy (Eg. a remote authentication service).

*For more information about `make run`, see [Debugging Custom Policies Locally with PDK](https://docs.mulesoft.com/pdk/latest/policies-pdk-debug-local).*

### Test
The `make test` goal runs unit tests and integration tests. Integration tests are placed in the `tests` directory and are configured with the files placed at the
`tests/<module-name>/<test-name>` directory.

*For more information about writing integration tests, see [Writing Integration Tests](https://docs.mulesoft.com/pdk/latest/policies-pdk-integration-tests).*

### Publish
The `make publish` goal publishes the policy asset in Anypoint Exchange, in your configured Organization.

Since the publish goal is intended to publish a policy asset in development, the _assetId_ and name published will explicitly say `dev`, and the versions published will include a timestamp at the end of the version. Eg.
- groupId: your configured organization id
- visible name: _{Your policy name} Dev_
- assetId: _{your-policy-asset-id}-dev_
- version: _{your-policy-version}-20230618115723_

*For more information about publishing policies, see [Uploading Custom Policies to Exchange](https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies).*

### Release
The `make release` goal also publishes the policy to Anypoint Exchange, but as a ready for production asset. In this case, the groupId, visible name, assetId and version will be the ones defined in the project.

*For more information about releasing policies, see [Uploading Custom Policies to Exchange](https://docs.mulesoft.com/pdk/latest/policies-pdk-publish-policies).*


### Policy Examples

The PDK provides provides a set of example policy projects to get started creating policies and using the PDK features. To learn more about these examples see [Custom policy Examples](https://docs.mulesoft.com/pdk/latest/policies-pdk-policy-templates).
