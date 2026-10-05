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

> **The budget is per gateway replica, and a restart resets it.** With the default
> `ledgerBackend: node`, every Envoy worker of one gateway replica checks and reserves against one
> shared ledger in the gateway's node-local data, so opening more connections does not multiply the
> budget on that replica. Replicas still hold independent budgets: with `R` replicas a scope can
> spend up to `R × aggregateBudget`, so divide the intended total by `R`, or run one replica. The
> ledger is not durable: a gateway process restart starts every scope again at zero.
> `ledgerBackend: worker` keeps the older per-worker ledger, which a caller *can* multiply across
> the `N` workers of each replica (up to `N × R × aggregateBudget`); with that backend, set
> `FLEX_SERVICE_ENVOY_CONCURRENCY=1` or divide by `N × R`. See Scope of the guarantee below.

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

A **governed call** is a JSON-RPC request whose `method` is listed in `governedMethods` (default
`["tools/call"]`). Everything else passes untouched (see Applicability below). On each governed
call the policy:

1. **Computes** the call's exposure contribution as an exact integer — an estimated-token weight,
   a spend amount in currency minor units read from the request body, or a fixed per-call weight
   (`contribution`). See Units below.
2. **Reserves** that contribution against a ledger keyed by budget scope (per agent, per fabric,
   per tenant — `budgetScope`) *before* authorizing the call.
3. **Authorizes** only if committed-plus-reserved exposure for that scope, including this call's
   own contribution, stays within `aggregateBudget`; otherwise denies the composing call even
   though it is individually, locally valid (`mode: block`), or records it and forwards anyway
   so composition can be characterized with zero enforcement risk (`mode: monitor`).
4. **Commits** the reservation into the ledger's running total on a successful upstream response;
   **releases** it on an upstream failure, so a call that never completed does not consume
   exposure it never spent. Success and failure are decided by the HTTP status alone: **2xx and
   3xx commit, 4xx and 5xx release.** The response body is never read, so a JSON-RPC `error`
   response or a tool result with `"isError": true` that arrives inside an HTTP 200 **is
   charged**. Size budgets on the assumption that a failed tool call can still cost its full
   contribution. Settlement is by reservation id and happens at most once. A reservation whose
   response never arrives is reclaimed after `reservationTimeoutMs` (see Reservation lifecycle
   below).

The reserve-then-authorize *order* is the whole point, and it is why this policy exists rather
than a cheaper read-then-write counter: under concurrency, a read-then-write counter lets every
caller check the same stale total before anyone writes, so N callers can all pass a check that
only one of them should have passed. Serializing the check-and-reserve into one atomic step is
what holds the budget — this is proven directly (see Testing, below) with a unit test that runs
both designs against the same concurrent load and shows the naive counter breach while the
reserve-then-authorize ledger holds.

## Applicability and Exchange listing

The Exchange listing carries only the short `metadata.labels.description` in
`definition/gcl.yaml` (Exchange caps it at 256 characters). This README is the full explanation.

| Label | Value | Meaning |
|---|---|---|
| `metadata/capabilities/assetTypes` | `mcp` | Attaches to MCP server instances only. |
| `metadata/capabilities/injectionPoint` | `inbound` | Runs on the request path, before the upstream. |
| `metadata/interfaceScope` | `api,resource` | Applies to a whole API instance or to selected resources. |

MCP is the only target declared because it is the only one this build's tests cover: every
filter test drives JSON-RPC 2.0 request bodies, and denials render as JSON-RPC `-32008` errors. An
earlier draft also claimed agent-to-agent and model-proxy instances. Neither was ever tested, so
neither is declared. Adding either one back needs its own test coverage first.

On an MCP instance this policy prices only the methods listed in `governedMethods`, by default
`tools/call`. Every other message is **ungoverned**: it is forwarded with no ledger or scope change
and its response is stamped `pass;reason=ungoverned-method`. Ungoverned means any of:

- a request or notification whose `method` is not listed, such as `initialize`,
  `notifications/initialized`, `ping`, `tools/list` or `notifications/cancelled`;
- a JSON-RPC response sent by the client, such as an elicitation or sampling reply;
- a request with no body, such as the `GET` that opens a server stream or the `DELETE` that ends
  a session.

So **an exhausted budget never blocks session setup, discovery, keep-alive, cancellation or
teardown.** It only refuses further `tools/call` requests. Ungoverned traffic is classified before
identity is read, so it passes even without an identity.

Matching is exact and case-sensitive: `Tools/Call` is not `tools/call`. A message that cannot be
classified stays governed and fails closed in `block` mode. That covers a body over the inspection
limit, a declared `charset` other than UTF-8, a body this policy cannot parse as JSON, a batch item that is not an object, an item without `"jsonrpc": "2.0"`, a
non-string `method`, and a body with a duplicate `method` (or any other duplicate) member, where
this policy and the upstream could disagree about which method is the real one. A governed method
sent as a notification is still governed.

`governedMethods` must be a non-empty list with no blank, whitespace-padded or duplicate entries.
There is no wildcard: `"*"` is rejected at configure time, so pricing every method means listing
each one. Listing `initialize` or a `notifications/*` method is allowed but logs a warning at
configure time, because it lets an exhausted budget block session setup or cancellation.

`scripts/check_exchange_metadata.py` (repo root) enforces all of this. It rejects a description
over 256 characters, placeholder text, an undeclared or untested asset type, and a
`P4A-SUBMISSION.md` applicability line that disagrees with `gcl.yaml`. With `--assets` it also
checks the files `make build` generates: a real org UUID in `exchange.json`, `minRuntimeVersion
1.14.0`, and generated definition labels identical to the source.

## Inspection boundary

**What this policy reads.** On the request, exactly three things, all from the JSON-RPC body: the
envelope's `method` (to decide whether the call is governed), its `id`(s) (to echo the caller's own
id on a `rpc-error` denial) and, when `contribution=spend-amount`, the integer value at
`spendAmountField`. Alongside those, for
`agent`/`tenant` budget scope, it reads the call's identity: by default the verified
`AuthenticationData` an upstream authentication policy attached (see Identity below), or, only when
`identitySource=trusted-header`, the one header named by `scopeHeader`. It never reads any other
header, the query string, or the request/response path. **On the response, it reads
nothing but headers** — the status code (2xx/3xx commit, 4xx/5xx release) — and never the
response body, so a JSON-RPC error inside an HTTP 200 is charged; see the `contribution` and Scope of the guarantee sections below for why an
`estimated-token-weight` reservation settles at its own pre-flight estimate rather than a real usage figure.

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
- **Charset** — the `Content-Type` must carry no `charset` parameter, or `charset=utf-8`
  (case-insensitive, optionally quoted). Any other charset, or a malformed `charset` parameter,
  excludes the body. This policy reads the body as UTF-8, but an upstream MCP server may decode it
  with the declared charset. Under `charset=utf-7`, `"method":"tools+AC8-call"` reads here as an
  unlisted method while the upstream decodes it to `tools/call`; excluding the body keeps that
  call governed and fail-closed instead of letting it pass as ungoverned.
- **Compression** — any `Content-Encoding` at all excludes the body; this policy never
  decompresses, so a compressed body's real JSON content is opaque to it.
- **Encoding** — a body that is not valid UTF-8 fails JSON parsing (JSON is a UTF-8-only format),
  so a **non-UTF-8** body is excluded the same way an oversized one is, even though this specific
  case cannot be caught at the header phase. The same holds for any body this policy's JSON parser
  rejects, such as a leading byte-order mark, a lone UTF-16 surrogate escape, or nesting deeper
  than 128 levels: another parser upstream may still accept it, possibly as a batch of many
  calls, so it is never priced as a single call.

A body excluded on any of these grounds is never buffered or read, so its method is unknown; it is
treated as governed and unpriceable —
fail-closed in `block` mode (denied, `onDeny` applies), recorded as zero contribution with the gap
flagged on the header in `monitor` mode (see the Configuration table below). None of this is a
security containment boundary the way a tripwire's would be — a call this policy cannot price has
an explicit, safe fallback, not a risk of missing a hidden secret — and none of it substitutes for
Flex/Gateway's own framing and buffering limits.

**Batch (array) requests.** A JSON-RPC batch is never priced as if it were a single call, and only
its governed items are priced: under `fixed-weight`/`estimated-token-weight` the per-item
weight/estimate is multiplied by the number of governed items; under `spend-amount` every governed
item's amount is read and summed, and the whole batch fails closed if any governed item is
unpriceable. A batch with no governed items is ungoverned and passes uncharged. A batch denied for
exceeding budget is refused atomically — never split so that some items land while others don't —
and, in `rpc-error` mode, gets back a JSON array with one `-32008` error per request id in the
batch, ungoverned requests included, since none of the batch is forwarded. Response items in a
batch have no request id to answer and are not echoed.

## Configuration

| Field | Type | Default | Purpose |
|---|---|---|---|
| `budgetScope` | `agent`\|`fabric`\|`tenant` | `agent` | The aggregation dimension. `agent`/`tenant` — one running total per canonical identity (see Identity below). `fabric` — one running total shared across every request this instance sees, ignoring identity. Ledger key is `"<budgetScope>:<canonical identity>"` (`fabric` uses a fixed value). |
| `identitySource` | `authentication`\|`trusted-header` | `authentication` | Where the identity comes from. `authentication` — the verified `AuthenticationData` set by an authentication policy (Client ID Enforcement, JWT Validation, OAuth introspection) that runs **before** this one. `trusted-header` — the `scopeHeader` value, which this policy cannot verify; use it only behind a chain that strips and re-injects that header (see Identity below). Ignored for `fabric`. |
| `identityField` | `client_id`\|`principal`\|`properties.<path>` | `client_id` | Which `AuthenticationData` field identifies the caller when `identitySource=authentication`. `properties.<path>` reads a dot path into the authentication properties (for example a JWT claim); the value must be a string. |
| `scopeHeader` | string | `x-agent-id` | Header carrying the identity when `identitySource=trusted-header`; must be non-blank in that mode, ignored otherwise. Matched case-insensitively. A header sent more than once is invalid. |
| `ledgerBackend` | `node`\|`worker` | `node` | Where the ledger lives. `node` — one ledger per policy instance per gateway replica, in the gateway's node-local shared data, shared by all its Envoy workers; every write is a bounded compare-and-swap (see Scope of the guarantee). `worker` — one in-memory ledger per Envoy worker, as in earlier builds; a caller can multiply it across workers. `cluster` (one budget across replicas) is **not implemented** and is rejected at configure time, as is any other value. |
| `ledgerNamespace` | string, empty or 1–64 of `A–Z a–z 0–9 . _ -` | `""` | Empty — the node ledger is private to this policy instance. Set — the ledger is stored under that name, so every instance on the replica configured with the same namespace (and the same `scopeDigestKey`) shares one budget per scope. Requires `ledgerBackend: node`. |
| `maxScopes` | integer, `1`–`1000000` | `10000` | Most scopes the ledger tracks at once (per worker for `worker`, per replica for `node`). At the cap a new scope may take the place of an idle scope (nothing committed or reserved). If none is idle the call is denied in `block` mode with `reason=scope-capacity`, or forwarded in `monitor` mode with that reason stamped. Live totals are never evicted. A refusal at the cap costs constant work, however many scopes are live (see Identity below). |
| `reservationTimeoutMs` | integer, `1000`–`86400000` | `60000` | How long a reservation may stay unsettled before it is reclaimed and its budget freed. Set it above the longest upstream timeout. See Reservation lifecycle below. |
| `scopeDisclosure` | `digest`\|`none`\|`raw` | `digest` | How the scope appears in `resultHeader` and denial messages. `digest` — `<budgetScope>:hmac-<16 hex>` (HMAC-SHA256 under `scopeDigestKey`, first 8 bytes), or `sha256-…` when no key is set. `none` — just `<budgetScope>`. `raw` — the canonical identity itself; only for trusted, internal consumers. |
| `scopeDigestKey` | string (sensitive) | `""` | HMAC key for `scopeDisclosure=digest` and, with `ledgerBackend: node`, for the shared-data ledger keys. Without a key the digest is a plain SHA-256 and the ledger keys an unkeyed HMAC, which anyone holding a candidate identity can recompute; the empty default is kept so the default configuration starts, and a warning is logged at startup. Set it from a secret. Changing it gives every identity a fresh budget (see Known edges). |
| `aggregateBudget` | integer, `0`–`9007199254740991` | `3000` | The exposure budget for the scope's current window, in `contribution`'s units (see Units below). A call is authorized only if committed-plus-reserved exposure for its scope, including its own contribution, would not exceed this. |
| `window` | `fixed-period`\|`worker-lifetime` | `fixed-period` | How long committed exposure counts. `fixed-period` resets every scope's committed total at each `windowMs` boundary, counted from the Unix epoch, so 24-hour windows start at 00:00 UTC. `worker-lifetime` never resets. See Accounting window below. With the node backend, changing `window` or `windowMs` starts a fresh ledger. The old value `rolling-24h` never rolled and is now rejected at configure time. |
| `windowMs` | integer, `60000`–`31622400000` | `86400000` | Window length in ms for `fixed-period` (1 minute to 366 days). Ignored for `worker-lifetime`. |
| `contribution` | `estimated-token-weight`\|`spend-amount`\|`fixed-weight` | `fixed-weight` | How the call's contribution is computed. `fixed-weight` — static, from `fixedWeight`. `spend-amount` — integer minor units read from the request body at `spendAmountField`. `estimated-token-weight` — reserved as `estimatedTokens` before authorizing, then **committed at that same estimate** on a successful response (this build's response handling is headers-only and never reads the response body for a real `usage.total_tokens` figure — see Scope of the guarantee below). This mode was called `token-cost` in earlier drafts; that name is now rejected at configure time, because the mode charges a fixed estimate and never measures a cost. A JSON-RPC **batch** (array) request's per-item contribution is multiplied/summed across every governed item, never priced as a single call. |
| `fixedWeight` | integer, `0`–`9007199254740991` | `1` | Per-call contribution when `contribution=fixed-weight`. |
| `governedMethods` | list of strings | `["tools/call"]` | The JSON-RPC methods this policy prices and enforces, matched exactly and case-sensitively. All other traffic is forwarded uncharged and stamped `pass;reason=ungoverned-method` (see Applicability above). Must be non-empty with no blank, padded or duplicate entries; `"*"` is rejected. |
| `spendAmountField` | string | `params.amount` | Dot-separated path into the parsed JSON-RPC request body read for the spend amount when `contribution=spend-amount`. Only governed requests are read. The value must be a JSON integer count of minor units (`1234` = 12.34 USD). Missing, unparseable, a fraction (`12.34`), a float-shaped integer (`1234.0`), an exponent (`1e3`), negative, a string, or too large for a u64: unpriceable. Above `9007199254740991`, or a batch that sums past it: out of range. Both are denied in `block` mode and recorded as zero in `monitor` mode. |
| `spendCurrency` | string, ISO 4217 | `USD` | Currency of `spend-amount` values: three uppercase letters, with amounts in that currency's ISO 4217 minor unit. Stamped into `resultHeader` as `unit=<code>-minor`. The policy does no currency conversion. |
| `estimatedTokens` | integer, `0`–`9007199254740991` | `500` | Pre-flight reservation estimate (tokens) when `contribution=estimated-token-weight`. Set to a conservative upper bound for the traffic this instance governs — this build commits the estimate itself on success (see `contribution` above), so an estimate set too low under-counts real exposure; released outright on upstream failure. |
| `mode` | `monitor`\|`block` | `monitor` | `monitor` — reserve, commit, and log the verdict every call would have received, but always forward the request regardless of budget; a call that composes past budget still signals a policy violation even though it is forwarded. `block` — deny a call whose contribution would push its scope over `aggregateBudget`, per `onDeny`, and signal a policy violation on that denial. In both modes a reservation commits on HTTP 2xx/3xx and releases on 4xx/5xx; a JSON-RPC error inside an HTTP 200 is charged. |
| `onDeny` | `rpc-error`\|`empty-403` | `rpc-error` | How a `block`-mode denial is rendered. `rpc-error` — in-band JSON-RPC response reusing the request's own id(s), error code `-32008`, message naming the scope and the budget that would be exceeded (never other sessions' call content); a denied **batch** gets back a matching JSON array with one `-32008` error per id, never a single collapsed error. `empty-403` — HTTP 403, empty body, no JSON-RPC envelope. Either way: a request the policy cannot confidently parse as JSON-RPC with echoable id(s) — including a body with a duplicate JSON object member, where this policy and the upstream tool could legitimately disagree about which id is "the" id — always falls back to `empty-403`; a JSON-RPC notification (no id) always gets an empty HTTP 202 on deny (JSON-RPC forbids responding to a notification). |
| `resultHeader` | string | `x-aggregate-risk-gate` | Header stamped on the **client-facing response** recording the verdict and the running total, e.g. `allowed;scope=agent:sha256-b534199b5ab2d7a9;contribution=800;total=2400/3000;unit=points` or, on denial, `denied;scope=agent:sha256-b534199b5ab2d7a9;would-be-total=3200;budget=3000;unit=points` (the `scope=` form follows `scopeDisclosure`). Calls that are not priced carry `reason=` instead of totals: `missing-identity`, `invalid-identity`, `scope-capacity`, `scope-saturated`, `ledger-contention`, `ledger-unavailable`, `unpriceable`, or `out-of-range`. Ungoverned traffic carries `pass;reason=ungoverned-method`. Never carries other sessions' call content, and by default never the raw identity. |

```yaml
- policyRef:
    name: aggregate-risk-gate-v1-0-impl
  config:
    budgetScope: agent
    identitySource: authentication
    identityField: client_id
    scopeHeader: x-agent-id
    ledgerBackend: node
    ledgerNamespace: ""
    maxScopes: 10000
    reservationTimeoutMs: 60000
    scopeDisclosure: digest
    scopeDigestKey: ""        # set from a secret; see scopeDigestKey above
    aggregateBudget: 3000
    window: fixed-period
    windowMs: 86400000
    contribution: fixed-weight
    fixedWeight: 800
    governedMethods:
      - tools/call
    spendAmountField: params.amount
    spendCurrency: USD
    estimatedTokens: 500
    mode: block
    onDeny: rpc-error
    resultHeader: x-aggregate-risk-gate
```

Reproducing the reference scenario against this config: five 800-unit calls from the same
authenticated client (`client_id` `broker-7` in the stamps below; with `scopeDigestKey` empty the
digest is the first 8 bytes of SHA-256 over `agent:broker-7`) — the first three commit (running total 2400/3000); the fourth is refused
in-band as a JSON-RPC `-32008` error naming a would-be total of 3200/3000; the fifth is refused the
same way. A different client gets its own independent 3000-unit budget. Changing a request header
does not: the header is not an identity in this mode.

On the fourth (denied) call above, the client-facing response carries, e.g.
`x-aggregate-risk-gate: denied;scope=agent:sha256-b534199b5ab2d7a9;would-be-total=3200;budget=3000;unit=points`. On
an allowed call it instead carries, e.g.
`x-aggregate-risk-gate: allowed;scope=agent:sha256-b534199b5ab2d7a9;contribution=800;total=2400/3000;unit=points;settlement=committed`.
The `settlement=` field says what the response did to the reservation (see Reservation lifecycle).
Neither format carries another session's call content or the raw identity — only a stable
digest and the numeric totals — so both are safe to forward downstream to logging, SIEM, or a
Kill Switch. The gateway log never carries an identity. At policy start-up the gateway log separately carries a plain diagnostic
line naming the armed configuration, e.g.
`Aggregate Risk Gate armed: budgetScope=agent, aggregateBudget=3000, contribution=fixed-weight, mode=block`
— a one-time informational line, not a per-call structured event; the `resultHeader` above is the
per-call decision record.

## Identity

The budget is only as strong as the identity it is keyed on. If a caller can pick its own
identity, it can mint a fresh budget per call. So by default (`identitySource=authentication`) the
identity is the verified `AuthenticationData` that an authentication policy earlier in the chain
attached. Client ID Enforcement sets `client_id`; JWT Validation and OAuth introspection set
`principal` and `properties`. **Order the authentication policy before this one.** With no
authentication data the call is `missing-identity`: denied in `block` mode.

`identitySource=trusted-header` keys on `scopeHeader` instead. This policy cannot verify a header,
so this mode is safe only when the chain in front of it guarantees the value:

1. a header-removal policy strips any client-sent `scopeHeader`, then
2. a policy that has verified the caller (for example a DataWeave headers transformation reading
   the authentication data) injects it, then
3. this policy runs.

Without that chain any client can set the header, and the budget is advisory.

Every identity is canonicalized before it keys the ledger: leading and trailing spaces and tabs
are trimmed and ASCII letters are lowercased, so `Broker-7`, `broker-7` and ` BROKER-7 ` share one
budget. Case folding can only merge budgets, never split one. An identity is `invalid-identity`
when it is longer than 256 bytes, contains anything outside visible ASCII, or contains a stamp
delimiter (`,` `;` `=` `"` `\`). A trusted header sent more than once, in any letter case, is also
invalid. An authentication property that is not a string is invalid. In `block` mode both
`missing-identity` and `invalid-identity` deny. In `monitor` mode the call is priced under one
fixed bucket per failure, `<budgetScope> (missing)` or `<budgetScope> (invalid)`; no canonical
identity contains a space, so these never collide with a real scope.

`maxScopes` bounds the ledger's memory. A flood of distinct identities cannot grow it past the cap,
and the cap cannot be used to reset someone else's total, because only idle scopes are evicted.
Idle scopes hold nothing committed or reserved. A flood also cannot make the cap expensive (P4A
review #49 A). The worker ledger keeps its scopes ordered by when each becomes idle, so a new scope
at the cap looks at one candidate and either evicts it or is refused; a unit test refuses 1,000 new
scopes against 100,000 live ones without examining any. The node ledger refuses at the cap after
reading two small records, and only one worker per replica rescans for idle scopes, at most once a
second; idle scopes are also swept every minute, so stale keys are deleted below the cap too. A stranded reservation stops pinning its scope two
timeouts after it was made (see Reservation lifecycle). Committed exposure does not expire; that is
reset by `window`.

**Breaking change.** Earlier builds always keyed on `scopeHeader`. A config that relies on that
must now set `identitySource: trusted-header` and, to keep raw scopes in the result header,
`scopeDisclosure: raw`.

## Reservation lifecycle

Every reservation gets an id that is unique on the replica (a random 64-bit per-worker prefix
and a counter), so a response handled by another worker settles it by id, a creation time and an expiry time
of creation + `reservationTimeoutMs`. Time is the gateway's own clock, read when the request
headers arrive and again when the response headers arrive. A reservation ends in exactly one of
these states, and the response stamps which one as `settlement=`:

| `settlement=` | When | Effect on the ledger |
|---|---|---|
| `committed` | Success response before the reservation was reclaimed | Reserved amount moves to committed |
| `released` | Failure response before the reservation was reclaimed | Reserved amount is freed |
| `late-committed` | Success response after reclaim, while the reservation's tombstone is still held (see below) | Amount is added to committed, with no budget check: the call did happen, and under-counting it is the unsafe direction |
| `late-released` | Failure response after reclaim, while the tombstone is still held | Nothing; the amount was already freed |
| `not-active` | The reservation was already settled, or its tombstone was dropped | Nothing |

Reclaim is lazy. It runs, under the same lock as admission (on the node backend, inside the same
compare-and-swap), whenever a call touches the scope, even a call that is then refused, and
across all scopes when a new scope arrives at a ledger already holding `maxScopes`. A reservation is
reclaimed by the first such pass at or after its expiry, which frees its budget and leaves a
tombstone so a slow response can still settle late. The tombstone is kept for at least one more
timeout and dropped by the first pass at or after `expiry + reservationTimeoutMs`. From then on the
reservation is counted as abandoned. A response settles before that pass runs, so the
"one more timeout" is a minimum, not a deadline. If nothing touches the scope, a response arriving
long after two timeouts still settles `late-committed` and is charged. That errs toward
over-counting, the safe direction, and was observed on a real gateway
(`docs/AGGREGATE-RISK-CONNECTED-2026-10-01.md`, case 5b). This covers a client that disconnects, a cancelled request,
and an upstream that times out without a response reaching this policy: their reservations free up
after the timeout instead of pinning the budget for the life of the worker.

Settling by id means a duplicate or reordered response cannot commit or release twice, a commit
after a release changes nothing, and a release after a commit cannot take back committed exposure.

**Choosing the timeout.** The timeout runs from when the gateway has received the whole request
body, not from when the headers arrived, so a client cannot shorten its own reservation by
uploading slowly (#56). Set `reservationTimeoutMs` above the longest time a governed call can
legitimately take from then, including upstream and gateway timeouts. Too short, and a slow call's
reservation is reclaimed while the call is still running. That frees budget another call can take
before the slow call commits late, so the scope can briefly overshoot its budget by the late amount.
Too long, and a stranded reservation holds budget longer than needed. Overshoot only happens past
the timeout. Within it the budget holds exactly.

A response that is not one of the normal kinds (`committed`, `released`) writes one log line with
the ledger counters: active, committed, released, expired, late-committed, late-released, abandoned,
not-active, deferred and contended. The line carries no identity. `settlement=deferred` appears only
with the node ledger, when a settlement could not be written (see Scope of the guarantee).

**Worker restart and config apply.** This paragraph describes `ledgerBackend: worker`; for the
node ledger see Scope of the guarantee. The worker ledger is in the memory of the worker's wasm VM. When the
worker restarts, every committed and reserved amount is gone and all scopes start again at zero. A
config apply that rebuilds the listener does the same, because Envoy then builds new wasm VMs, each
with an empty ledger. On a real Flex 1.14.0 gateway this happens at startup: the gateway applies its
config a second time about 5 s after the first, and a scope exhausted before that apply is admitted
again after it ([case 8b](../docs/AGGREGATE-RISK-CONNECTED-2026-10-01.md#f4-a-config-apply-resets-the-ledger)).
Not every apply rebuilds the listener. On a connected gateway, a UI Save & Apply with no config
change was applied, but the exhausted scope stayed denied (case 2d in the same doc). A policy
config change was not tested and may reset the ledger. A reset fails open. Apart from window boundaries, a restart or a config apply is the
only thing that resets totals. Worker-ledger settlement is an in-process map update, so it has no
transient failure to retry.

## Accounting window

With `window: fixed-period`, time is cut into periods of `windowMs` counted from the Unix epoch,
on the gateway's own clock. Period `n` covers `[n × windowMs, (n + 1) × windowMs)`. The first time a
scope is touched in a later period, its committed total resets to zero. Boundaries do not depend
on when a scope was first seen: two calls 1 ms apart on either side of a boundary land in
different periods.

A call still in flight at a boundary keeps its reservation, which counts against the new period
until it settles. When it commits, it is charged to the period it settles in. A clock that steps
backwards never resets a total, because periods only move forward. A scope whose committed total
is from an earlier period counts as idle for `maxScopes` eviction.

With `window: worker-lifetime` committed exposure accumulates until the ledger is reset: a worker
restart for `ledgerBackend: worker`, a gateway process restart for `node`. A scope with committed
exposure is then never idle, so it holds its `maxScopes` slot for as long as the ledger lives.

Changing `windowMs` remaps every timestamp to a new period number. The node backend keys its
records under a fingerprint that includes `window` and `windowMs`, so a change starts a fresh
ledger rather than reinterpreting old periods.

## Units

Every budget and contribution is an exact non-negative integer, and the ledger keeps them as
`u64`. Nothing is ever rounded. Each mode has its own unit, which `resultHeader` names:

| `contribution` | Unit | `unit=` stamp |
|---|---|---|
| `fixed-weight` | abstract points | `points` |
| `estimated-token-weight` | estimated tokens (a configured estimate, not measured usage) | `estimated-tokens` |
| `spend-amount` | ISO 4217 minor units of `spendCurrency` (cents for USD, yen for JPY) | `<CUR>-minor`, e.g. `USD-minor` |

The ceiling for any single amount, and for a batch's total, is `9007199254740991` (2^53 − 1), the
largest integer every JSON implementation represents exactly. Config values outside
`0`–`9007199254740991` are rejected at configure time. Fractional config values fail to deserialize.
A request amount above the ceiling is refused with `reason=out-of-range`. Ledger totals use
saturating arithmetic, so a sum that would overflow compares as over budget and never wraps
around to a small number.

## Scope of the guarantee

The ledger is real, atomic reserve-then-authorize, keyed by budget scope. There are two backends.

**`ledgerBackend: node` (the default).** The scope records live in the gateway's node-local shared
data (PDK `LocalDataStorage`, used through the `experimental_storage_sync` feature), which every
Envoy worker of one gateway replica reads and writes. Each worker is its own single-threaded wasm
VM, so the check and the reservation are made atomic with compare-and-swap: a worker reads the
scope's record, reclaims expired reservations, checks the budget and writes the new record back
only if nobody wrote it in between, retrying up to 12 times with no sleep. There is no
read-then-write fallback and no unconditional overwrite. Concretely:

- **One budget per policy instance per gateway replica.** Opening more connections does not
  multiply it. Unit tests drive two ledgers over one store with a CAS conflict forced on every
  write and admit exactly 3 of the reference calls; the real-gateway case `case8n` in
  `tests/connected_e2e.rs` runs the same 200-call burst on four Envoy workers and asserts exactly
  3 admitted. Replicas still have independent budgets: with `R` replicas a scope can reach
  `R × aggregateBudget`, so divide the intended total by `R` or run one replica.
- **Contention and storage errors fail closed.** When the retries run out, `block` mode denies with
  `reason=ledger-contention`; a storage error denies with `reason=ledger-unavailable`. `monitor`
  mode forwards either and stamps the reason. Nothing is reserved in either case.
- **Settlement is safe by direction.** A commit that cannot be written to its scope record is
  written instead to a per-reservation *commit marker* (a separate shared-data key, created with
  compare-and-swap), queued on the worker and retried on its next calls, stamped
  `settlement=deferred`. No worker takes a reservation off a record without first claiming its
  marker by compare-and-swap, so a worker that reclaims the reservation at its deadline, or drops
  its tombstone, charges a marked commit instead of discarding it. A commit made before the
  tombstone window closes therefore counts in the total at every moment, even if the committing
  worker never handles another call or its VM restarts and loses the queue. A commit that could not
  be marked either (the tombstone was already dropped, or the store failed) stays only in the
  queue, which charges it even if its reservation has meanwhile been reclaimed; while 256 or more
  such commits are queued, new reservations are refused as contended. A commit whose record reads as missing while the reservation could still be on it
  (PDK reports a host read error as "no value") is charged as a late commit rather than dropped. A
  release that cannot be written leaves the reservation held until it is reclaimed: an over-count
  that frees itself after `reservationTimeoutMs`.
- **Cleanup never deletes live state.** An idle record becomes a tombstone by compare-and-swap,
  and only the cleanup pass that marked a tombstone for deletion deletes it, at once. Tombstones
  are timed on the gateway clock read at that moment, not on the request's start time. On Flex a
  delete is a real removal of the shared-data key (verified by reading the PDK 1.10 source, not by
  a runtime test). A zero-length value, which only PDK's test stub writes on delete, reads as
  absent and is created over, so an empty record can never wedge a scope closed.
- **Keys carry no identity.** A record is stored under an HMAC-SHA256 of the scope (under
  `scopeDigestKey`), never the raw identity. Records are private to the policy instance unless
  `ledgerNamespace` is set. **Set `scopeDigestKey`.** It defaults to empty so the default
  configuration starts, and then the HMAC is unkeyed: anything that can list the replica's shared
  data can confirm a guessed identity from its key. The policy logs a warning at startup for the
  node backend with an empty key.
- **A scope record is bounded.** A scope holds at most 512 reservations in flight plus tombstones
  (about 50 KB of record). Past that, a call is refused with `reason=scope-saturated` (`block`
  fails closed, `monitor` forwards and flags), until reservations settle or time out. The worker
  backend applies the same cap per scope. A zero contribution reserves nothing and adds no entry.
- **A gateway process restart resets it.** The shared data is in process memory, not durable, so a
  restart or redeploy starts every scope again at zero, even mid-window. Whether a config apply
  that rebuilds the listener (which resets the worker ledger) keeps the node ledger is **not yet
  verified on a real gateway**: the shared data lives outside the wasm VMs, so it should survive,
  and `case8nb` in `tests/connected_e2e.rs` records what a real Flex 1.14.0 gateway does.
- **Known edges.**
  - The commit queue lives in the worker's VM and is retried only when that worker next handles a
    governed call. A PDK timer could drain it, but it is just as per-VM (lost on restart) and
    async, so the commit marker is what keeps a queued commit counted. The retries are immediate:
    PDK has no synchronous sleep to back off with inside a filter callback.
  - A marked commit that another worker charges at the reservation's deadline is charged to the
    period that deadline falls in. A commit whose write reported a failure that had in fact landed
    is charged twice. Both over-count. A committing worker stalled for longer than
    `reservationTimeoutMs` between its marker check and its marker write, past a cleanup pass,
    could leave a marker that nothing charges; each step is a back-to-back host call.
  - Each reservation that times out leaves a small marker key, deleted by cleanup once
    `2 × reservationTimeoutMs + 30 s` have passed and no record holds the reservation.
  - A duplicate commit of an already-settled reservation whose first read hits a host storage
    error is charged again as a late commit. This over-counts and never under-counts. The filter
    settles each reservation once, so it does not send duplicates itself.
  - A scope slot whose release exhausts its retries stays counted against `maxScopes`, and nothing
    recounts it, so fewer scopes fit (never more state evicted).
  - A worker that stalls between its read and its write across a whole cleanup pass could re-create
    a deleted record without taking a slot. A cleanup pass stalled for more than 10 minutes between
    marking a tombstone and deleting it could delete a record re-created meanwhile. Each wasm VM is
    single-threaded and these are back-to-back host calls, so both are very unlikely.
  - Instances that share a `ledgerNamespace` must use the same `scopeDigestKey`,
    `reservationTimeoutMs`, window and `maxScopes`. Nothing checks this.
  - **Reconfiguring.** Every key sits under a fingerprint of `scopeDigestKey`, `window` and
    `windowMs`, so changing any of them starts a fresh ledger: every identity gets a fresh budget
    at once (rotating the key is a budget reset), and the slot count starts at zero, so old
    records cannot keep `maxScopes` full. The old records are not deleted (another instance in a
    shared namespace may still use them); they sit in shared data until the gateway restarts,
    bounded by the old `maxScopes`.
  - With `window: worker-lifetime` a scope that has committed anything is never idle, so it keeps
    its slot until a restart: `maxScopes` is then a cap on distinct identities for the life of the
    ledger, and once it is reached new identities are refused with `reason=scope-capacity`. Use
    `fixed-period` (an earlier period counts as idle) when identities churn.
  - A storage status other than success or a CAS conflict panics inside PDK, which fails the call.
  - One hot scope serialises every worker on one record, and a record grows with its in-flight
    reservations, up to the 512-entry cap. A cleanup pass scans the whole namespace inside the call that runs it, at most
    once a second per replica.

**`ledgerBackend: worker`.** One in-process ledger per Envoy worker, backed by a mutex-serialized
map, as in earlier builds. It is race-safe within a worker (the concurrent-admission unit test
shows it holding the budget where a naive read-then-write counter breaches), but:

- **The budget is per worker, and a caller can multiply it.** Each worker, on each replica, holds
  the full `aggregateBudget`. With `N` workers in total a scope can be admitted up to
  `N × aggregateBudget` in a window, and a caller can push toward that by opening more connections.
  To make `aggregateBudget` an upper bound, divide the intended budget by `N`. That bound is safe
  but loose: a scope whose traffic lands on one worker gets only `1/N` of the intended budget.
- **Single-worker configuration gives one budget per replica.** Setting
  `FLEX_SERVICE_ENVOY_CONCURRENCY=1` gives each policy instance one worker ledger per replica,
  at the cost of worker parallelism. In the [real Flex 1.14.0 run, case 8](../docs/AGGREGATE-RISK-CONNECTED-2026-10-01.md#8-per-worker-scope-observed-15),
  12 of 200 calls were admitted with four workers and 3 of 200 with one worker, using
  `aggregateBudget: 3000` and `fixedWeight: 800`. These are observations from that run.
- **A restart, redeploy or config apply resets it.** A config apply resets it when it rebuilds the
  listener, which gives Envoy new wasm VMs. The gateway does this once at startup, about 5 s after
  it first applies its config. A UI Save & Apply with no config change did not reset it. There is
  no storage dependency, so no storage conflicts or errors to handle.

**Both backends:**

- **No signed decision records.** No ledger operation is independently attestable outside the
  gateway. This build makes no claim that its admit/deny decisions are cryptographically
  non-repudiable.
- **`estimated-token-weight` contribution is estimate-then-SETTLE, not estimate-then-reconcile,
  and it never measures actual token usage.** The reservation made before authorizing an
  `estimated-token-weight` call is `estimatedTokens`, a configured upper bound. This build's
  response leg is strictly headers-only (see Inspection boundary above). It never buffers or reads
  the response body, so it never learns a real `usage.total_tokens` figure to true up against. On
  a successful response the reservation is therefore **committed at the estimate itself**,
  unchanged (or released outright on failure). Set the estimate conservatively for the traffic
  this instance governs, since it is what actually lands in the ledger.

A ledger shared across replicas that survives restarts (`ledgerBackend: cluster`, rejected today),
and signed decision records (the full model in the `authorized-but-composed` reference work), are
**not implemented here**. Do not present this build as shipping them. The earlier `ledgerEndpoint`
placeholder has been removed.

## Testing

`cargo +1.89.0 test --lib --locked --offline` runs 207 tests, none of which touch the network or
Docker:

- **`src/ledger.rs` — the pure decision engine** (no PDK dependency, 55 tests): correctness of
  `reserve`/`force_reserve`/`force_reserve_checked`/`commit`/`release`/`record`/`snapshot`
  in isolation, plus two concurrency tests that are the load-bearing proof for this whole policy —
  `naive_counter_breaches_budget_under_concurrency` (a read-then-write counter admits 5 concurrent
  800-unit calls against a 3000 budget, breaching to 4000) and
  `reserve_then_authorize_holds_budget_under_concurrency` (the real ledger, same concurrent load,
  admits exactly 3 of 5, holding at 2400) — reproducing both the sequential-composition and the
  race scenario from `authorized-but-composed`, plus a broader multi-scope stress variant
  (`reserve_then_authorize_never_exceeds_budget_across_many_concurrent_scopes`). These two headline
  tests, and every other test in this file, are never weakened or skipped — they are the correctness
  proof this whole policy exists to make. Three more cover exact integer units: small contributions
  land exactly on the budget, an overflowing sum is denied rather than wrapping, and a forced
  reservation saturates and still reports the breach. Five cover the scope cap: a full ledger refuses a
  new scope when none is idle and keeps live totals, evicts only an idle scope, never refuses an
  already-tracked scope, and neither `snapshot` nor a stray `commit`/`release` creates a scope.
  Twelve cover the reservation lifecycle with an injected clock: ids are unique and every
  reservation has a bounded expiry; a duplicate commit or release, a commit after a release and a
  release after a commit change nothing; an abandoned reservation is reclaimed at its timeout
  without touching committed exposure; a late commit is charged exactly once and a late release
  changes nothing; once a call touches the scope more than one timeout after reclaim, the tombstone
  is dropped, the reservation is counted abandoned and a later settlement is `not-active`; the counters tell every state apart; and a stranded reservation stops pinning
  a full ledger after two timeouts.
  Six cover the accounting window: a fixed window resets committed exposure at the boundary;
  periods are aligned to the epoch, not first use; an in-flight reservation carries across a
  boundary and settles in the new period; a clock stepping backwards never resets a total;
  without a window nothing resets; and a scope from an earlier period can be evicted.
  Two cover the cost of the cap (#49 A): 1,000 refusals against 100,000 live scopes examine no
  scope at all, and the idle index follows every settlement.
- **`src/node_ledger.rs` — the node-wide ledger** (34 tests, over an in-memory test store that can
  force CAS conflicts and storage errors): two workers racing on every write admit exactly 3 of the
  reference calls, and interleaved workers admit exactly what fits; persistent CAS mismatch is
  `Contention` and a storage error `Unavailable`, both reserving nothing; a reservation made on
  one worker settles on another exactly once, late settlement follows the tombstone rules and ids
  are unique across workers; the store never holds a raw identity; a window rollover resets
  every worker's view; at the cap an idle scope is swept and live state kept, a refusal costs at
  most three store operations with 1,000 live scopes, and a settlement that leaves a scope idle
  lets the next new scope in; stale keys are deleted, a doomed record is never written over or
  deleted by a writer, a cleanup whose delete fails restores the tombstone, tombstones age on the
  store clock rather than a stale request time, and a swept scope keeps its window period; a
  commit whose record reads as missing is still charged, and a queued commit is charged even after
  its tombstone is dropped; a refused call past two timeouts drops a tombstone exactly as on the
  worker ledger (connected case 5c, replayed on both backends); an empty stored value reads as absent and never wedges a scope;
  and an unwritable commit is queued, an unwritable release stays held, and a long commit queue
  refuses new reservations. Commit markers: a deferred commit whose worker never runs again is
  charged by the worker that reclaims it (the M2 interleaving), including when the marker is
  written between that worker's read and its claim, or while a tombstone is being dropped; a
  commit drained by its own worker is charged once; markers are not written once nothing could
  charge them, and are collected after the tombstone window. A raw empty host value (fixint `Eof`)
  reads as absent; a zero contribution holds nothing; a scope refuses past 512 held entries; and a
  new digest key or window starts a fresh ledger with fresh slots.
- **`src/lib.rs` — the PDK filter** (116 tests), mostly exercised end to end through the
  `pdk-unit` harness, which runs the node backend over the real `LocalDataStorage` adapter: per-mode
  behavior (`monitor` never denies; `block` denies past budget), both `onDeny` renderings and their
  JSON-RPC-notification/non-JSON-RPC fallbacks, all three `contribution` modes including the
  unpriceable and estimate-then-settle edge cases, independent per-scope budgets, the missing-
  identity path in both modes, and that the `resultHeader` stamp lands on the client-facing
  response (not the upstream request) in both the allow and deny paths. Also:
  - **Ledger backends** — a contended or unavailable node ledger fails closed in `block` mode
    and is forwarded with `reason=ledger-contention`/`ledger-unavailable` in `monitor` mode; two
    node gates on one store share one budget while two worker gates each keep their own; the worker
    backend still runs through the filter; `cluster` is rejected as not implemented;
    `ledgerNamespace` is validated and selects the store the ledger opens.
  - **Identity** — a spoofed, rotating scope header does not mint a fresh budget under
    `authentication`; missing authentication fails closed; oversized, delimiter-bearing and
    space-bearing identities are denied as invalid; case and whitespace variants share one budget;
    a duplicated trusted header is invalid; the default stamp never echoes the raw identity; and
    the scope cap denies a new identity in `block` mode (keeping existing budgets) and stamps it in
    `monitor` mode.
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
    and an `estimated-token-weight` call commits its full pre-flight estimate rather than a smaller
    real usage figure the response body is never read to find
    (`estimated_token_weight_commits_the_full_estimate_and_never_reads_the_response_body`). Usage
    figures that are higher than the estimate, or malformed, don't change the charge either
    (`estimated_token_weight_ignores_over_and_malformed_usage_figures`).
  - **Settlement** — a successful response is stamped `settlement=committed` and a failure
    `settlement=released`, and a worker restart (`tester.restart()`) resets every total to zero.
    Upstream statuses 200, 202 and 302 commit and 404, 500 and 504 release
    (`settlement_commits_2xx_and_3xx_and_releases_4xx_and_5xx`), and a JSON-RPC `error` or an
    `isError: true` result inside an HTTP 200 is charged
    (`a_jsonrpc_error_or_is_error_result_inside_an_http_200_is_charged`).
  - **Governed methods** — a full MCP session (`initialize`, `notifications/initialized`,
    `tools/list`, `ping`, an elicitation response, bodyless `GET` and `DELETE`) runs on an
    exhausted budget and only `tools/call` is denied
    (`a_full_mcp_session_runs_on_an_exhausted_spend_budget_and_only_tools_call_is_denied`), and
    `initialize`, `ping` and `notifications/cancelled` still pass on an exhausted fixed-weight
    budget;
    ungoverned traffic creates no scope and changes no ledger counter; mixed batches charge only
    their governed items, and a denied mixed batch returns `-32008` for every request id; a
    duplicate `method` member fails closed; matching is case-sensitive; and an item that cannot be
    classified stays governed. A body this parser rejects (not JSON, a BOM, a lone surrogate, or a
    batch nested past 128 levels) fails closed rather than being charged as one call.
  - **Charset** — `charset=utf-7` carrying `"tools+AC8-call"` (UTF-7 for `tools/call`), and any
    other non-UTF-8 or malformed charset, is uninspectable: denied in `block` mode and flagged
    `reason=unpriceable` in `monitor` mode. No charset, or `utf-8` in any case or quoting, is
    inspected as before.
  - **Window** — with `windowMs: 60000` a spent budget is still denied at 59 s on the gateway
    clock (`tester.sleep`) and available again at 60 s; with `worker-lifetime` it is still denied
    400 days later.
  - **Exact integer units** — a spend amount of `12.34`, `1234.0`, `1e3`, `-5`, `"1234"`, or 2^64
    is refused as unpriceable before it reaches upstream. Amounts above 2^53 − 1 are refused as
    out of range, and so are spend-amount and fixed-weight batches whose total overflows. Monitor
    mode forwards those calls and stamps `reason=out-of-range`. 10 + 20 minor units land exactly
    on a budget of 30, which a float ledger gets wrong. `spendCurrency` is stamped as the unit.
- **Direct identity tests** (10): trimming, case folding, the 256-byte limit and the character
  rules in `canonical_identity`; duplicate and mixed-case trusted headers; `client_id`,
  `principal` and `properties.<path>` selection (a non-string property is invalid); and
  `digest` (keyed and unkeyed), `none` and `raw` display.
- **Direct `Gate::from_config` validation tests** (29): every config-validation rejection path
  (invalid enum values including `window`, the retired `rolling-24h` rejected with its replacements named, `windowMs` outside `60000`–`31622400000`, negative or above-2^53 − 1 amounts, a fractional
  amount refused by deserialization, the retired `token-cost` name rejected with its replacement
  named, a malformed `spendCurrency`, blank required strings, an unknown `identitySource`,
  `identityField` or `scopeDisclosure`, an empty, blank, padded, duplicated or `"*"`
  `governedMethods` list, and `maxScopes` outside `1`–`1000000`, `reservationTimeoutMs` outside `1000`–`86400000`) and the corresponding accepted
  cases.
- **`dot_path_value` unit tests** (4): the dotted-path body reader used for `spend-amount`.

Two Docker suites run the policy through a real, containerized Flex Gateway 1.14.0 with a real
HTTP mock upstream:

- **`tests/requests.rs`** has four `pdk_test` cases: sequential composition refuses the fourth
  call, a different agent has an independent budget, an MCP handshake (`initialize`,
  `notifications/initialized`, `tools/list`) passes under `spend-amount` + `block` while only
  `tools/call` is budgeted, and a slow upload over a raw socket (its last body byte held back
  past twice `reservationTimeoutMs`) still commits, so the next call is refused (#56).
- **`tests/connected_e2e.rs`** has the real-gateway validation cases from
  `docs/ASTRA-TASK-aggregate-risk-connected.md`. They are `#[ignore]` and are run explicitly.
  They cover:
  - authentication policy ordering, with spoofed headers ignored;
  - digest disclosure;
  - monitor mode;
  - reservation reclaim and late settlement, on one worker;
  - the fixed-window reset;
  - a restart;
  - the per-worker budget (`ledgerBackend: worker`, case 8) and the reset caused by a config
    apply (case 8b);
  - one budget across four Envoy workers with `ledgerBackend: node` (`case8n`, asserts exactly
    3 of 200 admitted; the container gets `FLEX_SERVICE_ENVOY_CONCURRENCY=4` through
    `FlexConfig::builder().env(...)`), and whether the node ledger survives the startup config
    apply (`case8nb`, observational).

  One more case, `case2c`, needs a connected-mode registration, a control-plane API instance
  and two real UI Save & Apply presses, so it is run by hand only.

Both suites need a Flex Gateway registration, which stays untracked. The CI `runtime-e2e` job
writes a disposable local-mode registration from a repository secret, runs both suites (case 5
on one Envoy worker; `case2c` skipped), deletes the registration and scans the evidence for
identifiers. Results, including the hand-run connected cases, are in
[`docs/AGGREGATE-RISK-CONNECTED-2026-10-01.md`](../docs/AGGREGATE-RISK-CONNECTED-2026-10-01.md).

CI does run the full packaging path on every push: `make build` generates the definition and
implementation assets, `scripts/check_exchange_metadata.py --assets` validates them, and the
generated files are uploaded as the `exchange-assets-aggregate-risk-gate` workflow artifact so
a reviewer can inspect exactly what would be published.

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
