# Approval-to-Execution Binding

> Part of the [Agent Governance Policies](../README.md) family.
>
> NIST SP 800-53 Rev 5 **AC-3** (Access Enforcement — the gateway is where the executed action
> either matches or fails to match what was approved), **AC-4** (Information Flow Enforcement —
> the approval record must travel with the request across the hop from approver to executor),
> **AU-10** (Non-repudiation — the P5 separate-attester requirement is *supporting* evidence toward
> this; the symmetric HMAC this build uses provides separation-of-duties, not non-repudiation in the
> PKI sense), and **AU-2** (Event Logging — the structured verdict line below). OWASP **LLM06:
> Excessive Agency**. MITRE ATLAS
> (adversarial-ML design context) and MITRE Engage (the **Expose**/**Affect** vocabulary used for
> `monitor`/`block` below) as design context, not a detection-coverage claim. EU AI Act
> **Article 14** (human oversight — the approval this policy verifies wasn't bypassed or altered
> *is* the human/upstream oversight decision) and **Article 15** (accuracy, robustness and
> cybersecurity — binding an execution to its approval under multi-hop composition is a
> robustness property). AIUC-1 **Domain B** (security / unauthorized actions).
>
> Every reference above is a supporting technical measure or a piece of enabling evidence toward
> the named control, article, or domain — **none of it is a certification**, and neither a single
> denial nor a passing test run establishes compliance on its own. Design context, not a
> compliance claim; see also the [MuleSoft PDK overview](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview).

## The customer need

An Agent Fabric approval and its execution are almost always separated by time and by hops: a
supervising broker approves an action; a downstream broker executes several calls later, over a
different connection. Nothing at the gateway normally proves those two events are the *same*
action. A changed vendor, a changed quantity, a re-pointed target, an approval reused past its
window — any of these can slip through the gap between "approved" and "executed," and today
nothing at the gateway catches it. This policy closes that gap: on every governed MCP
`tools/call` execution, it checks the accompanying approval record against five independent
predicates and denies the call if any **required** predicate fails.

**Scope: MCP `tools/call` only.** This policy binds exactly one JSON-RPC method — `tools/call` —
because that is the method that *executes a tool*, which is what an approval constrains. Every other
JSON-RPC method (`tools/list`, `initialize`, `ping`, notifications, anything unrecognized) is
**out of scope**: it is forwarded upstream untouched, with the result header stamped `out-of-scope`
in both monitor and block mode. The policy never blocks an identified non-`tools/call` method. At
the HTTP layer, only `POST` can carry a Streamable-HTTP `tools/call`, so a bodyless `GET` (the
server→client SSE stream), `DELETE` (session teardown with `Mcp-Session-Id`), `OPTIONS` or `HEAD` is
also forwarded untouched and stamped `out-of-scope` in both modes. A POST that cannot be inspected
— or parsed at all — still fails closed in block mode, because it could be a `tools/call` (see the
inspection boundary below).

Predicate semantics and canonical form follow the
[**Approval Binding Vectors (ABV) v0.1**](https://github.com/msaleme/approval-binding-vectors)
conformance corpus (MIT) — a protocol-neutral spec for exactly this question, with its own positive
controls and negative vectors. This implementation vendors the ABV vectors
(`tests/fixtures/abv/`) and drives its negative/positive unit tests directly from them.

- **`monitor`** (Expose) — evaluate every required predicate on every governed call and log the
  verdict (allow, or the specific predicate that would have failed) via a structured warning, but
  always forward the request regardless of the outcome. Use this to characterize how approvals and
  executions actually line up before switching anything to enforce.
- **`block`** (Affect) — deny the call when a required predicate fails, per `onDeny`, even though
  nothing about the request's own JSON-RPC framing is otherwise invalid.

### The five predicates

| ID | Predicate | The failure it excludes |
|---|---|---|
| **P1** | Action | Approved tool A, executed tool B. |
| **P2** | Arguments | Approved A with args X, executed A with args Y. Arguments are compared by canonical digest — the fail-closed subset where the ABV reference form and RFC 8785 JCS agree (see [Canonical form](#canonical-form)); a reference-shaped argument (an object carrying a `$ref` key at any depth) is **rejected under P2**, not dereferenced — the approved and executed argument bytes must match directly. |
| **P4** | Freshness | Approval correctly scoped and granted, but expired before execution — checked against this gateway's own wall clock, never a caller-supplied timestamp. |
| **P5** | Separate attester | A record whose only witness that it was approved is the party now executing it. The P5 HMAC covers a **versioned, domain-separated `mcp-v1` payload** (see below), and the executor identity it is checked against is read from the **verified authentication data**, never a caller-asserted header. |
| **P6** | Single use *(opt-in)* | One approval, replayed for a second execution. Enforced atomically via **local** gateway data storage in block mode, so single use holds **per gateway replica, until restart** — deploy a single replica for flows that need P6 (see [P6 boundary](#p6-single-use-boundary)). Reusable approvals are legitimate in some flows, so P6 defaults out of `requiredPredicates`. |

> **P3 (dereference) was removed.** An earlier draft carried a sixth predicate that verified the
> bytes behind a `$ref`-shaped argument via a caller-supplied `dereferenced` digest map. That put
> the gateway in the business of trusting a caller-populated blob map it cannot itself resolve.
> The safer rule — a reference-shaped argument is simply **rejected under P2** — is now the whole
> story; there is no P3 anywhere in the config, the code, or the ABV mapping.

**Honesty boundary.** This policy (and the ABV corpus it implements) tests whether the *record*
proves the executed action is the approved one. It does not and cannot prove that approving the
action was itself wise — that is a policy question the record cannot answer on its own. P5's
separate-attester requirement is what keeps the check from being a document an actor wrote about
itself; it does not establish that the attester was *entitled* to approve the action.

### Inspection boundary

**HTTP method first (#50).** A request whose method is not `POST` (compared case-insensitively)
and that carries no body is forwarded untouched, stamped `out-of-scope`, in both modes — on MCP
Streamable HTTP that is the `GET` SSE stream, the `DELETE` session teardown, and `OPTIONS`/`HEAD`.
A missing method is treated as `POST`, and a non-`POST` that *does* carry a body is inspected
exactly like a `POST` (so a `tools/call` body cannot dodge the binding by changing its verb).

Before any body is buffered, the policy checks the request's declared framing at the header phase:
a `content-type` that isn't `application/json` (or an `application/*+json` variant) — which
excludes SSE/streaming media types such as `text/event-stream` — a `charset` parameter other than
`utf-8`, or the presence of any `content-encoding` header (a compressed body, whose decoded size the declared `content-length`
cannot bound) is treated the same as malformed framing below: `monitor` mode logs and always
forwards the request uninspected; `block` mode denies before ever buffering it. This mirrors the
sibling Decoy Tool Sentinel's admission gate and is the reason SSE/streaming, compressed, and
non-UTF-8 bodies are excluded from inspection — this policy cannot safely buffer or parse them as
JSON at all.

**Charset.** The policy parses the body as UTF-8, so it inspects a body only when `content-type`
has no `charset` parameter or `charset=utf-8` (case-insensitive, whitespace-trimmed, optionally
quoted). Any other value — `utf-7`, `utf-16`, `iso-8859-1`, the `utf8` alias, an empty value, or a
second conflicting `charset` — is refused as malformed (`block` denies, `monitor` flags and
forwards). This closes a bypass: an upstream that decodes by charset, as the MCP TypeScript SDK
does, reads `"tools+AC8-call"` under `charset=utf-7` as `tools/call`, while a UTF-8 parse would see
an unknown, out-of-scope method and forward it unapproved.

**Framing (content-length).** The policy buffers a body only when it declares a valid
`content-length` no greater than **64 KiB**, and the body received must match it exactly. A `POST`
that declares no length — chunked transfer, or HTTP/2, where the header is optional — or an
oversized or mismatched one is **not buffered** and is treated as a **framing** refusal: `block`
mode denies it with an empty `403` stamped `denied;framing=content-length`; `monitor` mode forwards
it stamped `monitor;framing=content-length`. It is denied because it *could* be a `tools/call`, not
because it was identified as one; clients that need this policy in block mode must send a
`content-length` (HTTP/1.1 non-chunked bodies always do). Buffering an undeclared-length body under
a running 64 KiB cap is a follow-up, not this build.

Once a body clears both gates, the policy evaluates it only if it parses as a single (non-batch)
JSON-RPC 2.0 object. A `POST` with no body at all, a JSON-RPC **batch**, or fails to parse as a single JSON-RPC object at all (missing/invalid `jsonrpc`, missing
`method`, or — for `tools/call` — missing `params.name`), or one the JSON parser rejects outright
(nesting deeper than 128, a lone surrogate escape, a leading byte-order mark, invalid UTF-8) is
treated as **malformed** — never as an out-of-scope method: `monitor`
mode logs the verdict and always forwards; `block` mode denies. Batches are explicitly out of scope
for approval binding, not a future predicate — an approval record binds to one executed action, not
to a collection of them; a batch is therefore rejected atomically (the whole array denied together)
and never split into a per-member allow/deny — so an unauthorized or altered call riding inside an
otherwise-plausible batch can never slip through as one of several forwarded calls.

**What this policy reads — and nothing else.** Inspection is limited to: the approval envelope
(from `approvalHeader` or, for `approvalSource: rpc-param`, the `approvalRpcField` sibling member of
the JSON-RPC body), the executor identity header (`executorHeader`), and the JSON-RPC body itself
(`jsonrpc`/`id`/`method`/`params`, and for `tools/call`, `params.name`/`params.arguments`), plus the
HTTP method and the `content-type` (media type and `charset`)/`content-encoding`/`content-length`
framing headers. It never
inspects other headers, the query string, or the request path.

Denial rendering follows the request's own framing, not just `onDeny`:
- A JSON-RPC **notification** (no `id`) always gets an empty HTTP `202` — JSON-RPC forbids a
  response to a notification either way.
- A request this policy cannot confidently parse as a single, non-batch JSON-RPC call with an
  echoable `id` (malformed body, unreadable framing, or a request with no body at all) always
  falls back to an empty HTTP `403`, regardless of `onDeny` — echoing an `id` it cannot trust risks
  exposing a protected value. This includes a body with an **ambiguous duplicate `"id"` member**
  (e.g. `{"id":1,"id":"leaked-token",...}`): the strict parse rejects it outright rather than
  picking either candidate value, so neither one is ever echoed back.
- Otherwise, `onDeny: rpc-error` returns an in-band JSON-RPC `-32008` error reusing the request's
  own `id` (HTTP `200` — the error is payload-level, matching real JSON-RPC semantics, so a caller
  or test that only checks the HTTP status code cannot distinguish an allowed, forwarded request
  from an in-band denial); `onDeny: empty-403` returns a plain HTTP `403` with no JSON-RPC envelope.

### Configuration

| Field | Type | Default | Purpose |
|---|---|---|---|
| `approvalSource` | `header`\|`rpc-param`\|`sidecar` | `header` | Where the approval envelope rides. `sidecar` is rejected at startup (not implemented). |
| `approvalHeader` | string | `x-approval` | Header carrying the JSON-encoded envelope when `approvalSource: header`. |
| `approvalRpcField` | string | `approvalBinding` | Top-level JSON-RPC body member carrying the envelope when `approvalSource: rpc-param`. |
| `executorHeader` | string | `client_id` | **Fallback** header naming the executor. The executor identity is taken FIRST from the **verified** authentication data (`client_id`, then `principal`) established by an upstream authentication policy; this header is used only when no verified subject is present, and when P5 is required and no verified subject exists the call **fails closed** rather than trusting the header. Used only for P5. |
| `requiredPredicates` | string[] | `[P1, P2, P4, P5]` | Predicates that MUST hold. Empty list rejected at startup. P6 is opt-in. (There is no P3.) |
| `attesterKeys` | `{kid, key}[]` | `[]` | Known attester keys for the P5 HMAC-SHA256 check over the `mcp-v1` payload. Each `key` must be **at least 32 bytes** — a shorter key is rejected at startup. An attestation from an authority not listed here always fails P5. |
| `clockSkewSeconds` | integer | `60` | Tolerance applied to P4: valid while `now <= not_after + clockSkewSeconds`. `0`–`3600`; anything else is rejected at startup (**breaking**: a negative value used to be treated as `0`, and there was no upper limit). |
| `maxApprovalLifetimeSeconds` | integer | `0` (off) | Upper bound on an approval's **remaining** lifetime, checked under P4 against the gateway clock: an approval with `not_after > now + maxApprovalLifetimeSeconds + clockSkewSeconds` is denied `predicate=P4`. `1`–`31536000` when set; anything else, or setting it without P4 in `requiredPredicates`, is rejected at startup. See [Approval lifetime bound](#approval-lifetime-bound). |
| `stripApprovalEnvelope` | boolean | `true` | With `approvalSource: rpc-param`, cut the `approvalRpcField` member out of every forwarded body (an allowed call, or a monitor-mode forward) and set `content-length` to the new length. Ignored for `approvalSource: header`. See [rpc-param envelope removal](#rpc-param-envelope-removal). |
| `expectedAudience` | string | `""` | This gateway's deployment audience, bound into the `mcp-v1` payload as `aud`. **Required (non-empty) whenever P5 is required.** |
| `expectedTenant` | string | `""` | The tenant this gateway serves, bound as `tenant`. **Required (non-empty) whenever P5 is required.** |
| `expectedEnvironment` | string | `""` | The environment this gateway serves, bound as `env`. **Required (non-empty) whenever P5 is required.** |
| `mode` | `monitor`\|`block` | `monitor` | Evaluate and log only, vs. actually deny on a failed required predicate. |
| `onDeny` | `rpc-error`\|`empty-403` | `rpc-error` | How a block-mode denial is rendered. A request that can't be confidently parsed as a single, non-batch JSON-RPC call with an echoable id always falls back to `empty-403` regardless of this setting — echoing an untrustworthy id risks exposing a protected value. This includes a `POST` refused for framing (no valid declared `content-length` ≤ 64 KiB), stamped `denied;framing=content-length`. A notification (no id) always gets an empty HTTP 202. Never applies to a bodyless non-`POST` request (`GET` SSE stream, `DELETE` session, `OPTIONS`, `HEAD`), which is forwarded `out-of-scope` and never denied. |
| `resultHeader` | string | `x-approval-binding` | Header stamped with the verdict (`allowed`, `out-of-scope`, `would-deny;predicate=P2`, `denied;predicate=P5`, `denied;predicate=malformed`, `denied;framing=content-length`, the `monitor;…` forms of the last two, and `monitor;envelope=unstripped` or a `;envelope=unstripped` suffix when monitor mode forwards an rpc-param body whose envelope could not be removed) — never the approval or argument values themselves. |

The approval envelope shape (header or rpc-param, identical either way):
```json
{
  "approval": {
    "scope": {"action": "deploy.apply", "arguments_digest": "<sha256-hex>"},
    "not_after": "2026-09-19T12:00:00Z",
    "nonce": "n-0001"
  },
  "attestations": [
    {"claim": "approval", "authority": "approver.example", "mac": "<hmac-sha256-hex>"}
  ]
}
```

**The P5 `mac` is an HMAC-SHA256 over a versioned, domain-separated `mcp-v1` payload** — not over
the raw scope. The payload is the canonical JSON (see [Canonical form](#canonical-form)) of:
```json
{
  "v": "mcp-v1",
  "iss": "<attesting authority = attestation.authority>",
  "aud": "<expectedAudience>",
  "tenant": "<expectedTenant>",
  "env": "<expectedEnvironment>",
  "sub": "<the executor identity, from verified auth>",
  "action": "<approval.scope.action>",
  "arguments_digest": "<approval.scope.arguments_digest>",
  "not_after": "<approval.not_after>",
  "nonce": "<approval.nonce>"
}
```
Binding `aud`/`tenant`/`env` into the signed payload is what stops an approval minted for one
gateway, tenant, or environment from being replayed against another; binding `sub` is what makes
P5 a *separate*-attester check (the attesting authority must differ from the executor). Mutating any
of these protected claims after the MAC is computed causes P5 to fail.

### Canonical form

Digests (P2) and the P5 payload are computed over a **fail-closed subset** of RFC 8785 JCS: object
members sorted by key, compact separators, and only objects, arrays, strings, booleans, `null` and
integers. That output is byte-identical to the ABV reference checker's Python
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. Where that reference
form and JCS would disagree, the value is **rejected** rather than emitted in one of the two forms
(#52):
- **non-integer numbers** — JCS's ECMA-262 number formatting is not implemented;
- **integers outside ±(2^53 − 1)** — JCS serializes numbers as IEEE-754 doubles, so
  `9007199254740993` would become `9007199254740992` there;
- **objects whose key order differs between UTF-8 byte order (Python, this code) and UTF-16 code-unit
  order (JCS)** — only possible when keys mix supplementary-plane characters (e.g. emoji) with
  U+E000–U+FFFF.

A rejected value fails closed: under P2 the call is denied (`arguments not canonicalizable`). So
every digest this policy accepts is one a conforming JCS implementation would also produce.

```yaml
- policyRef:
    name: approval-execution-binding-v1-0-impl
  config:
    approvalSource: header
    approvalHeader: x-approval
    approvalRpcField: approvalBinding
    executorHeader: client_id
    requiredPredicates: [P1, P2, P4, P5]
    attesterKeys:
      - kid: approver.example
        key: "<shared-secret-at-least-32-bytes>"
    clockSkewSeconds: 60
    maxApprovalLifetimeSeconds: 900
    expectedAudience: mcp-gateway-prod
    expectedTenant: acme
    expectedEnvironment: prod
    mode: block
    onDeny: rpc-error
    resultHeader: x-approval-binding
```

### Approval lifetime bound

`maxApprovalLifetimeSeconds` (#52) caps how far in the future an approval's `not_after` may be,
measured from the gateway's clock when the call arrives:

```text
deny under P4  if  not_after > now + maxApprovalLifetimeSeconds + clockSkewSeconds
```

The check is part of P4, so it needs P4 in `requiredPredicates`; a config that sets it without P4
fails at startup. A `not_after` exactly at the limit is allowed. The bound also limits how long a P6
nonce is held, since a nonce is kept until `not_after + clockSkewSeconds`.

**Is `not_after` authenticated?** Only when P5 is required. `not_after` is one of the fields of the
signed `mcp-v1` payload (see above), so under P5 a caller can't change it without breaking the MAC.
Without P5 it is a value the caller supplies, and the bound is only as trustworthy as the caller.

**Why it bounds the remaining lifetime instead of checking an `iat` claim.** The review suggested
an issued-at (`iat`/`not_before`) claim in the signed payload, so the gateway could check
`not_after - iat`. That would change the `mcp-v1` payload, which means a new payload version, a
change for every attester, and a change to the ABV corpus vectors. Bounding `not_after` against the
gateway's own clock needs none of that and enforces the same thing at execution time: no approval
accepted now can stay valid for longer than the bound. What it doesn't do is reject an approval
that was issued long ago with a long lifetime and is now inside its last
`maxApprovalLifetimeSeconds`. An `iat` check would catch that, and it remains possible as a future
payload version.

### rpc-param envelope removal

With `approvalSource: rpc-param` and `stripApprovalEnvelope: true` (the default), the policy removes
the top-level `approvalRpcField` member from the body before forwarding it (#52), so the MCP server
never receives the approval or its attestation MACs, and a strict JSON-RPC server doesn't see an
unknown top-level member. This applies to every forwarded `tools/call`: an allowed call in either
mode, and a monitor-mode would-deny. An out-of-scope method, a denied call and `approvalSource:
header` are left as they are.

- **Byte-exact.** The member is cut out of the original bytes together with one adjoining comma.
  Nothing else is re-serialized, so the upstream receives exactly the argument bytes P2 checked,
  including their whitespace, member order and escapes. Only the top-level member is removed; a
  nested member with the same name is part of the arguments and stays. A key spelled with JSON
  escapes counts as the same member.
- **Checked before forwarding.** The strict parse has already rejected duplicate members at any
  depth, so at most one member can match. The stripped body is parsed again and must equal the
  original minus that member. If it doesn't, block mode denies the call as `malformed`. Monitor
  mode forwards it unchanged, records a policy violation, logs why, and stamps
  `monitor;envelope=unstripped` (or adds `;envelope=unstripped` to a would-deny) instead of
  `allowed`. The removal runs before the P6 reservation, so a failure
  never uses up a nonce.
- **`content-length` is rewritten.** PDK 1.10's `BodyHandler::set_body` writes only the body buffer
  (`pdk-classy` `hl/headers_body.rs`); nothing in the PDK or `proxy-wasm` 0.2.5 adjusts
  `content-length`. So the policy sets `content-length` to the new length itself. The request
  headers haven't been sent upstream yet at that point, because the filter is still holding the
  request to read its body. The `#[pdk_test]`
  `rpc_param_envelope_is_stripped_before_the_real_upstream` checks this on a real Flex Gateway
  1.14.0: the upstream mock accepts only the exact stripped bytes with the new `content-length`.
  It runs in CI (`runtime-e2e-approval`).

On a denial the log carries a structured event, e.g.
`{"event":"approval_execution_binding","action":"deny","predicate":"P1","reason":"approved action 'deploy.apply', executed 'deploy.destroy'"}`

The reason names only the failed predicate and, where relevant, the mismatched action/reference
identifiers — never the argument payload, approval-token values, or attestation key material.

**PDK policy violation registration.** Every predicate-failure decision — a `block`-mode denial
*and* a `monitor`-mode would-deny detection — registers a PDK policy violation via
`PolicyViolations::generate_policy_violation()`, mirroring the sibling Decoy Tool Sentinel, so
Anypoint Monitoring/SIEM records the hit even when `monitor` mode still forwards the request. A
structural/framing rejection that never reaches predicate evaluation at all (no body, wrong
content-type, framing refusals for a missing/oversized/mismatched `content-length`, unparseable
JSON-RPC envelope) does not
register a violation — there is no evaluated verdict to report — but is still logged via the
structured warning above and, in `block` mode, still denied.

### Honesty boundaries

Further honest limitations, disclosed rather than hidden:
- **Symmetric HMAC, not PKI — separation-of-duties, not non-repudiation.** `attesterKeys` holds
  shared secrets and P5 verifies an HMAC-SHA256 over the canonicalized versioned `mcp-v1` payload
  (not the raw scope). Because the verifying gateway holds the same secret it verifies against, this
  is a **separation-of-duties** control (the attester differs from the executor), **not**
  non-repudiation in the cryptographic sense — the gateway could in principle have minted the MAC
  itself. A production PKI deployment would instead verify asymmetric signatures against a JWKS;
  this build implements only the symmetric form. Keys shorter than 32 bytes are rejected at startup.
- **`approvalSource: sidecar` is not implemented.** Fetching the approval record from an external
  attestation service is out of scope for this build. Selecting it fails policy startup with a
  clear error rather than silently no-op-ing, so a misconfiguration can't be mistaken for an armed
  binding.
- <a id="p6-single-use-boundary"></a>**P6 single use is per gateway replica, until restart.** P6 uses
  gateway data storage `local()`, which is per-replica and has no TTL control. P6
  reserves the nonce atomically via the gateway's data-storage API (`store(&nonce,
  &StoreMode::Absent, ...)`): the first reservation succeeds and the call is allowed; a second
  reservation of the same nonce returns a CAS mismatch and the call is denied under P6; any other
  storage error **fails closed** (deny). The reservation happens only in **block** mode — monitor
  mode never reserves. But `local()` storage is **per-replica** and its durability across a gateway
  **restart** is runtime-defined: a replayed approval can slip through on a second replica or after
  a restart. A horizontally-scaled deployment needing durable, global P6 must swap `local()` for a
  shared/remote store. These behaviours can only be shown on a real gateway. The 2026-09-25
  connected run (brief: `docs/ASTRA-TASK-approval-p6-replay.md`) is a **qualified partial**
  verification. It proved P5 with real Client ID Enforcement and same-replica replay rejection.
  It observed replays reopening across replicas and after a restart, the expected `local()`
  limitation. It left shared-store global reservations unproven. It also found the
  storage-unavailable fail-closed branch correct by inspection but unreachable on `local()`,
  because the pinned proxy-wasm SDK panics on unexpected host statuses. See
  [`APPROVAL-P6-CONNECTED-2026-09-25`](../docs/APPROVAL-P6-CONNECTED-2026-09-25.md) and
  [`APPROVAL-STORAGE-UNAVAILABLE-2026-09-25`](../docs/APPROVAL-STORAGE-UNAVAILABLE-2026-09-25.md).
  **Recommendation: deploy a single gateway replica for flows that require P6**, and treat a
  restart as reopening unexpired approvals. The follow-up for a global guarantee is
  `remote()` storage with a TTL ≥ the maximum approval lifetime + `clockSkewSeconds`, keys
  namespaced by issuer — it is not in this build (#51).
- **Reserved P6 nonces are bounded by an approximate cap, not a TTL (#51).** `local()` has no TTL,
  so the policy bounds the store itself. Each reservation records the nonce's expiry, and the normal
  path is a single atomic `store(nonce, Absent, …)` — the same operation the P6 path was proven on.
  Each worker counts its reservations; when its count reaches **10,000**, it lists the store, deletes
  every nonce whose approval has expired under P4 (`now > not_after + clockSkewSeconds`), and resets
  its count to what remains. Forgetting such a nonce cannot reopen a replay, because replaying it is
  still a P4 denial. If the store is still full after that sweep, the reservation **fails closed** (a
  P6 denial); a storage error during the sweep also fails closed. Plan for these limits:
  (1) **the bound is approximate** — the count is per worker and resets when the worker's VM is
  rebuilt, while the store is shared by the replica's workers, so between sweeps the store can exceed
  10,000 by up to 10,000 per worker; (2) **the sweep's key listing (`get_keys`) is not yet verified on
  a real gateway** — it runs only at the cap, and if it errors there, P6 reservations at the cap fail
  closed; (3) **without P4 in `requiredPredicates`, no reserved nonce ever expires**, so once a sweep
  finds the store full a P6-only deployment stops admitting new single-use approvals on that replica
  until restart — require P4 with P6; (4) an approval with a far-future `not_after` holds its slot
  until then (see the next item).
- **The approval lifetime bound is off by default and checks `not_after`, not an issue time (#52).**
  With `maxApprovalLifetimeSeconds` unset, P4 checks only `now <= not_after + clockSkewSeconds`, so
  an attested `not_after` years away is accepted and, unless P6 is required, reusable until then.
  Set the bound when that matters. It limits the remaining lifetime, not the total, and `not_after`
  is authenticated only under P5 (see [Approval lifetime bound](#approval-lifetime-bound)).
- **The rpc-param envelope is removed only from bodies this policy forwards (#52).** With
  `stripApprovalEnvelope: false`, or on an out-of-scope method, the `approvalRpcField` member reaches
  the MCP server. Removal applies only to a single JSON-RPC object that passed the strict parse, so a
  batch or malformed body is never rewritten (it's denied in block mode and forwarded unchanged in
  monitor mode).
- **No `.on_response()` handler, by design.** Unlike the sibling MCP Honeytoken Tripwire, this
  filter registers only an `on_request` handler. PDK's `DualFilter` re-runs a configured response
  handler even over a request filter's own `Flow::Break` early reply, and a response handler that
  requires a declared `content-length` (as Tripwire's does) treats that self-generated reply as an
  uninspectable body and withholds it — which is why, empirically, Tripwire's in-band JSON-RPC
  denial bodies come back empty under `pdk_unit`. Registering no response handler here means this
  policy's own early-reply denials are sent as constructed, with nothing downstream re-inspecting
  them. This policy never rewrites a response body. It forwards a request unchanged, forwards it
  with only the `rpc-param` envelope removed (see above), or denies it before it reaches the
  upstream tool, so the response-body-rewriting boundary that applies to Tripwire does not apply
  here.
- **`onDeny: rpc-error` denials return HTTP 200,** by design: the JSON-RPC `-32008` error is
  delivered in-band, matching real JSON-RPC semantics where errors are payload-level, not
  transport-level. A caller (or a test) that only checks the HTTP status code cannot distinguish an
  allowed, forwarded request from an in-band denial — both return 200. Verify the response body
  shape (or, in tests, whether the upstream was actually reached) instead.
- **P4 is tested against the real clock, not the vendored vectors' fixed timestamps.** The ABV
  vectors encode fixed 2026-09-19 calendar timestamps for a checker that trusts a record-supplied
  "at"; this policy instead binds P4 to real wall-clock time (`chrono::Utc::now()`), so its freshness
  tests use dynamically computed `not_after` values instead of replaying a vector that would now
  always read as expired.
- **Reference-shaped arguments are rejected, not dereferenced.** An earlier draft carried a P3
  predicate that verified the bytes behind a `$ref`-shaped argument via a caller-supplied
  `dereferenced` digest map. That asked the gateway to trust a caller-populated blob map it cannot
  itself resolve. This build removes P3 entirely: any argument object carrying a `$ref` key (at any
  depth) is **rejected under P2** — the approved and executed argument bytes must match directly.
  (A `$ref` appearing only as a *string value* is fine; it is a `$ref`-shaped *object* that is
  rejected.)
- **A sound record checked by the party it constrains proves nothing without P5.** P5's
  separate-attester requirement exists precisely because a record whose only witness that it was
  approved is the executor itself is not evidence of anything beyond the executor's own say-so —
  the same limitation the ABV corpus states about itself.

### Testing

`src/test.rs` (declared as `#[cfg(test)] mod test;` from `src/lib.rs`; **97 tests**, run via
`cargo +1.89.0 test --lib`) covers all five predicates via the vendored ABV vectors
(`tests/fixtures/abv/`) plus hand-authored edge cases: config validation (empty/unknown predicates
and enum values, `sidecar` rejection, duplicate/blank attester kids, **sub-32-byte attester key
rejection**, **`expectedAudience` required when P5 is required**), malformed/oversized/batch/
notification JSON-RPC framing, monitor-vs-block behavior, the rpc-param approval source, **non-
`tools/call` methods forwarded as out-of-scope** (never blocked), **bodyless `GET` (SSE)/`DELETE`
(session)/`OPTIONS`/`HEAD` forwarded out-of-scope in block and monitor mode** while a bodyless or
lowercase `post` and a non-`POST` carrying a `tools/call` body stay bound, **framing refusals**
(no/short/oversized `content-length` stamped `denied;framing=content-length`), **charset
admission** (a UTF-7 `tools+AC8-call` body and every non-`utf-8` charset denied in block and
flagged in monitor; `utf-8` spellings allowed), **unparseable bodies** (lone surrogate, BOM, nesting
> 128) denied as malformed rather than forwarded out-of-scope, **`$ref`-shaped arguments rejected
under P2** (top-level, nested, `$ref`+extra keys) while a `$ref` string *value* is allowed,
**versioned canonical-JSON digests** (a float or non-integer number, an integer outside
±(2^53 − 1), and a UTF-8/UTF-16 key-order disagreement all fail closed; `null` vs `{}` vs
`[]` vs a scalar all produce distinct digests), **P5 authenticated over the `mcp-v1` payload** (each
protected claim, when mutated, flips to deny; kid rotation), **the executor read from verified
`AuthenticationData`** (an injected verified subject wins over a spoofed header; absent-and-P5-
required fails closed), **atomic single-use via data storage** (first allow, replay denied under P6,
monitor mode does not reserve; below the cap a reservation is one `store` call and never lists keys,
at the cap a sweep deletes P4-expired nonces and a still-full store fails closed, exercised with the
cap set to 3 under `cfg(test)`), **the approval lifetime bound** (allowed exactly at `now +
maxApprovalLifetimeSeconds + clockSkewSeconds`, denied one second or one millisecond past it, off
when unset, never relaxes expiry; range and requires-P4 validated at startup), **rpc-param envelope
removal** (first, middle, last and only member; whitespace and escapes kept byte-exact; an escaped
key matched; a nested same-name member kept; duplicates fail closed; forwarded body and
`content-length` checked on allow and on monitor would-deny; header mode and `stripApprovalEnvelope:
false` untouched; a monitor-mode strip failure never stamped `allowed`), **bounded clock skew**
(`clockSkewSeconds` outside `0`–`3600` rejected at startup, an out-of-range skew fails P4 closed
rather than disabling it, and a nonce expiry that can't be represented is never swept instead of
wrapping into the past), PDK policy-violation registration on both block-mode denials and
monitor-mode would-deny detections (and its absence on a clean allow), atomic (never partial) denial
of a batch containing an unauthorized call, the content-type/content-encoding header-phase admission
gate, bounded-depth JSON parsing (deeply nested bodies fail closed without panicking, in both the
JSON-RPC body and the approval header), a numeric-overflow literal that fails closed deterministically
without panicking, the ambiguous-duplicate-`id` containment rule, and a corpus self-consistency check
that deserializes every `tests/fixtures/abv/*.json` vector. `tests/requests.rs`
adds a small Docker/`pdk_test` end-to-end suite (sound-approval-reaches-upstream,
action-mismatch-denied-and-never-reaches-upstream, and the #50 transport pass-through: `GET` SSE and
`DELETE` session reach upstream stamped `out-of-scope` while an unapproved `tools/call` is denied) — deliberately smaller than Tripwire's
integration suite, since this policy's threat model ("is this record proof of this execution") is
already covered exhaustively by the unit tests; it adds only what an in-process harness cannot
exercise. Behaviour that needs a connected gateway was checked on a real Flex Gateway: P5 with
real Client ID Enforcement, and same-replica P6 replay rejection. That run was a qualified
partial verification; the evidence is in [`docs/`](../docs/README.md). `tests/CONNECTED.md`
describes the runnable connected extension.

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
