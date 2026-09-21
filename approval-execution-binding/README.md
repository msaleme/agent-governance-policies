# Approval-to-Execution Binding

> Part of the [Agent Governance Policies](../README.md) family.
>
> NIST SP 800-53 Rev 5 **AC-3** (Access Enforcement — the gateway is where the executed action
> either matches or fails to match what was approved), **AC-4** (Information Flow Enforcement —
> the approval record must travel with the request across the hop from approver to executor),
> **AU-10** (Non-repudiation — the P5 separate-attester requirement), and **AU-2** (Event
> Logging — the structured verdict line below). OWASP **LLM06: Excessive Agency**. MITRE ATLAS
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
nothing at the gateway catches it. This policy closes that gap: on every governed MCP/A2A
JSON-RPC execution, it checks the accompanying approval record against six independent
predicates and denies the call if any **required** predicate fails.

Predicate semantics, canonical form, and the P2/P3 precedence rule all follow the
[**Approval Binding Vectors (ABV) v0.1**](https://github.com/msaleme/approval-binding-vectors)
conformance corpus (MIT) — a protocol-neutral spec for exactly this question, with its own positive
controls and negative vectors. This implementation vendors all 12 ABV vectors
(`tests/fixtures/abv/`) and drives its negative/positive unit tests directly from them.

- **`monitor`** (Expose) — evaluate every required predicate on every governed call and log the
  verdict (allow, or the specific predicate that would have failed) via a structured warning, but
  always forward the request regardless of the outcome. Use this to characterize how approvals and
  executions actually line up before switching anything to enforce.
- **`block`** (Affect) — deny the call when a required predicate fails, per `onDeny`, even though
  nothing about the request's own JSON-RPC framing is otherwise invalid.

### The six predicates

| ID | Predicate | The failure it excludes |
|---|---|---|
| **P1** | Action | Approved tool A, executed tool B. |
| **P2** | Arguments | Approved A with args X, executed A with args Y. |
| **P3** | Dereference | An argument carried by reference (`{"$ref": "..."}`); the bytes behind it changed. Takes precedence over P2 whenever a reference is involved. |
| **P4** | Freshness | Approval correctly scoped and granted, but expired before execution — checked against this gateway's own wall clock, never a caller-supplied timestamp. |
| **P5** | Separate attester | A record whose only witness that it was approved is the party now executing it. |
| **P6** | Single use *(opt-in)* | One approval, replayed for a second execution. Reusable approvals are legitimate in some flows, so P6 defaults out of `requiredPredicates`. |

**Honesty boundary.** This policy (and the ABV corpus it implements) tests whether the *record*
proves the executed action is the approved one. It does not and cannot prove that approving the
action was itself wise — that is a policy question the record cannot answer on its own. P5's
separate-attester requirement is what keeps the check from being a document an actor wrote about
itself; it does not establish that the attester was *entitled* to approve the action.

### Inspection boundary

Before any body is buffered, the policy checks the request's declared framing at the header phase:
a `content-type` that isn't `application/json` (or an `application/*+json` variant) — which
excludes SSE/streaming media types such as `text/event-stream` — or the presence of any
`content-encoding` header (a compressed body, whose decoded size the declared `content-length`
cannot bound) is treated the same as malformed framing below: `monitor` mode logs and always
forwards the request uninspected; `block` mode denies before ever buffering it. This mirrors the
sibling Decoy Tool Sentinel's admission gate and is the reason SSE/streaming, compressed, and
non-UTF-8 bodies are excluded from inspection — this policy cannot safely buffer or parse them as
JSON at all.

Once a body clears that header-phase gate, the policy evaluates it only if it parses as a single
(non-batch) JSON-RPC 2.0 object with a valid, declared `content-length` no greater than **64 KiB**,
and the actual body received matches that declared length exactly. A body that is missing
entirely, declares no length or an oversized one, arrives with a length mismatch, is a JSON-RPC
**batch**, or fails to parse as a single JSON-RPC object at all (missing/invalid `jsonrpc`, missing
`method`, or — for `tools/call` — missing `params.name`) is treated as **malformed**: `monitor`
mode logs the verdict and always forwards; `block` mode denies. Batches are explicitly out of scope
for approval binding, not a future predicate — an approval record binds to one executed action, not
to a collection of them; a batch is therefore rejected atomically (the whole array denied together)
and never split into a per-member allow/deny — so an unauthorized or altered call riding inside an
otherwise-plausible batch can never slip through as one of several forwarded calls.

**What this policy reads — and nothing else.** Inspection is limited to: the approval envelope
(from `approvalHeader` or, for `approvalSource: rpc-param`, the `approvalRpcField` sibling member of
the JSON-RPC body), the executor identity header (`executorHeader`), and the JSON-RPC body itself
(`jsonrpc`/`id`/`method`/`params`, and for `tools/call`, `params.name`/`params.arguments`). It never
inspects arbitrary headers, the query string, or the request path.

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
| `executorHeader` | string | `client_id` | Header carrying the already-authenticated identity about to execute; used only for P5. |
| `requiredPredicates` | string[] | `[P1, P2, P3, P4, P5]` | Predicates that MUST hold. Empty list rejected at startup. P6 is opt-in. |
| `attesterKeys` | `{kid, key}[]` | `[]` | Known attester keys for the P5 HMAC-SHA256 check. An attestation from an authority not listed here always fails P5. |
| `clockSkewSeconds` | integer | `60` | Tolerance applied to P4: valid while `now <= not_after + clockSkewSeconds`. |
| `mode` | `monitor`\|`block` | `monitor` | Evaluate and log only, vs. actually deny on a failed required predicate. |
| `onDeny` | `rpc-error`\|`empty-403` | `rpc-error` | How a block-mode denial is rendered. A request that can't be confidently parsed as a single, non-batch JSON-RPC call with an echoable id always falls back to `empty-403` regardless of this setting — echoing an untrustworthy id risks exposing a protected value. A notification (no id) always gets an empty HTTP 202. |
| `resultHeader` | string | `x-approval-binding` | Header stamped with the verdict (`allowed`, `would-deny;predicate=P2`, `denied;predicate=P5`) — never the approval or argument values themselves. |

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
  ],
  "dereferenced": {"blob://plan-v1": "<sha256-hex-of-dereferenced-bytes>"}
}
```

```yaml
- policyRef:
    name: approval-execution-binding-v1-0-impl
  config:
    approvalSource: header
    approvalHeader: x-approval
    approvalRpcField: approvalBinding
    executorHeader: client_id
    requiredPredicates: [P1, P2, P3, P4, P5]
    attesterKeys:
      - kid: approver.example
        key: "<shared-secret>"
    clockSkewSeconds: 60
    mode: block
    onDeny: rpc-error
    resultHeader: x-approval-binding
```

On a denial the log carries a structured event, e.g.
`{"event":"approval_execution_binding","action":"deny","predicate":"P1","reason":"approved action 'deploy.apply', executed 'deploy.destroy'"}`

The reason names only the failed predicate and, where relevant, the mismatched action/reference
identifiers — never the argument payload, approval-token values, or attestation key material.

**PDK policy violation registration.** Every predicate-failure decision — a `block`-mode denial
*and* a `monitor`-mode would-deny detection — registers a PDK policy violation via
`PolicyViolations::generate_policy_violation()`, mirroring the sibling Decoy Tool Sentinel, so
Anypoint Monitoring/SIEM records the hit even when `monitor` mode still forwards the request. A
structural/framing rejection that never reaches predicate evaluation at all (no body, wrong
content-type, oversized/mismatched `content-length`, unparseable JSON-RPC envelope) does not
register a violation — there is no evaluated verdict to report — but is still logged via the
structured warning above and, in `block` mode, still denied.

### Honesty boundaries

Further honest limitations, disclosed rather than hidden:
- **Symmetric HMAC, not PKI.** `attesterKeys` holds shared secrets and P5 verifies an HMAC-SHA256
  over the canonicalized approval scope — mirroring the ABV reference checker's keyed-digest
  attestation model. A production PKI deployment would instead verify asymmetric signatures against
  a JWKS; this build implements only the symmetric form.
- **`approvalSource: sidecar` is not implemented.** Fetching the approval record from an external
  attestation service is out of scope for this build. Selecting it fails policy startup with a
  clear error rather than silently no-op-ing, so a misconfiguration can't be mistaken for an armed
  binding.
- **P6's nonce store is in-process, not distributed.** It is a single gateway worker's bounded
  (FIFO-evicted at 100,000 entries), in-memory set — reused-nonce detection does not span multiple
  gateway workers/replicas, and a restart clears it. A multi-replica deployment needing durable P6
  needs an external nonce store; this build does not provide one.
- **No `.on_response()` handler, by design.** Unlike the sibling MCP Honeytoken Tripwire, this
  filter registers only an `on_request` handler. PDK's `DualFilter` re-runs a configured response
  handler even over a request filter's own `Flow::Break` early reply, and a response handler that
  requires a declared `content-length` (as Tripwire's does) treats that self-generated reply as an
  uninspectable body and withholds it — which is why, empirically, Tripwire's in-band JSON-RPC
  denial bodies come back empty under `pdk_unit`. Registering no response handler here means this
  policy's own early-reply denials are sent as constructed, with nothing downstream re-inspecting
  them. This policy never rewrites a response body — it only forwards a request unchanged or
  denies it before it reaches the upstream tool, so the response-body-rewriting boundary that
  applies to Tripwire does not apply here.
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
- **`dereferenced` is a novel config-surface concept invented for this implementation.** ABV's
  neutral record shape doesn't include a caller-supplied blob-digest map — a real gateway has no
  blob store to dereference `$ref` URIs itself. This policy's approval envelope therefore carries an
  optional `dereferenced: {"<uri>": "<sha256-hex>", ...}` map, which the caller populates with the
  digest of the content each reference resolves to; P3 fails closed with "unresolvable reference" if
  a `$ref` has no matching entry. The gateway verifies a digest match against what the execution
  context presents for that reference — it does not, and cannot, fetch or independently re-resolve
  the reference itself.
- **A sound record checked by the party it constrains proves nothing without P5.** P5's
  separate-attester requirement exists precisely because a record whose only witness that it was
  approved is the executor itself is not evidence of anything beyond the executor's own say-so —
  the same limitation the ABV corpus states about itself.

### Testing

`src/lib.rs`'s `#[cfg(test)] mod test` (48 tests, run via `cargo +1.89.0 test --lib`) covers all six
predicates via the vendored ABV vectors (`tests/fixtures/abv/`) plus hand-authored edge cases:
config validation (empty/unknown predicates and enum values, `sidecar` rejection, duplicate/blank
attester kids), malformed/oversized/batch/notification JSON-RPC framing, monitor-vs-block behavior,
the rpc-param approval source, PDK policy-violation registration on both block-mode denials and
monitor-mode would-deny detections (and its absence on a clean allow), atomic (never partial)
denial of a batch containing an unauthorized call, the content-type/content-encoding header-phase
admission gate, bounded-depth JSON parsing (deeply nested bodies fail closed without panicking,
in both the JSON-RPC body and the approval header), a numeric-overflow literal that fails closed
deterministically without panicking, and the ambiguous-duplicate-`id` containment rule. `tests/requests.rs`
adds a small Docker/`pdk_test` end-to-end suite (sound-approval-reaches-upstream,
action-mismatch-denied-and-never-reaches-upstream) — deliberately smaller than Tripwire's
integration suite, since this policy's threat model ("is this record proof of this execution") is
already covered exhaustively by the unit tests; it adds only what an in-process harness cannot
exercise.

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
