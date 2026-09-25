# Approval binding: connected P5/P6 verification, 2026-09-25 UTC

**Qualified partial verification.** Seven real gateway probes passed in the final
container run. Same-replica nonce rejection and P5 with real Client-ID Enforcement
are proven. Cross-replica and restart replay reopening were observed as expected
limitations of `local()`. Shared-store global reservations and storage-error
fail-closed remain **unproven**; this is not an all-green completion of brief
cases 1–5. No live binding-policy interoperability failure was observed.

Machine evidence: [approval-p6-connected-2026-09-25.json](evidence/approval-p6-connected-2026-09-25.json).
Runnable extension and private setup: [tests/CONNECTED.md](../approval-execution-binding/tests/CONNECTED.md).

## Source and published artifact

Fresh clone/topic branch from `origin/main`
`3b7d9090d1dfba63bbd3e568ead7b848f8bd1ccd`, including PRs #19 and #23.
PR #22 was left untouched. The maintainer's original checkout was not modified.
No runtime, Predicate enum, GCL schema, or original P1/P2 composite was changed.

Rust 1.89.0, PDK and cargo-anypoint 1.10.0; installed AnyPoint CLI PDK plugin
1.9.0. Actual `make build` and standard `make publish` exited 0. Live Exchange
GETs returned 200 for both definition and implementation. The generated schema
retained `attesterKeys[].key`'s JSON-LD `@characteristics: [security:sensitive]`.
Exchange accepted `metadata/capabilities/assetTypes: mcp`, and applying the
published policy to the disposable MCP API returned 201. Both publish-time
acceptance items are **confirmed**. UI key masking was not separately tested.

Standard generation changes checked-in deserialization defaults. This was filed
as [issue #24](https://github.com/msaleme/agent-governance-policies/issues/24),
without patching the policy. The standard development publication
`0.0.1-20260925143950` has WASM SHA-256
`8f360d95df5605050dd12d5fe362c226a7c40f029b308d2c35b3c876fdf3720b`;
it was not the enforcement test artifact.

For the separate verification publication, the existing Makefile `FLAGS` hook
restored `HEAD:src/generated/config.rs` immediately after generation and before
compilation: `FLAGS=git restore --source=HEAD -- src/generated/config.rs &&`.
That `make publish` also exited 0. This preserved the checked-in runtime without
hand-editing generated source. The live artifact was:

- Definition: `approval-binding-live-20260925-dev`, `0.0.1-20260925144221`.
- Implementation: `approval-binding-live-20260925-flex-dev`, same version.
- WASM SHA-256: `52aa23bb5aa5563752b0e46b76d3693eba852cc5baeef7ca6eb7eea20ffc1f20`.
- Flex/Omni 1.14.0, linux/amd64; two connected Docker replicas and HTTP mock backend.

## Deployment and configuration

Authorized disposable Sandbox API **21197857**, deployment **28449921**, gateway
`approval-binding-live-20260925`. Ordered chain: Client-ID Enforcement 1.3.3
(policy 9342473), then approval binding (9342475). Required predicates
P1/P2/P4/P5/P6, `mode=block`, `onDeny=rpc-error`. Audience, tenant, environment,
independent attester and a fresh key of at least 32 bytes were configured. The
real client application had an approved API contract.

Performed one **real UI Save & Apply** in the API Settings page. The browser
showed deployment in progress; `deployment.updatedDate` changed from
`2026-09-25T14:46:36.621Z` to `2026-09-25T15:07:53.460Z`. The deployment API
subsequently reported `applied`, and API status was `active`. Polling missed the
short `updating` state; an exact API Active→Updating→Active sequence is **not**
claimed. Before enforcement probes, both replicas independently matched every
supplied policy configuration field, the WASM hash, and Ready=true in in-memory
runtime dump inspection. No raw dump was saved or published.

Harness retries reused that unchanged UI-applied deployment. There was no
repeated PATCH/Save & Apply churn. The initial attempt recorded six passing wire
probes, then its restart inspection raced flexctl startup (harness exit 101).
A test-only readiness retry fixed the harness; the next container run exited 0.
The final run added telemetry drains before restart/teardown and also exited 0.
All attempts and UTC timestamps are retained in the JSON, not merged into a
fictional single execution.

## Final wire results

Each `tools/call` invokes inert `deploy.apply` with `{"confirm":true}`. The sound
HMAC covers the `mcp-v1` claims, actual verified client subject, canonical argument
digest, expiry and nonce. Replays retain the same signed approval; request IDs
vary only to isolate upstream mock hit counts. Every request supplies a spoofed
`x-executor`; auth policy provenance determines the verified executor.

| Probe | HTTP | Binding outcome | Upstream hits | Result |
|---|---:|---|---:|---|
| Independent attester, verified subject, replica A | 200 | Forwarded | 1 | Pass P5 / initial P6 reservation |
| Same approval, replica A | 200 | P6 denied, JSON-RPC -32008 | 0 | Pass: exactly one hit across first/replay |
| Same approval, replica B | 200 | Forwarded | 1 | Known per-replica local-store limitation |
| Repeat on replica B | 200 | P6 denied, JSON-RPC -32008 | 0 | Pass: reservation persists on B |
| Self-attester equals verified executor | 200 | P5 denied, JSON-RPC -32008 | 0 | Pass |
| MAC subject uses spoofed header | 200 | P5 denied, JSON-RPC -32008 | 0 | Pass |
| Original approval after A restart | 200 | Forwarded | 1 | Known in-memory restart limitation |

Denied responses carried `x-approval-binding: denied;predicate=P5` or `P6`.
HTTP 200 with a JSON-RPC error is enforcement, not an allow. Actual container
start timestamps changed on restart, and configuration/hash/readiness were
rechecked before the replay. Direct replica selection proves isolated stores;
this is not a load-balancer distribution test. Pod rescheduling and independent
memory-pressure eviction were not exercised.

## Remaining storage proof

The unchanged entrypoint selects `store_builder.local(NONCE_STORE_NAME)`.
MuleSoft's [data storage documentation](https://docs.mulesoft.com/pdk/latest/policies-pdk-configure-features-data-storage)
describes remote/shared Redis storage for multi-replica persistence and atomic
reservation operations. That is the documented fix path; global reservation was
**not empirically verified** here. Changing the policy to select `remote()` would
cross this verification-only task's runtime boundary.

Case 4 is **not run**, not passed or failed: there is no detachable store backend
in this artifact, and no supported local-hostcall fault injection was identified.
Killing a gateway or breaking its control-plane connection would not prove the
policy's storage-error branch. Completing the two remaining checks requires a
separately authorized shared-store implementation or a supported runtime fault
injection mechanism, then real connected verification. No defect is fabricated
from this coverage gap.

## Monitoring, deletion and validation

The API-scoped `mulesoft.api.summary` query exported **four approval-policy
PolicyViolation counts in the final run’s 15:13 UTC export bucket**, matching the two P6 and two
P5 denies. Minute aggregation cannot attribute a metric to each individual
probe; JSON per-case metric counts are null. Readiness HTTP 401s belong to
Client-ID Enforcement and are reported separately. Earlier attempts lost some
counters during immediate restart/teardown; the final harness holds replicas
alive for 90 seconds before each operation. Wire/backend results are separate
from monitoring counts.

All disposable resources were deleted and checked: API and deployment/policies,
contract, client application, both versions of the definition and implementation,
MCP Exchange version, registration, replica/backend containers and Docker
network. Cloud resources returned GET 404, and Docker confirmed absence. Private
identity, credentials and captured logs were removed after a credential scan of
the proposed commit. Exact statuses and cleanup timestamps are in the JSON.

Local validation: the real connected composite exited 0; formatting and Python
syntax checks passed; original P1/P2 content and runtime/GCL files were confirmed
unchanged. GitHub `policies` and GitGuardian checks are PR gates, not evidence of
container enforcement. This PR must remain unmerged for maintainer review.
