# Connected P5/P6 composite

`requests.rs` retains the original two P1+P2 cases and adds the explicitly ignored
`connected_p5_p6_identity_replay_replica_and_restart` composite. It was compiled,
**not executed**, in the 2026-09-25 attempt: unchanged-schema publication was rejected
by Exchange ([issue #21](https://github.com/msaleme/agent-governance-policies/issues/21)).
The fixture and lifecycle integration below are prerequisites for a future run,
not artifacts that this blocked attempt claims to have provisioned.

Use a dedicated, authorized Docker daemon. PDK test startup removes containers and
networks carrying its own test labels; inspect those labels before running it.
Use fresh connected registration material in a private directory outside the repo.
Never reuse another project's registration. The composite owns two Flex 1.14.0
replicas and a real HttpMock upstream named `backend`, listening on port 80.

Provision a fresh MCP API instance listening on port 8081 and a chosen route, with
upstream `http://backend:80/`. Chain Client-ID Enforcement before this unchanged
custom policy. Create a disposable client application and approved contract.
Configure this policy with `requiredPredicates: [P1, P2, P4, P5, P6]`, `mode: block`,
`onDeny: rpc-error`, `approvalSource: header`, `approvalHeader: x-approval`,
`executorHeader: x-executor`, `resultHeader: x-approval-binding`, and the fixture's
nonempty audience, tenant and environment. Configure the same fresh ≥32-byte key
under the independent attester ID and the client ID (to exercise self-attestation
with a known key). Keep all values private. Do not change the schema to work around
#21 as part of verification.

Supply `APPROVAL_CONNECTED_FIXTURE` as the path of a mode-0600 JSON file containing:

| Field | Meaning |
|---|---|
| `registration_directory` | Private directory with fresh connected registration |
| `route` | Leading-slash API listener path |
| `client_id`, `client_secret` | Disposable application credentials |
| `attester_key`, `attester` | Fresh HMAC secret and separate authority ID |
| `audience`, `tenant`, `environment` | Exact deployed expected identity fields |
| `lifecycle_hook` | Absolute path of the operator's Python lifecycle adapter |
| `evidence_path` | Absolute path for sanitized per-case results |

The lifecycle adapter is deliberately external to the test: control-plane API
credentials and registration lifecycle stay outside the Rust assertion code.
It is **not implemented or exercised by this blocked run**. Its interface is:

```
python3 <lifecycle_hook> ready <replica-A-URL> <replica-B-URL>
python3 <lifecycle_hook> restart <replica-A-URL> <replica-B-URL>
```

For `ready`, wait for the API deployment push to apply, confirm the intended
ordered policies/configuration and the exact WASM SHA-256 on both replicas, and
wait for the real authentication policy's application cache to be ready. For
`restart`, restart **only replica A**, verify a new process start, then repeat
those readiness checks. Return nonzero on uncertainty. Never output raw gateway
dumps, registration material, configuration secrets or request headers. Record
sanitized control-plane timestamps, resource IDs and hash comparisons separately.
The composite captures hook output privately and does not print it.

After those prerequisites, select only the new composite:

```sh
DOCKER_DEFAULT_PLATFORM=linux/amd64 cargo +1.89.0 test --test requests \
  connected_p5_p6_identity_replay_replica_and_restart -- --ignored --exact
```

The test signs a real `mcp-v1` payload and selects replicas directly to remove
load-balancer routing ambiguity. It records status, denial predicate, RPC error
code and backend hit count for each request, then fails if any observed result
differs from its expectation. It intentionally expects replay to be allowed on
a different replica and after restart to document the demo's **local-store
limitation**, not global single-use. It does not prove a load balancer, remote
storage, or storage-error handling. PolicyViolation counts, artifact/deployment
identity, container restart evidence, and confirmed remote-resource deletion
must be joined into the run evidence separately. Do not equate this test's exit
code, a unit pass, or monitor observations with full connected verification.

Always delete the API instance, contract/client application, disposable Exchange
versions and registration after the run; confirm those deletions independently
of TestComposite's local container/network teardown.
