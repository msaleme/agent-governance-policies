# Approval binding connected verification — 2026-09-25 UTC

**Outcome: blocked before gateway policy execution.** The unchanged sensitive-key
GCL is rejected by PDK CLI 1.10.0 and by the live Exchange publisher. The isolated
Exchange retry returned **HTTP 400**, `strict mode: unknown keyword: "characteristics"`.
Filed [issue #21](https://github.com/msaleme/agent-governance-policies/issues/21).
No P5/P6 wire assertion ran; no container enforcement pass is claimed.

Machine record: [approval-p6-connected-20260925.json](evidence/approval-p6-connected-20260925.json).

## Source, authority and artifact

A fresh checkout/branch was created from `origin/main` at
`8f07a005cbbe4b7abe7cc828468489b00ae43a31`, with checkpoint `1e46807` confirmed
as an ancestor. The maintainer checkout was not modified. The user explicitly
authorized disposable Docker containers on this machine, overriding the brief's
assumption that Docker was unavailable, and had authorized API-based deployment.
Only the previously authorized personal Sandbox was used. No shared/customer
runtime or production resource was changed.

The unchanged `approval_execution_binding` 1.0.0 source built with Rust 1.89.0,
PDK 1.10.0, locked dependencies, release target `wasm32-wasip1`.

```
WASM SHA-256:
52aa23bb5aa5563752b0e46b76d3693eba852cc5baeef7ca6eb7eea20ffc1f20
```

This is the **built** artifact hash. No deployed hash exists for this attempt.
No runtime source, Predicate enum, source GCL, generated configuration, dependency
lockfile, or Makefile was changed.

## Publish-time observations

| Check | Actual result | Disposition |
|---|---|---|
| cargo-anypoint version | Isolated installation reports `cargo-anypoint 1.10.0` | Confirmed |
| `make package` with 1.10.0 on PATH | Exit 2: `No rule to make target 'package'` | Failed; Makefile has no such target |
| Standard PDK package generation | Both CLI plugin 1.9.0 and matching 1.10.0 reject `characteristics` | Failed |
| Direct live Exchange definition publication | Corrected-name retry reports HTTP 400, unknown keyword `characteristics` | Failed, #21 |
| `security:sensitive` acceptance/masking | Declaration cannot pass schema validation | Failed acceptance; masking untested |
| `assetTypes: mcp` | Generated metadata retains `capabilities.assetTypes: [mcp]`; entire asset rejected | Not independently proven |

The standard build probe called the installed PDK plugin's
`PolicyProject.buildAssetFiles(implementationGav, definitionGav,
"gateway.mulesoft.com/v1alpha1", "flexGateway")` in a disposable packaging directory.
It used an exact copy of `definition/gcl.yaml` and disposable coordinates; the
maintainer's metadata and source were untouched. The source property at issue is:

```yaml
attesterKeys:
  items:
    properties:
      key:
        type: string
        characteristics:
          - security:sensitive
```

For the direct API probe, the files already generated before the CLI's validation
failure supplied `metadata.yaml`, `gcl.yaml`, `gcl_src.yaml`, and `exchange.json`.
A JSON schema retained the complete GCL `spec.properties` and `required` values,
including the rejected keyword; only the GCL `extends` directive was excluded.
The definition ZIP retained the byte-identical source GCL. This probe did **not**
remove or rewrite the characteristic, disable a validator, or count as successful
standard packaging.

The Exchange upload operation (CLI transport to the live Exchange API) submitted:

```
asset: <authorized-org>/approval-p6-20260925-dev/0.0.1
type: policy
name: Approval-to-Execution Binding
files: metadata.yaml, schema.json, definition.zip
```

The first submission also reported a mismatch between the disposable upload name
and the name in `metadata.yaml`. That metadata-only mistake was corrected; its
failed asset returned GET 404. The second submission then failed solely with:

```
statusCode: 400
The asset is invalid There was an error trying to parse JSON schema,
strict mode: unknown keyword: "characteristics"
```

No implementation or MCP asset upload followed that rejection. No API instance,
policy application, contract, auth client, or gateway service container was created.
There was consequently no deployment push, `deployment.updatedDate`, Active state
transition, loaded configuration, or gateway PolicyViolation metric to verify.

## Case dispositions

The intended chain was Client-ID Enforcement followed by the unchanged approval
policy in **block** mode with P1/P2/P4/P5/P6 required. The prepared tests use
`tools/call` for `deploy.apply` with `{"confirm":true}`, a real `mcp-v1` HMAC, and a
caller-supplied `x-executor` value different from the verified client identity.
That configuration was **not deployed**, and those requests were **not sent**.

| Case | Actual wire result | Backend hits | Disposition |
|---|---|---|---|
| First use, then same-replica replay | Not sent | Unobserved | Blocked by #21 |
| Replay after restart | Not sent | Unobserved | Blocked by #21 |
| Replay on second replica | Not sent | Unobserved | Blocked by #21 |
| Separate attester + real verified executor | Not sent | Unobserved | Blocked by #21 |
| Self-attestation denial | Not sent | Unobserved | Blocked by #21 |
| Spoofed header subject denial | Not sent | Unobserved | Blocked by #21 |
| Shared-store fix path | Not sent | Unobserved | Outside unchanged-runtime scope |
| Real-store unavailable → fail closed | Not sent | Unobserved | No supported fault injection identified; also blocked by #21 |

**PolicyViolation counts are null/unobserved, not zero.** A unit pass or monitor
observation is not substituted for an enforcement result.

The unchanged entrypoint explicitly calls `store_builder.local("approval-nonces")`.
PDK 1.10.0 implements this with proxy-WASM in-process shared data; there is no
network store endpoint to disconnect. Switching to `remote(...)` changes runtime
behavior and is forbidden in this task. Killing the gateway or breaking its
upstream would not prove the policy's storage-error branch. The shared/remote fix
path remains associated with [issue #3](https://github.com/msaleme/agent-governance-policies/issues/3).
The known cross-replica/restart limitation is documented by the handoff and
[MuleSoft's storage documentation](https://docs.mulesoft.com/pdk/latest/policies-pdk-configure-features-data-storage),
**not observed afresh by this blocked run**.

## Test extension and validation

The original two `tests/requests.rs` P1+P2 composites remain byte-for-byte intact.
An explicitly ignored connected composite was appended. It prepares two real
Flex services plus HttpMock, signs approvals, captures sanitized per-case status,
RPC code, predicate and upstream counts, and selects replicas directly to avoid
routing ambiguity. It expects the demo's local-store replay limitations; that is
not a global single-use guarantee or load-balancer test.

`cargo +1.89.0 test --test requests --no-run --locked`, formatting and diff checks
passed. **The new composite was not executed.** Its deployment/readiness/restart
adapter and private fixture are external prerequisites, not completed run
artifacts. The [fixture and adapter contract](../approval-execution-binding/tests/CONNECTED.md)
records those limits. The deterministic unit suite was not rerun locally; CI's
required repository checks remain separate from live evidence.

## Cleanup

The disposable registration was created using an ephemeral `flexctl` container.
After the isolated publication failure, `flexctl registration delete` exited 0
and reported success. Gateway-target inventory contained no active matching
target. No test container remains; three unrelated, long-stopped containers were
left untouched. No test upstream or network was created.

Hard-delete requests and subsequent GETs returned **404** for all possible test
versions: `approval-p6-20260925-dev`, `approval-p6-20260925-flex-dev`, and
`approval-p6-20260925-mcp`, version `0.0.1`. The latter two were never published.
Private registration, command logs and staging files were removed after evidence
extraction and a credential scan. No identity, client credentials or signing
keys are included in this record.

This PR records a failed publication prerequisite and prepared test coverage.
It does not close connected verification or authorize a merge. Resume the live
matrix after the schema defect is resolved in a separate implementation change.
