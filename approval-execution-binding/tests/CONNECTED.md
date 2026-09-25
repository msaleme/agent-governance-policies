# Connected P5/P6 composite

The ignored `connected_p5_p6_identity_replay_replica_and_restart` test extends the
original two P1/P2 composites without changing them. It requires a disposable,
authorized connected gateway registration, MCP API, client application/contract,
and an ordered Client-ID Enforcement → approval-binding chain in block mode.
It starts two Flex 1.14.0 replicas and a real HTTP mock backend. Never run it on a
Docker daemon hosting another PDK test: PDK uses the shared `CreatedBy=pdk-test`
label and `pdk-test-network` name when cleaning up.

The test sends real authenticated requests and checks exact backend hit counts,
P5/P6 response headers, JSON-RPC error codes and HTTP statuses. It deliberately
selects each replica directly, then restarts replica A. Cross-replica and restart
allows document the local-store limitation; they do not prove global single-use.
Shared storage and storage-error injection are not implemented by this harness.

## Private prerequisites

Create a mode-0700 directory outside Git and keep its files mode 0600. Do not log,
commit, or paste credentials, registration YAML, signed approvals, raw runtime
dumps, or PDK container logs. Configure:

- `fixture.json`: `registration_directory`, `route` (for example `/mcp/`),
  `client_id`, `client_secret`, `attester_key` (at least 32 bytes), `attester`,
  `audience`, `tenant`, `environment`, `lifecycle_hook` (absolute path to
  `connected_lifecycle.py`), and `evidence_path` (private `cases.json`).
- `lifecycle.json`: `organization_id`, `environment_id`, `api_id`, `gateway_name`,
  `definition_asset_id`, `wasm_sha256`, and `deployment_mode: "ui"`. Provision the
  API first; the hook discovers the new registration and creates its deployment.
- `expected-configs.json`: an array containing the complete supplied
  `configurationData` objects for the auth and approval policies. The hook checks
  every supplied field against the loaded runtime configuration in memory and
  verifies the WASM hash and Ready condition. Never persist the raw dump.
- Environment variables `ANYPOINT_CLIENT_ID` and `ANYPOINT_CLIENT_SECRET`:
  authorized control-plane connected-app credentials, distinct from the fresh
  test client application credentials in the fixture.

The approval configuration requires P1/P2/P4/P5/P6, `mode: block`,
`onDeny: rpc-error`, `approvalSource: header`, `approvalHeader: x-approval`,
`resultHeader: x-approval-binding`, and `executorHeader: x-executor`. Supply all
three expected audience/tenant/environment values. Provision two attester-key
entries, one for the independent attester and one for the test client ID, with
the fresh test key. The latter permits testing cryptographically sound
self-attestation rejection. Auth policy 1.3.3 reads `client_id` and `client_secret`
headers through its configured expressions; it must run first.

## Run and apply

```sh
APPROVAL_CONNECTED_FIXTURE=/absolute/private/run/fixture.json \
DOCKER_DEFAULT_PLATFORM=linux/amd64 \
cargo +1.89.0 test --test requests \
  connected_p5_p6_identity_replay_replica_and_restart -- --ignored --exact
```

Capture stdout/stderr in the private directory. Once the deployment is created,
perform **one real UI Save & Apply** on that API's Settings page. Observe the
status and `deployment.updatedDate` change. Only after the real click, write
`ui-save-apply-confirmed.json` alongside the fixture with `api_id` matching the
numeric API ID, `method: "ui"`, and the actual UTC `at` timestamp. This marker is
an operator assertion, not independent proof of a browser action; retain
sanitized observations with the evidence. The hook then requires an applied
status, a changed timestamp, matching loaded configs/WASM, and authenticated
readiness before running cases. It waits up to 15 minutes for the UI marker.

If a harness-only retry is needed, the hook can reuse the same unchanged,
previously UI-applied deployment. It checks the matching UI marker and applied
status again. It does not PATCH a policy or repeatedly Save & Apply. If a live
API route wedges, delete and recreate the disposable instance.

The lifecycle adapter also has an `api` deployment mode for separately,
explicitly authorized workflows; this run used `ui`. Do not use `api` to satisfy
a task that specifically requires UI Save & Apply.

The hook waits 90 seconds before restart and teardown to allow gateway telemetry
to flush. Query API-scoped monitoring separately; the drain does not itself prove
that every metric arrived. Per-case wire/backend evidence is written after each
probe, before the final aggregate assertion. `lifecycle-evidence.json` contains
sanitized deployment/readiness/restart observations. A harness error is written
to `lifecycle-failure.json` without raw exception payloads.

After capturing metrics, delete and verify deletion of the contract, API and its
deployment/policies, client application, all published test versions, connected
registration, containers, and network. PDK teardown covers only its containers
and network. Delete private credentials and logs after extracting sanitized
evidence. Never present an ignored test, native compilation, or unit suite as a
successful container run.
