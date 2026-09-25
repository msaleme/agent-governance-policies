# Case 4: storage-unavailable fail-closed, 2026-09-25 UTC

**Qualified — not reachably testable on `local()` with this unchanged build.**
No non-CasMismatch store error was induced and no live denial is claimed. The
policy's catch-all `Err` branch is defensively correct by source inspection: it
records a violation and returns a P6 denial before forwarding. The pinned local
storage path does not provide a supported way to deliver the required error to
that branch. This is the qualified outcome explicitly permitted by the follow-up
brief, not a passed connected enforcement test.

Evidence: [machine-readable JSON](evidence/approval-storage-unavailable-2026-09-25.json).
Only case 4 was assessed. Cross-replica replay and the shared-store implementation
remain outside this pass; their existing evidence is unchanged.

## Baseline and artifact

Fresh isolated clone and branch from current `origin/main`, commit
`c1da6056244a697c9b8cf8dcfdc34ecf85de191f` (includes #23, #26 and #25).
The maintainer's checkout was not modified. Runtime code, Predicate enum, GCL,
and tests are unchanged.

Built the current source with Rust 1.89.0 using
`cargo +1.89.0 build --release --target wasm32-wasip1 --locked --offline` (exit 0).
WASM SHA-256:
`f8eb361ca514ab727b4153a5ea3141764b80ead6be2d63664c530017abfd91f1`.
This artifact was **not published or deployed**. The previous #25 artifact and
its live results are historical context, not evidence of a new run of this build.
This narrow follow-up did not repeat publication or the other connected cases.

## Why the error cannot be induced through this local path

1. [`configure`](../approval-execution-binding/src/lib.rs) always selects
   `store_builder.local(NONCE_STORE_NAME)`. There is no configured Redis endpoint
   or store-selection property to withdraw. MuleSoft documents separate
   [local and remote storage APIs](https://docs.mulesoft.com/pdk/latest/policies-pdk-configure-features-data-storage).
2. In PDK 1.10.0, `LocalDataStorage::store` serializes the value, converts the
   mode, then calls local `SharedData::set`. This policy uses `StoreMode::Absent`,
   which does not parse a CAS string, and stores the fixed `1u8`. Both the size
   and encoding passes of pinned `pdk-serde-fixint` 1.11.0 return success for that
   one-byte value. A caller cannot choose another serialization type or format.
3. The wasm32 target selects the real `proxy-wasm` SDK, not the native unit-test
   stub. PDK's shared-data implementation reaches `proxy_get_shared_data` and
   `proxy_set_shared_data` in Envoy; it does not use a remote storage client.
4. Crucially, the pinned
   [proxy-wasm 0.2.5 write wrapper](https://github.com/proxy-wasm/proxy-wasm-rust-sdk/blob/4930296ed8e3601f062196ede46603ae755d565c/src/hostcalls.rs#L537)
   returns success or `Err(CasMismatch)`. For another host status it panics,
   rather than returning that status to PDK. The read wrapper similarly panics
   on unexpected statuses. Although the PDK's error mapping accommodates other
   returned statuses, this SDK wrapper does not return them through this path.

Every inspected dependency file was checked against its cached crate archive;
archive SHA-256 values match `Cargo.lock`. The pinned upstream SDK source also
returned HTTP 200 and exactly matched the local dependency file. File/archive
hashes and source locations are retained in the JSON.

Consequently, breaking a Redis connection cannot affect this policy's local
reservation. Restarting the gateway clears local state and does not create the
required error. Neither resource exhaustion nor forced host corruption would
be a sound substitute for a supported storage-unavailable test. No such fault
was attempted. In particular, **a hypothetical WASM panic is not evidence of the
policy's P6 denial**; its wire behavior and fail-open/fail-closed consequences
were not tested or inferred.

A separately authorized remote/shared-store implementation would provide a
withdrawable backend for a future real fault test. That requires changing the
current runtime selection and is outside this verification-only mandate. No
claim of universal impossibility across SDK/runtime versions is made.

## Case design and actual observations

The intended configuration is block mode, required P1/P2/P6,
`approvalSource=header`, `onDeny=rpc-error`, and
`resultHeader=x-approval-binding`. The intended request is JSON-RPC id 1,
`tools/call`, inert `deploy.apply` with `{"confirm":true}`, accompanied by a
matching action/argument digest and a fresh nonempty nonce. No actual approval,
identity, key, or client credential was created for this assessment.

| Measurement | Expected if a non-CAS error is returned | Actual this pass |
|---|---|---|
| HTTP / RPC result | HTTP 200, error -32008 | Not observed |
| Result header | `denied;predicate=P6` | Not observed |
| Upstream hits | 0 | Unmeasured (`null`) |
| PolicyViolation count | 1 | Unmeasured (`null`) |
| Catch-all storage error branch | Executed | Not exercised |
| Disposition | Denied | Qualified: not reachably testable on local |

With `onDeny=empty-403`, the source's alternative is an empty HTTP 403; it was
also not exercised. No backend was provisioned, so zero requests sent must not
be presented as a measured zero-hit enforcement result.

No new connected gateway, API, or policy deployment was created after the
reachability assessment. Accordingly, UI Save & Apply and the deployment status
transition were not performed; no assertion relies on an API PATCH. No unit
suite or successful build is being presented as a successful gateway request.

## Gateway image inspection and cleanup

Offline inspection identified the same cached Flex 1.14.0 image used by #25:
`sha256:b21e1d901492bc2d2604848eff63e8c887c44a599f749d68212c5d19471452d1`.
Its Envoy reports `1.37.5/Modified/RELEASE/BoringSSL`, build
`f97695a50e11f5ff6719e129a466bf9204b64a7f`. This was an image inspection, not a
running policy test. Three sequential inspection containers used `--rm`,
`--network none`, no volumes, no credentials, and no listeners. Two exploratory
layout/version commands exited 1; the final Envoy version command exited 0.
These command exits were not policy outcomes.

All three containers were removed automatically; a final inspection confirmed
their name absent. No registration, API, policy, Exchange version, client,
upstream, network, or volume was created, so there is no cloud deletion to
perform. Existing cached images and unrelated containers were retained.

The evidence pair was checked for consistency and credential material. CI
`policies` and GitGuardian remain PR gates; neither substitutes for the missing
live assertion. No defect issue was filed because no live expectation failed.
The PR is for maintainer review and must not be merged automatically.
