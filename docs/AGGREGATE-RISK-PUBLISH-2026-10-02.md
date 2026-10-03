# Aggregate-risk gate: pinned-toolchain publication, 2026-10-02

WP2 evidence for [issue #16](https://github.com/msaleme/agent-governance-policies/issues/16).
**Case 9: pass**, limited to development publication under cargo-anypoint 1.10.0.
This does not establish that every #16 criterion is met. No runtime cases were rerun.
Machine-readable observations: [publication evidence](evidence/aggregate-risk-publish-2026-10-02.json).

## Artifact and commands

The private build copy came from brief commit `127f0d0`; policy source and definition match
`5b71d80`. Rust 1.89.0, cargo-anypoint **1.10.0**, and PDK CLI plugin 1.9.0 were used.
The owning organization was substituted only in the private Cargo.toml. Disposable asset
IDs were generated with letters only. No credentials or identifying metadata are included here.

| Command | Actual result |
|---|---|
| `cargo +1.89.0 install --locked cargo-anypoint@1.10.0 --root <temporary-tools-directory>` | Exit 0; cargo-anypoint 1.10.0 installed |
| `make build` (disposable asset IDs) | Exit 0 |
| `python3 scripts/check_exchange_metadata.py aggregate-risk-gate --assets` | Exit 0; `aggregate-risk-gate: Exchange metadata OK (incl. generated assets)` |
| `make publish` | Exit 0; both development assets published |
| `make build` (original asset IDs restored) | Exit 0 |
| Metadata checker after original-ID rebuild | Exit 0 |

Tool discovery used the temporary tools directory first on PATH and `RUSTUP_TOOLCHAIN=1.89.0`.
The public checkout's Cargo.toml remains unchanged. Generated policy source in the private
copy was compared with Git and was unchanged; no policy patch was used to obtain a pass.

WASM SHA-256 before publication and after the original-ID rebuild:

```text
33443716859f371bead629ab61cf326cb6b63496442fab0688e3898b4cce5ff9
```

This equals the [prior real-gateway run](AGGREGATE-RISK-CONNECTED-2026-10-01.md#run-identity).
After rebuilding, `target/policy-ref-name.txt` contains `aggregate-risk-gate-v1-0-impl`,
so the disposable publish name no longer remains in the generated runtime fixture.

## Live Exchange observations and cleanup

| Observation | Definition | Implementation |
|---|---|---|
| Asset/version GET | 200 | 200 |
| Stored metadata download | 200 | 200 |
| Stored metadata content | `capabilities.assetTypes: [mcp]`; description **232 characters** | `minRuntimeVersion: 1.14.0` |
| DELETE with `x-delete-type: hard-delete` | 204 | 204 |
| Version GET after deletion | 404 | 404 |
| Asset GET after deletion | 404 | 404 |

The API asset descriptor itself has an empty description; the 232-character description
was verified in the **downloaded stored definition metadata**, not inferred from the
local GCL or the descriptor. The implementation metadata has a runtime version rather
than the definition's description/attachment fields.

Sanitized request paths and status observations are in the JSON. Raw platform responses
were kept private because they contain organization identifiers and download locations.
`x-aggregate-risk-gate` and upstream hit counts do not apply to these control-plane
requests. This package created only two disposable Exchange assets. Both were deleted
and confirmed absent; it created no gateway, API, contract, application, or registration.

## Remaining #16 gates

- This is a development publish, not a release.
- Real gateway CI execution and the Client ID Enforcement run are still pending their
  authorization/operator steps. Prior manual runtime evidence retains its qualifications.
- Packaging CI currently fails because repository variable `ANYPOINT_GROUP_ID` is absent.
  Local packaging success does not make that CI criterion met.
- Global/multi-instance budget claims remain outside the implemented per-worker scope.
  The acceptance table must record maintainer-approved narrowing before claiming completion.
- This evidence PR requires maintainer review and merge approval; it does not close #16.

### Resolution, 2026-10-03

The gates above were left as they stood on 2026-10-02. Since then:

- **Packaging CI:** `ANYPOINT_GROUP_ID` was configured. The `exchange-assets` job now
  passes for both policies.
- **Runtime CI:** the `runtime-e2e` job runs the `#[pdk_test]` suites against a real
  Flex Gateway 1.14.0 container on every pull request and every push to `main`.
- **Client ID Enforcement:** passed on a connected gateway as case 2c. See
  [AGGREGATE-RISK-CONNECTED-2026-10-01.md](AGGREGATE-RISK-CONNECTED-2026-10-01.md).
- **Budget scope:** the documentation is narrowed to one budget per policy instance per
  gateway worker. No global or multi-instance claim is made.
- **#16:** merged in PR #35 and then PR #42, and closed by #42.

This is still a development publish. No production Exchange asset is published from
this repository.
