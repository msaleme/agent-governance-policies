# Changelog

## Unreleased

### Aggregate-Risk Gate

- **A slow upload can no longer expire its own reservation (#56).** The admission time was read
  when the request headers arrived, before the body was buffered. A client that held back its last
  body byte for longer than `reservationTimeoutMs` got a reservation that had already expired. It
  was reclaimed before the call was forwarded, so the next call was admitted, and the slow call's
  commit settled not-active: a permanent undercount. The admission time is now read once the body
  is fully received (bodyless and uninspectable calls keep the header-time reading).
- **Guard: no reservation is created already past its deadline (#56).** Both ledger backends
  re-read the gateway clock at reserve time and refuse a reservation whose deadline
  (admission time + `reservationTimeoutMs`) is at or before it. The node ledger reads the clock
  from its store, the worker ledger from the gateway clock injected at configure time. The call is
  denied with the new `reason=stale-admission` in `block` mode, or forwarded with that reason
  stamped in `monitor` mode. The guard refuses rather than moving the admission time forward, so a
  regression of the fix above shows up as refusals instead of being masked. A clock that reads 0
  (no clock) disables the guard; the unit tests that drive the ledgers directly with decreasing
  times use that and behave as before.
- **Documented limits, unchanged behaviour.** A call that runs for longer than twice the timeout,
  on a scope another call touches meanwhile, settles not-active and is never charged; a client
  that controls upstream duration can still provoke this, and it lasts until a restart
  (`worker-lifetime`) or until the window rolls. A client that disconnects after the upstream ran
  is never charged either, so it can run about `aggregateBudget ÷ contribution` uncharged calls
  every `reservationTimeoutMs`. See "Choosing the timeout" and "Scope of the guarantee" in the
  policy README.
- **Tests.** A filter-chain unit test (a hold filter ahead of the gate for the slow upload and one
  behind it for upstream time) fails on both backends when the body-time re-read is reverted. The
  `pdk_test` over a raw socket now overlaps a second call with the slow call's upstream time
  (mock delay 1000 ms, last byte held 4500 ms with a 2000 ms timeout) and asserts the second call
  is refused, the slow call settles `committed`, and the upstream is hit once.

### Approval-to-Execution Binding

- **Client JSON-RPC responses pass through (#57).** A client's reply to a server-initiated request
  (`roots/list`, sampling, elicitation) carries no `method`, so it was denied as malformed (an
  empty 403 in block mode), which broke MCP clients that answer server requests. By default a
  well-formed response is now forwarded untouched and stamped `out-of-scope` in both modes, and
  logged with `"kind":"response"`. Well-formed means `"jsonrpc":"2.0"`, a string or number `id`
  (`null` only on an error response), exactly one of `result` or `error`, no `method`, no other
  top-level member, and an `error` that is an object with an integer `code` and a string `message`.
  An ambiguous or malformed response still fails closed: both `result` and `error`, neither, a
  `method` alongside either, or a duplicate member. Batches are unchanged and still fail closed,
  including a batch of responses. **Such a response is not a tool call, but it is input to an
  in-flight server request (an elicitation answer can steer an approved call), and the approval
  does not bind it**; the README's inspection boundary now says so. Covered by unit tests and a new
  real-gateway `pdk_test` case; that case POSTs canned response bodies, not a real MCP SDK
  `roots/list` round trip.
- **New `clientResponses` option (`forward` | `deny`, default `forward`).** `forward` is the #57
  pass-through above. `deny` restores the earlier fail-closed handling: a client response is treated
  as malformed (empty 403 stamped `denied;predicate=malformed` in block mode; flagged
  `monitor;predicate=malformed` and forwarded in monitor mode), for deployments where approvals must
  also cover elicitation and sampling input. Any other value is rejected at startup.
- **Breaking: `approvalRpcField` may not be a JSON-RPC member name.** `jsonrpc`, `id`, `method`,
  `params`, `result` and `error` are now rejected at startup; such a value would have had the
  envelope collide with the JSON-RPC envelope itself.
- **The P6 nonce cap no longer rescans on every reservation (#58).** A reservation now checks the
  nonce key with `get` first and denies an existing nonce as a replay in O(1), so a replay at the
  cap is reported as a replay rather than `at capacity` and costs no scan; `store(…, Absent)` stays
  the authoritative single-use check, so a reservation that lands between the `get` and the `store`
  still loses as a replay. Only `store(…, Absent)` was exercised on a real gateway (the connected P6
  run); the `get` pre-check is unit-tested only. PDK 1.10's local `get` maps host storage errors to
  "absent", so the `get` can only fail closed on a value that doesn't decode; a host error there
  falls through to `store`. When a sweep leaves the store full, the worker remembers the earliest
  kept expiry and refuses further reservations at the cap in O(1) until that instant passes,
  instead of listing and reading the whole store on every request. A sweep that leaves less than a
  tenth of the cap free keeps that bound too (low-water hysteresis), a kept entry that can't be decoded
  bounds the next rescan to 60 seconds rather than never, and a worker's own sooner-expiring
  reservation lowers the bound. Without P4, a full store is never rescanned.

## 0.1.0-rc.2 — 2026-10-04

Fixes from the P4A re-review of `v0.1.0-rc.1` (#47–#52).

### Aggregate-Risk Gate

- **Breaking: only governed methods are priced (#47).** The new `governedMethods` property
  (default `["tools/call"]`) lists the JSON-RPC methods that are priced and reserved. Other
  methods, notifications, client responses and bodyless requests (the SSE `GET`, the session
  `DELETE`) pass through with no contribution and no ledger or scope entry, stamped
  `pass;reason=ungoverned-method`. Under `spend-amount` in block mode, an MCP client can now
  complete the handshake. An exhausted budget no longer blocks `initialize`, `ping`,
  cancellation or teardown. Batches are priced on their governed items only. A duplicate
  `method` member, or any duplicate member in a priced body, fails closed. Empty, blank,
  duplicate and `"*"` entries are rejected at configure time.
- **Ledger hardening (P4A review of #53).** A scope record is capped at 512 held reservations
  plus tombstones on both backends; past that a call is refused with the new
  `reason=scope-saturated` (block fails closed, monitor forwards and flags). A zero contribution
  creates no entry and settles as a no-op. On the node backend, a commit that cannot be written to
  its record is persisted to a per-reservation commit marker, and no worker reclaims a reservation
  or drops its tombstone without claiming that marker by compare-and-swap, so a deferred commit
  is no longer under-counted when its worker goes idle or its VM restarts. A raw empty host value
  (fixint `Eof`) now reads as absent instead of failing. Ledger keys sit under a fingerprint of
  `scopeDigestKey`, `window` and `windowMs`, so a reconfiguration starts a fresh ledger instead
  of leaving old records holding `maxScopes` slots; the reconfigure effects (a key rotation is a
  budget reset for every identity) and the worker-lifetime slot behaviour are documented. An empty
  `scopeDigestKey` with the node backend (the default) logs a startup warning; it is not refused,
  because that would stop the default configuration from starting.
- **Settlement documented (#49, finding B).** Settlement is by HTTP status only: 2xx and 3xx
  commit, 4xx and 5xx release. A JSON-RPC error or `isError` result inside an HTTP 200 is
  charged. Tests pin the mapping.
- **Node-wide ledger, now the default (#48).** The new `ledgerBackend` property selects where the
  ledger lives. `node` (the default) keeps it in the gateway's node-local shared data (PDK
  `LocalDataStorage`, through the `experimental_storage_sync` feature), so every Envoy worker of a
  replica checks and reserves against one budget and opening more connections no longer multiplies
  it. Every write is a compare-and-swap inside a bounded retry loop (12 attempts, no sleep), with
  no read-then-write fallback and no unconditional overwrite. When retries run out, block mode
  denies with `reason=ledger-contention`; a storage error denies with `reason=ledger-unavailable`;
  monitor mode forwards both and flags them. Settlement keeps the #17 rules across workers and is
  safe by direction: an unwritable commit is queued and retried (`settlement=deferred`, and a
  long queue refuses new reservations) and is charged even after its reservation is reclaimed; a
  commit whose record reads as missing within the reservation's lifetime is charged, not dropped;
  and an unwritable release stays held until reclaimed. Only the cleanup pass that marks a
  tombstone deletes it, timed on the gateway clock. A zero-length stored value reads as absent,
  so an empty record never wedges a scope closed. A refused call still saves its reclaim, so a
  touch past two timeouts drops a tombstone on the node backend exactly as on the worker one. Remaining known edges are listed in the policy
  README.
  Keys are an HMAC of the scope, never the raw identity, private to the policy instance unless the
  new `ledgerNamespace` is set. Stale keys are deleted, and `maxScopes` is enforced per replica
  without evicting live state. `worker` keeps the old per-worker ledger, whose multiplier and
  `FLEX_SERVICE_ENVOY_CONCURRENCY=1` workaround are still disclosed. `cluster` is rejected as not
  implemented. The node budget is per replica and resets when the gateway process restarts.
- **A refusal at the scope cap is cheap (#49, finding A).** The worker ledger keeps scopes ordered
  by when each becomes idle, so a new scope at the cap examines at most one candidate instead of
  scanning every live scope; a test refuses 1,000 new scopes against 100,000 live ones. On the
  node ledger a refusal at the cap reads two small records, and only one worker per replica
  rescans, at most once a second.
- **Charset and unparseable bodies fail closed.** A body is inspected only when its
  `Content-Type` has no `charset` or `charset=utf-8`. Any other charset makes it
  uninspectable, so a `tools/call` can't be hidden by an encoding the upstream decodes
  differently, such as `utf-7`. A body the JSON parser rejects (nesting too deep, a lone
  surrogate, a BOM) is now unpriceable instead of being charged as a single call.
- Library tests: 192 (was 140). A new `#[pdk_test]` drives a real MCP handshake through Flex
  under `spend-amount` in block mode. New real-gateway cases: `case8n` asserts exactly 3 of 200
  admitted across four Envoy workers with the node ledger, and `case8nb` records whether the node
  ledger survives the startup config apply.

### Approval-to-Execution Binding

- **Only POST is bound (#50).** In both modes, bodyless `GET`, `DELETE`, `OPTIONS` and `HEAD`
  requests are forwarded untouched, stamped `out-of-scope`. A POST without a valid
  `content-length` is still denied, now stamped `denied;framing=content-length`.
- **P6 claim narrowed, nonce store capped (#51).** Every P6 description now says single use
  holds per gateway replica, until restart. The nonce store has a fixed per-replica cap. At the
  cap, nonces of approvals already expired under P4 are swept, and if the store is still full
  the call is denied.
- **Canonical form hardened (#52).** Integers outside ±(2^53−1), and objects whose keys sort
  differently by UTF-8 bytes and UTF-16 code units, now fail closed.
- **Maximum approval lifetime (#52).** The new optional `maxApprovalLifetimeSeconds` (default
  `0`, off; range 1–31536000) bounds an approval's remaining lifetime under P4: an approval whose
  `not_after` is later than now + the maximum + `clockSkewSeconds`, on the gateway clock, is
  denied `predicate=P4`. Setting it without P4 in `requiredPredicates` fails at startup. It
  checks `not_after` rather than adding an `iat` claim, so the `mcp-v1` payload and the ABV
  corpus are unchanged. `not_after` is authenticated only when P5 is required.
- **`rpc-param` envelope removed before upstream (#52).** With `approvalSource: rpc-param`, the
  top-level `approvalRpcField` member is now cut out of every forwarded body (an allowed call, or
  a monitor-mode forward), byte-for-byte with one adjoining comma; the rest of the body is not
  re-serialized. The result is re-parsed and must equal the original minus that member, or block
  mode denies the call as malformed. `content-length` is set to the new length, because PDK 1.10's
  `set_body` does not update it. The new `stripApprovalEnvelope` (default `true`) turns this off.
  Header mode is unchanged.
- **CI** runs the approval-binding `#[pdk_test]` suite on a real Flex Gateway 1.14.0 container
  (new `runtime-e2e-approval` job). It asserts that the upstream receives the exact stripped
  bytes and the rewritten `content-length`. Both runtime jobs share one `flex-registration`
  concurrency group, and their full test output goes only to scanned log files.
- **Breaking: `clockSkewSeconds` is bounded to 0–3600.** Before, a negative value was treated as
  `0` and there was no upper limit, so a very large skew overflowed the P4 deadline and silently
  disabled expiry and the lifetime bound; it could also wrap a P6 nonce's stored expiry into the
  past, so the cap sweep could delete a live nonce. Out-of-range values are now rejected at
  startup, P4 fails closed if the deadline can't be computed, and a nonce expiry that can't be
  represented is never swept.
- **Charset and unparseable bodies fail closed.** A body with a `charset` other than
  `utf-8` is treated as malformed (denied in block mode, flagged in monitor mode). Before,
  `charset=utf-7` could carry a `tools/call` the policy read as an unknown method and
  forwarded unchecked. Bodies the JSON parser rejects already failed closed; tests now pin it.
- The P6 cap sweep runs only when the per-worker reservation count reaches the cap, so the
  normal path makes the same single atomic store call as before. The cap is approximate and
  the sweep's key listing is not yet verified on a real gateway.
- Library tests: 97 (was 46).

## 0.1.0-rc.1 — 2026-10-03

This is the first source prerelease of the Agent Governance Policies family: two
independent Rust and PDK 1.10.0 policies for MuleSoft Flex/Omni Gateway, built
with Rust 1.89.0 for `wasm32-wasip1`. Both policies are at version `1.0.0` in their
`Cargo.toml`, and the repository version is separate from that. Only the source
is released. There are no compiled WASM assets. Both policies were dev-published to
Exchange during verification and then deleted. No production Exchange asset is
published.

### Verification summary

- **Library tests:** 46 for approval binding and 140 for the aggregate-risk gate, all
  passing.
- **CI:** CI runs fmt, strict Clippy, the library tests, integration-test compilation
  and a release WASM build. It runs the full PDK packaging path with Exchange metadata
  validation. It also runs the aggregate-risk `#[pdk_test]` suites on a real Flex
  Gateway 1.14.0 container.
- **Real-gateway evidence:** the full set is listed in [docs/README.md](docs/README.md).
  - Approval binding: P5/P6 is a qualified partial. P5 and same-replica replay
    rejection were proven, and `local()` limits P6 to one replica.
  - Aggregate-risk gate: eight cases pass, including real Client ID Enforcement on a
    connected gateway. Three are qualified and three observed. None failed.
- **Review findings:** P4A reviewer findings #1–#7 and #14–#18 are resolved and
  closed.

### Added

- **Approval-to-Execution Binding** — enforces five `approval-binding-vectors`
  (ABV v0.1) predicates (P1 action, P2 canonical argument bytes — reference-shaped
  `$ref` arguments rejected, not dereferenced; P4 valid-at-execution, P5 separate
  attester, P6 opt-in single-use nonce) on admitted MCP **`tools/call`** requests;
  every other JSON-RPC method is forwarded untouched as out-of-scope. (An earlier
  draft's P3 dereference predicate was removed in favor of rejecting reference-shaped
  arguments under P2.) Vendors the ABV corpus as conformance fixtures. Monitor and
  block modes; JSON-RPC `-32008` or empty-`403` denial rendering. Real HMAC-SHA256
  P5 attestation over a versioned, domain-separated `mcp-v1` payload (checked against
  the *verified* executor identity, not a caller-asserted header), real wall-clock P4
  freshness, and atomic P6 single-use via gateway data storage (`StoreMode::Absent`).
- **Cross-Session Aggregate-Risk Gate** — a reserve-then-authorize decision engine
  (`ledger.rs`) that holds a shared exposure budget across sessions where each call
  is individually under its cap. PDK-independent engine, unit-tested under genuine
  OS-thread contention: a naive read-then-write counter is shown to breach the
  budget while the atomic reserve-then-authorize ledger holds it. Monitor and block
  modes; per-scope (agent/fabric/tenant) budgets; token-cost, spend-amount, and
  fixed-weight contribution modes with estimate-then-settle commitment (this build
  commits the full estimate; it does not read the response body to reconcile).
- Per-policy PDK project scaffold: config schema (`definition/gcl.yaml`), generated
  `Config`, Makefile, playground, and pinned `rust-toolchain.toml` (1.89.0).
- Repository scaffolding: MIT license, attribution and corpus provenance,
  composition notes, and a credential-free CI workflow.
- Attribution: full research provenance for the aggregate-risk corpus (position
  paper *"Authorized but Composed"*, Zenodo DOI 10.5281/zenodo.21400261, sibling
  DOI 10.5281/zenodo.21263262, and the `red-team-blue-team-agent-fabric` verifier
  harness) and a Protocol specifications section citing the governed wire formats
  (MCP, A2A, JSON-RPC 2.0).

### Fixed

- **Approval-to-Execution Binding** — the `attesterKeys[].key` sensitive-parameter
  marker now uses the doc-supported JSON-LD form (`"@context": { "@characteristics":
  ["security:sensitive"] }`). The earlier bare `characteristics: [security:sensitive]`
  was rejected by PDK's GCL→JSON-Schema compiler (ajv strict mode: unknown keyword),
  which blocked schema generation and Exchange publication (issue #21). Verified
  locally via `pdk policy-project build-asset-files`; re-confirm on a live Exchange
  publish.
- **Approval-to-Execution Binding** — `make build` now regenerates
  `src/generated/config.rs` identically to the checked-in file (issue #24). The
  `expectedAudience`/`expectedTenant`/`expectedEnvironment` properties were listed as
  schema-`required` while also carrying `default: ""`, so `config-gen` emitted them
  without the `#[serde(default)]` (and in a different field order) than the committed
  file relied on — the standard build was not reproducible. These fields are
  conditionally required (non-empty only when `P5` is in `requiredPredicates`, enforced
  at configure time in `lib.rs`), not always-present, so they are removed from the
  schema `required` list; `config-gen` now emits them as `Option<String>` and the two
  read sites treat `None` as empty. Verified reproducible: a second `config-gen` run
  yields no diff, and the full gate (fmt/clippy/lib+integration tests/release wasm)
  is green.
- **Cross-Session Aggregate-Risk Gate** — Exchange metadata is now publishable and
  consistent (issue #16). The GCL description was ~2,240 characters. Exchange caps it
  at 256, so it is now 232, and the full explanation lives in the README. The policy
  now declares `metadata/capabilities/assetTypes: mcp`, the only target its tests
  cover. `P4A-SUBMISSION.md` no longer claims A2A or LLM-proxy applicability. The
  removed description also claimed the policy reuses the gateway's token-usage signal.
  It never did, and that claim is gone.
- **CI** — a new `exchange-assets` job runs the full PDK packaging path (`make build`)
  for both policies from a clean checkout. It fails if `src/generated/config.rs` drifts
  from `gcl.yaml`, runs `scripts/check_exchange_metadata.py --assets` (which rejects
  over-length or placeholder metadata, untested asset types, a P4A applicability
  mismatch, a non-UUID `groupId`, and a wrong `minRuntimeVersion`), and uploads the
  generated assets as workflow artifacts. It reads the owning org UUID from the
  `ANYPOINT_GROUP_ID` repository variable; `Cargo.toml` keeps its placeholder.

- **Cross-Session Aggregate-Risk Gate** — exposure amounts are exact integers (issue #18).
  The ledger used `f64`, so cumulative decimal amounts drifted. 0.1 + 0.2 > 0.3, so a budget-exact
  call could be refused, and large values lost precision. The ledger is now `u64`, and saturating
  arithmetic means an overflowing sum compares as over budget. `aggregateBudget`, `fixedWeight`
  and `estimatedTokens` are schema `integer`s in `0`–`9007199254740991` (2^53 − 1). Spend amounts
  must be JSON integer minor units of the new `spendCurrency` (ISO 4217, default `USD`). A
  fraction, `1234.0`, an exponent, a negative value or a string is denied as unpriceable. A value
  over the ceiling, or a batch sum or product that overflows it, is denied with
  `reason=out-of-range`. `resultHeader` stamps integer totals and a `unit=` field. **Breaking:**
  the `token-cost` contribution is renamed `estimated-token-weight` and the old name is rejected
  at configure time. It always charged the configured estimate and never measured usage. That is
  unchanged and now tested against under-, over- and malformed usage responses. The unused
  `LedgerStore::reconcile` primitive and its two tests are removed. Its only caller passed the
  estimate back in unchanged, so every mode now settles through `commit`.
- **Cross-Session Aggregate-Risk Gate** — the budget is keyed on a verified identity (issue #14).
  The scope used to come from a caller-chosen header, so a client could mint a fresh budget per
  call by changing it. The identity now comes from the `AuthenticationData` set by an earlier
  authentication policy (`identitySource: authentication`, `identityField`: `client_id`, `principal`
  or `properties.<path>`). A header is used only with `identitySource: trusted-header`, which the
  README says must sit behind a strip-and-inject chain. Identities are trimmed and ASCII-lowercased.
  An identity over 256 bytes, outside visible ASCII, carrying a stamp delimiter, sent as a
  duplicate header, or a non-string property is denied with `reason=invalid-identity`. No identity
  is denied with `reason=missing-identity`. `maxScopes` (default 10000) caps the ledger: only an
  idle scope is evicted, otherwise a new scope is denied with `reason=scope-capacity`. The result
  header and denial messages show `scopeDisclosure` (default `digest`, an HMAC-SHA256 under the
  sensitive `scopeDigestKey`), not the raw identity, and identities are never logged. Adds the
  `sha2` and `hmac` crates. **Breaking:** a config that keyed on `scopeHeader` must now set
  `identitySource: trusted-header`, and `scopeDisclosure: raw` to keep raw scopes in the header.
- **Cross-Session Aggregate-Risk Gate** — reservations have a lifecycle (issue #17). A request whose
  response never reached the policy (client disconnect, cancellation, upstream timeout) used to hold
  its reservation for the life of the worker. Each reservation now has a worker-unique id, a creation
  time and an expiry from the new `reservationTimeoutMs` (default 60000, range 1000–86400000), read
  from the gateway clock. An expired reservation is reclaimed under the ledger lock, freeing its
  budget, and committed exposure is untouched. Settlement is by id and happens at most once, so a
  duplicate, reordered or crossed commit/release changes nothing. A response after reclaim settles
  late while the reservation's tombstone is held: a success is charged without a budget check, a
  failure changes nothing. Reclaim is lazy. The tombstone is held for at least one more timeout and
  dropped when the scope is next touched after that. From then on the reservation is counted
  abandoned. An untouched scope can therefore settle late after more than two timeouts. That
  over-counts, the safe direction, and was confirmed on a real gateway on 2026-10-01. `resultHeader` on an allowed or monitored call now
  ends with `settlement=committed|released|late-committed|late-released|not-active`, and any
  settlement that isn't on time logs the ledger counters, with no identities. A worker restart still
  resets the in-memory ledger. That is now documented and tested. **Breaking:** the allowed/monitor
  `resultHeader` format gains the trailing `settlement=` field.
- **Cross-Session Aggregate-Risk Gate** — `window` is enforced, and the claims match a per-worker
  ledger (issue #15). `window: fixed-period` now resets every scope's committed total at each
  `windowMs` boundary (new field, default 86400000, range 60000–31622400000), counted from the Unix
  epoch on the gateway clock. In-flight reservations carry across a boundary and settle in the new
  period, and a clock stepping backwards never resets a total. The new `window: worker-lifetime`
  never resets. The unimplemented `ledgerEndpoint` field is removed. The README, GCL and P4A text now
  say the budget is per policy instance per gateway worker: `N` workers admit up to
  `N × aggregateBudget`, and a restart or a config apply that rebuilds the listener resets the
  ledger (confirmed on a real gateway on 2026-10-02). A shared, durable ledger is future (v2)
  work. **Breaking:** `window: rolling-24h` (the old default) never rolled and is now rejected with
  its replacements named, the default is now `fixed-period` with a 24-hour window, and a config that
  sets `ledgerEndpoint` must drop it.

### Known limitations

- Approval-binding P5 attestation is symmetric HMAC in this build (separation-of-
  duties, not non-repudiation); the `sidecar` approval source is rejected at startup.
  A record checked only by the party it constrains is not meaningful without the
  separate-attester predicate. P6's single-use nonce store uses gateway `local()`
  storage, which is per-replica and has no policy-controlled TTL; durable, global
  single-use across replicas/restarts requires a shared store and is validated
  end-to-end separately (`approval-execution-binding/docs/ASTRA-TASK-approval-p6-replay.md`).
  Connected verification recorded two related qualifications (see
  `approval-execution-binding/docs/`): the P5/P6 enforcement paths were exercised
  on a real Flex Gateway, but (a) cross-replica single-use is unproven on `local()`
  by design, and (b) the storage-unavailable "other `Err` → fail closed" branch is
  defensively correct by inspection yet **not reachably testable on `local()`** — the
  pinned proxy-wasm SDK panics on unexpected host statuses rather than surfacing them
  to the policy, so that branch is exercised only with a shared/remote store. A
  shared/remote store is the single change that would close both: it makes single-use
  global across replicas and makes the storage-unavailable branch reachable.
- The aggregate-risk gate's ledger is in-process: one budget per policy instance per
  gateway worker (not shared across workers or replicas), reset by a restart or by a config
  apply that rebuilds the listener (which the gateway does once at startup), and with
  no cryptographic non-repudiation of decisions.
  Reference concurrency scenarios are synthetic, not production telemetry.
- Inspection targets admitted JSON-RPC envelopes and bodies, not paths, query
  strings, or arbitrary headers. Local tests do not establish general MCP
  interoperability or production effectiveness. Framework references in the policy
  READMEs are design/supporting-measure context, not certification.
