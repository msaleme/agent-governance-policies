# Aggregate-risk gate on a real Flex Gateway: evidence, 2026-10-01

This records the nine cases in
`aggregate-risk-gate/docs/ASTRA-TASK-aggregate-risk-connected.md`. They ran on the maintainer's
Mac against a real Flex Gateway 1.14.0 container, not on Astra. Machine-readable evidence is in
`docs/evidence/aggregate-risk-connected-2026-10-01.json`.

**Summary:**

- 7 cases pass: 1, 3, 4, 5a, 5c, 6 and 7. (Case 5 is split into 5a, 5b and 5c.)
- 3 are qualified: 2, 5b and 9.
- 1 is observed: 8. A follow-up adds case 8b, also observed (finding F4).
- None failed.

*Follow-up, 2026-10-03:* a connected-mode run adds case 2c (PASS), which closes case 2's
substitution with real Client ID Enforcement, and case 2d (OBSERVED, F4). It also rebuilt and
dev-published with cargo-anypoint 1.10.0, which closes case 9's toolchain qualification.

The policy source was not changed for this run.

## Run identity

| | |
|---|---|
| Source commit | `5b71d80` (policy `src/` and `definition/` unchanged) |
| WASM SHA-256 | `33443716859f371bead629ab61cf326cb6b63496442fab0688e3898b4cce5ff9` |
| Gateway | `mulesoft/flex-gateway:1.14.0` (`sha256:b21e1d90…452d1`), local mode, linux/amd64 under Rosetta |
| Workers | container nproc 14. Envoy `--concurrency 4` (pdk_test default). Single-worker runs set `FLEX_SERVICE_ENVOY_CONCURRENCY=1`. |
| Toolchain | rustc 1.89.0, pdk-test 1.10.0, anypoint PDK plugin 1.9.0, cargo-anypoint **1.9.0** (the Makefile pins 1.10.0) |
| Harness | Case 1 runs the unmodified `tests/requests.rs`. Cases 2–8 are `tests/connected_e2e.rs` (`#[ignore]`, one real Flex container plus a real httpmock upstream per case). |
| Identity | A disposable local-mode registration, deleted afterwards (see below). Cases 2c/2d (2026-10-03) used a disposable connected-mode registration. |

Unless noted, every case uses this config:

- `contribution: fixed-weight`, `fixedWeight: 800`, `aggregateBudget: 3000`
- `mode: block`, `onDeny: rpc-error`, `resultHeader: x-aggregate-risk-gate`
- `window: fixed-period` (24 h), `reservationTimeoutMs: 60000`

The upstream mock counts hits. The scope values in the stamps (`agent-alpha`, `broker-7`) are
test identities.

## Results

### 1: committed `#[pdk_test]` cases (PASS, closes the #16 execution gap)

Both cases ran unmodified for the first time on a gateway: `2 passed; 0 failed` in 23.75 s.

- `sequential_composition_through_a_real_gateway_refuses_the_fourth_call`
- `a_different_agent_has_an_independent_budget_through_a_real_gateway`

### 2: authentication policy runs first, and spoofed headers are ignored (QUALIFIED, #14)

**Substitution:** Client ID Enforcement needs control-plane contracts, which local mode doesn't
have. So the chain was built-in `http-basic-authentication-flex` → gate, with
`identitySource: authentication` and `identityField: principal`.

- (a) With no credentials, the call got **401** and the upstream was not hit.
- (b) With valid credentials and a different `x-agent-id` on every call:
  - Calls 1–3 got 200 with `allowed;scope=agent:agent-alpha;…;total=800|1600|2400/3000;…;settlement=committed`.
  - Call 4 got a 200 envelope with `error.code = -32008` and stamp `denied;…;would-be-total=3200;budget=3000`.
  - The upstream was hit **3** times.

The policy ordering and spoof resistance hold with a real authentication policy. A run with
Client ID Enforcement itself needed a connected-mode gateway; see case 2c below.

The Basic Auth password is generated per run and never recorded. The first run used a hardcoded
test value. After the harness was changed, case 2 was rerun with the same wire results. One
rerun in between was invalid: stale `target/` assets from the case 9 publish build had renamed
the policy, so Flex loaded no gate (empty stamps, 4 hits). The case's predicate failed that run.
After a rebuild with the original asset ids (WASM SHA-256 unchanged), it passed.

### 2c: Client ID Enforcement on a connected gateway (PASS, 2026-10-03, #14)

This follow-up closes the case 2 substitution. The harness is
`case2c_client_id_enforcement_on_a_connected_gateway` in `tests/connected_e2e.rs`, run with
`FLEX_SERVICE_ENVOY_CONCURRENCY=1`, so there is one ledger.

**Setup.** Everything below was disposable, made for this run in Sandbox, and is deleted now.

- A connected-mode Flex 1.14.0 gateway ran in the pdk_test container, with an httpmock upstream.
- An MCP API instance had this ordered chain:
  1. Client ID Enforcement 1.3.3, reading `client_id`/`client_secret` headers.
  2. A dev publish of this gate, with `identitySource: authentication`, `identityField: client_id`,
     digest disclosure and the default config above.
- A client application had an approved contract.

**UI Save & Apply.** The API created the deployment, but enforcement was asserted only after one
real UI Save & Apply.

- `deployment.updatedDate` moved from `14:40:53.314Z` to `14:52:54.501Z`, and the deployment
  status was `applied`.
- The harness waited for a 401 without credentials, and then for 20 s with no new config apply,
  before sending calls.

| Call | Credentials | `x-agent-id` | HTTP | Gate stamp / RPC error | Upstream hits |
|---|---|---|---|---|---|
| (a) | none | — | **401** | none (Client ID Enforcement refused first) | 0 |
| (b) 1–3 | valid client | `spoofed-1` … `spoofed-3` | 200 | `allowed;scope=agent:hmac-2fec5296612fd17e;…;total=800`, `1600`, `2400/3000` | 3 |
| (b) 4 | valid client | `spoofed-4` | 200 | `-32008`, `denied;…;would-be-total=3200;budget=3000` | 0 |

All four calls share one scope digest, whatever the spoofed header said. No stamp contains the
spoofed value or the client id. The gate keys on the identity that Client ID Enforcement verified.

### 2d: a UI Save & Apply with no config change (OBSERVED, 2026-10-03, F4)

The client stayed exhausted after case 2c. A second real UI Save & Apply with no changes moved
`deployment.updatedDate` from `14:52:54.501Z` to `14:57:43.980Z`, with status `applied`. The gateway
logged a new `Configuration applied` (4 → 5). After 20 s with no further apply, the same client
called again: **`-32008`, `would-be-total=3200`.** The ledger was **not** reset. See F4.

### 3: default digest disclosure (PASS, #14)

The config used `identitySource: authentication` and `scopeDisclosure: digest`, with a 48-char
key generated at runtime. The key was never recorded.

- Every stamp carried `scope=agent:hmac-ffc8f4c46b0d8b16`.
- The raw identity appeared in no response header.
- A grep of 60,766 bytes of gateway logs found neither the identity nor the digest key.

### 4: monitor mode (PASS)

Five calls returned 200 and all five reached the upstream (5 hits). Calls 4 and 5 stamp
`monitor;scope=agent:broker-7;contribution=800;total=3200/3000;…` and `…total=4000/3000;…`.
Nothing was denied.

*Note:* the brief expected `reason=budget-exceeded`. The policy emits the format documented in
the README, with no reason label. The first run failed only because the harness copied the
brief's wrong expectation. The assertion was corrected and the brief is fixed in this PR.

### 5: reservation reclaim and late settlement (#17), single worker

Setup: `reservationTimeoutMs: 1000`, `aggregateBudget: 1600`.

1. Slow call A starts.
2. Fast calls B and C are sent once 1 s has passed.
3. Call D is sent after A settles.

D's `would-be-total` shows whether A was charged: **3200** means charged, **2400** means not.

*At the default 4 workers the case is not meaningful.* A and B/C landed on different worker
ledgers, so B/C were admitted without any reclaim. These runs are superseded and listed in the
JSON. All the runs below used `FLEX_SERVICE_ENVOY_CONCURRENCY=1`.

| | Slow-call delay | Touch during flight | A's stamp | D | Disposition |
|---|---|---|---|---|---|
| 5a | 1500 ms (1559 ms observed) | — | `settlement=late-committed` | `-32008`, `would-be-total=3200` (charged without a budget check) | **PASS** |
| 5b | 2600 ms (2651 ms observed), more than 2 × TTL | none | `settlement=late-committed` | `would-be-total=3200` (charged) | **QUALIFIED: finding F1** |
| 5c | 3500 ms (3570 ms observed) | one call at 2.3 s (denied, `would-be-total=2400`) | `settlement=not-active` | `would-be-total=2400` (not charged) | **PASS** |

In every row, B and C were admitted (`total=800/1600`, `1600/1600`) after A's reservation was
reclaimed. No gateway upstream timeout cut a delay short.

**F1:** the README (§settlement table, and "kept for one more timeout … after that it is counted
as abandoned") says a response more than one timeout after reclaim settles `not-active`.

- What actually happens: the tombstone is dropped lazily, on the next call that touches the
  scope.
- So if nothing touches the scope (5b), a response even after 2 × TTL still settles
  `late-committed` and is charged.
- Once something touches the scope (5c), the documented `not-active` holds.

The deviation over-counts, which is the safe direction. It is a mismatch between the docs and
the behaviour, not a budget breach.

**Resolved by a docs fix in this change.** The behaviour is the safe one, so the policy code is
unchanged. The README settlement table and reclaim paragraph, its unit-test summary and the
CHANGELOG `#17` entry now say that the tombstone is held for *at least* one more timeout and is
dropped when the scope is next touched after that.

### 6: fixed window reset (PASS, #15)

- Config: `windowMs: 60000`.
- Before the boundary, the budget was exhausted at `2026-10-01T21:40:14.5Z` (call 4 got
  `-32008`).
- The epoch-aligned boundary was `1790890860000` (`21:41:00Z`).
- After the boundary, a call at `21:41:01.516Z` got `allowed;…;total=800/3000;…`.

### 7: restart (PASS, documented limitation, #15)

The budget was exhausted (call 4 got `-32008`) and the container got `docker restart`. The next
call, at `21:41:25.8Z`, got `allowed;…;total=800/3000`. The ledger is in-process and is reset by
a restart, as documented.

### 8: per-worker scope (OBSERVED, #15)

Each run sent 200 parallel calls, each on its own connection. With these values each worker
admits 3 calls (`3000 / 800`).

| Envoy concurrency | Admitted | Refused | Upstream hits |
|---|---|---|---|
| 4 (default) | **12** (= 4 × 3) | 188 | 12 |
| 1 | **3** | 197 | 3 |

This matches the README's `N × aggregateBudget`. **F2:** the README could add that
`FLEX_SERVICE_ENVOY_CONCURRENCY=1` makes `aggregateBudget` a single budget per replica, at the
cost of worker parallelism. *Resolved by a README note (PR #40).*

*Follow-up, 2026-10-02:* the first CI run of this case on a Linux runner admitted **24** of 200 at
four workers, not 12. That was not extra workers: the burst straddled a second startup config
apply that replaced every ledger (finding F4 below). Case 8 now waits for that apply before its
burst. On the Mac it then admits 12 (four `total=800` stamps, one per ledger), from one Envoy
process with four worker threads.

### F4: a config apply resets the ledger

Found while explaining the CI result above, on 2026-10-02. The policy source was not changed.

The Flex gateway applies its config **twice** at startup. The gateway log shows `Configuration
applied` once, then about 5 s later a second `Creating gateway` … `Configuration applied`. The
second apply replaces the listener, and Envoy builds new thread-local wasm VMs and destroys the old
ones. The ledger lives in the VM, so every scope starts again at zero.

| Run | Before the burst | During the burst | Ledgers reached (`total=800` stamps) | Admitted | Same scope after the apply |
|---|---|---|---|---|---|
| Mac, case 8b | 1 apply | 1 apply | 4 | 12 | admitted again: `total=800`, `1600`, `2400`, then denied at `3200` |
| Linux CI runner, diagnostic run | 1 apply | **1 → 2** | **8** (4 old + 4 new) | 20 | denied (the new ledgers were exhausted by the rest of the burst) |

Each ledger stamps its first admitted call `total=800/3000`, so counting those stamps counts the
ledgers a burst reached, without depending on Envoy's process list.

So a scope can be admitted up to its budget again after any config apply that rebuilds the
listener, not only after a restart. This is the over-admit direction. It is the same in-process
limitation as the restart reset, but the README said a restart was the only reset. Startup is the
only trigger confirmed.

*Follow-up, 2026-10-03 (case 2d):* a real UI Save & Apply with no config change, on a connected
gateway, did **not** reset the ledger. The gateway logged a new `Configuration applied` (4 → 5), but
once that apply settled, the client exhausted in case 2c was still denied (`-32008`,
`would-be-total=3200`). So not every apply rebuilds the listener. A policy config change was not
tested.

**Resolved as a docs fix in this change.** The policy code is unchanged. The README's restart
paragraph and limitations, and the CHANGELOG `#15` entry and known limitations, now say that a
restart **or a config apply that rebuilds the listener** resets the ledger. A shared ledger, the
fix for both, is already listed as v2 work. Case 8b now records the reset on every run.

### 9: Exchange publication (QUALIFIED, #16)

`make build` and `make publish` ran from a private working copy, with the org id substituted
only there. They exited 0 and published a dev version of both assets under disposable ids.

- The definition and implementation GETs returned **200**.
- Exchange's stored `metadata` file carries `capabilities.assetTypes: [mcp]` and the
  **232-char** description.
- `scripts/check_exchange_metadata.py --assets` passes on the generated files.

Qualifications:

- The build used cargo-anypoint 1.9.0, not the pinned 1.10.0.
- It was a dev publish, not a release.
- The PDK CLI rejects any asset id containing a digit with "Invalid asset-id", even though the
  message says numbers are allowed. A disposable id must therefore be digit-free.

*Follow-up, 2026-10-03:* for case 2c, the policy was rebuilt and dev-published with the pinned
cargo-anypoint **1.10.0** (rustc 1.89.0). `make publish` exited 0 and the WASM SHA-256 was
identical to the 1.9.0 build above. That closes the toolchain qualification. Case 9 stays
qualified only because it is a dev publish, not a release.

## Resource deletion (all confirmed)

| Resource | Action | Confirmation |
|---|---|---|
| Test Exchange definition and implementation | `DELETE` with `x-delete-type: hard-delete` → 204 | GET by version and by asset → 404. A search shows no test ids left. |
| Flex registrations (two local-mode: the original, plus one for the case 2 rerun) | Certificates, keys and registration files securely removed from disk | **Correction, 2026-10-03:** these registrations are absent from both environments' gateway lists and from ARM servers, but a local-mode registration *does* create a server-side registry target (a new registration under the same name fails with "already exists"). Those targets remain. They are inert because their certificates are gone. Deleting them needs their gateway ids, which went with the shredded files. |
| Flex and mock containers and networks | Removed by the pdk_test harness | 0 containers and 0 networks labelled `CreatedBy=pdk-test` |
| Shared gateways and APIs | Not touched | — |

**Cases 2c/2d (2026-10-03).** Every resource was disposable and created for this run.

| Resource | Action | Confirmation |
|---|---|---|
| Client application (its contract cascades) | `DELETE` → 204 | Application and contract GET → 404 |
| MCP API instance, with its two policies and its deployment | `DELETE` after the contract was gone | API and deployment GET → 404 |
| Dev Exchange definition and implementation of the gate | `DELETE` with `x-delete-type: hard-delete` → 204 | GET → 404 |
| Disposable MCP Exchange asset | `DELETE` | GET → 404 |
| Connected-mode Flex registration | `flexctl registration delete --file` → "Gateway deleted successfully" | Target shows `DELETED`, and the gateway is absent from the CONNECTED and DISCONNECTED lists. Registration files securely removed. |
| Flex and mock containers and networks | Removed | 0 containers and 0 networks labelled `CreatedBy=pdk-test` |

## Redaction

This doc and the JSON contain no org, environment or group ids, client ids or secrets,
registration material, digest keys, hostnames or IPs. The JSON's only hex strings are the WASM
SHA-256, the public Flex image digest and the HMAC scope digest of a test identity, made under a
discarded key.
