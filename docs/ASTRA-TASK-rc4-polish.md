# Astra task: rc.4 polish (#62, #63, #65)

**Context.** On 2026-10-08 Tommaso Bolis re-reviewed `v0.1.0-rc.3` (`6d414d1`) for the P4A
catalog and filed four issues. **None of them blocks catalog approval.** This brief covers
the three that are concrete and low-risk:

| Issue | Policy |
|---|---|
| **#62** | `approval-execution-binding`, "fix in the next rc" |
| **#63** | `approval-execution-binding`, polish |
| **#65** | `aggregate-risk-gate`, polish |

**#64 is out of scope.** It covers the aggregate-risk gate's unbounded cleanup pass,
uncharged abandoned calls and uncapped shared-data growth. It changes default behaviour
and needs maintainer decisions, so it gets a separate brief.

All references below were checked against `6d414d1` on the maintainer's Mac on
2026-10-09. If a line has moved, follow the symbol, not the number.

Read these first, in order:

1. Issues #62, #63 and #65 (full text).
2. The root `CLAUDE.md` for the hard rules, build commands and the PUBLIC-repo redaction
   check in `CONTRIBUTING.md`.
3. `docs/CODEX-HANDOFF.md` for branch and authorization conventions.

## Ground rules for this task

- This is **source work only, in Local Mode**. There is no gateway run, no release tag and
  no Exchange/P4A publish. Do not cut `v0.1.0-rc.4`; the maintainer tags it after merge.
- Every behaviour change needs a regression test that fails before the change.
- Do not weaken an existing test to pass a gate. If an item turns out to be wrong or
  riskier than described, defer it in the PR body with the reason.
- Keep `edition = "2018"` in both crates (see the Clippy item below).

## #62: approval-execution-binding, fix first

1. **`.expect()` in the request path** (`src/lib.rs:1717`,
   `declared_length.expect("admissible implies present")`). Replace it with a `let … else`
   that fails closed with **the same verdict as the inadmissible-framing branch just
   above it**, i.e. the same deny, reason and log event. Then check the rest of the
   non-test filter code for any remaining `unwrap()`/`expect()` on request/response data,
   and fix or justify each one in the PR.
2. **Startup rejects P6 without P4.** In config validation, reject `requiredPredicates`
   containing P6 but not P4. Without P4 no reserved nonce expires, so the store fills
   (about 10k per worker) and every P6 call is denied. Copy the existing
   `maxApprovalLifetimeSeconds`-requires-P4 check (around `lib.rs:1093`) for the wording
   and error style.
3. **P6 without P5:** without P5 the nonce isn't authenticated, so single use can be
   bypassed by minting a fresh nonce per call. Emit a **startup warning**; don't reject.
   Rejecting would break existing configs that are only weakened, not unusable. Say this
   in the PR so the maintainer can tighten it later.
4. Add tests:
   - P6 without P4 is rejected;
   - P6 + P4 is accepted;
   - P6 without P5 warns;
   - the former `.expect()` path denies instead of panicking. Use a unit-level call if the
     filter can't reach it.
5. Update the README and the `requiredPredicates` description in `definition/gcl.yaml`,
   then regenerate assets (`make build-asset-files`).

## #63: approval-execution-binding polish

- **Clippy on all targets (do this first).** `cargo +1.89.0 clippy --all-targets --locked
  --offline -- -D warnings` fails with exactly 4 errors: unused formatting placeholders in
  `panic!` messages at `src/test.rs:1828, 1921, 1938, 1939`. CI misses them because it
  runs `clippy --lib` only (`.github/workflows/*.yml`).
  - Fix the four messages by passing the arguments; don't bump the edition.
  - **Switch CI to `--all-targets` for both policies.** `aggregate-risk-gate` already
    passes `--all-targets` cleanly.
- **N3, nonce keys.**
  - Cap `approval.nonce` at 128 bytes and deny anything longer as malformed, using the
    existing malformed-approval verdict.
  - Key the P6 store on `sha256(iss | aud | tenant | env | nonce)`, using a separator
    that can't occur in the fields, or length-prefix them. Use whatever subset of those
    fields the approval payload actually carries, and name the subset in the PR.
  - Tests:
    - two different issuers with the same nonce don't collide;
    - an over-long nonce is denied;
    - a replay with the same issuer and nonce is still denied.
- **N4, the race between P4 and the sweep.** Make the sweep's expiry test strictly later
  than the freshness check: sweep when `now > not_after + skew + 1`, so a key that just
  passed P4 can't be swept before `store`. Re-checking freshness after the reservation is
  also fine. Add a test at the exact boundary second.
- **N5, header-mode envelope.** With `approvalSource: header` and `stripApprovalEnvelope:
  true`, remove the `x-approval` request header after evaluating it, in **block and
  monitor** mode alike, so attestation MACs don't reach the MCP server. Update the
  `stripApprovalEnvelope` description so it covers both sources. Add a test that the
  upstream request has no `x-approval` header, and keep a test that it stays when the
  flag is false.
- **N6, schema bounds.** Add `minimum: 0` and `maximum: 31536000` to
  `maxApprovalLifetimeSeconds` in `definition/gcl.yaml:139`, matching `clockSkewSeconds`.
  Keep the startup check, then regenerate assets.
- **N7, content-length.**
  - (a) After the body rewrite (`lib.rs:1585`), **remove** `content-length` and let the
    host frame the body, instead of setting it explicitly. The decoy Coordinator does the
    same and is runtime-verified on Flex 1.14. Run the `runtime-e2e-approval` CI job and
    report its result.
  - (b) Replace the bare `"content-length"` string literals with one constant.
  - (c) Document in the README and in the `mode` description that monitor mode still
    strips the envelope when `stripApprovalEnvelope` is on.
- **N8, docs.** Add to README "Known limits": in block mode, a `POST` without a declared
  `content-length` (common over HTTP/2 or chunked uploads) is denied with
  `denied;framing=content-length`. That is fail-closed by design, and some MCP clients
  and proxies drop the header.

## #65: aggregate-risk-gate polish

- **Reconcile writes a marker but discards the record** (`node_ledger.rs:746-821`).
  Persist the updated record together with the Expired/Dropped/claim marker. If that
  isn't safe while the record is busy, skip writing the marker in that case. Either way,
  add a test showing that a later deferred commit sees a record and marker that agree.
- **Pending-queue livelock** (`node_ledger.rs:929-974`, `PENDING_LIMIT = 256` at `:143`).
  Drop a queued commit whose record has vanished after a bounded number of attempts (pick
  N, e.g. 3) and log a named event when it is dropped. Add a test: 256 such entries no
  longer block every new reservation with `ledger-contention`.
- **Shared `ledgerNamespace` with an empty `scopeDigestKey`.** A startup warning already
  exists for `ledgerBackend: node` with an empty key (`lib.rs:1412`). Extend it, or add a
  second warning, for the case where `ledgerNamespace` is set and the key is empty. That
  config shares the ledger with any co-located policy using the same namespace, so it is
  read/write exposure, not just identity confirmation.
  - **Warn; don't refuse.** The default config must keep starting.
  - Say the same in the `ledgerNamespace` gcl description.
- **Monitor mode takes a scope slot for unpriceable calls** (`lib.rs:1176-1239`,
  `record(scope, 0)`). Don't record a zero-cost call in monitor mode, or release it right
  away. Add a test showing that a monitor-mode unpriceable call doesn't take up a scope
  slot.
- **Stale README startup log** (`README.md:269`). Update the "armed" log example to show
  the `ledgerBackend` field exactly as the `lib.rs` log line now prints it.
- **Mutex in the worker backend** (`ledger.rs:58`, `:623`). No change; it's documented and
  justified. Say so in the PR.

## Boundaries (load-bearing)

- Make no change to verdict semantics beyond what's listed. Existing tests must pass
  unchanged.
- **The repo is PUBLIC.** Commit no org, environment or client IDs, hosts, digest keys or
  registration material. Run the `CONTRIBUTING.md` redaction check before every commit.
  `Cargo.toml` keeps the placeholder `group_id`.
- Honesty: report only what was run. State test counts as measured. Don't claim
  connected-mode verification for anything that only ran in Local Mode.

## Verification (per policy, pinned 1.89.0)

```bash
cargo +1.89.0 fmt --check
cargo +1.89.0 clippy --all-targets --locked --offline -- -D warnings
cargo +1.89.0 test --lib --locked --offline
cargo +1.89.0 test --tests --no-run --locked --offline
cargo +1.89.0 build --release --target wasm32-wasip1 --locked
```

## Definition of done

- One PR from a fresh topic branch off `origin/main`, with `Closes #62`, `Closes #63` and
  `Closes #65`. Use `Refs` for any item you deferred.
- CI is green, including the `runtime-e2e` and `runtime-e2e-approval` jobs and the new
  `--all-targets` Clippy step.
- The PR body lists every item as **fixed / deferred (with reason) / no change**, plus new
  test counts per policy and the rc.4 CHANGELOG entry text. Leave tagging to the
  maintainer.
- Nothing published, nothing tagged, and existing tags `v0.1.0-rc.1`..`rc.3` untouched.
