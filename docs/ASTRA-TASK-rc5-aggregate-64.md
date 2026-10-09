# Astra task: rc.5, aggregate-risk gate before GA (#64)

**Context.** Tommaso Bolis's rc.3 re-review filed #64 against `aggregate-risk-gate`. It
**doesn't block catalog approval** but is wanted before GA. rc.4 (`034f6db`, PR #67)
deliberately left it out because it changes default behaviour. The maintainer has now
made the design decisions below. Implement them; don't reopen them.

All references below were checked against `034f6db` on the maintainer's Mac on
2026-10-09. If a line has moved, follow the symbol, not the number.

Read these first, in order:

1. Issue #64 (full text).
2. The root `CLAUDE.md` for the hard rules, build commands and the PUBLIC-repo redaction
   check in `CONTRIBUTING.md`.
3. `docs/CODEX-HANDOFF.md` for branch and authorization conventions.
4. `aggregate-risk-gate/README.md` "Scope of the guarantee" and the sweep description.

## Ground rules for this task

- **Source work only, in Local Mode.** No gateway run, no release tag, no Exchange/P4A
  publish. Don't cut `v0.1.0-rc.5`; the maintainer tags it after merge.
- Every behaviour change needs a regression test that **fails on `034f6db`**. Say in the
  PR which tests you checked against `034f6db`.
- Implement **both** backends (`worker` in `ledger.rs`, `node` in `node_ledger.rs`) unless
  an item says otherwise.
- Don't weaken an existing test to pass a gate. If a test's contract genuinely changes
  (item 2 does change some), say which tests and why in the PR body.
- Keep `edition = "2018"`.
- **PR body hygiene:** never write "fix", "close" or "resolve" directly before an issue
  number, **even negated**: on PR 67 the phrase "do not resolve" before the issue number
  made GitHub close issue 64 at merge. Use
  `Closes #64` exactly once, and `Refs #N` otherwise.

## 1. Bound the cleanup pass (per-pass budget + cursor)

Today `maybe_collect` → `sweep` (`node_ledger.rs:721`, `:748`) runs inside an ordinary
request. It calls `store.keys()` (→ PDK `get_keys()`, `node_ledger.rs:1235`), then
`get`s and decodes **every** matching scope record and commit marker in one pass.

Decision: **a fixed per-pass budget plus a persisted cursor.**

- Add `SWEEP_BUDGET: usize = 256`. A pass processes at most that many keys under this
  ledger's prefix (scope records `s:` and markers `c:` together), in **sorted key order**,
  starting strictly after the cursor.
- Persist the cursor in the `Sweep` record (`node_ledger.rs:226`), e.g.
  `cursor: Option<String>`. Write it with the same CAS as the existing `put_sweep`. It
  must decode an old `Sweep` record with no cursor (`#[serde(default)]`); an old record
  means starting from the beginning.
- When a pass reaches the end, reset the cursor and keep today's `next_gc` /
  `not_before` scheduling. When it stops early on the budget, schedule the next pass soon
  (`MIN_RESCAN_MS`) so a large namespace is still covered in bounded time. Keep the
  existing `next_idle` handling for the keys the pass did process.
- `freed` / slot-count adjustment stays per pass, exactly as now.
- **Honest limit, put it in the README:** `get_keys()` still returns every key in the
  store in one call (the PDK has no paged listing), so sorting and filtering that list is
  not bounded. The budget bounds the expensive part: the per-key `get`, decode, reconcile
  and write. Don't claim more.
- **Startup warning:** `ledgerBackend: node` with `maxScopes > 100000` logs a warning that
  the listing cost grows with the namespace. Warn; don't reject. The schema maximum stays
  1000000.

Tests:

- A namespace of 10 × `SWEEP_BUDGET` idle scopes plus markers: a single `sweep` performs
  at most `SWEEP_BUDGET` store `get`s. Count them in `FakeStore`.
- Repeated passes free every idle scope exactly once. The slot count ends at 0 and no
  key is visited twice before the cursor wraps.
- A legacy `Sweep` record without a cursor decodes, and the pass starts from the
  beginning.
- The warning fires above 100000 and not at 100000.

## 2. Charge abandoned reservations: `onReservationTimeout`

Today a reservation whose response never reaches the policy is reclaimed at its deadline
(`ScopeState::reclaim`, `ledger.rs:211`; node: the `Expired` mark, `node_ledger.rs:237`)
**uncharged**. A client that drops connections after the upstream ran gets free side
effects. The policy itself treats under-counting as the unsafe direction.

Decision: **new option `onReservationTimeout: commit | release`.**

- **Default: `commit` in `block` mode, `release` in `monitor` mode.** In the gcl,
  represent "default by mode" as a third value, `auto` (the default), that resolves at
  startup: block → commit, monitor → release. Log the resolved value in the "armed" line.
- `commit`: at the reservation deadline, the contribution moves from `reserved` to
  `committed` (a **provisional charge**), so the exposure never leaves the total.
  - A **late commit** inside the existing tombstone window is a no-op. It is already
    charged; never charge twice.
  - A **late release** inside the window (an error or refused response that arrived
    late) refunds the provisional charge, **but only if the window period is unchanged**
    since the charge. Otherwise it's a no-op; never refund into a new period. Use
    `saturating_sub`.
  - After the tombstone window, nothing changes the charge.
- `release`: today's behaviour, unchanged.
- **Node backend:** the provisional charge must survive the multi-worker marker
  protocol. A reservation charged at its deadline must not be charged again by a
  `Commit` marker. A late release must refund through the same CAS/reload discipline.
  Extend `Mark` as needed; don't add a second source of truth. Old markers must still
  decode.
- `stats`: count provisional charges and refunds separately from `late_committed`, so
  they're visible in the existing stats/log line.
- Docs: describe the option and the trade-off in the gcl `reservationTimeoutMs`,
  `onReservationTimeout` and `mode` descriptions (so it shows in the Anypoint UI) and in
  the README "Scope of the guarantee". The trade-off is that an honest call slower than
  the timeout is charged even if it later fails, unless its failure arrives within the
  tombstone window. Remove the README text that says abandoned calls are never charged,
  and say instead that this is the behaviour in `release` mode.

Tests (worker **and** node):

- block + `auto`: an abandoned reservation is charged at the deadline, and the next
  reservation sees the reduced headroom. Must fail on `034f6db`.
- A late commit after the provisional charge: charged once.
- A late release in the same period refunds; after a period roll it doesn't refund.
- monitor + `auto` and explicit `release`: today's behaviour (no charge).
- Node: a deferred `Commit` marker plus a deadline charge on another worker gives one
  charge, not two.

This changes the contract of some existing tests that assert "reclaimed uncharged". Under
block-mode defaults, set those tests to `release` explicitly rather than editing their
assertions, and list them in the PR.

## 3. Cap shared-data growth

- **Commit markers count against a cap.** Add a marker counter beside the scope count
  (`COUNT_KEY`, `node_ledger.rs:164`), adjusted on marker create (put-if-absent) and
  marker delete. Cap = `maxScopes`. At the cap, `persist_commit` returns `false`. The
  commit then stays in the in-memory pending queue, as it does today when the marker write
  fails. **Never drop or charge a commit because of the marker cap.** Count drift is
  acceptable only in the safe direction: over-counting refuses markers early; it never
  admits beyond the cap. Document how drift is corrected (the sweep recounts the markers
  it sees, or explain why it can't).
- **Stale-fingerprint ledgers** (left by a change to `scopeDigestKey`, `window` or
  `windowMs`, or by a deleted instance): **don't delete them.** In a shared
  `ledgerNamespace`, another live instance with a mismatched config can own a different
  prefix, and deleting it would destroy its budget state. Instead:
  - while sweeping, count keys under *other* prefixes in the listing that pass 1 already
    has, and log a named event `aggregate_risk_foreign_prefix_keys` with the count, at most
    once per `GC_INTERVAL_MS`;
  - document the expected growth and how to reclaim it (a gateway restart clears `local()`
    storage).
- Tests: the marker cap refuses a marker at `maxScopes`, and that commit stays pending
  and is not lost. The marker counter decrements when a marker is collected. The
  foreign-prefix event reports the right count.

## Boundaries (load-bearing)

- Make no change to verdict semantics beyond items 1–3. Existing tests must pass unchanged,
  except those item 2 re-pins to `release` (list them).
- **The repo is PUBLIC.** Commit no org, environment or client IDs, hosts, digest keys or
  registration material. Run the `CONTRIBUTING.md` redaction check before every commit.
  `Cargo.toml` keeps the placeholder `group_id`.
- Honesty: report only what was run. State test counts as measured. Don't claim
  connected-mode verification for Local Mode results.

## Verification (aggregate-risk-gate, pinned 1.89.0)

```bash
cargo +1.89.0 fmt --check
cargo +1.89.0 clippy --all-targets --locked --offline -- -D warnings
cargo +1.89.0 test --lib --locked --offline
cargo +1.89.0 test --tests --no-run --locked --offline
cargo +1.89.0 build --release --target wasm32-wasip1 --locked
```

Regenerate assets with `make build-asset-files` after the gcl changes.

## Definition of done

- One PR from a fresh topic branch off `origin/main`, with `Closes #64` exactly once.
- CI is green, including `runtime-e2e`. If a runtime case asserts uncharged reclaim, pin it
  to `release` and say so. Don't delete it.
- The PR body lists every item as **fixed / deferred (with reason) / no change**,
  including:
  - new test counts;
  - which new tests were checked failing against `034f6db`;
  - the re-pinned tests;
  - the rc.5 CHANGELOG entry text, marking `onReservationTimeout`'s block-mode default as
    **Breaking**.
- Nothing published, nothing tagged, and tags `v0.1.0-rc.1`..`rc.4` untouched.
