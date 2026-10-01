// Copyright 2026 msaleme. Licensed under the MIT License.
//
// Reserve-then-authorize decision engine — the "hard part" of the Cross-Session
// Aggregate-Risk Gate, deliberately kept free of any PDK dependency so it can be
// exhaustively unit tested (including under real OS-thread concurrency) without a
// gateway runtime in the loop.
//
// The property under test is the one the companion research
// (github.com/msaleme/authorized-but-composed) demonstrates: individually valid
// calls can compose past a shared budget, and only a check-and-reserve that is a
// SINGLE atomic step holds that budget under concurrency. A naive read-then-write
// counter (read the running total, decide, then write) breaches, because two
// concurrent callers can both read the same pre-commit total before either writes.
// `Ledger::reserve` never does that: the compare against `budget` and the mutation
// of `reserved` happen while holding one lock, so no other caller can observe an
// intermediate state.
//
// Scope of the guarantee: this is a single, in-process, mutex-serialized store.
// It is a real, correct reserve-then-authorize engine (proven below, including
// under genuine multi-thread contention), not a simulation of one. One `Ledger`
// exists per policy instance per gateway worker: it is NOT shared across
// workers or replicas, it does not survive a restart, and it carries no
// cryptographic attestation of its decisions. A shared, durable ledger is
// future work (v2); nothing here should be read as a claim of durability,
// multi-worker sharing, or non-repudiation.

// Units: every amount here is an exact, non-negative integer (`u64`) in the
// policy's configured unit (fixed-weight points, estimated tokens, or a
// currency's minor unit). There is no floating point anywhere in the decision
// path. `lib.rs` bounds every budget and contribution to `MAX_UNITS` (2^53 - 1)
// before it reaches this module; additions here saturate at `u64::MAX`, far
// above any admissible budget, so a sum that would overflow always compares as
// over budget instead of wrapping around.

// Time: every operation takes `now`, milliseconds on the gateway's own clock
// (`lib.rs` reads the PDK `Clock`). Passing it in keeps this module free of any
// host dependency and makes expiry exactly reproducible in tests.
//
// Windows: with a fixed window of `w` ms, period `n` is `[n*w, (n+1)*w)` since
// the Unix epoch. The first time a scope is touched in a later period, its
// committed exposure resets to zero. In-flight reservations are not reset: they
// carry into the new period, and settle there. Periods only move forward, so a
// clock that steps backwards never resets a total.

use std::collections::HashMap;
use std::sync::Mutex;

/// One in-flight reservation's ledger record.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Held {
    contribution: u64,
    expires_at: u64,
}

/// One scope's running exposure. `committed` is exposure from calls that already
/// happened (successfully, or force-recorded in monitor mode). `active` holds
/// the reservations set aside for in-flight calls whose outcome is not yet
/// known, and `reserved` is their sum. Budget checks compare against
/// `committed + reserved`, so a reserved amount blocks a concurrent composing
/// call exactly as if it had already landed — that is the whole mechanism.
///
/// `reclaimed` keeps a tombstone for each reservation that expired before it
/// was settled, until `expires_at + ttl`, so a late settlement is recognised
/// as late rather than as a duplicate (see `LedgerStore::commit`).
#[derive(Default, Clone, Debug, PartialEq)]
struct ScopeState {
    /// The window period `committed` belongs to (always 0 without a window).
    period: u64,
    committed: u64,
    reserved: u64,
    active: HashMap<u64, Held>,
    reclaimed: HashMap<u64, Held>,
}

impl ScopeState {
    /// An idle scope has nothing committed, nothing in flight and no pending
    /// tombstone, so it holds no enforcement state: dropping it and re-creating
    /// it later at zero is indistinguishable from keeping it. Only idle scopes
    /// are ever evicted.
    fn is_idle(&self) -> bool {
        self.committed == 0 && self.active.is_empty() && self.reclaimed.is_empty()
    }

    fn total(&self) -> u64 {
        self.committed.saturating_add(self.reserved)
    }

    /// Starts a new window period: committed exposure from an earlier period
    /// no longer counts. Reservations are untouched.
    fn roll(&mut self, period: u64) {
        if period > self.period {
            self.period = period;
            self.committed = 0;
        }
    }

    /// Moves every reservation whose deadline has passed out of `active` (its
    /// contribution leaves `reserved`; `committed` is untouched) and drops
    /// tombstones older than one further `ttl`. Returns how many reservations
    /// expired and how many tombstones were dropped unsettled.
    fn reclaim(&mut self, now: u64, ttl: u64) -> (u64, u64) {
        let expired: Vec<u64> = self
            .active
            .iter()
            .filter(|(_, held)| now >= held.expires_at)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            if let Some(held) = self.active.remove(id) {
                self.reserved = self.reserved.saturating_sub(held.contribution);
                self.reclaimed.insert(*id, held);
            }
        }
        let before = self.reclaimed.len();
        self.reclaimed
            .retain(|_, held| now < held.expires_at.saturating_add(ttl));
        (expired.len() as u64, (before - self.reclaimed.len()) as u64)
    }
}

/// A held reservation against a scope, returned by a successful `reserve` or
/// `force_reserve`. Settle it with `commit` or `release`. Both are idempotent:
/// only the first settlement of an `id` changes the ledger. If neither is
/// called by `expires_at`, the next ledger operation on the scope reclaims it.
#[derive(Clone, Debug, PartialEq)]
pub struct Reservation {
    /// Unique for the life of the ledger that issued it: a counter that is
    /// never reused. Stage A IDs never leave the worker process. A shared
    /// Stage B store would need IDs unique across workers.
    pub id: u64,
    pub scope: String,
    pub contribution: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

/// How a `commit` or `release` call was applied.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Settlement {
    /// The reservation was active: moved into `committed`.
    Committed,
    /// The reservation was active: removed without committing.
    Released,
    /// The reservation had expired and been reclaimed. A late commit still
    /// charges its contribution to `committed`, because the call it covered
    /// did happen and an under-count is the unsafe direction for a risk
    /// budget. The charge is applied without a budget check, the same way
    /// monitor mode records exposure it can no longer refuse.
    LateCommitted,
    /// The reservation had expired and been reclaimed; nothing to undo.
    LateReleased,
    /// Already settled, or unknown to this ledger (for example a settlement
    /// that arrived more than `2 × ttl` after the reservation was made). A
    /// no-op, so a duplicate or reordered settlement never double-counts.
    NotActive,
}

impl Settlement {
    pub fn label(self) -> &'static str {
        match self {
            Settlement::Committed => "committed",
            Settlement::Released => "released",
            Settlement::LateCommitted => "late-committed",
            Settlement::LateReleased => "late-released",
            Settlement::NotActive => "not-active",
        }
    }
}

/// Ledger-wide reservation counters for operator telemetry. Each counter only
/// ever increases except `active`, which is the current number in flight.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct LedgerStats {
    pub active: u64,
    pub committed: u64,
    pub released: u64,
    /// Reservations reclaimed because they passed their deadline unsettled.
    pub expired: u64,
    pub late_committed: u64,
    pub late_released: u64,
    /// Expired reservations whose tombstone was dropped with no settlement
    /// ever arriving: the request was cancelled or its response hook never ran.
    pub abandoned: u64,
    /// Settlements that matched nothing (duplicate, reordered, or too late).
    pub not_active: u64,
}

/// A denied reservation attempt: the call was NOT reserved and NOT mutated into
/// the ledger. There is nothing to release for a `Denial` — that is the point of
/// checking before mutating.
#[derive(Clone, Debug, PartialEq)]
pub struct Denial {
    pub scope: String,
    pub contribution: u64,
    /// `committed + reserved` for this scope at the moment of the check, before
    /// this call's own contribution.
    pub current_total: u64,
    /// What the total would have become had this call been admitted.
    pub would_be_total: u64,
    pub budget: u64,
}

/// A point-in-time view of one scope's ledger state, for tests and for stamping
/// diagnostic headers. Not itself part of the decision engine.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Snapshot {
    pub committed: u64,
    pub reserved: u64,
}

/// Why `reserve` refused a call.
#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    /// Admitting the contribution would push the scope over its budget.
    OverBudget(Denial),
    /// `scope` is new and the ledger already tracks `max_scopes` scopes, none
    /// of them idle. The call is refused rather than evicting live state.
    AtCapacity,
}

#[cfg(test)]
impl Refusal {
    /// The budget denial inside an `OverBudget` refusal; panics otherwise.
    pub fn over_budget(self) -> Denial {
        match self {
            Refusal::OverBudget(denial) => denial,
            Refusal::AtCapacity => panic!("expected OverBudget, got AtCapacity"),
        }
    }
}

impl Snapshot {
    pub fn total(&self) -> u64 {
        self.committed.saturating_add(self.reserved)
    }
}

/// The behavior every backend must provide. `lib.rs` (the PDK-aware filter)
/// calls the ledger only through this trait (it constructs a `Ledger` once), so
/// a shared (v2) backend could later implement the same trait without touching
/// the filter's decision logic — an explicit seam for the roadmap work called out in the module
/// doc comment, not a claim that such a backend exists today.
///
/// Every method first reclaims the scope's expired reservations, under the
/// same lock as the operation itself.
pub trait LedgerStore {
    /// Atomically checks `scope`'s committed-plus-reserved exposure against
    /// `budget` and, only if `contribution` fits, reserves it until
    /// `now + ttl`. On denial, no reservation is made for `scope`. A new scope
    /// that does not fit under the ledger's scope cap is refused with
    /// `AtCapacity`.
    fn reserve(
        &self,
        scope: &str,
        contribution: u64,
        budget: u64,
        now: u64,
    ) -> Result<Reservation, Refusal>;

    /// Reserves `contribution` against `scope` unconditionally, ignoring
    /// `budget` — the monitor-mode primitive: composition is still tracked
    /// accurately (including symmetric commit/release around the upstream
    /// outcome), but nothing is ever denied.
    ///
    /// The filter (`lib.rs`) calls `force_reserve_checked` instead, since
    /// monitor mode needs the breach signal to raise a policy violation.
    /// `force_reserve` is kept as the simpler, directly-tested primitive
    /// `force_reserve_checked` is documented against (and is deliberately
    /// NOT implemented by delegating to this method plus a second locked
    /// read, which would reopen the exact read-then-write race window this
    /// module's whole correctness story is about) — hence `#[allow(dead_code)]`
    /// rather than deleting a real, tested API.
    ///
    /// `None` only when `scope` is new and the ledger is at its scope cap.
    #[allow(dead_code)]
    fn force_reserve(&self, scope: &str, contribution: u64, now: u64) -> Option<Reservation>;

    /// `force_reserve`, plus a breach signal: reserves `contribution`
    /// against `scope` unconditionally (never denies — monitor mode still
    /// forwards every call), but also reports whether doing so pushed
    /// committed-plus-reserved exposure over `budget`. This is what lets
    /// monitor mode raise the same policy-violation signal a block-mode
    /// denial would, without actually denying the call. `None` only when
    /// `scope` is new and the ledger is at its scope cap.
    fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: u64,
        budget: u64,
        now: u64,
    ) -> Option<(Reservation, bool)>;

    /// Settles a reservation as successful. An active reservation moves its
    /// contribution from `reserved` into `committed`. See `Settlement` for
    /// the expired and already-settled cases.
    fn commit(&self, reservation: &Reservation, now: u64) -> Settlement;

    /// Settles a reservation as not consumed: an active reservation's
    /// contribution leaves `reserved` without ever reaching `committed`. Used
    /// when the upstream call failed, so a failed call does not count against
    /// the budget.
    fn release(&self, reservation: &Reservation, now: u64) -> Settlement;

    /// Records `contribution` directly into `committed`, bypassing both the
    /// budget check and the reserve/commit two-step. Used for a call whose
    /// exposure is known only after it already happened and so can no longer be
    /// denied (e.g. monitor mode's unpriceable-at-request-time cases, or a
    /// direct audit correction). Returns `false`, recording nothing, only when
    /// `scope` is new and the ledger is at its scope cap.
    fn record(&self, scope: &str, contribution: u64, now: u64) -> bool;

    /// A read-only view of one scope's current state, for diagnostics/tests.
    /// Never creates an entry, reclaims, or starts a new window period: it
    /// shows the scope as of its last touch. An untracked scope reads as zero.
    fn snapshot(&self, scope: &str) -> Snapshot;

    /// The ledger-wide reservation counters.
    fn stats(&self) -> LedgerStats;
}

struct Inner {
    scopes: HashMap<String, ScopeState>,
    next_id: u64,
    stats: LedgerStats,
}

/// The per-worker ledger: an in-process, mutex-serialized `HashMap` of scope states.
/// `std::sync::Mutex` (rather than `RefCell`) is a deliberate choice beyond what
/// the PDK's single-threaded async runtime strictly requires — it lets the unit
/// tests below exercise `reserve` under genuine OS-thread contention, not just
/// simulated/interleaved async calls, which is the strongest evidence available
/// short of a real distributed backend that reserve-then-authorize actually holds
/// the budget under a race.
///
/// Cardinality is bounded by `max_scopes`. When a NEW scope arrives at the cap,
/// expired reservations are reclaimed across the ledger and then one idle scope
/// (see `ScopeState::is_idle`) is evicted to make room; if every tracked scope
/// still holds committed or reserved exposure, the new scope is refused
/// instead. Live enforcement state is never evicted, so the cap can never be
/// used to reset another scope's running total.
pub struct Ledger {
    inner: Mutex<Inner>,
    max_scopes: usize,
    ttl: u64,
    /// Fixed window length in ms; `None` accumulates for the worker's life.
    window: Option<u64>,
}

/// The default reservation lifetime used by tests of the budget arithmetic.
#[cfg(test)]
pub const TEST_TTL: u64 = 60_000;

impl Ledger {
    /// An unbounded ledger, for tests of the budget arithmetic itself.
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_limits(usize::MAX, TEST_TTL, None)
    }

    #[cfg(test)]
    pub fn with_max_scopes(max_scopes: usize) -> Self {
        Self::with_limits(max_scopes, TEST_TTL, None)
    }

    #[cfg(test)]
    pub fn with_window(window: u64) -> Self {
        Self::with_limits(usize::MAX, TEST_TTL, Some(window))
    }

    /// `ttl` is the reservation lifetime in milliseconds.
    pub fn with_limits(max_scopes: usize, ttl: u64, window: Option<u64>) -> Self {
        Ledger {
            inner: Mutex::new(Inner {
                scopes: HashMap::new(),
                next_id: 1,
                stats: LedgerStats::default(),
            }),
            max_scopes,
            ttl,
            window,
        }
    }

    fn period(&self, now: u64) -> u64 {
        self.window.map_or(0, |window| now / window)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned mutex (a prior panic while the lock was held) still holds
        // valid, if possibly inconsistent, ledger data. Recovering it rather than
        // panicking again keeps this store fail-open at the Rust-panic level
        // while the filter above it stays fail-closed at the policy-decision
        // level (a denial is a normal, safe `Err`, never a panic).
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Runs `f` on `scope`'s state, creating it if needed, after reclaiming
    /// its expired reservations. Returns `None`, without running `f`, if
    /// `scope` is new and there is no room for it. The capacity check, any
    /// reclamation or eviction, and `f` all happen under one lock.
    fn with_state<R>(
        &self,
        scope: &str,
        now: u64,
        f: impl FnOnce(&mut ScopeState, &mut u64, &mut LedgerStats) -> R,
    ) -> Option<R> {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let period = self.period(now);
        if !inner.scopes.contains_key(scope) && inner.scopes.len() >= self.max_scopes {
            for state in inner.scopes.values_mut() {
                state.roll(period);
                count_reclaim(&mut inner.stats, state.reclaim(now, self.ttl));
            }
            let idle = inner
                .scopes
                .iter()
                .find(|(_, state)| state.is_idle())
                .map(|(key, _)| key.clone());
            match idle {
                Some(key) => {
                    inner.scopes.remove(&key);
                }
                None => return None,
            }
        }
        let state = inner.scopes.entry(scope.to_string()).or_default();
        state.roll(period);
        count_reclaim(&mut inner.stats, state.reclaim(now, self.ttl));
        Some(f(state, &mut inner.next_id, &mut inner.stats))
    }

    /// Adds a new active reservation to `state`.
    fn hold(
        &self,
        state: &mut ScopeState,
        next_id: &mut u64,
        stats: &mut LedgerStats,
        scope: &str,
        contribution: u64,
        now: u64,
    ) -> Reservation {
        let id = *next_id;
        *next_id += 1;
        let expires_at = now.saturating_add(self.ttl);
        state.reserved = state.reserved.saturating_add(contribution);
        state.active.insert(
            id,
            Held {
                contribution,
                expires_at,
            },
        );
        stats.active += 1;
        Reservation {
            id,
            scope: scope.to_string(),
            contribution,
            created_at: now,
            expires_at,
        }
    }

    /// Settles `reservation` on its EXISTING scope. An untracked scope
    /// (never created, or evicted while idle) settles as `NotActive`.
    fn settle(&self, reservation: &Reservation, now: u64, commit: bool) -> Settlement {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let stats = &mut inner.stats;
        let outcome = match inner.scopes.get_mut(&reservation.scope) {
            None => Settlement::NotActive,
            Some(state) => {
                // A commit lands in the current window period.
                state.roll(self.period(now));
                // Settlement first, reclamation second: a response that lands
                // before the scope is next touched still settles normally,
                // even if its deadline has technically passed.
                let outcome = if let Some(held) = state.active.remove(&reservation.id) {
                    state.reserved = state.reserved.saturating_sub(held.contribution);
                    stats.active = stats.active.saturating_sub(1);
                    if commit {
                        state.committed = state.committed.saturating_add(held.contribution);
                        Settlement::Committed
                    } else {
                        Settlement::Released
                    }
                } else if let Some(held) = state.reclaimed.remove(&reservation.id) {
                    if commit {
                        state.committed = state.committed.saturating_add(held.contribution);
                        Settlement::LateCommitted
                    } else {
                        Settlement::LateReleased
                    }
                } else {
                    Settlement::NotActive
                };
                count_reclaim(stats, state.reclaim(now, self.ttl));
                outcome
            }
        };
        match outcome {
            Settlement::Committed => stats.committed += 1,
            Settlement::Released => stats.released += 1,
            Settlement::LateCommitted => stats.late_committed += 1,
            Settlement::LateReleased => stats.late_released += 1,
            Settlement::NotActive => stats.not_active += 1,
        }
        outcome
    }

    /// How many scopes the ledger currently tracks.
    #[cfg(test)]
    pub fn scope_count(&self) -> usize {
        self.lock().scopes.len()
    }
}

fn count_reclaim(stats: &mut LedgerStats, (expired, abandoned): (u64, u64)) {
    stats.active = stats.active.saturating_sub(expired);
    stats.expired += expired;
    stats.abandoned += abandoned;
}

impl LedgerStore for Ledger {
    fn reserve(
        &self,
        scope: &str,
        contribution: u64,
        budget: u64,
        now: u64,
    ) -> Result<Reservation, Refusal> {
        self.with_state(scope, now, |state, next_id, stats| {
            let current_total = state.total();
            let would_be_total = current_total.saturating_add(contribution);
            if would_be_total > budget {
                return Err(Refusal::OverBudget(Denial {
                    scope: scope.to_string(),
                    contribution,
                    current_total,
                    would_be_total,
                    budget,
                }));
            }
            Ok(self.hold(state, next_id, stats, scope, contribution, now))
        })
        .unwrap_or(Err(Refusal::AtCapacity))
    }

    fn force_reserve(&self, scope: &str, contribution: u64, now: u64) -> Option<Reservation> {
        self.with_state(scope, now, |state, next_id, stats| {
            self.hold(state, next_id, stats, scope, contribution, now)
        })
    }

    fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: u64,
        budget: u64,
        now: u64,
    ) -> Option<(Reservation, bool)> {
        self.with_state(scope, now, |state, next_id, stats| {
            let reservation = self.hold(state, next_id, stats, scope, contribution, now);
            (reservation, state.total() > budget)
        })
    }

    fn commit(&self, reservation: &Reservation, now: u64) -> Settlement {
        self.settle(reservation, now, true)
    }

    fn release(&self, reservation: &Reservation, now: u64) -> Settlement {
        self.settle(reservation, now, false)
    }

    fn record(&self, scope: &str, contribution: u64, now: u64) -> bool {
        self.with_state(scope, now, |state, _, _| {
            state.committed = state.committed.saturating_add(contribution);
        })
        .is_some()
    }

    fn snapshot(&self, scope: &str) -> Snapshot {
        self.lock()
            .scopes
            .get(scope)
            .map(|state| Snapshot {
                committed: state.committed,
                reserved: state.reserved,
            })
            .unwrap_or(Snapshot {
                committed: 0,
                reserved: 0,
            })
    }

    fn stats(&self) -> LedgerStats {
        self.lock().stats
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    // ---------------------------------------------------------------------
    // The companion repo's sequential-composition scenario, reproduced exactly:
    // authorized-but-composed/examples/authorized-but-composed/{synthetic-policy,
    // synthetic-session-actions}.json — per-session cap 1000 (enforced upstream of
    // this ledger, not modeled here), aggregate budget 3000, five sessions each
    // requesting 800. The first three commit (2400 total); the fourth's own
    // per-call amount is locally valid (800 <= 1000 cap) but composes to 3200,
    // over the 3000 budget, so it is refused even though nothing about the call
    // itself was invalid.
    // ---------------------------------------------------------------------

    const CAP_BUDGET: u64 = 3000;
    const CAP_CONTRIBUTION: u64 = 800;

    #[test]
    fn sequential_composition_refuses_the_call_that_would_exceed_budget() {
        let ledger = Ledger::new();
        let scope = "agent:fleet-a";

        // Sessions 1-3: each individually valid, each admitted, composing to 2400.
        for _ in 0..3 {
            let reservation = ledger
                .reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET, 0)
                .expect("first three sessions must be admitted");
            ledger.commit(&reservation, 0);
        }
        assert_eq!(ledger.snapshot(scope).total(), 2400);

        // Session 4: locally valid (800 <= a 1000 per-session cap enforced above
        // this ledger), but 2400 + 800 = 3200 > 3000 — refused.
        let denial = ledger
            .reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET, 0)
            .expect_err("fourth session composes past the aggregate budget")
            .over_budget();
        assert_eq!(denial.current_total, 2400);
        assert_eq!(denial.would_be_total, 3200);
        assert_eq!(denial.budget, CAP_BUDGET);

        // The refusal must not have mutated the ledger.
        assert_eq!(ledger.snapshot(scope).total(), 2400);
    }

    #[test]
    fn sequential_composition_a_fifth_session_is_also_refused() {
        let ledger = Ledger::new();
        let scope = "agent:fleet-a";
        for _ in 0..3 {
            let reservation = ledger
                .reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET, 0)
                .unwrap();
            ledger.commit(&reservation, 0);
        }
        // Two more attempts at 800 each: both refused, neither changes the total.
        for _ in 0..2 {
            assert!(ledger
                .reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET, 0)
                .is_err());
        }
        assert_eq!(ledger.snapshot(scope).total(), 2400);
    }

    // ---------------------------------------------------------------------
    // The companion repo's RACE scenario, reproduced exactly:
    // authorized-but-composed-race/{synthetic-policy,synthetic-concurrent-
    // sessions}.json — the same cap/budget/contribution, but five sessions
    // dispatched CONCURRENTLY. A naive read-then-write counter authorizes all
    // five (reads the same pre-commit snapshot, so nothing prevents 4000 > 3000
    // from landing). Reserve-then-authorize against this serialized ledger must
    // hold the budget: exactly three of the five commit (2400), and the other two
    // are denied — never four, never five.
    // ---------------------------------------------------------------------

    /// A literal naive read-then-write counter — deliberately reproducing the
    /// checked-then-acted bug reserve-then-authorize exists to fix, so the
    /// contrast is a real, executable difference rather than an assertion.
    struct NaiveCounter {
        total: Mutex<u64>,
    }

    impl NaiveCounter {
        fn new() -> Self {
            Self {
                total: Mutex::new(0),
            }
        }

        /// Read the current total, decide, THEN write — with a delay between the
        /// read and the write so that under real thread contention, other
        /// threads' reads can land inside the window and observe the same
        /// pre-write snapshot. This is what makes the naive counter breach: the
        /// check and the mutation are two steps, not one.
        fn naive_check_then_add(&self, amount: u64, budget: u64) -> bool {
            let current = *self.total.lock().unwrap();
            let would_be = current.saturating_add(amount);
            if would_be > budget {
                return false;
            }
            // The gap a real read-then-write counter has: another thread's read
            // can land here, before this thread's write is visible.
            thread::yield_now();
            let mut total = self.total.lock().unwrap();
            *total = total.saturating_add(amount);
            true
        }
    }

    #[test]
    fn naive_counter_breaches_budget_under_concurrency() {
        // This test documents the bug reserve-then-authorize fixes. It is
        // expected to demonstrate a breach (all five admitted, 4000 > 3000) on
        // the overwhelming majority of runs on a real multi-core scheduler; it
        // is retried a bounded number of times only to avoid one flaky pass on
        // extremely fast/serialized CI hosts and NEVER masks a hold as a breach.
        let mut observed_breach = false;
        for _ in 0..25 {
            let counter = Arc::new(NaiveCounter::new());
            let handles: Vec<_> = (0..5)
                .map(|_| {
                    let counter = Arc::clone(&counter);
                    thread::spawn(move || {
                        counter.naive_check_then_add(CAP_CONTRIBUTION, CAP_BUDGET)
                    })
                })
                .collect();
            let admitted = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|admitted| *admitted)
                .count();
            let total = *counter.total.lock().unwrap();
            if admitted > 3 {
                observed_breach = true;
                assert!(
                    total > CAP_BUDGET,
                    "{}",
                    format!(
                        "naive counter admitted {admitted} sessions totalling {total}, over budget {CAP_BUDGET}"
                    )
                );
                break;
            }
        }
        assert!(
            observed_breach,
            "expected the naive read-then-write counter to breach budget at least once in 25 runs"
        );
    }

    #[test]
    fn reserve_then_authorize_holds_budget_under_concurrency() {
        // Same five concurrent 800-unit calls against the same 3000 budget,
        // against the real Ledger instead of the naive counter above. Reserve is
        // one atomic step (check-and-mutate under one lock acquisition), so no
        // thread can observe a stale pre-write snapshot: exactly three commit.
        for _ in 0..25 {
            let ledger = Arc::new(Ledger::new());
            let scope = "agent:fleet-race";
            let handles: Vec<_> = (0..5)
                .map(|_| {
                    let ledger = Arc::clone(&ledger);
                    thread::spawn(move || {
                        ledger
                            .reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET, 0)
                            .map(|reservation| {
                                ledger.commit(&reservation, 0);
                            })
                    })
                })
                .collect();
            let admitted = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|result| result.is_ok())
                .count();
            assert_eq!(
                admitted, 3,
                "reserve-then-authorize must admit exactly 3 of 5"
            );
            assert_eq!(
                ledger.snapshot(scope).total(),
                2400,
                "committed total must never exceed the 3000 budget"
            );
        }
    }

    #[test]
    fn reserve_then_authorize_never_exceeds_budget_across_many_concurrent_scopes() {
        // A stronger stress form: many threads, hammering many different scopes
        // concurrently, each scope with its own independent budget. No scope's
        // committed total may ever exceed its own budget, and scopes must not
        // leak exposure into one another.
        let ledger = Arc::new(Ledger::new());
        let scopes = ["agent:a", "agent:b", "agent:c"];
        let per_call = 250;
        let budget = 1000; // holds at most 4 of the 10 attempts per scope

        let mut handles = Vec::new();
        for scope in scopes {
            for _ in 0..10 {
                let ledger = Arc::clone(&ledger);
                handles.push(thread::spawn(move || {
                    ledger
                        .reserve(scope, per_call, budget, 0)
                        .map(|reservation| {
                            ledger.commit(&reservation, 0);
                        })
                }));
            }
        }
        for handle in handles {
            let _ = handle.join().unwrap();
        }
        for scope in scopes {
            let total = ledger.snapshot(scope).total();
            assert!(
                total <= budget,
                "{}",
                format!("scope {scope} total {total} exceeded budget {budget}")
            );
            assert_eq!(
                total, 1000,
                "scope {scope} should have admitted exactly 4 of 10 calls"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Reservation lifecycle: commit / release.
    // ---------------------------------------------------------------------

    #[test]
    fn commit_moves_contribution_from_reserved_to_committed() {
        let ledger = Ledger::new();
        let reservation = ledger.reserve("s", 100, 1000, 0).unwrap();
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0,
                reserved: 100
            }
        );
        ledger.commit(&reservation, 0);
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 100,
                reserved: 0
            }
        );
    }

    #[test]
    fn release_removes_reservation_without_committing() {
        let ledger = Ledger::new();
        let reservation = ledger.reserve("s", 100, 1000, 0).unwrap();
        ledger.release(&reservation, 0);
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0,
                reserved: 0
            }
        );
    }

    #[test]
    fn a_released_reservation_frees_budget_for_a_later_call() {
        let ledger = Ledger::new();
        let first = ledger.reserve("s", 900, 1000, 0).unwrap();
        assert!(
            ledger.reserve("s", 200, 1000, 0).is_err(),
            "900 reserved leaves no room for 200"
        );
        ledger.release(&first, 0);
        assert!(
            ledger.reserve("s", 200, 1000, 0).is_ok(),
            "releasing the first reservation must free its budget"
        );
    }

    #[test]
    fn record_bypasses_the_budget_check_entirely() {
        let ledger = Ledger::new();
        // record() has no budget parameter: it cannot be denied by construction.
        ledger.record("s", 10_000, 0);
        assert_eq!(ledger.snapshot("s").committed, 10_000);
    }

    #[test]
    fn force_reserve_always_succeeds_even_over_a_notional_budget() {
        let ledger = Ledger::new();
        let reservation = ledger.force_reserve("s", 10_000, 0).unwrap();
        assert_eq!(ledger.snapshot("s").reserved, 10_000);
        ledger.commit(&reservation, 0);
        assert_eq!(ledger.snapshot("s").committed, 10_000);
    }

    #[test]
    fn force_reserve_checked_reports_no_breach_when_within_budget() {
        let ledger = Ledger::new();
        let (reservation, breached) = ledger.force_reserve_checked("s", 500, 1000, 0).unwrap();
        assert!(!breached);
        assert_eq!(ledger.snapshot("s").reserved, 500);
        ledger.commit(&reservation, 0);
    }

    #[test]
    fn force_reserve_checked_reports_breach_when_over_budget_but_still_reserves() {
        let ledger = Ledger::new();
        // Never denies (monitor-mode primitive), but must still truthfully
        // report that this reservation pushed the scope over budget.
        let (reservation, breached) = ledger.force_reserve_checked("s", 1500, 1000, 0).unwrap();
        assert!(breached);
        assert_eq!(
            ledger.snapshot("s").reserved,
            1500,
            "force_reserve_checked must still reserve the full amount despite the breach"
        );
        ledger.commit(&reservation, 0);
        assert_eq!(ledger.snapshot("s").committed, 1500);
    }

    #[test]
    fn force_reserve_checked_breach_reflects_prior_committed_exposure_too() {
        let ledger = Ledger::new();
        let first = ledger.force_reserve_checked("s", 800, 1000, 0).unwrap();
        assert!(!first.1);
        ledger.commit(&first.0, 0);
        // 800 committed + 300 more reserved = 1100 > 1000: a breach, even
        // though this second call's OWN amount is well within budget alone.
        let (reservation, breached) = ledger.force_reserve_checked("s", 300, 1000, 0).unwrap();
        assert!(breached);
        ledger.commit(&reservation, 0);
    }

    #[test]
    fn force_reserve_still_supports_release_on_upstream_failure() {
        // Monitor mode's mechanics must stay symmetric: a call that never
        // actually landed upstream should not count against the running total,
        // even though force_reserve never denies up front.
        let ledger = Ledger::new();
        let reservation = ledger.force_reserve("s", 500, 0).unwrap();
        ledger.release(&reservation, 0);
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0,
                reserved: 0
            }
        );
    }

    // ---------------------------------------------------------------------
    // Budget-scope keying / isolation.
    // ---------------------------------------------------------------------

    #[test]
    fn different_scopes_have_independent_totals() {
        let ledger = Ledger::new();
        let a = ledger.reserve("agent:a", 900, 1000, 0).unwrap();
        ledger.commit(&a, 0);
        // A different scope key starts fresh even though it shares a budget.
        assert!(ledger.reserve("agent:b", 900, 1000, 0).is_ok());
        assert_eq!(ledger.snapshot("agent:a").total(), 900);
        assert_eq!(ledger.snapshot("agent:b").total(), 900);
    }

    #[test]
    fn budget_scope_dimension_is_encoded_in_the_key_not_a_separate_field() {
        // "agent:x" and "tenant:x" are different ledger keys even though the
        // identity value "x" is the same — the aggregation dimension is part of
        // the key. This test documents that contract at the ledger layer (the
        // filter is what actually builds these keys; see lib.rs).
        let ledger = Ledger::new();
        let agent_res = ledger.reserve("agent:x", 900, 1000, 0).unwrap();
        ledger.commit(&agent_res, 0);
        assert!(
            ledger.reserve("tenant:x", 900, 1000, 0).is_ok(),
            "a different scope dimension for the same identity value must not share budget"
        );
    }

    // ---------------------------------------------------------------------
    // Boundary / off-by-one correctness.
    // ---------------------------------------------------------------------

    #[test]
    fn a_call_landing_exactly_on_budget_is_admitted() {
        let ledger = Ledger::new();
        assert!(
            ledger.reserve("s", 1000, 1000, 0).is_ok(),
            "exactly-at-budget must be admitted"
        );
    }

    #[test]
    fn a_call_one_unit_over_budget_is_denied() {
        let ledger = Ledger::new();
        let denial = ledger
            .reserve("s", 1001, 1000, 0)
            .unwrap_err()
            .over_budget();
        assert_eq!(denial.would_be_total, 1001);
    }

    #[test]
    fn a_zero_contribution_call_is_always_admitted_even_at_zero_budget() {
        let ledger = Ledger::new();
        assert!(ledger.reserve("s", 0, 0, 0).is_ok());
    }

    #[test]
    fn a_zero_budget_denies_any_positive_contribution() {
        let ledger = Ledger::new();
        assert!(ledger.reserve("s", 1, 0, 0).is_err());
    }

    #[test]
    fn committed_exposure_from_a_prior_call_counts_against_a_new_reservation() {
        let ledger = Ledger::new();
        let reservation = ledger.reserve("s", 1000, 1000, 0).unwrap();
        ledger.commit(&reservation, 0);
        // The scope is now fully committed; even a zero-sized new call is fine,
        // but anything positive must be denied.
        assert!(ledger.reserve("s", 0, 1000, 0).is_ok());
        assert!(ledger.reserve("s", 1, 1000, 0).is_err());
    }

    #[test]
    fn an_in_flight_reservation_counts_against_a_concurrent_reservation_attempt() {
        // The core of reserve-then-authorize: a RESERVED (not yet committed)
        // amount must block a composing call exactly as if it had landed.
        let ledger = Ledger::new();
        let first = ledger.reserve("s", 600, 1000, 0).unwrap();
        assert!(
            ledger.reserve("s", 500, 1000, 0).is_err(),
            "an in-flight reservation must count against the budget check"
        );
        ledger.release(&first, 0);
        assert!(ledger.reserve("s", 500, 1000, 0).is_ok());
    }

    #[test]
    fn release_never_drives_reserved_negative() {
        // Releasing a reservation that (by programmer error) does not match what
        // is actually held must not underflow the tracked state into a negative
        // "reserved" that would let future calls smuggle extra budget through.
        let ledger = Ledger::new();
        assert_eq!(
            ledger.release(&forged("s", 1, 500), 0),
            Settlement::NotActive
        );
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0,
                reserved: 0
            }
        );
    }

    #[test]
    fn denial_report_carries_the_scope_and_amounts_for_diagnostics() {
        let ledger = Ledger::new();
        let reservation = ledger.reserve("agent:z", 700, 1000, 0).unwrap();
        ledger.commit(&reservation, 0);
        let denial = ledger
            .reserve("agent:z", 400, 1000, 0)
            .unwrap_err()
            .over_budget();
        assert_eq!(denial.scope, "agent:z");
        assert_eq!(denial.contribution, 400);
        assert_eq!(denial.current_total, 700);
        assert_eq!(denial.would_be_total, 1100);
        assert_eq!(denial.budget, 1000);
    }

    // ---------------------------------------------------------------------
    // Exact integer arithmetic (P4A review #18).
    // ---------------------------------------------------------------------

    #[test]
    fn cumulative_small_contributions_land_exactly_on_budget() {
        // The f64 build's failure mode: ten 0.1 contributions sum to
        // 0.9999999999999999, and 0.1 + 0.2 > 0.3. In exact minor units, ten
        // contributions of 1 against a budget of 10 admit exactly ten, and the
        // eleventh is denied.
        let ledger = Ledger::new();
        for _ in 0..10 {
            let reservation = ledger.reserve("s", 1, 10, 0).expect("within budget");
            ledger.commit(&reservation, 0);
        }
        assert_eq!(ledger.snapshot("s").total(), 10);
        assert!(ledger.reserve("s", 1, 10, 0).is_err());

        let ledger = Ledger::new();
        ledger.commit(&ledger.reserve("s", 10, 30, 0).unwrap(), 0);
        ledger.commit(&ledger.reserve("s", 20, 30, 0).unwrap(), 0);
        assert_eq!(ledger.snapshot("s").total(), 30, "10 + 20 is exactly 30");
    }

    #[test]
    fn an_overflowing_sum_is_denied_rather_than_wrapping() {
        let ledger = Ledger::new();
        ledger.record("s", u64::MAX - 1, 0);
        let denial = ledger
            .reserve("s", 10, u64::MAX - 1, 0)
            .unwrap_err()
            .over_budget();
        assert_eq!(
            denial.would_be_total,
            u64::MAX,
            "the sum saturates instead of wrapping to a small number"
        );
        assert_eq!(ledger.snapshot("s").total(), u64::MAX - 1);
    }

    #[test]
    fn force_reserve_checked_saturates_and_reports_the_breach() {
        let ledger = Ledger::new();
        ledger.record("s", u64::MAX, 0);
        let (reservation, breached) = ledger.force_reserve_checked("s", 5, 1000, 0).unwrap();
        assert!(breached);
        assert_eq!(ledger.snapshot("s").total(), u64::MAX);
        ledger.release(&reservation, 0);
        assert_eq!(ledger.snapshot("s").reserved, 0);
    }

    #[test]
    fn an_unknown_scope_has_a_zero_snapshot() {
        let ledger = Ledger::new();
        assert_eq!(
            ledger.snapshot("never-seen"),
            Snapshot {
                committed: 0,
                reserved: 0
            }
        );
    }

    #[test]
    fn snapshot_of_an_unknown_scope_does_not_start_tracking_it() {
        let ledger = Ledger::with_max_scopes(1);
        ledger.snapshot("probe");
        assert_eq!(ledger.scope_count(), 0);
    }

    #[test]
    fn a_full_ledger_refuses_a_new_scope_when_no_scope_is_idle() {
        let ledger = Ledger::with_max_scopes(2);
        let a = ledger.reserve("a", 10, 100, 0).unwrap();
        ledger.commit(&a, 0);
        let _in_flight = ledger.reserve("b", 10, 100, 0).unwrap();
        assert!(matches!(
            ledger.reserve("c", 10, 100, 0),
            Err(Refusal::AtCapacity)
        ));
        assert!(ledger.force_reserve_checked("c", 10, 100, 0).is_none());
        assert!(!ledger.record("c", 10, 0));
        assert_eq!(ledger.scope_count(), 2);
        // Neither live scope lost its state to make room.
        assert_eq!(ledger.snapshot("a").committed, 10);
        assert_eq!(ledger.snapshot("b").reserved, 10);
    }

    #[test]
    fn a_full_ledger_evicts_only_an_idle_scope() {
        let ledger = Ledger::with_max_scopes(2);
        let a = ledger.reserve("a", 10, 100, 0).unwrap();
        ledger.commit(&a, 0);
        // "b" reserved then released: zero committed, zero reserved — idle.
        let b = ledger.reserve("b", 10, 100, 0).unwrap();
        ledger.release(&b, 0);
        assert!(ledger.reserve("c", 10, 100, 0).is_ok());
        assert_eq!(ledger.scope_count(), 2);
        assert_eq!(ledger.snapshot("a").committed, 10, "live scope kept");
        assert_eq!(ledger.snapshot("b").total(), 0);
    }

    #[test]
    fn an_already_tracked_scope_is_never_refused_for_capacity() {
        let ledger = Ledger::with_max_scopes(1);
        let first = ledger.reserve("a", 10, 100, 0).unwrap();
        ledger.commit(&first, 0);
        assert!(ledger.reserve("a", 10, 100, 0).is_ok());
    }

    #[test]
    fn commit_and_release_on_an_untracked_scope_do_not_create_it() {
        let ledger = Ledger::with_max_scopes(1);
        ledger.commit(&forged("ghost", 1, 5), 0);
        ledger.release(&forged("ghost", 1, 5), 0);
        assert_eq!(ledger.scope_count(), 0);
    }

    /// A reservation this ledger never issued.
    fn forged(scope: &str, id: u64, contribution: u64) -> Reservation {
        Reservation {
            id,
            scope: scope.to_string(),
            contribution,
            created_at: 0,
            expires_at: TEST_TTL,
        }
    }

    // -----------------------------------------------------------------------
    // Reservation lifecycle (issue #17): IDs, TTL, idempotent settlement.
    // -----------------------------------------------------------------------

    #[test]
    fn every_reservation_has_a_unique_id_and_a_bounded_lifetime() {
        let ledger = Ledger::new();
        let mut ids = std::collections::HashSet::new();
        for i in 0..1000u64 {
            let scope = format!("s{}", i % 7);
            let r = ledger.force_reserve(&scope, 1, i).unwrap();
            assert!(ids.insert(r.id), "id {} reused", r.id);
            assert_eq!(r.created_at, i);
            assert_eq!(r.expires_at, i + TEST_TTL);
        }
    }

    #[test]
    fn a_duplicate_commit_does_not_double_count() {
        let ledger = Ledger::new();
        let r = ledger.reserve("s", 800, 3000, 0).unwrap();
        assert_eq!(ledger.commit(&r, 1), Settlement::Committed);
        assert_eq!(ledger.commit(&r, 2), Settlement::NotActive);
        assert_eq!(ledger.snapshot("s").committed, 800);
        assert_eq!(ledger.snapshot("s").reserved, 0);
    }

    #[test]
    fn a_duplicate_release_does_not_under_count() {
        let ledger = Ledger::new();
        let held = ledger.reserve("s", 500, 3000, 0).unwrap();
        let r = ledger.reserve("s", 800, 3000, 0).unwrap();
        assert_eq!(ledger.release(&r, 1), Settlement::Released);
        assert_eq!(ledger.release(&r, 2), Settlement::NotActive);
        // The other in-flight reservation still counts in full.
        assert_eq!(ledger.snapshot("s").reserved, 500);
        ledger.commit(&held, 3);
    }

    #[test]
    fn commit_after_release_does_not_commit() {
        let ledger = Ledger::new();
        let r = ledger.reserve("s", 800, 3000, 0).unwrap();
        ledger.release(&r, 1);
        assert_eq!(ledger.commit(&r, 2), Settlement::NotActive);
        assert_eq!(ledger.snapshot("s").total(), 0);
    }

    #[test]
    fn release_after_commit_does_not_uncommit() {
        let ledger = Ledger::new();
        let r = ledger.reserve("s", 800, 3000, 0).unwrap();
        ledger.commit(&r, 1);
        assert_eq!(ledger.release(&r, 2), Settlement::NotActive);
        assert_eq!(ledger.snapshot("s").committed, 800);
    }

    #[test]
    fn an_abandoned_reservation_is_reclaimed_after_its_ttl_without_touching_committed() {
        let ledger = Ledger::new();
        let done = ledger.reserve("s", 1000, 3000, 0).unwrap();
        ledger.commit(&done, 0);
        // The response hook for this one never runs.
        let _stranded = ledger.reserve("s", 2000, 3000, 0).unwrap();
        assert!(
            ledger.reserve("s", 1, 3000, TEST_TTL - 1).is_err(),
            "still held one millisecond before its deadline"
        );
        assert!(ledger.reserve("s", 2000, 3000, TEST_TTL).is_ok());
        assert_eq!(ledger.snapshot("s").committed, 1000, "committed kept");
        assert_eq!(ledger.stats().expired, 1);
    }

    #[test]
    fn a_late_commit_after_reclaim_charges_the_exposure_exactly_once() {
        let ledger = Ledger::new();
        let r = ledger.reserve("s", 800, 3000, 0).unwrap();
        // Another call at the deadline reclaims it.
        assert_eq!(ledger.snapshot("s").reserved, 800);
        ledger.record("s", 0, TEST_TTL);
        assert_eq!(ledger.snapshot("s").reserved, 0);
        // Then the slow upstream succeeds: the call happened, so it is charged.
        assert_eq!(ledger.commit(&r, TEST_TTL + 1), Settlement::LateCommitted);
        assert_eq!(ledger.snapshot("s").committed, 800);
        assert_eq!(ledger.commit(&r, TEST_TTL + 2), Settlement::NotActive);
        assert_eq!(ledger.snapshot("s").committed, 800);
    }

    #[test]
    fn a_late_release_after_reclaim_changes_nothing() {
        let ledger = Ledger::new();
        let r = ledger.reserve("s", 800, 3000, 0).unwrap();
        ledger.record("s", 0, TEST_TTL);
        assert_eq!(ledger.release(&r, TEST_TTL + 1), Settlement::LateReleased);
        assert_eq!(ledger.snapshot("s").total(), 0);
    }

    #[test]
    fn a_settlement_before_the_scope_is_touched_again_is_on_time() {
        // Reclamation is lazy: past the deadline but not yet reclaimed, the
        // reservation is still active and settles normally.
        let ledger = Ledger::new();
        let r = ledger.reserve("s", 800, 3000, 0).unwrap();
        assert_eq!(ledger.commit(&r, TEST_TTL + 5), Settlement::Committed);
        assert_eq!(ledger.snapshot("s").committed, 800);
    }

    #[test]
    fn a_cancelled_request_is_counted_abandoned_and_a_very_late_settlement_is_dropped() {
        let ledger = Ledger::new();
        let r = ledger.reserve("s", 800, 3000, 0).unwrap();
        ledger.record("s", 0, TEST_TTL);
        assert_eq!(ledger.stats().abandoned, 0, "tombstone still held");
        ledger.record("s", 0, 2 * TEST_TTL);
        assert_eq!(ledger.stats().abandoned, 1);
        // Past 2 × ttl the ledger no longer knows the reservation.
        assert_eq!(ledger.commit(&r, 2 * TEST_TTL + 1), Settlement::NotActive);
        assert_eq!(ledger.snapshot("s").committed, 0);
    }

    #[test]
    fn stats_distinguish_every_reservation_state() {
        let ledger = Ledger::new();
        let committed = ledger.reserve("s", 1, 100, 0).unwrap();
        let released = ledger.reserve("s", 1, 100, 0).unwrap();
        let late = ledger.reserve("s", 1, 100, 0).unwrap();
        let _abandoned = ledger.reserve("s", 1, 100, 0).unwrap();
        let _active = ledger.reserve("t", 1, 100, 0).unwrap();
        ledger.commit(&committed, 1);
        ledger.release(&released, 1);
        ledger.commit(&committed, 2);
        ledger.record("s", 0, TEST_TTL);
        ledger.commit(&late, TEST_TTL + 1);
        ledger.record("s", 0, 2 * TEST_TTL);
        assert_eq!(
            ledger.stats(),
            LedgerStats {
                active: 1,
                committed: 1,
                released: 1,
                expired: 2,
                late_committed: 1,
                late_released: 0,
                abandoned: 1,
                not_active: 1,
            }
        );
    }

    #[test]
    fn a_stranded_reservation_stops_pinning_its_scope_after_two_ttls() {
        let ledger = Ledger::with_max_scopes(1);
        let _stranded = ledger.reserve("a", 10, 100, 0).unwrap();
        assert!(matches!(
            ledger.reserve("b", 10, 100, TEST_TTL - 1),
            Err(Refusal::AtCapacity)
        ));
        // Expired, but its tombstone still waits for a late settlement.
        assert!(matches!(
            ledger.reserve("b", 10, 100, TEST_TTL),
            Err(Refusal::AtCapacity)
        ));
        assert!(ledger.reserve("b", 10, 100, 2 * TEST_TTL).is_ok());
    }

    // -----------------------------------------------------------------------
    // Accounting windows (issue #15).
    // -----------------------------------------------------------------------

    const DAY: u64 = 86_400_000;

    #[test]
    fn a_fixed_window_resets_committed_exposure_at_the_boundary() {
        let ledger = Ledger::with_window(DAY);
        let r = ledger.reserve("s", 3000, 3000, 0).unwrap();
        ledger.commit(&r, 0);
        assert!(
            ledger.reserve("s", 1, 3000, DAY - 1).is_err(),
            "same period"
        );
        let next = ledger.reserve("s", 3000, 3000, DAY).unwrap();
        ledger.commit(&next, DAY);
        assert_eq!(ledger.snapshot("s").committed, 3000);
    }

    #[test]
    fn fixed_window_periods_are_aligned_to_the_epoch_not_to_first_use() {
        // Two calls one millisecond apart straddle a boundary: the second one
        // starts a fresh period even though the scope was first seen 1 ms ago.
        let ledger = Ledger::with_window(DAY);
        let r = ledger.reserve("s", 3000, 3000, 5 * DAY - 1).unwrap();
        ledger.commit(&r, 5 * DAY - 1);
        assert!(ledger.reserve("s", 3000, 3000, 5 * DAY).is_ok());
    }

    #[test]
    fn an_in_flight_reservation_carries_across_the_boundary_and_settles_in_the_new_period() {
        let ledger = Ledger::with_window(DAY);
        let committed = ledger.reserve("s", 1000, 3000, DAY - 10).unwrap();
        ledger.commit(&committed, DAY - 10);
        let in_flight = ledger.reserve("s", 2000, 3000, DAY - 5).unwrap();
        // The new period drops the 1000 committed, but the 2000 still in flight
        // keeps counting against it.
        assert!(ledger.reserve("s", 1001, 3000, DAY).is_err());
        assert_eq!(ledger.commit(&in_flight, DAY + 1), Settlement::Committed);
        assert_eq!(ledger.snapshot("s").committed, 2000);
        assert_eq!(ledger.snapshot("s").reserved, 0);
    }

    #[test]
    fn a_clock_stepping_backwards_never_resets_a_total() {
        let ledger = Ledger::with_window(DAY);
        let r = ledger.reserve("s", 3000, 3000, 3 * DAY).unwrap();
        ledger.commit(&r, 3 * DAY);
        assert!(ledger.reserve("s", 1, 3000, 2 * DAY).is_err());
        assert_eq!(ledger.snapshot("s").committed, 3000);
    }

    #[test]
    fn without_a_window_committed_exposure_never_resets() {
        let ledger = Ledger::new();
        let r = ledger.reserve("s", 3000, 3000, 0).unwrap();
        ledger.commit(&r, 0);
        assert!(ledger.reserve("s", 1, 3000, 1000 * DAY).is_err());
        assert_eq!(ledger.snapshot("s").committed, 3000);
    }

    #[test]
    fn a_scope_from_an_earlier_period_is_idle_and_can_be_evicted() {
        let ledger = Ledger::with_limits(1, TEST_TTL, Some(DAY));
        let r = ledger.reserve("a", 10, 100, 0).unwrap();
        ledger.commit(&r, 0);
        assert!(matches!(
            ledger.reserve("b", 10, 100, DAY - 1),
            Err(Refusal::AtCapacity)
        ));
        assert!(ledger.reserve("b", 10, 100, DAY).is_ok());
        assert_eq!(ledger.scope_count(), 1);
    }
}
