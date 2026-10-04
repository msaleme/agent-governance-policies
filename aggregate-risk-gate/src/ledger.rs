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
// Two backends implement `LedgerStore`:
//
// - `Ledger` (this file, `ledgerBackend: worker`): an in-process,
//   mutex-serialized store. One exists per policy instance per gateway worker.
//   It is NOT shared across workers, so a caller spread across N workers (for
//   example by opening more connections) faces N independent budgets and can
//   spend up to N times the configured budget. The Mutex is not cross-worker
//   protection: the concurrency tests below prove atomicity between threads
//   that share one `Ledger`. The deployment answer for this backend is one
//   worker (`FLEX_SERVICE_ENVOY_CONCURRENCY=1`), or a budget of the intended
//   total divided by N; see the README.
// - `NodeLedger` (`node_ledger.rs`, `ledgerBackend: node`, the default): the
//   same scope state, held in the gateway's node-local shared data and updated
//   with compare-and-swap, so every worker of one gateway replica shares one
//   budget.
//
// Neither backend is shared across replicas, survives a process restart, or
// carries a cryptographic attestation of its decisions. Nothing here should be
// read as a claim of durability, cluster-wide sharing, or non-repudiation.

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

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

/// A reservation id: unique across every worker that shares a ledger. The
/// high 64 bits are a per-ledger prefix (random for the node backend, whose
/// reservations are settled by whichever worker sees the response), the low
/// 64 bits a counter that is never reused.
pub type ReservationId = u128;

/// One in-flight reservation's ledger record.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Held {
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
#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct ScopeState {
    /// The window period `committed` belongs to (always 0 without a window).
    period: u64,
    committed: u64,
    reserved: u64,
    active: HashMap<ReservationId, Held>,
    reclaimed: HashMap<ReservationId, Held>,
    /// Where this scope sits in the worker ledger's idle index (`None` when
    /// not indexed). Never stored by the node backend.
    #[serde(skip)]
    indexed_at: Option<u64>,
}

impl ScopeState {
    /// An idle scope has nothing committed, nothing in flight and no pending
    /// tombstone, so it holds no enforcement state: dropping it and re-creating
    /// it later at zero is indistinguishable from keeping it. Only idle scopes
    /// are ever evicted.
    pub(crate) fn is_idle(&self) -> bool {
        self.committed == 0 && self.active.is_empty() && self.reclaimed.is_empty()
    }

    pub(crate) fn total(&self) -> u64 {
        self.committed.saturating_add(self.reserved)
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            committed: self.committed,
            reserved: self.reserved,
        }
    }

    /// The earliest time at which this scope will be idle if nothing else
    /// happens to it: when its window period ends (never, without a window,
    /// if anything is committed) and when its last reservation's tombstone is
    /// dropped. `roll` then `reclaim` at any `now >= idle_at` leaves it idle.
    /// A settlement can only bring that moment forward, never push it back,
    /// except a commit, which is followed by a fresh computation.
    pub(crate) fn idle_at(&self, ttl: u64, window: Option<u64>) -> u64 {
        let mut at = 0;
        if self.committed > 0 {
            at = match window {
                Some(window) => self.period.saturating_add(1).saturating_mul(window),
                None => u64::MAX,
            };
        }
        for held in self.active.values().chain(self.reclaimed.values()) {
            at = at.max(held.expires_at.saturating_add(ttl));
        }
        at
    }

    /// Starts a new window period: committed exposure from an earlier period
    /// no longer counts. Reservations are untouched.
    pub(crate) fn roll(&mut self, period: u64) {
        if period > self.period {
            self.period = period;
            self.committed = 0;
        }
    }

    /// Moves every reservation whose deadline has passed out of `active` (its
    /// contribution leaves `reserved`; `committed` is untouched) and drops
    /// tombstones older than one further `ttl`. Returns how many reservations
    /// expired and how many tombstones were dropped unsettled.
    pub(crate) fn reclaim(&mut self, now: u64, ttl: u64) -> (u64, u64) {
        let expired: Vec<ReservationId> = self
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

    /// The budget check, without mutating anything.
    pub(crate) fn check(&self, scope: &str, contribution: u64, budget: u64) -> Result<(), Refusal> {
        let current_total = self.total();
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
        Ok(())
    }

    /// Adds a new active reservation `id` and returns it.
    pub(crate) fn hold(
        &mut self,
        id: ReservationId,
        scope: &str,
        contribution: u64,
        now: u64,
        ttl: u64,
    ) -> Reservation {
        let expires_at = now.saturating_add(ttl);
        self.reserved = self.reserved.saturating_add(contribution);
        self.active.insert(
            id,
            Held {
                contribution,
                expires_at,
            },
        );
        Reservation {
            id,
            scope: scope.to_string(),
            contribution,
            created_at: now,
            expires_at,
            total: self.total(),
        }
    }

    /// Settles reservation `id` on this state: settlement first, so a
    /// response that lands before the scope is next touched still settles
    /// normally even if its deadline has technically passed. The caller
    /// reclaims afterwards.
    pub(crate) fn settle(&mut self, id: ReservationId, commit: bool) -> Settlement {
        if let Some(held) = self.active.remove(&id) {
            self.reserved = self.reserved.saturating_sub(held.contribution);
            if commit {
                self.committed = self.committed.saturating_add(held.contribution);
                Settlement::Committed
            } else {
                Settlement::Released
            }
        } else if let Some(held) = self.reclaimed.remove(&id) {
            if commit {
                self.committed = self.committed.saturating_add(held.contribution);
                Settlement::LateCommitted
            } else {
                Settlement::LateReleased
            }
        } else {
            Settlement::NotActive
        }
    }

    pub(crate) fn record(&mut self, contribution: u64) {
        self.committed = self.committed.saturating_add(contribution);
    }
}

/// A held reservation against a scope, returned by a successful `reserve` or
/// `force_reserve`. Settle it with `commit` or `release`. Both are idempotent:
/// only the first settlement of an `id` changes the ledger. If neither is
/// called by `expires_at`, the next ledger operation on the scope reclaims it.
#[derive(Clone, Debug, PartialEq)]
pub struct Reservation {
    pub id: ReservationId,
    pub scope: String,
    pub contribution: u64,
    pub created_at: u64,
    pub expires_at: u64,
    /// The scope's committed-plus-reserved total right after this
    /// reservation was made, for the result header.
    pub total: u64,
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
    /// Node backend only: the shared store could not apply the settlement
    /// now (persistent contention or a storage error). Both directions stay
    /// safe: a deferred commit is queued on this worker and retried on its
    /// next ledger calls, and a deferred release leaves the reservation held
    /// until it is reclaimed, an over-count that frees itself after the
    /// timeout.
    Deferred,
}

impl Settlement {
    pub fn label(self) -> &'static str {
        match self {
            Settlement::Committed => "committed",
            Settlement::Released => "released",
            Settlement::LateCommitted => "late-committed",
            Settlement::LateReleased => "late-released",
            Settlement::NotActive => "not-active",
            Settlement::Deferred => "deferred",
        }
    }
}

/// Ledger-wide reservation counters for operator telemetry. Each counter only
/// ever increases except `active`, which is the current number in flight. The
/// node backend keeps these per worker: they count the operations this worker
/// performed on the shared ledger.
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
    /// Node backend: settlements that could not be applied at once.
    pub deferred: u64,
    /// Node backend: calls refused (block) or flagged (monitor) because the
    /// shared ledger stayed contended or failed.
    pub contended: u64,
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

/// A point-in-time view of one scope's ledger state, for tests. Not itself
/// part of the decision engine.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Snapshot {
    pub committed: u64,
    pub reserved: u64,
}

/// Why a ledger operation refused a call.
#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    /// Admitting the contribution would push the scope over its budget.
    OverBudget(Denial),
    /// `scope` is new and the ledger already tracks `max_scopes` scopes, none
    /// of them idle. The call is refused rather than evicting live state.
    AtCapacity,
    /// Node backend: every compare-and-swap attempt lost to a concurrent
    /// writer. Nothing was reserved.
    Contention,
    /// Node backend: the shared store returned an error or a record it could
    /// not read. Nothing was reserved.
    Unavailable,
}

#[cfg(test)]
impl Refusal {
    /// The budget denial inside an `OverBudget` refusal; panics otherwise.
    pub fn over_budget(self) -> Denial {
        match self {
            Refusal::OverBudget(denial) => denial,
            _ => panic!("expected OverBudget"),
        }
    }
}

#[cfg(test)]
impl Snapshot {
    pub fn total(&self) -> u64 {
        self.committed.saturating_add(self.reserved)
    }
}

/// The behavior every backend provides. `lib.rs` (the PDK-aware filter) calls
/// the ledger only through this trait, so the worker and node backends share
/// the filter's decision logic unchanged.
///
/// Every method first reclaims the scope's expired reservations, as part of
/// the same atomic step as the operation itself.
pub trait LedgerStore {
    /// Atomically checks `scope`'s committed-plus-reserved exposure against
    /// `budget` and, only if `contribution` fits, reserves it until
    /// `now + ttl`. On any refusal, no reservation is made for `scope`. A new
    /// scope that does not fit under the ledger's scope cap is refused with
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
    /// NOT implemented by delegating to this method plus a second read,
    /// which would reopen the exact read-then-write race window this
    /// module's whole correctness story is about) — hence `#[allow(dead_code)]`
    /// rather than deleting a real, tested API.
    ///
    /// Refused only for `AtCapacity`, `Contention` or `Unavailable`.
    #[allow(dead_code)]
    fn force_reserve(
        &self,
        scope: &str,
        contribution: u64,
        now: u64,
    ) -> Result<Reservation, Refusal>;

    /// `force_reserve`, plus a breach signal: reserves `contribution`
    /// against `scope` unconditionally (never denies for budget — monitor
    /// mode still forwards every call), but also reports whether doing so
    /// pushed committed-plus-reserved exposure over `budget`. This is what
    /// lets monitor mode raise the same policy-violation signal a block-mode
    /// denial would, without actually denying the call.
    fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: u64,
        budget: u64,
        now: u64,
    ) -> Result<(Reservation, bool), Refusal>;

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
    /// direct audit correction). Refused only for `AtCapacity`, `Contention`
    /// or `Unavailable`, in which case nothing is recorded.
    fn record(&self, scope: &str, contribution: u64, now: u64) -> Result<(), Refusal>;

    /// A read-only view of one scope's current state, for tests.
    /// Never creates an entry, reclaims, or starts a new window period: it
    /// shows the scope as of its last touch. An untracked scope reads as zero.
    #[cfg(test)]
    fn snapshot(&self, scope: &str) -> Snapshot;

    /// The ledger-wide reservation counters.
    fn stats(&self) -> LedgerStats;

    /// How many scopes the ledger currently tracks.
    #[cfg(test)]
    fn scope_count(&self) -> usize;
}

struct Inner {
    scopes: HashMap<String, ScopeState>,
    /// Every tracked scope, ordered by `ScopeState::idle_at`, so the scope
    /// that becomes idle first is always the first entry (P4A review #49).
    idle_index: BTreeSet<(u64, String)>,
    next_id: ReservationId,
    stats: LedgerStats,
    /// How many scope states the capacity path has examined.
    #[cfg(test)]
    examined: u64,
}

impl Inner {
    /// Moves `scope`'s idle-index entry to its current `idle_at`.
    fn reindex(&mut self, scope: &str, ttl: u64, window: Option<u64>) {
        let Some(state) = self.scopes.get_mut(scope) else {
            return;
        };
        let at = state.idle_at(ttl, window);
        if state.indexed_at == Some(at) {
            return;
        }
        if let Some(old) = state.indexed_at.replace(at) {
            self.idle_index.remove(&(old, scope.to_string()));
        }
        self.idle_index.insert((at, scope.to_string()));
    }

    /// Makes room for one new scope by evicting the scope that becomes idle
    /// first, if it is idle by `now`. Examines at most one scope state, so a
    /// refusal at the cap costs one ordered-set lookup, never a scan.
    fn evict_one(&mut self, now: u64, period: u64, ttl: u64, window: Option<u64>) -> bool {
        let Some((at, key)) = self.idle_index.first() else {
            return false;
        };
        if *at > now {
            return false;
        }
        let entry = (*at, key.clone());
        #[cfg(test)]
        {
            self.examined += 1;
        }
        let idle = match self.scopes.get_mut(&entry.1) {
            Some(state) => {
                state.roll(period);
                count_reclaim(&mut self.stats, state.reclaim(now, ttl));
                state.is_idle()
            }
            None => true,
        };
        if idle {
            self.scopes.remove(&entry.1);
            self.idle_index.remove(&entry);
        } else {
            // Unreachable while the index is exact; refuse rather than scan.
            self.reindex(&entry.1, ttl, window);
        }
        idle
    }
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
/// the scope that becomes idle first (see `ScopeState::is_idle` and
/// `idle_at`) is evicted if it is idle now; otherwise the new scope is
/// refused. Live enforcement state is never evicted, so the cap can never be
/// used to reset another scope's running total, and a refusal at the cap costs
/// O(log n), not a scan of every scope.
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
                idle_index: BTreeSet::new(),
                next_id: 1,
                stats: LedgerStats::default(),
                #[cfg(test)]
                examined: 0,
            }),
            max_scopes,
            ttl,
            window,
        }
    }

    fn period(&self, now: u64) -> u64 {
        period(self.window, now)
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
    /// its expired reservations. Returns `AtCapacity`, without running `f`,
    /// if `scope` is new and there is no room for it. The capacity check, any
    /// reclamation or eviction, and `f` all happen under one lock.
    fn with_state<R>(
        &self,
        scope: &str,
        now: u64,
        f: impl FnOnce(&mut ScopeState, &mut ReservationId, &mut LedgerStats) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let period = self.period(now);
        if !inner.scopes.contains_key(scope)
            && inner.scopes.len() >= self.max_scopes
            && !inner.evict_one(now, period, self.ttl, self.window)
        {
            return Err(Refusal::AtCapacity);
        }
        let state = inner.scopes.entry(scope.to_string()).or_default();
        state.roll(period);
        count_reclaim(&mut inner.stats, state.reclaim(now, self.ttl));
        let result = f(state, &mut inner.next_id, &mut inner.stats);
        inner.reindex(scope, self.ttl, self.window);
        result
    }

    /// Adds a new active reservation to `state`.
    fn hold(
        &self,
        state: &mut ScopeState,
        next_id: &mut ReservationId,
        stats: &mut LedgerStats,
        scope: &str,
        contribution: u64,
        now: u64,
    ) -> Reservation {
        let id = *next_id;
        *next_id += 1;
        stats.active += 1;
        state.hold(id, scope, contribution, now, self.ttl)
    }

    /// Settles `reservation` on its EXISTING scope. An untracked scope
    /// (never created, or evicted while idle) settles as `NotActive`.
    fn settle(&self, reservation: &Reservation, now: u64, commit: bool) -> Settlement {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let outcome = match inner.scopes.get_mut(&reservation.scope) {
            None => Settlement::NotActive,
            Some(state) => {
                // A commit lands in the current window period.
                state.roll(self.period(now));
                let outcome = state.settle(reservation.id, commit);
                count_reclaim(&mut inner.stats, state.reclaim(now, self.ttl));
                outcome
            }
        };
        inner.reindex(&reservation.scope, self.ttl, self.window);
        count_settlement(&mut inner.stats, outcome);
        outcome
    }

    /// How many scope states the capacity path has examined so far.
    #[cfg(test)]
    pub fn examined(&self) -> u64 {
        self.lock().examined
    }
}

/// The window period `now` falls in (always 0 without a window).
pub(crate) fn period(window: Option<u64>, now: u64) -> u64 {
    window.map_or(0, |window| now / window)
}

pub(crate) fn count_reclaim(stats: &mut LedgerStats, (expired, abandoned): (u64, u64)) {
    stats.active = stats.active.saturating_sub(expired);
    stats.expired += expired;
    stats.abandoned += abandoned;
}

pub(crate) fn count_settlement(stats: &mut LedgerStats, outcome: Settlement) {
    match outcome {
        Settlement::Committed => {
            stats.active = stats.active.saturating_sub(1);
            stats.committed += 1
        }
        Settlement::Released => {
            stats.active = stats.active.saturating_sub(1);
            stats.released += 1
        }
        Settlement::LateCommitted => stats.late_committed += 1,
        Settlement::LateReleased => stats.late_released += 1,
        Settlement::NotActive => stats.not_active += 1,
        Settlement::Deferred => stats.deferred += 1,
    }
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
            state.check(scope, contribution, budget)?;
            Ok(self.hold(state, next_id, stats, scope, contribution, now))
        })
    }

    fn force_reserve(
        &self,
        scope: &str,
        contribution: u64,
        now: u64,
    ) -> Result<Reservation, Refusal> {
        self.with_state(scope, now, |state, next_id, stats| {
            Ok(self.hold(state, next_id, stats, scope, contribution, now))
        })
    }

    fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: u64,
        budget: u64,
        now: u64,
    ) -> Result<(Reservation, bool), Refusal> {
        self.with_state(scope, now, |state, next_id, stats| {
            let reservation = self.hold(state, next_id, stats, scope, contribution, now);
            let breached = reservation.total > budget;
            Ok((reservation, breached))
        })
    }

    fn commit(&self, reservation: &Reservation, now: u64) -> Settlement {
        self.settle(reservation, now, true)
    }

    fn release(&self, reservation: &Reservation, now: u64) -> Settlement {
        self.settle(reservation, now, false)
    }

    fn record(&self, scope: &str, contribution: u64, now: u64) -> Result<(), Refusal> {
        self.with_state(scope, now, |state, _, _| {
            state.record(contribution);
            Ok(())
        })
    }

    #[cfg(test)]
    fn snapshot(&self, scope: &str) -> Snapshot {
        self.lock()
            .scopes
            .get(scope)
            .map(ScopeState::snapshot)
            .unwrap_or(Snapshot {
                committed: 0,
                reserved: 0,
            })
    }

    fn stats(&self) -> LedgerStats {
        self.lock().stats
    }

    #[cfg(test)]
    fn scope_count(&self) -> usize {
        self.lock().scopes.len()
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
        ledger.record("s", 10_000, 0).unwrap();
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
        ledger.record("s", u64::MAX - 1, 0).unwrap();
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
        ledger.record("s", u64::MAX, 0).unwrap();
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
    fn a_refusal_at_capacity_examines_at_most_one_scope_however_many_are_live() {
        // P4A review #49 A: 100k live (non-idle) scopes, then 1000 new
        // identities. Each refusal must cost an index lookup, not a scan.
        const LIVE: usize = 100_000;
        let ledger = Ledger::with_max_scopes(LIVE);
        for i in 0..LIVE {
            let r = ledger.reserve(&format!("live-{i}"), 1, 10, 0).unwrap();
            ledger.commit(&r, 0);
        }
        assert_eq!(ledger.examined(), 0, "filling the ledger never evicts");
        for i in 0..1000 {
            assert_eq!(
                ledger.reserve(&format!("new-{i}"), 1, 10, 1).unwrap_err(),
                Refusal::AtCapacity
            );
        }
        // Committed exposure without a window never goes idle, so the index
        // head is never even due: no scope state is examined at all.
        assert_eq!(ledger.examined(), 0);
        assert_eq!(ledger.scope_count(), LIVE);

        // With a window, the head is due once the period ends; it is
        // examined once and evicted, and the next refusal is again O(1).
        let windowed = Ledger::with_limits(2, TEST_TTL, Some(DAY));
        for scope in ["a", "b"] {
            let r = windowed.reserve(scope, 1, 10, 0).unwrap();
            windowed.commit(&r, 0);
        }
        let _live = windowed.reserve("c", 1, 10, DAY).unwrap();
        assert_eq!(windowed.examined(), 1, "one stale scope evicted for c");
        assert!(windowed.reserve("d", 1, 10, DAY).is_ok());
        assert_eq!(windowed.examined(), 2, "the other stale scope for d");
        assert_eq!(
            windowed.reserve("e", 1, 10, DAY).unwrap_err(),
            Refusal::AtCapacity
        );
        assert_eq!(windowed.examined(), 2, "nothing due: refused unexamined");
    }

    #[test]
    fn the_idle_index_follows_every_settlement() {
        let ledger = Ledger::with_max_scopes(1);
        let r = ledger.reserve("a", 5, 100, 0).unwrap();
        // In flight until 2 * TTL at the latest.
        assert_eq!(
            ledger.reserve("b", 1, 100, 1).unwrap_err(),
            Refusal::AtCapacity
        );
        // Released at once: idle now, so the next new scope may take its slot.
        ledger.release(&r, 2);
        assert!(ledger.reserve("b", 1, 100, 3).is_ok());
        assert_eq!(ledger.snapshot("a").total(), 0);
        assert_eq!(ledger.scope_count(), 1);
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
        assert_eq!(
            ledger.force_reserve_checked("c", 10, 100, 0),
            Err(Refusal::AtCapacity)
        );
        assert_eq!(ledger.record("c", 10, 0), Err(Refusal::AtCapacity));
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
    fn forged(scope: &str, id: ReservationId, contribution: u64) -> Reservation {
        Reservation {
            id,
            scope: scope.to_string(),
            contribution,
            created_at: 0,
            expires_at: TEST_TTL,
            total: contribution,
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
        ledger.record("s", 0, TEST_TTL).unwrap();
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
        ledger.record("s", 0, TEST_TTL).unwrap();
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
        ledger.record("s", 0, TEST_TTL).unwrap();
        assert_eq!(ledger.stats().abandoned, 0, "tombstone still held");
        ledger.record("s", 0, 2 * TEST_TTL).unwrap();
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
        ledger.record("s", 0, TEST_TTL).unwrap();
        ledger.commit(&late, TEST_TTL + 1);
        ledger.record("s", 0, 2 * TEST_TTL).unwrap();
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
                ..LedgerStats::default()
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
