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
// Stage A / Stage B honesty boundary: this is the Stage A ledger — a single,
// in-process, mutex-serialized store. It is a real, correct reserve-then-authorize
// engine (proven below, including under genuine multi-thread contention), not a
// simulation of one. It is NOT a distributed, multi-region, or replay-consistent
// ledger, and it carries no cryptographic attestation of its decisions — that is
// Stage B, unshipped roadmap work. Every scope here lives only as long as the
// process that holds it; nothing here should be read as a claim of durability,
// multi-worker sharing, or non-repudiation.

// Units: every amount here is an exact, non-negative integer (`u64`) in the
// policy's configured unit (fixed-weight points, estimated tokens, or a
// currency's minor unit). There is no floating point anywhere in the decision
// path. `lib.rs` bounds every budget and contribution to `MAX_UNITS` (2^53 - 1)
// before it reaches this module; additions here saturate at `u64::MAX`, far
// above any admissible budget, so a sum that would overflow always compares as
// over budget instead of wrapping around.

use std::collections::HashMap;
use std::sync::Mutex;

/// One scope's running exposure: `committed` is exposure from calls that already
/// happened (successfully, or force-recorded in monitor mode); `reserved` is
/// exposure that has been set aside for an in-flight call whose outcome is not
/// yet known. Budget checks compare against `committed + reserved`, so a reserved
/// amount blocks a concurrent composing call exactly as if it had already landed
/// — that is the whole mechanism.
#[derive(Default, Clone, Copy, Debug, PartialEq)]
struct ScopeState {
    committed: u64,
    reserved: u64,
}

impl ScopeState {
    /// An idle scope has nothing committed and nothing in flight, so it holds
    /// no enforcement state: dropping it and re-creating it later at zero is
    /// indistinguishable from keeping it. Only idle scopes are ever evicted.
    fn is_idle(&self) -> bool {
        self.committed == 0 && self.reserved == 0
    }
}

impl ScopeState {
    fn total(&self) -> u64 {
        self.committed.saturating_add(self.reserved)
    }
}

/// A held reservation against a scope, returned by a successful `reserve` or
/// `force_reserve`. Must be resolved with exactly one of `commit` or `release`
/// — holding it longer than necessary keeps `reserved` inflated and
/// makes the scope look more exposed than it is.
#[derive(Clone, Debug, PartialEq)]
pub struct Reservation {
    pub scope: String,
    pub contribution: u64,
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
/// depends only on this trait, never on `Ledger` directly, so a Stage B
/// distributed backend could later implement the same trait without touching the
/// filter logic — an explicit seam for the roadmap work called out in the module
/// doc comment, not a claim that such a backend exists today.
pub trait LedgerStore {
    /// Atomically checks `scope`'s committed-plus-reserved exposure against
    /// `budget` and, only if `contribution` fits, reserves it. On denial, the
    /// ledger is left completely unmutated for `scope`. A new scope that does
    /// not fit under the ledger's scope cap is refused with `AtCapacity`.
    fn reserve(&self, scope: &str, contribution: u64, budget: u64) -> Result<Reservation, Refusal>;

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
    fn force_reserve(&self, scope: &str, contribution: u64) -> Option<Reservation>;

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
    ) -> Option<(Reservation, bool)>;

    /// Resolves a reservation as successful: moves its contribution from
    /// `reserved` into `committed`.
    fn commit(&self, reservation: Reservation);

    /// Resolves a reservation as not-consumed: removes its contribution from
    /// `reserved` without ever adding it to `committed`. Used when the upstream
    /// call failed, so a failed call does not count against the budget.
    fn release(&self, reservation: Reservation);

    /// Records `contribution` directly into `committed`, bypassing both the
    /// budget check and the reserve/commit two-step. Used for a call whose
    /// exposure is known only after it already happened and so can no longer be
    /// denied (e.g. monitor mode's unpriceable-at-request-time cases, or a
    /// direct audit correction). Returns `false`, recording nothing, only when
    /// `scope` is new and the ledger is at its scope cap.
    fn record(&self, scope: &str, contribution: u64) -> bool;

    /// A read-only view of one scope's current state, for diagnostics/tests.
    /// Never creates an entry: an untracked scope reads as zero.
    fn snapshot(&self, scope: &str) -> Snapshot;
}

/// The Stage A ledger: an in-process, mutex-serialized `HashMap` of scope states.
/// `std::sync::Mutex` (rather than `RefCell`) is a deliberate choice beyond what
/// the PDK's single-threaded async runtime strictly requires — it lets the unit
/// tests below exercise `reserve` under genuine OS-thread contention, not just
/// simulated/interleaved async calls, which is the strongest evidence available
/// short of a real distributed backend that reserve-then-authorize actually holds
/// the budget under a race.
///
/// Cardinality is bounded by `max_scopes`. When a NEW scope arrives at the cap,
/// one idle scope (see `ScopeState::is_idle`) is evicted to make room; if every
/// tracked scope holds committed or reserved exposure, the new scope is refused
/// instead. Live enforcement state is never evicted, so the cap can never be
/// used to reset another scope's running total.
pub struct Ledger {
    scopes: Mutex<HashMap<String, ScopeState>>,
    max_scopes: usize,
}

impl Ledger {
    /// An unbounded ledger, for tests of the budget arithmetic itself.
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_max_scopes(usize::MAX)
    }

    pub fn with_max_scopes(max_scopes: usize) -> Self {
        Ledger {
            scopes: Mutex::new(HashMap::new()),
            max_scopes,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ScopeState>> {
        // A poisoned mutex (a prior panic while the lock was held) still holds
        // valid, if possibly inconsistent, ledger data. Recovering it rather than
        // panicking again keeps this store fail-open at the Rust-panic level
        // while the filter above it stays fail-closed at the policy-decision
        // level (a denial is a normal, safe `Err`, never a panic).
        self.scopes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Runs `f` on `scope`'s state, creating it if needed. Returns `None`,
    /// without running `f`, if `scope` is new and there is no room for it.
    /// The capacity check, any eviction, and `f` all happen under one lock.
    fn with_state<R>(&self, scope: &str, f: impl FnOnce(&mut ScopeState) -> R) -> Option<R> {
        let mut guard = self.lock();
        if !guard.contains_key(scope) && guard.len() >= self.max_scopes {
            let idle = guard
                .iter()
                .find(|(_, state)| state.is_idle())
                .map(|(key, _)| key.clone());
            match idle {
                Some(key) => {
                    guard.remove(&key);
                }
                None => return None,
            }
        }
        Some(f(guard.entry(scope.to_string()).or_default()))
    }

    /// Runs `f` on an EXISTING scope's state; a no-op if it is untracked.
    fn with_existing(&self, scope: &str, f: impl FnOnce(&mut ScopeState)) {
        if let Some(state) = self.lock().get_mut(scope) {
            f(state);
        }
    }

    /// How many scopes the ledger currently tracks.
    #[cfg(test)]
    pub fn scope_count(&self) -> usize {
        self.lock().len()
    }
}

impl LedgerStore for Ledger {
    fn reserve(&self, scope: &str, contribution: u64, budget: u64) -> Result<Reservation, Refusal> {
        self.with_state(scope, |state| {
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
            state.reserved = state.reserved.saturating_add(contribution);
            Ok(Reservation {
                scope: scope.to_string(),
                contribution,
            })
        })
        .unwrap_or(Err(Refusal::AtCapacity))
    }

    fn force_reserve(&self, scope: &str, contribution: u64) -> Option<Reservation> {
        self.with_state(scope, |state| {
            state.reserved = state.reserved.saturating_add(contribution);
            Reservation {
                scope: scope.to_string(),
                contribution,
            }
        })
    }

    fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: u64,
        budget: u64,
    ) -> Option<(Reservation, bool)> {
        self.with_state(scope, |state| {
            state.reserved = state.reserved.saturating_add(contribution);
            let breached = state.total() > budget;
            (
                Reservation {
                    scope: scope.to_string(),
                    contribution,
                },
                breached,
            )
        })
    }

    // A reservation's scope always exists: it holds `reserved > 0` (or was
    // created by the reserve that issued it), so it is never idle and never
    // evicted while the reservation is outstanding.
    fn commit(&self, reservation: Reservation) {
        self.with_existing(&reservation.scope, |state| {
            state.reserved = state.reserved.saturating_sub(reservation.contribution);
            state.committed = state.committed.saturating_add(reservation.contribution);
        });
    }

    fn release(&self, reservation: Reservation) {
        self.with_existing(&reservation.scope, |state| {
            state.reserved = state.reserved.saturating_sub(reservation.contribution);
        });
    }

    fn record(&self, scope: &str, contribution: u64) -> bool {
        self.with_state(scope, |state| {
            state.committed = state.committed.saturating_add(contribution);
        })
        .is_some()
    }

    fn snapshot(&self, scope: &str) -> Snapshot {
        self.lock()
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
                .reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET)
                .expect("first three sessions must be admitted");
            ledger.commit(reservation);
        }
        assert_eq!(ledger.snapshot(scope).total(), 2400);

        // Session 4: locally valid (800 <= a 1000 per-session cap enforced above
        // this ledger), but 2400 + 800 = 3200 > 3000 — refused.
        let denial = ledger
            .reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET)
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
            let reservation = ledger.reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET).unwrap();
            ledger.commit(reservation);
        }
        // Two more attempts at 800 each: both refused, neither changes the total.
        for _ in 0..2 {
            assert!(ledger.reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET).is_err());
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
                            .reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET)
                            .map(|reservation| {
                                ledger.commit(reservation);
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
                    ledger.reserve(scope, per_call, budget).map(|reservation| {
                        ledger.commit(reservation);
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
        let reservation = ledger.reserve("s", 100, 1000).unwrap();
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0,
                reserved: 100
            }
        );
        ledger.commit(reservation);
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
        let reservation = ledger.reserve("s", 100, 1000).unwrap();
        ledger.release(reservation);
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
        let first = ledger.reserve("s", 900, 1000).unwrap();
        assert!(
            ledger.reserve("s", 200, 1000).is_err(),
            "900 reserved leaves no room for 200"
        );
        ledger.release(first);
        assert!(
            ledger.reserve("s", 200, 1000).is_ok(),
            "releasing the first reservation must free its budget"
        );
    }

    #[test]
    fn record_bypasses_the_budget_check_entirely() {
        let ledger = Ledger::new();
        // record() has no budget parameter: it cannot be denied by construction.
        ledger.record("s", 10_000);
        assert_eq!(ledger.snapshot("s").committed, 10_000);
    }

    #[test]
    fn force_reserve_always_succeeds_even_over_a_notional_budget() {
        let ledger = Ledger::new();
        let reservation = ledger.force_reserve("s", 10_000).unwrap();
        assert_eq!(ledger.snapshot("s").reserved, 10_000);
        ledger.commit(reservation);
        assert_eq!(ledger.snapshot("s").committed, 10_000);
    }

    #[test]
    fn force_reserve_checked_reports_no_breach_when_within_budget() {
        let ledger = Ledger::new();
        let (reservation, breached) = ledger.force_reserve_checked("s", 500, 1000).unwrap();
        assert!(!breached);
        assert_eq!(ledger.snapshot("s").reserved, 500);
        ledger.commit(reservation);
    }

    #[test]
    fn force_reserve_checked_reports_breach_when_over_budget_but_still_reserves() {
        let ledger = Ledger::new();
        // Never denies (monitor-mode primitive), but must still truthfully
        // report that this reservation pushed the scope over budget.
        let (reservation, breached) = ledger.force_reserve_checked("s", 1500, 1000).unwrap();
        assert!(breached);
        assert_eq!(
            ledger.snapshot("s").reserved,
            1500,
            "force_reserve_checked must still reserve the full amount despite the breach"
        );
        ledger.commit(reservation);
        assert_eq!(ledger.snapshot("s").committed, 1500);
    }

    #[test]
    fn force_reserve_checked_breach_reflects_prior_committed_exposure_too() {
        let ledger = Ledger::new();
        let first = ledger.force_reserve_checked("s", 800, 1000).unwrap();
        assert!(!first.1);
        ledger.commit(first.0);
        // 800 committed + 300 more reserved = 1100 > 1000: a breach, even
        // though this second call's OWN amount is well within budget alone.
        let (reservation, breached) = ledger.force_reserve_checked("s", 300, 1000).unwrap();
        assert!(breached);
        ledger.commit(reservation);
    }

    #[test]
    fn force_reserve_still_supports_release_on_upstream_failure() {
        // Monitor mode's mechanics must stay symmetric: a call that never
        // actually landed upstream should not count against the running total,
        // even though force_reserve never denies up front.
        let ledger = Ledger::new();
        let reservation = ledger.force_reserve("s", 500).unwrap();
        ledger.release(reservation);
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
        let a = ledger.reserve("agent:a", 900, 1000).unwrap();
        ledger.commit(a);
        // A different scope key starts fresh even though it shares a budget.
        assert!(ledger.reserve("agent:b", 900, 1000).is_ok());
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
        let agent_res = ledger.reserve("agent:x", 900, 1000).unwrap();
        ledger.commit(agent_res);
        assert!(
            ledger.reserve("tenant:x", 900, 1000).is_ok(),
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
            ledger.reserve("s", 1000, 1000).is_ok(),
            "exactly-at-budget must be admitted"
        );
    }

    #[test]
    fn a_call_one_unit_over_budget_is_denied() {
        let ledger = Ledger::new();
        let denial = ledger.reserve("s", 1001, 1000).unwrap_err().over_budget();
        assert_eq!(denial.would_be_total, 1001);
    }

    #[test]
    fn a_zero_contribution_call_is_always_admitted_even_at_zero_budget() {
        let ledger = Ledger::new();
        assert!(ledger.reserve("s", 0, 0).is_ok());
    }

    #[test]
    fn a_zero_budget_denies_any_positive_contribution() {
        let ledger = Ledger::new();
        assert!(ledger.reserve("s", 1, 0).is_err());
    }

    #[test]
    fn committed_exposure_from_a_prior_call_counts_against_a_new_reservation() {
        let ledger = Ledger::new();
        let reservation = ledger.reserve("s", 1000, 1000).unwrap();
        ledger.commit(reservation);
        // The scope is now fully committed; even a zero-sized new call is fine,
        // but anything positive must be denied.
        assert!(ledger.reserve("s", 0, 1000).is_ok());
        assert!(ledger.reserve("s", 1, 1000).is_err());
    }

    #[test]
    fn an_in_flight_reservation_counts_against_a_concurrent_reservation_attempt() {
        // The core of reserve-then-authorize: a RESERVED (not yet committed)
        // amount must block a composing call exactly as if it had landed.
        let ledger = Ledger::new();
        let first = ledger.reserve("s", 600, 1000).unwrap();
        assert!(
            ledger.reserve("s", 500, 1000).is_err(),
            "an in-flight reservation must count against the budget check"
        );
        ledger.release(first);
        assert!(ledger.reserve("s", 500, 1000).is_ok());
    }

    #[test]
    fn release_never_drives_reserved_negative() {
        // Releasing a reservation that (by programmer error) does not match what
        // is actually held must not underflow the tracked state into a negative
        // "reserved" that would let future calls smuggle extra budget through.
        let ledger = Ledger::new();
        ledger.release(Reservation {
            scope: "s".to_string(),
            contribution: 500,
        });
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
        let reservation = ledger.reserve("agent:z", 700, 1000).unwrap();
        ledger.commit(reservation);
        let denial = ledger
            .reserve("agent:z", 400, 1000)
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
            let reservation = ledger.reserve("s", 1, 10).expect("within budget");
            ledger.commit(reservation);
        }
        assert_eq!(ledger.snapshot("s").total(), 10);
        assert!(ledger.reserve("s", 1, 10).is_err());

        let ledger = Ledger::new();
        ledger.commit(ledger.reserve("s", 10, 30).unwrap());
        ledger.commit(ledger.reserve("s", 20, 30).unwrap());
        assert_eq!(ledger.snapshot("s").total(), 30, "10 + 20 is exactly 30");
    }

    #[test]
    fn an_overflowing_sum_is_denied_rather_than_wrapping() {
        let ledger = Ledger::new();
        ledger.record("s", u64::MAX - 1);
        let denial = ledger
            .reserve("s", 10, u64::MAX - 1)
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
        ledger.record("s", u64::MAX);
        let (reservation, breached) = ledger.force_reserve_checked("s", 5, 1000).unwrap();
        assert!(breached);
        assert_eq!(ledger.snapshot("s").total(), u64::MAX);
        ledger.release(reservation);
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
        let a = ledger.reserve("a", 10, 100).unwrap();
        ledger.commit(a);
        let _in_flight = ledger.reserve("b", 10, 100).unwrap();
        assert!(matches!(
            ledger.reserve("c", 10, 100),
            Err(Refusal::AtCapacity)
        ));
        assert!(ledger.force_reserve_checked("c", 10, 100).is_none());
        assert!(!ledger.record("c", 10));
        assert_eq!(ledger.scope_count(), 2);
        // Neither live scope lost its state to make room.
        assert_eq!(ledger.snapshot("a").committed, 10);
        assert_eq!(ledger.snapshot("b").reserved, 10);
    }

    #[test]
    fn a_full_ledger_evicts_only_an_idle_scope() {
        let ledger = Ledger::with_max_scopes(2);
        let a = ledger.reserve("a", 10, 100).unwrap();
        ledger.commit(a);
        // "b" reserved then released: zero committed, zero reserved — idle.
        let b = ledger.reserve("b", 10, 100).unwrap();
        ledger.release(b);
        assert!(ledger.reserve("c", 10, 100).is_ok());
        assert_eq!(ledger.scope_count(), 2);
        assert_eq!(ledger.snapshot("a").committed, 10, "live scope kept");
        assert_eq!(ledger.snapshot("b").total(), 0);
    }

    #[test]
    fn an_already_tracked_scope_is_never_refused_for_capacity() {
        let ledger = Ledger::with_max_scopes(1);
        let first = ledger.reserve("a", 10, 100).unwrap();
        ledger.commit(first);
        assert!(ledger.reserve("a", 10, 100).is_ok());
    }

    #[test]
    fn commit_and_release_on_an_untracked_scope_do_not_create_it() {
        let ledger = Ledger::with_max_scopes(1);
        ledger.commit(Reservation {
            scope: "ghost".to_string(),
            contribution: 5,
        });
        ledger.release(Reservation {
            scope: "ghost".to_string(),
            contribution: 5,
        });
        assert_eq!(ledger.scope_count(), 0);
    }
}
