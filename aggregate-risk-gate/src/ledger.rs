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
    committed: f64,
    reserved: f64,
}

impl ScopeState {
    fn total(&self) -> f64 {
        self.committed + self.reserved
    }
}

/// A held reservation against a scope, returned by a successful `reserve` or
/// `force_reserve`. Must be resolved with exactly one of `commit`, `release`, or
/// `reconcile` — holding it longer than necessary keeps `reserved` inflated and
/// makes the scope look more exposed than it is.
#[derive(Clone, Debug, PartialEq)]
pub struct Reservation {
    pub scope: String,
    pub contribution: f64,
}

/// A denied reservation attempt: the call was NOT reserved and NOT mutated into
/// the ledger. There is nothing to release for a `Denial` — that is the point of
/// checking before mutating.
#[derive(Clone, Debug, PartialEq)]
pub struct Denial {
    pub scope: String,
    pub contribution: f64,
    /// `committed + reserved` for this scope at the moment of the check, before
    /// this call's own contribution.
    pub current_total: f64,
    /// What the total would have become had this call been admitted.
    pub would_be_total: f64,
    pub budget: f64,
}

/// A point-in-time view of one scope's ledger state, for tests and for stamping
/// diagnostic headers. Not itself part of the decision engine.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Snapshot {
    pub committed: f64,
    pub reserved: f64,
}

impl Snapshot {
    pub fn total(&self) -> f64 {
        self.committed + self.reserved
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
    /// ledger is left completely unmutated for `scope`.
    fn reserve(&self, scope: &str, contribution: f64, budget: f64) -> Result<Reservation, Denial>;

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
    #[allow(dead_code)]
    fn force_reserve(&self, scope: &str, contribution: f64) -> Reservation;

    /// `force_reserve`, plus a breach signal: reserves `contribution`
    /// against `scope` unconditionally (never denies — monitor mode still
    /// forwards every call), but also reports whether doing so pushed
    /// committed-plus-reserved exposure over `budget`. This is what lets
    /// monitor mode raise the same policy-violation signal a block-mode
    /// denial would, without actually denying the call.
    fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: f64,
        budget: f64,
    ) -> (Reservation, bool);

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
    /// direct audit correction).
    fn record(&self, scope: &str, contribution: f64);

    /// Resolves an ESTIMATED reservation once its final amount is known:
    /// releases the estimate from `reserved`, then commits
    /// `actual_contribution` in its place — never re-checking the budget,
    /// because the call already happened and its exposure cannot be
    /// retroactively denied. A general estimate-then-settle primitive: this
    /// build's token-cost contribution mode calls it with
    /// `actual_contribution` equal to the original estimate itself (it never
    /// learns a different real figure — see `response_filter` in `lib.rs`),
    /// but the primitive is written generally enough to also serve a true
    /// reconcile-to-a-different-value, for a caller that has one.
    fn reconcile(&self, reservation: Reservation, actual_contribution: f64);

    /// A read-only view of one scope's current state, for diagnostics/tests.
    fn snapshot(&self, scope: &str) -> Snapshot;
}

/// The Stage A ledger: an in-process, mutex-serialized `HashMap` of scope states.
/// `std::sync::Mutex` (rather than `RefCell`) is a deliberate choice beyond what
/// the PDK's single-threaded async runtime strictly requires — it lets the unit
/// tests below exercise `reserve` under genuine OS-thread contention, not just
/// simulated/interleaved async calls, which is the strongest evidence available
/// short of a real distributed backend that reserve-then-authorize actually holds
/// the budget under a race.
#[derive(Default)]
pub struct Ledger {
    scopes: Mutex<HashMap<String, ScopeState>>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_state<R>(&self, scope: &str, f: impl FnOnce(&mut ScopeState) -> R) -> R {
        // A poisoned mutex (a prior panic while the lock was held) still holds
        // valid, if possibly inconsistent, ledger data. Recovering it rather than
        // panicking again keeps this store fail-open at the Rust-panic level
        // while the filter above it stays fail-closed at the policy-decision
        // level (a denial is a normal, safe `Err`, never a panic).
        let mut guard = self
            .scopes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = guard.entry(scope.to_string()).or_default();
        f(state)
    }
}

impl LedgerStore for Ledger {
    fn reserve(&self, scope: &str, contribution: f64, budget: f64) -> Result<Reservation, Denial> {
        self.with_state(scope, |state| {
            let current_total = state.total();
            let would_be_total = current_total + contribution;
            if would_be_total > budget {
                return Err(Denial {
                    scope: scope.to_string(),
                    contribution,
                    current_total,
                    would_be_total,
                    budget,
                });
            }
            state.reserved += contribution;
            Ok(Reservation {
                scope: scope.to_string(),
                contribution,
            })
        })
    }

    fn force_reserve(&self, scope: &str, contribution: f64) -> Reservation {
        self.with_state(scope, |state| {
            state.reserved += contribution;
        });
        Reservation {
            scope: scope.to_string(),
            contribution,
        }
    }

    fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: f64,
        budget: f64,
    ) -> (Reservation, bool) {
        self.with_state(scope, |state| {
            state.reserved += contribution;
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

    fn commit(&self, reservation: Reservation) {
        self.with_state(&reservation.scope, |state| {
            state.reserved = (state.reserved - reservation.contribution).max(0.0);
            state.committed += reservation.contribution;
        });
    }

    fn release(&self, reservation: Reservation) {
        self.with_state(&reservation.scope, |state| {
            state.reserved = (state.reserved - reservation.contribution).max(0.0);
        });
    }

    fn record(&self, scope: &str, contribution: f64) {
        self.with_state(scope, |state| {
            state.committed += contribution;
        });
    }

    fn reconcile(&self, reservation: Reservation, actual_contribution: f64) {
        self.with_state(&reservation.scope, |state| {
            state.reserved = (state.reserved - reservation.contribution).max(0.0);
            state.committed += actual_contribution;
        });
    }

    fn snapshot(&self, scope: &str) -> Snapshot {
        self.with_state(scope, |state| Snapshot {
            committed: state.committed,
            reserved: state.reserved,
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

    const CAP_BUDGET: f64 = 3000.0;
    const CAP_CONTRIBUTION: f64 = 800.0;

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
        assert_eq!(ledger.snapshot(scope).total(), 2400.0);

        // Session 4: locally valid (800 <= a 1000 per-session cap enforced above
        // this ledger), but 2400 + 800 = 3200 > 3000 — refused.
        let denial = ledger
            .reserve(scope, CAP_CONTRIBUTION, CAP_BUDGET)
            .expect_err("fourth session composes past the aggregate budget");
        assert_eq!(denial.current_total, 2400.0);
        assert_eq!(denial.would_be_total, 3200.0);
        assert_eq!(denial.budget, CAP_BUDGET);

        // The refusal must not have mutated the ledger.
        assert_eq!(ledger.snapshot(scope).total(), 2400.0);
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
        assert_eq!(ledger.snapshot(scope).total(), 2400.0);
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
        total: Mutex<f64>,
    }

    impl NaiveCounter {
        fn new() -> Self {
            Self {
                total: Mutex::new(0.0),
            }
        }

        /// Read the current total, decide, THEN write — with a delay between the
        /// read and the write so that under real thread contention, other
        /// threads' reads can land inside the window and observe the same
        /// pre-write snapshot. This is what makes the naive counter breach: the
        /// check and the mutation are two steps, not one.
        fn naive_check_then_add(&self, amount: f64, budget: f64) -> bool {
            let current = *self.total.lock().unwrap();
            let would_be = current + amount;
            if would_be > budget {
                return false;
            }
            // The gap a real read-then-write counter has: another thread's read
            // can land here, before this thread's write is visible.
            thread::yield_now();
            *self.total.lock().unwrap() += amount;
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
                2400.0,
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
        let per_call = 250.0;
        let budget = 1000.0; // holds at most 4 of the 10 attempts per scope

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
                total, 1000.0,
                "scope {scope} should have admitted exactly 4 of 10 calls"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Reservation lifecycle: commit / release / reconcile.
    // ---------------------------------------------------------------------

    #[test]
    fn commit_moves_contribution_from_reserved_to_committed() {
        let ledger = Ledger::new();
        let reservation = ledger.reserve("s", 100.0, 1000.0).unwrap();
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0.0,
                reserved: 100.0
            }
        );
        ledger.commit(reservation);
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 100.0,
                reserved: 0.0
            }
        );
    }

    #[test]
    fn release_removes_reservation_without_committing() {
        let ledger = Ledger::new();
        let reservation = ledger.reserve("s", 100.0, 1000.0).unwrap();
        ledger.release(reservation);
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0.0,
                reserved: 0.0
            }
        );
    }

    #[test]
    fn a_released_reservation_frees_budget_for_a_later_call() {
        let ledger = Ledger::new();
        let first = ledger.reserve("s", 900.0, 1000.0).unwrap();
        assert!(
            ledger.reserve("s", 200.0, 1000.0).is_err(),
            "900 reserved leaves no room for 200"
        );
        ledger.release(first);
        assert!(
            ledger.reserve("s", 200.0, 1000.0).is_ok(),
            "releasing the first reservation must free its budget"
        );
    }

    #[test]
    fn reconcile_replaces_estimate_with_actual_contribution() {
        let ledger = Ledger::new();
        // Reserve against a 500-token estimate...
        let reservation = ledger.reserve("s", 500.0, 1000.0).unwrap();
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0.0,
                reserved: 500.0
            }
        );
        // ...but the real usage.total_tokens turns out to be 340.
        ledger.reconcile(reservation, 340.0);
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 340.0,
                reserved: 0.0
            }
        );
    }

    #[test]
    fn reconcile_with_an_actual_higher_than_the_estimate_still_lands_the_real_amount() {
        // The estimate is a pre-flight guess, not a cap on the real cost — an
        // under-estimate must not silently truncate the true exposure.
        let ledger = Ledger::new();
        let reservation = ledger.reserve("s", 200.0, 1000.0).unwrap();
        ledger.reconcile(reservation, 900.0);
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 900.0,
                reserved: 0.0
            }
        );
    }

    #[test]
    fn record_bypasses_the_budget_check_entirely() {
        let ledger = Ledger::new();
        // record() has no budget parameter: it cannot be denied by construction.
        ledger.record("s", 10_000.0);
        assert_eq!(ledger.snapshot("s").committed, 10_000.0);
    }

    #[test]
    fn force_reserve_always_succeeds_even_over_a_notional_budget() {
        let ledger = Ledger::new();
        let reservation = ledger.force_reserve("s", 10_000.0);
        assert_eq!(ledger.snapshot("s").reserved, 10_000.0);
        ledger.commit(reservation);
        assert_eq!(ledger.snapshot("s").committed, 10_000.0);
    }

    #[test]
    fn force_reserve_checked_reports_no_breach_when_within_budget() {
        let ledger = Ledger::new();
        let (reservation, breached) = ledger.force_reserve_checked("s", 500.0, 1000.0);
        assert!(!breached);
        assert_eq!(ledger.snapshot("s").reserved, 500.0);
        ledger.commit(reservation);
    }

    #[test]
    fn force_reserve_checked_reports_breach_when_over_budget_but_still_reserves() {
        let ledger = Ledger::new();
        // Never denies (monitor-mode primitive), but must still truthfully
        // report that this reservation pushed the scope over budget.
        let (reservation, breached) = ledger.force_reserve_checked("s", 1500.0, 1000.0);
        assert!(breached);
        assert_eq!(
            ledger.snapshot("s").reserved,
            1500.0,
            "force_reserve_checked must still reserve the full amount despite the breach"
        );
        ledger.commit(reservation);
        assert_eq!(ledger.snapshot("s").committed, 1500.0);
    }

    #[test]
    fn force_reserve_checked_breach_reflects_prior_committed_exposure_too() {
        let ledger = Ledger::new();
        let first = ledger.force_reserve_checked("s", 800.0, 1000.0);
        assert!(!first.1);
        ledger.commit(first.0);
        // 800 committed + 300 more reserved = 1100 > 1000: a breach, even
        // though this second call's OWN amount is well within budget alone.
        let (reservation, breached) = ledger.force_reserve_checked("s", 300.0, 1000.0);
        assert!(breached);
        ledger.commit(reservation);
    }

    #[test]
    fn force_reserve_still_supports_release_on_upstream_failure() {
        // Monitor mode's mechanics must stay symmetric: a call that never
        // actually landed upstream should not count against the running total,
        // even though force_reserve never denies up front.
        let ledger = Ledger::new();
        let reservation = ledger.force_reserve("s", 500.0);
        ledger.release(reservation);
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0.0,
                reserved: 0.0
            }
        );
    }

    // ---------------------------------------------------------------------
    // Budget-scope keying / isolation.
    // ---------------------------------------------------------------------

    #[test]
    fn different_scopes_have_independent_totals() {
        let ledger = Ledger::new();
        let a = ledger.reserve("agent:a", 900.0, 1000.0).unwrap();
        ledger.commit(a);
        // A different scope key starts fresh even though it shares a budget.
        assert!(ledger.reserve("agent:b", 900.0, 1000.0).is_ok());
        assert_eq!(ledger.snapshot("agent:a").total(), 900.0);
        assert_eq!(ledger.snapshot("agent:b").total(), 900.0);
    }

    #[test]
    fn budget_scope_dimension_is_encoded_in_the_key_not_a_separate_field() {
        // "agent:x" and "tenant:x" are different ledger keys even though the
        // identity value "x" is the same — the aggregation dimension is part of
        // the key. This test documents that contract at the ledger layer (the
        // filter is what actually builds these keys; see lib.rs).
        let ledger = Ledger::new();
        let agent_res = ledger.reserve("agent:x", 900.0, 1000.0).unwrap();
        ledger.commit(agent_res);
        assert!(
            ledger.reserve("tenant:x", 900.0, 1000.0).is_ok(),
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
            ledger.reserve("s", 1000.0, 1000.0).is_ok(),
            "exactly-at-budget must be admitted"
        );
    }

    #[test]
    fn a_call_one_unit_over_budget_is_denied() {
        let ledger = Ledger::new();
        let denial = ledger.reserve("s", 1000.01, 1000.0).unwrap_err();
        assert_eq!(denial.would_be_total, 1000.01);
    }

    #[test]
    fn a_zero_contribution_call_is_always_admitted_even_at_zero_budget() {
        let ledger = Ledger::new();
        assert!(ledger.reserve("s", 0.0, 0.0).is_ok());
    }

    #[test]
    fn a_zero_budget_denies_any_positive_contribution() {
        let ledger = Ledger::new();
        assert!(ledger.reserve("s", 0.01, 0.0).is_err());
    }

    #[test]
    fn committed_exposure_from_a_prior_call_counts_against_a_new_reservation() {
        let ledger = Ledger::new();
        let reservation = ledger.reserve("s", 1000.0, 1000.0).unwrap();
        ledger.commit(reservation);
        // The scope is now fully committed; even a zero-sized new call is fine,
        // but anything positive must be denied.
        assert!(ledger.reserve("s", 0.0, 1000.0).is_ok());
        assert!(ledger.reserve("s", 0.01, 1000.0).is_err());
    }

    #[test]
    fn an_in_flight_reservation_counts_against_a_concurrent_reservation_attempt() {
        // The core of reserve-then-authorize: a RESERVED (not yet committed)
        // amount must block a composing call exactly as if it had landed.
        let ledger = Ledger::new();
        let first = ledger.reserve("s", 600.0, 1000.0).unwrap();
        assert!(
            ledger.reserve("s", 500.0, 1000.0).is_err(),
            "an in-flight reservation must count against the budget check"
        );
        ledger.release(first);
        assert!(ledger.reserve("s", 500.0, 1000.0).is_ok());
    }

    #[test]
    fn release_never_drives_reserved_negative() {
        // Releasing a reservation that (by programmer error) does not match what
        // is actually held must not underflow the tracked state into a negative
        // "reserved" that would let future calls smuggle extra budget through.
        let ledger = Ledger::new();
        ledger.release(Reservation {
            scope: "s".to_string(),
            contribution: 500.0,
        });
        assert_eq!(
            ledger.snapshot("s"),
            Snapshot {
                committed: 0.0,
                reserved: 0.0
            }
        );
    }

    #[test]
    fn denial_report_carries_the_scope_and_amounts_for_diagnostics() {
        let ledger = Ledger::new();
        let reservation = ledger.reserve("agent:z", 700.0, 1000.0).unwrap();
        ledger.commit(reservation);
        let denial = ledger.reserve("agent:z", 400.0, 1000.0).unwrap_err();
        assert_eq!(denial.scope, "agent:z");
        assert_eq!(denial.contribution, 400.0);
        assert_eq!(denial.current_total, 700.0);
        assert_eq!(denial.would_be_total, 1100.0);
        assert_eq!(denial.budget, 1000.0);
    }

    #[test]
    fn an_unknown_scope_has_a_zero_snapshot() {
        let ledger = Ledger::new();
        assert_eq!(
            ledger.snapshot("never-seen"),
            Snapshot {
                committed: 0.0,
                reserved: 0.0
            }
        );
    }
}
