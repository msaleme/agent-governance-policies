// Copyright 2026 msaleme. Licensed under the MIT License.
//
// The durable, distributed ledger trait for the Aggregate-Risk Gate.
//
// Stage B: Transitioned from in-memory to remote storage. All amounts are
// represented as fixed-point i64 integers to ensure exact accounting.

use async_trait::async_trait;
use std::time::Duration;

/// A held reservation against a scope.
/// `id` is a unique identifier (e.g. UUID) ensuring idempotency and enabling
/// explicit expiry/recovery.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Reservation {
    pub id: String,
    pub scope: String,
    pub contribution: i64,
    pub timestamp: u64,
}

/// A denied reservation attempt.
#[derive(Clone, Debug, PartialEq)]
pub struct Denial {
    pub scope: String,
    pub contribution: i64,
    pub current_total: i64,
    pub would_be_total: i64,
    pub budget: i64,
}

/// A point-in-time view of one scope's exposure.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Snapshot {
    pub committed: i64,
    pub reserved: i64,
}

impl Snapshot {
    pub fn total(&self) -> i64 {
        self.committed + self.reserved
    }
}

#[async_trait]
pub trait LedgerStore: Send + Sync {
    /// Atomically checks `scope`'s committed-plus-reserved exposure against
    /// `budget` and, only if `contribution` fits, reserves it.
    async fn reserve(
        &self,
        scope: &str,
        contribution: i64,
        budget: i64,
        window: Duration,
    ) -> Result<Reservation, Denial>;

    /// Reserves `contribution` against `scope` unconditionally, but reports
    /// whether this pushed the scope over budget.
    async fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: i64,
        budget: i64,
        window: Duration,
    ) -> (Reservation, bool);

    /// Resolves a reservation as successful: moves its contribution from
    /// `reserved` into `committed`. If `actual_contribution` is provided,
    /// it uses that instead of the estimated amount.
    async fn commit(&self, reservation: Reservation, actual_contribution: Option<i64>);

    /// Resolves a reservation as not-consumed: removes its contribution from
    /// `reserved` without ever adding it to `committed`.
    async fn release(&self, reservation: Reservation);

    /// Records `contribution` directly into `committed`, bypassing the budget check.
    async fn record(&self, scope: &str, contribution: i64, window: Duration);

    /// A read-only view of one scope's current state.
    async fn snapshot(&self, scope: &str, window: Duration) -> Snapshot;
}
