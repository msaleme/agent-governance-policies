// Copyright 2026 msaleme. Licensed under the MIT License.

use std::time::Duration;
use async_trait::async_trait;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Reservation {
    pub id: String,
    pub scope: String,
    pub contribution: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Denial {
    pub scope: String,
    pub contribution: i64,
    pub current_total: i64,
    pub would_be_total: i64,
    pub budget: i64,
}

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
    async fn reserve(
        &self, 
        scope: &str, 
        contribution: i64, 
        budget: i64, 
        window: Duration
    ) -> Result<Reservation, Denial>;

    async fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: i64,
        budget: i64,
        window: Duration,
    ) -> (Reservation, bool);

    async fn commit(
        &self, 
        reservation: Reservation, 
        actual_contribution: Option<i64>
    );

    async fn release(
        &self, 
        reservation: Reservation
    );

    async fn record(
        &self, 
        scope: &str, 
        contribution: i64, 
        window: Duration
    );

    async fn snapshot(
        &self, 
        scope: &str, 
        window: Duration
    ) -> Snapshot;
}
