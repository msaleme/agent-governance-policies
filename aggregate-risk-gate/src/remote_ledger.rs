// Copyright 2026 msaleme. Licensed under the MIT License.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use async_trait::async_trait;
use uuid::Uuid;
use std::sync::Arc;

use crate::ledger::{LedgerStore, Reservation, Denial, Snapshot};
use pdk_data_storage_lib::{DataStorage, StoreMode, DataStorageError};

pub struct PdkRemoteLedger<S: DataStorage> {
    store: Arc<S>,
}

impl<S: DataStorage + Send + Sync + 'static> PdkRemoteLedger<S> {
    pub fn new(store: S) -> Self {
        Self { store: Arc::new(store) }
    }

    fn get_bucket_key(scope: &str, timestamp: u64) -> String {
        format!("total:{}:{}", scope, timestamp)
    }

    fn get_reserved_key(scope: &str) -> String {
        format!("res_total:{}", scope)
    }

    fn get_lock_key(scope: &str) -> String {
        format!("lock:{}", scope)
    }

    fn get_res_key(id: &str) -> String {
        format!("res:{}", id)
    }

    async fn acquire_lock(store: &S, scope: &str) -> Result<(), DataStorageError> {
        let lock_key = Self::get_lock_key(scope);
        loop {
            if store.store(&lock_key, &StoreMode::Absent, &"locked").await.is_ok() {
                return Ok(());
            }
            futures_lite::future::yield_now().await;
        }
    }

    async fn release_lock(store: &S, scope: &str) -> Result<(), DataStorageError> {
        store.delete(&Self::get_lock_key(scope)).await
    }

    async fn update_counter(store: &S, scope: &str, delta: i64) -> Result<i64, DataStorageError> {
        Self::acquire_lock(store, scope).await?;
        let key = Self::get_reserved_key(scope);
        let current = match store.get::<i64>(&key).await {
            Ok(Some((val, _))) => val,
            Ok(None) => 0,
            Err(e) => {
                let _ = Self::release_lock(store, scope).await;
                return Err(e);
            }
        };
        let new_val = current + delta;
        // Use Absent for a counter update if Overwrite is missing, or a custom mode.
        let res = store.store(&key, &StoreMode::Absent, &new_val).await;
        let _ = Self::release_lock(store, scope).await;
        res?;
        Ok(new_val)
    }

    async fn get_committed_total(store: &S, scope: &str, window: Duration) -> i64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let window_secs = window.as_secs();
        let mut total = 0;
        let bucket_size = 3600;
        let start_bucket = (now - window_secs) / bucket_size;
        let end_bucket = now / bucket_size;
        for b in start_bucket..=end_bucket {
            let key = Self::get_bucket_key(scope, b * bucket_size);
            if let Ok(Some((val, _))) = store.get::<i64>(&key).await {
                total += val;
            }
        }
        total
    }
}

#[async_trait]
impl<S: DataStorage + Send + Sync + 'static> LedgerStore for PdkRemoteLedger<S> {
    async fn reserve(
        &self, 
        scope: &str, 
        contribution: i64, 
        budget: i64, 
        window: Duration
    ) -> Result<Reservation, Denial> {
        let res_id = Uuid::new_v4().to_string();
        let res_key = Self::get_res_key(&res_id);
        let reservation = Reservation {
            id: res_id.clone(),
            scope: scope.to_string(),
            contribution,
        };

        if self.store.store(&res_key, &StoreMode::Absent, &reservation).await.is_err() {
            return Err(Denial {
                scope: scope.to_string(),
                contribution,
                current_total: 0,
                would_be_total: 0,
                budget,
            });
        }

        let committed = Self::get_committed_total(&self.store, scope, window).await;
        let reserved = match self.store.get::<i64>(&Self::get_reserved_key(scope)).await {
            Ok(Some((val, _))) => val,
            _ => 0,
        };

        if committed + reserved + contribution > budget {
            let _ = self.store.delete(&res_key).await;
            return Err(Denial {
                scope: scope.to_string(),
                contribution,
                current_total: committed + reserved,
                would_be_total: committed + reserved + contribution,
                budget,
            });
        }

        if let Err(_) = Self::update_counter(&self.store, scope, contribution).await {
            let _ = self.store.delete(&res_key).await;
            return Err(Denial {
                scope: scope.to_string(),
                contribution,
                current_total: committed + reserved,
                would_be_total: committed + reserved + contribution,
                budget,
            });
        }

        Ok(reservation)
    }

    async fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: i64,
        budget: i64,
        window: Duration,
    ) -> (Reservation, bool) {
        let res_id = Uuid::new_v4().to_string();
        let res_key = Self::get_res_key(&res_id);
        let reservation = Reservation {
            id: res_id.clone(),
            scope: scope.to_string(),
            contribution,
        };
        let _ = self.store.store(&res_key, &StoreMode::Absent, &reservation).await;
        let committed = Self::get_committed_total(&self.store, scope, window).await;
        let reserved = match self.store.get::<i64>(&Self::get_reserved_key(scope)).await {
            Ok(Some((val, _))) => val,
            _ => 0,
        };
        let breached = committed + reserved + contribution > budget;
        let _ = Self::update_counter(&self.store, scope, contribution).await;
        (reservation, breached)
    }

    async fn commit(
        &self, 
        reservation: Reservation, 
        actual_contribution: Option<i64>
    ) {
        let contribution = actual_contribution.unwrap_or(reservation.contribution);
        let _ = self.store.delete(&Self::get_res_key(&reservation.id)).await;
        let _ = Self::update_counter(&self.store, &reservation.scope, -reservation.contribution).await;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let bucket_key = Self::get_bucket_key(&reservation.scope, (now / 3600) * 3600);
        loop {
            if self.store.store(&Self::get_lock_key(&reservation.scope), &StoreMode::Absent, &"locked").await.is_ok() {
                let current = match self.store.get::<i64>(&bucket_key).await {
                    Ok(Some((val, _))) => val,
                    _ => 0,
                };
                let _ = self.store.store(&bucket_key, &StoreMode::Absent, &(current + contribution)).await;
                let _ = self.store.delete(&Self::get_lock_key(&reservation.scope)).await;
                break;
            }
            futures_lite::future::yield_now().await;
        }
    }

    async fn release(
        &self, 
        reservation: Reservation
    ) {
        let _ = self.store.delete(&Self::get_res_key(&reservation.id)).await;
        let _ = Self::update_counter(&self.store, &reservation.scope, -reservation.contribution).await;
    }

    async fn record(
        &self, 
        scope: &str, 
        contribution: i64, 
        window: Duration
    ) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let bucket_key = Self::get_bucket_key(scope, (now / 3600) * 3600);
        loop {
            if self.store.store(&Self::get_lock_key(scope), &StoreMode::Absent, &"locked").await.is_ok() {
                let current = match self.store.get::<i64>(&bucket_key).await {
                    Ok(Some((val, _))) => val,
                    _ => 0,
                };
                let _ = self.store.store(&bucket_key, &StoreMode::Absent, &(current + contribution)).await;
                let _ = self.store.delete(&Self::get_lock_key(scope)).await;
                break;
            }
            futures_lite::future::yield_now().await;
        }
    }

    async fn snapshot(
        &self, 
        scope: &str, 
        window: Duration
    ) -> Snapshot {
        let committed = Self::get_committed_total(&self.store, scope, window).await;
        let reserved = match self.store.get::<i64>(&Self::get_reserved_key(scope)).await {
            Ok(Some((val, _))) => val,
            _ => 0,
        };
        Snapshot { committed, reserved }
    }
}
