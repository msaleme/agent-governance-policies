// Copyright 2026 msaleme. Licensed under the MIT License.
//
// Stage B: Distributed Ledger implementation using PDK Remote Data Storage.
//
// This implementation ensures that the aggregate budget is held across
// multiple replicas by using a lock-protected atomic check-and-reserve.

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

    async fn acquire_lock(&self, scope: &str) -> Result<(), DataStorageError> {
        let lock_key = Self::get_lock_key(scope);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        loop {
            // Attempt to acquire lock
            if self.store.store(&lock_key, &StoreMode::Absent, &now).await.is_ok() {
                return Ok(());
            }
            
            // Check for expired lock (30s TTL)
            if let Ok(Some((timestamp, _))) = self.store.get::<u64>(&lock_key).await {
                if now - timestamp > 30 {
                    // Attempt to "steal" expired lock by overwriting
                    let _ = self.store.store(&lock_key, &StoreMode::Absent, &now).await;
                    // Verify we successfully stole it
                    if self.store.get::<u64>(&lock_key).await.ok().flatten().map(|t| t == now).unwrap_or(false) {
                        return Ok(());
                    }
                }
            }
            
            futures_lite::future::yield_now().await;
        }
    }

    async fn release_lock(&self, scope: &str) -> Result<(), DataStorageError> {
        self.store.delete(&Self::get_lock_key(scope)).await
    }

    async fn update_counter(&self, scope: &str, delta: i64) -> Result<i64, DataStorageError> {
        self.acquire_lock(scope).await?;
        let key = Self::get_reserved_key(scope);
        let current = match self.store.get::<i64>(&key).await {
            Ok(Some((val, _))) => val,
            Ok(None) => 0,
            Err(e) => {
                let _ = self.release_lock(scope).await;
                return Err(e);
            }
        };
        let new_val = current + delta;
        
        // Atomic update via Lock + Overwrite. 
        // We delete and store as a simple way to simulate overwrite in this SDK.
        let _ = self.store.delete(&key).await;
        let res = self.store.store(&key, &StoreMode::Absent, &new_val).await;
        let _ = self.release_lock(scope).await;
        res?;
        Ok(new_val)
    }

    async fn get_committed_total(&self, scope: &str, window: Duration) -> i64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let window_secs = window.as_secs();
        let mut total = 0;
        
        let bucket_size = 3600;
        let start_bucket = (now - window_secs) / bucket_size;
        let end_bucket = now / bucket_size;

        for b in start_bucket..=end_bucket {
            let key = Self::get_bucket_key(scope, b * bucket_size);
            if let Ok(Some((val, _))) = self.store.get::<i64>(&key).await {
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
        self.acquire_lock(scope).await.map_err(|_| Denial {
            scope: scope.to_string(),
            contribution,
            current_total: 0,
            would_be_total: 0,
            budget,
        })?;

        let committed = self.get_committed_total(scope, window).await;
        let reserved = match self.store.get::<i64>(&Self::get_reserved_key(scope)).await {
            Ok(Some((val, _))) => val,
            _ => 0,
        };

        if committed + reserved + contribution > budget {
            let _ = self.release_lock(scope).await;
            return Err(Denial {
                scope: scope.to_string(),
                contribution,
                current_total: committed + reserved,
                would_be_total: committed + reserved + contribution,
                budget,
            });
        }

        let res_id = Uuid::new_v4().to_string();
        let reservation = Reservation {
            id: res_id.clone(),
            scope: scope.to_string(),
            contribution,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        // Store reservation record
        if let Err(_) = self.store.store(&Self::get_res_key(&res_id), &StoreMode::Absent, &reservation).await {
            let _ = self.release_lock(scope).await;
            return Err(Denial {
                scope: scope.to_string(),
                contribution,
                current_total: committed + reserved,
                would_be_total: committed + reserved + contribution,
                budget,
            });
        }

        // Update the aggregate reserved counter
        let _ = self.update_counter(scope, contribution).await;
        let _ = self.release_lock(scope).await;

        Ok(reservation)
    }

    async fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: i64,
        budget: i64,
        window: Duration,
    ) -> (Reservation, bool) {
        let _ = self.acquire_lock(scope).await;
        let committed = self.get_committed_total(scope, window).await;
        let reserved = match self.store.get::<i64>(&Self::get_reserved_key(scope)).await {
            Ok(Some((val, _))) => val,
            _ => 0,
        };
        let breached = committed + reserved + contribution > budget;
        
        let res_id = Uuid::new_v4().to_string();
        let reservation = Reservation {
            id: res_id.clone(),
            scope: scope.to_string(),
            contribution,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        let _ = self.store.store(&Self::get_res_key(&res_id), &StoreMode::Absent, &reservation).await;
        let _ = self.update_counter(scope, contribution).await;
        let _ = self.release_lock(scope).await;
        (reservation, breached)
    }

    async fn commit(
        &self, 
        reservation: Reservation, 
        actual_contribution: Option<i64>
    ) {
        let contribution = actual_contribution.unwrap_or(reservation.contribution);
        
        // 1. Remove reservation
        let _ = self.store.delete(&Self::get_res_key(&reservation.id)).await;
        
        // 2. Decrement reserved total
        let _ = self.update_counter(&reservation.scope, -reservation.contribution).await;
        
        // 3. Increment committed total in current bucket
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let bucket_key = Self::get_bucket_key(&reservation.scope, (now / 3600) * 3600);
        
        self.acquire_lock(&reservation.scope).await.ok();
        let current = match self.store.get::<i64>(&bucket_key).await {
            Ok(Some((val, _))) => val,
            _ => 0,
        };
        let _ = self.store.delete(&bucket_key).await;
        let _ = self.store.store(&bucket_key, &StoreMode::Absent, &(current + contribution)).await;
        let _ = self.release_lock(&reservation.scope).await;
    }

    async fn release(
        &self, 
        reservation: Reservation
    ) {
        let _ = self.store.delete(&Self::get_res_key(&reservation.id)).await;
        let _ = self.update_counter(&reservation.scope, -reservation.contribution).await;
    }

    async fn record(
        &self, 
        scope: &str, 
        contribution: i64, 
        window: Duration
    ) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let bucket_key = Self::get_bucket_key(scope, (now / 3600) * 3600);
        
        self.acquire_lock(scope).await.ok();
        let current = match self.store.get::<i64>(&bucket_key).await {
            Ok(Some((val, _))) => val,
            _ => 0,
        };
        let _ = self.store.delete(&bucket_key).await;
        let _ = self.store.store(&bucket_key, &StoreMode::Absent, &(current + contribution)).await;
        let _ = self.release_lock(scope).await;
    }

    async fn snapshot(
        &self, 
        scope: &str, 
        window: Duration
    ) -> Snapshot {
        let committed = self.get_committed_total(scope, window).await;
        let reserved = match self.store.get::<i64>(&Self::get_reserved_key(scope)).await {
            Ok(Some((val, _))) => val,
            _ => 0,
        };
        Snapshot { committed, reserved }
    }
}
