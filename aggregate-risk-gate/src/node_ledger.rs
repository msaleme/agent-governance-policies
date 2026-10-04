// Copyright 2026 msaleme. Licensed under the MIT License.
//
// The node-wide ledger (`ledgerBackend: node`, P4A review #48): the same scope
// state as the per-worker `Ledger`, held in the gateway's node-local shared data
// so that every Envoy worker of one gateway replica checks and reserves against
// ONE budget.
//
// Each worker is its own single-threaded VM; the shared data is process-wide and
// offers get, a compare-and-swap set (`StoreMode::Cas`), a create-only set
// (`StoreMode::Absent`) and an unconditional delete. Every ledger write here is
// a CAS (or Absent) against the version this worker just read, inside a bounded
// retry loop with no sleep:
//
//   get -> roll + reclaim -> budget check -> CAS store   (retry on mismatch)
//
// So a check and its reservation are one atomic step across workers, exactly as
// the per-worker `Ledger`'s mutex makes them one step across threads. There is no
// read-then-write fallback and no unconditional (`Always`) write of a ledger
// value. When the retries run out the call is refused with `Contention` (block
// mode fails closed; monitor mode forwards and flags it), and a storage error is
// `Unavailable`, handled the same way.
//
// Keys. A scope's record lives under `s:` + hex(HMAC-SHA256(scopeDigestKey,
// "ledger-key-v1\0" || scope)), so raw identities never appear in shared data,
// and the namespace is per policy instance (or an explicit `ledgerNamespace`).
// `n` holds how many scope records are counted against `maxScopes` and `sweep`
// coordinates cleanup.
//
// Capacity and cleanup (P4A review #49 A, node side). A new scope takes a slot
// by CAS-incrementing `n`. At the cap, a refusal reads `n` and `sweep` and stops:
// O(1). Only once `sweep.not_before` has passed does one worker claim the sweep
// (by CAS on `sweep`) and scan the namespace, so a flood of new identities costs
// at most one O(n) scan per `MIN_RESCAN_MS` per replica. A scan turns each idle
// scope into a `Vacant` tombstone by CAS (a concurrent writer's CAS then fails
// and it retries) and frees its slot; a `Vacant` record older than `GRACE_MS` is
// CAS'd to `Doomed`, which no writer ever writes over, and then deleted. Live
// state is never evicted. The same scan runs every `GC_INTERVAL_MS` so stale
// keys are deleted even below the cap.
//
// Reservation ids carry a random 64-bit per-worker prefix and a counter, so a
// reservation made on worker A can be settled by id on worker B (the response
// may run on either), and the #17 rules hold unchanged: settle at most once,
// late settlement while the tombstone is held, `NotActive` otherwise.
//
// Settlement exhaustion is safe by direction. A commit that cannot be written is
// queued on this worker and retried at the start of its next ledger calls; while
// that queue is long, new reservations are refused, so exposure is never lost
// silently. A release that cannot be written leaves the reservation held until
// it is reclaimed: an over-count that frees itself after the timeout.
//
// Known edges, documented rather than hidden: a slot whose decrement exhausts its
// retries stays counted (fewer scopes fit, never more state evicted); and a
// writer that stalls between its get and its CAS for longer than `GRACE_MS`
// across a sweep could re-create a deleted record without a slot. Neither can
// over-admit a budget.
//
// Scope of the guarantee: one budget per policy instance per gateway REPLICA,
// reset when the gateway process restarts. Not shared across replicas, not
// durable.

#[cfg(test)]
use crate::ledger::Snapshot;
use crate::ledger::{
    count_reclaim, count_settlement, period, LedgerStats, LedgerStore, Refusal, Reservation,
    ReservationId, ScopeState, Settlement,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::convert::TryFrom;

/// CAS attempts for a reservation before it is refused as contended.
pub const RESERVE_RETRIES: u32 = 12;
/// CAS attempts for a settlement before it is deferred.
const SETTLE_RETRIES: u32 = 64;
/// CAS attempts for one queued commit on each later call.
const DRAIN_RETRIES: u32 = 8;
/// How many queued commits one call retries.
const DRAIN_PER_CALL: usize = 16;
/// New reservations are refused while this many commits are queued.
const PENDING_LIMIT: usize = 256;
/// How long a `Vacant` tombstone is kept before it is deleted.
const GRACE_MS: u64 = 30_000;
/// The shortest gap between two capacity sweeps on one replica.
const MIN_RESCAN_MS: u64 = 1_000;
/// The longest a full ledger waits before it rescans.
const MAX_RESCAN_MS: u64 = 30_000;
/// How often stale keys are collected below the cap.
const GC_INTERVAL_MS: u64 = 60_000;

const SCOPE_PREFIX: &str = "s:";
const COUNT_KEY: &str = "n";
const SWEEP_KEY: &str = "sweep";

/// Why a shared-data operation failed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StoreError {
    /// The key changed since it was read (or, for `Put::Absent`, exists).
    CasMismatch,
    /// Any other storage error, or a value that could not be read.
    Failed,
}

/// The only write modes the ledger uses. There is deliberately no `Always`.
#[derive(Clone, Copy, Debug)]
pub enum Put<'a> {
    /// Create the key; fails with `CasMismatch` if it exists.
    Absent,
    /// Replace the version this CAS identifies.
    Cas(&'a str),
}

/// The shared-data operations the node ledger needs. Implemented over PDK
/// local shared data in production (`PdkStore`) and by an in-memory store in
/// the unit tests, which can force CAS conflicts between two "workers".
pub trait KvStore {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, String)>, StoreError>;
    fn put(&self, key: &str, mode: Put<'_>, value: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
    fn keys(&self) -> Result<Vec<String>, StoreError>;
}

/// A scope key's value.
#[derive(Debug, Serialize, Deserialize)]
enum Record {
    Scope(ScopeState),
    /// Swept while idle; its slot is free. Re-used by the next writer.
    Vacant {
        since: u64,
    },
    /// Being deleted since `at`; never written over.
    Doomed {
        at: u64,
    },
}

/// The `sweep` key's value.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Sweep {
    /// No capacity sweep before this time.
    not_before: u64,
    /// No periodic collection before this time.
    next_gc: u64,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(value).map_err(|_| StoreError::Failed)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StoreError> {
    serde_json::from_slice(bytes).map_err(|_| StoreError::Failed)
}

fn unavailable(_: StoreError) -> Refusal {
    Refusal::Unavailable
}

/// What a scope key held when it was read.
enum Read {
    /// No record, or a `Vacant` one: a new scope that needs a slot.
    New(Option<String>),
    Live(ScopeState, String),
    Doomed(u64),
}

/// The node-wide ledger. One per policy instance per worker, all sharing one
/// namespace of the replica's shared data.
pub struct NodeLedger {
    store: Box<dyn KvStore>,
    key_secret: Vec<u8>,
    max_scopes: u64,
    ttl: u64,
    window: Option<u64>,
    /// The high 64 bits of every id this worker issues.
    id_prefix: u64,
    next_id: Cell<u64>,
    stats: RefCell<LedgerStats>,
    /// Commits that could not be written yet.
    pending: RefCell<VecDeque<Reservation>>,
    /// When this worker next looks at the shared `sweep` record for GC.
    next_gc_check: Cell<u64>,
}

impl NodeLedger {
    pub fn new(
        store: Box<dyn KvStore>,
        key_secret: Vec<u8>,
        max_scopes: usize,
        ttl: u64,
        window: Option<u64>,
        id_prefix: u64,
    ) -> Self {
        NodeLedger {
            store,
            key_secret,
            max_scopes: u64::try_from(max_scopes).unwrap_or(u64::MAX),
            ttl,
            window,
            id_prefix,
            next_id: Cell::new(1),
            stats: RefCell::new(LedgerStats::default()),
            pending: RefCell::new(VecDeque::new()),
            next_gc_check: Cell::new(0),
        }
    }

    fn key(&self, scope: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key_secret)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(b"ledger-key-v1\0");
        mac.update(scope.as_bytes());
        let hex: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{SCOPE_PREFIX}{hex}")
    }

    fn next_id(&self) -> ReservationId {
        let counter = self.next_id.get();
        self.next_id.set(counter.wrapping_add(1));
        (ReservationId::from(self.id_prefix) << 64) | ReservationId::from(counter)
    }

    fn read(&self, key: &str) -> Result<Read, StoreError> {
        Ok(match self.store.get(key)? {
            None => Read::New(None),
            Some((bytes, cas)) => match decode::<Record>(&bytes)? {
                Record::Scope(state) => Read::Live(state, cas),
                Record::Vacant { .. } => Read::New(Some(cas)),
                Record::Doomed { at } => Read::Doomed(at),
            },
        })
    }

    fn put_record(&self, key: &str, cas: Option<&str>, record: &Record) -> Result<(), StoreError> {
        let mode = match cas {
            Some(cas) => Put::Cas(cas),
            None => Put::Absent,
        };
        self.store.put(key, mode, &encode(record)?)
    }

    /// The reserve/record loop: read `scope`, roll and reclaim it, run `f`
    /// (which may refuse, writing nothing), and CAS the result back.
    fn mutate<R>(
        &self,
        scope: &str,
        now: u64,
        mut f: impl FnMut(&mut ScopeState) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        let result = self.mutate_inner(scope, now, &mut f);
        if matches!(result, Err(Refusal::Contention) | Err(Refusal::Unavailable)) {
            self.stats.borrow_mut().contended += 1;
        }
        result
    }

    fn mutate_inner<R>(
        &self,
        scope: &str,
        now: u64,
        f: &mut impl FnMut(&mut ScopeState) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        self.drain_pending(now);
        if self.pending.borrow().len() >= PENDING_LIMIT {
            return Err(Refusal::Contention);
        }
        self.maybe_collect(now);
        let key = self.key(scope);
        for _ in 0..RESERVE_RETRIES {
            let (mut state, cas, new) = match self.read(&key).map_err(unavailable)? {
                Read::Doomed(at) => {
                    // A sweep is deleting this key. Only once the sweeper is
                    // surely done may a writer remove it itself; until then
                    // the call reads again (and is refused as contended if
                    // the delete never lands within the retries).
                    if now >= at.saturating_add(GRACE_MS) {
                        let _ = self.store.delete(&key);
                    }
                    continue;
                }
                Read::New(cas) => (ScopeState::default(), cas, true),
                Read::Live(state, cas) => (state, Some(cas), false),
            };
            state.roll(period(self.window, now));
            let reclaimed = state.reclaim(now, self.ttl);
            let result = f(&mut state)?;
            if new {
                self.acquire_slot(now)?;
            }
            match self.put_record(&key, cas.as_deref(), &Record::Scope(state)) {
                Ok(()) => {
                    count_reclaim(&mut self.stats.borrow_mut(), reclaimed);
                    return Ok(result);
                }
                Err(err) => {
                    if new {
                        self.adjust_count(-1);
                    }
                    if err == StoreError::Failed {
                        return Err(Refusal::Unavailable);
                    }
                }
            }
        }
        Err(Refusal::Contention)
    }

    /// Takes one of `maxScopes` slots for a new scope record. At the cap this
    /// is O(1) (two reads) unless a sweep is due.
    fn acquire_slot(&self, now: u64) -> Result<(), Refusal> {
        let mut swept = false;
        for _ in 0..RESERVE_RETRIES {
            let (count, cas) = self.read_count().map_err(unavailable)?;
            if count < self.max_scopes {
                match self.put_count(count + 1, cas.as_deref()) {
                    Ok(()) => return Ok(()),
                    Err(StoreError::CasMismatch) => continue,
                    Err(StoreError::Failed) => return Err(Refusal::Unavailable),
                }
            }
            if swept {
                return Err(Refusal::AtCapacity);
            }
            let (sweep, sweep_cas) = self.read_sweep().map_err(unavailable)?;
            if now < sweep.not_before {
                return Err(Refusal::AtCapacity);
            }
            // Claim the sweep; a worker that loses the claim just refuses.
            let claim = Sweep {
                not_before: now.saturating_add(MIN_RESCAN_MS),
                next_gc: now.saturating_add(GC_INTERVAL_MS),
            };
            let Ok(cas) = self.put_sweep(&claim, sweep_cas.as_deref()) else {
                return Err(Refusal::AtCapacity);
            };
            self.sweep(now, cas);
            swept = true;
        }
        Err(Refusal::Contention)
    }

    fn read_count(&self) -> Result<(u64, Option<String>), StoreError> {
        Ok(match self.store.get(COUNT_KEY)? {
            None => (0, None),
            Some((bytes, cas)) => (decode::<u64>(&bytes)?, Some(cas)),
        })
    }

    fn put_count(&self, count: u64, cas: Option<&str>) -> Result<(), StoreError> {
        let mode = cas.map_or(Put::Absent, Put::Cas);
        self.store.put(COUNT_KEY, mode, &encode(&count)?)
    }

    /// Adds `delta` to the slot count, best effort. A decrement that cannot
    /// be written leaves the slot counted: fewer new scopes fit, which is the
    /// conservative direction.
    fn adjust_count(&self, delta: i64) {
        for _ in 0..SETTLE_RETRIES {
            let Ok((count, cas)) = self.read_count() else {
                return;
            };
            let next = if delta < 0 {
                count.saturating_sub(delta.unsigned_abs())
            } else {
                count.saturating_add(delta.unsigned_abs())
            };
            match self.put_count(next, cas.as_deref()) {
                Err(StoreError::CasMismatch) => continue,
                _ => return,
            }
        }
    }

    fn read_sweep(&self) -> Result<(Sweep, Option<String>), StoreError> {
        Ok(match self.store.get(SWEEP_KEY)? {
            None => (Sweep::default(), None),
            Some((bytes, cas)) => (decode::<Sweep>(&bytes)?, Some(cas)),
        })
    }

    /// CAS-writes the sweep record and returns its new version.
    fn put_sweep(&self, sweep: &Sweep, cas: Option<&str>) -> Result<String, StoreError> {
        let mode = cas.map_or(Put::Absent, Put::Cas);
        self.store.put(SWEEP_KEY, mode, &encode(sweep)?)?;
        // Read back the version this worker now owns.
        match self.store.get(SWEEP_KEY)? {
            Some((_, cas)) => Ok(cas),
            None => Err(StoreError::Failed),
        }
    }

    /// Runs the periodic collection when it is due on the replica.
    fn maybe_collect(&self, now: u64) {
        if now < self.next_gc_check.get() {
            return;
        }
        self.next_gc_check
            .set(now.saturating_add(GC_INTERVAL_MS / 4));
        let Ok((sweep, cas)) = self.read_sweep() else {
            return;
        };
        if now < sweep.next_gc {
            return;
        }
        let claim = Sweep {
            not_before: sweep.not_before,
            next_gc: now.saturating_add(GC_INTERVAL_MS),
        };
        if let Ok(cas) = self.put_sweep(&claim, cas.as_deref()) {
            self.sweep(now, cas);
        }
    }

    /// One scan of the namespace, by the worker holding the `sweep` claim
    /// `claim_cas`: idle scopes become `Vacant` (freeing their slots), old
    /// `Vacant` records are deleted via `Doomed`. Never touches live state.
    /// Correctness never depends on the claim being exclusive: every change
    /// is a CAS, and only a sweep's own successful conversions free slots.
    fn sweep(&self, now: u64, claim_cas: String) {
        let Ok(keys) = self.store.keys() else {
            return;
        };
        let mut freed: i64 = 0;
        let mut next_idle = u64::MAX;
        for key in keys.iter().filter(|key| key.starts_with(SCOPE_PREFIX)) {
            let Ok(Some((bytes, cas))) = self.store.get(key) else {
                continue;
            };
            match decode::<Record>(&bytes) {
                Ok(Record::Scope(mut state)) => {
                    state.roll(period(self.window, now));
                    let _ = state.reclaim(now, self.ttl);
                    if state.is_idle() {
                        let vacant = Record::Vacant { since: now };
                        if self.put_record(key, Some(&cas), &vacant).is_ok() {
                            freed += 1;
                            continue;
                        }
                    }
                    next_idle = next_idle.min(state.idle_at(self.ttl, self.window));
                }
                Ok(Record::Vacant { since }) => {
                    if now >= since.saturating_add(GRACE_MS)
                        && self
                            .put_record(key, Some(&cas), &Record::Doomed { at: now })
                            .is_ok()
                    {
                        let _ = self.store.delete(key);
                    }
                }
                // Left behind by a sweep that stopped mid-delete; nothing
                // writes over `Doomed`, so once that sweep is surely done
                // it is safe to drop.
                Ok(Record::Doomed { at }) => {
                    if now >= at.saturating_add(GRACE_MS) {
                        let _ = self.store.delete(key);
                    }
                }
                Err(_) => {}
            }
        }
        if freed > 0 {
            self.adjust_count(-freed);
        }
        let not_before = next_idle
            .max(now.saturating_add(MIN_RESCAN_MS))
            .min(now.saturating_add(MAX_RESCAN_MS));
        let done = Sweep {
            not_before,
            next_gc: now.saturating_add(GC_INTERVAL_MS),
        };
        let _ = self.put_sweep(&done, Some(&claim_cas));
    }

    /// One settlement attempt loop on the shared record.
    fn try_settle(
        &self,
        reservation: &Reservation,
        now: u64,
        commit: bool,
        retries: u32,
    ) -> Result<Settlement, StoreError> {
        let key = self.key(&reservation.scope);
        for _ in 0..retries {
            let (mut state, cas) = match self.read(&key)? {
                Read::Live(state, cas) => (state, cas),
                // Untracked (never created, or swept while idle).
                Read::New(_) | Read::Doomed(_) => return Ok(Settlement::NotActive),
            };
            state.roll(period(self.window, now));
            let outcome = state.settle(reservation.id, commit);
            if outcome == Settlement::NotActive {
                return Ok(outcome);
            }
            let reclaimed = state.reclaim(now, self.ttl);
            let idle = state.is_idle();
            match self.put_record(&key, Some(&cas), &Record::Scope(state)) {
                Ok(()) => {
                    count_reclaim(&mut self.stats.borrow_mut(), reclaimed);
                    if idle {
                        self.hint_idle(now);
                    }
                    return Ok(outcome);
                }
                Err(StoreError::CasMismatch) => continue,
                Err(err) => return Err(err),
            }
        }
        Err(StoreError::CasMismatch)
    }

    /// A settlement just left a scope idle: let the next new scope at the cap
    /// sweep sooner, without sweeping more than once per `MIN_RESCAN_MS`.
    fn hint_idle(&self, now: u64) {
        let Ok((sweep, Some(cas))) = self.read_sweep() else {
            return;
        };
        let soonest = sweep
            .next_gc
            .saturating_sub(GC_INTERVAL_MS)
            .saturating_add(MIN_RESCAN_MS)
            .max(now);
        if sweep.not_before > soonest {
            let hinted = Sweep {
                not_before: soonest,
                next_gc: sweep.next_gc,
            };
            let _ = self.put_sweep(&hinted, Some(&cas));
        }
    }

    /// Retries queued commits, a few per call.
    fn drain_pending(&self, now: u64) {
        for _ in 0..DRAIN_PER_CALL {
            let Some(reservation) = self.pending.borrow_mut().pop_front() else {
                return;
            };
            match self.try_settle(&reservation, now, true, DRAIN_RETRIES) {
                Ok(outcome) => count_settlement(&mut self.stats.borrow_mut(), outcome),
                Err(_) => {
                    self.pending.borrow_mut().push_front(reservation);
                    return;
                }
            }
        }
    }

    /// How many commits are queued on this worker.
    #[cfg(test)]
    pub fn pending(&self) -> usize {
        self.pending.borrow().len()
    }
}

impl LedgerStore for NodeLedger {
    fn reserve(
        &self,
        scope: &str,
        contribution: u64,
        budget: u64,
        now: u64,
    ) -> Result<Reservation, Refusal> {
        let id = self.next_id();
        let reservation = self.mutate(scope, now, |state| {
            state.check(scope, contribution, budget)?;
            Ok(state.hold(id, scope, contribution, now, self.ttl))
        })?;
        self.stats.borrow_mut().active += 1;
        Ok(reservation)
    }

    fn force_reserve(
        &self,
        scope: &str,
        contribution: u64,
        now: u64,
    ) -> Result<Reservation, Refusal> {
        self.force_reserve_checked(scope, contribution, u64::MAX, now)
            .map(|(reservation, _)| reservation)
    }

    fn force_reserve_checked(
        &self,
        scope: &str,
        contribution: u64,
        budget: u64,
        now: u64,
    ) -> Result<(Reservation, bool), Refusal> {
        let id = self.next_id();
        let reservation = self.mutate(scope, now, |state| {
            Ok(state.hold(id, scope, contribution, now, self.ttl))
        })?;
        self.stats.borrow_mut().active += 1;
        let breached = reservation.total > budget;
        Ok((reservation, breached))
    }

    fn commit(&self, reservation: &Reservation, now: u64) -> Settlement {
        self.drain_pending(now);
        let outcome = match self.try_settle(reservation, now, true, SETTLE_RETRIES) {
            Ok(outcome) => outcome,
            Err(_) => {
                self.pending.borrow_mut().push_back(reservation.clone());
                Settlement::Deferred
            }
        };
        count_settlement(&mut self.stats.borrow_mut(), outcome);
        outcome
    }

    fn release(&self, reservation: &Reservation, now: u64) -> Settlement {
        self.drain_pending(now);
        // A release that cannot be written stays held until reclaimed.
        let outcome = self
            .try_settle(reservation, now, false, SETTLE_RETRIES)
            .unwrap_or(Settlement::Deferred);
        count_settlement(&mut self.stats.borrow_mut(), outcome);
        outcome
    }

    fn record(&self, scope: &str, contribution: u64, now: u64) -> Result<(), Refusal> {
        self.mutate(scope, now, |state| {
            state.record(contribution);
            Ok(())
        })
    }

    #[cfg(test)]
    fn snapshot(&self, scope: &str) -> Snapshot {
        match self.read(&self.key(scope)) {
            Ok(Read::Live(state, _)) => state.snapshot(),
            _ => Snapshot {
                committed: 0,
                reserved: 0,
            },
        }
    }

    fn stats(&self) -> LedgerStats {
        *self.stats.borrow()
    }

    #[cfg(test)]
    fn scope_count(&self) -> usize {
        self.store
            .keys()
            .unwrap_or_default()
            .iter()
            .filter(|key| matches!(self.read(key), Ok(Read::Live(..))))
            .count()
    }
}

/// `KvStore` over PDK local shared data, through the synchronous
/// `blocking()` handle (the ledger runs inside one filter callback).
pub struct PdkStore(pub pdk::data_storage::LocalDataStorage);

impl KvStore for PdkStore {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, String)>, StoreError> {
        use pdk::data_storage::BlockingDataStorage;
        self.0
            .blocking()
            .get::<Vec<u8>>(key)
            .map_err(|_| StoreError::Failed)
    }

    fn put(&self, key: &str, mode: Put<'_>, value: &[u8]) -> Result<(), StoreError> {
        use pdk::data_storage::{BlockingDataStorage, DataStorageError, StoreMode};
        let mode = match mode {
            Put::Absent => StoreMode::Absent,
            Put::Cas(cas) => StoreMode::Cas(cas.to_string()),
        };
        match self.0.blocking().store(key, &mode, &value.to_vec()) {
            Ok(()) => Ok(()),
            Err(DataStorageError::CasMismatch) => Err(StoreError::CasMismatch),
            Err(_) => Err(StoreError::Failed),
        }
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        use pdk::data_storage::BlockingDataStorage;
        self.0
            .blocking()
            .delete(key)
            .map_err(|_| StoreError::Failed)
    }

    fn keys(&self) -> Result<Vec<String>, StoreError> {
        use pdk::data_storage::BlockingDataStorage;
        self.0.blocking().get_keys().map_err(|_| StoreError::Failed)
    }
}

/// A random 64-bit id prefix for this worker, from the standard library's
/// randomly keyed hasher, seeded from the host's random source.
pub fn random_prefix() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write(b"aggregate-risk-gate reservation id prefix");
    hasher.finish()
}

/// An in-memory `KvStore` with Envoy's shared-data semantics, for tests. Clones
/// share one map, so two `NodeLedger`s over clones behave as two workers of
/// one replica. Hooks run just before a `put` reaches the map, which lets a
/// test interleave another worker's whole operation between this worker's
/// read and its CAS.
#[cfg(test)]
pub mod fake {
    use super::{KvStore, Put, StoreError};
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::rc::Rc;

    type Hook = Box<dyn FnOnce()>;

    #[derive(Default)]
    struct Inner {
        map: HashMap<String, (Vec<u8>, u32)>,
        next_cas: u32,
        hooks: VecDeque<Hook>,
        forced_mismatches: u32,
        failing: bool,
        ops: u64,
    }

    #[derive(Clone, Default)]
    pub struct FakeStore(Rc<RefCell<Inner>>);

    impl FakeStore {
        /// Runs `hook` just before the next `put`.
        pub fn before_next_put(&self, hook: impl FnOnce() + 'static) {
            self.0.borrow_mut().hooks.push_back(Box::new(hook));
        }

        /// Makes the next `n` puts fail with a CAS mismatch.
        pub fn force_mismatches(&self, n: u32) {
            self.0.borrow_mut().forced_mismatches = n;
        }

        /// Makes every operation fail with a storage error.
        pub fn set_failing(&self, failing: bool) {
            self.0.borrow_mut().failing = failing;
        }

        /// How many operations have reached the store.
        pub fn ops(&self) -> u64 {
            self.0.borrow().ops
        }

        fn enter(&self) -> Result<(), StoreError> {
            let mut inner = self.0.borrow_mut();
            inner.ops += 1;
            if inner.failing {
                return Err(StoreError::Failed);
            }
            Ok(())
        }
    }

    impl KvStore for FakeStore {
        fn get(&self, key: &str) -> Result<Option<(Vec<u8>, String)>, StoreError> {
            self.enter()?;
            Ok(self
                .0
                .borrow()
                .map
                .get(key)
                .map(|(value, cas)| (value.clone(), cas.to_string())))
        }

        fn put(&self, key: &str, mode: Put<'_>, value: &[u8]) -> Result<(), StoreError> {
            let hook = self.0.borrow_mut().hooks.pop_front();
            if let Some(hook) = hook {
                hook();
            }
            self.enter()?;
            let mut inner = self.0.borrow_mut();
            if inner.forced_mismatches > 0 {
                inner.forced_mismatches -= 1;
                return Err(StoreError::CasMismatch);
            }
            let current = inner.map.get(key).map(|(_, cas)| *cas);
            match (mode, current) {
                (Put::Absent, Some(_)) => return Err(StoreError::CasMismatch),
                (Put::Cas(cas), Some(current)) if cas != current.to_string() => {
                    return Err(StoreError::CasMismatch)
                }
                // Like Envoy, a CAS on a missing key creates it.
                _ => {}
            }
            inner.next_cas += 1;
            let cas = inner.next_cas;
            inner.map.insert(key.to_string(), (value.to_vec(), cas));
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.enter()?;
            self.0.borrow_mut().map.remove(key);
            Ok(())
        }

        fn keys(&self) -> Result<Vec<String>, StoreError> {
            self.enter()?;
            Ok(self.0.borrow().map.keys().cloned().collect())
        }
    }
}

#[cfg(test)]
mod test {
    use super::fake::FakeStore;
    use super::*;
    use std::rc::Rc;

    const TTL: u64 = 60_000;
    const DAY: u64 = 86_400_000;

    /// One "worker": a node ledger over a clone of the shared fake store.
    fn worker(store: &FakeStore, prefix: u64) -> NodeLedger {
        worker_with(store, prefix, 10_000, None)
    }

    fn worker_with(
        store: &FakeStore,
        prefix: u64,
        max_scopes: usize,
        window: Option<u64>,
    ) -> NodeLedger {
        NodeLedger::new(
            Box::new(store.clone()),
            b"test-key".to_vec(),
            max_scopes,
            TTL,
            window,
            prefix,
        )
    }

    #[test]
    fn two_workers_racing_on_every_write_never_exceed_the_joint_budget() {
        // Case 8 in miniature: budget 3000, weight 800, so exactly 3 fit.
        // Before each of A's writes, worker B runs a whole reservation, so
        // every write A attempts is against a version B already replaced.
        let store = FakeStore::default();
        let a = Rc::new(worker(&store, 1));
        let b = Rc::new(worker(&store, 2));
        let mut admitted = 0;
        for _ in 0..5 {
            let other = Rc::clone(&b);
            let raced = Rc::new(std::cell::Cell::new(None));
            let slot = Rc::clone(&raced);
            store.before_next_put(move || slot.set(Some(other.reserve("s", 800, 3000, 0).is_ok())));
            let mine = a.reserve("s", 800, 3000, 0);
            admitted += usize::from(mine.is_ok()) + usize::from(raced.get() == Some(true));
        }
        assert_eq!(admitted, 3);
        assert_eq!(a.snapshot("s").total(), 2400);
        assert_eq!(b.snapshot("s").total(), 2400);
        assert_eq!(a.scope_count(), 1);
    }

    #[test]
    fn interleaved_workers_admit_exactly_what_fits() {
        let store = FakeStore::default();
        let workers: Vec<NodeLedger> = (0..4).map(|i| worker(&store, i)).collect();
        let admitted = (0..200)
            .filter(|i| workers[i % 4].reserve("s", 800, 3000, 0).is_ok())
            .count();
        assert_eq!(admitted, 3);
    }

    #[test]
    fn persistent_cas_mismatch_refuses_as_contention_and_reserves_nothing() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        store.force_mismatches(u32::MAX);
        assert_eq!(a.reserve("s", 800, 3000, 0), Err(Refusal::Contention));
        assert_eq!(
            a.force_reserve_checked("s", 800, 3000, 0),
            Err(Refusal::Contention)
        );
        assert_eq!(a.record("s", 800, 0), Err(Refusal::Contention));
        assert_eq!(a.stats().contended, 3);
        store.force_mismatches(0);
        assert_eq!(a.snapshot("s").total(), 0);
        assert_eq!(a.scope_count(), 0);
        // No slot leaked: a one-scope ledger still takes a new scope.
        let one = worker_with(&store, 2, 1, None);
        assert!(one.reserve("t", 1, 10, 0).is_ok());
    }

    #[test]
    fn a_storage_error_is_unavailable_and_reserves_nothing() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        store.set_failing(true);
        assert_eq!(a.reserve("s", 800, 3000, 0), Err(Refusal::Unavailable));
        assert_eq!(a.record("s", 0, 0), Err(Refusal::Unavailable));
        store.set_failing(false);
        assert_eq!(a.snapshot("s").total(), 0);
    }

    #[test]
    fn a_reservation_made_on_one_worker_settles_on_another_exactly_once() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        assert_eq!(b.commit(&r, 1), Settlement::Committed);
        assert_eq!(a.commit(&r, 2), Settlement::NotActive, "duplicate");
        assert_eq!(b.release(&r, 3), Settlement::NotActive, "crossed");
        assert_eq!(a.snapshot("s").committed, 800);
        assert_eq!(a.snapshot("s").reserved, 0);

        // Reordered: the release lands first and wins; the commit is a no-op.
        let r = b.reserve("s", 800, 3000, 4).unwrap();
        assert_eq!(a.release(&r, 5), Settlement::Released);
        assert_eq!(b.commit(&r, 6), Settlement::NotActive);
        assert_eq!(a.snapshot("s").total(), 800);
    }

    #[test]
    fn a_late_settlement_on_another_worker_follows_the_tombstone_rules() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        let late = a.reserve("s", 800, 3000, 0).unwrap();
        let gone = a.reserve("s", 800, 3000, 0).unwrap();
        // B touches the scope after the deadline: both are reclaimed.
        assert!(b.record("s", 0, TTL).is_ok());
        assert_eq!(b.snapshot("s").total(), 0);
        assert_eq!(b.stats().expired, 2);
        // A late commit on B is still charged; a late release changes nothing.
        assert_eq!(b.commit(&late, TTL + 1), Settlement::LateCommitted);
        assert_eq!(a.release(&gone, TTL + 1), Settlement::LateReleased);
        assert_eq!(a.snapshot("s").committed, 800);
        // After the tombstone window it is too late.
        assert_eq!(a.commit(&gone, 3 * TTL), Settlement::NotActive);
        assert_eq!(a.snapshot("s").committed, 800);
    }

    #[test]
    fn reservation_ids_are_unique_across_workers() {
        let store = FakeStore::default();
        let a = worker(&store, random_prefix());
        let b = worker(&store, random_prefix());
        let ra = a.reserve("s", 1, 100, 0).unwrap();
        let rb = b.reserve("s", 1, 100, 0).unwrap();
        assert_ne!(ra.id, rb.id);
        assert_ne!(ra.id >> 64, rb.id >> 64, "random per-worker prefixes");
        // Settling A's id never touches B's reservation.
        assert_eq!(b.commit(&ra, 1), Settlement::Committed);
        assert_eq!(a.snapshot("s").reserved, 1);
    }

    #[test]
    fn the_shared_store_never_holds_a_raw_identity() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        a.reserve("agent:broker-7", 1, 100, 0).unwrap();
        let keys = store.keys().unwrap();
        assert!(
            keys.iter().all(|key| !key.contains("broker-7")),
            "{:?}",
            keys
        );
        assert!(keys.iter().any(|key| key.len() == SCOPE_PREFIX.len() + 64));
        // A different digest key gives a different ledger key.
        let other = NodeLedger::new(Box::new(store.clone()), b"x".to_vec(), 10, TTL, None, 3);
        assert_ne!(a.key("agent:broker-7"), other.key("agent:broker-7"));
    }

    #[test]
    fn a_window_rollover_resets_committed_exposure_for_every_worker() {
        let store = FakeStore::default();
        let a = worker_with(&store, 1, 10, Some(DAY));
        let b = worker_with(&store, 2, 10, Some(DAY));
        let r = a.reserve("s", 3000, 3000, 0).unwrap();
        b.commit(&r, 1);
        assert!(b.reserve("s", 1, 3000, DAY - 1).is_err());
        assert!(b.reserve("s", 3000, 3000, DAY).is_ok());
        assert_eq!(a.snapshot("s").committed, 0);
    }

    #[test]
    fn at_the_node_cap_an_idle_scope_is_swept_and_live_state_is_kept() {
        let store = FakeStore::default();
        let a = worker_with(&store, 1, 2, None);
        let b = worker_with(&store, 2, 2, None);
        let live = a.reserve("live", 5, 100, 0).unwrap();
        a.commit(&live, 0);
        let idle = b.reserve("idle", 5, 100, 0).unwrap();
        b.release(&idle, 0);
        // A new scope at the cap: refused until the release's sweep hint is
        // due (at most one sweep per MIN_RESCAN_MS), then B sweeps "idle"
        // away and takes its slot.
        assert_eq!(b.reserve("new", 1, 100, 1), Err(Refusal::AtCapacity));
        assert!(b.reserve("new", 1, 100, MIN_RESCAN_MS).is_ok());
        assert_eq!(a.snapshot("live").committed, 5, "live state kept");
        assert_eq!(a.snapshot("idle").total(), 0);
        assert_eq!(a.scope_count(), 2);
        // Every tracked scope is live: refused, and nothing is evicted.
        assert_eq!(
            a.reserve("another", 1, 100, 3 * MIN_RESCAN_MS),
            Err(Refusal::AtCapacity)
        );
        assert_eq!(a.scope_count(), 2);
        assert_eq!(a.snapshot("live").committed, 5);
    }

    #[test]
    fn stale_keys_are_deleted_by_the_periodic_collection() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let r = a.reserve("s", 5, 100, 0).unwrap();
        a.release(&r, 0);
        let scope_keys = |store: &FakeStore| {
            store
                .keys()
                .unwrap()
                .iter()
                .filter(|key| key.starts_with(SCOPE_PREFIX))
                .count()
        };
        assert_eq!(scope_keys(&store), 1);
        // First collection: the idle scope becomes a Vacant tombstone.
        a.record("other", 0, GC_INTERVAL_MS).unwrap();
        // A later collection, past the grace period, deletes both.
        a.record("third", 0, 3 * GC_INTERVAL_MS).unwrap();
        a.record("third", 0, 5 * GC_INTERVAL_MS).unwrap();
        assert_eq!(a.snapshot("s").total(), 0);
        assert_eq!(scope_keys(&store), 1, "only the live scope remains");
    }

    #[test]
    fn a_doomed_record_is_never_written_over() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let key = a.key("s");
        store
            .put(
                &key,
                Put::Absent,
                &encode(&Record::Doomed { at: 0 }).unwrap(),
            )
            .unwrap();
        // While the sweep that doomed it may still be running: refused.
        assert_eq!(a.reserve("s", 1, 100, 1), Err(Refusal::Contention));
        // Once it is surely done, the writer deletes it and proceeds.
        assert!(a.reserve("s", 1, 100, GRACE_MS).is_ok());
    }

    #[test]
    fn a_refusal_at_the_node_cap_costs_a_constant_number_of_store_reads() {
        const LIVE: usize = 1_000;
        let store = FakeStore::default();
        let a = worker_with(&store, 1, LIVE, None);
        for i in 0..LIVE {
            let r = a.reserve(&format!("live-{i}"), 1, 10, 0).unwrap();
            a.commit(&r, 0);
        }
        // The first refusal may sweep once (nothing is idle, so it frees
        // nothing); every later one within the rescan interval is O(1).
        assert_eq!(a.reserve("new-0", 1, 10, 1), Err(Refusal::AtCapacity));
        let before = store.ops();
        for i in 1..=100 {
            assert_eq!(
                a.reserve(&format!("new-{i}"), 1, 10, 2),
                Err(Refusal::AtCapacity)
            );
        }
        let per_refusal = (store.ops() - before) / 100;
        assert!(per_refusal <= 3, "{} store ops per refusal", per_refusal);
        assert_eq!(a.scope_count(), LIVE);
    }

    #[test]
    fn a_settlement_that_leaves_a_scope_idle_lets_the_next_new_scope_in() {
        let store = FakeStore::default();
        let a = worker_with(&store, 1, 1, None);
        let r = a.reserve("a", 5, 100, 0).unwrap();
        assert_eq!(a.reserve("b", 1, 100, 1), Err(Refusal::AtCapacity));
        a.release(&r, 2);
        assert!(a.reserve("b", 1, 100, MIN_RESCAN_MS + 1).is_ok());
    }

    #[test]
    fn a_commit_that_cannot_be_written_is_queued_not_lost() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        store.force_mismatches(u32::MAX);
        assert_eq!(a.commit(&r, 1), Settlement::Deferred);
        assert_eq!(a.pending(), 1);
        // Held, not lost: the reservation still counts.
        store.force_mismatches(0);
        assert_eq!(b.snapshot("s").total(), 800);
        // A's next call writes the queued commit first.
        a.record("other", 0, 2).unwrap();
        assert_eq!(a.pending(), 0);
        assert_eq!(b.snapshot("s").committed, 800);
        assert_eq!(a.stats().committed, 1);
        assert_eq!(a.stats().deferred, 1);
    }

    #[test]
    fn a_release_that_cannot_be_written_stays_held_until_reclaimed() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        store.set_failing(true);
        assert_eq!(a.release(&r, 1), Settlement::Deferred);
        store.set_failing(false);
        assert_eq!(a.snapshot("s").reserved, 800, "an over-count, not lost");
        assert!(a.record("s", 0, TTL).is_ok());
        assert_eq!(a.snapshot("s").reserved, 0, "freed at the timeout");
    }

    #[test]
    fn a_long_commit_queue_refuses_new_reservations() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let held: Vec<Reservation> = (0..PENDING_LIMIT)
            .map(|i| a.reserve(&format!("s{i}"), 1, 10, 0).unwrap())
            .collect();
        store.set_failing(true);
        for r in &held {
            assert_eq!(a.commit(r, 1), Settlement::Deferred);
        }
        store.set_failing(false);
        store.force_mismatches(u32::MAX);
        assert_eq!(a.reserve("new", 1, 10, 2), Err(Refusal::Contention));
        store.force_mismatches(0);
        // Once the queue drains below the limit, reservations resume.
        while a.pending() >= PENDING_LIMIT {
            let _ = a.reserve("new", 1, 10, 3);
        }
        assert!(a.reserve("new", 1, 10, 3).is_ok());
    }
}
