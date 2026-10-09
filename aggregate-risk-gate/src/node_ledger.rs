// Copyright 2026 msaleme. Licensed under the MIT License.
//
// The node-wide ledger (`ledgerBackend: node`, P4A review #48): the same scope
// state as the per-worker `Ledger`, held in the gateway's node-local shared data
// so that every Envoy worker of one gateway replica checks and reserves against
// ONE budget.
//
// Each worker is its own single-threaded VM; the shared data is process-wide and
// offers get, a compare-and-swap set (`StoreMode::Cas`), a create-only set
// (`StoreMode::Absent`) and an unconditional delete. On Flex the delete is a
// real removal (verified by reading the PDK 1.10 source: `remove_shared_data_key`);
// a zero-length value, which only PDK's wasm stub writes, reads as absent (see
// `non_empty` and `read_value`). Every ledger write here is
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
// `n` holds how many scope records are counted against `maxScopes`, `sweep`
// coordinates cleanup, and `c:` + id is a reservation's commit marker. Every
// key starts with a fingerprint, the first 8 bytes of HMAC-SHA256(scopeDigestKey,
// "ledger-config-v1\0" || window length), so changing the digest key or the
// window starts a fresh ledger (records, slot count, sweep state) instead of
// reusing records it can no longer reach (a new key) or would remap to other
// periods (a new window), which would otherwise hold their `maxScopes` slots
// for good. The old ledger's keys are left in place (another instance may share
// the namespace) until the gateway restarts.
//
// Capacity and cleanup (P4A review #49 A, node side). A new scope takes a slot
// by CAS-incrementing `n`. At the cap, a refusal reads `n` and `sweep` and stops:
// O(1). Only once `sweep.not_before` has passed does one worker claim the sweep
// (by CAS on `sweep`) and scan the namespace, so a flood of new identities costs
// at most one O(n) scan per `MIN_RESCAN_MS` per replica. A scan turns each idle
// scope into a `Vacant` tombstone by CAS (a concurrent writer's CAS then fails
// and it retries) and frees its slot; a `Vacant` record older than `GRACE_MS` is
// CAS'd to `Doomed`, which no writer ever writes over, and deleted at once by the
// sweep that won that CAS and by nobody else (if the delete fails, that sweep
// CASes it back to `Vacant`; a `Doomed` left older than `RECOVER_MS` is CAS'd
// back to `Vacant`, never deleted). Tombstones are stamped and aged on the
// store's clock read at that moment, not on the request's possibly stale `now`.
// Live state is never evicted. The same scan runs every `GC_INTERVAL_MS` so
// stale keys are deleted even below the cap.
//
// Every touch, including one whose call is then refused or settles
// `NotActive`, saves its roll and reclaim (by CAS) whenever they changed the
// record, exactly as the worker ledger does under its lock, so tombstones are
// dropped at the same moments on both backends.
//
// Reservation ids carry a random 64-bit per-worker prefix and a counter, so a
// reservation made on worker A can be settled by id on worker B (the response
// may run on either), and the #17 rules hold unchanged: settle at most once,
// late settlement while the tombstone is held, `NotActive` otherwise.
//
// Settlement exhaustion is safe by direction. A commit that cannot be written is
// queued on this worker and retried at the start of its next ledger calls. It is
// also written to the reservation's commit marker (`Absent`/CAS), and every
// touch that takes a reservation off a record (expiring it at its deadline, or
// dropping its tombstone) first claims its marker by CAS: if the marker holds a
// commit, the touch charges it instead. A marker write and a claim race on one
// key, so exactly one wins and the other re-reads: a commit marked before the
// tombstone is dropped is in the total at every moment, whether or not the
// committing worker ever runs again or keeps its queue across a VM restart
// (P4A review M2). The queue copy then finds the reservation gone and adds
// nothing. A commit that could not be marked (the tombstone was already dropped,
// the tombstone window has passed, or the store failed) is queue-only, and the
// queue charges it even if its reservation has meanwhile been reclaimed and
// dropped; while that queue is long, new reservations are refused. A PDK timer
// was the alternative, but it lives in the same VM (lost on restart, idle with
// it) and is async; there is no synchronous sleep either, so retries do not back
// off. A commit
// whose record reads as missing while the reservation could still be on it (PDK
// reports a host read error as "no value") is charged too, never dropped. A
// release that cannot be written leaves the reservation held until it is
// reclaimed: an over-count that frees itself after the timeout.
//
// Known edges, documented rather than hidden:
// - The commit queue lives in the worker's VM and is lost if the VM restarts;
//   only an unmarked (queue-only) commit is lost with it.
// - A marked commit charged by another worker at the deadline lands in that
//   moment's window period, and a put that reported failure but landed is
//   charged twice: over-counts. A committer stalled for longer than `ttl`
//   between its marker read and its marker write, across a sweep that deleted
//   the marker, could write a marker nothing charges. Each step is a
//   back-to-back host call.
// - Every reservation that expires leaves a marker key, deleted by a sweep once
//   `expires_at + 2 × ttl + GRACE_MS` has passed and its record no longer holds
//   it.
// - A duplicate commit whose first read hits a host error (reported as "no
//   value") is charged again as a late commit: an over-count, never an under.
// - A slot whose decrement exhausts its retries stays counted, and nothing
//   recounts `n`: fewer scopes fit, never more state evicted.
// - A writer that stalls between its get and its CAS across a whole sweep could
//   re-create a deleted record without a slot; a sweep stalled for longer than
//   `RECOVER_MS` between its `Doomed` CAS and its delete could delete a record
//   re-created after recovery. Single-threaded VMs make both very unlikely.
// - Workers sharing an explicit `ledgerNamespace` must share the digest key,
//   `ttl`, `window` and `maxScopes`; nothing checks that. Rotating the key or
//   changing the window gives every identity a fresh budget.
// - With no window, a scope with committed exposure is never idle, so it keeps
//   its slot until the gateway restarts.
// - A host storage status other than ok or CAS mismatch panics inside PDK.
// - One hot scope serialises every worker on one key. A record grows with its
//   in-flight reservations up to `MAX_HELD` entries (then `Saturated`).
// - The sweep scans every key of the namespace inline in the call that runs it
//   (at most once per `MIN_RESCAN_MS`).
//
// Scope of the guarantee: one budget per policy instance per gateway REPLICA,
// reset when the gateway process restarts. Not shared across replicas, not
// durable.

#[cfg(test)]
use crate::ledger::Snapshot;
use crate::ledger::{
    count_reclaim, count_settlement, expired_on_arrival, period, settle_free, LedgerStats,
    LedgerStore, Refusal, Reservation, ReservationId, ScopeState, Settlement,
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
const MISSING_RECORD_ATTEMPTS: u8 = 3;
/// How long a `Vacant` tombstone is kept before it is deleted.
const GRACE_MS: u64 = 30_000;
/// A `Doomed` record this old was left by a sweep that never finished its
/// delete; a later sweep turns it back into `Vacant` (by CAS, never a delete).
const RECOVER_MS: u64 = 600_000;
/// The shortest gap between two capacity sweeps on one replica.
const MIN_RESCAN_MS: u64 = 1_000;
/// The longest a full ledger waits before it rescans.
const MAX_RESCAN_MS: u64 = 30_000;
/// How often stale keys are collected below the cap.
const GC_INTERVAL_MS: u64 = 60_000;

/// Read/claim attempts on one reservation's commit marker.
const MARKER_RETRIES: u32 = 4;

// Every key below sits under the ledger's configuration fingerprint (see
// `NodeLedger::new`).
const SCOPE_PREFIX: &str = "s:";
const MARKER_PREFIX: &str = "c:";
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
    /// The current time in epoch milliseconds, read at the moment of the
    /// call: the gateway clock, re-read at reserve time. The tombstone
    /// protocol uses it instead of the request's `now`, which may be older,
    /// and no reservation is made that it shows already past its deadline
    /// (#56). `0` means "no clock" and leaves the caller's `now` in force.
    fn now(&self) -> u64 {
        0
    }
}

/// A scope key's value.
#[derive(Debug, Serialize, Deserialize)]
enum Record {
    Scope(ScopeState),
    /// Swept while idle; its slot is free. Re-used by the next writer, which
    /// starts from the swept scope's window `period` (so a writer whose `now`
    /// is a little stale cannot land a commit in an earlier period).
    Vacant {
        since: u64,
        #[serde(default)]
        period: u64,
    },
    /// Being deleted by the sweep that wrote it at `at`. No writer writes
    /// over it and only that sweep deletes it.
    Doomed {
        at: u64,
        #[serde(default)]
        period: u64,
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

/// A reservation's commit marker, under `c:` + its id: the shared record of a
/// commit that could not be written to the scope record, and of the touches
/// that took the reservation off the record without charging it.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
enum Mark {
    /// A commit that could not be written. Whichever touch next takes the
    /// reservation off the record (at its deadline or when its tombstone is
    /// dropped) charges it instead.
    Commit,
    /// A touch reclaimed the reservation at its deadline, uncharged.
    Expired,
    /// A touch dropped the reservation's tombstone, uncharged. A commit that
    /// finds this is past the tombstone window and is queued on its worker.
    Dropped,
}

#[derive(Debug, Serialize, Deserialize)]
struct Marker {
    mark: Mark,
    /// The scope record the reservation is on.
    key: String,
    id: ReservationId,
    expires_at: u64,
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
    /// No record, or a `Vacant` one (with its CAS and window period): a new
    /// scope that needs a slot.
    New(Option<String>, u64),
    Live(ScopeState, String),
    Doomed,
}

/// A commit queued on this worker.
struct Pending {
    reservation: Reservation,
    /// Its commit marker was written: a later touch charges it even if this
    /// worker never runs again, so the queue only lands it sooner.
    persisted: bool,
    missing_record_attempts: u8,
}

/// hex(HMAC-SHA256(`secret`, `parts`...)).
fn hmac_hex(secret: &[u8], parts: &[&[u8]]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts a key of any length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The node-wide ledger. One per policy instance per worker, all sharing one
/// namespace of the replica's shared data.
pub struct NodeLedger {
    store: Box<dyn KvStore>,
    key_secret: Vec<u8>,
    /// The configuration fingerprint every key starts with.
    prefix: String,
    max_scopes: u64,
    ttl: u64,
    window: Option<u64>,
    /// The high 64 bits of every id this worker issues.
    id_prefix: u64,
    next_id: Cell<u64>,
    stats: RefCell<LedgerStats>,
    /// Commits that could not be written yet.
    pending: RefCell<VecDeque<Pending>>,
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
        // Keys sit under a fingerprint of the settings that decide which
        // record a scope maps to and which window period it is in, so a
        // reconfiguration that changes them starts a fresh ledger (records,
        // slot count and sweep state) instead of reusing records it can no
        // longer interpret or reach.
        let window_ms = window.unwrap_or(0).to_le_bytes();
        let fingerprint = hmac_hex(&key_secret, &[b"ledger-config-v1\0", &window_ms]);
        NodeLedger {
            store,
            prefix: format!("{}/", &fingerprint[..16]),
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
        let hex = hmac_hex(&self.key_secret, &[b"ledger-key-v1\0", scope.as_bytes()]);
        format!("{}{SCOPE_PREFIX}{hex}", self.prefix)
    }

    fn count_key(&self) -> String {
        format!("{}{COUNT_KEY}", self.prefix)
    }

    fn sweep_key(&self) -> String {
        format!("{}{SWEEP_KEY}", self.prefix)
    }

    fn marker_key(&self, id: ReservationId) -> String {
        format!("{}{MARKER_PREFIX}{id:032x}", self.prefix)
    }

    fn read_marker(&self, id: ReservationId) -> Result<Option<(Marker, String)>, StoreError> {
        Ok(match self.store.get(&self.marker_key(id))? {
            None => None,
            Some((bytes, cas)) => Some((decode::<Marker>(&bytes)?, cas)),
        })
    }

    fn put_marker(&self, marker: &Marker, cas: Option<&str>) -> Result<(), StoreError> {
        let mode = cas.map_or(Put::Absent, Put::Cas);
        self.store
            .put(&self.marker_key(marker.id), mode, &encode(marker)?)
    }

    /// Before a touch takes reservation `id` off record `key` uncharged, at
    /// its deadline (`tombstone` false) or by dropping its tombstone (true),
    /// stamps that on the reservation's marker. Returns `true` instead if the
    /// marker holds a commit, which the caller then charges. Every step is an
    /// `Absent` or CAS write, so a commit marker written concurrently is
    /// either seen here or fails and sees this claim.
    fn claim(
        &self,
        key: &str,
        id: ReservationId,
        expires_at: u64,
        tombstone: bool,
    ) -> Result<bool, StoreError> {
        for _ in 0..MARKER_RETRIES {
            let cas = match self.read_marker(id)? {
                Some((marker, _)) if marker.mark == Mark::Commit => return Ok(true),
                Some((marker, _)) if marker.mark == Mark::Dropped || !tombstone => {
                    return Ok(false)
                }
                Some((_, cas)) => Some(cas),
                None => None,
            };
            let marker = Marker {
                mark: if tombstone {
                    Mark::Dropped
                } else {
                    Mark::Expired
                },
                key: key.to_string(),
                id,
                expires_at,
            };
            match self.put_marker(&marker, cas.as_deref()) {
                Ok(()) => return Ok(false),
                Err(StoreError::CasMismatch) => continue,
                Err(err) => return Err(err),
            }
        }
        Err(StoreError::CasMismatch)
    }

    /// Runs `claim` for every entry a reclaim of `state` at `now` would take
    /// off the record, and commits those whose marker holds a commit.
    /// Returns how many it committed.
    fn reconcile(&self, key: &str, state: &mut ScopeState, now: u64) -> Result<u64, StoreError> {
        let mut charged = 0;
        for (id, expires_at, tombstone) in state.due(now, self.ttl) {
            if self.claim(key, id, expires_at, tombstone)? {
                state.settle(id, true);
                charged += 1;
            }
        }
        Ok(charged)
    }

    /// Writes a commit marker for `reservation`, whose commit could not be
    /// written to its record. Returns whether it is now persisted. Not once
    /// the tombstone window has passed on the store clock (a sweep may then
    /// collect markers), nor once a touch has dropped the tombstone.
    fn persist_commit(&self, reservation: &Reservation, now: u64) -> bool {
        let clock = now.max(self.store.now());
        if clock >= reservation.expires_at.saturating_add(self.ttl) {
            return false;
        }
        let marker = Marker {
            mark: Mark::Commit,
            key: self.key(&reservation.scope),
            id: reservation.id,
            expires_at: reservation.expires_at,
        };
        for _ in 0..MARKER_RETRIES {
            let cas = match self.read_marker(reservation.id) {
                Ok(None) => None,
                Ok(Some((found, _))) if found.mark == Mark::Commit => return true,
                Ok(Some((found, cas))) if found.mark == Mark::Expired => Some(cas),
                _ => return false,
            };
            match self.put_marker(&marker, cas.as_deref()) {
                Ok(()) => return true,
                Err(StoreError::CasMismatch) => continue,
                Err(StoreError::Failed) => return false,
            }
        }
        false
    }

    /// Deletes marker `key` once no record can still hold its reservation:
    /// past `expires_at + 2 × ttl + GRACE_MS` on the store clock, and gone
    /// from its scope record.
    fn collect_marker(&self, key: &str, clock: u64) {
        let Ok(Some((bytes, _))) = self.store.get(key) else {
            return;
        };
        let Ok(marker) = decode::<Marker>(&bytes) else {
            return;
        };
        let due = marker
            .expires_at
            .saturating_add(self.ttl.saturating_mul(2))
            .saturating_add(GRACE_MS);
        if clock < due {
            return;
        }
        match self.read(&marker.key) {
            Ok(Read::Live(state, _)) if state.holds(marker.id) => {}
            Ok(_) => {
                let _ = self.store.delete(key);
            }
            Err(_) => {}
        }
    }

    /// Counts a touch whose write landed.
    fn count_touch(&self, reclaimed: (u64, u64), charged: u64) {
        let mut stats = self.stats.borrow_mut();
        count_reclaim(&mut stats, reclaimed);
        stats.late_committed += charged;
    }

    /// Queued commits whose marker could not be written.
    fn unpersisted(&self) -> usize {
        self.pending
            .borrow()
            .iter()
            .filter(|entry| !entry.persisted)
            .count()
    }

    fn next_id(&self) -> ReservationId {
        let counter = self.next_id.get();
        self.next_id.set(counter.wrapping_add(1));
        (ReservationId::from(self.id_prefix) << 64) | ReservationId::from(counter)
    }

    fn read(&self, key: &str) -> Result<Read, StoreError> {
        Ok(match self.store.get(key)? {
            None => Read::New(None, 0),
            Some((bytes, cas)) => match decode::<Record>(&bytes)? {
                Record::Scope(state) => Read::Live(state, cas),
                Record::Vacant { period, .. } => Read::New(Some(cas), period),
                Record::Doomed { .. } => Read::Doomed,
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
        if self.unpersisted() >= PENDING_LIMIT {
            return Err(Refusal::Contention);
        }
        self.maybe_collect(now);
        self.mutate_core(&self.key(scope), now, RESERVE_RETRIES, f)
    }

    /// The CAS loop itself, with no draining or collection, so a queued
    /// commit can be charged through it from `drain_pending`.
    fn mutate_core<R>(
        &self,
        key: &str,
        now: u64,
        retries: u32,
        f: &mut impl FnMut(&mut ScopeState) -> Result<R, Refusal>,
    ) -> Result<R, Refusal> {
        // A refusal whose roll/reclaim could not be saved (CAS conflict):
        // the call is still refused for that reason if retries run out.
        let mut refused = None;
        for _ in 0..retries {
            let (mut state, cas, new) = match self.read(key).map_err(unavailable)? {
                // The sweep that wrote it is deleting this key: read again,
                // and be refused as contended if that never lands within the
                // retries. A writer never deletes it itself.
                Read::Doomed => continue,
                Read::New(cas, period) => (ScopeState::at_period(period), cas, true),
                Read::Live(state, cas) => (state, Some(cas), false),
            };
            let rolled = state.roll_to(period(self.window, now));
            let charged = match self.reconcile(key, &mut state, now) {
                Ok(charged) => charged,
                Err(StoreError::CasMismatch) => continue,
                Err(StoreError::Failed) => return Err(Refusal::Unavailable),
            };
            let reclaimed = state.reclaim(now, self.ttl);
            let result = match f(&mut state) {
                Ok(result) => result,
                // Refused, but the touch still counts: like the worker
                // ledger, save the roll and reclaim (which may drop an old
                // tombstone, so a later settlement of it is `NotActive`).
                Err(refusal) => {
                    if new || (!rolled && charged == 0 && reclaimed == (0, 0)) {
                        return Err(refusal);
                    }
                    match self.put_record(key, cas.as_deref(), &Record::Scope(state)) {
                        Ok(()) => {
                            self.count_touch(reclaimed, charged);
                            return Err(refusal);
                        }
                        Err(StoreError::CasMismatch) => {
                            refused = Some(refusal);
                            continue;
                        }
                        Err(StoreError::Failed) => return Err(refusal),
                    }
                }
            };
            if new {
                self.acquire_slot(now)?;
            }
            match self.put_record(key, cas.as_deref(), &Record::Scope(state)) {
                Ok(()) => {
                    self.count_touch(reclaimed, charged);
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
        Err(refused.unwrap_or(Refusal::Contention))
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
        Ok(match self.store.get(&self.count_key())? {
            None => (0, None),
            Some((bytes, cas)) => (decode::<u64>(&bytes)?, Some(cas)),
        })
    }

    fn put_count(&self, count: u64, cas: Option<&str>) -> Result<(), StoreError> {
        let mode = cas.map_or(Put::Absent, Put::Cas);
        self.store.put(&self.count_key(), mode, &encode(&count)?)
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
        Ok(match self.store.get(&self.sweep_key())? {
            None => (Sweep::default(), None),
            Some((bytes, cas)) => (decode::<Sweep>(&bytes)?, Some(cas)),
        })
    }

    /// CAS-writes the sweep record and returns its new version.
    fn put_sweep(&self, sweep: &Sweep, cas: Option<&str>) -> Result<String, StoreError> {
        let mode = cas.map_or(Put::Absent, Put::Cas);
        self.store.put(&self.sweep_key(), mode, &encode(sweep)?)?;
        // Read back the version this worker now owns.
        match self.store.get(&self.sweep_key())? {
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
    /// `Vacant` records are deleted via `Doomed`, and commit markers no
    /// record can still need are deleted. Never touches live state.
    /// Correctness never depends on the claim being exclusive: every change
    /// is a CAS, and only a sweep's own successful conversions free slots.
    fn sweep(&self, now: u64, claim_cas: String) {
        // Tombstones are stamped and aged on the store's clock, read now:
        // the request's `now` may be stale. Scheduling stays on `now`.
        let clock = now.max(self.store.now());
        let Ok(keys) = self.store.keys() else {
            return;
        };
        let mut freed: i64 = 0;
        let mut next_idle = u64::MAX;
        let scope_prefix = format!("{}{SCOPE_PREFIX}", self.prefix);
        let marker_prefix = format!("{}{MARKER_PREFIX}", self.prefix);
        for key in &keys {
            if key.starts_with(&marker_prefix) {
                self.collect_marker(key, clock);
                continue;
            }
            if !key.starts_with(&scope_prefix) {
                continue;
            }
            let Ok(Some((bytes, cas))) = self.store.get(key) else {
                continue;
            };
            match decode::<Record>(&bytes) {
                Ok(Record::Scope(mut state)) => {
                    let mut current_cas = cas;
                    for _ in 0..MARKER_RETRIES {
                        let rolled = state.roll_to(period(self.window, now));
                        // Markers are recoverable claims. Save every reconciled
                        // record, including busy ones, using the same CAS/reload
                        // discipline as an ordinary ledger touch.
                        let Ok(charged) = self.reconcile(key, &mut state, now) else {
                            break;
                        };
                        let reclaimed = state.reclaim(now, self.ttl);
                        if !rolled && charged == 0 && reclaimed == (0, 0) && !state.is_idle() {
                            next_idle = next_idle.min(state.idle_at(self.ttl, self.window));
                            break;
                        }
                        let idle = state.is_idle();
                        let idle_at = state.idle_at(self.ttl, self.window);
                        let updated = if idle {
                            Record::Vacant {
                                since: clock,
                                period: state.period(),
                            }
                        } else {
                            Record::Scope(state)
                        };
                        match self.put_record(key, Some(&current_cas), &updated) {
                            Ok(()) => {
                                self.count_touch(reclaimed, charged);
                                if idle {
                                    freed += 1;
                                } else {
                                    next_idle = next_idle.min(idle_at);
                                }
                                break;
                            }
                            // Unsaved: still schedule a rescan for this record.
                            Err(StoreError::Failed) => {
                                next_idle = next_idle.min(idle_at);
                                break;
                            }
                            Err(StoreError::CasMismatch) => {
                                next_idle = next_idle.min(idle_at);
                                let Ok(Some((bytes, cas))) = self.store.get(key) else {
                                    break;
                                };
                                let Ok(Record::Scope(latest)) = decode::<Record>(&bytes) else {
                                    break;
                                };
                                state = latest;
                                current_cas = cas;
                            }
                        }
                    }
                }
                Ok(Record::Vacant { since, period }) => {
                    if clock >= since.saturating_add(GRACE_MS) {
                        self.delete_vacant(key, &cas, since, period, clock);
                    }
                }
                // Left behind by a sweep whose delete never landed (and whose
                // restore failed too). Deleting it here could remove a record
                // re-created after that sweep's own delete, so it is only
                // ever CAS'd back to `Vacant`, for a later sweep to retry.
                Ok(Record::Doomed { at, period }) => {
                    if clock >= at.saturating_add(RECOVER_MS) {
                        let vacant = Record::Vacant {
                            since: clock,
                            period,
                        };
                        let _ = self.put_record(key, Some(&cas), &vacant);
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

    /// Deletes a `Vacant` record: CAS it to `Doomed` (so no writer re-uses
    /// it meanwhile), then delete it at once. Only the sweep that won that
    /// CAS deletes; if its delete fails it puts the `Vacant` record back.
    fn delete_vacant(&self, key: &str, cas: &str, since: u64, period: u64, now: u64) {
        let doomed = Record::Doomed { at: now, period };
        if self.put_record(key, Some(cas), &doomed).is_err() {
            return;
        }
        if self.store.delete(key).is_ok() {
            return;
        }
        if let Ok(Some((_, cas))) = self.store.get(key) {
            let vacant = Record::Vacant { since, period };
            let _ = self.put_record(key, Some(&cas), &vacant);
        }
    }

    /// One settlement attempt loop on the shared record. `Ok(None)` means
    /// the scope has no live record.
    fn try_settle(
        &self,
        reservation: &Reservation,
        now: u64,
        commit: bool,
        retries: u32,
    ) -> Result<Option<Settlement>, StoreError> {
        let key = self.key(&reservation.scope);
        for _ in 0..retries {
            let (mut state, cas) = match self.read(&key)? {
                Read::Live(state, cas) => (state, cas),
                // Untracked (never created, or swept while idle).
                Read::New(..) | Read::Doomed => return Ok(None),
            };
            let rolled = state.roll_to(period(self.window, now));
            let outcome = state.settle(reservation.id, commit);
            let charged = self.reconcile(&key, &mut state, now)?;
            let reclaimed = state.reclaim(now, self.ttl);
            // Nothing changed: no write. Otherwise the roll and reclaim are
            // saved even for `NotActive`, as the worker ledger does.
            if outcome == Settlement::NotActive && !rolled && charged == 0 && reclaimed == (0, 0) {
                return Ok(Some(outcome));
            }
            let idle = state.is_idle();
            match self.put_record(&key, Some(&cas), &Record::Scope(state)) {
                Ok(()) => {
                    self.count_touch(reclaimed, charged);
                    if idle {
                        self.hint_idle(now);
                    }
                    return Ok(Some(outcome));
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

    /// Charges a commit whose reservation may no longer be on the record:
    /// settles it if it is still held, and otherwise adds its contribution
    /// to `committed` (creating the record if it is missing) as a late
    /// commit. Used for a commit that was never written (a queued one) and
    /// for one whose record is missing while the reservation could still be
    /// on it (a host read error or a sweep race), so neither is dropped.
    fn charge(
        &self,
        reservation: &Reservation,
        now: u64,
        retries: u32,
    ) -> Result<Settlement, Refusal> {
        let key = self.key(&reservation.scope);
        self.mutate_core(&key, now, retries, &mut |state| {
            Ok(match state.settle(reservation.id, true) {
                Settlement::NotActive => {
                    state.record(reservation.contribution);
                    Settlement::LateCommitted
                }
                outcome => outcome,
            })
        })
    }

    /// Retries queued commits, a few per call. An unpersisted queued commit
    /// is charged even if its reservation has meanwhile been reclaimed and
    /// dropped. A persisted one is only settled if it is still on the
    /// record: if not, a touch already charged it through its marker.
    fn drain_pending(&self, now: u64) {
        for _ in 0..DRAIN_PER_CALL {
            let Some(mut entry) = self.pending.borrow_mut().pop_front() else {
                return;
            };
            let result = if entry.persisted {
                match self.try_settle(&entry.reservation, now, true, DRAIN_RETRIES) {
                    Ok(outcome) => Ok(outcome.filter(|o| *o != Settlement::NotActive)),
                    Err(StoreError::Failed) => Err(Refusal::Unavailable),
                    Err(StoreError::CasMismatch) => Err(Refusal::Contention),
                }
            } else {
                self.charge(&entry.reservation, now, DRAIN_RETRIES)
                    .map(Some)
            };
            match result {
                Ok(Some(outcome)) => count_settlement(&mut self.stats.borrow_mut(), outcome),
                Ok(None) => {}
                // The store is down: stop, and keep the order.
                Err(Refusal::Unavailable) => {
                    self.pending.borrow_mut().push_front(entry);
                    return;
                }
                // Bound only confirmed missing-record capacity failures. An
                // outage or ordinary CAS contention must never discard a commit.
                Err(Refusal::AtCapacity)
                    if matches!(
                        self.read(&self.key(&entry.reservation.scope)),
                        Ok(Read::New(_, _))
                    ) =>
                {
                    entry.missing_record_attempts += 1;
                    if entry.missing_record_attempts >= MISSING_RECORD_ATTEMPTS {
                        pdk::logger::warn!(
                            "{}",
                            serde_json::json!({
                                "event":"aggregate_risk_pending_commit_dropped",
                                "reason":"missing-record-at-capacity",
                                "attempts":entry.missing_record_attempts
                            })
                        );
                    } else {
                        self.pending.borrow_mut().push_back(entry);
                    }
                }
                Err(_) => self.pending.borrow_mut().push_back(entry),
            }
        }
    }

    /// Queues a commit that could not be written. `on_record` says the
    /// reservation was on a live record when that failed, so a commit
    /// marker can stand in for it; otherwise only the queue can.
    fn defer(&self, reservation: &Reservation, now: u64, on_record: bool) -> Settlement {
        let persisted = on_record && self.persist_commit(reservation, now);
        let mut pending = self.pending.borrow_mut();
        // A persisted commit is safe without the queue, so it is only queued
        // (to land sooner) while there is room.
        if !persisted || pending.len() < PENDING_LIMIT {
            pending.push_back(Pending {
                reservation: reservation.clone(),
                persisted,
                missing_record_attempts: 0,
            });
        }
        Settlement::Deferred
    }

    /// Refuses a reservation that would already be past its deadline.
    fn check_fresh(&self, now: u64) -> Result<(), Refusal> {
        if expired_on_arrival(now, self.ttl, self.store.now()) {
            return Err(Refusal::Stale);
        }
        Ok(())
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
        self.check_fresh(now)?;
        let id = self.next_id();
        let reservation = self.mutate(scope, now, |state| {
            state.check(scope, contribution, budget)?;
            state.hold(id, scope, contribution, now, self.ttl)
        })?;
        if contribution > 0 {
            self.stats.borrow_mut().active += 1;
        }
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
        self.check_fresh(now)?;
        let id = self.next_id();
        let reservation = self.mutate(scope, now, |state| {
            state.hold(id, scope, contribution, now, self.ttl)
        })?;
        if contribution > 0 {
            self.stats.borrow_mut().active += 1;
        }
        let breached = reservation.total > budget;
        Ok((reservation, breached))
    }

    fn commit(&self, reservation: &Reservation, now: u64) -> Settlement {
        self.drain_pending(now);
        if let Some(outcome) = settle_free(&mut self.stats.borrow_mut(), reservation, true) {
            return outcome;
        }
        let outcome = match self.try_settle(reservation, now, true, SETTLE_RETRIES) {
            Ok(Some(outcome)) => outcome,
            // No record although the reservation (or its tombstone) would
            // still be on it: charge rather than trust the read.
            Ok(None) if now < reservation.expires_at.saturating_add(self.ttl) => self
                .charge(reservation, now, SETTLE_RETRIES)
                .unwrap_or_else(|_| self.defer(reservation, now, false)),
            Ok(None) => Settlement::NotActive,
            Err(_) => self.defer(reservation, now, true),
        };
        count_settlement(&mut self.stats.borrow_mut(), outcome);
        outcome
    }

    fn release(&self, reservation: &Reservation, now: u64) -> Settlement {
        self.drain_pending(now);
        if let Some(outcome) = settle_free(&mut self.stats.borrow_mut(), reservation, false) {
            return outcome;
        }
        // A release that cannot be written stays held until reclaimed.
        let outcome = self
            .try_settle(reservation, now, false, SETTLE_RETRIES)
            .map_or(Settlement::Deferred, |outcome| {
                outcome.unwrap_or(Settlement::NotActive)
            });
        count_settlement(&mut self.stats.borrow_mut(), outcome);
        outcome
    }

    #[cfg(test)]
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
            .filter(|key| key.starts_with(&format!("{}{SCOPE_PREFIX}", self.prefix)))
            .filter(|key| matches!(self.read(key), Ok(Read::Live(..))))
            .count()
    }
}

/// A zero-length value reads as no value. PDK local storage's
/// `StoreMode::Absent` treats an empty host value as absent and creates over
/// it (CAS against that value's version), so reading it as missing makes the
/// ledger's next write an `Absent` create that succeeds, instead of a decode
/// error that would leave the scope refused as unavailable for good.
///
/// Two layers, because `PdkStore` reads `Vec<u8>` through PDK's fixint
/// encoding (an 8-byte length prefix, then the bytes): a raw empty host value
/// fails that decode with `serde_fixint::Error::Eof`, which `read_value` maps
/// to absent; this filter catches a value that decodes to zero bytes. The
/// ledger itself never writes either: every value it stores is a non-empty
/// JSON document, so its fixint encoding is at least 9 bytes. Flex's delete
/// is a real removal (`remove_shared_data_key`); an empty value can only come
/// from PDK's wasm stub, which deletes by writing one, or another writer.
pub fn non_empty(read: Option<(Vec<u8>, String)>) -> Option<(Vec<u8>, String)> {
    read.filter(|(value, _)| !value.is_empty())
}

/// A `get::<Vec<u8>>` result from PDK local storage, with a raw empty host
/// value read as absent (see `non_empty`). `Eof` is the only error fixint
/// gives for input shorter than a `Vec<u8>`'s length prefix; the ledger's
/// whole-value writes never leave a truncated non-empty value, and one would
/// read as absent too, its `Absent` create then refused as contention rather
/// than unavailable.
pub fn read_value(
    read: Result<Option<(Vec<u8>, String)>, pdk::data_storage::DataStorageError>,
) -> Result<Option<(Vec<u8>, String)>, StoreError> {
    use pdk::data_storage::DataStorageError;
    match read {
        Ok(read) => Ok(non_empty(read)),
        Err(DataStorageError::Serialization(serde_fixint::Error::Eof)) => Ok(None),
        Err(_) => Err(StoreError::Failed),
    }
}

/// `KvStore` over PDK local shared data, through the synchronous
/// `blocking()` handle (the ledger runs inside one filter callback).
pub struct PdkStore {
    pub storage: pdk::data_storage::LocalDataStorage,
    pub clock: std::rc::Rc<pdk::hl::timer::Clock>,
}

impl KvStore for PdkStore {
    fn get(&self, key: &str) -> Result<Option<(Vec<u8>, String)>, StoreError> {
        use pdk::data_storage::BlockingDataStorage;
        read_value(self.storage.blocking().get::<Vec<u8>>(key))
    }

    fn put(&self, key: &str, mode: Put<'_>, value: &[u8]) -> Result<(), StoreError> {
        use pdk::data_storage::{BlockingDataStorage, DataStorageError, StoreMode};
        let mode = match mode {
            Put::Absent => StoreMode::Absent,
            Put::Cas(cas) => StoreMode::Cas(cas.to_string()),
        };
        match self.storage.blocking().store(key, &mode, &value.to_vec()) {
            Ok(()) => Ok(()),
            Err(DataStorageError::CasMismatch) => Err(StoreError::CasMismatch),
            Err(_) => Err(StoreError::Failed),
        }
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        use pdk::data_storage::BlockingDataStorage;
        self.storage
            .blocking()
            .delete(key)
            .map_err(|_| StoreError::Failed)
    }

    fn keys(&self) -> Result<Vec<String>, StoreError> {
        use pdk::data_storage::BlockingDataStorage;
        self.storage
            .blocking()
            .get_keys()
            .map_err(|_| StoreError::Failed)
    }

    fn now(&self) -> u64 {
        crate::epoch_ms(self.clock.now())
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
    use super::{non_empty, KvStore, Put, StoreError};
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
        failing_deletes: bool,
        hidden_gets: u32,
        contended: Option<String>,
        clock: u64,
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

        /// Makes every put to `key` fail with a CAS mismatch (`None`: none),
        /// like another worker winning that one key every time.
        pub fn contend(&self, key: Option<String>) {
            self.0.borrow_mut().contended = key;
        }

        /// Makes every operation fail with a storage error.
        pub fn set_failing(&self, failing: bool) {
            self.0.borrow_mut().failing = failing;
        }

        /// Makes every delete fail with a storage error.
        pub fn set_failing_deletes(&self, failing: bool) {
            self.0.borrow_mut().failing_deletes = failing;
        }

        /// Makes the next `n` gets read as missing, like a host read error
        /// that PDK reports as no value.
        pub fn hide_next_gets(&self, n: u32) {
            self.0.borrow_mut().hidden_gets = n;
        }

        /// Sets the store's own clock (`0` means none).
        pub fn set_now(&self, now: u64) {
            self.0.borrow_mut().clock = now;
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
            let mut inner = self.0.borrow_mut();
            if inner.hidden_gets > 0 {
                inner.hidden_gets -= 1;
                return Ok(None);
            }
            // Through the same filter as `PdkStore`.
            Ok(non_empty(
                inner
                    .map
                    .get(key)
                    .map(|(value, cas)| (value.clone(), cas.to_string())),
            ))
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
            if inner.contended.as_deref() == Some(key) {
                return Err(StoreError::CasMismatch);
            }
            // Like PDK local storage, `Absent` treats an empty value as
            // absent and creates over it.
            let current = inner
                .map
                .get(key)
                .map(|(value, cas)| (value.is_empty(), *cas));
            match (mode, current) {
                (Put::Absent, Some((false, _))) => return Err(StoreError::CasMismatch),
                (Put::Absent, Some((true, _))) => {}
                (Put::Cas(cas), Some((_, current))) if cas != current.to_string() => {
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
            let mut inner = self.0.borrow_mut();
            if inner.failing_deletes {
                return Err(StoreError::Failed);
            }
            inner.map.remove(key);
            Ok(())
        }

        fn keys(&self) -> Result<Vec<String>, StoreError> {
            self.enter()?;
            Ok(self.0.borrow().map.keys().cloned().collect())
        }

        fn now(&self) -> u64 {
            self.0.borrow().clock
        }
    }
}

#[cfg(test)]
mod test {
    use super::fake::FakeStore;
    use super::*;
    use crate::ledger::MAX_HELD;
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
        let scope_prefix = format!("{}{SCOPE_PREFIX}", a.prefix);
        assert!(keys
            .iter()
            .any(|key| key.starts_with(&scope_prefix) && key.len() == scope_prefix.len() + 64));
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
        let scope_prefix = format!("{}{SCOPE_PREFIX}", a.prefix);
        let scope_keys = |store: &FakeStore| {
            store
                .keys()
                .unwrap()
                .iter()
                .filter(|key| key.starts_with(&scope_prefix))
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
                &encode(&Record::Doomed { at: 0, period: 0 }).unwrap(),
            )
            .unwrap();
        // Only the sweep that doomed it deletes it: a writer is refused,
        // however late it is, and never deletes the key itself.
        assert_eq!(a.reserve("s", 1, 100, 1), Err(Refusal::Contention));
        assert_eq!(
            a.reserve("s", 1, 100, 10 * GRACE_MS),
            Err(Refusal::Contention)
        );
        assert!(matches!(a.read(&key), Ok(Read::Doomed)));
        // Left that long, a sweep CASes it back to Vacant and it is re-used.
        assert!(a.reserve("s", 1, 100, RECOVER_MS).is_ok());
        assert_eq!(a.snapshot("s").reserved, 1);
    }

    /// The connected case 5c sequence (TTL 1000 ms, slow call 3500 ms, touch
    /// at 2300 ms, budget 1600, weight 800) on both backends: the refused
    /// touch past two TTLs drops the slow call's tombstone, so its response
    /// settles `NotActive` and D sees would-be-total 2400.
    #[test]
    fn a_refused_touch_drops_the_tombstone_exactly_like_the_worker_ledger() {
        use crate::ledger::{Denial, Ledger};
        let store = FakeStore::default();
        let node = NodeLedger::new(Box::new(store.clone()), b"k".to_vec(), 100, 1000, None, 1);
        let worker = Ledger::with_limits(100, 1000, None);
        let backends: [(&str, &dyn LedgerStore); 2] = [("node", &node), ("worker", &worker)];
        for (name, ledger) in backends {
            let a = ledger.reserve("s", 800, 1600, 0).unwrap();
            for _ in 0..2 {
                let fast = ledger.reserve("s", 800, 1600, 1200).unwrap();
                assert_eq!(
                    ledger.commit(&fast, 1200),
                    Settlement::Committed,
                    "{}",
                    name
                );
            }
            assert!(ledger.reserve("s", 800, 1600, 2300).is_err(), "{}", name);
            assert_eq!(ledger.commit(&a, 3500), Settlement::NotActive, "{}", name);
            match ledger.reserve("s", 800, 1600, 3500) {
                Err(Refusal::OverBudget(Denial { would_be_total, .. })) => {
                    assert_eq!(would_be_total, 2400, "{}", name)
                }
                other => panic!("{}: {:?}", name, other),
            }
        }
    }

    #[test]
    fn an_empty_value_reads_as_absent_and_never_wedges_a_scope() {
        assert_eq!(non_empty(Some((Vec::new(), "7".to_string()))), None);
        assert!(non_empty(Some((b"1".to_vec(), "7".to_string()))).is_some());
        let store = FakeStore::default();
        let a = worker_with(&store, 1, 1, None);
        // Empty values under the scope, slot-count and sweep keys, as PDK's
        // wasm stub leaves after a delete.
        for key in [a.key("s"), a.count_key(), a.sweep_key()] {
            store.put(&key, Put::Absent, &[]).unwrap();
        }
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        assert_eq!(a.commit(&r, 1), Settlement::Committed);
        assert_eq!(a.snapshot("s").committed, 800);
        assert_eq!(
            a.read_count().unwrap().0,
            1,
            "slot taken over the empty count"
        );
        // A real value is never created over.
        assert_eq!(
            store.put(&a.key("s"), Put::Absent, b"x"),
            Err(StoreError::CasMismatch)
        );
        // A collection runs over the empty sweep record too.
        a.record("s", 0, GC_INTERVAL_MS).unwrap();
        assert!(a.read_sweep().unwrap().1.is_some());
    }

    #[test]
    fn a_sweep_whose_delete_fails_puts_the_vacant_record_back() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let r = a.reserve("s", 5, 100, 0).unwrap();
        a.release(&r, 0);
        let key = a.key("s");
        a.record("other", 0, GC_INTERVAL_MS).unwrap();
        assert!(matches!(a.read(&key), Ok(Read::New(Some(_), _))), "vacant");
        store.set_failing_deletes(true);
        a.record("other", 0, 3 * GC_INTERVAL_MS).unwrap();
        assert!(
            matches!(a.read(&key), Ok(Read::New(Some(_), _))),
            "restored"
        );
        store.set_failing_deletes(false);
        a.record("other", 0, 5 * GC_INTERVAL_MS).unwrap();
        assert!(store.get(&key).unwrap().is_none(), "deleted on retry");
    }

    #[test]
    fn the_tombstone_protocol_runs_on_the_store_clock_not_a_stale_request_time() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let r = a.reserve("s", 5, 100, 0).unwrap();
        a.release(&r, 0);
        let key = a.key("s");
        // The request times lag the real clock by a lot.
        store.set_now(10 * GC_INTERVAL_MS);
        a.record("other", 0, GC_INTERVAL_MS).unwrap();
        // By request time the grace period has passed; by the clock it
        // has not, so the tombstone stays.
        a.record("other", 0, 3 * GC_INTERVAL_MS).unwrap();
        assert!(matches!(a.read(&key), Ok(Read::New(Some(_), _))), "kept");
        store.set_now(10 * GC_INTERVAL_MS + GRACE_MS);
        a.record("other", 0, 5 * GC_INTERVAL_MS).unwrap();
        assert!(store.get(&key).unwrap().is_none());
    }

    #[test]
    fn a_commit_whose_record_reads_as_missing_is_still_charged() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        // A host read error that PDK reports as "no value".
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        store.hide_next_gets(1);
        assert_eq!(b.commit(&r, 1), Settlement::Committed);
        assert_eq!(a.snapshot("s").committed, 800);
        assert_eq!(a.snapshot("s").reserved, 0);
        // The record really is gone within the reservation's lifetime.
        let r = a.reserve("t", 800, 3000, 0).unwrap();
        store.delete(&a.key("t")).unwrap();
        assert_eq!(b.commit(&r, 1), Settlement::LateCommitted);
        assert_eq!(a.snapshot("t").committed, 800);
        // Past `expires_at + ttl` the #17 rule holds: too late.
        let r = a.reserve("u", 800, 3000, 0).unwrap();
        store.delete(&a.key("u")).unwrap();
        assert_eq!(b.commit(&r, 2 * TTL), Settlement::NotActive);
        assert_eq!(a.snapshot("u").committed, 0);
    }

    #[test]
    fn a_queued_commit_is_charged_even_after_its_tombstone_is_dropped() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        store.force_mismatches(u32::MAX);
        assert_eq!(a.commit(&r, 1), Settlement::Deferred);
        store.force_mismatches(0);
        // B reclaims the reservation and later drops its tombstone.
        b.record("s", 0, 3 * TTL).unwrap();
        assert_eq!(b.snapshot("s").total(), 0);
        a.record("other", 0, 3 * TTL + 1).unwrap();
        assert_eq!(a.pending(), 0);
        assert_eq!(b.snapshot("s").committed, 800, "charged, not dropped");
        assert_eq!(a.stats().late_committed, 1);
    }

    #[test]
    fn a_swept_scope_keeps_its_window_period() {
        let store = FakeStore::default();
        let a = worker_with(&store, 1, 10, Some(DAY));
        let r = a.reserve("s", 5, 100, 5 * DAY).unwrap();
        a.release(&r, 5 * DAY);
        a.record("other", 0, 5 * DAY + GC_INTERVAL_MS).unwrap();
        assert!(matches!(a.read(&a.key("s")), Ok(Read::New(Some(_), 5))));
        // A writer whose time is a little stale (the previous period) re-uses
        // the record: its commit lands in the swept scope's period.
        a.record("s", 100, 5 * DAY - 1).unwrap();
        assert!(a
            .reserve("s", 1, 100, 5 * DAY + GC_INTERVAL_MS + 1)
            .is_err());
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

    fn markers(ledger: &NodeLedger, store: &FakeStore) -> usize {
        let prefix = format!("{}{MARKER_PREFIX}", ledger.prefix);
        store
            .keys()
            .unwrap()
            .iter()
            .filter(|key| key.starts_with(&prefix))
            .count()
    }

    /// A's commit cannot reach the scope record (contended), so A writes it
    /// to the reservation's marker and queues it.
    fn defer_commit(store: &FakeStore, a: &NodeLedger, r: &Reservation, now: u64) {
        store.contend(Some(a.key(&r.scope)));
        assert_eq!(a.commit(r, now), Settlement::Deferred);
        store.contend(None);
    }

    #[test]
    fn a_deferred_commit_is_charged_when_another_worker_reclaims_it() {
        // P4A review M2: A defers a commit, then never runs again (idle, or
        // its VM restarted and lost the queue). B reclaims the reservation
        // at its deadline: the marker makes B charge it, not drop it.
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        defer_commit(&store, &a, &r, 1);
        assert_eq!(a.pending(), 1);
        assert_eq!(markers(&a, &store), 1);
        drop(a);
        // Before the deadline it is still held, so it counts.
        assert_eq!(b.snapshot("s").total(), 800);
        b.record("s", 0, TTL).unwrap();
        assert_eq!(b.snapshot("s").committed, 800, "charged at the deadline");
        assert_eq!(b.snapshot("s").total(), 800);
        assert_eq!(b.stats().late_committed, 1);
        assert_eq!(b.stats().expired, 0);
        // Later touches never charge it twice.
        b.record("s", 0, 3 * TTL).unwrap();
        assert_eq!(b.snapshot("s").committed, 800);
        assert!(b.reserve("s", 2200, 3000, 3 * TTL).is_ok());
        assert!(b.reserve("s", 1, 3000, 3 * TTL).is_err());
    }

    #[test]
    fn a_commit_marker_written_during_a_reclaim_is_still_charged() {
        // The commit lands on the marker between B's marker read and B's
        // write of its own claim: B's write fails and B re-reads the commit.
        let store = Rc::new(FakeStore::default());
        let a = Rc::new(worker(&store, 1));
        let b = worker(&store, 2);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        {
            let (store, a, r) = (Rc::clone(&store), Rc::clone(&a), r.clone());
            // B's first write at its deadline touch is the marker claim.
            store
                .clone()
                .before_next_put(move || defer_commit(&store, &a, &r, TTL - 1));
        }
        b.record("s", 0, TTL).unwrap();
        assert_eq!(b.snapshot("s").committed, 800);
        // A's queued copy finds the reservation gone and adds nothing.
        a.record("other", 0, TTL + 1).unwrap();
        assert_eq!(a.pending(), 0);
        assert_eq!(b.snapshot("s").committed, 800);
        assert_eq!(a.stats().committed + a.stats().late_committed, 0);
    }

    #[test]
    fn a_commit_marker_written_after_expiry_is_charged_when_the_tombstone_drops() {
        let store = Rc::new(FakeStore::default());
        let a = Rc::new(worker(&store, 1));
        let b = worker(&store, 2);
        let c = worker(&store, 3);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        // B reclaims it at the deadline (the marker records that, uncharged).
        b.record("s", 0, TTL).unwrap();
        assert_eq!(b.snapshot("s").total(), 0);
        // The late commit can't reach the record, nor can A run again, and
        // it lands on the marker while C is dropping the tombstone.
        {
            let (store, a, r) = (Rc::clone(&store), Rc::clone(&a), r.clone());
            store
                .clone()
                .before_next_put(move || defer_commit(&store, &a, &r, 2 * TTL - 1));
        }
        c.record("s", 0, 2 * TTL).unwrap();
        assert_eq!(c.snapshot("s").committed, 800, "charged, not dropped");
        assert_eq!(c.stats().late_committed, 1);
        assert_eq!(c.stats().abandoned, 0);
    }

    #[test]
    fn a_commit_is_not_persisted_once_its_tombstone_can_be_dropped() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        a.record("s", 0, TTL).unwrap();
        a.record("s", 0, 2 * TTL).unwrap();
        // A touch dropped the tombstone uncharged, so a commit marker could
        // never be charged: a stale-clock commit stays queue-only.
        assert!(!a.persist_commit(&r, 2 * TTL - 1));
        // Past the tombstone window on the store clock, likewise.
        let r = a.reserve("t", 800, 3000, 0).unwrap();
        store.set_now(2 * TTL);
        assert!(!a.persist_commit(&r, 1));
        store.set_now(0);
        assert!(a.persist_commit(&r, 1));
        assert!(a.persist_commit(&r, 1), "idempotent");
    }

    #[test]
    fn a_persisted_commit_drained_by_its_own_worker_is_charged_once() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        defer_commit(&store, &a, &r, 1);
        a.record("other", 0, 2).unwrap();
        assert_eq!(a.pending(), 0);
        assert_eq!(b.snapshot("s").committed, 800);
        // B's later deadline touch finds nothing on the record to charge.
        b.record("s", 0, 3 * TTL).unwrap();
        assert_eq!(b.snapshot("s").committed, 800);
        assert_eq!(b.stats().late_committed, 0);
    }

    #[test]
    fn markers_are_collected_once_no_record_can_hold_them() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        let r = a.reserve("s", 800, 3000, 0).unwrap();
        defer_commit(&store, &a, &r, 1);
        b.record("s", 0, TTL).unwrap();
        assert_eq!(markers(&b, &store), 1);
        // Not before expires_at + 2 × ttl + grace...
        b.record("other", 0, 2 * TTL).unwrap();
        assert_eq!(markers(&b, &store), 1);
        // ...then the periodic collection deletes it.
        let due = TTL + 2 * TTL + GRACE_MS;
        b.record("other", 0, due + GC_INTERVAL_MS).unwrap();
        b.record("other", 0, due + 2 * GC_INTERVAL_MS).unwrap();
        assert_eq!(markers(&b, &store), 0);
        assert_eq!(b.snapshot("s").committed, 800);
    }

    #[test]
    fn a_zero_contribution_holds_nothing_on_the_node_ledger() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let r = a.reserve("s", 0, 3000, 0).unwrap();
        assert_eq!(a.snapshot("s").reserved, 0);
        assert_eq!(a.stats().active, 0);
        let before = store.ops();
        assert_eq!(a.commit(&r, 1), Settlement::Committed);
        let r = a.reserve("s", 0, 3000, 2).unwrap();
        assert_eq!(a.release(&r, 3), Settlement::Released);
        assert!(a.reserve("s", 3000, 3000, 4).is_ok());
        assert!(store.ops() > before);
        let stats = a.stats();
        assert_eq!((stats.committed, stats.released), (1, 1));
        assert_eq!((stats.not_active, stats.deferred), (0, 0));
    }

    #[test]
    fn a_node_scope_refuses_reservations_past_max_held() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        for i in 0..MAX_HELD {
            let ledger = if i % 2 == 0 { &a } else { &b };
            ledger.reserve("s", 1, u64::MAX, 0).unwrap();
        }
        assert_eq!(a.reserve("s", 1, u64::MAX, 0), Err(Refusal::Saturated));
        assert_eq!(b.force_reserve("s", 1, 0).err(), Some(Refusal::Saturated));
        assert!(a.reserve("s", 0, u64::MAX, 0).is_ok());
        assert!(a.reserve("t", 1, u64::MAX, 0).is_ok());
        // The record stays bounded: the refusals added nothing.
        let (bytes, _) = store.get(&a.key("s")).unwrap().unwrap();
        assert!(bytes.len() < 64 * 1024, "{} bytes", bytes.len());
        assert_eq!(
            a.reserve("s", 1, u64::MAX, TTL),
            Err(Refusal::Saturated),
            "tombstones still count"
        );
        assert!(a.reserve("s", 1, u64::MAX, 2 * TTL).is_ok());
    }

    #[test]
    fn a_new_digest_key_or_window_starts_a_fresh_ledger() {
        // P4A review L3: in worker-lifetime mode a committed scope never
        // frees its slot. After a reconfiguration the old records are no
        // longer reachable, so they must not keep the slots either.
        let store = FakeStore::default();
        let old = worker_with(&store, 1, 1, None);
        let r = old.reserve("a", 5, 100, 0).unwrap();
        old.commit(&r, 0);
        assert_eq!(old.reserve("b", 1, 100, 1), Err(Refusal::AtCapacity));
        let rewindowed = worker_with(&store, 2, 1, Some(DAY));
        assert!(rewindowed.reserve("b", 1, 100, 1).is_ok());
        assert_eq!(rewindowed.snapshot("a").committed, 0);
        let rekeyed = NodeLedger::new(
            Box::new(store.clone()),
            b"rotated".to_vec(),
            1,
            TTL,
            None,
            3,
        );
        assert!(rekeyed.reserve("b", 1, 100, 1).is_ok());
        // The same settings share one ledger, across workers and restarts.
        let same = worker_with(&store, 4, 1, None);
        assert_eq!(same.snapshot("a").committed, 5);
        assert_eq!(same.reserve("b", 1, 100, 1), Err(Refusal::AtCapacity));
    }

    #[test]
    fn a_raw_empty_host_value_reads_as_absent() {
        // PdkStore reads `Vec<u8>` through fixint; an empty host value fails
        // that decode with `Eof`, which must read as absent, not a failure.
        let eof = serde_fixint::from_slice::<Vec<u8>>(&[]).unwrap_err();
        assert!(matches!(eof, serde_fixint::Error::Eof));
        let read = Err(pdk::data_storage::DataStorageError::Serialization(eof));
        assert_eq!(read_value(read), Ok(None));
        let other = Err(pdk::data_storage::DataStorageError::CasMismatch);
        assert_eq!(read_value(other), Err(StoreError::Failed));
        assert_eq!(
            read_value(Ok(Some((Vec::new(), "1".to_string())))),
            Ok(None)
        );
        // The ledger never writes an empty host value: even an empty `Vec`
        // encodes to its 8-byte length prefix.
        assert_eq!(serde_fixint::to_vec(&Vec::<u8>::new()).unwrap().len(), 8);
    }

    #[test]
    fn a_reservation_already_past_its_deadline_is_never_created() {
        // #56: a call whose `now` lags the gateway clock (the store's) by a
        // full timeout is refused on every reserving path, and nothing is
        // written.
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        store.set_now(10 * TTL);
        let stale = 10 * TTL - TTL;
        assert_eq!(a.reserve("s", 1, 1, stale), Err(Refusal::Stale));
        assert_eq!(a.force_reserve("s", 1, stale), Err(Refusal::Stale));
        assert_eq!(
            a.force_reserve_checked("s", 1, 1, stale),
            Err(Refusal::Stale)
        );
        assert!(store.get(&a.key("s")).unwrap().is_none(), "nothing written");
        assert_eq!(a.stats().active, 0);
        // One millisecond fresher and the deadline is still ahead.
        let r = a.reserve("s", 1, 1, stale + 1).unwrap();
        assert_eq!(r.expires_at, 10 * TTL + 1);
        assert!(matches!(
            b.reserve("s", 1, 1, 10 * TTL),
            Err(Refusal::OverBudget(_))
        ));
        assert_eq!(a.commit(&r, 10 * TTL), Settlement::Committed);
        assert_eq!(b.snapshot("s").committed, 1);
    }
    #[test]
    fn rc4_sweep_persists_reconciled_busy_record_before_deferred_commit() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        let r = a.reserve("busy", 800, 3000, 0).unwrap();
        let live = a.reserve("busy", 1, 3000, TTL / 2).unwrap();
        defer_commit(&store, &a, &r, 1);
        b.sweep(TTL, String::new());
        assert_eq!(b.snapshot("busy").committed, 800);
        assert_eq!(b.snapshot("busy").reserved, 1);
        a.drain_pending(TTL + 1);
        assert_eq!(a.pending(), 0);
        assert_eq!(b.snapshot("busy").committed, 800);
        assert_eq!(b.commit(&live, TTL + 1), Settlement::Committed);
        assert_eq!(b.snapshot("busy").committed, 801);
    }
    #[test]
    fn rc4_missing_records_cannot_livelock_a_full_pending_queue() {
        let store = FakeStore::default();
        let a = worker_with(&store, 1, PENDING_LIMIT, None);
        let reservations: Vec<_> = (0..PENDING_LIMIT)
            .map(|i| a.reserve(&format!("lost-{i}"), 1, 10, 0).unwrap())
            .collect();
        store.set_failing(true);
        for r in &reservations {
            assert_eq!(a.commit(r, 1), Settlement::Deferred);
        }
        store.set_failing(false);
        // Records vanished without freeing the shared slot count.
        for r in &reservations {
            store.delete(&a.key(&r.scope)).unwrap();
        }
        for _ in 0..(3 * PENDING_LIMIT / DRAIN_PER_CALL) {
            a.drain_pending(2);
        }
        assert_eq!(a.pending(), 0);
        // Stale slot accounting is separate; it must no longer be queue contention.
        assert_eq!(a.reserve("new", 1, 10, 3), Err(Refusal::AtCapacity));
    }

    #[test]
    fn rc4_sweep_reloads_a_contended_record_without_losing_the_commit() {
        let store = FakeStore::default();
        let a = worker(&store, 1);
        let b = worker(&store, 2);
        let r = a.reserve("busy", 800, 3000, 0).unwrap();
        a.reserve("busy", 1, 3000, TTL / 2).unwrap();
        defer_commit(&store, &a, &r, 1);
        store.force_mismatches(1);
        b.sweep(TTL, String::new());
        assert_eq!(b.snapshot("busy").committed, 800);
        assert_eq!(b.snapshot("busy").reserved, 1);
        a.drain_pending(TTL + 1);
        assert_eq!(b.snapshot("busy").committed, 800);
    }
}
