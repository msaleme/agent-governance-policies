// Copyright 2026 msaleme. Licensed under the MIT License.
//
// Durable, windowed ledger using SQLite.

use rusqlite::{params, Connection, Result as SqlResult};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use crate::ledger::{LedgerStore, Reservation, Denial, Snapshot};

pub struct SqliteLedger {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteLedger {
    pub fn new(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS contributions (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                amount REAL NOT NULL,
                timestamp INTEGER NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reservations (
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                amount REAL NOT NULL,
                expires_at INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

impl LedgerStore for SqliteLedger {
    fn reserve(&self, scope: &str, contribution: f64, budget: f64, window: Duration) -> Result<Reservation, Denial> {
        let conn = self.conn.lock().unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let window_secs = window.as_secs();
        
        let committed: f64 = conn.query_row(
            "SELECT SUM(amount) FROM contributions WHERE scope = ? AND timestamp > ?",
            params![scope, now - window_secs],
            |row| row.get(0),
        ).unwrap_or(0.0);

        let reserved: f64 = conn.query_row(
            "SELECT SUM(amount) FROM reservations WHERE scope = ?",
            params![scope],
            |row| row.get(0),
        ).unwrap_or(0.0);

        let current_total = committed + reserved;
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

        let id = Uuid::new_v4();
        let expires_at = SystemTime::now() + Duration::from_secs(300);
        let expires_at_secs = expires_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        conn.execute(
            "INSERT INTO reservations (id, scope, amount, expires_at) VALUES (?, ?, ?, ?)",
            params![id.to_string(), scope, contribution, expires_at_secs],
        ).unwrap();

        Ok(Reservation {
            id,
            scope: scope.to_string(),
            contribution,
            expires_at,
        })
    }

    fn force_reserve_checked(&self, scope: &str, contribution: f64, budget: f64, window: Duration) -> (Reservation, bool) {
        let conn = self.conn.lock().unwrap();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let window_secs = window.as_secs();

        let committed: f64 = conn.query_row(
            "SELECT SUM(amount) FROM contributions WHERE scope = ? AND timestamp > ?",
            params![scope, now - window_secs],
            |row| row.get(0),
        ).unwrap_or(0.0);

        let reserved: f64 = conn.query_row(
            "SELECT SUM(amount) FROM reservations WHERE scope = ?",
            params![scope],
            |row| row.get(0),
        ).unwrap_or(0.0);

        let id = Uuid::new_v4();
        let expires_at = SystemTime::now() + Duration::from_secs(300);
        let expires_at_secs = expires_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        conn.execute(
            "INSERT INTO reservations (id, scope, amount, expires_at) VALUES (?, ?, ?, ?)",
            params![id.to_string(), scope, contribution, expires_at_secs],
        ).unwrap();

        let breached = (committed + reserved + contribution) > budget;
        (Reservation { id, scope: scope.to_string(), contribution, expires_at }, breached)
    }

    fn commit(&self, reservation: Reservation, actual_contribution: Option<f64>) {
        let conn = self.conn.lock().unwrap();
        let amount = actual_contribution.unwrap_or(reservation.contribution);
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        
        conn.execute(
            "INSERT INTO contributions (id, scope, amount, timestamp) VALUES (?, ?, ?, ?)",
            params![Uuid::new_v4().to_string(), reservation.scope, amount, now],
        ).unwrap();
        conn.execute(
            "DELETE FROM reservations WHERE id = ?",
            params![reservation.id.to_string()],
        ).unwrap();
    }

    fn release(&self, reservation: Reservation) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM reservations WHERE id = ?",
            params![reservation.id.to_string()],
        ).unwrap();
    }

    fn record(&self, scope: &str, contribution: f64) {
        let conn = self.conn.lock().unwrap();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        conn.execute(
            "INSERT INTO contributions (id, scope, amount, timestamp) VALUES (?, ?, ?, ?)",
            params![Uuid::new_v4().to_string(), scope, contribution, now],
        ).unwrap();
    }

    fn snapshot(&self, scope: &str, window: Duration) -> Snapshot {
        let conn = self.conn.lock().unwrap();
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let window_secs = window.as_secs();

        let committed: f64 = conn.query_row(
            "SELECT SUM(amount) FROM contributions WHERE scope = ? AND timestamp > ?",
            params![scope, now - window_secs],
            |row| row.get(0),
        ).unwrap_or(0.0);

        let reserved: f64 = conn.query_row(
            "SELECT SUM(amount) FROM reservations WHERE scope = ?",
            params![scope],
            |row| row.get(0),
        ).unwrap_or(0.0);

        Snapshot { committed, reserved }
    }
}
