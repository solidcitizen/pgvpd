//! Connection Pool — session pooling for upstream Postgres connections.
//!
//! Pool key is `(database, role)`. Each bucket holds up to `pool_size` connections.
//! Idle connections are reaped after `pool_idle_timeout` seconds.

use bytes::BytesMut;
use rustls::ClientConfig;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::auth;
use crate::config::Config;
use crate::connection::{PipeEnd, PipeOutcome, connect_upstream};
use crate::metrics::Metrics;
use crate::protocol::{
    BackendFrameTracker, build_cancel_request, build_query_message, build_startup_message,
    parse_backend_key_data, try_read_backend_message,
};
use crate::stream::{UpstreamStream, read_or_eof};

/// Pool key — identifies a bucket of reusable connections.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub database: String,
    pub role: String,
}

/// A pooled upstream connection with cached handshake data.
#[allow(dead_code)]
pub struct PooledConn {
    pub stream: UpstreamStream,
    pub created_at: Instant,
    pub last_used: Instant,
    /// Cached ParameterStatus messages from the initial handshake.
    pub param_statuses: Vec<BytesMut>,
    /// Cached BackendKeyData message from the initial handshake.
    pub backend_key_data: BytesMut,
    /// This connection's REAL upstream backend key (pid, secret), parsed once at
    /// creation and preserved for the connection's whole pooled life. Used to
    /// route a CancelRequest to this exact backend. Unlike `backend_key_data`
    /// (which is reset and re-attached from the bucket cache on reuse), this must
    /// stay tied to the physical connection.
    pub real_key: Option<(u32, u32)>,
}

struct PoolBucket {
    idle: VecDeque<PooledConn>,
    total: u32,
    /// Cached ParameterStatus messages from the first connection's handshake.
    /// Reused for all subsequent connections in this bucket.
    cached_param_statuses: Option<Vec<BytesMut>>,
    /// Cached BackendKeyData from the first connection's handshake.
    cached_backend_key_data: Option<BytesMut>,
}

impl PoolBucket {
    fn new() -> Self {
        Self {
            idle: VecDeque::new(),
            total: 0,
            cached_param_statuses: None,
            cached_backend_key_data: None,
        }
    }
}

/// Snapshot of pool state for the admin /status and /metrics endpoints.
#[derive(Debug)]
pub struct PoolSnapshot {
    pub buckets: Vec<PoolBucketSnapshot>,
}

/// Snapshot of a single pool bucket.
#[derive(Debug)]
pub struct PoolBucketSnapshot {
    pub database: String,
    pub role: String,
    pub total: u32,
    pub idle: u32,
}

/// Connection pool for upstream Postgres connections.
pub struct Pool {
    buckets: Mutex<HashMap<PoolKey, PoolBucket>>,
    config: Arc<Config>,
    upstream_tls: Option<Arc<ClientConfig>>,
    metrics: Arc<Metrics>,
}

impl Pool {
    pub fn new(
        config: Arc<Config>,
        upstream_tls: Option<Arc<ClientConfig>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            config,
            upstream_tls,
            metrics,
        }
    }

    /// Snapshot of current pool state (for admin API).
    pub async fn snapshot(&self) -> PoolSnapshot {
        let buckets = self.lock_buckets();
        let mut result = Vec::with_capacity(buckets.len());
        for (key, bucket) in buckets.iter() {
            result.push(PoolBucketSnapshot {
                database: key.database.clone(),
                role: key.role.clone(),
                total: bucket.total,
                idle: bucket.idle.len() as u32,
            });
        }
        PoolSnapshot { buckets: result }
    }

    /// Check out a connection from the pool. Reuses an idle connection if available,
    /// otherwise creates a new one (if under pool_size). Waits if pool is full.
    pub async fn checkout(
        &self,
        key: &PoolKey,
        conn_id: u64,
    ) -> Result<PooledConn, Box<dyn std::error::Error + Send + Sync>> {
        let timeout = Duration::from_secs(self.config.pool_checkout_timeout);
        let deadline = Instant::now() + timeout;

        loop {
            // The bucket lock is a std mutex: it must not be held across an
            // await, so the locked section decides what to do and ends before
            // any connecting happens.
            let reserved_slot = {
                let mut buckets = self.lock_buckets();
                let bucket = buckets.entry(key.clone()).or_insert_with(PoolBucket::new);

                // Try to pop an idle connection
                if let Some(mut conn) = bucket.idle.pop_front() {
                    conn.last_used = Instant::now();
                    // Re-attach cached handshake data if the conn lost it (recycled)
                    if conn.param_statuses.is_empty()
                        && let Some(ref cached) = bucket.cached_param_statuses
                    {
                        conn.param_statuses = cached.clone();
                    }
                    if conn.backend_key_data.is_empty()
                        && let Some(ref cached) = bucket.cached_backend_key_data
                    {
                        conn.backend_key_data = cached.clone();
                    }
                    Metrics::inc(&self.metrics.pool_reuses);
                    Metrics::inc(&self.metrics.pool_checkouts);
                    debug!(conn_id, database = %key.database, role = %key.role, "pool: reusing idle connection");
                    return Ok(conn);
                }

                // Reserve a slot for a new connection if under limit
                if bucket.total < self.config.pool_size {
                    bucket.total += 1;
                    true
                } else {
                    false
                }
            };

            if reserved_slot {
                // Hold the reserved slot in an RAII guard so it is released on
                // EVERY exit from the create: an Err return, and — critically —
                // a cancellation. `checkout` runs inside the per-connection
                // handshake timeout (`tokio::time::timeout`), so if
                // `create_connection` outlives it the future is dropped mid-await
                // and neither match arm runs. Without the guard the reserved
                // `total` would never be decremented, leaking a phantom slot;
                // enough leaks pin `total` at `pool_size` and wedge the bucket
                // permanently (issue #20). The guard is disarmed only once the
                // connection exists and its slot is owned by the returned conn.
                let mut reservation = SlotReservation {
                    pool: self,
                    key,
                    armed: true,
                };
                Metrics::inc(&self.metrics.pool_creates);
                debug!(conn_id, database = %key.database, role = %key.role, "pool: creating new connection");
                match self.create_connection(key, conn_id).await {
                    Ok(conn) => {
                        reservation.disarm();
                        // Cache handshake data on first connection for this bucket
                        let mut buckets = self.lock_buckets();
                        if let Some(bucket) = buckets.get_mut(key)
                            && bucket.cached_param_statuses.is_none()
                        {
                            bucket.cached_param_statuses = Some(conn.param_statuses.clone());
                            bucket.cached_backend_key_data = Some(conn.backend_key_data.clone());
                        }
                        Metrics::inc(&self.metrics.pool_checkouts);
                        return Ok(conn);
                    }
                    Err(e) => {
                        // `reservation` drops here and releases the slot.
                        return Err(e);
                    }
                }
            }

            // Pool is full — wait and retry
            if Instant::now() >= deadline {
                Metrics::inc(&self.metrics.pool_timeouts);
                return Err("pool checkout timeout: all connections in use".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Return a connection to the pool after use.
    ///
    /// The pipe reports how the session ended and how many responses upstream
    /// still owes for requests it already received. Anything outstanding is
    /// drained first, then `ROLLBACK` and `DISCARD ALL` reset the session, so
    /// the next holder never finds a stale message on the wire (issue #11).
    /// A connection whose protocol state cannot be trusted is discarded.
    pub async fn checkin(
        &self,
        key: PoolKey,
        mut stream: UpstreamStream,
        real_key: Option<(u32, u32)>,
        conn_id: u64,
        mut outcome: PipeOutcome,
    ) {
        if matches!(
            outcome.end,
            PipeEnd::UpstreamClosed | PipeEnd::UpstreamError(_)
        ) {
            Metrics::inc(&self.metrics.pool_discards);
            debug!(conn_id, "pool: upstream gone, discarding connection");
            self.decrement_total(&key);
            return;
        }

        if outcome.framing_lost || outcome.rfq_received > outcome.sync_points_sent {
            Metrics::inc(&self.metrics.pool_discards);
            warn!(
                conn_id,
                sync_points = outcome.sync_points_sent,
                ready_for_query = outcome.rfq_received,
                "pool: protocol state unknown, discarding connection"
            );
            self.decrement_total(&key);
            return;
        }

        let outstanding = outcome.sync_points_sent - outcome.rfq_received;

        // Reset the connection in two steps:
        // 1. ROLLBACK — ends any open transaction (no-op if idle)
        // 2. DISCARD ALL — resets all session state
        // These MUST be separate SimpleQuery messages because PostgreSQL
        // wraps multi-statement queries in an implicit transaction, and
        // DISCARD ALL refuses to run inside a transaction block.
        let mut buf = BytesMut::with_capacity(1024);
        let reset_timeout = Duration::from_secs(5);

        match tokio::time::timeout(reset_timeout, async {
            // Step 0: drain responses the departed client never read, so the
            // ReadyForQuery consumed by each step below is that step's own.
            if outstanding > 0 || outcome.tracker.mid_message() {
                Metrics::inc(&self.metrics.pool_drains);
                info!(
                    conn_id,
                    outstanding,
                    "pool: client left with responses outstanding — draining before reset"
                );
                // The client abandoned an in-flight query. Cancel it upstream so
                // the drain doesn't have to wait the whole query out before the
                // slot can be reused (issue #14). Best-effort and advisory.
                if outstanding > 0
                    && let Some((pid, secret)) = real_key
                {
                    self.cancel_upstream_query(pid, secret, conn_id).await;
                }
                if !Self::drain_outstanding(
                    &mut stream,
                    &mut outcome.tracker,
                    outstanding,
                    &mut buf,
                )
                .await
                {
                    warn!(conn_id, "pool: drain failed, discarding");
                    return false;
                }
            }
            // Step 1: ROLLBACK
            if !Self::send_and_drain(&mut stream, "ROLLBACK", &mut buf, conn_id).await {
                return false;
            }
            // Step 2: DISCARD ALL
            Self::send_and_drain(&mut stream, "DISCARD ALL", &mut buf, conn_id).await
        })
        .await
        {
            Ok(true) => {
                // Connection is clean — return to pool
                Metrics::inc(&self.metrics.pool_checkins);
                let mut buckets = self.lock_buckets();
                if let Some(bucket) = buckets.get_mut(&key) {
                    // Return to the idle queue. param_statuses/backend_key_data
                    // are re-attached from the bucket cache on checkout, so they
                    // are left empty here; real_key stays tied to this physical
                    // connection so a later checkout can still route a cancel.
                    bucket.idle.push_back(PooledConn {
                        stream,
                        created_at: Instant::now(),
                        last_used: Instant::now(),
                        param_statuses: Vec::new(),
                        backend_key_data: BytesMut::new(),
                        real_key,
                    });
                    debug!(conn_id, database = %key.database, role = %key.role, "pool: connection returned");
                } else {
                    // Bucket disappeared — discard
                    debug!(conn_id, "pool: bucket gone, discarding connection");
                }
            }
            _ => {
                Metrics::inc(&self.metrics.pool_discards);
                warn!(conn_id, "pool: reset failed or timed out, discarding");
                self.decrement_total(&key);
            }
        }
    }

    /// Read from upstream until `outstanding` ReadyForQuery messages have been
    /// consumed and the stream sits on a message boundary. Returns false on EOF
    /// or read error. Bytes are discarded: they were for a client that is gone.
    async fn drain_outstanding(
        stream: &mut UpstreamStream,
        tracker: &mut BackendFrameTracker,
        mut outstanding: u64,
        buf: &mut BytesMut,
    ) -> bool {
        while outstanding > 0 || tracker.mid_message() {
            buf.clear();
            match stream.read_buf(buf).await {
                Ok(0) | Err(_) => return false,
                Ok(_) => {}
            }
            outstanding = outstanding.saturating_sub(tracker.feed(buf));
        }
        buf.clear();
        true
    }

    /// Send a SimpleQuery and drain responses until ReadyForQuery.
    /// Returns false if the write fails, an ErrorResponse is received, or read fails.
    async fn send_and_drain(
        stream: &mut UpstreamStream,
        sql: &str,
        buf: &mut BytesMut,
        conn_id: u64,
    ) -> bool {
        let msg = build_query_message(sql);
        if stream.write_all(&msg).await.is_err() {
            warn!(conn_id, sql, "pool: checkin write failed");
            return false;
        }
        loop {
            // read_or_eof so an upstream that FINs mid-reset ends the drain
            // promptly instead of spinning until reset_timeout.
            if read_or_eof(stream, buf).await.is_err() {
                return false;
            }
            while let Some(msg) = try_read_backend_message(buf) {
                if msg.is_error_response() {
                    warn!(conn_id, error = %msg.error_message(), "pool: reset error");
                    return false;
                }
                if msg.is_ready_for_query() {
                    return true;
                }
            }
        }
    }

    /// Create a new upstream connection, authenticate, and cache handshake data.
    async fn create_connection(
        &self,
        key: &PoolKey,
        conn_id: u64,
    ) -> Result<PooledConn, Box<dyn std::error::Error + Send + Sync>> {
        let mut server = connect_upstream(&self.config, &self.upstream_tls).await?;

        // Send StartupMessage with the pool role
        let mut params = std::collections::HashMap::new();
        params.insert("user".into(), key.role.clone());
        params.insert("database".into(), key.database.clone());
        let startup_msg = build_startup_message(&params);
        server.write_all(&startup_msg).await?;

        // Authenticate to upstream
        let mut server_buf = BytesMut::with_capacity(4096);
        let upstream_password = self.config.upstream_password.as_deref().unwrap_or("");
        auth::authenticate_upstream(
            &mut server,
            &mut server_buf,
            &key.role,
            upstream_password,
            conn_id,
        )
        .await?;

        // Collect ParameterStatus, BackendKeyData, ReadyForQuery
        let mut param_statuses = Vec::new();
        let mut backend_key_data = BytesMut::new();

        loop {
            if server_buf.is_empty() {
                read_or_eof(&mut server, &mut server_buf).await?;
            }

            let mut ready = false;
            while let Some(msg) = try_read_backend_message(&mut server_buf) {
                if msg.is_parameter_status() {
                    param_statuses.push(msg.raw);
                } else if msg.is_backend_key_data() {
                    backend_key_data = msg.raw;
                } else if msg.is_ready_for_query() {
                    ready = true;
                    break;
                } else if msg.is_error_response() {
                    return Err(
                        format!("upstream error during connect: {}", msg.error_message()).into(),
                    );
                }
            }

            if ready {
                break;
            }
        }

        let now = Instant::now();
        let real_key = parse_backend_key_data(&backend_key_data);
        Ok(PooledConn {
            stream: server,
            created_at: now,
            last_used: now,
            param_statuses,
            backend_key_data,
            real_key,
        })
    }

    /// Background task: evict connections idle longer than pool_idle_timeout.
    pub async fn idle_reaper(self: Arc<Self>) {
        let idle_timeout = Duration::from_secs(self.config.pool_idle_timeout);
        let interval = Duration::from_secs(30); // check every 30s

        loop {
            tokio::time::sleep(interval).await;

            let mut buckets = self.lock_buckets();
            let mut total_reaped = 0u32;

            for (key, bucket) in buckets.iter_mut() {
                let before = bucket.idle.len();
                bucket
                    .idle
                    .retain(|conn| conn.last_used.elapsed() < idle_timeout);
                let reaped = before - bucket.idle.len();
                if reaped > 0 {
                    bucket.total = bucket.total.saturating_sub(reaped as u32);
                    total_reaped += reaped as u32;
                    debug!(
                        database = %key.database,
                        role = %key.role,
                        reaped,
                        remaining = bucket.idle.len(),
                        "pool: reaped idle connections"
                    );
                }
            }

            // Remove empty buckets
            buckets.retain(|_, bucket| bucket.total > 0);

            if total_reaped > 0 {
                info!(reaped = total_reaped, "pool: idle reaper cycle");
            }
        }
    }

    fn decrement_total(&self, key: &PoolKey) {
        let mut buckets = self.lock_buckets();
        if let Some(bucket) = buckets.get_mut(key) {
            bucket.total = bucket.total.saturating_sub(1);
        }
    }

    /// Best-effort: open a fresh connection to upstream and send a CancelRequest
    /// for `(pid, secret)`. PostgreSQL requires a cancel on a separate
    /// connection and sends no reply, so this connects, writes, and closes.
    /// Failures are ignored — a cancel is advisory.
    async fn cancel_upstream_query(&self, pid: u32, secret: u32, conn_id: u64) {
        match connect_upstream(&self.config, &self.upstream_tls).await {
            Ok(mut c) => {
                let _ = c.write_all(&build_cancel_request(pid, secret)).await;
                let _ = c.shutdown().await;
                debug!(conn_id, pid, "pool: sent cancel for orphaned query");
            }
            Err(e) => debug!(conn_id, error = %e, "pool: cancel connect failed"),
        }
    }

    /// Lock the bucket map. The guard is never held across an await point, so
    /// a poisoned mutex (a panic while locked) is recovered rather than spread.
    fn lock_buckets(&self) -> std::sync::MutexGuard<'_, HashMap<PoolKey, PoolBucket>> {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// RAII guard for a slot reserved in [`Pool::checkout`] before its upstream
/// connection exists.
///
/// `checkout` increments `bucket.total` under the lock, then awaits
/// `create_connection`. It runs inside the per-connection handshake timeout, so
/// that await can be dropped mid-flight (the upstream accepted the socket but is
/// slow to answer the startup). This guard decrements the reserved slot on every
/// drop — Err return or cancellation — unless [`disarm`](Self::disarm) is called
/// once the connection exists and owns the slot. Without it a cancelled create
/// leaks the slot, and enough leaks pin `total` at `pool_size` and wedge the
/// bucket permanently (issue #20).
struct SlotReservation<'a> {
    pool: &'a Pool,
    key: &'a PoolKey,
    armed: bool,
}

impl SlotReservation<'_> {
    /// The created connection now owns the slot; do not release it on drop.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SlotReservation<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.pool.decrement_total(self.key);
        }
    }
}

/// A checked-out pool slot.
///
/// Consumed by [`PoolLease::checkin`]. Dropping it any other way — an error
/// after checkout, a handshake timeout cancelling the future — releases the
/// slot so the bucket's `total` never drifts above the connections that exist.
pub struct PoolLease {
    pool: Arc<Pool>,
    key: PoolKey,
    armed: bool,
}

impl PoolLease {
    pub fn new(pool: Arc<Pool>, key: PoolKey) -> Self {
        Self {
            pool,
            key,
            armed: true,
        }
    }

    /// Return the connection to the pool (or discard it), consuming the lease.
    /// `real_key` is this connection's upstream backend key, preserved so the
    /// pool can route a cancel and re-tag the idle connection.
    pub async fn checkin(
        mut self,
        stream: UpstreamStream,
        real_key: Option<(u32, u32)>,
        conn_id: u64,
        outcome: PipeOutcome,
    ) {
        self.armed = false;
        let pool = Arc::clone(&self.pool);
        pool.checkin(self.key.clone(), stream, real_key, conn_id, outcome)
            .await;
    }
}

impl Drop for PoolLease {
    fn drop(&mut self) {
        if self.armed {
            debug!(
                database = %self.key.database,
                role = %self.key.role,
                "pool: lease dropped without checkin — releasing slot"
            );
            Metrics::inc(&self.pool.metrics.pool_discards);
            self.pool.decrement_total(&self.key);
        }
    }
}
