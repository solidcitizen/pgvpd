//! Tenant Isolation — per-tenant connection limits, rate limiting, allow/deny lists.
//!
//! The TenantRegistry is shared across all connection tasks. It tracks per-tenant
//! runtime state (active connections, rate window) and enforces limits configured
//! in pgvpd.conf. TenantGuard is an RAII guard that decrements the active connection
//! count when the connection ends.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::metrics::Metrics;

/// Per-tenant runtime state, created on first connection for that tenant.
struct TenantState {
    active_connections: AtomicU32,
    /// Rate limit: sliding window start time and count.
    rate_window: Mutex<(Instant, u32)>,
}

/// Registry of per-tenant state, shared across all connection tasks.
pub struct TenantRegistry {
    tenants: Mutex<HashMap<String, Arc<TenantState>>>,
    allow: Option<HashSet<String>>,
    deny: Option<HashSet<String>>,
    max_connections: Option<u32>,
    rate_limit: Option<u32>,
    metrics: Arc<Metrics>,
}

/// RAII guard that decrements active_connections on drop.
pub struct TenantGuard {
    state: Arc<TenantState>,
}

impl Drop for TenantGuard {
    fn drop(&mut self) {
        self.state
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl TenantRegistry {
    pub fn new(config: &Config, metrics: Arc<Metrics>) -> Self {
        Self {
            tenants: Mutex::new(HashMap::new()),
            allow: config
                .tenant_allow
                .as_ref()
                .map(|v| v.iter().cloned().collect()),
            deny: config
                .tenant_deny
                .as_ref()
                .map(|v| v.iter().cloned().collect()),
            max_connections: config.tenant_max_connections,
            rate_limit: config.tenant_rate_limit,
            metrics,
        }
    }

    /// Check allow/deny list. Returns Err with message if denied.
    pub fn check_access(&self, tenant_id: &str) -> Result<(), String> {
        if let Some(ref deny) = self.deny
            && deny.contains(tenant_id)
        {
            Metrics::inc(&self.metrics.tenant_rejected_deny);
            return Err(format!("tenant '{}' is denied", tenant_id));
        }
        if let Some(ref allow) = self.allow
            && !allow.contains(tenant_id)
        {
            Metrics::inc(&self.metrics.tenant_rejected_deny);
            return Err(format!("tenant '{}' is not in allow list", tenant_id));
        }
        Ok(())
    }

    /// Try to acquire a connection slot for this tenant.
    /// Returns a TenantGuard that decrements the count on drop.
    /// Returns Err if connection limit or rate limit exceeded.
    pub async fn acquire(&self, tenant_id: &str) -> Result<TenantGuard, String> {
        let state = self.get_or_create(tenant_id).await;

        // Check connection limit
        if let Some(max) = self.max_connections {
            let current = state.active_connections.load(Ordering::Relaxed);
            if current >= max {
                Metrics::inc(&self.metrics.tenant_rejected_limit);
                return Err(format!(
                    "tenant '{}' connection limit exceeded ({}/{})",
                    tenant_id, current, max
                ));
            }
        }

        // Check rate limit
        if let Some(limit) = self.rate_limit {
            let mut window = state.rate_window.lock().await;
            let now = Instant::now();
            let elapsed = now.duration_since(window.0);
            if elapsed.as_secs() >= 1 {
                // New window
                *window = (now, 1);
            } else if window.1 >= limit {
                Metrics::inc(&self.metrics.tenant_rejected_rate);
                return Err(format!(
                    "tenant '{}' rate limit exceeded ({}/s)",
                    tenant_id, limit
                ));
            } else {
                window.1 += 1;
            }
        }

        // Acquire slot
        state.active_connections.fetch_add(1, Ordering::Relaxed);
        Ok(TenantGuard {
            state: Arc::clone(&state),
        })
    }

    async fn get_or_create(&self, tenant_id: &str) -> Arc<TenantState> {
        let mut tenants = self.tenants.lock().await;
        if let Some(state) = tenants.get(tenant_id) {
            Arc::clone(state)
        } else {
            let state = Arc::new(TenantState {
                active_connections: AtomicU32::new(0),
                rate_window: Mutex::new((Instant::now(), 0)),
            });
            tenants.insert(tenant_id.to_string(), Arc::clone(&state));
            state
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(
        allow: Option<Vec<&str>>,
        deny: Option<Vec<&str>>,
        max_conn: Option<u32>,
        rate: Option<u32>,
    ) -> Config {
        Config {
            tenant_allow: allow.map(|v| v.into_iter().map(String::from).collect()),
            tenant_deny: deny.map(|v| v.into_iter().map(String::from).collect()),
            tenant_max_connections: max_conn,
            tenant_rate_limit: rate,
            ..Default::default()
        }
    }

    fn make_metrics() -> Arc<Metrics> {
        Arc::new(Metrics::new(vec![]))
    }

    #[test]
    fn test_deny_list_blocks() {
        let config = make_config(None, Some(vec!["bad"]), None, None);
        let reg = TenantRegistry::new(&config, make_metrics());
        assert!(reg.check_access("bad").is_err());
        assert!(reg.check_access("good").is_ok());
    }

    #[test]
    fn test_allow_list_blocks_unlisted() {
        let config = make_config(Some(vec!["alpha", "beta"]), None, None, None);
        let reg = TenantRegistry::new(&config, make_metrics());
        assert!(reg.check_access("alpha").is_ok());
        assert!(reg.check_access("beta").is_ok());
        assert!(reg.check_access("gamma").is_err());
    }

    #[test]
    fn test_no_lists_allows_all() {
        let config = make_config(None, None, None, None);
        let reg = TenantRegistry::new(&config, make_metrics());
        assert!(reg.check_access("anything").is_ok());
    }

    #[tokio::test]
    async fn test_connection_limit() {
        let config = make_config(None, None, Some(2), None);
        let reg = TenantRegistry::new(&config, make_metrics());

        let g1 = reg.acquire("t1").await;
        assert!(g1.is_ok());
        let g2 = reg.acquire("t1").await;
        assert!(g2.is_ok());
        // Third should fail
        let g3 = reg.acquire("t1").await;
        assert!(g3.is_err());

        // Different tenant should succeed
        let g4 = reg.acquire("t2").await;
        assert!(g4.is_ok());

        // Drop one, then t1 should succeed again
        drop(g1);
        let g5 = reg.acquire("t1").await;
        assert!(g5.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let config = make_config(None, None, None, Some(3));
        let reg = TenantRegistry::new(&config, make_metrics());

        // First 3 should succeed
        let _g1 = reg.acquire("t1").await.unwrap();
        let _g2 = reg.acquire("t1").await.unwrap();
        let _g3 = reg.acquire("t1").await.unwrap();

        // Fourth in same second should fail
        let g4 = reg.acquire("t1").await;
        assert!(g4.is_err());
    }
}
