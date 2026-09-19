//! Admin HTTP API — health checks, Prometheus metrics, pool/resolver status.
//!
//! Spawned as a background task when `admin_port` is configured.
//! Endpoints:
//!   GET /health  — 200 OK, for load balancer health checks
//!   GET /metrics — Prometheus exposition format
//!   GET /status  — JSON snapshot of pool and resolver state

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::metrics::Metrics;
use crate::pool::Pool;
use crate::resolver::ResolverEngine;

/// Shared state for admin endpoints.
#[derive(Clone)]
pub struct AdminState {
    pub metrics: Arc<Metrics>,
    pub pool: Option<Arc<Pool>>,
    pub resolver: Option<Arc<ResolverEngine>>,
}

/// Start the admin HTTP server on the given host and port.
///
/// The admin endpoints are unauthenticated and `/status` + `/metrics` reveal
/// pool topology (databases, roles, bucket counts), so the bind host defaults to
/// `127.0.0.1` (issue #13). Set `admin_host` to expose it deliberately.
pub async fn serve(state: AdminState, host: String, port: u16) {
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/status", get(status))
        .with_state(state);

    let addr = format!("{host}:{port}");
    match TcpListener::bind(&addr).await {
        Ok(listener) => {
            info!(addr = %addr, "admin API");
            if let Err(e) = axum::serve(listener, app).await {
                error!(error = %e, "admin server error");
            }
        }
        Err(e) => {
            error!(addr = %addr, error = %e, "failed to bind admin port");
        }
    }
}

// ─── GET /health ─────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        r#"{"status":"ok"}"#,
    )
}

// ─── GET /metrics ────────────────────────────────────────────────────────────

async fn metrics(State(state): State<AdminState>) -> Response {
    let m = &state.metrics;
    let mut out = String::with_capacity(2048);

    // Connection metrics
    out.push_str("# HELP pgvpd_connections_total Total connections accepted.\n");
    out.push_str("# TYPE pgvpd_connections_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_connections_total",
        "",
        m.connections_total.load(Ordering::Relaxed),
    );
    out.push_str("# HELP pgvpd_connections_active Currently active connections.\n");
    out.push_str("# TYPE pgvpd_connections_active gauge\n");
    push_metric(
        &mut out,
        "pgvpd_connections_active",
        "",
        m.connections_active.load(Ordering::Relaxed),
    );

    // Pool metrics (per bucket from snapshot)
    if let Some(pool) = &state.pool {
        let snap = pool.snapshot().await;
        out.push_str("# HELP pgvpd_pool_connections_total Total connections in pool bucket.\n");
        out.push_str("# TYPE pgvpd_pool_connections_total gauge\n");
        out.push_str("# HELP pgvpd_pool_connections_idle Idle connections in pool bucket.\n");
        out.push_str("# TYPE pgvpd_pool_connections_idle gauge\n");
        for b in &snap.buckets {
            let labels = format!(r#"database="{}",role="{}""#, b.database, b.role);
            push_metric(
                &mut out,
                "pgvpd_pool_connections_total",
                &labels,
                b.total as u64,
            );
            push_metric(
                &mut out,
                "pgvpd_pool_connections_idle",
                &labels,
                b.idle as u64,
            );
        }
    }

    out.push_str("# HELP pgvpd_pool_checkouts_total Total pool checkouts.\n");
    out.push_str("# TYPE pgvpd_pool_checkouts_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_pool_checkouts_total",
        "",
        m.pool_checkouts.load(Ordering::Relaxed),
    );
    out.push_str("# HELP pgvpd_pool_reuses_total Pool connections reused from idle.\n");
    out.push_str("# TYPE pgvpd_pool_reuses_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_pool_reuses_total",
        "",
        m.pool_reuses.load(Ordering::Relaxed),
    );
    out.push_str("# HELP pgvpd_pool_creates_total New pool connections created.\n");
    out.push_str("# TYPE pgvpd_pool_creates_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_pool_creates_total",
        "",
        m.pool_creates.load(Ordering::Relaxed),
    );
    out.push_str("# HELP pgvpd_pool_checkins_total Pool connections returned.\n");
    out.push_str("# TYPE pgvpd_pool_checkins_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_pool_checkins_total",
        "",
        m.pool_checkins.load(Ordering::Relaxed),
    );
    out.push_str(
        "# HELP pgvpd_pool_discards_total Pool connections discarded on checkin failure.\n",
    );
    out.push_str("# TYPE pgvpd_pool_discards_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_pool_discards_total",
        "",
        m.pool_discards.load(Ordering::Relaxed),
    );
    out.push_str("# HELP pgvpd_pool_timeouts_total Pool checkout timeouts.\n");
    out.push_str("# TYPE pgvpd_pool_timeouts_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_pool_timeouts_total",
        "",
        m.pool_timeouts.load(Ordering::Relaxed),
    );
    out.push_str(
        "# HELP pgvpd_pool_drains_total Checkins that drained responses a departed client left in flight.\n",
    );
    out.push_str("# TYPE pgvpd_pool_drains_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_pool_drains_total",
        "",
        m.pool_drains.load(Ordering::Relaxed),
    );

    // Resolver metrics
    if let Some(resolver) = &state.resolver {
        let cache_size = resolver.cache_size().await;
        out.push_str("# HELP pgvpd_resolver_cache_size Current resolver cache entries.\n");
        out.push_str("# TYPE pgvpd_resolver_cache_size gauge\n");
        push_metric(&mut out, "pgvpd_resolver_cache_size", "", cache_size as u64);
    }

    out.push_str("# HELP pgvpd_resolver_cache_hits_total Resolver cache hits.\n");
    out.push_str("# TYPE pgvpd_resolver_cache_hits_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_resolver_cache_hits_total",
        "",
        m.resolver_cache_hits.load(Ordering::Relaxed),
    );
    out.push_str("# HELP pgvpd_resolver_cache_misses_total Resolver cache misses.\n");
    out.push_str("# TYPE pgvpd_resolver_cache_misses_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_resolver_cache_misses_total",
        "",
        m.resolver_cache_misses.load(Ordering::Relaxed),
    );

    if !m.resolver_names.is_empty() {
        out.push_str("# HELP pgvpd_resolver_executions_total Resolver executions.\n");
        out.push_str("# TYPE pgvpd_resolver_executions_total counter\n");
        for (i, name) in m.resolver_names.iter().enumerate() {
            let labels = format!(r#"resolver="{}""#, name);
            if let Some(counter) = m.resolver_executions.get(i) {
                push_metric(
                    &mut out,
                    "pgvpd_resolver_executions_total",
                    &labels,
                    counter.load(Ordering::Relaxed),
                );
            }
        }
        out.push_str("# HELP pgvpd_resolver_errors_total Resolver errors.\n");
        out.push_str("# TYPE pgvpd_resolver_errors_total counter\n");
        for (i, name) in m.resolver_names.iter().enumerate() {
            let labels = format!(r#"resolver="{}""#, name);
            if let Some(counter) = m.resolver_errors.get(i) {
                push_metric(
                    &mut out,
                    "pgvpd_resolver_errors_total",
                    &labels,
                    counter.load(Ordering::Relaxed),
                );
            }
        }
    }

    // Tenant isolation metrics
    out.push_str("# HELP pgvpd_tenant_rejected_total Tenant connections rejected.\n");
    out.push_str("# TYPE pgvpd_tenant_rejected_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_tenant_rejected_total",
        r#"reason="deny""#,
        m.tenant_rejected_deny.load(Ordering::Relaxed),
    );
    push_metric(
        &mut out,
        "pgvpd_tenant_rejected_total",
        r#"reason="limit""#,
        m.tenant_rejected_limit.load(Ordering::Relaxed),
    );
    push_metric(
        &mut out,
        "pgvpd_tenant_rejected_total",
        r#"reason="rate""#,
        m.tenant_rejected_rate.load(Ordering::Relaxed),
    );
    out.push_str("# HELP pgvpd_tenant_timeouts_total Tenant query timeouts.\n");
    out.push_str("# TYPE pgvpd_tenant_timeouts_total counter\n");
    push_metric(
        &mut out,
        "pgvpd_tenant_timeouts_total",
        "",
        m.tenant_timeouts.load(Ordering::Relaxed),
    );

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        out,
    )
        .into_response()
}

fn push_metric(out: &mut String, name: &str, labels: &str, value: u64) {
    if labels.is_empty() {
        out.push_str(&format!("{name} {value}\n"));
    } else {
        out.push_str(&format!("{name}{{{labels}}} {value}\n"));
    }
}

// ─── GET /status ─────────────────────────────────────────────────────────────

async fn status(State(state): State<AdminState>) -> Response {
    let m = &state.metrics;

    let mut json = String::with_capacity(1024);
    json.push_str("{\n");

    // Connections
    json.push_str(&format!(
        "  \"connections_total\": {},\n  \"connections_active\": {},\n",
        m.connections_total.load(Ordering::Relaxed),
        m.connections_active.load(Ordering::Relaxed),
    ));

    // Pool
    json.push_str("  \"pool\": {\n");
    json.push_str(&format!(
        "    \"checkouts\": {},\n",
        m.pool_checkouts.load(Ordering::Relaxed)
    ));
    json.push_str(&format!(
        "    \"reuses\": {},\n",
        m.pool_reuses.load(Ordering::Relaxed)
    ));
    json.push_str(&format!(
        "    \"creates\": {},\n",
        m.pool_creates.load(Ordering::Relaxed)
    ));
    json.push_str(&format!(
        "    \"checkins\": {},\n",
        m.pool_checkins.load(Ordering::Relaxed)
    ));
    json.push_str(&format!(
        "    \"discards\": {},\n",
        m.pool_discards.load(Ordering::Relaxed)
    ));
    json.push_str(&format!(
        "    \"timeouts\": {},\n",
        m.pool_timeouts.load(Ordering::Relaxed)
    ));

    json.push_str("    \"buckets\": [");
    if let Some(pool) = &state.pool {
        let snap = pool.snapshot().await;
        for (i, b) in snap.buckets.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                "\n      {{\"database\": \"{}\", \"role\": \"{}\", \"total\": {}, \"idle\": {}}}",
                b.database, b.role, b.total, b.idle
            ));
        }
        if !snap.buckets.is_empty() {
            json.push('\n');
            json.push_str("    ");
        }
    }
    json.push_str("]\n");
    json.push_str("  },\n");

    // Resolvers
    json.push_str("  \"resolvers\": {\n");
    json.push_str(&format!(
        "    \"cache_hits\": {},\n",
        m.resolver_cache_hits.load(Ordering::Relaxed)
    ));
    json.push_str(&format!(
        "    \"cache_misses\": {},\n",
        m.resolver_cache_misses.load(Ordering::Relaxed)
    ));

    if let Some(resolver) = &state.resolver {
        let cache_size = resolver.cache_size().await;
        json.push_str(&format!("    \"cache_size\": {},\n", cache_size));
    } else {
        json.push_str("    \"cache_size\": 0,\n");
    }

    json.push_str("    \"resolvers\": [");
    for (i, name) in m.resolver_names.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        let execs = m
            .resolver_executions
            .get(i)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        let errs = m
            .resolver_errors
            .get(i)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0);
        json.push_str(&format!(
            "\n      {{\"name\": \"{}\", \"executions\": {}, \"errors\": {}}}",
            name, execs, errs
        ));
    }
    if !m.resolver_names.is_empty() {
        json.push('\n');
        json.push_str("    ");
    }
    json.push_str("]\n");
    json.push_str("  },\n");

    // Tenant isolation
    json.push_str("  \"tenant\": {\n");
    json.push_str(&format!(
        "    \"rejected_deny\": {},\n",
        m.tenant_rejected_deny.load(Ordering::Relaxed)
    ));
    json.push_str(&format!(
        "    \"rejected_limit\": {},\n",
        m.tenant_rejected_limit.load(Ordering::Relaxed)
    ));
    json.push_str(&format!(
        "    \"rejected_rate\": {},\n",
        m.tenant_rejected_rate.load(Ordering::Relaxed)
    ));
    json.push_str(&format!(
        "    \"timeouts\": {}\n",
        m.tenant_timeouts.load(Ordering::Relaxed)
    ));
    json.push_str("  }\n");

    json.push_str("}\n");

    (StatusCode::OK, [("content-type", "application/json")], json).into_response()
}
