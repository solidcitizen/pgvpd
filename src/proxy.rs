//! TCP Listener — accepts connections and spawns per-connection tasks.
//! Supports both plain and TLS listeners.

use rustls::ClientConfig;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

use crate::admin::{self, AdminState};
use crate::cancel::CancelRegistry;
use crate::config::{Config, PoolMode};
use crate::connection;
use crate::metrics::Metrics;
use crate::pool::Pool;
use crate::resolver::{self, ResolverEngine};
use crate::stream::ClientStream;
use crate::tenant::TenantRegistry;
use crate::tls;

static CONN_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Start the Pgvpd proxy server.
pub async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    config
        .validate()
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // ─── Build TLS state once at startup ────────────────────────────────

    // TLS termination (client → Pgvpd)
    let tls_acceptor = match (&config.tls_port, &config.tls_cert, &config.tls_key) {
        (Some(_), Some(cert), Some(key)) => {
            let server_config = tls::build_server_config(cert, key)?;
            Some(TlsAcceptor::from(server_config))
        }
        _ => None,
    };

    // TLS origination (Pgvpd → upstream)
    let upstream_tls: Option<Arc<ClientConfig>> = if config.upstream_tls {
        Some(tls::build_client_config(
            config.upstream_tls_verify,
            config.upstream_tls_ca.as_deref(),
        )?)
    } else {
        None
    };

    // ─── Context resolvers (if configured) ──────────────────────────────
    // We need resolver names before creating Metrics, so we load resolvers
    // first (without metrics), then create Metrics, then set metrics on the engine.

    // Peek at resolver names for Metrics initialization
    let resolver_names: Vec<String> = match &config.resolvers {
        Some(path) => {
            let engine = resolver::load_resolvers(path, None)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            engine.resolvers.iter().map(|r| r.name.clone()).collect()
        }
        None => Vec::new(),
    };

    // ─── Metrics ─────────────────────────────────────────────────────────

    let metrics = Arc::new(Metrics::new(resolver_names));

    // Routes client CancelRequests to the right upstream connection (pool mode).
    let cancel_registry = Arc::new(CancelRegistry::new());

    // Now load resolvers for real (with metrics)
    let resolver_engine: Option<Arc<ResolverEngine>> = match &config.resolvers {
        Some(path) => {
            let engine = resolver::load_resolvers(path, Some(Arc::clone(&metrics)))
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            info!(
                resolvers = engine.resolvers.len(),
                file = %path,
                "context resolvers loaded"
            );
            for r in &engine.resolvers {
                let inject_vars: Vec<&str> = r.inject.iter().map(|(k, _)| k.as_str()).collect();
                info!(
                    name = %r.name,
                    params = ?r.params,
                    inject = ?inject_vars,
                    required = r.required,
                    cache_ttl = r.cache_ttl.as_secs(),
                    "  resolver"
                );
            }
            let engine = Arc::new(engine);

            // Spawn cache evictor if any resolver uses caching
            if engine
                .resolvers
                .iter()
                .any(|r| r.cache_ttl > Duration::ZERO)
            {
                let evictor = Arc::clone(&engine);
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        evictor.evict_expired().await;
                    }
                });
            }

            Some(engine)
        }
        None => None,
    };

    // ─── Connection pool (if configured) ────────────────────────────────

    let config = Arc::new(config);

    let pool: Option<Arc<Pool>> = if config.pool_mode == PoolMode::Session {
        let pool = Arc::new(Pool::new(
            Arc::clone(&config),
            upstream_tls.clone(),
            Arc::clone(&metrics),
        ));
        let reaper_pool = Arc::clone(&pool);
        tokio::spawn(async move {
            reaper_pool.idle_reaper().await;
        });
        info!(
            pool_mode = %config.pool_mode,
            pool_size = config.pool_size,
            idle_timeout = config.pool_idle_timeout,
            checkout_timeout = config.pool_checkout_timeout,
            "connection pool"
        );
        Some(pool)
    } else {
        None
    };

    // ─── Tenant isolation (if configured) ──────────────────────────────

    let tenant_registry: Option<Arc<TenantRegistry>> = if config.has_tenant_limits() {
        info!("tenant isolation enabled");
        Some(Arc::new(TenantRegistry::new(&config, Arc::clone(&metrics))))
    } else {
        None
    };

    // ─── Plain listener (always starts) ─────────────────────────────────

    let plain_addr = format!("{}:{}", config.listen_host, config.listen_port);
    let plain_listener = TcpListener::bind(&plain_addr).await?;

    info!(
        addr = %plain_addr,
        upstream = %format!("{}:{}", config.upstream_host, config.upstream_port),
        separator = %config.tenant_separator,
        context_vars = %config.context_variables.join(", "),
        "plain listener"
    );

    if !config.superuser_bypass.is_empty() {
        info!(bypass = %config.superuser_bypass.join(", "), "superuser bypass");
    }

    if upstream_tls.is_some() {
        info!(verify = config.upstream_tls_verify, "upstream TLS enabled");
    }

    info!(
        timeout_secs = config.handshake_timeout_secs,
        "handshake timeout"
    );

    // ─── Admin API (if configured) ──────────────────────────────────────

    if let Some(admin_port) = config.admin_port {
        let admin_state = AdminState {
            metrics: Arc::clone(&metrics),
            pool: pool.clone(),
            resolver: resolver_engine.clone(),
        };
        tokio::spawn(admin::serve(
            admin_state,
            config.admin_host.clone(),
            admin_port,
        ));
    }

    // ─── TLS listener (if configured) ───────────────────────────────────

    if let (Some(tls_port), Some(acceptor)) = (config.tls_port, tls_acceptor) {
        let tls_addr = format!("{}:{}", config.listen_host, tls_port);
        let tls_listener = TcpListener::bind(&tls_addr).await?;
        info!(addr = %tls_addr, "TLS listener");

        let tls_config = Arc::clone(&config);
        let tls_upstream = upstream_tls.clone();
        let tls_pool = pool.clone();
        let tls_resolver = resolver_engine.clone();
        let tls_metrics = Arc::clone(&metrics);
        let tls_tenant = tenant_registry.clone();
        let tls_cancel = Arc::clone(&cancel_registry);

        tokio::spawn(async move {
            loop {
                match tls_listener.accept().await {
                    Ok((socket, _)) => {
                        let config = Arc::clone(&tls_config);
                        let upstream = tls_upstream.clone();
                        let pool = tls_pool.clone();
                        let resolver = tls_resolver.clone();
                        let tenant = tls_tenant.clone();
                        let cancel = Arc::clone(&tls_cancel);
                        let acceptor = acceptor.clone();
                        let m = Arc::clone(&tls_metrics);
                        let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;

                        tokio::spawn(async move {
                            Metrics::inc(&m.connections_total);
                            Metrics::inc(&m.connections_active);
                            match acceptor.accept(socket).await {
                                Ok(tls_stream) => {
                                    let client = ClientStream::Tls(tls_stream);
                                    connection::handle_connection(
                                        client,
                                        config,
                                        upstream,
                                        pool,
                                        resolver,
                                        tenant,
                                        cancel,
                                        Arc::clone(&m),
                                        conn_id,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    debug!(conn_id, error = %e, "TLS handshake failed");
                                }
                            }
                            Metrics::dec(&m.connections_active);
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "TLS accept error");
                    }
                }
            }
        });
    }

    // ─── Plain accept loop (runs on main task) ──────────────────────────

    loop {
        let (socket, _) = plain_listener.accept().await?;
        let config = Arc::clone(&config);
        let upstream = upstream_tls.clone();
        let pool = pool.clone();
        let resolver = resolver_engine.clone();
        let tenant = tenant_registry.clone();
        let cancel = Arc::clone(&cancel_registry);
        let m = Arc::clone(&metrics);
        let conn_id = CONN_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;

        tokio::spawn(async move {
            Metrics::inc(&m.connections_total);
            Metrics::inc(&m.connections_active);
            let client = ClientStream::Plain(socket);
            connection::handle_connection(
                client,
                config,
                upstream,
                pool,
                resolver,
                tenant,
                cancel,
                Arc::clone(&m),
                conn_id,
            )
            .await;
            Metrics::dec(&m.connections_active);
        });
    }
}
