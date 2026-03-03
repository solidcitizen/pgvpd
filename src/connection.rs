//! Per-Connection Handler
//!
//! Async state machine managing a single client connection through:
//!   WaitStartup → Authenticating → PostAuth → Resolving → Injecting → Transparent
//!
//! In pool mode, pgvpd authenticates the client itself, checks out a pooled
//! upstream connection, resets + resolves + re-injects context, then enters
//! the transparent pipe.

use bytes::{Buf, BytesMut};
use rustls::ClientConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use crate::auth;
use crate::config::{Config, PoolMode};
use crate::metrics::Metrics;
use crate::pool::{Pool, PoolKey};
use crate::protocol::{
    SSL_DENY, StartupType, build_error_response, build_query_message, build_startup_message,
    escape_set_value, quote_ident, try_read_backend_message, try_read_startup,
};
use crate::resolver::ResolverEngine;
use crate::stream::{ClientStream, UpstreamStream};
use crate::tenant::{TenantGuard, TenantRegistry};
use crate::tls::parse_server_name;

/// Result of the handshake phase.
pub enum HandshakeResult {
    /// Passthrough — direct upstream connection, no pooling.
    Passthrough(UpstreamStream),
    /// Pooled — connection checked out from pool, must be returned on disconnect.
    Pooled {
        stream: UpstreamStream,
        key: PoolKey,
        pool: Arc<Pool>,
    },
    /// Fully handled (cancel request, error, etc.) — nothing more to do.
    Done,
}

/// Handle a single client connection through its full lifecycle.
#[allow(clippy::too_many_arguments)]
pub async fn handle_connection(
    mut client: ClientStream,
    config: Arc<Config>,
    upstream_tls: Option<Arc<ClientConfig>>,
    pool: Option<Arc<Pool>>,
    resolver_engine: Option<Arc<ResolverEngine>>,
    tenant_registry: Option<Arc<TenantRegistry>>,
    config_metrics: Arc<Metrics>,
    conn_id: u64,
) {
    let peer = client
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());
    debug!(conn_id, peer, "new connection");

    let timeout = Duration::from_secs(config.handshake_timeout_secs);

    let (result, _tenant_guard) = match tokio::time::timeout(
        timeout,
        handshake(
            &mut client,
            &config,
            &upstream_tls,
            &pool,
            &resolver_engine,
            &tenant_registry,
            conn_id,
        ),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            debug!(conn_id, error = %e, "connection ended");
            return;
        }
        Err(_) => {
            warn!(conn_id, "handshake timeout");
            send_error(
                &mut client,
                "FATAL",
                "08006",
                "handshake timeout — no StartupMessage received in time",
            )
            .await;
            return;
        }
    };
    // _tenant_guard lives here until handle_connection returns,
    // decrementing the per-tenant active connection count on drop.

    let query_timeout = config.tenant_query_timeout.map(Duration::from_secs);

    match result {
        HandshakeResult::Done => {}
        HandshakeResult::Passthrough(mut server) => {
            debug!(conn_id, "transparent pipe");
            let result = if let Some(timeout) = query_timeout {
                match tokio::time::timeout(
                    timeout,
                    tokio::io::copy_bidirectional(&mut client, &mut server),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        warn!(conn_id, "query timeout (passthrough)");
                        Metrics::inc(&config_metrics.tenant_timeouts);
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "tenant query timeout",
                        ))
                    }
                }
            } else {
                tokio::io::copy_bidirectional(&mut client, &mut server).await
            };
            if let Err(e) = result {
                debug!(conn_id, error = %e, "connection ended");
            }
        }
        HandshakeResult::Pooled {
            mut stream,
            key,
            pool,
        } => {
            debug!(conn_id, "transparent pipe (pooled)");
            if let Err(e) = pipe_pooled(
                &mut client,
                &mut stream,
                conn_id,
                query_timeout,
                &config_metrics,
            )
            .await
            {
                debug!(conn_id, error = %e, "connection ended");
            }
            pool.checkin(key, stream, conn_id).await;
        }
    }
}

/// Bidirectional pipe for pooled connections.
///
/// Unlike `copy_bidirectional`, this intercepts the Postgres Terminate message
/// ('X') from the client so the upstream connection stays alive for pool reuse.
/// If `query_timeout` is set, the connection is terminated after that many seconds
/// of inactivity (no data in either direction).
async fn pipe_pooled(
    client: &mut ClientStream,
    server: &mut UpstreamStream,
    conn_id: u64,
    query_timeout: Option<Duration>,
    metrics: &Metrics,
) -> std::io::Result<()> {
    use std::pin::pin;
    use tokio::time::Instant;

    let mut client_buf = BytesMut::with_capacity(8192);
    let mut server_buf = BytesMut::with_capacity(8192);
    let idle_timeout = query_timeout.unwrap_or(Duration::from_secs(86400 * 365));
    let mut deadline = pin!(tokio::time::sleep(idle_timeout));

    loop {
        tokio::select! {
            result = client.read_buf(&mut client_buf) => {
                let n = result?;
                if n == 0 {
                    debug!(conn_id, "client EOF (no Terminate)");
                    return Ok(());
                }
                if forward_client_messages(&mut client_buf, server).await? {
                    debug!(conn_id, "client sent Terminate — preserving upstream");
                    return Ok(());
                }
                deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
            result = server.read_buf(&mut server_buf) => {
                let n = result?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "upstream closed unexpectedly",
                    ));
                }
                client.write_all(&server_buf).await?;
                server_buf.clear();
                deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
            _ = &mut deadline, if query_timeout.is_some() => {
                warn!(conn_id, "query timeout (pooled)");
                Metrics::inc(&metrics.tenant_timeouts);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "tenant query timeout",
                ));
            }
        }
    }
}

/// Forward complete frontend messages to server, stopping on Terminate ('X').
///
/// Returns `true` if Terminate was found (caller should stop piping).
/// Leaves incomplete messages in the buffer for the next read.
async fn forward_client_messages(
    buf: &mut BytesMut,
    server: &mut UpstreamStream,
) -> std::io::Result<bool> {
    loop {
        if buf.len() < 5 {
            return Ok(false);
        }

        let msg_type = buf[0];
        let length = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if length < 4 {
            // Malformed framing — forward everything, let upstream handle it
            server.write_all(buf).await?;
            buf.clear();
            return Ok(false);
        }
        let total = 1 + length as usize;

        if buf.len() < total {
            return Ok(false); // Incomplete message, wait for more data
        }

        if msg_type == b'X' {
            // Terminate — consume but don't forward
            buf.advance(total);
            return Ok(true);
        }

        server.write_all(&buf[..total]).await?;
        buf.advance(total);
    }
}

/// Run the handshake phases: startup parsing, auth relay, context injection.
async fn handshake(
    client: &mut ClientStream,
    config: &Config,
    upstream_tls: &Option<Arc<ClientConfig>>,
    pool: &Option<Arc<Pool>>,
    resolver_engine: &Option<Arc<ResolverEngine>>,
    tenant_registry: &Option<Arc<TenantRegistry>>,
    conn_id: u64,
) -> Result<(HandshakeResult, Option<TenantGuard>), Box<dyn std::error::Error + Send + Sync>> {
    // ─── Phase 1: Read StartupMessage ───────────────────────────────────

    let mut buf = BytesMut::with_capacity(1024);

    let startup = loop {
        client.read_buf(&mut buf).await?;

        match try_read_startup(&mut buf) {
            Some(StartupType::SslRequest) => {
                debug!(conn_id, "SSL request denied");
                client.write_all(SSL_DENY).await?;
                continue;
            }
            Some(StartupType::CancelRequest) => {
                debug!(conn_id, "cancel request — closing");
                return Ok((HandshakeResult::Done, None));
            }
            Some(StartupType::Startup(s)) => break s,
            None => continue,
        }
    };

    let raw_user = startup.params.get("user").cloned().unwrap_or_default();
    if raw_user.is_empty() {
        send_error(client, "FATAL", "08004", "no username in StartupMessage").await;
        return Ok((HandshakeResult::Done, None));
    }

    let database = startup
        .params
        .get("database")
        .cloned()
        .unwrap_or_else(|| "default".into());

    // ─── Superuser bypass (always passthrough, never pooled) ────────────

    if config.superuser_bypass.contains(&raw_user) {
        info!(conn_id, user = %raw_user, "superuser bypass");
        let mut server = connect_upstream(config, upstream_tls).await?;
        let original = build_startup_message(&startup.params);
        server.write_all(&original).await?;
        if !buf.is_empty() {
            server.write_all(&buf).await?;
        }
        return Ok((HandshakeResult::Passthrough(server), None));
    }

    // ─── Extract tenant context from username ───────────────────────────

    let sep_idx = match raw_user.find(&config.tenant_separator) {
        Some(i) => i,
        None => {
            send_error(
                client,
                "FATAL",
                "28000",
                &format!(
                    "username must contain context values separated by '{}'",
                    config.tenant_separator
                ),
            )
            .await;
            return Ok((HandshakeResult::Done, None));
        }
    };

    let actual_user = &raw_user[..sep_idx];
    let tenant_payload = &raw_user[sep_idx + config.tenant_separator.len()..];

    if actual_user.is_empty() || tenant_payload.is_empty() {
        send_error(
            client,
            "FATAL",
            "28000",
            "empty role or context in username",
        )
        .await;
        return Ok((HandshakeResult::Done, None));
    }

    let context_values: Vec<&str> = if config.context_variables.len() > 1 {
        tenant_payload.split(&config.value_separator).collect()
    } else {
        vec![tenant_payload]
    };

    if context_values.len() != config.context_variables.len() {
        send_error(
            client,
            "FATAL",
            "28000",
            &format!(
                "expected {} context value(s), got {}",
                config.context_variables.len(),
                context_values.len()
            ),
        )
        .await;
        return Ok((HandshakeResult::Done, None));
    }

    info!(
        conn_id,
        role = actual_user,
        database = %database,
        "tenant connection"
    );

    // ─── Tenant isolation checks ────────────────────────────────────────

    let tenant_guard = if let Some(registry) = tenant_registry {
        if let Err(msg) = registry.check_access(tenant_payload) {
            send_error(client, "FATAL", "28000", &msg).await;
            return Ok((HandshakeResult::Done, None));
        }
        match registry.acquire(tenant_payload).await {
            Ok(guard) => Some(guard),
            Err(msg) => {
                send_error(client, "FATAL", "53300", &msg).await;
                return Ok((HandshakeResult::Done, None));
            }
        }
    } else {
        None
    };

    // ─── Branch: pool mode vs passthrough ───────────────────────────────

    if config.pool_mode == PoolMode::Session
        && let Some(pool) = pool
    {
        let (result, _) = handle_pooled(
            client,
            config,
            pool,
            actual_user,
            &database,
            &context_values,
            resolver_engine,
            conn_id,
        )
        .await?;
        return Ok((result, tenant_guard));
    }

    // ─── Passthrough: connect and relay auth ────────────────────────────

    let (result, _) = handle_passthrough(
        client,
        config,
        upstream_tls,
        &startup.params,
        &mut buf,
        actual_user,
        &context_values,
        resolver_engine,
        conn_id,
    )
    .await?;
    Ok((result, tenant_guard))
}

/// Passthrough mode — connect to upstream, relay auth, resolve context, inject.
#[allow(clippy::too_many_arguments)]
async fn handle_passthrough(
    client: &mut ClientStream,
    config: &Config,
    upstream_tls: &Option<Arc<ClientConfig>>,
    startup_params: &HashMap<String, String>,
    buf: &mut BytesMut,
    actual_user: &str,
    context_values: &[&str],
    resolver_engine: &Option<Arc<ResolverEngine>>,
    conn_id: u64,
) -> Result<(HandshakeResult, Option<TenantGuard>), Box<dyn std::error::Error + Send + Sync>> {
    let mut server = connect_upstream(config, upstream_tls).await?;
    debug!(
        conn_id,
        host = %config.upstream_host,
        port = config.upstream_port,
        "connected to upstream"
    );

    // Send rewritten StartupMessage
    let mut rewritten_params = startup_params.clone();
    rewritten_params.insert("user".into(), actual_user.to_string());
    let startup_msg = build_startup_message(&rewritten_params);
    server.write_all(&startup_msg).await?;

    if !buf.is_empty() {
        server.write_all(buf).await?;
        buf.clear();
    }

    // ─── Authentication relay ───────────────────────────────────────────

    let mut server_buf = BytesMut::with_capacity(4096);
    let mut auth_done = false;

    while !auth_done {
        server.read_buf(&mut server_buf).await?;

        while let Some(msg) = try_read_backend_message(&mut server_buf) {
            if msg.is_auth_ok() {
                debug!(conn_id, "authentication OK");
                client.write_all(&msg.raw).await?;
                auth_done = true;
                break;
            }

            if msg.is_error_response() {
                warn!(conn_id, error = %msg.error_message(), "auth error from server");
            }

            client.write_all(&msg.raw).await?;

            if msg.is_auth_challenge() {
                let mut client_buf = BytesMut::with_capacity(1024);
                client.read_buf(&mut client_buf).await?;
                server.write_all(&client_buf).await?;
            }
        }
    }

    // ─── Post-auth — wait for ReadyForQuery ─────────────────────────────

    let buffered_ready: BytesMut = loop {
        if server_buf.is_empty() {
            server.read_buf(&mut server_buf).await?;
        }

        let mut ready_msg = None;
        while let Some(msg) = try_read_backend_message(&mut server_buf) {
            if msg.is_ready_for_query() {
                debug!(
                    conn_id,
                    "ReadyForQuery buffered — resolving + injecting context"
                );
                ready_msg = Some(msg.raw);
                break;
            }

            if msg.is_error_response() {
                warn!(conn_id, error = %msg.error_message(), "post-auth error");
            }

            client.write_all(&msg.raw).await?;
        }

        if let Some(raw) = ready_msg {
            break raw;
        }
    };

    // ─── Resolve context ────────────────────────────────────────────────

    let mut context_map = build_static_context(config, context_values);

    if let Some(engine) = resolver_engine
        && let Err(e) = engine
            .resolve_context(&mut server, &mut server_buf, &mut context_map, conn_id)
            .await
    {
        error!(conn_id, error = %e, "resolver failed — terminating connection");
        send_error(client, "FATAL", "XX000", &format!("resolver failed: {e}")).await;
        return Ok((HandshakeResult::Done, None));
    }

    // ─── Inject all context (static + resolved) ─────────────────────────

    let target_role = config.set_role.as_deref().unwrap_or(actual_user);
    inject_context_from_map(
        &mut server,
        &mut server_buf,
        client,
        target_role,
        &context_map,
        &buffered_ready,
        conn_id,
    )
    .await?;

    // Flush any remaining buffered server data
    if !server_buf.is_empty() {
        client.write_all(&server_buf).await?;
    }

    Ok((HandshakeResult::Passthrough(server), None))
}

/// Pool mode — pgvpd authenticates client, checks out pooled connection,
/// resets, resolves context, injects, then enters transparent pipe.
#[allow(clippy::too_many_arguments)]
async fn handle_pooled(
    client: &mut ClientStream,
    config: &Config,
    pool: &Arc<Pool>,
    actual_user: &str,
    database: &str,
    context_values: &[&str],
    resolver_engine: &Option<Arc<ResolverEngine>>,
    conn_id: u64,
) -> Result<(HandshakeResult, Option<TenantGuard>), Box<dyn std::error::Error + Send + Sync>> {
    // ─── Authenticate client ────────────────────────────────────────────

    let pool_password = config.pool_password.as_deref().unwrap_or("");
    if let Err(e) = auth::authenticate_client(client, pool_password, conn_id).await {
        send_error(client, "FATAL", "28P01", &e).await;
        return Ok((HandshakeResult::Done, None));
    }

    // ─── Checkout from pool ─────────────────────────────────────────────

    let key = PoolKey {
        database: database.to_string(),
        role: actual_user.to_string(),
    };

    let pooled = match pool.checkout(&key, conn_id).await {
        Ok(c) => c,
        Err(e) => {
            send_error(
                client,
                "FATAL",
                "53300",
                &format!("pool checkout failed: {e}"),
            )
            .await;
            return Ok((HandshakeResult::Done, None));
        }
    };

    let mut server = pooled.stream;
    let mut server_buf = BytesMut::with_capacity(4096);

    // ─── Reset connection ───────────────────────────────────────────────

    let reset_msg = build_query_message("DISCARD ALL;");
    server.write_all(&reset_msg).await?;

    loop {
        server.read_buf(&mut server_buf).await?;
        let mut done = false;
        while let Some(msg) = try_read_backend_message(&mut server_buf) {
            if msg.is_error_response() {
                error!(conn_id, error = %msg.error_message(), "pool: DISCARD ALL failed");
                send_error(
                    client,
                    "FATAL",
                    "XX000",
                    &format!("DISCARD ALL failed: {}", msg.error_message()),
                )
                .await;
                return Ok((HandshakeResult::Done, None));
            }
            if msg.is_ready_for_query() {
                done = true;
                break;
            }
        }
        if done {
            break;
        }
    }

    // ─── Resolve context ────────────────────────────────────────────────

    let mut context_map = build_static_context(config, context_values);

    if let Some(engine) = resolver_engine
        && let Err(e) = engine
            .resolve_context(&mut server, &mut server_buf, &mut context_map, conn_id)
            .await
    {
        error!(conn_id, error = %e, "resolver failed (pooled) — terminating");
        send_error(client, "FATAL", "XX000", &format!("resolver failed: {e}")).await;
        return Ok((HandshakeResult::Done, None));
    }

    // ─── Inject context ─────────────────────────────────────────────────

    let mut set_clauses = Vec::new();
    for (var, val) in &context_map {
        match val {
            Some(v) => {
                let safe_val = escape_set_value(v);
                set_clauses.push(format!("SET {var} = {safe_val}"));
            }
            None => {
                set_clauses.push(format!("SET {var} = ''"));
            }
        }
    }
    let target_role = config.set_role.as_deref().unwrap_or(actual_user);
    set_clauses.push(format!("SET ROLE {}", quote_ident(target_role)?));
    let sql = set_clauses.join("; ") + ";";

    debug!(conn_id, sql = %sql, "pool: inject context");
    let query_msg = build_query_message(&sql);
    server.write_all(&query_msg).await?;

    loop {
        server.read_buf(&mut server_buf).await?;
        let mut done = false;
        while let Some(msg) = try_read_backend_message(&mut server_buf) {
            if msg.is_error_response() {
                error!(conn_id, error = %msg.error_message(), "pool: context injection failed");
                send_error(
                    client,
                    "FATAL",
                    "XX000",
                    &format!("context injection failed: {}", msg.error_message()),
                )
                .await;
                return Ok((HandshakeResult::Done, None));
            }
            if msg.is_ready_for_query() {
                done = true;
                break;
            }
        }
        if done {
            break;
        }
    }

    // ─── Synthesize handshake to client ─────────────────────────────────

    for ps in &pooled.param_statuses {
        client.write_all(ps).await?;
    }
    client.write_all(&pooled.backend_key_data).await?;
    let ready = build_ready_for_query();
    client.write_all(&ready).await?;

    let context_summary: String = context_map
        .iter()
        .map(|(k, v)| format!("{}={}", k, v.as_deref().unwrap_or("NULL")))
        .collect::<Vec<_>>()
        .join(", ");

    info!(
        conn_id,
        context = %context_summary,
        role = target_role,
        "context set (pooled)"
    );

    Ok((
        HandshakeResult::Pooled {
            stream: server,
            key,
            pool: Arc::clone(pool),
        },
        None,
    ))
}

/// Build a context map from static (username-extracted) values.
fn build_static_context(
    config: &Config,
    context_values: &[&str],
) -> HashMap<String, Option<String>> {
    let mut map = HashMap::new();
    for (var, val) in config.context_variables.iter().zip(context_values.iter()) {
        map.insert(var.clone(), Some(val.to_string()));
    }
    map
}

/// Inject context from a map of session_var → value. Sends SET statements + SET ROLE,
/// consumes response, forwards buffered ReadyForQuery to client.
async fn inject_context_from_map(
    server: &mut UpstreamStream,
    server_buf: &mut BytesMut,
    client: &mut ClientStream,
    actual_user: &str,
    context: &HashMap<String, Option<String>>,
    buffered_ready: &[u8],
    conn_id: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut set_clauses = Vec::new();
    for (var, val) in context {
        match val {
            Some(v) => {
                // Use escape_literal for static context (validated tenant IDs),
                // escape_set_value for everything else. Since the map merges both,
                // use escape_set_value uniformly — it's safe for all values.
                let safe_val = escape_set_value(v);
                set_clauses.push(format!("SET {var} = {safe_val}"));
            }
            None => {
                set_clauses.push(format!("SET {var} = ''"));
            }
        }
    }
    set_clauses.push(format!("SET ROLE {}", quote_ident(actual_user)?));
    let sql = set_clauses.join("; ") + ";";

    let context_summary: String = context
        .iter()
        .map(|(k, v)| format!("{}={}", k, v.as_deref().unwrap_or("NULL")))
        .collect::<Vec<_>>()
        .join(", ");

    debug!(conn_id, sql = %sql, "injecting");
    let query_msg = build_query_message(&sql);
    server.write_all(&query_msg).await?;

    loop {
        server.read_buf(server_buf).await?;

        let mut injection_done = false;
        while let Some(msg) = try_read_backend_message(server_buf) {
            if msg.is_error_response() {
                error!(conn_id, error = %msg.error_message(), "context injection failed");
                client.write_all(&msg.raw).await?;
                return Err(msg.error_message().into());
            }

            if msg.is_ready_for_query() {
                info!(
                    conn_id,
                    context = %context_summary,
                    role = actual_user,
                    "context set"
                );
                client.write_all(buffered_ready).await?;
                injection_done = true;
                break;
            }

            if msg.is_parameter_status() {
                client.write_all(&msg.raw).await?;
            }
        }

        if injection_done {
            break;
        }
    }

    Ok(())
}

/// Build a ReadyForQuery ('Z') message with 'I' (idle) status.
fn build_ready_for_query() -> BytesMut {
    use bytes::BufMut;
    let mut buf = BytesMut::with_capacity(6);
    buf.put_u8(b'Z');
    buf.put_i32(5);
    buf.put_u8(b'I');
    buf
}

/// Connect to upstream Postgres, optionally wrapping in TLS.
pub async fn connect_upstream(
    config: &Config,
    upstream_tls: &Option<Arc<ClientConfig>>,
) -> Result<UpstreamStream, Box<dyn std::error::Error + Send + Sync>> {
    let tcp = TcpStream::connect((&*config.upstream_host, config.upstream_port)).await?;

    if let Some(tls_config) = upstream_tls {
        let server_name = parse_server_name(&config.upstream_host)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls_config));
        let tls_stream = connector.connect(server_name, tcp).await?;
        Ok(UpstreamStream::Tls(tls_stream))
    } else {
        Ok(UpstreamStream::Plain(tcp))
    }
}

async fn send_error(client: &mut ClientStream, severity: &str, sqlstate: &str, message: &str) {
    warn!(message, "rejecting connection");
    let msg = build_error_response(severity, sqlstate, message);
    let _ = client.write_all(&msg).await;
    let _ = client.shutdown().await;
}
