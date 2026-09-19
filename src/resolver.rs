//! Context Resolvers — database-resolved session context.
//!
//! Resolvers are named SQL queries that run post-auth to derive additional session
//! variables from database state. They execute in dependency order, chain results
//! via bind parameters, and cache results with configurable TTL.

use bytes::BytesMut;
use serde::Deserialize;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use crate::metrics::Metrics;
use crate::protocol::{backend, build_query_message, escape_set_value, try_read_backend_message};
use crate::stream::UpstreamStream;

// ─── TOML Deserialization ───────────────────────────────────────────────────

/// Top-level structure of the resolvers TOML file.
#[derive(Debug, Deserialize)]
pub struct ResolverFile {
    pub resolver: Vec<ResolverToml>,
}

/// One `[[resolver]]` block as parsed from TOML.
#[derive(Debug, Deserialize)]
pub struct ResolverToml {
    pub name: String,
    pub query: String,
    #[serde(default)]
    pub params: Vec<String>,
    pub inject: HashMap<String, String>, // session_var -> column_name
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub cache_ttl: u64, // seconds, 0 = no caching
}

// ─── Validated Definitions ──────────────────────────────────────────────────

/// Validated resolver definition in execution order.
#[derive(Debug, Clone)]
pub struct ResolverDef {
    pub name: String,
    pub query: String,
    pub params: Vec<String>,
    pub inject: Vec<(String, String)>, // (session_var, column_name) ordered
    pub required: bool,
    pub depends_on: Vec<String>,
    pub cache_ttl: Duration,
}

// ─── Cache ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    values: HashMap<String, Option<String>>, // column_name -> value
    expires_at: Instant,
}

// ─── Resolver Engine ────────────────────────────────────────────────────────

/// The resolver engine: holds ordered resolvers and a shared result cache.
pub struct ResolverEngine {
    pub resolvers: Vec<ResolverDef>,
    cache: Mutex<HashMap<(String, u64), CacheEntry>>,
    metrics: Option<Arc<Metrics>>,
}

/// Load resolvers from a TOML file, validate, and topologically sort.
pub fn load_resolvers(path: &str, metrics: Option<Arc<Metrics>>) -> Result<ResolverEngine, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read resolver file '{}': {}", path, e))?;

    let parsed: ResolverFile =
        toml::from_str(&content).map_err(|e| format!("invalid TOML in '{}': {}", path, e))?;

    if parsed.resolver.is_empty() {
        return Err(format!(
            "resolver file '{}' contains no [[resolver]] blocks",
            path
        ));
    }

    let defs: Vec<ResolverDef> = parsed
        .resolver
        .into_iter()
        .map(|r| ResolverDef {
            name: r.name,
            query: r.query,
            params: r.params,
            inject: r.inject.into_iter().collect(),
            required: r.required,
            depends_on: r.depends_on,
            cache_ttl: Duration::from_secs(r.cache_ttl),
        })
        .collect();

    // Validate: no duplicate names
    let mut names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for def in &defs {
        if !names.insert(&def.name) {
            return Err(format!("duplicate resolver name: '{}'", def.name));
        }
    }

    // Validate: depends_on references exist
    for def in &defs {
        for dep in &def.depends_on {
            if !names.contains(dep.as_str()) {
                return Err(format!(
                    "resolver '{}' depends on '{}' which does not exist",
                    def.name, dep
                ));
            }
        }
    }

    // Validate: max chain depth
    if defs.len() > 10 {
        return Err("too many resolvers (max 10)".into());
    }

    let sorted = topological_sort(&defs)?;

    Ok(ResolverEngine {
        resolvers: sorted,
        cache: Mutex::new(HashMap::new()),
        metrics,
    })
}

// ─── Topological Sort ───────────────────────────────────────────────────────

fn topological_sort(defs: &[ResolverDef]) -> Result<Vec<ResolverDef>, String> {
    let name_to_idx: HashMap<&str, usize> = defs
        .iter()
        .enumerate()
        .map(|(i, d)| (d.name.as_str(), i))
        .collect();

    let n = defs.len();
    let mut in_degree = vec![0usize; n];
    let mut adj: Vec<Vec<usize>> = vec![vec![]; n];

    for (i, def) in defs.iter().enumerate() {
        for dep_name in &def.depends_on {
            let dep_idx = name_to_idx[dep_name.as_str()];
            adj[dep_idx].push(i);
            in_degree[i] += 1;
        }
    }

    let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
    for (i, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            queue.push_back(i);
        }
    }

    let mut order: Vec<usize> = Vec::with_capacity(n);
    while let Some(idx) = queue.pop_front() {
        order.push(idx);
        for &neighbor in &adj[idx] {
            in_degree[neighbor] -= 1;
            if in_degree[neighbor] == 0 {
                queue.push_back(neighbor);
            }
        }
    }

    if order.len() != n {
        return Err("cycle detected in resolver dependencies".into());
    }

    Ok(order.into_iter().map(|i| defs[i].clone()).collect())
}

// ─── Resolver Execution ─────────────────────────────────────────────────────

impl ResolverEngine {
    /// Current cache size (for admin API).
    pub async fn cache_size(&self) -> usize {
        self.cache.lock().await.len()
    }

    /// Execute all resolvers in order, populating `context` with resolved values.
    /// `context` comes in with static context from username extraction.
    pub async fn resolve_context(
        &self,
        server: &mut UpstreamStream,
        server_buf: &mut BytesMut,
        context: &mut HashMap<String, Option<String>>,
        conn_id: u64,
    ) -> Result<(), io::Error> {
        for (resolver_idx, def) in self.resolvers.iter().enumerate() {
            // Collect input param values
            let mut skip = false;
            let mut input_values: Vec<Option<String>> = Vec::with_capacity(def.params.len());

            for param_name in &def.params {
                match context.get(param_name) {
                    Some(Some(val)) => input_values.push(Some(val.clone())),
                    Some(None) => {
                        input_values.push(None);
                        skip = true;
                    }
                    None => {
                        error!(
                            conn_id,
                            resolver = %def.name,
                            param = %param_name,
                            "resolver references unknown context variable"
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "resolver '{}' references unknown param '{}'",
                                def.name, param_name
                            ),
                        ));
                    }
                }
            }

            // If any input is NULL, skip this resolver
            if skip {
                debug!(conn_id, resolver = %def.name, "skipping — input param is NULL");
                for (session_var, _) in &def.inject {
                    context.insert(session_var.clone(), None);
                }
                continue;
            }

            // Check cache
            let cache_key = if def.cache_ttl > Duration::ZERO {
                let key = make_cache_key(&def.name, &input_values);
                let cache = self.cache.lock().await;
                if let Some(entry) = cache.get(&key)
                    && entry.expires_at > Instant::now()
                {
                    if let Some(m) = &self.metrics {
                        Metrics::inc(&m.resolver_cache_hits);
                    }
                    debug!(conn_id, resolver = %def.name, "cache hit");
                    for (session_var, col_name) in &def.inject {
                        let val = entry.values.get(col_name).cloned().flatten();
                        context.insert(session_var.clone(), val);
                    }
                    continue;
                }
                drop(cache);
                Some(key)
            } else {
                None
            };

            // Execute resolver query
            if let Some(m) = &self.metrics {
                Metrics::inc(&m.resolver_cache_misses);
                if let Some(counter) = m.resolver_executions.get(resolver_idx) {
                    Metrics::inc(counter);
                }
            }
            let result =
                match execute_resolver(server, server_buf, def, &input_values, conn_id).await {
                    Ok(r) => r,
                    Err(e) => {
                        if let Some(m) = &self.metrics
                            && let Some(counter) = m.resolver_errors.get(resolver_idx)
                        {
                            Metrics::inc(counter);
                        }
                        return Err(e);
                    }
                };

            match result {
                None => {
                    if def.required {
                        error!(
                            conn_id,
                            resolver = %def.name,
                            "required resolver returned no rows — terminating"
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("required resolver '{}' returned no rows", def.name),
                        ));
                    }
                    debug!(conn_id, resolver = %def.name, "no rows — setting outputs to NULL");
                    let mut cache_values = HashMap::new();
                    for (session_var, col_name) in &def.inject {
                        context.insert(session_var.clone(), None);
                        cache_values.insert(col_name.clone(), None);
                    }
                    if let Some(key) = cache_key {
                        let mut cache = self.cache.lock().await;
                        cache.insert(
                            key,
                            CacheEntry {
                                values: cache_values,
                                expires_at: Instant::now() + def.cache_ttl,
                            },
                        );
                    }
                }
                Some(row) => {
                    let mut cache_values = HashMap::new();
                    for (session_var, col_name) in &def.inject {
                        let val = row.get(col_name).cloned();
                        cache_values.insert(col_name.clone(), val.clone());
                        context.insert(session_var.clone(), val);
                    }
                    info!(conn_id, resolver = %def.name, "resolved");
                    if let Some(key) = cache_key {
                        let mut cache = self.cache.lock().await;
                        cache.insert(
                            key,
                            CacheEntry {
                                values: cache_values,
                                expires_at: Instant::now() + def.cache_ttl,
                            },
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Evict expired entries from the cache.
    pub async fn evict_expired(&self) {
        let mut cache = self.cache.lock().await;
        let before = cache.len();
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
        let evicted = before - cache.len();
        if evicted > 0 {
            debug!(
                evicted,
                remaining = cache.len(),
                "resolver cache: evicted expired entries"
            );
        }
    }
}

/// Execute a single resolver query. Returns Ok(Some(row)) for first row,
/// Ok(None) for zero rows, or Err on SQL error.
async fn execute_resolver(
    server: &mut UpstreamStream,
    server_buf: &mut BytesMut,
    def: &ResolverDef,
    input_values: &[Option<String>],
    conn_id: u64,
) -> Result<Option<HashMap<String, String>>, io::Error> {
    let sql = substitute_params(&def.query, input_values)?;
    debug!(conn_id, resolver = %def.name, sql = %sql, "executing resolver");

    let query_msg = build_query_message(&sql);
    server.write_all(&query_msg).await?;

    let mut column_names: Vec<String> = Vec::new();
    let mut first_row: Option<HashMap<String, String>> = None;

    loop {
        if server_buf.is_empty() {
            let n = server.read_buf(server_buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed during resolver query",
                ));
            }
        }

        while let Some(msg) = try_read_backend_message(server_buf) {
            match msg.msg_type {
                backend::ROW_DESCRIPTION => {
                    column_names = parse_row_description(&msg.payload);
                    debug!(conn_id, resolver = %def.name, columns = ?column_names, "RowDescription");
                }
                backend::DATA_ROW => {
                    if first_row.is_none() {
                        first_row = Some(parse_data_row(&msg.payload, &column_names));
                    }
                    // Ignore subsequent rows
                }
                backend::COMMAND_COMPLETE | backend::EMPTY_QUERY_RESPONSE => {}
                backend::READY_FOR_QUERY => {
                    return Ok(first_row);
                }
                backend::ERROR_RESPONSE => {
                    let err_msg = msg.error_message();
                    error!(conn_id, resolver = %def.name, error = %err_msg, "resolver query error");
                    drain_to_ready(server, server_buf).await?;
                    return Err(io::Error::other(format!(
                        "resolver '{}' query error: {}",
                        def.name, err_msg
                    )));
                }
                _ => {} // NoticeResponse, etc.
            }
        }
    }
}

/// Consume messages until ReadyForQuery (used after ErrorResponse).
async fn drain_to_ready(
    server: &mut UpstreamStream,
    server_buf: &mut BytesMut,
) -> Result<(), io::Error> {
    loop {
        if server_buf.is_empty() {
            let n = server.read_buf(server_buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "upstream closed while draining to ReadyForQuery",
                ));
            }
        }
        while let Some(msg) = try_read_backend_message(server_buf) {
            if msg.is_ready_for_query() {
                return Ok(());
            }
        }
    }
}

// ─── Parameter Substitution ─────────────────────────────────────────────────

/// Replace $1, $2, ... in SQL with escaped literal values.
/// Replaces in reverse order so $10 doesn't collide with $1.
fn substitute_params(sql: &str, values: &[Option<String>]) -> Result<String, io::Error> {
    let mut result = sql.to_string();
    for i in (0..values.len()).rev() {
        let placeholder = format!("${}", i + 1);
        let replacement = match &values[i] {
            Some(val) => escape_set_value(val),
            None => "NULL".to_string(),
        };
        result = result.replace(&placeholder, &replacement);
    }
    Ok(result)
}

// ─── Cache Key ──────────────────────────────────────────────────────────────

fn make_cache_key(resolver_name: &str, input_values: &[Option<String>]) -> (String, u64) {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for val in input_values {
        val.hash(&mut hasher);
    }
    (resolver_name.to_string(), hasher.finish())
}

// ─── Wire Protocol Parsing ──────────────────────────────────────────────────

/// Parse column names from a RowDescription message payload.
fn parse_row_description(payload: &[u8]) -> Vec<String> {
    if payload.len() < 2 {
        return Vec::new();
    }
    let field_count = i16::from_be_bytes([payload[0], payload[1]]) as usize;
    let mut names = Vec::with_capacity(field_count);
    let mut offset = 2;

    for _ in 0..field_count {
        if offset >= payload.len() {
            break;
        }
        let name_end = payload[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| offset + p)
            .unwrap_or(payload.len());
        let name = String::from_utf8_lossy(&payload[offset..name_end]).to_string();
        offset = name_end + 1;
        // Skip: table_oid(4) + col_num(2) + type_oid(4) + type_size(2) + type_modifier(4) + format_code(2) = 18
        offset += 18;
        names.push(name);
    }

    names
}

/// Parse a DataRow message payload into a map of column_name -> value.
/// NULL values (length = -1) are omitted from the map.
fn parse_data_row(payload: &[u8], column_names: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if payload.len() < 2 {
        return map;
    }
    let field_count = i16::from_be_bytes([payload[0], payload[1]]) as usize;
    let mut offset = 2;

    for i in 0..field_count {
        if offset + 4 > payload.len() {
            break;
        }
        let len = i32::from_be_bytes([
            payload[offset],
            payload[offset + 1],
            payload[offset + 2],
            payload[offset + 3],
        ]);
        offset += 4;

        if len < 0 {
            continue; // NULL
        }

        let len = len as usize;
        if offset + len > payload.len() {
            break;
        }
        let value = String::from_utf8_lossy(&payload[offset..offset + len]).to_string();
        offset += len;

        if i < column_names.len() {
            map.insert(column_names[i].clone(), value);
        }
    }

    map
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_def(name: &str, deps: &[&str]) -> ResolverDef {
        ResolverDef {
            name: name.to_string(),
            query: String::new(),
            params: vec![],
            inject: vec![],
            required: false,
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
            cache_ttl: Duration::ZERO,
        }
    }

    #[test]
    fn test_topological_sort_simple_chain() {
        let defs = vec![
            make_def("c", &["b"]),
            make_def("a", &[]),
            make_def("b", &["a"]),
        ];
        let sorted = topological_sort(&defs).unwrap();
        let names: Vec<&str> = sorted.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_topological_sort_cycle_detected() {
        let defs = vec![make_def("a", &["b"]), make_def("b", &["a"])];
        assert!(topological_sort(&defs).is_err());
    }

    #[test]
    fn test_topological_sort_no_deps() {
        let defs = vec![make_def("x", &[]), make_def("y", &[])];
        let sorted = topological_sort(&defs).unwrap();
        assert_eq!(sorted.len(), 2);
    }

    #[test]
    fn test_substitute_params() {
        let sql = "SELECT * FROM t WHERE a = $1 AND b = $2";
        let vals = vec![Some("hello".to_string()), Some("world".to_string())];
        let result = substitute_params(sql, &vals).unwrap();
        assert_eq!(result, "SELECT * FROM t WHERE a = 'hello' AND b = 'world'");
    }

    #[test]
    fn test_substitute_params_with_quotes() {
        let sql = "SELECT * FROM t WHERE a = $1";
        let vals = vec![Some("it's".to_string())];
        let result = substitute_params(sql, &vals).unwrap();
        assert_eq!(result, "SELECT * FROM t WHERE a = 'it''s'");
    }

    #[test]
    fn test_substitute_params_array_literal() {
        let sql = "SELECT * FROM t WHERE a = ANY($1::uuid[])";
        let vals = vec![Some("{abc,def}".to_string())];
        let result = substitute_params(sql, &vals).unwrap();
        assert_eq!(result, "SELECT * FROM t WHERE a = ANY('{abc,def}'::uuid[])");
    }

    #[test]
    fn test_parse_row_description() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1i16.to_be_bytes()); // 1 field
        payload.extend_from_slice(b"org_id\0");
        payload.extend_from_slice(&[0u8; 18]); // field descriptor
        let names = parse_row_description(&payload);
        assert_eq!(names, vec!["org_id"]);
    }

    #[test]
    fn test_parse_row_description_multiple() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&2i16.to_be_bytes());
        payload.extend_from_slice(b"org_id\0");
        payload.extend_from_slice(&[0u8; 18]);
        payload.extend_from_slice(b"role\0");
        payload.extend_from_slice(&[0u8; 18]);
        let names = parse_row_description(&payload);
        assert_eq!(names, vec!["org_id", "role"]);
    }

    #[test]
    fn test_parse_data_row() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1i16.to_be_bytes()); // 1 field
        payload.extend_from_slice(&3i32.to_be_bytes()); // length 3
        payload.extend_from_slice(b"abc");
        let cols = vec!["org_id".to_string()];
        let row = parse_data_row(&payload, &cols);
        assert_eq!(row.get("org_id").unwrap(), "abc");
    }

    #[test]
    fn test_parse_data_row_null() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1i16.to_be_bytes());
        payload.extend_from_slice(&(-1i32).to_be_bytes()); // NULL
        let cols = vec!["org_id".to_string()];
        let row = parse_data_row(&payload, &cols);
        assert!(!row.contains_key("org_id"));
    }

    #[test]
    fn test_parse_data_row_multiple() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&2i16.to_be_bytes());
        payload.extend_from_slice(&5i32.to_be_bytes());
        payload.extend_from_slice(b"org-1");
        payload.extend_from_slice(&5i32.to_be_bytes());
        payload.extend_from_slice(b"admin");
        let cols = vec!["org_id".to_string(), "role".to_string()];
        let row = parse_data_row(&payload, &cols);
        assert_eq!(row.get("org_id").unwrap(), "org-1");
        assert_eq!(row.get("role").unwrap(), "admin");
    }
}
