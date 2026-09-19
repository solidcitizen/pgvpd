//! Configuration — CLI flags, environment variables, config file.

use clap::Parser;
use std::fmt;
use std::fs;
use std::path::Path;

/// Pool mode — how upstream connections are managed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolMode {
    /// No pooling — each client gets a fresh upstream connection (passthrough auth).
    None,
    /// Session pooling — upstream connections are reused across client sessions.
    Session,
}

impl fmt::Display for PoolMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Session => write!(f, "session"),
        }
    }
}

/// Pgvpd — Virtual Private Database for PostgreSQL
#[derive(Parser, Debug)]
#[command(name = "pgvpd", version, about)]
pub struct Cli {
    /// Config file path
    #[arg(long, default_value = "pgvpd.conf")]
    pub config: String,

    /// Listen port
    #[arg(long, short = 'p')]
    pub port: Option<u16>,

    /// Bind address
    #[arg(long)]
    pub listen_host: Option<String>,

    /// Upstream Postgres host
    #[arg(long)]
    pub upstream_host: Option<String>,

    /// Upstream Postgres port
    #[arg(long)]
    pub upstream_port: Option<u16>,

    /// Tenant separator in username
    #[arg(long)]
    pub separator: Option<String>,

    /// Comma-separated context variable names
    #[arg(long)]
    pub context: Option<String>,

    /// Separator for multiple values in tenant payload
    #[arg(long)]
    pub value_separator: Option<String>,

    /// Comma-separated superuser bypass usernames
    #[arg(long)]
    pub superuser: Option<String>,

    /// Log level
    #[arg(long)]
    pub log_level: Option<String>,

    /// TLS listen port (enables TLS termination)
    #[arg(long)]
    pub tls_port: Option<u16>,

    /// Path to TLS certificate (PEM)
    #[arg(long)]
    pub tls_cert: Option<String>,

    /// Path to TLS private key (PEM)
    #[arg(long)]
    pub tls_key: Option<String>,

    /// Enable TLS to upstream Postgres
    #[arg(long)]
    pub upstream_tls: bool,

    /// Verify upstream TLS certificate (default: true)
    #[arg(long)]
    pub upstream_tls_verify: Option<bool>,

    /// Path to custom CA certificate for upstream TLS
    #[arg(long)]
    pub upstream_tls_ca: Option<String>,

    /// Handshake timeout in seconds
    #[arg(long)]
    pub handshake_timeout: Option<u64>,

    /// Pool mode: none or session
    #[arg(long)]
    pub pool_mode: Option<String>,

    /// Max upstream connections per (database, role)
    #[arg(long)]
    pub pool_size: Option<u32>,

    /// Password clients must provide in pool mode
    #[arg(long)]
    pub pool_password: Option<String>,

    /// Password pgvpd uses to authenticate to upstream in pool mode
    #[arg(long)]
    pub upstream_password: Option<String>,

    /// Seconds idle before a pooled connection is closed
    #[arg(long)]
    pub pool_idle_timeout: Option<u64>,

    /// Seconds to wait for a connection when pool is full
    #[arg(long)]
    pub pool_checkout_timeout: Option<u64>,

    /// Path to context resolver TOML file
    #[arg(long)]
    pub resolvers: Option<String>,

    /// HTTP port for admin API (health, metrics, status)
    #[arg(long)]
    pub admin_port: Option<u16>,

    /// Host/interface the admin API binds (default: 127.0.0.1)
    #[arg(long)]
    pub admin_host: Option<String>,

    /// Override SET ROLE target (default: use rewritten username)
    #[arg(long)]
    pub set_role: Option<String>,

    /// Comma-separated tenant allow list (only these tenants may connect)
    #[arg(long)]
    pub tenant_allow: Option<String>,

    /// Comma-separated tenant deny list (these tenants are rejected)
    #[arg(long)]
    pub tenant_deny: Option<String>,

    /// Max concurrent connections per tenant
    #[arg(long)]
    pub tenant_max_connections: Option<u32>,

    /// Max new connections per tenant per second
    #[arg(long)]
    pub tenant_rate_limit: Option<u32>,

    /// Seconds of inactivity before tenant connection is terminated
    #[arg(long)]
    pub tenant_query_timeout: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_port: u16,
    pub listen_host: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub tenant_separator: String,
    pub context_variables: Vec<String>,
    pub value_separator: String,
    pub superuser_bypass: Vec<String>,
    pub log_level: String,
    pub tls_port: Option<u16>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub upstream_tls: bool,
    pub upstream_tls_verify: bool,
    pub upstream_tls_ca: Option<String>,
    pub handshake_timeout_secs: u64,
    pub pool_mode: PoolMode,
    pub pool_size: u32,
    pub pool_password: Option<String>,
    pub upstream_password: Option<String>,
    pub pool_idle_timeout: u64,
    pub pool_checkout_timeout: u64,
    pub resolvers: Option<String>,
    pub admin_port: Option<u16>,
    pub admin_host: String,
    pub set_role: Option<String>,
    pub tenant_allow: Option<Vec<String>>,
    pub tenant_deny: Option<Vec<String>>,
    pub tenant_max_connections: Option<u32>,
    pub tenant_rate_limit: Option<u32>,
    pub tenant_query_timeout: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_port: 6432,
            listen_host: "127.0.0.1".into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 5432,
            tenant_separator: ".".into(),
            context_variables: vec!["app.current_tenant_id".into()],
            value_separator: ":".into(),
            superuser_bypass: vec!["postgres".into()],
            log_level: "info".into(),
            tls_port: None,
            tls_cert: None,
            tls_key: None,
            upstream_tls: false,
            upstream_tls_verify: true,
            upstream_tls_ca: None,
            handshake_timeout_secs: 30,
            pool_mode: PoolMode::None,
            pool_size: 20,
            pool_password: None,
            upstream_password: None,
            pool_idle_timeout: 300,
            pool_checkout_timeout: 5,
            resolvers: None,
            admin_port: None,
            admin_host: "127.0.0.1".into(),
            set_role: None,
            tenant_allow: None,
            tenant_deny: None,
            tenant_max_connections: None,
            tenant_rate_limit: None,
            tenant_query_timeout: None,
        }
    }
}

impl Config {
    /// Load configuration: defaults → config file → env vars → CLI flags.
    pub fn load() -> Self {
        let cli = Cli::parse();
        let mut config = Config::default();

        // 1. Config file
        let config_path = Path::new(&cli.config);
        if config_path.exists()
            && let Ok(content) = fs::read_to_string(config_path)
        {
            apply_config_file(&mut config, &content);
        }

        // 2. Environment variables
        apply_env(&mut config);

        // 3. CLI flags (highest priority)
        if let Some(v) = cli.port {
            config.listen_port = v;
        }
        if let Some(v) = cli.listen_host {
            config.listen_host = v;
        }
        if let Some(v) = cli.upstream_host {
            config.upstream_host = v;
        }
        if let Some(v) = cli.upstream_port {
            config.upstream_port = v;
        }
        if let Some(v) = cli.separator {
            config.tenant_separator = v;
        }
        if let Some(v) = cli.context {
            config.context_variables = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Some(v) = cli.value_separator {
            config.value_separator = v;
        }
        if let Some(v) = cli.superuser {
            config.superuser_bypass = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Some(v) = cli.log_level {
            config.log_level = v;
        }
        if let Some(v) = cli.tls_port {
            config.tls_port = Some(v);
        }
        if let Some(v) = cli.tls_cert {
            config.tls_cert = Some(v);
        }
        if let Some(v) = cli.tls_key {
            config.tls_key = Some(v);
        }
        if cli.upstream_tls {
            config.upstream_tls = true;
        }
        if let Some(v) = cli.upstream_tls_verify {
            config.upstream_tls_verify = v;
        }
        if let Some(v) = cli.upstream_tls_ca {
            config.upstream_tls_ca = Some(v);
        }
        if let Some(v) = cli.handshake_timeout {
            config.handshake_timeout_secs = v;
        }
        if let Some(v) = &cli.pool_mode {
            config.pool_mode = parse_pool_mode(v);
        }
        if let Some(v) = cli.pool_size {
            config.pool_size = v;
        }
        if let Some(v) = cli.pool_password {
            config.pool_password = Some(v);
        }
        if let Some(v) = cli.upstream_password {
            config.upstream_password = Some(v);
        }
        if let Some(v) = cli.pool_idle_timeout {
            config.pool_idle_timeout = v;
        }
        if let Some(v) = cli.pool_checkout_timeout {
            config.pool_checkout_timeout = v;
        }
        if let Some(v) = cli.resolvers {
            config.resolvers = Some(v);
        }
        if let Some(v) = cli.admin_port {
            config.admin_port = Some(v);
        }
        if let Some(v) = cli.admin_host {
            config.admin_host = v;
        }
        if let Some(v) = cli.set_role {
            config.set_role = Some(v);
        }
        if let Some(v) = cli.tenant_allow {
            config.tenant_allow = Some(v.split(',').map(|s| s.trim().to_string()).collect());
        }
        if let Some(v) = cli.tenant_deny {
            config.tenant_deny = Some(v.split(',').map(|s| s.trim().to_string()).collect());
        }
        if let Some(v) = cli.tenant_max_connections {
            config.tenant_max_connections = Some(v);
        }
        if let Some(v) = cli.tenant_rate_limit {
            config.tenant_rate_limit = Some(v);
        }
        if let Some(v) = cli.tenant_query_timeout {
            config.tenant_query_timeout = Some(v);
        }

        config
    }

    /// Validate configuration. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.tls_port.is_some() && (self.tls_cert.is_none() || self.tls_key.is_none()) {
            return Err("tls_port requires both tls_cert and tls_key".into());
        }
        if self.handshake_timeout_secs == 0 {
            return Err("handshake_timeout must be > 0".into());
        }
        if self.pool_mode == PoolMode::Session {
            if self.pool_password.is_none() {
                return Err("pool_mode = session requires pool_password".into());
            }
            if self.upstream_password.is_none() {
                return Err("pool_mode = session requires upstream_password".into());
            }
            if self.pool_size == 0 {
                return Err("pool_size must be > 0".into());
            }
        }
        if let Some(ref path) = self.resolvers
            && !std::path::Path::new(path).exists()
        {
            return Err(format!("resolvers file not found: {}", path));
        }
        if self.tenant_allow.is_some() && self.tenant_deny.is_some() {
            return Err("tenant_allow and tenant_deny cannot both be set".into());
        }
        Ok(())
    }

    /// Returns true if any tenant isolation feature is configured.
    pub fn has_tenant_limits(&self) -> bool {
        self.tenant_allow.is_some()
            || self.tenant_deny.is_some()
            || self.tenant_max_connections.is_some()
            || self.tenant_rate_limit.is_some()
    }
}

fn apply_config_file(config: &mut Config, content: &str) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some(eq_pos) = trimmed.find('=') else {
            continue;
        };

        let key = trimmed[..eq_pos].trim();
        let mut value = trimmed[eq_pos + 1..].trim().to_string();

        // Strip quotes
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }

        match key {
            "port" | "listen_port" => {
                if let Ok(v) = value.parse() {
                    config.listen_port = v;
                }
            }
            "listen_host" | "host" => config.listen_host = value,
            "upstream_host" => config.upstream_host = value,
            "upstream_port" => {
                if let Ok(v) = value.parse() {
                    config.upstream_port = v;
                }
            }
            "tenant_separator" | "separator" => config.tenant_separator = value,
            "context_variables" | "context" => {
                config.context_variables = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            "value_separator" => config.value_separator = value,
            "superuser_bypass" | "superuser" => {
                config.superuser_bypass = value.split(',').map(|s| s.trim().to_string()).collect();
            }
            "log_level" => config.log_level = value,
            "tls_port" => {
                if let Ok(v) = value.parse() {
                    config.tls_port = Some(v);
                }
            }
            "tls_cert" => config.tls_cert = Some(value),
            "tls_key" => config.tls_key = Some(value),
            "upstream_tls" => {
                config.upstream_tls = matches!(value.as_str(), "true" | "1" | "yes");
            }
            "upstream_tls_verify" => {
                config.upstream_tls_verify = !matches!(value.as_str(), "false" | "0" | "no");
            }
            "upstream_tls_ca" => config.upstream_tls_ca = Some(value),
            "handshake_timeout" | "handshake_timeout_secs" => {
                if let Ok(v) = value.parse() {
                    config.handshake_timeout_secs = v;
                }
            }
            "pool_mode" => {
                config.pool_mode = parse_pool_mode(&value);
            }
            "pool_size" => {
                if let Ok(v) = value.parse() {
                    config.pool_size = v;
                }
            }
            "pool_password" => config.pool_password = Some(value),
            "upstream_password" => config.upstream_password = Some(value),
            "pool_idle_timeout" => {
                if let Ok(v) = value.parse() {
                    config.pool_idle_timeout = v;
                }
            }
            "pool_checkout_timeout" => {
                if let Ok(v) = value.parse() {
                    config.pool_checkout_timeout = v;
                }
            }
            "resolvers" => config.resolvers = Some(value),
            "admin_port" => {
                if let Ok(v) = value.parse() {
                    config.admin_port = Some(v);
                }
            }
            "admin_host" => config.admin_host = value,
            "set_role" => config.set_role = Some(value),
            "tenant_allow" => {
                config.tenant_allow =
                    Some(value.split(',').map(|s| s.trim().to_string()).collect());
            }
            "tenant_deny" => {
                config.tenant_deny = Some(value.split(',').map(|s| s.trim().to_string()).collect());
            }
            "tenant_max_connections" => {
                if let Ok(v) = value.parse() {
                    config.tenant_max_connections = Some(v);
                }
            }
            "tenant_rate_limit" => {
                if let Ok(v) = value.parse() {
                    config.tenant_rate_limit = Some(v);
                }
            }
            "tenant_query_timeout" => {
                if let Ok(v) = value.parse() {
                    config.tenant_query_timeout = Some(v);
                }
            }
            _ => {}
        }
    }
}

fn apply_env(config: &mut Config) {
    if let Ok(v) = std::env::var("PGVPD_PORT")
        && let Ok(p) = v.parse()
    {
        config.listen_port = p;
    }
    if let Ok(v) = std::env::var("PGVPD_HOST") {
        config.listen_host = v;
    }
    if let Ok(v) = std::env::var("PGVPD_UPSTREAM_HOST") {
        config.upstream_host = v;
    }
    if let Ok(v) = std::env::var("PGVPD_UPSTREAM_PORT")
        && let Ok(p) = v.parse()
    {
        config.upstream_port = p;
    }
    if let Ok(v) = std::env::var("PGVPD_TENANT_SEPARATOR") {
        config.tenant_separator = v;
    }
    if let Ok(v) = std::env::var("PGVPD_CONTEXT_VARIABLES") {
        config.context_variables = v.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Ok(v) = std::env::var("PGVPD_VALUE_SEPARATOR") {
        config.value_separator = v;
    }
    if let Ok(v) = std::env::var("PGVPD_SUPERUSER_BYPASS") {
        config.superuser_bypass = v.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Ok(v) = std::env::var("PGVPD_LOG_LEVEL") {
        config.log_level = v;
    }
    if let Ok(v) = std::env::var("PGVPD_TLS_PORT")
        && let Ok(p) = v.parse()
    {
        config.tls_port = Some(p);
    }
    if let Ok(v) = std::env::var("PGVPD_TLS_CERT") {
        config.tls_cert = Some(v);
    }
    if let Ok(v) = std::env::var("PGVPD_TLS_KEY") {
        config.tls_key = Some(v);
    }
    if let Ok(v) = std::env::var("PGVPD_UPSTREAM_TLS") {
        config.upstream_tls = matches!(v.as_str(), "true" | "1" | "yes");
    }
    if let Ok(v) = std::env::var("PGVPD_UPSTREAM_TLS_VERIFY") {
        config.upstream_tls_verify = !matches!(v.as_str(), "false" | "0" | "no");
    }
    if let Ok(v) = std::env::var("PGVPD_UPSTREAM_TLS_CA") {
        config.upstream_tls_ca = Some(v);
    }
    if let Ok(v) = std::env::var("PGVPD_HANDSHAKE_TIMEOUT")
        && let Ok(t) = v.parse()
    {
        config.handshake_timeout_secs = t;
    }
    if let Ok(v) = std::env::var("PGVPD_POOL_MODE") {
        config.pool_mode = parse_pool_mode(&v);
    }
    if let Ok(v) = std::env::var("PGVPD_POOL_SIZE")
        && let Ok(n) = v.parse()
    {
        config.pool_size = n;
    }
    if let Ok(v) = std::env::var("PGVPD_POOL_PASSWORD") {
        config.pool_password = Some(v);
    }
    if let Ok(v) = std::env::var("PGVPD_UPSTREAM_PASSWORD") {
        config.upstream_password = Some(v);
    }
    if let Ok(v) = std::env::var("PGVPD_POOL_IDLE_TIMEOUT")
        && let Ok(t) = v.parse()
    {
        config.pool_idle_timeout = t;
    }
    if let Ok(v) = std::env::var("PGVPD_POOL_CHECKOUT_TIMEOUT")
        && let Ok(t) = v.parse()
    {
        config.pool_checkout_timeout = t;
    }
    if let Ok(v) = std::env::var("PGVPD_RESOLVERS") {
        config.resolvers = Some(v);
    }
    if let Ok(v) = std::env::var("PGVPD_ADMIN_PORT")
        && let Ok(p) = v.parse()
    {
        config.admin_port = Some(p);
    }
    if let Ok(v) = std::env::var("PGVPD_ADMIN_HOST") {
        config.admin_host = v;
    }
    if let Ok(v) = std::env::var("PGVPD_SET_ROLE") {
        config.set_role = Some(v);
    }
    if let Ok(v) = std::env::var("PGVPD_TENANT_ALLOW") {
        config.tenant_allow = Some(v.split(',').map(|s| s.trim().to_string()).collect());
    }
    if let Ok(v) = std::env::var("PGVPD_TENANT_DENY") {
        config.tenant_deny = Some(v.split(',').map(|s| s.trim().to_string()).collect());
    }
    if let Ok(v) = std::env::var("PGVPD_TENANT_MAX_CONNECTIONS")
        && let Ok(n) = v.parse()
    {
        config.tenant_max_connections = Some(n);
    }
    if let Ok(v) = std::env::var("PGVPD_TENANT_RATE_LIMIT")
        && let Ok(n) = v.parse()
    {
        config.tenant_rate_limit = Some(n);
    }
    if let Ok(v) = std::env::var("PGVPD_TENANT_QUERY_TIMEOUT")
        && let Ok(n) = v.parse()
    {
        config.tenant_query_timeout = Some(n);
    }
}

fn parse_pool_mode(value: &str) -> PoolMode {
    match value.trim().to_lowercase().as_str() {
        "session" => PoolMode::Session,
        _ => PoolMode::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Config file parsing ─────────────────────────────────────────────

    #[test]
    fn parse_basic_config_file() {
        let mut config = Config::default();
        apply_config_file(
            &mut config,
            r#"
port = 7777
upstream_host = db.example.com
upstream_port = 5433
log_level = debug
"#,
        );
        assert_eq!(config.listen_port, 7777);
        assert_eq!(config.upstream_host, "db.example.com");
        assert_eq!(config.upstream_port, 5433);
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn parse_quoted_values() {
        let mut config = Config::default();
        apply_config_file(
            &mut config,
            r#"
upstream_host = "db.example.com"
pool_password = 'my secret'
"#,
        );
        assert_eq!(config.upstream_host, "db.example.com");
        assert_eq!(config.pool_password, Some("my secret".into()));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let mut config = Config::default();
        apply_config_file(
            &mut config,
            r#"
# This is a comment
port = 9999

  # Another comment
upstream_port = 5433
"#,
        );
        assert_eq!(config.listen_port, 9999);
        assert_eq!(config.upstream_port, 5433);
    }

    #[test]
    fn unknown_keys_ignored() {
        let mut config = Config::default();
        apply_config_file(&mut config, "unknown_key = some_value\nport = 8888\n");
        assert_eq!(config.listen_port, 8888);
    }

    #[test]
    fn lines_without_equals_ignored() {
        let mut config = Config::default();
        apply_config_file(&mut config, "no equals sign here\nport = 8888\n");
        assert_eq!(config.listen_port, 8888);
    }

    #[test]
    fn csv_context_variables() {
        let mut config = Config::default();
        apply_config_file(
            &mut config,
            "context_variables = app.tenant_id, app.user_id, app.role\n",
        );
        assert_eq!(
            config.context_variables,
            vec!["app.tenant_id", "app.user_id", "app.role"]
        );
    }

    #[test]
    fn pool_mode_parsing() {
        let mut config = Config::default();
        apply_config_file(&mut config, "pool_mode = session\n");
        assert_eq!(config.pool_mode, PoolMode::Session);

        let mut config = Config::default();
        apply_config_file(&mut config, "pool_mode = none\n");
        assert_eq!(config.pool_mode, PoolMode::None);

        let mut config = Config::default();
        apply_config_file(&mut config, "pool_mode = garbage\n");
        assert_eq!(config.pool_mode, PoolMode::None);
    }

    #[test]
    fn tls_config_from_file() {
        let mut config = Config::default();
        apply_config_file(
            &mut config,
            "tls_port = 6433\ntls_cert = /path/to/cert.pem\ntls_key = /path/to/key.pem\n",
        );
        assert_eq!(config.tls_port, Some(6433));
        assert_eq!(config.tls_cert, Some("/path/to/cert.pem".into()));
        assert_eq!(config.tls_key, Some("/path/to/key.pem".into()));
    }

    #[test]
    fn upstream_tls_booleans() {
        let mut config = Config::default();
        apply_config_file(&mut config, "upstream_tls = true\n");
        assert!(config.upstream_tls);

        let mut config = Config::default();
        apply_config_file(&mut config, "upstream_tls = yes\n");
        assert!(config.upstream_tls);

        let mut config = Config::default();
        apply_config_file(&mut config, "upstream_tls = 1\n");
        assert!(config.upstream_tls);

        let mut config = Config::default();
        apply_config_file(&mut config, "upstream_tls = false\n");
        assert!(!config.upstream_tls);

        // upstream_tls_verify defaults to true; setting false flips it
        let mut config = Config::default();
        apply_config_file(&mut config, "upstream_tls_verify = false\n");
        assert!(!config.upstream_tls_verify);

        let mut config = Config::default();
        apply_config_file(&mut config, "upstream_tls_verify = no\n");
        assert!(!config.upstream_tls_verify);
    }

    #[test]
    fn tenant_lists_from_file() {
        let mut config = Config::default();
        apply_config_file(&mut config, "tenant_allow = alpha, beta, gamma\n");
        assert_eq!(
            config.tenant_allow,
            Some(vec!["alpha".into(), "beta".into(), "gamma".into()])
        );

        let mut config = Config::default();
        apply_config_file(&mut config, "tenant_deny = bad_tenant\n");
        assert_eq!(config.tenant_deny, Some(vec!["bad_tenant".into()]));
    }

    #[test]
    fn all_numeric_fields_parse() {
        let mut config = Config::default();
        apply_config_file(
            &mut config,
            r#"
pool_size = 50
pool_idle_timeout = 600
pool_checkout_timeout = 10
handshake_timeout = 60
tenant_max_connections = 100
tenant_rate_limit = 50
tenant_query_timeout = 30
"#,
        );
        assert_eq!(config.pool_size, 50);
        assert_eq!(config.pool_idle_timeout, 600);
        assert_eq!(config.pool_checkout_timeout, 10);
        assert_eq!(config.handshake_timeout_secs, 60);
        assert_eq!(config.tenant_max_connections, Some(100));
        assert_eq!(config.tenant_rate_limit, Some(50));
        assert_eq!(config.tenant_query_timeout, Some(30));
    }

    #[test]
    fn invalid_numeric_values_are_ignored() {
        let mut config = Config::default();
        apply_config_file(&mut config, "port = not_a_number\n");
        assert_eq!(config.listen_port, 6432); // stays at default
    }

    #[test]
    fn key_aliases() {
        // "listen_port" and "port" are aliases
        let mut config = Config::default();
        apply_config_file(&mut config, "listen_port = 7777\n");
        assert_eq!(config.listen_port, 7777);

        // "host" and "listen_host" are aliases
        let mut config = Config::default();
        apply_config_file(&mut config, "host = 0.0.0.0\n");
        assert_eq!(config.listen_host, "0.0.0.0");

        // "separator" and "tenant_separator" are aliases
        let mut config = Config::default();
        apply_config_file(&mut config, "separator = +\n");
        assert_eq!(config.tenant_separator, "+");

        // "superuser" and "superuser_bypass" are aliases
        let mut config = Config::default();
        apply_config_file(&mut config, "superuser = admin, root\n");
        assert_eq!(config.superuser_bypass, vec!["admin", "root"]);
    }

    // ─── Env var overrides ───────────────────────────────────────────────

    #[test]
    fn env_var_overrides() {
        // Set an env var, apply it, check it took effect
        let mut config = Config::default();
        apply_config_file(&mut config, "port = 7777\n");
        assert_eq!(config.listen_port, 7777);

        // Env var should override config file
        // SAFETY: test runs single-threaded (cargo test default), no concurrent env access
        unsafe { std::env::set_var("PGVPD_PORT", "8888") };
        apply_env(&mut config);
        assert_eq!(config.listen_port, 8888);
        unsafe { std::env::remove_var("PGVPD_PORT") };
    }

    #[test]
    fn env_var_tenant_settings() {
        let mut config = Config::default();
        // SAFETY: test runs single-threaded (cargo test default), no concurrent env access
        unsafe { std::env::set_var("PGVPD_TENANT_ALLOW", "t1,t2,t3") };
        apply_env(&mut config);
        assert_eq!(
            config.tenant_allow,
            Some(vec!["t1".into(), "t2".into(), "t3".into()])
        );
        unsafe { std::env::remove_var("PGVPD_TENANT_ALLOW") };
    }

    // ─── Validation ──────────────────────────────────────────────────────

    #[test]
    fn validate_default_config_passes() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_tls_port_without_cert_fails() {
        let mut config = Config::default();
        config.tls_port = Some(6433);
        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("tls_cert"));
    }

    #[test]
    fn validate_tls_port_with_cert_and_key_passes() {
        let mut config = Config::default();
        config.tls_port = Some(6433);
        config.tls_cert = Some("/tmp/cert.pem".into());
        config.tls_key = Some("/tmp/key.pem".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_zero_handshake_timeout_fails() {
        let mut config = Config::default();
        config.handshake_timeout_secs = 0;
        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("handshake_timeout"));
    }

    #[test]
    fn validate_session_pool_without_password_fails() {
        let mut config = Config::default();
        config.pool_mode = PoolMode::Session;
        config.upstream_password = Some("pass".into());
        // Missing pool_password
        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("pool_password"));
    }

    #[test]
    fn validate_session_pool_without_upstream_password_fails() {
        let mut config = Config::default();
        config.pool_mode = PoolMode::Session;
        config.pool_password = Some("pass".into());
        // Missing upstream_password
        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("upstream_password"));
    }

    #[test]
    fn validate_session_pool_with_zero_pool_size_fails() {
        let mut config = Config::default();
        config.pool_mode = PoolMode::Session;
        config.pool_password = Some("pass".into());
        config.upstream_password = Some("pass".into());
        config.pool_size = 0;
        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("pool_size"));
    }

    #[test]
    fn validate_session_pool_fully_configured_passes() {
        let mut config = Config::default();
        config.pool_mode = PoolMode::Session;
        config.pool_password = Some("pass".into());
        config.upstream_password = Some("pass".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_resolvers_file_not_found_fails() {
        let mut config = Config::default();
        config.resolvers = Some("/nonexistent/path/resolvers.toml".into());
        assert!(config.validate().is_err());
        assert!(
            config
                .validate()
                .unwrap_err()
                .contains("resolvers file not found")
        );
    }

    #[test]
    fn validate_both_allow_and_deny_fails() {
        let mut config = Config::default();
        config.tenant_allow = Some(vec!["a".into()]);
        config.tenant_deny = Some(vec!["b".into()]);
        assert!(config.validate().is_err());
        assert!(
            config
                .validate()
                .unwrap_err()
                .contains("cannot both be set")
        );
    }

    // ─── has_tenant_limits ───────────────────────────────────────────────

    #[test]
    fn has_tenant_limits_detection() {
        let config = Config::default();
        assert!(!config.has_tenant_limits());

        let mut config = Config::default();
        config.tenant_allow = Some(vec!["a".into()]);
        assert!(config.has_tenant_limits());

        let mut config = Config::default();
        config.tenant_deny = Some(vec!["b".into()]);
        assert!(config.has_tenant_limits());

        let mut config = Config::default();
        config.tenant_max_connections = Some(10);
        assert!(config.has_tenant_limits());

        let mut config = Config::default();
        config.tenant_rate_limit = Some(5);
        assert!(config.has_tenant_limits());
    }

    // ─── parse_pool_mode ─────────────────────────────────────────────────

    #[test]
    fn pool_mode_case_insensitive() {
        assert_eq!(parse_pool_mode("Session"), PoolMode::Session);
        assert_eq!(parse_pool_mode("SESSION"), PoolMode::Session);
        assert_eq!(parse_pool_mode("  session  "), PoolMode::Session);
        assert_eq!(parse_pool_mode("none"), PoolMode::None);
        assert_eq!(parse_pool_mode("anything_else"), PoolMode::None);
    }

    #[test]
    fn pool_mode_display() {
        assert_eq!(format!("{}", PoolMode::None), "none");
        assert_eq!(format!("{}", PoolMode::Session), "session");
    }
}
