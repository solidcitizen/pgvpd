mod admin;
mod auth;
mod cancel;
mod config;
mod connection;
mod metrics;
mod pool;
mod protocol;
mod proxy;
mod resolver;
mod stream;
mod tenant;
mod tls;

use std::io::{self, Write};
use tracing_subscriber::EnvFilter;

fn banner() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let label = format!("P G V P D  v{version}");
    let pad_total = 48 - label.len();
    let pad_left = pad_total / 2;
    let pad_right = pad_total - pad_left;
    format!(
        r#"
  ╔══════════════════════════════════════════════════╗
  ║{:pad_left$}{label}{:pad_right$}║
  ║      Virtual Private Database for PostgreSQL     ║
  ║                    [ Rust ]                      ║
  ╚══════════════════════════════════════════════════╝
"#,
        "", "",
    )
}

#[tokio::main]
async fn main() {
    let config = config::Config::load();

    // Set up tracing with the configured log level.
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    // Log through a non-blocking writer (a bounded channel drained by a
    // dedicated worker thread, lossy: drops lines when full) rather than
    // writing to stdout directly on the connection tasks. This keeps logging
    // OFF the connection data path: a slow reader can never block a task, and a
    // closed/destroyed stdout can never fail a write on a task. Writing to
    // stdout directly is fatal when a parent closes both pipes — the write
    // fails, tracing-subscriber's error fallback `eprintln!`s to a now-closed
    // stderr, and `eprintln!` panics on write error, killing the per-connection
    // task and permanently wedging the proxy (issue #21). The `_log_guard` must
    // live for the whole program so buffered lines flush on shutdown.
    let (log_writer, _log_guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_writer(log_writer)
        .init();

    // Banner goes straight to stderr; if stderr is closed this is a one-shot at
    // startup, not on the connection path.
    let _ = writeln!(io::stderr(), "{}", banner());

    if let Err(e) = proxy::run(config).await {
        let _ = writeln!(io::stderr(), "fatal: {e}");
        std::process::exit(1);
    }
}
