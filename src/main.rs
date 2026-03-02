mod admin;
mod auth;
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

    // Set up tracing with the configured log level
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    eprintln!("{}", banner());

    if let Err(e) = proxy::run(config).await {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
