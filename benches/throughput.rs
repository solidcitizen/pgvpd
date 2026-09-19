//! Throughput benchmark: measure pgvpd proxy overhead vs direct connection.
//!
//! Requires a running Postgres on localhost:5432 (or PGVPD_BENCH_PG_PORT)
//! and a running pgvpd on localhost:6432 (or PGVPD_BENCH_PROXY_PORT).
//!
//! Usage:
//!   # Terminal 1: start postgres (e.g., via docker)
//!   docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
//!
//!   # Terminal 2: start pgvpd
//!   ./target/release/pgvpd --upstream-port 5432
//!
//!   # Terminal 3: run benchmark
//!   cargo bench --bench throughput
//!
//! The benchmark measures round-trip latency of `SELECT 1` through both
//! a direct connection and through the pgvpd proxy, reporting the overhead.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Build a Postgres StartupMessage for the given user and database.
fn build_startup(user: &str, database: &str) -> Vec<u8> {
    let mut params = Vec::new();

    // user
    params.extend_from_slice(b"user\0");
    params.extend_from_slice(user.as_bytes());
    params.push(0);

    // database
    params.extend_from_slice(b"database\0");
    params.extend_from_slice(database.as_bytes());
    params.push(0);

    // terminal null
    params.push(0);

    let total_len = 4 + 4 + params.len(); // length + version + params
    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&(total_len as i32).to_be_bytes());
    msg.extend_from_slice(&196608_i32.to_be_bytes()); // protocol 3.0
    msg.extend_from_slice(&params);
    msg
}

/// Build a SimpleQuery ('Q') message.
fn build_query(sql: &str) -> Vec<u8> {
    let msg_len = 4 + sql.len() + 1;
    let mut msg = Vec::with_capacity(1 + msg_len);
    msg.push(b'Q');
    msg.extend_from_slice(&(msg_len as i32).to_be_bytes());
    msg.extend_from_slice(sql.as_bytes());
    msg.push(0);
    msg
}

/// Build a Terminate ('X') message.
fn build_terminate() -> Vec<u8> {
    let mut msg = Vec::with_capacity(5);
    msg.push(b'X');
    msg.extend_from_slice(&4_i32.to_be_bytes());
    msg
}

/// Read backend messages until we see ReadyForQuery ('Z').
fn read_until_ready(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        // Scan for ReadyForQuery ('Z')
        // In the backend message format: type(1) + length(4) + payload
        // ReadyForQuery is: 'Z' + int32(5) + byte(status)
        for (i, &b) in buf.iter().enumerate().take(n) {
            if b == b'Z' && i + 5 < n {
                // This is a rough scan — sufficient for benchmarking
                return Ok(());
            }
        }
    }
}

/// Send a password message ('p') for cleartext auth.
fn build_password_msg(password: &str) -> Vec<u8> {
    let msg_len = 4 + password.len() + 1;
    let mut msg = Vec::with_capacity(1 + msg_len);
    msg.push(b'p');
    msg.extend_from_slice(&(msg_len as i32).to_be_bytes());
    msg.extend_from_slice(password.as_bytes());
    msg.push(0);
    msg
}

/// Connect, authenticate, and return a ready-to-query stream.
/// Handles both direct (no auth / trust) and cleartext password auth.
fn connect_and_auth(
    addr: &str,
    user: &str,
    database: &str,
    password: Option<&str>,
) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;

    // Send startup
    let startup = build_startup(user, database);
    stream.write_all(&startup).ok()?;

    // Read response — could be AuthOk, AuthCleartext, or ReadyForQuery
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }

    // Check if we got an auth challenge (type 'R')
    if buf[0] == b'R' && n >= 9 {
        let subtype = i32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        match subtype {
            0 => {
                // AuthOk — continue reading until ReadyForQuery
            }
            3 => {
                // Cleartext password
                if let Some(pw) = password {
                    let pw_msg = build_password_msg(pw);
                    stream.write_all(&pw_msg).ok()?;
                } else {
                    return None;
                }
            }
            _ => return None, // Unsupported auth for benchmark
        }
    }

    // Read until ReadyForQuery
    read_until_ready(&mut stream).ok()?;
    Some(stream)
}

/// Run N iterations of `SELECT 1` on the stream, return average latency.
fn bench_select1(stream: &mut TcpStream, iterations: u32) -> Duration {
    let query = build_query("SELECT 1");
    let mut total = Duration::ZERO;

    for _ in 0..iterations {
        let start = Instant::now();
        stream.write_all(&query).unwrap();
        read_until_ready(stream).unwrap();
        total += start.elapsed();
    }

    total / iterations
}

fn main() {
    let pg_port = std::env::var("PGVPD_BENCH_PG_PORT").unwrap_or_else(|_| "5432".into());
    let proxy_port = std::env::var("PGVPD_BENCH_PROXY_PORT").unwrap_or_else(|_| "6432".into());
    let pg_user = std::env::var("PGVPD_BENCH_PG_USER").unwrap_or_else(|_| "postgres".into());
    let pg_pass = std::env::var("PGVPD_BENCH_PG_PASS").ok();
    let db = std::env::var("PGVPD_BENCH_DB").unwrap_or_else(|_| "postgres".into());
    let iterations: u32 = std::env::var("PGVPD_BENCH_ITERATIONS")
        .unwrap_or_else(|_| "1000".into())
        .parse()
        .unwrap_or(1000);

    let warmup = 100;

    println!("pgvpd throughput benchmark");
    println!("──────────────────────────");
    println!("iterations:   {iterations}");
    println!("direct:       localhost:{pg_port}");
    println!("proxy:        localhost:{proxy_port}");
    println!();

    // ─── Direct connection ───────────────────────────────────────────

    let direct_addr = format!("localhost:{pg_port}");
    let mut direct = match connect_and_auth(&direct_addr, &pg_user, &db, pg_pass.as_deref()) {
        Some(s) => s,
        None => {
            eprintln!("Could not connect directly to Postgres at {direct_addr}");
            eprintln!("Start Postgres and try again, or set PGVPD_BENCH_PG_PORT");
            std::process::exit(1);
        }
    };

    // Warmup
    bench_select1(&mut direct, warmup);
    let direct_avg = bench_select1(&mut direct, iterations);
    direct.write_all(&build_terminate()).ok();

    // ─── Proxy connection ────────────────────────────────────────────

    let proxy_addr = format!("localhost:{proxy_port}");
    let proxy_user = format!("{pg_user}.bench_tenant");
    let mut proxy = match connect_and_auth(&proxy_addr, &proxy_user, &db, pg_pass.as_deref()) {
        Some(s) => s,
        None => {
            eprintln!("Could not connect through pgvpd at {proxy_addr}");
            eprintln!("Start pgvpd and try again, or set PGVPD_BENCH_PROXY_PORT");
            std::process::exit(1);
        }
    };

    // Warmup
    bench_select1(&mut proxy, warmup);
    let proxy_avg = bench_select1(&mut proxy, iterations);
    proxy.write_all(&build_terminate()).ok();

    // ─── Results ─────────────────────────────────────────────────────

    let overhead = proxy_avg.saturating_sub(direct_avg);
    let overhead_pct = if direct_avg.as_nanos() > 0 {
        (overhead.as_nanos() as f64 / direct_avg.as_nanos() as f64) * 100.0
    } else {
        0.0
    };

    println!("Results (average per SELECT 1):");
    println!(
        "  direct:    {:>8.1}us",
        direct_avg.as_nanos() as f64 / 1000.0
    );
    println!(
        "  proxy:     {:>8.1}us",
        proxy_avg.as_nanos() as f64 / 1000.0
    );
    println!(
        "  overhead:  {:>8.1}us ({:.1}%)",
        overhead.as_nanos() as f64 / 1000.0,
        overhead_pct
    );
}
