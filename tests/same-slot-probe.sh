#!/usr/bin/env bash
set -euo pipefail

# Same-slot drain-pin probe for solidcitizen/pgvpd#14.
#
# Brings up the test Postgres (Docker), starts pgvpd on a single-connection pool
# (tests/pgvpd-pool-size1.conf), and runs tests/drizzle/same-slot-probe.mjs,
# which measures how long an abandoned in-flight query pins the one pool slot
# before the next client can reuse it. Prints a JSON summary. Correct results
# are always required; set THRESHOLD_MS to also fail when the pin exceeds it
# (a red-then-green pin for the #14 fix).
#
# Usage:
#   ./tests/same-slot-probe.sh                 # measure (SLEEP_S=3)
#   SLEEP_S=8 ./tests/same-slot-probe.sh       # longer abandoned query
#   THRESHOLD_MS=200 ./tests/same-slot-probe.sh  # assert the pin is short (post-#14)
#   PGVPD_BIN=/path/to/pgvpd ./tests/same-slot-probe.sh  # probe a specific build
#
# Env: SLEEP_S, TRIALS, THRESHOLD_MS, PGVPD_BIN, PGVPD_TEST_PG_PORT.

cd "$(dirname "$0")/.."

PG_HOST=127.0.0.1
PG_PORT=${PGVPD_TEST_PG_PORT:-15432}
PGVPD_PORT=16432
PGVPD_LOG=/tmp/pgvpd-same-slot-probe.log

BIN=${PGVPD_BIN:-./target/release/pgvpd}
if [ ! -x "$BIN" ]; then
  echo "Building pgvpd (release)…"
  cargo build --release
  BIN=./target/release/pgvpd
fi

STARTED_PG=0
if ! docker compose -f tests/docker-compose.yml ps --status running 2>/dev/null | grep -q postgres; then
  echo "Starting test Postgres…"
  docker compose -f tests/docker-compose.yml up -d --wait
  STARTED_PG=1
fi
PGPASSWORD=testpass psql -h "$PG_HOST" -p "$PG_PORT" -U postgres -d pgvpd_test \
  -f tests/fixtures.sql -v ON_ERROR_STOP=1 >/dev/null

lsof -tiTCP:$PGVPD_PORT -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
"$BIN" --config tests/pgvpd-pool-size1.conf > "$PGVPD_LOG" 2>&1 &
PGVPD_PID=$!

cleanup() {
  kill "$PGVPD_PID" 2>/dev/null || true
  wait "$PGVPD_PID" 2>/dev/null || true
  if [ "$STARTED_PG" = 1 ]; then
    docker compose -f tests/docker-compose.yml down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Wait for the proxy to accept connections.
for _ in $(seq 1 30); do nc -z "$PG_HOST" "$PGVPD_PORT" 2>/dev/null && break; sleep 0.1; done

( cd tests/drizzle && PGVPD_HOST="$PG_HOST" PGVPD_PORT="$PGVPD_PORT" \
    SLEEP_S="${SLEEP_S:-3}" TRIALS="${TRIALS:-5}" THRESHOLD_MS="${THRESHOLD_MS:-}" \
    node same-slot-probe.mjs )
