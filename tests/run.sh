#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# pgvpd Integration Tests
# ============================================================================
# Runs end-to-end tests against a real Postgres instance via Docker.
#
# Usage:  ./tests/run.sh
# ============================================================================

cd "$(dirname "$0")/.."

CI_MODE=false
if [ "${1:-}" = "--ci" ]; then
  CI_MODE=true
fi

PGVPD_PORT=16432
PG_PORT=${PGVPD_TEST_PG_PORT:-15432}
PG_HOST=${PGVPD_TEST_PG_HOST:-127.0.0.1}
PG_DB=pgvpd_test
PG_USER=postgres
PG_PASS=${PGVPD_TEST_PG_PASS:-testpass}
TEST_UUID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UNKNOWN_UUID="00000000-0000-0000-0000-000000000000"

PASSED=0
FAILED=0
ERRORS=""
PGVPD_PID=""

# ─── Helpers ───────────────────────────────────────────────────────────────

cleanup() {
  if [ -n "$PGVPD_PID" ] && kill -0 "$PGVPD_PID" 2>/dev/null; then
    kill "$PGVPD_PID" 2>/dev/null || true
    wait "$PGVPD_PID" 2>/dev/null || true
  fi
  PGVPD_PID=""
}

cleanup_all() {
  cleanup
  if [ "$CI_MODE" = false ]; then
    echo ""
    echo "Stopping Postgres..."
    docker compose -f tests/docker-compose.yml down -v 2>/dev/null || true
  fi
}

trap cleanup_all EXIT

pass() {
  PASSED=$((PASSED + 1))
  echo "  PASS: $1"
}

fail() {
  FAILED=$((FAILED + 1))
  ERRORS="${ERRORS}  FAIL: $1\n"
  echo "  FAIL: $1"
}

PGVPD_BIN="./target/debug/pgvpd"
if [ "$CI_MODE" = true ] && [ -f "./target/release/pgvpd" ]; then
  PGVPD_BIN="./target/release/pgvpd"
fi

start_pgvpd() {
  local config="$1"
  local logfile="tests/pgvpd-test.log"
  $PGVPD_BIN --config "$config" > "$logfile" 2>&1 &
  PGVPD_PID=$!
  # Wait for pgvpd to start accepting connections
  local retries=0
  while ! nc -z $PG_HOST $PGVPD_PORT 2>/dev/null; do
    retries=$((retries + 1))
    if [ $retries -gt 30 ]; then
      echo "ERROR: pgvpd did not start within 3 seconds"
      cat "$logfile"
      exit 1
    fi
    sleep 0.1
  done
}

stop_pgvpd() {
  if [ -n "$PGVPD_PID" ] && kill -0 "$PGVPD_PID" 2>/dev/null; then
    kill "$PGVPD_PID" 2>/dev/null || true
    wait "$PGVPD_PID" 2>/dev/null || true
  fi
  PGVPD_PID=""
}

pgvpd_log() {
  cat tests/pgvpd-test.log 2>/dev/null || true
}

# Run a psql command through pgvpd; captures stdout
run_psql() {
  local user="$1"
  shift
  PGPASSWORD="$PG_PASS" psql -h $PG_HOST -p $PGVPD_PORT -U "$user" -d $PG_DB \
    -t -A --no-psqlrc "$@" 2>&1 || true
}

# Run a psql command through pgvpd with a specific password
run_psql_pw() {
  local user="$1"
  local pw="$2"
  shift 2
  PGPASSWORD="$pw" psql -h $PG_HOST -p $PGVPD_PORT -U "$user" -d $PG_DB \
    -t -A --no-psqlrc "$@" 2>&1 || true
}

# ─── Start Postgres ───────────────────────────────────────────────────────

if [ "$CI_MODE" = false ]; then
  echo "Starting Postgres..."
  docker compose -f tests/docker-compose.yml up -d --wait
else
  echo "CI mode: using existing Postgres at $PG_HOST:$PG_PORT"
fi

echo "Loading fixtures..."
PGPASSWORD="$PG_PASS" psql -h $PG_HOST -p $PG_PORT -U $PG_USER -d $PG_DB \
  -f tests/fixtures.sql -v ON_ERROR_STOP=1 > /dev/null

echo "Building pgvpd..."
cargo build --quiet

# ═══════════════════════════════════════════════════════════════════════════
# Suite 1: Passthrough Mode
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ Suite 1: Passthrough Mode ═══"
start_pgvpd tests/pgvpd-test.conf

# Test 1.1: Tenant A isolation
result=$(run_psql "app_user.tenant_a" -c "SELECT name FROM tenants ORDER BY name")
if echo "$result" | grep -q "Alice Corp" && echo "$result" | grep -q "Alice LLC" && ! echo "$result" | grep -q "Bob"; then
  pass "1.1 Tenant A isolation — sees only tenant_a rows"
else
  fail "1.1 Tenant A isolation — unexpected result: $result"
fi

# Test 1.2: Tenant B isolation
result=$(run_psql "app_user.tenant_b" -c "SELECT name FROM tenants ORDER BY name")
if echo "$result" | grep -q "Bob Inc" && echo "$result" | grep -q "Bob Ltd" && ! echo "$result" | grep -q "Alice"; then
  pass "1.2 Tenant B isolation — sees only tenant_b rows"
else
  fail "1.2 Tenant B isolation — unexpected result: $result"
fi

# Test 1.3: Superuser bypass
result=$(run_psql "postgres" -c "SELECT count(*) FROM tenants")
if echo "$result" | grep -q "4"; then
  pass "1.3 Superuser bypass — sees all 4 rows"
else
  fail "1.3 Superuser bypass — unexpected result: $result"
fi

# Test 1.4: Bad username (no separator)
result=$(run_psql "baduser" -c "SELECT 1" 2>&1)
if echo "$result" | grep -qi "fatal\|error\|refused\|closed"; then
  pass "1.4 Bad username — connection rejected"
else
  fail "1.4 Bad username — expected error, got: $result"
fi

# Test 1.5: Context variable set
result=$(run_psql "app_user.tenant_a" -c "SELECT current_setting('app.current_tenant_id', true)")
if echo "$result" | grep -q "tenant_a"; then
  pass "1.5 Context variable — app.current_tenant_id = tenant_a"
else
  fail "1.5 Context variable — unexpected result: $result"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Suite 2: Pool Mode
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ Suite 2: Pool Mode ═══"
start_pgvpd tests/pgvpd-pool-test.conf

# Test 2.1: Pool auth + tenant isolation
result=$(run_psql "app_user.tenant_a" -c "SELECT name FROM tenants ORDER BY name")
if echo "$result" | grep -q "Alice Corp" && ! echo "$result" | grep -q "Bob"; then
  pass "2.1 Pool auth + isolation — tenant_a isolated"
else
  fail "2.1 Pool auth + isolation — unexpected result: $result"
fi

# Test 2.2: Bad pool password
result=$(run_psql_pw "app_user.tenant_a" "wrongpass" -c "SELECT 1" 2>&1)
if echo "$result" | grep -qi "fatal\|error\|refused\|denied\|closed\|password"; then
  pass "2.2 Bad pool password — rejected"
else
  fail "2.2 Bad pool password — expected error, got: $result"
fi

# Test 2.3: Superuser bypass in pool mode
result=$(run_psql "postgres" -c "SELECT count(*) FROM tenants")
if echo "$result" | grep -q "4"; then
  pass "2.3 Superuser bypass (pool mode) — sees all rows"
else
  fail "2.3 Superuser bypass (pool mode) — unexpected result: $result"
fi

# Test 2.4: Pool reuse — first connection returns to pool, second reuses it
run_psql "app_user.tenant_a" -c "SELECT 1" > /dev/null 2>&1
sleep 0.3
run_psql "app_user.tenant_a" -c "SELECT 1" > /dev/null 2>&1
if pgvpd_log | grep -q "reusing idle connection"; then
  pass "2.4 Pool reuse — idle connection reused"
else
  fail "2.4 Pool reuse — no 'reusing idle connection' in logs"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Suite 3: Resolvers
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ Suite 3: Resolvers ═══"
start_pgvpd tests/pgvpd-resolver-test.conf

# Test 3.1: Resolver populates context
result=$(run_psql "app_user.$TEST_UUID" -c "SELECT current_setting('app.org_id', true)")
if echo "$result" | grep -q "11111111-2222-3333-4444-555555555555"; then
  pass "3.1 Resolver populates context — app.org_id resolved"
else
  fail "3.1 Resolver populates context — unexpected result: $result"
fi

# Also check org_role
result=$(run_psql "app_user.$TEST_UUID" -c "SELECT current_setting('app.org_role', true)")
if echo "$result" | grep -q "admin"; then
  pass "3.1b Resolver populates context — app.org_role = admin"
else
  fail "3.1b Resolver populates context — unexpected org_role: $result"
fi

# Test 3.2: Resolver no rows (unknown UUID)
result=$(run_psql "app_user.$UNKNOWN_UUID" -c "SELECT current_setting('app.org_id', true)")
# With required=false and no rows, the variable should be empty or unset
if [ -z "$(echo "$result" | tr -d '[:space:]')" ] || echo "$result" | grep -q "^$"; then
  pass "3.2 Resolver no rows — app.org_id empty (fail-closed)"
else
  fail "3.2 Resolver no rows — expected empty, got: $result"
fi

# Test 3.3: Cache hit
# First connection populates cache
run_psql "app_user.$TEST_UUID" -c "SELECT 1" > /dev/null 2>&1
# Second connection should hit cache
run_psql "app_user.$TEST_UUID" -c "SELECT 1" > /dev/null 2>&1
if pgvpd_log | grep -q "cache hit"; then
  pass "3.3 Cache hit — resolver result cached"
else
  fail "3.3 Cache hit — no 'cache hit' in logs"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Suite 4: Admin API
# ═══════════════════════════════════════════════════════════════════════════

ADMIN_PORT=19090

echo ""
echo "═══ Suite 4: Admin API ═══"
start_pgvpd tests/pgvpd-admin-test.conf

# Wait for admin port to be ready
retries=0
while ! nc -z $PG_HOST $ADMIN_PORT 2>/dev/null; do
  retries=$((retries + 1))
  if [ $retries -gt 30 ]; then
    echo "ERROR: admin API did not start within 3 seconds"
    pgvpd_log
    fail "4.0 Admin API startup"
    stop_pgvpd
    break
  fi
  sleep 0.1
done

# Test 4.1: Health endpoint
result=$(curl -s http://$PG_HOST:$ADMIN_PORT/health)
if echo "$result" | grep -q '"status":"ok"'; then
  pass "4.1 /health — returns ok"
else
  fail "4.1 /health — unexpected result: $result"
fi

# Test 4.2: Metrics endpoint
result=$(curl -s http://$PG_HOST:$ADMIN_PORT/metrics)
if echo "$result" | grep -q "pgvpd_connections_total" && echo "$result" | grep -q "pgvpd_pool_checkouts_total"; then
  pass "4.2 /metrics — contains expected metric names"
else
  fail "4.2 /metrics — unexpected result: $result"
fi

# Test 4.3: Status endpoint
result=$(curl -s http://$PG_HOST:$ADMIN_PORT/status)
if echo "$result" | grep -q '"connections_total"' && echo "$result" | grep -q '"pool"'; then
  pass "4.3 /status — returns JSON with pool info"
else
  fail "4.3 /status — unexpected result: $result"
fi

# Test 4.4: Metrics update after a connection
run_psql "app_user.tenant_a" -c "SELECT 1" > /dev/null 2>&1
sleep 0.3
result=$(curl -s http://$PG_HOST:$ADMIN_PORT/metrics)
if echo "$result" | grep -q "pgvpd_connections_total [1-9]"; then
  pass "4.4 /metrics — connections_total incremented after connection"
else
  fail "4.4 /metrics — connections_total not incremented: $result"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Suite 5: Tenant Isolation
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ Suite 5: Tenant Isolation ═══"
start_pgvpd tests/pgvpd-tenant-test.conf

# Test 5.1: Denied tenant rejected
result=$(run_psql "app_user.blocked_tenant" -c "SELECT 1" 2>&1)
if echo "$result" | grep -qi "denied\|fatal\|error\|refused\|closed"; then
  pass "5.1 Denied tenant — connection rejected"
else
  fail "5.1 Denied tenant — expected rejection, got: $result"
fi

# Test 5.2: Allowed tenant works
result=$(run_psql "app_user.tenant_a" -c "SELECT 1")
if echo "$result" | grep -q "1"; then
  pass "5.2 Allowed tenant — connection succeeds"
else
  fail "5.2 Allowed tenant — unexpected result: $result"
fi

# Test 5.3: Connection limit enforced
# Start two long-running connections
PGPASSWORD="$PG_PASS" psql -h $PG_HOST -p $PGVPD_PORT -U "app_user.tenant_a" -d $PG_DB \
  -c "SELECT pg_sleep(5)" > /dev/null 2>&1 &
BG_PID1=$!
sleep 0.3
PGPASSWORD="$PG_PASS" psql -h $PG_HOST -p $PGVPD_PORT -U "app_user.tenant_a" -d $PG_DB \
  -c "SELECT pg_sleep(5)" > /dev/null 2>&1 &
BG_PID2=$!
sleep 0.3

# Third should fail (limit is 2)
result=$(run_psql "app_user.tenant_a" -c "SELECT 1" 2>&1)
if echo "$result" | grep -qi "limit\|fatal\|error\|refused\|closed"; then
  pass "5.3 Connection limit — third connection rejected"
else
  fail "5.3 Connection limit — expected rejection, got: $result"
fi

# Cleanup background connections
kill $BG_PID1 2>/dev/null || true
kill $BG_PID2 2>/dev/null || true
wait $BG_PID1 2>/dev/null || true
wait $BG_PID2 2>/dev/null || true
sleep 0.3

# Test 5.4: Connection limit is per-tenant
PGPASSWORD="$PG_PASS" psql -h $PG_HOST -p $PGVPD_PORT -U "app_user.tenant_a" -d $PG_DB \
  -c "SELECT pg_sleep(5)" > /dev/null 2>&1 &
BG_PID1=$!
PGPASSWORD="$PG_PASS" psql -h $PG_HOST -p $PGVPD_PORT -U "app_user.tenant_a" -d $PG_DB \
  -c "SELECT pg_sleep(5)" > /dev/null 2>&1 &
BG_PID2=$!
sleep 0.3

# tenant_b should succeed even though tenant_a is at limit
result=$(run_psql "app_user.tenant_b" -c "SELECT 1")
if echo "$result" | grep -q "1"; then
  pass "5.4 Per-tenant limit — tenant_b succeeds while tenant_a at limit"
else
  fail "5.4 Per-tenant limit — unexpected result: $result"
fi

kill $BG_PID1 2>/dev/null || true
kill $BG_PID2 2>/dev/null || true
wait $BG_PID1 2>/dev/null || true
wait $BG_PID2 2>/dev/null || true
sleep 0.5

# Test 5.5: Query timeout
# pg_sleep(10) should be killed by the 3-second idle timeout
result=$(run_psql "app_user.tenant_a" -c "SELECT pg_sleep(10)" 2>&1)
if echo "$result" | grep -qi "timeout\|fatal\|error\|closed\|server closed"; then
  pass "5.5 Query timeout — long query terminated"
else
  fail "5.5 Query timeout — expected timeout, got: $result"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Suite 6: SQL Helpers
# ═══════════════════════════════════════════════════════════════════════════
# These tests run directly against Postgres (not through pgvpd) since the
# helper functions are pure SQL. Session variables are set manually.

echo ""
echo "═══ Suite 6: SQL Helpers ═══"

# Helper to run psql directly against Postgres (not through pgvpd)
run_pg() {
  PGPASSWORD="$PG_PASS" psql -h $PG_HOST -p $PG_PORT -U $PG_USER -d $PG_DB \
    -t -A --no-psqlrc "$@" 2>&1 || true
}

# Test 6.1: pgvpd_context — basic read
result=$(run_pg -c "SET app.x = 'hello'; SELECT pgvpd_context('app.x');")
if echo "$result" | grep -q "hello"; then
  pass "6.1 pgvpd_context — reads session variable"
else
  fail "6.1 pgvpd_context — expected 'hello', got: $result"
fi

# Test 6.2: pgvpd_context — fail-closed on missing
result=$(run_pg -c "SELECT pgvpd_context('app.unset_var');")
if [ -z "$(echo "$result" | tr -d '[:space:]')" ]; then
  pass "6.2 pgvpd_context — NULL on missing variable (fail-closed)"
else
  fail "6.2 pgvpd_context — expected NULL/empty, got: $result"
fi

# Test 6.3: pgvpd_context_array — comma-separated parsing
result=$(run_pg -c "SET app.ids = 'a,b,c'; SELECT pgvpd_context_array('app.ids');")
if echo "$result" | grep -q "{a,b,c}"; then
  pass "6.3 pgvpd_context_array — parses comma-separated values"
else
  fail "6.3 pgvpd_context_array — expected {a,b,c}, got: $result"
fi

# Test 6.4: pgvpd_context_contains — UUID match
UUID1="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UUID2="11111111-2222-3333-4444-555555555555"
result=$(run_pg -c "SET app.ids = '$UUID1,$UUID2'; SELECT pgvpd_context_contains('app.ids', '$UUID1');")
if echo "$result" | grep -q "t"; then
  pass "6.4 pgvpd_context_contains — finds UUID in list"
else
  fail "6.4 pgvpd_context_contains — expected true, got: $result"
fi

# Test 6.5: pgvpd_context_contains — negative
result=$(run_pg -c "SET app.ids = '$UUID1,$UUID2'; SELECT pgvpd_context_contains('app.ids', '$UNKNOWN_UUID');")
if echo "$result" | grep -q "f"; then
  pass "6.5 pgvpd_context_contains — false for missing UUID"
else
  fail "6.5 pgvpd_context_contains — expected false, got: $result"
fi

# Test 6.6: pgvpd_context_text_contains
result=$(run_pg -c "SET app.roles = 'admin,viewer'; SELECT pgvpd_context_text_contains('app.roles', 'admin');")
if echo "$result" | grep -q "t"; then
  pass "6.6 pgvpd_context_text_contains — finds text in list"
else
  fail "6.6 pgvpd_context_text_contains — expected true, got: $result"
fi

# Test 6.7: pgvpd_context_uuid_array
result=$(run_pg -c "SET app.ids = '$UUID1,$UUID2'; SELECT pgvpd_context_uuid_array('app.ids');")
if echo "$result" | grep -q "$UUID1" && echo "$result" | grep -q "$UUID2"; then
  pass "6.7 pgvpd_context_uuid_array — returns UUID array"
else
  fail "6.7 pgvpd_context_uuid_array — unexpected result: $result"
fi

# Test 6.8: pgvpd_protect_acl — builds policy and enforces access
# Build a multi-path ACL policy on acl_cases
run_pg -c "SELECT pgvpd_protect_acl('acl_cases', '[
  {\"column\": \"creator_id\", \"var\": \"app.user_id\", \"type\": \"uuid\"},
  {\"column\": \"id\", \"var\": \"app.granted_case_ids\", \"type\": \"uuid_array\"},
  {\"column\": \"org_id\", \"var\": \"app.org_id\", \"type\": \"uuid\",
   \"when\": \"pgvpd_context(''app.org_role'') = ''admin''\"}
]');" > /dev/null 2>&1

# Verify policy exists
policy_check=$(run_pg -c "SELECT count(*) FROM pg_policies WHERE tablename = 'acl_cases' AND policyname = 'pgvpd_acl_acl_cases';")
if echo "$policy_check" | grep -q "1"; then
  pass "6.8a pgvpd_protect_acl — policy created"
else
  fail "6.8a pgvpd_protect_acl — policy not found: $policy_check"
fi

# Test that app_user with creator_id match sees the case
result=$(run_pg -c "
  SET ROLE app_user;
  SET app.user_id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  SET app.granted_case_ids = '';
  SET app.org_id = '';
  SET app.org_role = '';
  SELECT title FROM acl_cases ORDER BY title;
  RESET ROLE;
")
if echo "$result" | grep -q "Case owned by test user" && ! echo "$result" | grep -q "Case in other org"; then
  pass "6.8b pgvpd_protect_acl — creator_id path works"
else
  fail "6.8b pgvpd_protect_acl — unexpected result: $result"
fi

# Test that org admin sees all cases in their org
result=$(run_pg -c "
  SET ROLE app_user;
  SET app.user_id = '00000000-0000-0000-0000-000000000000';
  SET app.granted_case_ids = '';
  SET app.org_id = '11111111-2222-3333-4444-555555555555';
  SET app.org_role = 'admin';
  SELECT title FROM acl_cases ORDER BY title;
  RESET ROLE;
")
if echo "$result" | grep -q "Case owned by test user" && echo "$result" | grep -q "Case in same org" && ! echo "$result" | grep -q "Case in other org"; then
  pass "6.8c pgvpd_protect_acl — org admin path works"
else
  fail "6.8c pgvpd_protect_acl — unexpected result: $result"
fi

# Test that uuid_array grant path works
result=$(run_pg -c "
  SET ROLE app_user;
  SET app.user_id = '00000000-0000-0000-0000-000000000000';
  SET app.granted_case_ids = 'aaaaaaaa-0000-0000-0000-000000000003';
  SET app.org_id = '';
  SET app.org_role = '';
  SELECT title FROM acl_cases ORDER BY title;
  RESET ROLE;
")
if echo "$result" | grep -q "Case in other org" && ! echo "$result" | grep -q "Case owned by test user"; then
  pass "6.8d pgvpd_protect_acl — uuid_array grant path works"
else
  fail "6.8d pgvpd_protect_acl — unexpected result: $result"
fi

# ═══════════════════════════════════════════════════════════════════════════
# Suite 7: Drizzle ORM
# ═══════════════════════════════════════════════════════════════════════════

if ! command -v node &>/dev/null; then
  echo ""
  echo "═══ Suite 7: Drizzle ORM (SKIPPED — node not found) ═══"
else
  echo ""
  echo "═══ Suite 7: Drizzle ORM — Passthrough ═══"
  start_pgvpd tests/pgvpd-test.conf

  drizzle_result=0
  (cd tests/drizzle && npm install --silent 2>/dev/null && PGVPD_SUITE=passthrough PGVPD_HOST=$PG_HOST PGVPD_PORT=$PGVPD_PORT PG_DB=$PG_DB PG_PASS=$PG_PASS npx tsx test.ts) || drizzle_result=$?

  if [ $drizzle_result -eq 0 ]; then
    pass "7.1  Drizzle passthrough — tenant_a SELECT"
    pass "7.1b Drizzle passthrough — tenant_b SELECT"
    pass "7.2  Drizzle passthrough — cross-tenant WHERE"
    pass "7.3  Drizzle passthrough — INSERT scoped"
    pass "7.3b Drizzle passthrough — INSERT wrong tenant rejected"
    pass "7.4  Drizzle passthrough — transaction scoped"
    pass "7.5  Drizzle passthrough — superuser bypass"
  else
    fail "7.x  Drizzle passthrough tests failed (exit code $drizzle_result)"
  fi

  stop_pgvpd

  echo ""
  echo "═══ Suite 7P: Drizzle ORM — Pool ═══"
  start_pgvpd tests/pgvpd-pool-test.conf

  drizzle_pool_result=0
  (cd tests/drizzle && PGVPD_SUITE=pool PGVPD_HOST=$PG_HOST PGVPD_PORT=$PGVPD_PORT PG_DB=$PG_DB PG_PASS=$PG_PASS npx tsx test.ts) || drizzle_pool_result=$?

  if [ $drizzle_pool_result -eq 0 ]; then
    pass "7P.1 Drizzle pool — tenant isolation"
    pass "7P.2 Drizzle pool — cross-tenant invisibility"
    pass "7P.3 Drizzle pool — superuser bypass"
  else
    fail "7P.x Drizzle pool tests failed (exit code $drizzle_pool_result)"
  fi

  stop_pgvpd
fi

# ═══════════════════════════════════════════════════════════════════════════
# Suite 8: Multi-Context
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ Suite 8: Multi-Context ═══"
start_pgvpd tests/pgvpd-multicontext-test.conf

# Test 8.1: Multi-context with all values populated
result=$(run_psql "app_user.val_a:val_b" -c "SELECT current_setting('app.ctx_a', true) || ',' || current_setting('app.ctx_b', true)")
if echo "$result" | grep -q "val_a,val_b"; then
  pass "8.1 Multi-context — both variables set correctly"
else
  fail "8.1 Multi-context — unexpected result: $result"
fi

# Test 8.2: Multi-context with second value empty
result=$(run_psql "app_user.val_a:" -c "SELECT current_setting('app.ctx_a', true) || ',' || current_setting('app.ctx_b', true)")
if echo "$result" | grep -q "val_a,"; then
  pass "8.2 Multi-context — empty second segment accepted"
else
  fail "8.2 Multi-context — unexpected result: $result"
fi

# Test 8.3: Multi-context with first value empty
result=$(run_psql "app_user.:val_b" -c "SELECT current_setting('app.ctx_a', true) || ',' || current_setting('app.ctx_b', true)")
if echo "$result" | grep -q ",val_b"; then
  pass "8.3 Multi-context — empty first segment accepted"
else
  fail "8.3 Multi-context — unexpected result: $result"
fi

# Test 8.4: Wrong number of values — still rejected
result=$(run_psql "app_user.only_one" -c "SELECT 1" 2>&1)
if echo "$result" | grep -qi "fatal\|error\|refused\|closed"; then
  pass "8.4 Multi-context — wrong segment count rejected"
else
  fail "8.4 Multi-context — expected rejection, got: $result"
fi

stop_pgvpd

# ═══════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════

TOTAL=$((PASSED + FAILED))
echo ""
echo "═══════════════════════════════════"
echo "  Results: $PASSED/$TOTAL passed"
if [ $FAILED -gt 0 ]; then
  echo ""
  echo -e "$ERRORS"
  echo "═══════════════════════════════════"
  exit 1
else
  echo "  All tests passed."
  echo "═══════════════════════════════════"
  exit 0
fi
