// Regression test for solidcitizen/pgvpd#12 — query cancellation in pool mode
// must reach ONLY the cancelling client's own upstream query, never another
// tenant's. Before the fix CancelRequest was dropped (a no-op) and every client
// shared the bucket's cached BackendKeyData, so a naive cancel would have hit an
// arbitrary tenant. pgvpd now hands each client its own minted key and routes a
// CancelRequest through the registry to that client's connection alone.
//
// Setup: two tenants on the same pool bucket, each on its own upstream backend.
// Tenant A runs a long pg_sleep; tenant B runs a short one. We cancel A using
// the key pgvpd handed A. A must be cancelled (57014); B must finish normally.
//
// Exit 0 (GREEN): A cancelled, B unaffected.
// Exit 2 (RED):   A not cancelled (no-op), or B was affected (mis-routed).
//
// Env: PGVPD_BIN (required); UP_HOST/UP_PORT (default 127.0.0.1:15432),
//      PG_DB (default pgvpd_test), PG_PASS (default testpass).
import { spawn } from 'node:child_process';
import net from 'node:net';
import pg from 'pg';

const BIN = process.env.PGVPD_BIN;
if (!BIN) { console.error('PGVPD_BIN required'); process.exit(3); }

const PROXY = 16482, ADMIN = 16483;
let UP_HOST = process.env.UP_HOST || '127.0.0.1';
if (UP_HOST === 'localhost') UP_HOST = '127.0.0.1';
const UP_PORT = +(process.env.UP_PORT || 15432);
const DB = process.env.PG_DB || 'pgvpd_test';
const PASS = process.env.PG_PASS || 'testpass';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const child = spawn(BIN, [], { env: { ...process.env,
  PGVPD_HOST: '127.0.0.1', PGVPD_PORT: String(PROXY), PGVPD_ADMIN_PORT: String(ADMIN),
  PGVPD_UPSTREAM_HOST: UP_HOST, PGVPD_UPSTREAM_PORT: String(UP_PORT),
  PGVPD_CONTEXT_VARIABLES: 'app.current_tenant_id', PGVPD_TENANT_SEPARATOR: '.',
  PGVPD_SUPERUSER_BYPASS: 'postgres', PGVPD_LOG_LEVEL: 'info',
  PGVPD_POOL_MODE: 'session', PGVPD_POOL_SIZE: '4',
  PGVPD_POOL_PASSWORD: PASS, PGVPD_UPSTREAM_PASSWORD: PASS,
  PGVPD_POOL_CHECKOUT_TIMEOUT: '5' },
  stdio: ['ignore', 'pipe', 'pipe'] });
let childErr = '';
child.stdout.on('data', () => {});
child.stderr.on('data', (d) => { if (childErr.length < 2000) childErr += d.toString(); });

function portOpen(port) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    s.setTimeout(1000);
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('timeout', () => { s.destroy(); resolve(false); });
    s.once('error', () => { s.destroy(); resolve(false); });
    s.connect(port, '127.0.0.1');
  });
}
async function waitForProxy(deadlineMs) {
  const end = Date.now() + deadlineMs;
  while (Date.now() < end) {
    if (child.exitCode !== null) return false;
    if (await portOpen(PROXY)) return true;
    await sleep(200);
  }
  return false;
}
// Send a raw CancelRequest to pgvpd using (pid, secret).
function sendCancel(pid, secret) {
  return new Promise((resolve) => {
    const buf = Buffer.alloc(16);
    buf.writeInt32BE(16, 0);
    buf.writeInt32BE(80877102, 4); // CancelRequest code
    buf.writeInt32BE(pid | 0, 8);
    buf.writeInt32BE(secret | 0, 12);
    const s = net.connect(PROXY, '127.0.0.1', () => { s.end(buf); });
    s.on('close', () => resolve());
    s.on('error', () => resolve());
  });
}

let code = 0;
const a = new pg.Client({ user: 'app_user.tenant_a', password: PASS, host: '127.0.0.1', port: PROXY, database: DB });
const b = new pg.Client({ user: 'app_user.tenant_b', password: PASS, host: '127.0.0.1', port: PROXY, database: DB });
try {
  if (!(await waitForProxy(20000))) { console.log('SETUP FAIL: proxy never came up | err:', childErr.slice(0, 300)); child.kill('SIGKILL'); process.exit(3); }
  await sleep(300);
  await a.connect();
  await b.connect();

  const aPid = a.processID, aSecret = a.secretKey;
  const bPid = b.processID, bSecret = b.secretKey;
  if (!Number.isInteger(aPid) || !Number.isInteger(aSecret) || aPid === bPid) {
    console.log('SETUP FAIL: cancel keys unavailable or not distinct', { aPid, aSecret, bPid, bSecret });
    child.kill('SIGKILL'); process.exit(3);
  }

  // Fire both queries; do not await yet.
  let aResult = 'pending', bResult = 'pending';
  const aQuery = a.query('select pg_sleep(30)').then(() => { aResult = 'completed'; }).catch((e) => { aResult = 'ERR:' + (e.code || e.message.slice(0, 30)); });
  const bQuery = b.query('select pg_sleep(2)').then(() => { bResult = 'completed'; }).catch((e) => { bResult = 'ERR:' + (e.code || e.message.slice(0, 30)); });

  await sleep(600); // both queries now in flight upstream

  await sendCancel(aPid, aSecret); // cancel ONLY A

  await Promise.race([aQuery, sleep(5000)]); // A should reject promptly
  await Promise.race([bQuery, sleep(4000)]); // B should finish (~2s)

  // A cancelled => query_canceled (57014). B unaffected => completed.
  const aCancelled = aResult === 'ERR:57014';
  const bOk = bResult === 'completed';
  console.log(JSON.stringify({ aPid, bPid, aResult, bResult, aCancelled, bOk }, null, 2));
  if (!aCancelled || !bOk) code = 2;
} catch (e) {
  console.log('ERROR:', e.message);
  code = 3;
} finally {
  await a.end().catch(() => {});
  await b.end().catch(() => {});
  child.kill('SIGKILL');
  await sleep(150);
}
process.exit(code);
