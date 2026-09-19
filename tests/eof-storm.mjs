// Regression test for solidcitizen/pgvpd#24 (and its EOF-blind siblings) —
// a client that connects and immediately closes during the handshake must NOT
// busy-spin the connection task until handshake_timeout.
//
// Before the fix, every handshake-phase read loop used `read_buf(...).await?`,
// which returns Ok(0) on EOF. A FIN'd socket therefore returned Ok(0) forever,
// the loop re-tried forever, and the task spun a core at ~100% CPU until the
// handshake timeout fired and logged "handshake timeout". After the fix, every
// such loop reads through `stream::read_or_eof`, which maps Ok(0) to an error,
// so the task ends immediately with a "connection ended" debug and no timeout.
//
// This case never reaches upstream (the client closes during Phase 1 startup),
// so it needs no Postgres — only a booted pgvpd.
//
// Exit 0 (GREEN): no "handshake timeout" logged and the proxy still accepts.
// Exit 2 (RED):   the proxy logged a handshake timeout (i.e. it spun to the cap).
//
// Env: PGVPD_BIN (required).
import { spawn, execSync } from 'node:child_process';
import net from 'node:net';

const BIN = process.env.PGVPD_BIN;
if (!BIN) { console.error('PGVPD_BIN required'); process.exit(3); }

const PROXY = +(process.env.EOF_PROXY_PORT || 16452);
const ADMIN = +(process.env.EOF_ADMIN_PORT || 16453);
const HS = 1;              // handshake_timeout seconds (min allowed)
const N = 15;             // connect-and-close events
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const child = spawn(BIN, [], { env: { ...process.env,
  PGVPD_HOST: '127.0.0.1',
  PGVPD_PORT: String(PROXY), PGVPD_ADMIN_PORT: String(ADMIN),
  // Upstream is never reached in this test — point it at a closed port.
  PGVPD_UPSTREAM_HOST: '127.0.0.1', PGVPD_UPSTREAM_PORT: '1',
  PGVPD_CONTEXT_VARIABLES: 'app.current_tenant_id', PGVPD_TENANT_SEPARATOR: '.',
  PGVPD_HANDSHAKE_TIMEOUT: String(HS), PGVPD_LOG_LEVEL: 'debug' },
  stdio: ['ignore', 'pipe', 'pipe'] });

let logs = '';
child.stdout.on('data', (d) => { logs += d.toString(); });
child.stderr.on('data', (d) => { logs += d.toString(); });
child.on('error', (e) => { logs += 'spawn error: ' + e.message + '\n'; });

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
    await sleep(150);
  }
  return false;
}
// Cumulative CPU seconds of the child, best-effort, cross-platform.
function cpuSeconds() {
  try {
    const t = execSync(`ps -o time= -p ${child.pid}`, { encoding: 'utf8' }).trim();
    // formats: SS, MM:SS, HH:MM:SS, DD-HH:MM:SS (optional fractional seconds)
    const [dh, rest] = t.includes('-') ? t.split('-') : [null, t];
    const parts = rest.split(':').map(Number);
    let s = 0; for (const p of parts) s = s * 60 + p;
    if (dh !== null) s += Number(dh) * 86400;
    return s;
  } catch { return NaN; }
}
// One raw connect that immediately FINs — no StartupMessage sent.
function connectAndClose() {
  return new Promise((resolve) => {
    const s = net.connect(PROXY, '127.0.0.1');
    s.once('connect', () => { s.end(); resolve(); });   // FIN, no bytes
    s.once('error', () => resolve());
  });
}

let code = 0;
try {
  if (!(await waitForProxy(15000))) {
    console.log('SETUP FAIL: proxy never came up | exit=', child.exitCode, '| logs:', logs.slice(0, 400));
    child.kill('SIGKILL'); process.exit(3);
  }
  await sleep(200);

  const cpuBefore = cpuSeconds();
  const t0 = Date.now();
  await Promise.all(Array.from({ length: N }, connectAndClose));
  // Wait past the handshake timeout so a spinning build has time to log it.
  await sleep(HS * 1000 + 800);
  const cpuAfter = cpuSeconds();

  // Count only the per-connection timeout warn (carries conn_id) — not pgvpd's
  // startup line that reports the configured "handshake timeout" value.
  const timeouts = logs.split('\n')
    .filter((l) => l.includes('handshake timeout') && l.includes('conn_id')).length;
  const stillUp = await portOpen(PROXY);
  const cpuDelta = Number.isNaN(cpuBefore) || Number.isNaN(cpuAfter) ? null
    : +(cpuAfter - cpuBefore).toFixed(2);

  console.log(JSON.stringify({
    events: N, handshake_timeout_secs: HS, elapsed_ms: Date.now() - t0,
    handshake_timeouts_logged: timeouts, proxy_still_accepts: stillUp,
    child_cpu_seconds_delta: cpuDelta,   // ~0 when fixed; ~N*HS worth of spin when broken
  }, null, 2));

  // The defect signature: a connect-and-close spun to the handshake cap and
  // logged a timeout. Fixed builds never do.
  if (timeouts > 0 || !stillUp) code = 2;
} finally {
  child.kill('SIGKILL');
  await sleep(150);
}
process.exit(code);
