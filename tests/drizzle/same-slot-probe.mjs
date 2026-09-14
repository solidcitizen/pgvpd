// Same-slot drain-pin probe for solidcitizen/pgvpd#14.
//
// #11's fix (1.0.3) makes checkin DRAIN an abandoned in-flight query's response
// before returning the pooled connection, trading "fast but poisoned" for
// "correct but pinned". This probe measures the pin: with pool_size=1, client B
// must reuse client A's exact slot, so B's checkout is delayed by however long
// A's abandoned query still has to run (capped by pgvpd's 5s reset timeout,
// after which the slot is discarded and a fresh one created).
//
// It is a MEASUREMENT, not a pass/fail test by default, because the pinned
// behaviour is correct on 1.0.3 — #14 is about shortening it (cancel the
// abandoned query via client_connection_check_interval). Set THRESHOLD_MS to
// turn it into a red-then-green pin: it exits 2 when the abandon-median exceeds
// the threshold (red before #14 lands, green after the backend cancels).
//
// Env: PGVPD_HOST, PGVPD_PORT, PG_DB, PG_PASS, SLEEP_S (abandoned query length),
//      TRIALS, THRESHOLD_MS (optional).
import pg from 'pg';
const { Client } = pg;

const base = {
  host: process.env.PGVPD_HOST || '127.0.0.1',
  port: +(process.env.PGVPD_PORT || 16432),
  database: process.env.PG_DB || 'pgvpd_test',
  password: process.env.PG_PASS || 'testpass',
};
const user = 'app_user.tenant_a';
const SLEEP_S = +(process.env.SLEEP_S || 3);
const TRIALS = +(process.env.TRIALS || 5);
const THRESHOLD_MS = process.env.THRESHOLD_MS ? +process.env.THRESHOLD_MS : null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function warm() { const c = new Client({ ...base, user }); await c.connect(); await c.query('SELECT 1'); await c.end(); }

async function trial(abandon) {
  const a = new Client({ ...base, user });
  a.on('error', () => {});
  await a.connect();
  if (abandon) {
    a.query(`SELECT pg_sleep(${SLEEP_S})`).catch(() => {});
    await sleep(80);              // let the query reach the backend
    a.connection.stream.destroy(); // abandon mid-query, no Terminate
  } else {
    await a.query('SELECT 1');     // fast, clean control
    await a.end();
  }
  // B must reuse A's slot (pool_size=1). Time checkout + first query.
  const t0 = Date.now();
  const b = new Client({ ...base, user });
  let err = null;
  b.on('error', (e) => { err = e; });
  await b.connect();
  const r = await b.query("SELECT current_setting('app.current_tenant_id') AS t, count(*)::int AS n FROM tenants");
  const ms = Date.now() - t0;
  const ok = !err && r.rows.length === 1 && r.rows[0].t === 'tenant_a' && r.rows[0].n === 2;
  try { await b.end(); } catch { /* ignore */ }
  return { ms, ok };
}

const median = (a) => { const s = a.map((x) => x.ms).sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };

await warm();
const clean = [];
const abandon = [];
for (let i = 0; i < TRIALS; i++) { clean.push(await trial(false)); await sleep(200); }
for (let i = 0; i < TRIALS; i++) { abandon.push(await trial(true)); await sleep(200); }

const cleanMed = median(clean);
const abandonMed = median(abandon);
const correct = clean.every((x) => x.ok) && abandon.every((x) => x.ok);
const out = {
  sleep_s: SLEEP_S,
  trials: TRIALS,
  clean_ms_median: cleanMed,
  abandon_ms_median: abandonMed,
  pin_ms: abandonMed - cleanMed,
  results_all_correct: correct,
  clean_ms: clean.map((x) => x.ms),
  abandon_ms: abandon.map((x) => x.ms),
};
if (THRESHOLD_MS !== null) {
  out.threshold_ms = THRESHOLD_MS;
  out.verdict = abandonMed <= THRESHOLD_MS ? 'PASS' : 'RED (slot pinned; #14 not yet mitigated)';
}
console.log(JSON.stringify(out, null, 2));

// Correctness is always required. Latency only fails when a threshold is set.
const correctnessFail = !correct;
const latencyFail = THRESHOLD_MS !== null && abandonMed > THRESHOLD_MS;
process.exit(correctnessFail || latencyFail ? 2 : 0);
