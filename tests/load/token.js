// QUAL-05 token-endpoint benchmark (PRD §6.3): >= 1,000 req/s at p99 < 50 ms, no failures.
//
// client_credentials with client_secret_basic against BASE/token (the default tenant at the public
// host; JWT access token, the tenant's default RS256 key). An open model: constant-arrival-rate
// starts RATE iterations per second whether or not earlier ones finished, so a slow server shows up
// as latency and dropped iterations instead of a lower request rate (no coordinated omission).
//
// Two scenarios: a 15 s warm-up at the same rate (tagged phase=warmup, excluded from the latency
// threshold) and the 60 s measured run (phase=measure). Failure, check and dropped-iteration
// thresholds cover the whole run: a single error anywhere fails it. k6 exits non-zero when a
// threshold fails.
//
// Env: BASE (default http://localhost:8080), RATE (default 1000), CLIENT_ID, CLIENT_SECRET,
// SUMMARY (path of the JSON summary, default summary-token.json). Run by tests/load/run-perf.sh.

import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';

const BASE = __ENV.BASE || 'http://localhost:8080';
const RATE = parseInt(__ENV.RATE || '1000', 10);
const WARMUP = '15s';
const MEASURE = '60s';

if (!__ENV.CLIENT_ID || !__ENV.CLIENT_SECRET) {
  throw new Error('CLIENT_ID and CLIENT_SECRET are required');
}

const arrival = {
  executor: 'constant-arrival-rate',
  rate: RATE,
  timeUnit: '1s',
  preAllocatedVUs: 100,
  maxVUs: 400,
};

export const options = {
  discardResponseBodies: true,
  scenarios: {
    warmup: { ...arrival, duration: WARMUP, tags: { phase: 'warmup' } },
    measure: { ...arrival, duration: MEASURE, startTime: WARMUP, tags: { phase: 'measure' } },
  },
  thresholds: {
    'http_req_duration{phase:measure}': ['p(99)<50'],
    http_req_failed: ['rate==0'],
    checks: ['rate==1'],
    dropped_iterations: ['count==0'],
    // Recorded in the summary (measured throughput); no threshold of its own.
    'http_reqs{phase:measure}': ['count>=0'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

const AUTH =
  'Basic ' +
  encoding.b64encode(
    `${encodeURIComponent(__ENV.CLIENT_ID)}:${encodeURIComponent(__ENV.CLIENT_SECRET)}`,
  );
const PARAMS = {
  headers: {
    Authorization: AUTH,
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  },
};

export default function () {
  const r = http.post(`${BASE}/token`, 'grant_type=client_credentials', PARAMS);
  check(r, { 'status 200': (x) => x.status === 200 });
}

// The JSON summary for run-perf.sh (median of trials, job summary). Written here instead of
// `--summary-export` so the file format does not depend on the k6 CLI flags.
export function handleSummary(data) {
  const m = data.metrics;
  const value = (name, stat) => (m[name] && m[name].values ? m[name].values[stat] : undefined);
  const line =
    `token: p99=${value('http_req_duration{phase:measure}', 'p(99)')} ms, ` +
    `reqs(measure)=${value('http_reqs{phase:measure}', 'count')}, ` +
    `failed=${value('http_req_failed', 'rate')}, ` +
    `dropped=${value('dropped_iterations', 'count') || 0}\n`;
  return {
    [__ENV.SUMMARY || 'summary-token.json']: JSON.stringify(data, null, 2),
    stdout: line,
  };
}
