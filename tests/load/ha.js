// OPS-03 HA scenario: steady token traffic through the load balancer while run-ha.sh restarts the
// three nodes one after another (20 s apart). Every request must succeed: a draining node leaves
// the HAProxy pool before it stops accepting, and HAProxy retries only connection failures.
//
// 300 req/s for 120 s, constant-arrival-rate (open model). Same failure thresholds as token.js;
// no latency threshold (restarts are allowed to cost latency, not errors).
//
// The `shared_limit` scenario hook is filled in by plan 05-26: with small quotas, K requests for
// one client sent to the three nodes directly must be limited in aggregate (quota + burst, not 3x).
// Until then it is not part of `options.scenarios`, so nothing here pretends to test it.
//
// Env: BASE (default http://localhost:8080, the HAProxy frontend), RATE (default 300), CLIENT_ID,
// CLIENT_SECRET, SUMMARY (default summary-ha.json). Run by tests/load/run-ha.sh.

import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';

const BASE = __ENV.BASE || 'http://localhost:8080';
const RATE = parseInt(__ENV.RATE || '300', 10);

if (!__ENV.CLIENT_ID || !__ENV.CLIENT_SECRET) {
  throw new Error('CLIENT_ID and CLIENT_SECRET are required');
}

export const options = {
  discardResponseBodies: true,
  scenarios: {
    through_lb: {
      executor: 'constant-arrival-rate',
      rate: RATE,
      timeUnit: '1s',
      duration: '120s',
      preAllocatedVUs: 50,
      maxVUs: 300,
      exec: 'throughLb',
      tags: { phase: 'restarts' },
    },
    // shared_limit: added by 05-26 (see the header).
  },
  thresholds: {
    http_req_failed: ['rate==0'],
    checks: ['rate==1'],
    dropped_iterations: ['count==0'],
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

export function throughLb() {
  const r = http.post(`${BASE}/token`, 'grant_type=client_credentials', PARAMS);
  check(r, { 'status 200': (x) => x.status === 200 });
}

export function handleSummary(data) {
  const m = data.metrics;
  const value = (name, stat) => (m[name] && m[name].values ? m[name].values[stat] : undefined);
  const line =
    `ha: reqs=${value('http_reqs', 'count')}, failed=${value('http_req_failed', 'rate')}, ` +
    `p99=${value('http_req_duration', 'p(99)')} ms, dropped=${value('dropped_iterations', 'count') || 0}\n`;
  return {
    [__ENV.SUMMARY || 'summary-ha.json']: JSON.stringify(data, null, 2),
    stdout: line,
  };
}
