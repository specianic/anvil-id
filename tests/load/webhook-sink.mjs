// tests/load/webhook-sink.mjs: a counting webhook receiver for the OPS-03 exactly-once check.
//
// POST /hook   records the delivery (webhook-id header, event type and user id from the body) and
//              answers 204. A delivery without a webhook-id header is counted as malformed.
// GET  /stats  {"total", "unique", "duplicates": {id: count}, "malformed", "types": {type: n},
//              "user_ids": n distinct data.user_id values}
//
// Signatures are not verified here (the webhook tests prove signing); this sink only counts.
// Standard library only. Env: PORT (default 9000). Run by deploy/compose/ha (service `sink`).

import http from 'node:http';

const PORT = Number.parseInt(process.env.PORT || '9000', 10);
const MAX_BODY = 64 * 1024;

const seen = new Map();
const types = new Map();
const users = new Set();
let total = 0;
let malformed = 0;

function stats() {
  const duplicates = {};
  for (const [id, n] of seen) {
    if (n > 1) duplicates[id] = n;
  }
  return {
    total,
    unique: seen.size,
    duplicates,
    malformed,
    types: Object.fromEntries(types),
    user_ids: users.size,
  };
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/stats') {
    const body = JSON.stringify(stats());
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(body);
    return;
  }
  if (req.method !== 'POST' || req.url !== '/hook') {
    res.writeHead(404);
    res.end();
    return;
  }
  const chunks = [];
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size <= MAX_BODY) chunks.push(c);
  });
  req.on('end', () => {
    total += 1;
    const id = req.headers['webhook-id'];
    if (typeof id !== 'string' || id === '' || size > MAX_BODY) {
      malformed += 1;
    } else {
      seen.set(id, (seen.get(id) || 0) + 1);
      try {
        const event = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        types.set(event.type, (types.get(event.type) || 0) + 1);
        if (event.data && typeof event.data.user_id === 'string') users.add(event.data.user_id);
      } catch {
        malformed += 1;
      }
    }
    res.writeHead(204);
    res.end();
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`webhook sink listening on :${PORT}`);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
