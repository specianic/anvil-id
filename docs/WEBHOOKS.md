# Webhooks

Added in 0.4. AnvilID can notify your services when users, sessions and (since 1.0)
organizations change: each tenant registers HTTPS endpoints, picks the event types it wants, and
receives signed `POST` requests in the [Standard Webhooks](https://www.standardwebhooks.com/) format.

Webhooks are a notification channel, not a data feed. A payload names **what** happened and the
ids involved. It never carries an email address, a name, an IP address or any other profile data:
fetch what you need from the admin API with the ids.

## Managing endpoints

Through the console (**Webhooks** in a tenant) or the admin API, scope `admin:settings:read` /
`admin:settings:write` (plus `admin:write` for the `system` tenant):

| Route (under `/api/admin/v1/tenants/{slug}`) | What it does |
|---|---|
| `GET /webhooks`, `GET /webhooks/{id}` | List or show endpoints. Secrets are never returned; the view shows `secret_configured` and, during a rotation, `previous_secret_expires_at` |
| `POST /webhooks` | Create: `{name, url, events, enabled}`. The response (`201`) is `{endpoint, secret}`; **the secret is shown only in this response** |
| `PATCH /webhooks/{id}` | Change `name`, `url`, `events` or `enabled` |
| `DELETE /webhooks/{id}` | Delete the endpoint and its delivery log |
| `POST /webhooks/{id}/secret` | Rotate the secret (the new one is shown once; see [Rotation](#secret-rotation)) |
| `POST /webhooks/{id}/test` | Queue a `test` event for this endpoint (`202`), whatever it subscribes to |
| `GET /webhooks/{id}/deliveries` | Delivery log, newest first: status, attempts, last HTTP status, error class, next attempt, completion time. No payloads |
| `POST /webhooks/deliveries/{delivery_id}/redeliver` | Queue a copy of a delivery (`202`). The copy has a new `webhook-id` |

Endpoint names are 1-64 characters of `a-z`, `0-9`, `-` and `_`, starting with a letter or digit,
unique per tenant. The URL must be `https` and must pass the outbound policy (no private,
loopback, link-local or other reserved addresses unless the operator allow-listed them with
`outbound_allow_cidrs`; see [OPERATIONS.md](OPERATIONS.md#outbound-requests)). Plain `http` is accepted
only in development mode. A refused URL is a `422` that names the field.

Webhook endpoints are part of the declarative tenant configuration
([CONFIG-YAML.md](CONFIG-YAML.md)); the secret is written there as `{configured: true}` or
supplied by reference.

## Events

| Type | Sent when | `data` ids |
|---|---|---|
| `user.created` | An administrator creates a user, a user registers, or an upstream sign-in creates an account | `user_id` |
| `user.updated` | An administrator or the user changes the profile, or custom attributes change | `user_id` |
| `user.deleted` | A user is deleted | `user_id` |
| `user.email_verified` | An email address is verified | `user_id` |
| `user.email_changed` | A user's email address changes | `user_id` |
| `user.password_changed` | A password is changed on the account page or reset through recovery | `user_id` |
| `session.created` | A user signs in | `user_id` |
| `session.revoked` | An administrator or the user revokes a session (`session_id`), or all sessions of a user (`user_id`) | `session_id` or `user_id` |
| `session.logged_out` | A user signs out (RP-initiated logout names the relying party) | `session_id`, `user_id` when the user signed out, `client_id` for RP-initiated logout |
| `organization.created` (1.0) | An organization is created | `org_id` |
| `organization.deleted` (1.0) | An organization is deleted (its memberships go with it; no `member_removed` per member) | `org_id` |
| `organization.member_added` (1.0) | A user joins an organization: an administrator adds them, they accept an invitation, or their first sign-in through an organization connection makes them a member | `user_id`, `org_id` |
| `organization.member_removed` (1.0) | An administrator or organization admin removes a member | `user_id`, `org_id` |
| `organization.domain_verified` (1.0) | An organization verifies a domain by DNS TXT record | `domain_id`, `org_id` |
| `organization.domain_unverified` (1.0) | The daily re-check has failed for 7 days and the domain returns to pending ([OPERATIONS.md](OPERATIONS.md#domain-verification-and-the-daily-re-check)) | `domain_id`, `org_id` |
| `test` | The test action of the console or the API | none |

Organization events carry ids only, like every other event: never the organization's slug or
name, nor the domain name (fetch them with
`GET /api/admin/v1/tenants/{slug}/organizations/{org_id}` and `…/domains/{domain_id}`). Other
organization changes (updates, role assignments, invitations, routing settings) are in the audit
log but emit no webhook.

Only successful actions emit events: a failed sign-in never produces `session.created`. Events
are enqueued in the same database transaction as the audit event that records the action, so an
event is never sent for a change that did not commit, and a committed change always has its
deliveries queued.

## Payload

```json
{
  "type": "user.created",
  "timestamp": "2026-11-26T10:00:00Z",
  "data": {
    "tenant": "0195b7a2-6c1e-7d3a-9f00-2b4c1d8e9a10",
    "user_id": "0195b7a3-1f2e-7a4b-8c00-5d6e7f8091a2",
    "actor": { "kind": "user", "id": "0195b7a3-1f2e-7a4b-8c00-5d6e7f8091a2" }
  }
}
```

- `type`: one of the event types above.
- `timestamp`: when the action happened (RFC 3339, UTC).
- `data.tenant`: the **tenant id** (a UUID, the `id` field of the tenant in the admin API), not
  the slug.
- `data.actor`: who did it. `kind` is `user`, `client`, `admin` or `system`; `id` is present when
  there is one (a user id, a client id, or the admin token's subject).
- `data.org_id` and `data.domain_id` (1.0): the organization and domain-claim ids of the
  `organization.*` events.
- Only the ids listed for the event type appear. Ids are copied only when they look like
  identifiers (no `@`, no whitespace, at most 512 bytes; CIMD client ids are URLs).

Treat unknown fields and unknown event types as forward-compatible additions: ignore them.

## Request

Example (illustrative values):

```http
POST /your/endpoint HTTP/1.1
content-type: application/json
webhook-id: 0195b7a4-0a1b-7c2d-8e3f-405162738495
webhook-timestamp: 1795687200
webhook-signature: v1,K5oZfzN95Z9UVu1EsfQmfVNQhnkZ2pj9o9NDN/H/pI4=

{"type":"user.created", ...}
```

| Header | Meaning |
|---|---|
| `webhook-id` | The delivery id. **The same for every retry of one delivery**; a redelivery from the console or API gets a new id |
| `webhook-timestamp` | Unix seconds of this attempt (each retry is signed again at send time) |
| `webhook-signature` | Space-separated list of `v1,<base64>` signatures. Usually one; two during a secret rotation (new secret first) |

AnvilID waits up to 15 seconds for an answer, never follows redirects, and reads at most 64 KiB
of the response body, which it discards.

## Verifying signatures

The secret has the form `whsec_<base64>`. The HMAC key is the **base64-decoded part after the
`whsec_` prefix** (not the string itself). The signature is

```
base64( HMAC-SHA256( key, "{webhook-id}.{webhook-timestamp}.{raw body}" ) )
```

prefixed with `v1,`. To verify a request:

1. Read the **raw body bytes** before any JSON parsing (re-serialising changes the bytes).
2. Reject the request if `webhook-timestamp` is more than a few minutes away from your clock
   (5 minutes is a common tolerance). This bounds replays.
3. Compute the expected signature and compare it, in constant time, with **each** `v1,` entry of
   `webhook-signature`. Accept if any entry matches.
4. Optionally remember `webhook-id`s you have processed (see [Delivery semantics](#delivery-semantics)).

Node.js (`node:crypto`, no dependencies):

```js
import { createHmac, timingSafeEqual } from 'node:crypto';

const TOLERANCE_SECONDS = 5 * 60;

export function verifyWebhook(secret, headers, rawBody) {
  const id = headers['webhook-id'];
  const timestamp = headers['webhook-timestamp'];
  const signatures = headers['webhook-signature'] ?? '';
  if (!id || !/^\d+$/.test(timestamp ?? '')) return false;
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > TOLERANCE_SECONDS) return false;

  const key = Buffer.from(secret.slice('whsec_'.length), 'base64');
  const mac = createHmac('sha256', key).update(`${id}.${timestamp}.`).update(rawBody).digest('base64');
  const expected = Buffer.from(`v1,${mac}`);
  return signatures.split(' ').some((entry) => {
    const given = Buffer.from(entry);
    return given.length === expected.length && timingSafeEqual(given, expected);
  });
}
```

Python (standard library):

```python
import base64, hashlib, hmac, time

TOLERANCE_SECONDS = 5 * 60

def verify_webhook(secret: str, headers: dict, raw_body: bytes) -> bool:
    msg_id = headers.get("webhook-id", "")
    timestamp = headers.get("webhook-timestamp", "")
    if not msg_id or not timestamp.isdigit():
        return False
    if abs(time.time() - int(timestamp)) > TOLERANCE_SECONDS:
        return False
    key = base64.b64decode(secret.removeprefix("whsec_"))
    mac = hmac.new(key, f"{msg_id}.{timestamp}.".encode() + raw_body, hashlib.sha256).digest()
    expected = "v1," + base64.b64encode(mac).decode()
    return any(hmac.compare_digest(expected, entry)
               for entry in headers.get("webhook-signature", "").split(" "))
```

The e2e suite verifies real deliveries this way (`tests/e2e/lib/webhook-sink.ts`), and the Rust
signer is checked against the specification's published example.

## Delivery semantics

Deliveries are **at least once**. Retries, a node stopping in the middle of a request, or a
redelivery can bring the same event more than once. **Deduplicate on `webhook-id`**: store the
ids you have processed (for a few days) and acknowledge a repeated id without processing it
again. Deliveries are not ordered: two events about the same user can arrive in either order, so
use `timestamp` or re-read the current state from the admin API.

How AnvilID treats your answer:

| Answer | Result |
|---|---|
| `2xx` | Delivered |
| `410 Gone` | The delivery fails and **the endpoint is disabled** (`disabled_reason: gone`, audited `webhook_endpoint_disabled`). Re-enable it with `PATCH {"enabled": true}` |
| `3xx` (redirects are not followed), `429`, other `4xx`, `5xx`, timeout, network error, blocked destination | Retried |

Retry schedule (delay before each attempt): immediately, 5 s, 5 min, 30 min, 2 h, 5 h, 10 h, 14 h,
20 h, 24 h. That is 10 attempts over about three days, each delay plus up to 10 % jitter. A
`Retry-After` header (in seconds) on the answer can extend the next delay, up to 24 hours. After
the tenth failed attempt the delivery is marked failed and audited as `webhook_delivery_failed`;
the console and the API can redeliver it.

Answer quickly (within a few seconds) and do the work asynchronously. A slow answer holds a
delivery slot: each node sends at most 8 deliveries at a time.

Completed deliveries stay in the delivery log for the audit retention period
(`audit_retention_days`) and are then deleted with the audit events.

## Secret rotation

`POST /webhooks/{id}/secret` returns a new secret once. For the next **24 hours** every delivery
carries two signatures, `v1,<new> v1,<previous>`, so you can deploy the new secret at your own
pace: a receiver that knows either secret keeps accepting deliveries. After 24 hours only the new
secret signs.

Secrets are sealed with the installation's key-encryption key at rest and never appear in
responses after creation or rotation, in logs or in audit events.

## Operating notes

- Delivery runs inside every `anvilid serve` node; no extra process is needed. On Postgres, nodes
  claim due deliveries with row locks, so each attempt is sent by one node.
- Delivery attempts are counted in `anvil_webhook_deliveries_total{outcome}` with `outcome` one of
  `delivered`, `retry`, `failed`, `disabled` (see [OPERATIONS.md](OPERATIONS.md#metrics)).
- A delivery in flight while a node stops is not lost: its lease expires after 45 seconds and
  another attempt (with the same `webhook-id`) follows.
