# Security Scanner

A full stack engineering portfolio project: submit HTTP posture checks, process durable jobs, and review evidence in a Next.js dashboard. Python/FastAPI, PostgreSQL, Redis and Docker Compose.

## Run the complete demo

```sh
docker compose up --build -d
# Dashboard: http://localhost:3002
# API docs: http://localhost:8001/docs
python smoke.py
docker compose down
```

Choose `demo-weak` or `demo-hardened`, run a scan and inspect the findings. The demo services intentionally use HTTP, so both receive a transport finding. No external websites are scanned by default. PostgreSQL data persists until `docker compose down -v`.

## What it checks

One GET request, headers only, with a 10-second total deadline and redirects disabled. Checks include HTTPS, presence of HSTS on HTTPS, CSP, frame protection, nosniff, Referrer-Policy, wildcard CORS and cookie flags. Cookie values are never retained. Reports contain policy observations and remediation; missing headers do not prove exploitability. CSP presence is checked, not semantic policy strength. This is not a SQL injection, XSS or dependency scanner.

## Reliability design

```mermaid
flowchart TD
  UI[Next.js dashboard] --> API[Authenticated FastAPI]
  API --> PG[PostgreSQL jobs and reports]
  API --> Redis[Redis wake signal]
  Redis --> Worker[Python worker]
  PG --> Worker
  Worker --> Target[Registered demo target]
  Worker --> PG
```

PostgreSQL owns the queue. Claim transactions use `FOR UPDATE SKIP LOCKED`; HTTP runs outside the transaction. Each attempt receives a UUID fencing token and a 30-second lease. Expired leases can be reclaimed. Completion requires the current token, making stale worker writes harmless. Results and completed status are persisted together. Failures retry with exponential delay, up to three attempts; a final expired lease becomes failed. Delivery is at least once, so a reclaimed job may repeat the GET request.

Redis stores bounded advisory wake signals. A missed notification or Redis outage delays work by polling rather than losing it. `Idempotency-Key` is unique per tenant; reusing it for another target returns 409. Read endpoints filter by tenant. History returns the most recent 50 scans.

## API example

```sh
curl -X POST http://localhost:8001/scans \
  -H 'Authorization: Bearer development-only-key' \
  -H 'Idempotency-Key: demo-001' \
  -H 'Content-Type: application/json' \
  -d '{"target_id":"demo-weak"}'
```

`GET /targets`, `GET /scans`, `GET /scans/{id}` use the same bearer token. A new scan returns 202, an idempotent replay returns 200. `GET /health` checks PostgreSQL. The dashboard polls every three seconds and exports JSON reports.

## Configuration and trust boundaries

`DATABASE_URL`, `REDIS_URL`, `API_TOKENS_JSON` (token → tenant), and `TARGETS_JSON` (target ID → URL) configure the backend. Target URLs are operator configuration, never request input. Registry validation permits HTTP(S) only and rejects embedded usernames. The registry is a trust boundary, not a DNS rebinding defense: production needs an isolated egress network, explicit destination controls and ownership verification before targets are registered.

`API_URL` and `API_TOKEN` configure the Next.js server proxy. The token is never sent to the browser. The proxy permits only the documented paths and requires same-origin JSON submissions. Compose publishes the API and dashboard on loopback. Development keys and passwords are examples only.

The dashboard intentionally shares one demo tenant and has no user login. Do not expose it publicly as a multi-user product. Production work includes user sessions, HTTPS, quotas, versioned migrations, managed secrets, monitoring, retention and per-tenant target authorization. Schema initialization is serialized with a PostgreSQL advisory lock; future schema changes require explicit migrations.

## Validation

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest -q
cd web && npm ci && npm run build
```

Without `DATABASE_URL`, integration tests are skipped. CI uses real PostgreSQL and Redis for idempotency, tenant isolation, leases, fencing and retry exhaustion. A second job builds all containers and runs the complete API-to-worker-to-demo scan, plus a Next.js page smoke check. Local unit tests cover header policies, cookie redaction and redirect rejection.
