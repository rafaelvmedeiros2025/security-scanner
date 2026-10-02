import hmac
import json
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import FastAPI, Header, HTTPException, Depends, Response
from pydantic import BaseModel, ConfigDict, Field
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool
from redis.asyncio import Redis

TARGETS = json.loads(os.getenv('TARGETS_JSON', '{"demo-weak":"http://demo:8080/weak","demo-hardened":"http://demo:8080/hardened"}'))
TOKENS = json.loads(os.getenv('API_TOKENS_JSON', '{"development-only-key":"demo"}'))
if not TARGETS or any(urlsplit(url).scheme not in ('http', 'https') or urlsplit(url).username for url in TARGETS.values()):
    raise ValueError('Invalid target registry')

@asynccontextmanager
async def lifespan(app):
    app.state.pool = AsyncConnectionPool(os.environ['DATABASE_URL'], kwargs={'row_factory': dict_row}, open=False)
    await app.state.pool.open(wait=True)
    async with app.state.pool.connection() as conn:
        await conn.execute('SELECT pg_advisory_xact_lock(90404)')
        await conn.execute(Path(__file__).with_name('schema.sql').read_text())
    app.state.redis = Redis.from_url(os.getenv('REDIS_URL', 'redis://redis:6379'), socket_connect_timeout=1, socket_timeout=3)
    yield
    await app.state.redis.aclose()
    await app.state.pool.close()

app = FastAPI(title='Security Scanner', lifespan=lifespan)

def tenant(authorization: str = Header(default='')):
    for token, name in TOKENS.items():
        if hmac.compare_digest(authorization, 'Bearer ' + token):
            return name
    raise HTTPException(401, 'Invalid API token')

class ScanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target_id: str = Field(min_length=1, max_length=80)

@app.get('/health')
async def health():
    async with app.state.pool.connection() as conn:
        await conn.execute('SELECT 1')
    return {'status': 'ok'}

@app.get('/targets')
async def targets(owner=Depends(tenant)):
    return [{'id': key} for key in TARGETS]

@app.post('/scans')
async def create(body: ScanRequest, response: Response, idempotency_key: str = Header(min_length=1, max_length=128), owner=Depends(tenant)):
    if body.target_id not in TARGETS:
        raise HTTPException(422, 'Unknown registered target')
    async with app.state.pool.connection() as conn:
        cur = await conn.execute("INSERT INTO scans(id,tenant,target,idem) VALUES(%s,%s,%s,%s) ON CONFLICT(tenant,idem) DO NOTHING RETURNING *", (uuid.uuid4(), owner, body.target_id, idempotency_key))
        row = await cur.fetchone()
        created = row is not None
        if not row:
            row = await (await conn.execute('SELECT * FROM scans WHERE tenant=%s AND idem=%s', (owner, idempotency_key))).fetchone()
        if row['target'] != body.target_id:
            raise HTTPException(409, 'Idempotency key already used for another target')
    if created:
        try:
            await app.state.redis.lpush('scanner:wake', '1')
            await app.state.redis.ltrim('scanner:wake', 0, 499)
        except Exception:
            pass  # PostgreSQL polling processes committed work even when Redis is unavailable.
    response.status_code = 202 if created else 200
    return public(row)

def public(row):
    return {key: row[key] for key in ('id','target','status','attempts','created_at','result','error')}

@app.get('/scans')
async def history(owner=Depends(tenant)):
    async with app.state.pool.connection() as conn:
        rows = await (await conn.execute('SELECT * FROM scans WHERE tenant=%s ORDER BY created_at DESC LIMIT 50', (owner,))).fetchall()
        return [public(row) for row in rows]

@app.get('/scans/{scan_id}')
async def detail(scan_id: uuid.UUID, owner=Depends(tenant)):
    async with app.state.pool.connection() as conn:
        row = await (await conn.execute('SELECT * FROM scans WHERE id=%s AND tenant=%s', (scan_id, owner))).fetchone()
        if not row:
            raise HTTPException(404, 'Scan not found')
        return public(row)
