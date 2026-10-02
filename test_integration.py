import os
import uuid
import httpx
import pytest
import pytest_asyncio

pytestmark = pytest.mark.skipif(not os.getenv('DATABASE_URL'), reason='Requires PostgreSQL and Redis')

@pytest_asyncio.fixture
async def runtime():
    from app import app, lifespan, TOKENS
    TOKENS['other-key']='other'
    async with lifespan(app):
        async with app.state.pool.connection() as conn:
            await conn.execute('TRUNCATE scans')
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test',headers={'Authorization':'Bearer development-only-key'}) as client:
            yield app, client

async def create(client, key='key', target='demo-weak'):
    return await client.post('/scans',json={'target_id':target},headers={'Idempotency-Key':key})

@pytest.mark.asyncio
async def test_idempotency_and_conflict(runtime):
    _,client=runtime
    a=await create(client);b=await create(client)
    assert a.status_code==202 and b.status_code==200
    assert a.json()['id']==b.json()['id']
    assert (await create(client,target='demo-hardened')).status_code==409

@pytest.mark.asyncio
async def test_auth_registry_and_isolation(runtime):
    _,client=runtime
    assert (await client.get('/scans',headers={'Authorization':'bad'})).status_code==401
    assert (await create(client,target='http://localhost')).status_code==422
    job=(await create(client)).json()
    assert (await client.get('/scans/'+job['id'],headers={'Authorization':'Bearer other-key'})).status_code==404
    assert (await client.get('/scans',headers={'Authorization':'Bearer other-key'})).json()==[]

@pytest.mark.asyncio
async def test_claim_fencing_and_atomic_result(runtime):
    from store import claim,finish
    app,client=runtime
    await create(client)
    job=await claim(app.state.pool)
    assert await claim(app.state.pool) is None
    stale={**job,'token':uuid.uuid4()}
    assert not await finish(app.state.pool,stale,result={'findings':[]})
    assert await finish(app.state.pool,job,result={'findings':[],'http_status':200})
    result=(await client.get('/scans/'+str(job['id']))).json()
    assert result['status']=='completed' and result['result']['http_status']==200

@pytest.mark.asyncio
async def test_expired_lease_and_retry_exhaustion(runtime):
    from store import claim,finish
    app,client=runtime
    await create(client)
    first=await claim(app.state.pool)
    async with app.state.pool.connection() as conn:
        await conn.execute("UPDATE scans SET lease_until=now()-interval '1 second'")
    second=await claim(app.state.pool)
    assert second['attempts']==2 and second['token']!=first['token']
    assert not await finish(app.state.pool,first,result={})
    assert await finish(app.state.pool,second,error=True)
    async with app.state.pool.connection() as conn:
        await conn.execute("UPDATE scans SET available_at=now()-interval '1 second'")
    third=await claim(app.state.pool)
    await finish(app.state.pool,third,error=True)
    assert (await client.get('/scans/'+str(third['id']))).json()['status']=='failed'

@pytest.mark.asyncio
async def test_concurrent_idempotent_submissions(runtime):
    import asyncio
    _,client=runtime
    results=await asyncio.gather(*(create(client,'parallel') for _ in range(8)))
    assert sum(r.status_code==202 for r in results)==1
    assert len({r.json()['id'] for r in results})==1

@pytest.mark.asyncio
async def test_redis_outage_preserves_committed_job(runtime):
    from store import claim
    app,client=runtime
    original=app.state.redis
    class Offline:
        async def lpush(self,*args):
            raise ConnectionError('Redis unavailable')
    app.state.redis=Offline()
    try:
        response=await create(client)
        assert response.status_code==202
        assert str((await claim(app.state.pool))['id'])==response.json()['id']
    finally:
        app.state.redis=original

@pytest.mark.asyncio
async def test_final_expired_lease_is_terminal(runtime):
    from store import claim
    app,client=runtime
    await create(client)
    job=await claim(app.state.pool)
    async with app.state.pool.connection() as conn:
        await conn.execute("UPDATE scans SET attempts=3, lease_until=now()-interval '1 second'")
    assert await claim(app.state.pool) is None
    assert (await client.get('/scans/'+str(job['id']))).json()['status']=='failed'
