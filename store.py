import uuid
from psycopg.types.json import Jsonb


async def claim(pool):
    async with pool.connection() as conn:
        async with conn.transaction():
            await conn.execute("UPDATE scans SET status='failed', error='Worker lease expired after final attempt', token=NULL, lease_until=NULL WHERE status='running' AND lease_until<now() AND attempts>=3")
            row = await (await conn.execute("""SELECT * FROM scans WHERE
                (status='queued' AND available_at<=now()) OR
                (status='running' AND lease_until<now())
                ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1""")).fetchone()
            if not row:
                return None
            token = uuid.uuid4()
            return await (await conn.execute("""UPDATE scans SET status='running',
                attempts=attempts+1, token=%s, lease_until=now()+interval '30 seconds'
                WHERE id=%s RETURNING *""", (token, row['id']))).fetchone()


async def finish(pool, job, result=None, error=None):
    async with pool.connection() as conn:
        if error:
            status = 'failed' if job['attempts'] >= 3 else 'queued'
            cur = await conn.execute("""UPDATE scans SET status=%s, error=%s,
                available_at=now()+(%s * interval '1 second'), token=NULL, lease_until=NULL
                WHERE id=%s AND token=%s AND status='running'""",
                (status, 'Target request failed', 2 ** job['attempts'], job['id'], job['token']))
        else:
            cur = await conn.execute("""UPDATE scans SET status='completed', result=%s,
                error=NULL, token=NULL, lease_until=NULL WHERE id=%s AND token=%s AND status='running'""",
                (Jsonb(result), job['id'], job['token']))
        return cur.rowcount == 1
