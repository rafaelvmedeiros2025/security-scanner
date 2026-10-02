import asyncio
import logging
import httpx
from app import app, lifespan, TARGETS
from scanner import scan
from store import claim, finish

async def run():
    async with lifespan(app):
        async with httpx.AsyncClient(timeout=8, trust_env=False, follow_redirects=False) as client:
            while True:
                job = await claim(app.state.pool)
                if job:
                    try:
                        result = await scan(TARGETS[job['target']], client)
                    except Exception:
                        await finish(app.state.pool, job, error=True)
                        logging.warning('Scan request failed: %s', job['id'])
                    else:
                        await finish(app.state.pool, job, result=result)
                else:
                    try:
                        await app.state.redis.brpop('scanner:wake', timeout=2)
                    except Exception:
                        await asyncio.sleep(2)

if __name__ == '__main__':
    asyncio.run(run())
