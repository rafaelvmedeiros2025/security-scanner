import json
import time
import urllib.request

def request(path, body=None):
    req=urllib.request.Request('http://localhost:8001'+path, data=json.dumps(body).encode() if body else None, headers={'Authorization':'Bearer development-only-key','Idempotency-Key':'smoke','Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)
for attempt in range(60):
    try:
        request('/health')
        break
    except Exception:
        time.sleep(1)
else:
    raise RuntimeError('API unavailable')
job=request('/scans', {'target_id':'demo-weak'})
for attempt in range(60):
    result=request('/scans/'+job['id'])
    if result['status']=='completed':
        assert any(f['code']=='headers.csp' for f in result['result']['findings'])
        break
    time.sleep(1)
else:
    raise RuntimeError('Worker did not complete scan')
with urllib.request.urlopen('http://localhost:3002', timeout=10) as response:
    assert b'Security scanner' in response.read()
print('Compose smoke passed: API, PostgreSQL queue, Redis, worker, demo target and Next.js')
