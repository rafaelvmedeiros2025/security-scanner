import httpx
import pytest
from scanner import inspect, scan


def codes(url, headers):
    return {f['code'] for f in inspect(url, httpx.Headers(headers))}


def test_missing_headers():
    assert {'transport.http','headers.csp','headers.frames','headers.nosniff','headers.referrer'} <= codes('http://demo/weak', {})


def test_hardened_https():
    headers = {'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",'Strict-Transport-Security':'max-age=31536000','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}
    assert codes('https://demo', headers) == set()


def test_hsts_only_for_https():
    assert 'headers.hsts' in codes('https://demo', {})
    assert 'headers.hsts' not in codes('http://demo', {})


def test_cookie_values_are_redacted():
    result = inspect('https://demo', httpx.Headers({'Set-Cookie':'sensitive=secret; Path=/'}))
    assert 'secret' not in str(result)
    assert {'cookie.secure','cookie.httponly','cookie.samesite'} <= {f['code'] for f in result}


def test_secure_cookie():
    assert not any(f.startswith('cookie.') for f in codes('https://demo', {'Set-Cookie':'session=secret; Secure; HttpOnly; SameSite=Strict'}))


def test_frame_alternative():
    assert 'headers.frames' not in codes('http://demo', {'X-Frame-Options':'DENY'})


@pytest.mark.asyncio
async def test_redirect_not_followed():
    seen=[]
    def respond(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={'Location':'http://unregistered/'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        result=await scan('http://demo',client)
    assert seen==['http://demo']
    assert result['http_status']==302


@pytest.mark.asyncio
async def test_invalid_scheme():
    async with httpx.AsyncClient(trust_env=False) as client:
        with pytest.raises(ValueError):
            await scan('file:///etc/passwd',client)
