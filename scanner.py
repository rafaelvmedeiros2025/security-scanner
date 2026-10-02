"""Header posture checks. No crawling, redirects or exploit payloads."""
import asyncio
from http.cookies import SimpleCookie
from urllib.parse import urlsplit
import httpx


def inspect(url, headers):
    findings = []
    def add(code, severity, evidence, remediation):
        findings.append(dict(code=code, severity=severity, evidence=evidence, remediation=remediation))
    https = urlsplit(url).scheme == "https"
    if not https:
        add("transport.http", "medium", "Target uses HTTP", "Use HTTPS with a valid certificate.")
    if https and not headers.get("strict-transport-security"):
        add("headers.hsts", "medium", "HSTS missing", "Set Strict-Transport-Security after validating HTTPS deployment.")
    csp = headers.get("content-security-policy", "")
    if not csp:
        add("headers.csp", "medium", "CSP missing", "Define and test a Content-Security-Policy for this application.")
    if "frame-ancestors" not in csp.lower() and headers.get("x-frame-options", "").upper() not in ("DENY", "SAMEORIGIN"):
        add("headers.frames", "medium", "Frame protection missing", "Set CSP frame-ancestors or X-Frame-Options.")
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        add("headers.nosniff", "low", "nosniff missing", "Set X-Content-Type-Options: nosniff.")
    if not headers.get("referrer-policy"):
        add("headers.referrer", "low", "Referrer-Policy missing", "Set an explicit Referrer-Policy.")
    if headers.get("access-control-allow-origin") == "*":
        add("cors.wildcard", "info", "Wildcard CORS", "Review whether public cross-origin access is intended.")
    for index, raw in enumerate(headers.get_list("set-cookie")):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for value in cookie.values():
            # Never store cookie names or values in findings.
            for flag in ("secure", "httponly", "samesite"):
                if not value[flag]:
                    add("cookie." + flag, "low", f"Cookie #{index + 1} lacks {flag}", f"Review and set {flag} where appropriate.")
    return findings


async def scan(url, client):
    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("Only HTTP(S) targets are supported")
    async with asyncio.timeout(10):
        async with client.stream("GET", url, headers={"Origin": "https://scanner.example"}, follow_redirects=False) as response:
            return {"http_status": response.status_code, "findings": inspect(url, response.headers)}
