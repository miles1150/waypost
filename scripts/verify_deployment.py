#!/usr/bin/env python3
"""Verify a deployed Worker without printing credentials or private response bodies."""
import argparse
import http.client
import json
import os
import re
import subprocess
import urllib.parse
from http.cookies import SimpleCookie
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples'))
from consumer import USER_AGENT

# Workers Static Assets: HTML revalidates, fingerprinted files are immutable.
# prepare_dashboard_assets.py fingerprints with a 12-hex digest.
HTML_CACHE = {'public', 'max-age=0', 'must-revalidate'}
ASSET_CACHE = {'public', 'max-age=31536000', 'immutable'}
FINGERPRINTED_ASSET = re.compile(
    r'/dashboard/(?:locales/)?[A-Za-z0-9_-]+\.[0-9a-f]{12}\.(?:json|js|css)(?![A-Za-z0-9])'
)


def cache_directives(headers):
    return {part.strip().lower() for part in headers.get('cache-control', '').split(',') if part.strip()}


def assert_nosniff(headers):
    if headers.get('x-content-type-options') != 'nosniff':
        raise AssertionError('Service response must disable MIME sniffing.')


def assert_transport(headers, https):
    if https and 'max-age=' not in headers.get('strict-transport-security', ''):
        raise AssertionError('HTTPS transport policy missing.')


def assert_frame_ancestors(headers):
    if "frame-ancestors 'none'" not in headers.get('content-security-policy', ''):
        raise AssertionError('Dashboard CSP missing.')


def assert_worker_uncached(headers):
    if headers.get('cache-control') != 'no-store':
        raise AssertionError('Service response must not be cached.')
    assert_nosniff(headers)


def dashboard_redirect_target(location, origin):
    parsed = urllib.parse.urlsplit(location or '')
    if parsed.scheme or parsed.netloc:
        if f'{parsed.scheme}://{parsed.netloc}' != origin:
            return False
    return parsed.path == '/dashboard/'


def fingerprinted_paths(body):
    if isinstance(body, bytes):
        body = body.decode('utf-8', 'replace')
    found = []
    for match in FINGERPRINTED_ASSET.findall(body or ''):
        if match not in found:
            found.append(match)
    return found


def check_dashboard(exchange, origin, https):
    """Dashboard documents are static assets. /dashboard may 307 to /dashboard/."""
    status, headers, _ = exchange('GET', '/dashboard')
    if status not in (307, 308) or not dashboard_redirect_target(headers.get('location'), origin):
        raise AssertionError('Expected GET /dashboard to redirect to /dashboard/.')
    assert_frame_ancestors(headers)
    assert_transport(headers, https)
    assert_nosniff(headers)
    status, headers, body = exchange('GET', '/dashboard/')
    if status != 200 or 'text/html' not in headers.get('content-type', ''):
        raise AssertionError('Dashboard document at /dashboard/ was not returned.')
    assert_frame_ancestors(headers)
    assert_transport(headers, https)
    directives = cache_directives(headers)
    if 'no-store' in directives or not HTML_CACHE <= directives:
        raise AssertionError('Dashboard HTML must revalidate; it is not a no-store Worker response.')
    assert_nosniff(headers)
    pending = fingerprinted_paths(body)
    if not pending:
        raise AssertionError('Dashboard HTML did not reference fingerprinted static assets.')
    seen = list(pending)
    while pending:
        path = pending.pop(0)
        status, asset_headers, asset = exchange('GET', path)
        if status != 200:
            raise AssertionError('Fingerprinted dashboard asset was not returned.')
        if not ASSET_CACHE <= cache_directives(asset_headers):
            raise AssertionError('Fingerprinted dashboard asset must allow a long immutable cache.')
        assert_nosniff(asset_headers)
        if not isinstance(asset, (str, bytes)):
            continue
        for extra in fingerprinted_paths(asset):
            if extra not in seen:
                seen.append(extra)
                pending.append(extra)


def verify(origin, admin_secret, check_rate_limit=False, check_api_rate_limit=False):
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1')):
        raise ValueError('Use HTTPS for a public service.')
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('Expected a service origin, without credentials, path or query.')
    origin = origin.rstrip('/')
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(parsed.hostname, parsed.port, timeout=30)
    checks = []

    def exchange(method, path, value=None, headers=None):
        data = json.dumps(value).encode() if value is not None else None
        # One connection keeps edge probes bound to the same client/Cloudflare location.
        # http.client does not follow redirects or forward operator credentials elsewhere.
        connection.request(method, path, body=data, headers={'content-type': 'application/json', 'user-agent': USER_AGENT, **(headers or {})})
        response = connection.getresponse()
        raw = response.read()
        status, actual_headers = response.status, response.headers
        body = json.loads(raw) if 'application/json' in actual_headers.get('content-type', '') else raw
        return status, actual_headers, body

    def request(method, path, value=None, headers=None):
        status, actual_headers, body = exchange(method, path, value, headers)
        assert_worker_uncached(actual_headers)
        return status, actual_headers, body

    status, _, body = request('GET', '/health')
    assert status == 200 and body['data']['status'] == 'ok', 'Liveness check failed.'
    checks.append('liveness')
    check_dashboard(exchange, origin, parsed.scheme == 'https')
    checks.append('dashboard_headers')
    status, _, _ = request('GET', '/ready')
    assert status == 401, 'Readiness must require operator authentication.'
    status, _, body = request('GET', '/ready', headers={'authorization': 'Bearer ' + admin_secret})
    assert status == 200 and body['data']['status'] == 'ready' and body['data']['schema_revision'] == len(list((Path(__file__).resolve().parents[1] / 'migrations').glob('*.sql'))), 'D1/R2 readiness check failed.'
    expected_environment = 'production' if parsed.scheme == 'https' else 'development'
    assert body['data']['environment'] == expected_environment, 'Deployment environment is not the expected profile.'
    checks.append('authenticated_d1_r2_readiness')
    status, _, _ = request('POST', '/admin/session', {'admin_secret': admin_secret}, {'origin': 'https://invalid-origin.example'})
    assert status == 403, 'Foreign browser origin was accepted.'
    checks.append('origin_rejection')
    status, headers, body = request('POST', '/admin/session', {'admin_secret': admin_secret}, {'origin': origin})
    assert status == 200, 'Operator login failed.'
    cookie_header = headers.get('set-cookie', '')
    cookies = SimpleCookie(); cookies.load(cookie_header)
    session = cookies['waypost_admin']
    assert session['httponly'] and session['samesite'] == 'Strict', 'Unsafe operator cookie.'
    if parsed.scheme == 'https':
        assert session['secure'], 'Operator cookie must use Secure over HTTPS.'
    csrf = body['data']['csrf_token']
    assert session.value not in csrf, 'CSRF value disclosed session credential.'
    session_headers = {'cookie': 'waypost_admin=' + session.value, 'origin': origin}
    status, _, _ = request('POST', '/admin/v0/registry', {'kind': 'spaces', 'limit': 1}, session_headers)
    assert status == 403, 'Operator write accepted without CSRF.'
    session_headers['x-waypost-csrf'] = csrf
    status, _, _ = request('POST', '/admin/v0/registry', {'kind': 'spaces', 'limit': 1}, session_headers)
    assert status == 200, 'Authenticated registry read failed.'
    status, _, _ = request('DELETE', '/admin/session', {}, session_headers)
    assert status == 200, 'Operator logout failed.'
    status, _, _ = request('GET', '/admin/session', headers=session_headers)
    assert status == 401, 'Logged-out session remained active.'
    checks.append('operator_session_csrf_logout')
    if check_rate_limit:
        for _ in range(40):
            status, _, body = request('POST', '/admin/session', {'admin_secret': 'invalid-test-admin-secret-32-bytes-long'}, {'origin': origin})
            if status == 429:
                assert body['error']['code'] == 'RATE_LIMITED', 'Unexpected rate-limit response.'
                checks.append('login_rate_limit')
                break
            assert status == 401, 'Unexpected login failure status.'
        else:
            raise AssertionError('Login rate limit was not enforced.')
    if check_api_rate_limit:
        # Sequential remote D1 reads may never reach 300/min. Use bounded async I/O
        # to exercise the actual API budget; no worker threads or credentials are used.
        probe = """
import {performance} from 'node:perf_hooks';
const [origin, userAgent] = process.argv.slice(1);
const started = performance.now();
for (let count = 0; count < 640 && performance.now() - started < 45000; count += 8) {
  const results = await Promise.all(Array.from({length: 8}, async (_, i) => {
    const response = await fetch(origin + '/admin/session', {redirect: 'manual',
      headers: {'user-agent': userAgent, cookie: 'waypost_admin=invalid_probe_' + (count + i)},
      signal: AbortSignal.timeout(15000)});
    const value = await response.json();
    if (response.status === 429 && value.error?.code === 'RATE_LIMITED') return true;
    if (response.status !== 401) throw new Error('Unexpected API probe status: ' + response.status);
    return false;
  }));
  if (results.some(Boolean)) {
    console.log(JSON.stringify({limited: true, requests: count + 8}));
    process.exit(0);
  }
}
console.log(JSON.stringify({limited: false}));
"""
        result = subprocess.run(['node', '--input-type=module', '-e', probe, origin, USER_AGENT], capture_output=True, text=True, timeout=65)
        assert result.returncode == 0, 'API burst probe failed.'
        assert json.loads(result.stdout)['limited'], 'API rate limit was not observed in the bounded burst.'
        checks.append('session_read_api_rate_limit')
    connection.close()
    return {'result': 'passed', 'origin': origin, 'checks': checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--admin-secret-file', type=Path)
    parser.add_argument('--check-rate-limit', action='store_true', help='Uses this IP login budget; run after other checks.')
    parser.add_argument('--check-api-rate-limit', action='store_true', help='Exercises the local IP API budget; run last.')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    secret = args.admin_secret_file.read_text().strip() if args.admin_secret_file else os.environ.get('WAYPOST_ADMIN_SECRET')
    if not secret:
        parser.error('Set WAYPOST_ADMIN_SECRET or --admin-secret-file; never pass credentials in the URL.')
    result = verify(args.url, secret, args.check_rate_limit, args.check_api_rate_limit)
    output = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(output)
    print(output, end='')

if __name__ == '__main__':
    main()
