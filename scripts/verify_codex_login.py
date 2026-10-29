#!/usr/bin/env python3
"""Codex CLI MCP login against local Workerd without a configured client ID.

Prerequisite: `node scripts/serve_local_workerd.mjs --product waypost --port 8793`
with --dcr and/or --cimd. The synthetic seeded owner session approves consent.
Codex discovers the server and chooses its own client identity (a Client ID
Metadata Document URL, or dynamic registration); the config never names one.

  python3 scripts/verify_codex_login.py --codex PATH [--registration auto|dcr|cimd]
      [--expect metadata_document|dynamic_registration]

Never prints tokens, codes or cookies.
"""
import argparse
import json
import os
import pty
import select
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = 'http://127.0.0.1:8793'
COOKIE = 'waypost_account=' + 'c' * 43
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


no_redirect = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))


def call(path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = dict(headers or {})
    if data:
        h['Content-Type'] = 'application/json'
    try:
        r = no_redirect.open(urllib.request.Request(BASE + path, data=data, headers=h), timeout=20)
    except urllib.error.HTTPError as e:
        r = e
    raw = r.read()
    return r.status, r.headers, (json.loads(raw) if raw else None)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--codex', required=True)
    p.add_argument('--registration', default='auto', choices=['auto', 'dcr', 'cimd'])
    p.add_argument('--expect', choices=['metadata_document', 'dynamic_registration'])
    a = p.parse_args()
    home = tempfile.mkdtemp(prefix='codex-home-')
    with open(os.path.join(home, 'config.toml'), 'w') as f:
        # Only the server URL: no client_id, no oauth table.
        f.write('mcp_oauth_credentials_store = "file"\n[mcp_servers.waypost]\nurl = "%s/mcp"\n' % BASE)
    env = {**os.environ, 'CODEX_HOME': home, 'NO_PROXY': '127.0.0.1', 'no_proxy': '127.0.0.1'}
    argv = [a.codex, 'mcp', 'login', 'waypost', '--no-browser']
    if a.registration != 'auto':
        argv += ['--oauth-client-registration', a.registration]
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(env)
        os.execv(a.codex, argv)
    phase = 'authorization URL'
    out = b''
    try:
        url = None
        deadline = time.time() + 60
        while url is None and time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 1)
            if ready:
                try:
                    out += os.read(fd, 65536)
                except OSError:
                    break
            for line in out.decode(errors='replace').splitlines():
                if line.startswith(BASE + '/oauth/authorize?'):
                    url = line.strip()
        assert url, 'no authorization URL'
        q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        client_id = q['client_id'][0]
        phase = 'browser consent'
        status, headers, _ = call('/oauth/authorize?' + urllib.parse.urlparse(url).query)
        assert status == 303, status
        rid = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)['oauth_request'][0]
        browser = COOKIE + '; ' + headers['Set-Cookie'].split(';')[0]
        csrf = call('/account/session', headers={'Cookie': COOKIE})[2]['data']['csrf_token']
        _, _, preview = call('/oauth/consent?request_id=' + rid, headers={'Cookie': browser})
        if a.expect:
            assert preview['client_kind'] == a.expect, preview['client_kind']
        status, _, decided = call('/oauth/consent', {'request_id': rid, 'decision': 'approve', 'actor_id': 'actor_test', 'consumer_id': 'consumer_test'},
                                  headers={'Cookie': browser, 'Origin': BASE, 'X-Waypost-CSRF': csrf})
        assert status == 200, decided
        phase = 'callback delivery'
        # The browser follows the redirect to Codex's loopback listener.
        try:
            opener.open(decided['redirect_uri'], timeout=20).read()
        except urllib.error.HTTPError as e:
            raise AssertionError('callback rejected with %d' % e.code)
        deadline = time.time() + 60
        code = None
        while code is None and time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 1)
            if ready:
                try:
                    out += os.read(fd, 65536)
                except OSError:
                    pass
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                code = os.waitstatus_to_exitcode(status)
        if code is None:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            raise AssertionError('codex did not finish')
        assert code == 0, 'codex exit %d' % code
        phase = 'stored credentials and tool use'
        listed = subprocess.run([a.codex, 'mcp', 'list', '--json'], env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        servers = json.loads(listed.stdout)
        entry = next(s for s in servers if s.get('name') == 'waypost')
        print(json.dumps({'result': 'passed', 'codex': subprocess.run([a.codex, '--version'], env=env, capture_output=True, text=True).stdout.strip(),
                          'registration_flag': a.registration, 'client_kind': preview['client_kind'],
                          'client_id': client_id if not client_id.startswith('dcr_') else 'dcr_…',
                          'redirect_uri_path': urllib.parse.urlparse(q['redirect_uri'][0]).path,
                          'configured_client_id': False, 'auth_status': entry.get('auth_status'), 'runtime': 'local Workerd, synthetic owner'}))
    except Exception as e:
        tail = out.decode(errors='replace')[-400:]
        print(json.dumps({'result': 'failed', 'phase': phase, 'error': f'{type(e).__name__}: {e}', 'codex_output_tail': tail}))
        raise SystemExit(1)
    finally:
        shutil.rmtree(home, ignore_errors=True)


if __name__ == '__main__':
    main()
