#!/usr/bin/env python3
"""Actual Codex automatic OAuth client discovery on a disposable local Worker.

Requires Docker, Node and the explicitly supplied static Linux Codex binary.
No HOME/CODEX_HOME mutation, production credential, real Google login or model call.
"""
import argparse
import json
import os
from pathlib import Path
import re
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
REPO = Path(__file__).resolve().parents[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def request(path, body=None, headers=None):
    if not path.startswith('/') or path.startswith('//'):
        raise RuntimeError('Only the isolated fixture is allowed')
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, headers={'Content-Type': 'application/json', **(headers or {})})
    try:
        response = opener.open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    raw = response.read()
    return response.status, response.headers, json.loads(raw) if raw else None


def expect(value, message):
    if not value:
        raise RuntimeError(message)


def read_until(process, predicate, timeout=60):
    deadline = time.monotonic() + timeout
    buffer = b''
    while time.monotonic() < deadline:
        if select.select([process.stdout], [], [], .2)[0]:
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            buffer += chunk
            result = predicate(buffer)
            if result is not None:
                return result
    words = ('not found', 'not configured', 'authentication', 'failed', 'fetch', 'OAuth', 'support', 'Dynamic', 'registration', 'client', 'scope', 'keyring', 'credentials', 'connection', 'refused', 'HTTPS', 'secure', 'Unable', 'No MCP server', 'login required', 'Unauthorized', 'Forbidden', 'logged in', 'log in', 'Please run', 'API key', 'subscription', 'login', 'required', 'Missing', 'token', 'browser', 'terminal', 'interactive', 'TTY', 'requires an interactive terminal')
    diagnostics = [word for word in words if word.lower() in buffer.decode(errors='ignore').lower()]
    tags = sorted(set(re.findall(r'\b(?:invalid_client_metadata|invalid_redirect_uri|invalid_client|invalid_scope|invalid_request|access_denied|ECONNREFUSED|ENOTFOUND)\b', buffer.decode(errors='ignore'))))
    raise RuntimeError(('Local client exited before expected response; exit=' if process.poll() is not None else 'Local client response timeout; exit=') + str(process.poll()) + '; safe_error_tags=' + ','.join(tags) + '; diagnostic_terms=' + ','.join(diagnostics))


def json_response(process, identifier):
    def match(data):
        for line in data.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get('id') == identifier:
                return item
        return None
    return read_until(process, match)


def send(process, value):
    process.stdin.write((json.dumps(value) + '\n').encode())
    process.stdin.flush()


def approve_authorization(url):
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qs(parsed.query)
    client_id = query['client_id'][0]
    expect(client_id.startswith('dcr_'), 'Codex did not obtain a dynamic client ID')
    expect(query['code_challenge_method'] == ['S256'], 'Codex did not use S256')
    status, headers, _ = request(parsed.path + '?' + parsed.query)
    expect(status == 303, 'Authorization request failed')
    browser = headers['Set-Cookie'].split(';')[0]
    request_id = urllib.parse.parse_qs(urllib.parse.urlsplit(headers['Location']).query)['oauth_request'][0]
    status, _, session = request('/account/session', headers={'Cookie': COOKIE})
    expect(status == 200, 'Synthetic account unavailable')
    csrf = session['data']['csrf_token']
    status, _, consent = request('/oauth/consent', {'request_id': request_id, 'decision': 'approve', 'actor_id': 'actor_test', 'consumer_id': 'consumer_test'}, {'Cookie': COOKIE + '; ' + browser, 'Origin': BASE, 'X-Waypost-CSRF': csrf})
    expect(status == 200, 'Explicit consent failed')
    callback = consent['redirect_uri']
    callback_query = urllib.parse.parse_qs(urllib.parse.urlsplit(callback).query)
    expect(callback_query.get('state') == query.get('state'), 'Callback state changed')
    expect(callback_query['iss'] == [BASE], 'Callback issuer changed')
    return callback


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex-binary', type=Path, required=True)
    parser.add_argument('--claude-binary', type=Path, help='Optional Claude 2.1.296 no-model OAuth login and connection check')
    args = parser.parse_args()
    binary = args.codex_binary.resolve()
    expect(binary.is_file(), 'Static Codex binary missing')
    phase = 'start isolated Worker'
    service = login = app = claude = None
    containers = []
    image = 'waypost-auto-oauth-test:' + str(os.getpid())
    result = None
    temporary = tempfile.TemporaryDirectory(prefix='waypost-auto-oauth-')
    temp = temporary.name
    try:
        private = Path(temp)
        private.chmod(0o700)
        service = subprocess.Popen(['node', 'tests/oauth_client_discovery_worker.mjs', '--serve'], cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        read_until(service, lambda data: True if b'"ready":true' in data else None)
        phase = 'build isolated static client container'
        build = private / 'image'
        build.mkdir()
        shutil.copy2(binary, build / 'codex')
        uid, gid = os.getuid(), os.getgid()
        (build / 'scratch-tmp').mkdir()
        (build / 'scratch-tmp/.keep').touch()
        (build / 'passwd').write_text(f'fixture:x:{uid}:{gid}:Synthetic client:/root:/nonexistent\n')
        (build / 'group').write_text(f'fixture:x:{gid}:\n')
        (build / 'Dockerfile').write_text(f'FROM scratch\nCOPY codex /codex\nCOPY passwd /etc/passwd\nCOPY group /etc/group\nCOPY --chown={uid}:{gid} scratch-tmp/ /tmp/\nWORKDIR /tmp\nWORKDIR /root\nUSER {uid}:{gid}\nENTRYPOINT ["/codex"]\n')
        subprocess.run(['docker', 'build', '--network=none', '-t', image, str(build)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        home_dir = private / 'client-root'
        (home_dir / '.codex').mkdir(parents=True)
        (home_dir / '.codex/config.toml').write_text('mcp_oauth_credentials_store = "file"\n[analytics]\nenabled = false\n[mcp_servers.waypost]\nurl = "' + BASE + '/mcp"\n')
        (home_dir / '.codex/config.toml').chmod(0o600)
        # Docker's /etc/passwd home belongs only to this container. The host's
        # HOME and CODEX_HOME are neither reassigned nor mounted into it.
        def command(name, *arguments):
            containers.append(name)
            return ['docker', 'run', '--rm', '--name', name, '--network', 'host', '-i', '--mount', f'type=bind,src={home_dir},dst=/root', image, *arguments]
        version = subprocess.run(command('waypost-version-' + str(os.getpid()), '--version'), check=True, capture_output=True, text=True).stdout.strip()
        expect('0.162.1' in version, 'This regression requires Codex 0.162.1')
        phase = 'actual Codex discovery and dynamic registration'
        login = subprocess.Popen(command('waypost-login-' + str(os.getpid()), 'mcp', 'login', 'waypost', '--no-browser'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        def authorize_url(data):
            found = re.search(rb'http://127\.0\.0\.1:8793/oauth/authorize\?[^\s\x1b]+(?=[\s\x1b])', data)
            return found.group().decode() if found else None
        url = read_until(login, authorize_url)
        phase = 'synthetic Google account explicit consent'
        callback = approve_authorization(url)
        login.stdin.write((callback + '\n').encode())
        login.stdin.flush()
        login.communicate(timeout=45)
        expect(login.returncode == 0, 'Codex login failed')
        phase = 'actual Codex MCP tools discovery without model'
        app = subprocess.Popen(command('waypost-appserver-' + str(os.getpid()), 'app-server'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        send(app, {'id': 1, 'method': 'initialize', 'params': {'clientInfo': {'name': 'waypost-isolated-acceptance', 'version': '1'}, 'capabilities': {'experimentalApi': True}}})
        expect('result' in json_response(app, 1), 'App server initialization failed')
        send(app, {'method': 'initialized'})
        send(app, {'id': 2, 'method': 'mcpServerStatus/list', 'params': {'serverName': 'waypost', 'detail': 'toolsAndAuthOnly'}})
        reply = json_response(app, 2)
        servers = reply.get('result', {}).get('data', [])
        server = next((s for s in servers if s.get('name') == 'waypost'), {})
        tools = server.get('tools', {})
        expect(len(tools) == 11, 'Codex did not discover all 11 MCP tools')
        expect(server.get('authStatus') == 'oAuth', 'Codex did not report OAuth authentication')
        result = {'result': 'passed', 'codex_verified': True, 'client': version, 'runtime': 'isolated actual Workerd/D1', 'client_id_configured': False, 'dynamic_registration': True, 'pkce_login': True, 'codex_app_server_tools': len(tools), 'model_calls': 0, 'identity': 'synthetic seeded Google account, not real Google login', 'claude_tested': False, 'claude': None, 'production_touched': False}
        claude_result = None
        if args.claude_binary:
            phase = 'actual Claude automatic OAuth login'
            claude_binary = args.claude_binary.resolve()
            expect(claude_binary.is_file(), 'Claude binary missing')
            config_dir = private / 'claude-config'; config_dir.mkdir(mode=0o700)
            claude_env = {'PATH': os.environ.get('PATH', ''), 'CLAUDE_CONFIG_DIR': str(config_dir), 'DISABLE_AUTOUPDATER': '1', 'DISABLE_TELEMETRY': '1', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1'}
            claude_version = subprocess.run([str(claude_binary), '--version'], cwd=private, env=claude_env, check=True, capture_output=True, text=True, timeout=20).stdout.strip()
            expect('2.1.296' in claude_version, 'This regression requires Claude 2.1.296')
            subprocess.run([str(claude_binary), 'mcp', 'add', '--transport', 'http', '--scope', 'user', 'waypost', BASE + '/mcp'], cwd=private, env=claude_env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            phase = 'actual Claude authorization URL discovery'
            claude = subprocess.Popen([str(claude_binary), 'mcp', 'login', 'waypost', '--no-browser'], cwd=private, env=claude_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            url = read_until(claude, authorize_url)
            phase = 'actual Claude explicit consent'
            callback = approve_authorization(url)
            claude.stdin.write((callback + '\n').encode()); claude.stdin.flush()
            phase = 'actual Claude token exchange completion'
            claude.communicate(timeout=45)
            expect(claude.returncode == 0, 'Claude OAuth login failed')
            phase = 'actual Claude MCP connection check'
            health = subprocess.run([str(claude_binary), 'mcp', 'get', 'waypost'], cwd=private, env=claude_env, check=True, capture_output=True, text=True, timeout=40)
            expect('connected' in health.stdout.lower(), 'Claude did not report connected MCP server')
            claude_result = {'client': claude_version, 'dynamic_registration': True, 'pkce_login': True, 'mcp_connection_check': True, 'tool_listing_verified': False, 'model_calls': 0}
        result['claude_tested'] = bool(claude_result)
        result['claude'] = claude_result
    except Exception as error:
        failure = {'result': 'failed', 'phase': phase, 'error_type': type(error).__name__, 'detail': str(error) if isinstance(error, RuntimeError) else None, 'exit_code': getattr(error, 'returncode', None)}
        print(json.dumps({**result, 'result': 'partial', 'claude_tested': True, 'claude': failure} if result else failure))
        return 1
    finally:
        # The fixture contains only this run's families. Explicitly revoke them
        # before disposing its private D1; never print OAuth tokens or CLI output.
        if service is not None and service.poll() is None:
            try:
                _, _, session = request('/account/session', headers={'Cookie': COOKIE})
                headers = {'Cookie': COOKIE, 'Origin': BASE, 'X-Waypost-CSRF': session['data']['csrf_token']}
                status, _, families = request('/account/oauth/list', {}, headers)
                if status == 200:
                    for family in families['data']['items']:
                        request('/account/oauth/revoke', {'space_id': 'space_test', 'family_id': family['family_id']}, headers)
            except Exception:
                pass  # All fixture storage is disposed below even on protocol failure.
        for name in containers:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for process in (login, app, claude, service):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        subprocess.run(['docker', 'image', 'rm', '-f', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        temporary.cleanup()
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
