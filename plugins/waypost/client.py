#!/usr/bin/env python3
"""Private local Waypost device pairing and bounded stdio MCP forwarding.

This implements Waypost's experimental custom pairing, not OAuth device grant
or MCP OAuth. Pairing runs interactively outside the model's tool channel.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 1024 * 1024
ID = re.compile(r'[A-Za-z0-9_-]{1,96}\Z')


class SafeError(Exception):
    """Only fixed, nonsecret messages and validated public IDs reach output."""


class ProtocolError(SafeError):
    def __init__(self, code):
        self.code = code if re.fullmatch(r'[A-Z_]{1,64}', str(code)) else 'REMOTE_ERROR'
        super().__init__(self.code)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def origin(value, allow_loopback=False):
    try:
        p = urllib.parse.urlsplit(value)
        _ = p.port
    except ValueError:
        raise SafeError('Invalid service origin.') from None
    if (p.username or p.password or p.query or p.fragment or p.path not in ('', '/')
            or not p.hostname or any(c.isspace() for c in value)):
        raise SafeError('Expected a fixed service origin, without path or credentials.')
    if p.scheme != 'https' and not (allow_loopback and p.scheme == 'http'
                                      and p.hostname in ('127.0.0.1', '::1')):
        raise SafeError('HTTPS is required; loopback HTTP requires explicit development mode.')
    return urllib.parse.urlunsplit((p.scheme, p.netloc, '', '', ''))


def private_read(path, limit=MAX_BYTES):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_mode & 0o077
                or (hasattr(os, 'getuid') and s.st_uid != os.getuid())):
            raise SafeError('Configuration and token must be private regular files owned by this user.')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise SafeError('Private file exceeds size limit.')
        return data
    finally:
        os.close(fd)


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = path.lstat()
    if (not stat.S_ISDIR(s.st_mode) or s.st_mode & 0o077
            or (hasattr(os, 'getuid') and s.st_uid != os.getuid())):
        raise SafeError('Use a private configuration directory owned by this user.')


def atomic_new(path, data):
    """Durable private publication with no overwriting of existing configurations."""
    private_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix='.waypost-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.link(temporary, path)  # atomic exclusive creation, including symlink races
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        os.unlink(temporary)


class Transport:
    def __init__(self, service):
        self.service = service
        self.opener = urllib.request.build_opener(NoRedirect())

    def post(self, path, value, token=None):
        if path not in ('/account/devices/start', '/account/devices/token', '/mcp'):
            raise SafeError('Unsupported endpoint.')
        body = json.dumps(value, ensure_ascii=False, allow_nan=False).encode()
        if len(body) > MAX_BYTES:
            raise SafeError('Request exceeds size limit.')
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        req = urllib.request.Request(self.service + path, data=body, headers=headers, method='POST')
        try:
            response = self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            response = e
        with response:
            data = response.read(MAX_BYTES + 1)
            code = response.status
        if len(data) > MAX_BYTES:
            raise SafeError('Response exceeds size limit; outcome may be unknown.')
        if code == 202 and not data:
            return None
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError):
            raise SafeError('Invalid remote response; outcome may be unknown.') from None
        if not 200 <= code < 300:
            if isinstance(value, dict) and isinstance(value.get('error'), dict):
                raise ProtocolError(value['error'].get('code'))
            raise SafeError('Remote request failed; outcome may be unknown.')
        return value


def envelope(value):
    if not isinstance(value, dict) or value.get('ok') is not True or not isinstance(value.get('data'), dict):
        raise SafeError('Unexpected pairing response; outcome may be unknown.')
    return value['data']


def public_id(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise SafeError('Invalid identity in response.')
    return value


def pair(service, name, config_path, allow_loopback=False, transport=None, sleep=time.sleep, now=time.monotonic):
    service = origin(service, allow_loopback)
    config_path = Path(config_path).expanduser().absolute()
    private_directory(config_path.parent)
    if config_path.exists() or config_path.is_symlink():
        raise SafeError('Configuration already exists; preserve it and revoke/replace deliberately.')
    if not name or len(name.encode()) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise SafeError('Device name must be 1–80 bytes without controls.')
    transport = transport or Transport(service)
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    start = envelope(transport.post('/account/devices/start', {
        'display_name': name, 'code_challenge_method': 'S256', 'code_challenge': challenge}))
    device_id = public_id(start.get('device_id'))
    user_code = start.get('user_code')
    device_code = start.get('device_code')
    if (not isinstance(user_code, str) or not re.fullmatch(r'[A-Za-z0-9-]{8,32}', user_code)
            or not isinstance(device_code, str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', device_code)):
        raise SafeError('Invalid pairing codes.')
    interval, expires = start.get('interval'), start.get('expires_in')
    if (type(interval) is not int or not 1 <= interval <= 60
            or type(expires) is not int or not 1 <= expires <= 1800):
        raise SafeError('Invalid pairing lifetime.')
    print(json.dumps({'device_id': device_id, 'user_code': user_code, 'verification_uri': service + '/account'}), flush=True)
    deadline = now() + expires
    try:
        while now() < deadline:
            sleep(interval)
            if now() >= deadline:
                break
            try:
                result = envelope(transport.post('/account/devices/token', {
                    'device_code': device_code, 'code_verifier': verifier}))
            except ProtocolError as e:
                if e.code == 'AUTHORIZATION_PENDING':
                    continue
                raise
            token = result.get('token')
            if (not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{20,512}', token)
                    or result.get('token_type') != 'Bearer'):
                raise SafeError('Invalid credential response.')
            identity = {k: public_id(result.get(k)) for k in ('space_id', 'actor_id', 'consumer_id', 'token_id')}
            token_path = config_path.parent / ('token-' + secrets.token_hex(12))
            config = dict(identity, version=1, base_url=service, token_file=str(token_path),
                          device_id=device_id, allow_loopback=allow_loopback)
            atomic_new(token_path, token.encode())
            atomic_new(config_path, (json.dumps(config, indent=2) + '\n').encode())
            print('Pairing saved privately. Verify identity with waypost_describe before use.', flush=True)
            return config
        raise SafeError('Pairing expired.')
    except Exception:
        # No automatic second redemption after network, disk, malformed response,
        # or any result except explicit AUTHORIZATION_PENDING.
        raise SafeError('Pairing stopped; outcome may be unknown. Check and revoke device ' + device_id + ' before pairing again.') from None


def load_config(path):
    try:
        config = json.loads(private_read(Path(path).expanduser()))
        if config.get('version') != 1 or type(config.get('allow_loopback', False)) is not bool:
            raise SafeError('Unsupported local configuration.')
        service = origin(config['base_url'], config.get('allow_loopback', False))
        if not Path(config['token_file']).is_absolute():
            raise SafeError('Token path must be absolute.')
        for key in ('space_id', 'actor_id', 'consumer_id', 'token_id', 'device_id'):
            public_id(config[key])
        token = private_read(config['token_file'], 512).decode().strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{20,512}', token):
            raise SafeError('Invalid local credential.')
        return config, service, token
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise SafeError('Invalid local configuration.') from None


def serve(path, input_stream=None, output_stream=None, transport=None):
    _, service, token = load_config(path)
    transport = transport or Transport(service)
    input_stream = input_stream or sys.stdin.buffer
    output_stream = output_stream or sys.stdout
    while True:
        raw = input_stream.readline(MAX_BYTES + 1)
        if not raw:
            return
        if len(raw) > MAX_BYTES:
            raise SafeError('Input exceeds size limit; forwarding stopped.')
        request_id, notification = None, False
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise SafeError('Expected JSON-RPC object.')
            request_id = value.get('id')
            notification = 'id' not in value
            if (value.get('jsonrpc') != '2.0' or not isinstance(value.get('method'), str)
                    or ('id' in value and type(request_id) not in (str, int, type(None)))):
                raise SafeError('Invalid JSON-RPC request.')
            response = transport.post('/mcp', value, token)
            if notification:
                continue
            if (not isinstance(response, dict) or response.get('jsonrpc') != '2.0'
                    or response.get('id') != request_id or ('result' not in response and 'error' not in response)):
                raise SafeError('Invalid MCP response.')
            if 'error' in response:
                response = {'jsonrpc': '2.0', 'id': request_id,
                            'error': {'code': -32000, 'message': 'Waypost rejected the request; inspect the service safely.'}}
        except Exception:
            if notification:
                continue
            response = {'jsonrpc': '2.0', 'id': request_id,
                        'error': {'code': -32000, 'message': 'Waypost request failed; outcome may be unknown. Do not blindly retry writes.'}}
        output_stream.write(json.dumps(response, ensure_ascii=False, allow_nan=False) + '\n')
        output_stream.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    default = os.environ.get('WAYPOST_CONFIG', str(Path.home() / '.config/waypost-plugin/config.json'))
    p = commands.add_parser('pair')
    p.add_argument('--url', required=True)
    p.add_argument('--name', required=True)
    p.add_argument('--config', default=default)
    p.add_argument('--allow-loopback', action='store_true', help='Development only: literal loopback HTTP')
    s = commands.add_parser('serve')
    s.add_argument('--config', default=default)
    args = parser.parse_args()
    try:
        if args.command == 'pair':
            pair(args.url, args.name, args.config, args.allow_loopback)
        else:
            serve(args.config)
    except Exception as e:
        print(str(e) if isinstance(e, SafeError) else 'Waypost operation failed; inspect private configuration safely.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
