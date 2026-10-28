"""Isolated protocol tests; no real IdP, Codex, Claude, or production service."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('waypost_account_plugin', ROOT / 'plugins/waypost/client.py')
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


class PairTransport:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail
        self.polls = 0

    def post(self, path, value, token=None):
        self.calls.append((path, value, token))
        if path.endswith('/start'):
            return {'ok': True, 'data': {'device_id': 'device_test', 'device_code': 's' * 43,
                    'user_code': 'ABCD-EFGH-IJKL-MNOP', 'interval': 5, 'expires_in': 600}}
        self.polls += 1
        if self.fail:
            raise OSError('secret upstream address and credential')
        if self.polls == 1:
            raise plugin.ProtocolError('AUTHORIZATION_PENDING')
        return {'ok': True, 'data': {'token': 'wp_test_' + 't' * 43, 'token_type': 'Bearer',
                'token_id': 'token_test', 'space_id': 'space_test', 'actor_id': 'actor_test',
                'consumer_id': 'consumer_test', 'expires_in': 3600}}


class PluginTests(unittest.TestCase):
    def test_pair_private_files_and_stable_pkce_without_secret_output(self):
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / 'config.json'
            transport, output = PairTransport(), io.StringIO()
            with contextlib.redirect_stdout(output):
                result = plugin.pair('https://waypost.example', 'Laptop', config,
                                     transport=transport, sleep=lambda _: None)
            self.assertEqual(transport.polls, 2)
            first, second = transport.calls[1][1], transport.calls[2][1]
            self.assertEqual(first, second)
            import base64, hashlib
            self.assertEqual(transport.calls[0][1]['code_challenge'],
                base64.urlsafe_b64encode(hashlib.sha256(first['code_verifier'].encode()).digest()).rstrip(b'=').decode())
            for secret in (first['code_verifier'], first['device_code'], 'wp_test_' + 't' * 43):
                self.assertNotIn(secret, output.getvalue())
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(Path(result['token_file']).stat().st_mode & 0o777, 0o600)
            self.assertEqual(plugin.load_config(config)[1], 'https://waypost.example')
            with self.assertRaises(plugin.SafeError):
                plugin.pair('https://waypost.example', 'Laptop', config, transport=transport)

    def test_unknown_redemption_stops_without_retry_or_credential_publication(self):
        with tempfile.TemporaryDirectory() as d:
            t = PairTransport(fail=True)
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(plugin.SafeError, 'revoke device device_test') as e:
                    plugin.pair('https://waypost.example', 'Laptop', Path(d) / 'config.json',
                                transport=t, sleep=lambda _: None)
            self.assertEqual(t.polls, 1)
            self.assertNotIn('secret upstream', str(e.exception))
            self.assertEqual(list(Path(d).iterdir()), [])

    def test_private_config_and_origin_rejections(self):
        for url in ('http://example.com', 'https://user:key@example.com',
                    'https://example.com/path', 'https://example.com?token=x',
                    'https://example.com/#fragment', 'https://example.com\n'):
            with self.assertRaises(plugin.SafeError):
                plugin.origin(url)
        self.assertEqual(plugin.origin('http://127.0.0.1:8765', True), 'http://127.0.0.1:8765')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'secret'
            p.write_text('secret')
            p.chmod(0o644)
            with self.assertRaises(plugin.SafeError): plugin.private_read(p)
            p.chmod(0o600)
            link = Path(d) / 'link'
            link.symlink_to(p)
            with self.assertRaises(OSError): plugin.private_read(link)
            with self.assertRaises(FileExistsError): plugin.atomic_new(p, b'new')
            self.assertEqual(p.read_text(), 'secret')

    def test_stdio_forwards_once_suppresses_notifications_and_sanitizes_errors(self):
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / 'config.json'
            with contextlib.redirect_stdout(io.StringIO()):
                plugin.pair('https://waypost.example', 'Laptop', config,
                            transport=PairTransport(), sleep=lambda _: None)
            class MCP:
                def __init__(self): self.calls = []
                def post(self, path, value, token):
                    self.calls.append((path, value, token))
                    if value['method'] == 'fail': raise OSError('SECRET_TOKEN')
                    return {'jsonrpc': '2.0', 'id': value.get('id'), 'result': {'tools': []}}
            m = MCP()
            requests = [
                {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'},
                {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'fail'},
            ]
            out = io.StringIO()
            plugin.serve(config, io.BytesIO(('\n'.join(map(json.dumps, requests)) + '\n').encode()), out, m)
            results = [json.loads(x) for x in out.getvalue().splitlines()]
            self.assertEqual(len(m.calls), 3)
            self.assertEqual([r['id'] for r in results], [1, 2])
            self.assertEqual(results[0]['result'], {'tools': []})
            self.assertIn('unknown', results[1]['error']['message'])
            self.assertNotIn('SECRET_TOKEN', out.getvalue())
            with self.assertRaises(plugin.SafeError):
                plugin.serve(config, io.BytesIO(b'x' * (plugin.MAX_BYTES + 1)), io.StringIO(), m)
            self.assertEqual(len(m.calls), 3)

    def test_transport_rejects_redirects_and_oversized_responses(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        class Handler(BaseHTTPRequestHandler):
            calls = []
            def do_POST(self):
                Handler.calls.append(self.path)
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                self.send_response(302)
                self.send_header('Location', '/leak')
                self.end_headers()
                self.wfile.write(b'{"error":{"code":"REDIRECT_REJECTED"}}')
            def do_GET(self):
                Handler.calls.append(self.path)
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            t = plugin.Transport('http://127.0.0.1:' + str(server.server_port))
            # Isolated local test only: remove proxy routing from this test opener.
            import urllib.request
            t.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), plugin.NoRedirect())
            with self.assertRaises(plugin.ProtocolError):
                t.post('/mcp', {'jsonrpc':'2.0','id':1,'method':'ping'}, 'private-token')
            self.assertEqual(Handler.calls, ['/mcp'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        class Huge(io.BytesIO):
            status = 200
        class Opener:
            def open(self, request, timeout): return Huge(b'x' * (plugin.MAX_BYTES + 1))
        t.opener = Opener()
        with self.assertRaisesRegex(plugin.SafeError, 'size limit'):
            t.post('/mcp', {'id':1})

    def test_manifests_and_bundled_skill_are_consistent(self):
        root = ROOT / 'plugins/waypost'
        manifest = json.loads((root / 'plugin.json').read_text())
        self.assertEqual(manifest['name'], root.name)
        mcp = json.loads((root / 'mcp.json').read_text())['mcpServers']['waypost']
        self.assertEqual(mcp['args'], ['${PLUGIN_ROOT}/client.py', 'serve'])
        for source in (ROOT / 'skills/waypost').rglob('*'):
            if source.is_file():
                self.assertEqual(source.read_bytes(), (root / 'skills/waypost' / source.relative_to(ROOT / 'skills/waypost')).read_bytes())


if __name__ == '__main__':
    unittest.main()
