#!/usr/bin/env python3
"""Exercise a designated synthetic Space through real HTTP/MCP and a simulated Codex CLI.

Creates only test-owned actors, consumers and credentials in --space-id. The caller
must provision that isolated Space first. Credentials are revoked and actors disabled
in finally; synthetic messages/audit remain for inspection. Never prints secrets or
response bodies. This verifies HTTP behavior, not Cloudflare D1 billing counters.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid


class Failure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, url, secret):
        self.url, self.secret = url.rstrip('/'), secret
        self.opener = urllib.request.build_opener(NoRedirect())

    def raw(self, method, path, value=None):
        request = urllib.request.Request(self.url + path, method=method,
            data=json.dumps(value).encode() if value is not None else None,
            headers={'Authorization': 'Bearer ' + self.secret,
                     'Content-Type': 'application/json',
                     'Accept': 'application/json, text/event-stream',
                     'User-Agent': 'Waypost/0.1.0 acceptance'})
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            try:
                body = json.loads(response.read(2 * 1024 * 1024))
            except ValueError:
                raise Failure('non-JSON HTTP response') from None
            return response.status, body

    def request(self, method, path, value=None):
        status, body = self.raw(method, path, value)
        if status >= 400 or body.get('ok') is not True:
            code = body.get('error', {}).get('code', 'HTTP_' + str(status))
            raise Failure('API rejected request: ' + str(code))
        return body['data']

    def denied(self, method, path, value, code):
        status, body = self.raw(method, path, value)
        check(status >= 400 and body.get('error', {}).get('code') == code,
              'expected rejection ' + code)

    def mcp(self, name, arguments):
        status, body = self.raw('POST', '/mcp', {'jsonrpc': '2.0', 'id': 1,
            'method': 'tools/call', 'params': {'name': name, 'arguments': arguments}})
        result = body.get('result', {}).get('structuredContent', {})
        check(status == 200 and result.get('ok') is True, 'MCP call failed')
        return result['data']


def check(condition, label):
    if not condition:
        raise Failure(label)


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(value)


def run(args, owner_secret):
    control = Client(args.url, owner_secret)
    root = '/admin/v0/spaces/' + args.space_id
    prefix = 'accept-' + uuid.uuid4().hex
    tokens, actors, checks, cleanup_errors = [], [], [], []
    result = {'space_id': args.space_id,
              'codex_transport': 'simulated CLI' if args.bridge_binary else 'not exercised',
              'checks': checks}

    def assistant(label):
        actor = control.request('POST', root + '/actors', {'request_id': prefix + label,
            'kind': 'agent', 'display_name': 'Acceptance ' + label})['actor_id']
        actors.append(actor)
        consumer = control.request('POST', root + '/consumers', {'request_id': prefix + label + '-c',
            'actor_id': actor, 'view': 'inbox', 'filter': {}})['consumer_id']
        return actor, consumer

    def token(label, actor, consumer):
        value = control.request('POST', root + '/tokens', {'request_id': prefix + label,
            'actor_id': actor, 'consumer_id': consumer})
        tokens.append(value['token_id'])
        return value, Client(args.url, value['token'])

    try:
        target_actor, target_consumer = assistant('target')
        source_actor, source_consumer = assistant('source')
        target_token, target = token('target-token', target_actor, target_consumer)
        _, source = token('source-token', source_actor, source_consumer)
        routing_path = root + '/tokens/' + target_token['token_id'] + '/routing'
        detail = control.request('GET', routing_path)
        before_identity = target.request('GET', '/v0/describe')
        check(before_identity.get('access_model') == 'space_membership',
              'server does not advertise space membership')
        check(not any(k in before_identity for k in ('scopes', 'resource_grants', 'allowed_recipient_ids')),
              'server still advertises connection grants')
        target.denied('PUT', routing_path, {}, 'UNAUTHENTICATED')
        target.denied('POST', '/v0/inbox/read', {'consumer_id': source_consumer}, 'NOT_FOUND')
        checks.append('membership advertised; connection cannot manage routing or use another Consumer')
        message = source.request('POST', '/v0/messages', {'request_id': prefix + '-message',
            'recipient_ids': [target_actor], 'kind': 'info', 'subject': 'Synthetic acceptance',
            'body': {'text': 'Untrusted test text must not enter the queue notification.'}})
        page = target.request('POST', '/v0/inbox/read', {'consumer_id': target_consumer})
        check(any(i['resource_id'] == message['message_id'] for i in page['items']),
              'same-space message missing without grants')
        check(target.request('GET', '/v0/messages/' + message['message_id'])['message_id'] == message['message_id'],
              'message unreadable without grants')
        edit = {'request_id': prefix + '-routing', 'expected_authority_version': detail['authority_version'],
            'default_recipient_id': source_actor}
        changed = control.request('PUT', routing_path, edit)
        after_identity = target.request('GET', '/v0/describe')
        check(all(before_identity[k] == after_identity[k] for k in ('space_id', 'actor_id', 'consumer_id')),
              'identity changed after routing edit')
        check(changed['authority_version'] == detail['authority_version'] + 1, 'version did not increment')
        replay = control.request('PUT', routing_path, edit)
        check(replay['replayed'] and replay['authority_version'] == changed['authority_version'], 'replay changed version')
        control.denied('PUT', routing_path, dict(edit, request_id=prefix + '-stale'), 'REVISION_CONFLICT')
        control.denied('PUT', routing_path, dict(edit, default_recipient_id=None), 'IDEMPOTENCY_CONFLICT')
        reply = target.request('POST', '/v0/messages', {'request_id': prefix + '-reverse',
            'kind': 'info', 'subject': 'Reverse synthetic acceptance', 'body': {'text': 'No side effects.'}})
        source_page = source.request('POST', '/v0/inbox/read', {'consumer_id': source_consumer})
        check(any(i['resource_id'] == reply['message_id'] for i in source_page['items']),
              'default routing did not deliver reverse message')
        checks.append('same-space bidirectional send/read without grants; default routing, replay and CAS verified')
        check(target.mcp('waypost_describe', {})['actor_id'] == target_actor, 'MCP identity mismatch')
        check(any(i['resource_id'] == message['message_id'] for i in target.mcp('waypost_inbox',
            {'consumer_id': target_consumer})['items']), 'MCP inbox missing message')
        checks.append('real HTTP MCP describe and inbox')

        if args.bridge_binary:
            with tempfile.TemporaryDirectory(prefix='waypost-acceptance-') as temporary:
                directory = Path(temporary)
                counter, fake = directory / 'queue-count', directory / 'codex-simulated'
                private_write(fake, '#!' + sys.executable + '\nimport pathlib,sys\n'
                    'assert sys.argv[1] == "queue"\n'
                    'prompt = sys.argv[sys.argv.index("--message")+1]\n'
                    'assert "Untrusted test text" not in prompt\n'
                    'path = pathlib.Path(' + repr(str(counter)) + ')\n'
                    'path.write_text(str(int(path.read_text())+1) if path.exists() else "1")\n'
                    'print("Queued message queue_accept123 for thread " + sys.argv[sys.argv.index("--thread")+1] + ".")\n')
                fake.chmod(0o700)
                secret_file, config_file = directory / 'token', directory / 'config.json'
                private_write(secret_file, target_token['token'])
                config = {'base_url': args.url.rstrip('/'), 'token_file': str(secret_file),
                    'state_dir': str(directory / 'state'), 'space_id': args.space_id,
                    'actor_id': target_actor, 'consumer_id': target_consumer,
                    'thread_id': '11111111-1111-4111-8111-111111111111', 'codex_path': str(fake),
                    'codex_remote': None, 'codex_home': None}
                private_write(config_file, json.dumps(config))

                def once():
                    call = subprocess.run([str(Path(args.bridge_binary).resolve()), '--config', str(config_file), 'once'],
                                          capture_output=True, timeout=120)
                    check(call.returncode == 0, 'bridge once failed (output suppressed)')

                once()
                check(counter.exists() and counter.read_text() == '1', 'bridge did not notify exactly once')
                once()
                check(counter.read_text() == '1', 'bridge duplicated notification after restart')
                empty = target.request('POST', '/v0/inbox/read',
                    {'consumer_id': target_consumer, 'cursor': page['next_cursor']})
                check(empty['items'] == [], 'bridge unexpectedly published visible feed items')
                # Routing changes must not reset visibility or duplicate an accepted notification.
                detail = control.request('GET', routing_path)
                control.request('PUT', routing_path, dict(edit, request_id=prefix + '-route-reset',
                    expected_authority_version=detail['authority_version'], default_recipient_id=None))
                once()
                check(counter.read_text() == '1', 'routing change duplicated notification')
                checks.append('real bridge binary: simulated queue, restart dedup, empty feed, routing-change dedup')
                result['empty_poll_evidence'] = 'no new visible feed items or queue calls; D1 writes need external metrics'

        control.request('DELETE', root + '/tokens/' + target_token['token_id'])
        target.denied('POST', '/v0/inbox/read', {'consumer_id': target_consumer}, 'UNAUTHENTICATED')
        target.denied('GET', '/v0/messages/' + message['message_id'], None, 'UNAUTHENTICATED')
        checks.append('revocation stops original bearer reads')
        result['result'] = 'passed'
    finally:
        for tid in tokens:
            try:
                control.request('DELETE', root + '/tokens/' + tid)
            except Exception:
                cleanup_errors.append('token revocation failed')
        for aid in actors:
            try:
                control.request('POST', root + '/actors/' + aid + '/disable', {})
            except Exception:
                cleanup_errors.append('actor disable failed')
        result['cleanup'] = 'completed' if not cleanup_errors else cleanup_errors
        if cleanup_errors:
            raise Failure('test cleanup incomplete')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--owner-secret-file', type=Path, required=True)
    parser.add_argument('--space-id', required=True)
    parser.add_argument('--bridge-binary', type=Path)
    args = parser.parse_args()
    try:
        url = urllib.parse.urlsplit(args.url)
        check(url.scheme == 'https' or (url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost', '::1')),
              'remote service requires HTTPS')
        check(not url.username and not url.password and url.path in ('', '/') and not url.query and not url.fragment,
              'URL must be a service origin')
        check(re.fullmatch(r'[A-Za-z0-9_-]{1,96}', args.space_id), 'invalid space ID')
        info = args.owner_secret_file.lstat()
        check(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077, 'secret must be a private regular file')
        if hasattr(os, 'getuid'):
            check(info.st_uid == os.getuid(), 'secret must belong to the current user')
        secret = args.owner_secret_file.read_text().strip()
        check(secret.startswith('wp_user_'), 'expected a space owner credential, not deployment admin')
        print(json.dumps(run(args, secret), indent=2))
    except Exception as error:
        # Network/CLI exceptions may embed sensitive headers or output: emit only known-safe failures.
        reason = str(error) if isinstance(error, Failure) else type(error).__name__
        print(json.dumps({'result': 'failed', 'reason': reason}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
