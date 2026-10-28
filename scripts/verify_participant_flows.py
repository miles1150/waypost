#!/usr/bin/env python3
"""Local-only integration acceptance for webhook, Codex and scheduled participants.

Starts a real native Waypost service with temporary storage. Webhook and Codex
receivers are explicitly simulated; HTTP/MCP messaging, authorization, persistence
and receipts use the actual service. No remote URL or production credentials are
accepted. Temporary credentials and service state are removed on exit.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from verify_space_membership import Client, Failure, check, private_write


KINDS = ('webhook', 'codex', 'scheduled')
THREAD_ID = '11111111-1111-4111-8111-111111111111'


class SimulatedResponseLoss(Exception):
    pass


def database_digest(path):
    """Read-only evidence of persisted state; not a D1 billing measurement."""
    digest = hashlib.sha256()
    with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True) as db:
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        for (name,) in tables:
            digest.update(name.encode())
            rows = db.execute('SELECT * FROM "' + name.replace('"', '""') + '"').fetchall()
            for row in sorted(map(repr, rows)):
                digest.update(row.encode())
    return digest.hexdigest()


class WebhookFixture:
    def __init__(self):
        self.secret = secrets.token_urlsafe(32)
        self.deliveries = []
        self.valid_auth = True
        self.drop_response = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                fixture.valid_auth &= self.headers.get('Authorization') == 'Bearer ' + fixture.secret
                data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
                fixture.deliveries.append(data)
                if fixture.drop_response:
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                self.send_response(202)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"accepted":true}')

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port) + '/notify'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class NativeFixture:
    def __init__(self, root, server_binary):
        self.root = root
        self.data = root / 'native'
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            port = available.getsockname()[1]
        self.url = 'http://127.0.0.1:' + str(port)
        self.secret = secrets.token_hex(32)
        self.process = subprocess.Popen([str(server_binary), 'serve', '--data', str(self.data),
            '--listen', '127.0.0.1:' + str(port)], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=dict(os.environ,
                WAYPOST_ADMIN_SECRET=self.secret, WAYPOST_PUBLIC_ORIGIN=self.url))
        self.control = Client(self.url, self.secret)
        try:
            self.initialize()
        except BaseException:
            self.close()
            raise

    def initialize(self):
        for _ in range(100):
            if self.process.poll() is not None:
                raise Failure('native service exited before readiness')
            try:
                self.space = self.control.request('POST', '/admin/v0/spaces',
                    {'request_id': 'participant-fixture', 'display_name': 'Local participant acceptance'})
                break
            except Exception:
                time.sleep(.1)
        else:
            self.close()
            raise Failure('native service readiness timeout')
        self.admin_root = '/admin/v0/spaces/' + self.space['space_id']
        self.participants = {}
        for kind in KINDS:
            actor = self.control.request('POST', self.admin_root + '/actors',
                {'request_id': kind, 'kind': 'agent', 'display_name': 'Simulated ' + kind})
            consumer = self.control.request('POST', self.admin_root + '/consumers',
                {'request_id': kind + '-consumer', 'actor_id': actor['actor_id'], 'view': 'inbox',
                 'filter': {}})
            self.participants[kind] = {'actor': actor['actor_id'], 'consumer': consumer['consumer_id']}
        for kind, participant in self.participants.items():
            token = self.control.request('POST', self.admin_root + '/tokens',
                {'request_id': kind + '-token', 'actor_id': participant['actor'],
                 'consumer_id': participant['consumer']})
            participant.update(token=token['token'], token_id=token['token_id'], client=Client(self.url, token['token']))
            bridge_token = self.control.request('POST', self.admin_root + '/tokens',
                {'request_id': kind + '-bridge-token', 'actor_id': participant['actor'],
                 'consumer_id': participant['consumer']})
            participant.update(bridge_token=bridge_token['token'], bridge_token_id=bridge_token['token_id'],
                               bridge_client=Client(self.url, bridge_token['token']))

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def digest(self):
        return database_digest(self.data / 'metadata.sqlite')

    def receipt_count(self):
        with sqlite3.connect('file:' + str(self.data / 'metadata.sqlite') + '?mode=ro', uri=True) as db:
            return db.execute('SELECT count(*) FROM receipts').fetchone()[0]

    def route(self, kind, destination):
        participant = self.participants[kind]
        path = self.admin_root + '/tokens/' + participant['bridge_token_id'] + '/routing'
        detail = self.control.request('GET', path)
        return self.control.request('PUT', path, {'request_id': uuid.uuid4().hex,
            'expected_authority_version': detail['authority_version'],
            'default_recipient_id': destination})

    def revoke_bridge(self, kind):
        participant = self.participants[kind]
        self.control.request('DELETE', self.admin_root + '/tokens/' + participant['bridge_token_id'])

    def replace_bridge(self, kind):
        participant = self.participants[kind]
        issued = self.control.request('POST', self.admin_root + '/tokens',
            {'request_id': kind + '-replacement', 'actor_id': participant['actor'],
             'consumer_id': participant['consumer']})
        participant.update(bridge_token=issued['token'], bridge_token_id=issued['token_id'],
                           bridge_client=Client(self.url, issued['token']))


def read_all(participant, limit=1):
    cursor, messages, pages = None, [], 0
    while True:
        page = participant['client'].request('POST', '/v0/inbox/read',
            {'consumer_id': participant['consumer'], 'cursor': cursor, 'limit': limit})
        pages += 1
        messages.extend(page['items'])
        cursor = page['next_cursor']
        if not page['has_more']:
            return messages, cursor, pages
        check(pages < 50, 'unbounded pagination')


def receive_and_ack(participant, items, path):
    """Full content and pending receipt are committed locally before any received ACK."""
    client = participant['client']
    processed_now = 0
    with sqlite3.connect(path) as db:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS inbox(item_id TEXT PRIMARY KEY, content TEXT, ack_key TEXT, '
                   'received_acked INTEGER DEFAULT 0, processed INTEGER DEFAULT 0, '
                   'processed_acked INTEGER DEFAULT 0, mock_result TEXT)')
        for item in items:
            previous = db.execute('SELECT processed_acked FROM inbox WHERE item_id=?', (item['item_id'],)).fetchone()
            if previous and previous[0]:
                continue
            if previous is None:
                content = client.request('GET', '/v0/messages/' + item['resource_id'])
                with db:
                    db.execute('INSERT INTO inbox(item_id,content,ack_key) VALUES(?,?,?)',
                        (item['item_id'], json.dumps(content), 'received-' + item['item_id']))
            # Reading the committed row makes the persistence boundary inspectable.
            row = db.execute('SELECT content,ack_key,received_acked,processed FROM inbox WHERE item_id=?',
                             (item['item_id'],)).fetchone()
            check(json.loads(row[0])['message_id'] == item['resource_id'], 'local saved content mismatch')
            if not row[2]:
                ack = {'request_id': row[1], 'consumer_id': participant['consumer'],
                       'items': [{'item_id': item['item_id'], 'stage': 'received'}]}
                receipt = client.request('POST', '/v0/receipts', ack)
                check(receipt['items'][0]['stage'] == 'received', 'received boundary not recorded')
                check(client.request('POST', '/v0/receipts', ack) == receipt, 'ACK replay differs')
                with db:
                    db.execute('UPDATE inbox SET received_acked=1 WHERE item_id=?', (item['item_id'],))
            if not row[3]:
                # Deterministic simulated business handling, not an external model or action.
                summary = json.dumps({'simulated': True, 'text_chars': len(json.loads(row[0])['body']['text'])})
                with db:
                    db.execute('UPDATE inbox SET processed=1,mock_result=? WHERE item_id=?', (summary, item['item_id']))
                processed_now += 1
            complete = client.request('POST', '/v0/receipts', {'request_id': 'processed-' + item['item_id'],
                'consumer_id': participant['consumer'], 'items': [{'item_id': item['item_id'], 'stage': 'processed'}]})
            check(complete['items'][0]['stage'] == 'processed', 'processed boundary not recorded')
            with db:
                db.execute('UPDATE inbox SET processed_acked=1 WHERE item_id=?', (item['item_id'],))
    return processed_now


def bridge_command(binary, config_path, command, expect_success=True):
    result = subprocess.run([str(binary), '--config', str(config_path), *command],
                            capture_output=True, timeout=120)
    check((result.returncode == 0) == expect_success, 'bridge exit status differs (output suppressed)')


def bridge_once(binary, config_path, expect_success=True):
    bridge_command(binary, config_path, ['once'], expect_success)


def run(args):
    checks = []
    with tempfile.TemporaryDirectory(prefix='waypost-participants-') as temporary:
        root = Path(temporary)
        fixture = NativeFixture(root, args.server_binary)
        webhook = None
        try:
            webhook = WebhookFixture()
            # Notification adapter configuration is deliberately kept in one function
            # so this harness follows the approved bridge contract, not a parallel API.
            configs, queue_log = configure_bridges(fixture, root, webhook)
            baseline = fixture.digest()
            for config in configs.values():
                bridge_once(args.bridge_binary, config)
            check(fixture.digest() == baseline, 'empty bridge polling mutated server state')
            check(not webhook.deliveries and not queue_log.exists(), 'empty poll notified a runtime')
            checks.append('empty polling leaves persisted server state unchanged')
            matrix = []
            for source in KINDS:
                for target in KINDS:
                    participant = fixture.participants[source]
                    payload = {'request_id': source + '-to-' + target,
                        'recipient_ids': [fixture.participants[target]['actor']], 'kind': 'info',
                        'subject': 'Synthetic participant flow',
                        'body': {'text': 'UNTRUSTED_MATRIX_BODY ' + source + ' to ' + target}}
                    if source == 'codex':
                        send = lambda: participant['client'].mcp('waypost_send', payload)
                    else:
                        send = lambda: participant['client'].request('POST', '/v0/messages', payload)
                    if source == 'webhook' and target == 'codex':
                        try:
                            send()
                            raise SimulatedResponseLoss()
                        except SimulatedResponseLoss:
                            status = participant['client'].request('POST', '/v0/submissions/status',
                                {'operation': 'message.send', 'request_id': payload['request_id']})
                            check(status['submission_state'] == 'committed', 'lost send response could not be recovered')
                    message = send()
                    check(send()['message_id'] == message['message_id'], 'stable send request duplicated message')
                    matrix.append({'source': source, 'target': target, 'message_id': message['message_id']})
            checks.append('all 9 sender/receiver pairs publish once under stable request replay')
            checks.append('injected lost send response after real commit recovered by submission status and stable ID')
            snapshot = fixture.digest()
            for config in configs.values():
                bridge_once(args.bridge_binary, config)
                bridge_once(args.bridge_binary, config)
            check(fixture.digest() == snapshot, 'notification bridge wrote server receipts or state')
            check(len(webhook.deliveries) == 3 and webhook.valid_auth, 'webhook notification count/auth mismatch')
            required = {'version', 'event', 'delivery_id', 'space_id', 'actor_id', 'consumer_id', 'item_id', 'message_id'}
            check(all(set(item) == required and item['version'] == 1 and item['event'] == 'waypost.message.available'
                      for item in webhook.deliveries), 'webhook reference schema differs')
            check(len({item['delivery_id'] for item in webhook.deliveries}) == 3, 'webhook delivery identity duplicated')
            codex_notifications = queue_log.read_text().splitlines()
            check(len(codex_notifications) == 3, 'Codex notification count mismatch')
            check('UNTRUSTED_MATRIX_BODY' not in json.dumps(webhook.deliveries) + queue_log.read_text(),
                  'message body leaked into runtime notification')
            check(fixture.receipt_count() == 0, 'notification incorrectly acknowledged message')
            checks.append('webhook/Codex acceptance and restart do not ACK or duplicate notifications')
            cursors = {}
            for kind in KINDS:
                participant = fixture.participants[kind]
                feed, cursor, pages = read_all(participant)
                items = [item for item in feed if item['item_type'] == 'message']
                cursors[kind] = cursor
                expected = {row['message_id'] for row in matrix if row['target'] == kind}
                check({item['resource_id'] for item in items} == expected and pages >= 3,
                      'paginated receiver matrix differs')
                local_inbox = root / (kind + '-inbox.sqlite')
                if kind == 'scheduled':
                    original_request = participant['client'].request
                    def lose_first_received_response(method, path, body=None):
                        response = original_request(method, path, body)
                        if path == '/v0/receipts' and body['items'][0]['stage'] == 'received':
                            raise SimulatedResponseLoss()
                        return response
                    participant['client'].request = lose_first_received_response
                    try:
                        receive_and_ack(participant, items, local_inbox)
                        raise Failure('response loss was not injected')
                    except SimulatedResponseLoss:
                        pass
                    finally:
                        participant['client'].request = original_request
                    with sqlite3.connect(local_inbox) as saved:
                        check(saved.execute('SELECT received_acked,processed FROM inbox').fetchall() == [(0, 0)],
                              'lost ACK response incorrectly confirmed local processing')
                check(receive_and_ack(participant, items, local_inbox) == 3, 'initial simulated processing count differs')
                before_repeat = fixture.digest()
                check(receive_and_ack(participant, items, local_inbox) == 0, 'restart repeated simulated business handling')
                check(fixture.digest() == before_repeat, 'repeat scheduled processing rewrote server receipts')
            check(fixture.receipt_count() == 9, 'expected 9 independent processed receipts')
            checks.append('all 3 consumers paginate, persist full content, received then processed')
            checks.append('restarted scheduled processing skips completed business and confirmed ACKs')
            checks.append('injected lost received ACK response resumes durable inbox and replays same receipt request')
            before_counts = (len(webhook.deliveries), len(queue_log.read_text().splitlines()))
            snapshot = fixture.digest()
            for kind in ('webhook', 'codex'):
                bridge_once(args.bridge_binary, configs[kind])
            check(before_counts == (len(webhook.deliveries), len(queue_log.read_text().splitlines())),
                  'receipt updates caused a notification loop')
            check(fixture.digest() == snapshot, 'receipt feed processing mutated server state')
            checks.append('receipt updates in unfiltered inboxes do not trigger notification loops')
            # The simulated endpoint records a delivery, then closes before replying.
            fixture.participants['scheduled']['client'].request('POST', '/v0/messages',
                {'request_id': 'webhook-unknown', 'recipient_ids': [fixture.participants['webhook']['actor']],
                 'kind': 'info', 'subject': 'Unknown delivery fixture', 'body': {'text': 'UNTRUSTED_MATRIX_BODY recovery'}})
            webhook.drop_response = True
            bridge_once(args.bridge_binary, configs['webhook'])
            check(len(webhook.deliveries) == before_counts[0] + 1, 'response-loss delivery did not reach webhook')
            first_unknown = webhook.deliveries[-1]
            with sqlite3.connect(root / 'webhook-state/state.sqlite3') as state:
                check(state.execute('SELECT status FROM items WHERE item_id=?', (first_unknown['item_id'],)).fetchone() == ('unknown',),
                      'lost webhook response was not recorded as unknown')
            bridge_once(args.bridge_binary, configs['webhook'])
            check(len(webhook.deliveries) == before_counts[0] + 1, 'unknown webhook delivery was automatically resent')
            webhook.drop_response = False
            bridge_command(args.bridge_binary, configs['webhook'], ['reconcile', first_unknown['item_id'], 'pending'])
            bridge_once(args.bridge_binary, configs['webhook'])
            check(webhook.deliveries[-1]['delivery_id'] == first_unknown['delivery_id'], 'explicit retry changed webhook delivery identity')
            before_counts = (len(webhook.deliveries), len(queue_log.read_text().splitlines()))
            checks.append('webhook accepted then lost response stays unknown; explicit retry preserves delivery ID')
            for kind in ('webhook', 'codex'):
                fixture.route(kind, fixture.participants['scheduled']['actor'])
                participant = fixture.participants[kind]
                participant['bridge_client'].request('POST', '/v0/inbox/read',
                    {'consumer_id': participant['consumer'], 'cursor': cursors[kind]})
                bridge_once(args.bridge_binary, configs[kind])
            check(before_counts == (len(webhook.deliveries), len(queue_log.read_text().splitlines())),
                  'routing change re-notified old messages')
            checks.append('default routing changes preserve cursors without duplicate notifications')
            for kind in ('webhook', 'codex'):
                pending = fixture.participants['scheduled']['client'].request('POST', '/v0/messages',
                    {'request_id': kind + '-pending-revoke', 'recipient_ids': [fixture.participants[kind]['actor']],
                     'kind': 'info', 'subject': 'Pending revoke fixture', 'body': {'text': 'UNTRUSTED_MATRIX_BODY pending'}})
                bridge_command(args.bridge_binary, configs[kind], ['scan'])
                with sqlite3.connect(root / (kind + '-state') / 'state.sqlite3') as state:
                    check(state.execute('SELECT status FROM items WHERE resource_id=?', (pending['message_id'],)).fetchone() == ('pending',),
                          'scan did not persist pending notification')
                fixture.revoke_bridge(kind)
                bridge_once(args.bridge_binary, configs[kind], expect_success=False)
            check(before_counts == (len(webhook.deliveries), len(queue_log.read_text().splitlines())),
                  'revoked connection still dispatched')
            checks.append('connection revocation blocks already-persisted pending work in both adapters')
            for kind in ('webhook', 'codex'):
                fixture.replace_bridge(kind)
                # Existing synthetic credential file is private and bridge is stopped here.
                (root / (kind + '-token')).write_text(fixture.participants[kind]['bridge_token'])
                bridge_once(args.bridge_binary, configs[kind])
            check((len(webhook.deliveries), len(queue_log.read_text().splitlines())) ==
                  (before_counts[0] + 1, before_counts[1] + 1), 'replacement connection did not dispatch pending work exactly once')
            checks.append('replacement connection with unchanged identity dispatches pending references once')
            # One explicitly chosen reply demonstrates correlation without an automatic reply loop.
            original = next(row for row in matrix if row['source'] == 'codex' and row['target'] == 'scheduled')
            reply_body = {'request_id': 'one-explicit-result', 'recipient_ids': [fixture.participants['codex']['actor']],
                'in_reply_to': original['message_id'], 'kind': 'result', 'subject': 'Simulated handler result',
                'body': {'text': 'Simulated handler durably recorded the message text length; no external action was executed.'}}
            sender = fixture.participants['scheduled']['client']
            reply = sender.request('POST', '/v0/messages', reply_body)
            check(sender.request('POST', '/v0/messages', reply_body)['message_id'] == reply['message_id'],
                  'stable reply request duplicated result')
            delivered = fixture.participants['codex']['client'].request('GET', '/v0/messages/' + reply['message_id'])
            check(delivered['in_reply_to'] == original['message_id'], 'result lost reply correlation')
            checks.append('one explicit simulated result reply retains correlation and stable send ID')
            return {'result': 'passed', 'service': 'real native HTTP/MCP with temporary SQLite',
                    'runtime_adapters': 'simulated webhook and Codex; scheduled receiver uses real HTTP',
                    'matrix_pairs': 9, 'checks': checks}
        finally:
            try:
                if webhook is not None:
                    webhook.close()
            finally:
                fixture.close()


def configure_bridges(fixture, root, webhook):
    """Use approved v2 adapters; loopback exception is explicit and test-only."""
    fake, queue_log = root / 'codex-simulated', root / 'queue-log'
    private_write(fake, '#!' + sys.executable + '\nimport json,pathlib,sys\n'
        'assert sys.argv[1] == "queue"\n'
        'prompt = sys.argv[sys.argv.index("--message")+1]\n'
        'assert "UNTRUSTED_MATRIX_BODY" not in prompt\n'
        'path = pathlib.Path(' + repr(str(queue_log)) + ')\n'
        'with path.open("a") as stream: stream.write(json.dumps(prompt)+"\\n")\n'
        'print("Queued message queue_accept123 for thread " + sys.argv[sys.argv.index("--thread")+1] + ".")\n')
    fake.chmod(0o700)
    url_file, secret_file = root / 'webhook-url', root / 'webhook-secret'
    private_write(url_file, webhook.url)
    private_write(secret_file, webhook.secret)
    adapters = {
        'webhook': {'type': 'webhook', 'url_file': str(url_file), 'secret_file': str(secret_file),
                    'allow_loopback_test': True},
        'codex': {'type': 'codex', 'thread_id': THREAD_ID, 'codex_path': str(fake),
                  'codex_remote': None, 'codex_home': None},
    }
    configs = {}
    for kind, adapter in adapters.items():
        participant = fixture.participants[kind]
        token_file, config_file = root / (kind + '-token'), root / (kind + '-config.json')
        private_write(token_file, participant['bridge_token'])
        private_write(config_file, json.dumps({'config_version': 2, 'base_url': fixture.url,
            'token_file': str(token_file), 'state_dir': str(root / (kind + '-state')),
            'space_id': fixture.space['space_id'], 'actor_id': participant['actor'],
            'consumer_id': participant['consumer'], 'wake_adapter': adapter}))
        configs[kind] = config_file
    return configs, queue_log


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parent.parent
    parser.add_argument('--server-binary', type=Path, default=repo / 'target/debug/waypost')
    parser.add_argument('--bridge-binary', type=Path, default=repo / 'bridge/target/debug/waypost-bridge')
    args = parser.parse_args()
    args.server_binary, args.bridge_binary = args.server_binary.resolve(), args.bridge_binary.resolve()
    try:
        check(args.server_binary.is_file() and args.bridge_binary.is_file(), 'build both native binaries first')
        print(json.dumps(run(args), indent=2))
    except Exception as error:
        print(json.dumps({'result': 'failed', 'reason': str(error) if isinstance(error, Failure)
                          else type(error).__name__}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
