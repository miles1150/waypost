"""Legacy public metadata import preserves policy and never revives disabled IDs."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('legacy_import', ROOT / 'scripts/import_legacy_oauth_clients.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LegacyClientImport(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        for migration in sorted((ROOT / 'migrations').glob('*.sql')):
            self.db.executescript(migration.read_text())
        self.config = {'clients': [
            {'client_id': 'codex-personal', 'name': "Owner's Codex", 'redirect_uris': ['http://127.0.0.1:8765/callback/existing'], 'allow_loopback_port_variation': True},
            {'client_id': 'claude-personal', 'name': 'Claude', 'redirect_uris': ['http://localhost:8766/callback'], 'allow_loopback_port_variation': False},
        ]}

    def tearDown(self):
        self.db.close()

    def test_preserves_revision_and_exact_policy_idempotently(self):
        sql = module.generate(self.config, 123)
        self.db.executescript(sql)
        before = self.db.execute('SELECT * FROM oauth_dynamic_clients ORDER BY client_id').fetchall()
        self.db.executescript(module.generate(self.config, 456))
        self.assertEqual(before, self.db.execute('SELECT * FROM oauth_dynamic_clients ORDER BY client_id').fetchall())
        rows = self.db.execute('SELECT client_id,source,revision,allow_loopback_port_variation,metadata_json FROM oauth_dynamic_clients ORDER BY client_id').fetchall()
        self.assertEqual([('claude-personal', 'legacy', 0, 0), ('codex-personal', 'legacy', 0, 1)], [row[:4] for row in rows])
        self.assertEqual("Owner's Codex", json.loads(rows[1][4])['client_name'])
        self.assertEqual([], self.db.execute('PRAGMA foreign_key_check').fetchall())

    def test_never_overwrites_conflicting_or_disabled_clients(self):
        self.db.executescript(module.generate(self.config, 123))
        self.db.execute("UPDATE oauth_dynamic_clients SET disabled=1, revision=7 WHERE client_id='codex-personal'")
        self.config['clients'][0]['redirect_uris'] = ['https://changed.example/callback']
        self.db.executescript(module.generate(self.config, 456))
        row = self.db.execute("SELECT disabled,revision,metadata_json FROM oauth_dynamic_clients WHERE client_id='codex-personal'").fetchone()
        self.assertEqual((1, 7), row[:2])
        self.assertEqual(['http://127.0.0.1:8765/callback/existing'], json.loads(row[2])['redirect_uris'])

    def test_rejects_noncanonical_legacy_redirects(self):
        for uri in ['https://example.com/cb?', 'https://example.com/cb#', 'https://example.com' + chr(92) + 'path/cb', 'https://EXAMPLE.com/cb', 'https://example.com:443/cb', 'https://example.com/a/%2e%2e/cb']:
            config = json.loads(json.dumps(self.config))
            config['clients'][0]['redirect_uris'] = [uri]
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                module.generate(config, 123)

    def test_rejects_credentials_and_unsafe_redirect_without_partial_sql(self):
        for key, value in [('client_secret', 'synthetic-not-a-secret'), ('redirect_uris', ['http://internal.example/callback']), ('allow_loopback_port_variation', 1)]:
            config = json.loads(json.dumps(self.config))
            config['clients'][1][key] = value
            with self.assertRaises(ValueError):
                module.generate(config, 123)
        self.assertEqual(0, self.db.execute('SELECT count(*) FROM oauth_dynamic_clients').fetchone()[0])


if __name__ == '__main__':
    unittest.main()
