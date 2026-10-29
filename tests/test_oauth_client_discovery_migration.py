"""Migration 0015 preserves populated legacy data; it grants no new authority."""
from pathlib import Path
import sqlite3
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ClientDiscoveryMigration(unittest.TestCase):
    def test_populated_legacy_oauth_and_agent_records_survive(self):
        db = sqlite3.connect(':memory:')
        try:
            db.execute('PRAGMA foreign_keys=ON')
            migrations = sorted((ROOT / 'migrations').glob('*.sql'))
            target = next(path for path in migrations if path.name.startswith('0015_'))
            for path in migrations:
                if path == target:
                    break
                db.executescript(path.read_text())
            db.executescript("""
BEGIN;
INSERT INTO spaces(space_id,display_name,source_uri,default_actor_id,default_consumer_id,created_at) VALUES('space_old','Historical','urn:test:old','actor_old','consumer_old',1);
INSERT INTO actors(space_id,actor_id,display_name,kind,created_at) VALUES('space_old','actor_old','Old','agent',1);
INSERT INTO consumers(space_id,consumer_id,actor_id,view,created_at) VALUES('space_old','consumer_old','actor_old','inbox',1);
INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_old','https://issuer.example','old',1);
INSERT INTO account_spaces VALUES('space_old','account_old',1);
INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at) VALUES('token_legacy',zeroblob(32),'space_old','actor_old','consumer_old',1);
INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at,credential_kind,expires_at) VALUES('token_oauth',randomblob(32),'space_old','actor_old','consumer_old',1,'oauth',9000000000000);
INSERT INTO oauth_requests(request_id,kind,client_id,resource,scope,code_challenge,code_digest,status,created_at,expires_at,next_poll_at,account_id,space_id,actor_id,consumer_id,approved_at,family_id)
VALUES('request_old','code','registered-old','https://service.example/mcp','waypost','challenge',randomblob(32),'consumed',1,9000000000000,1,'account_old','space_old','actor_old','consumer_old',1,'family_old');
INSERT INTO oauth_families(family_id,client_id,resource,scope,account_id,space_id,actor_id,consumer_id,created_at,expires_at)
VALUES('family_old','registered-old','https://service.example/mcp','waypost','account_old','space_old','actor_old','consumer_old',1,9000000000000);
INSERT INTO oauth_access_tokens VALUES('token_oauth','family_old');
INSERT INTO oauth_refresh_tokens(token_digest,family_id,expires_at,used_at,redeem_nonce) VALUES(randomblob(32),'family_old',9000000000000,2,'historical-replay-marker');
COMMIT;
""")
            tables = ['spaces', 'actors', 'consumers', 'accounts', 'account_spaces', 'tokens',
                      'oauth_requests', 'oauth_families', 'oauth_access_tokens', 'oauth_refresh_tokens']
            before = {}
            for table in tables:
                columns = [row[1] for row in db.execute(f'PRAGMA table_info({table})')]
                before[table] = (columns, db.execute(f'SELECT {",".join(columns)} FROM {table} ORDER BY rowid').fetchall())
            db.executescript(target.read_text())
            for table, (columns, rows) in before.items():
                self.assertEqual(db.execute(f'SELECT {",".join(columns)} FROM {table} ORDER BY rowid').fetchall(), rows, table)
            self.assertEqual(db.execute('SELECT client_revision FROM oauth_requests').fetchall(), [(0,)])
            self.assertEqual(db.execute('SELECT client_revision FROM oauth_families').fetchall(), [(0,)])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM oauth_dynamic_clients').fetchone()[0], 0)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
        finally:
            db.close()


if __name__ == '__main__':
    unittest.main()
