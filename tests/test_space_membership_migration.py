"""Upgrade a populated schema-11 database without changing identity or durable history."""
from pathlib import Path
import sqlite3
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MembershipMigrationTests(unittest.TestCase):
    def test_old_identity_and_history_survive_removed_grants(self):
        db = sqlite3.connect(':memory:')
        db.execute('PRAGMA foreign_keys=ON')
        for migration in sorted((ROOT / 'migrations').glob('*.sql')):
            if migration.name.startswith('0012_'):
                break
            db.executescript(migration.read_text())
        db.execute('BEGIN')
        db.execute("INSERT INTO spaces(space_id,display_name,source_uri,default_actor_id,default_consumer_id,created_at) VALUES('s','test','test:space','a','c',1)")
        db.execute("INSERT INTO actors(space_id,actor_id,display_name,kind,created_at) VALUES('s','a','owner','user',1)")
        db.execute("INSERT INTO consumers(space_id,consumer_id,actor_id,view,created_at) VALUES('s','c','a','inbox',1)")
        for i, revoked in enumerate((None, 77)):
            db.execute("INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,expires_at,revoked_at,created_at,default_recipient_id) VALUES(?,?,'s','a','c',999,?,1,'a')", (f't{i}', bytes([i]) * 32, revoked))
            db.execute("INSERT INTO token_scopes VALUES(?,'message.send')", (f't{i}',))
            db.execute("INSERT INTO token_recipients VALUES(?,'s','a')", (f't{i}',))
        db.execute("INSERT INTO memory_collections VALUES('s','col','a','shared','materials',0,1)")
        db.execute("INSERT INTO token_collections VALUES('t0','s','col','read')")
        db.execute("INSERT INTO blobs VALUES('s','blob','a','object','text/plain',0,?,NULL,1)", (bytes(32),))
        db.execute("INSERT INTO token_blob_grants VALUES('t0','s','blob')")
        db.execute("INSERT INTO token_permission_changes VALUES('audit','s','t0','edit','fp',1,'operator','{}','{}',1)")
        db.execute("INSERT INTO threads VALUES('s','thread',1)")
        db.execute("INSERT INTO thread_members VALUES('s','thread','a')")
        db.execute("INSERT INTO submissions(submission_id,space_id,producer_id,operation,request_id,fingerprint,resource_id,thread_id,state,created_at) VALUES('submission','s','a','message.send','send',?,'message','thread','committed',1)", (bytes(32),))
        db.execute("INSERT INTO messages VALUES('s','message','submission','a','thread',NULL,'info','subject','body-ref',1)")
        db.execute("INSERT INTO message_recipients VALUES('s','message','a')")
        db.execute("INSERT INTO feed_items(item_id,space_id,item_type,resource_id,resource_version,producer_id,committed_at) VALUES('item','s','message','message',1,'a',1)")
        db.execute("INSERT INTO feed_recipients VALUES('s','item','a')")
        db.execute("INSERT INTO receipts VALUES('s','receipt','c','item',2,1,1,'ack')")
        db.execute("INSERT INTO consumer_checkpoints VALUES('s','c',1,'old-fingerprint',1,1)")
        db.commit()
        preserved = ('spaces', 'actors', 'consumers', 'tokens', 'memory_collections', 'blobs',
                     'threads', 'thread_members', 'submissions', 'messages', 'message_recipients',
                     'feed_items', 'feed_recipients', 'receipts', 'consumer_checkpoints', 'token_permission_changes')
        before = {t: db.execute(f'SELECT * FROM {t}').fetchall() for t in preserved}
        db.executescript((ROOT / 'migrations/0012_space_membership.sql').read_text())
        for table in preserved:
            self.assertEqual(before[table], db.execute(f'SELECT * FROM {table}').fetchall(), table)
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertFalse(tables & {'token_scopes', 'token_recipients', 'token_collections', 'token_blob_grants'})
        self.assertIn('token_routing_changes', tables)
        self.assertEqual([], db.execute('PRAGMA foreign_key_check').fetchall())
        db.close()


if __name__ == '__main__':
    unittest.main()
