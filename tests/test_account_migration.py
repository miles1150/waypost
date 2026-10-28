"""Additive migration preserves populated identities and legacy recovery material."""
import sqlite3
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

class AccountMigration(unittest.TestCase):
    def test_schema_12_upgrade_preserves_all_existing_rows_and_restore(self):
        db = sqlite3.connect(':memory:')
        db.execute('PRAGMA foreign_keys=ON')
        for path in sorted((ROOT/'migrations').glob('*.sql')):
            if path.name.startswith('0013_'):
                break
            db.executescript(path.read_text())
        db.executescript("""
        BEGIN;
        INSERT INTO spaces(space_id,display_name,source_uri,default_actor_id,default_consumer_id,created_at) VALUES('s','Personal','urn:test:s','a','c',1);
        INSERT INTO actors(space_id,actor_id,display_name,kind,created_at) VALUES('s','a','Owner','user',1);
        INSERT INTO consumers(space_id,consumer_id,actor_id,view,created_at) VALUES('s','c','a','inbox',1);
        INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,expires_at,created_at) VALUES('t',zeroblob(32),'s','a','c',12345,1);
        INSERT INTO space_admin_credentials VALUES('s',zeroblob(32),3,NULL,1);
        INSERT INTO space_invitations(invitation_id,space_id,token_digest,owner_version,state,created_at,expires_at) VALUES('i','s',zeroblob(32),3,'revoked',1,2);
        INSERT INTO threads VALUES('s','thread',1);
        INSERT INTO submissions(submission_id,space_id,producer_id,operation,request_id,fingerprint,resource_id,state,created_at)
          VALUES('committed','s','a','message.send','sent',zeroblob(32),'message','committed',1),
                ('pending','s','a','message.send','pending',zeroblob(32),'pending-message','prepared',1);
        INSERT INTO messages(space_id,message_id,submission_id,producer_id,thread_id,kind,subject,body_ref,committed_at)
          VALUES('s','message','committed','a','thread','info','Synthetic history','synthetic-body-reference',1);
        INSERT INTO feed_items(item_id,space_id,item_type,resource_id,resource_version,producer_id,thread_id,committed_at)
          VALUES('item','s','message','message',1,'a','thread',1);
        INSERT INTO receipts VALUES('s','receipt','c','item',1,1,1,'committed');
        COMMIT;
        """)
        tables=[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        before={t:db.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables}
        backup='\n'.join(db.iterdump())
        db.executescript((ROOT/'migrations/0013_personal_accounts.sql').read_text())
        self.assertEqual(before,{t:db.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables})
        self.assertEqual([],db.execute('PRAGMA foreign_key_check').fetchall())
        restored=sqlite3.connect(':memory:');restored.executescript(backup)
        self.assertEqual(before,{t:restored.execute(f'SELECT * FROM "{t}"').fetchall() for t in tables})
        db.executescript("""
        INSERT INTO accounts VALUES('account','https://issuer.example','sub',1,0);
        INSERT INTO account_spaces VALUES('s','account',0);
        INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at)
          VALUES('paired',X'0101010101010101010101010101010101010101010101010101010101010101','s','a','c',0);
        INSERT INTO account_devices(device_id,device_digest,user_digest,code_challenge,display_name,state,created_at,expires_at,next_poll_at,account_id,space_id,actor_id,consumer_id,token_id)
          VALUES('d',zeroblob(32),zeroblob(32),'test','Device','consumed',0,1,0,'account','s','a','c','paired');
        """)
        db.executescript('BEGIN;\n'+(ROOT/'scripts/account-rollback-revoke.sql').read_text()+'\nCOMMIT;')
        self.assertIsNotNone(db.execute("SELECT revoked_at FROM tokens WHERE token_id='paired'").fetchone()[0])
        self.assertIsNone(db.execute("SELECT revoked_at FROM tokens WHERE token_id='t'").fetchone()[0])
        self.assertEqual('revoked',db.execute("SELECT state FROM account_devices WHERE device_id='d'").fetchone()[0])
        self.assertEqual(1,db.execute('SELECT count(*) FROM account_spaces').fetchone()[0])
        db.close();restored.close()
