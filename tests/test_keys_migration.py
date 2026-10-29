"""Upgrade from the established OAuth registry without replacing its data."""
import json
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class KeysMigration(unittest.TestCase):
    def test_upgrade_retains_registered_client_and_existing_account(self):
        db = sqlite3.connect(":memory:")
        db.execute("PRAGMA foreign_keys=ON")
        migrations = sorted((ROOT / "migrations").glob("*.sql"))
        old = [path for path in migrations if path.name < "0016_keys.sql"]
        for path in old:
            db.executescript(path.read_text())
        db.execute("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('owner','https://issuer.example','owner',1)")
        metadata = json.dumps({"client_id":"dcr_old","client_name":"existing","redirect_uris":["https://example.com/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"waypost"})
        db.execute("INSERT INTO oauth_dynamic_clients(client_id,source,metadata_json,security_fingerprint,revision,valid_until,created_at,updated_at) VALUES('dcr_old','dcr',?,'fingerprint',7,999999,1,1)", (metadata,))
        db.commit()
        db.executescript((ROOT / "migrations/0016_keys.sql").read_text())
        self.assertEqual(db.execute("SELECT subject FROM accounts WHERE account_id='owner'").fetchone(), ("owner",))
        self.assertEqual(db.execute("SELECT revision,metadata_json FROM oauth_dynamic_clients WHERE client_id='dcr_old'").fetchone(), (7, metadata))
        self.assertEqual(db.execute("SELECT count(*) FROM key_entries").fetchone(), (0,))
        self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])


if __name__ == "__main__":
    unittest.main()
