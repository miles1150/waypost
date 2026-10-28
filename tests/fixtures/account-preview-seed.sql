-- SYNTHETIC LOCAL-ONLY fixture. Never apply to a real deployment.
PRAGMA defer_foreign_keys=ON;
INSERT INTO spaces(space_id,display_name,source_uri,default_actor_id,default_consumer_id,created_at) VALUES('space_test','Local test','urn:test:account','actor_test','consumer_test',0);
INSERT INTO actors(space_id,actor_id,display_name,kind,created_at) VALUES('space_test','actor_test','Test','agent',0);
INSERT INTO consumers(space_id,consumer_id,actor_id,view,created_at) VALUES('space_test','consumer_test','actor_test','inbox',0);
INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_test','https://issuer.example','fixture',0);
INSERT INTO account_spaces VALUES('space_test','account_test',0);
INSERT INTO account_sessions VALUES(X'0c49d89230696ff3c031ca5a128a4e121e3589bf872c17fa04487ed0cc245d21','account_test','space_test',CAST(strftime('%s','now') AS INTEGER)*1000,CAST(strftime('%s','now') AS INTEGER)*1000+3600000);
