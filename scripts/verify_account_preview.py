#!/usr/bin/env python3
"""Synthetic local Workerd acceptance; NEVER targets production.

Run from repository root against 127.0.0.1:8793 after applying migrations and
loading tests/fixtures/account-preview-seed.sql into an isolated local D1.
Configure only the public test OIDC key (see fixture README); no real IdP call.
The account session is deliberately synthetic. Private output stays in /tmp.
"""
import urllib.request,urllib.error,json,hashlib,base64,secrets,subprocess,tempfile
from pathlib import Path
base='http://127.0.0.1:8793';cookie='waypost_account='+'c'*43
csrf=None

def call(path,body=None,owner=False,token=None):
 headers={'Content-Type':'application/json'}
 if owner:
  headers.update({'Cookie':cookie,'Origin':base})
  if csrf:headers['X-Waypost-CSRF']=csrf
 if token:headers['Authorization']='Bearer '+token
 req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers=headers)
 with urllib.request.urlopen(req,timeout=20) as r:
  value=json.load(r);assert value['ok'],value
  return value['data']
csrf=call('/account/session',owner=True)['csrf_token']
verifier=secrets.token_urlsafe(32)
challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
pair=call('/account/devices/start',{'display_name':'Isolated Workerd acceptance','code_challenge':challenge,'code_challenge_method':'S256'})
info=call('/account/devices/inspect',{'user_code':pair['user_code']},owner=True);assert info['space_id']=='space_test'
call('/account/devices/approve',{'user_code':pair['user_code'],'actor_id':'actor_test','consumer_id':'consumer_test'},owner=True)
cred=call('/account/devices/token',{'device_code':pair['device_code'],'code_verifier':verifier});token=cred['token']
assert call('/v0/describe',token=token)['actor_id']=='actor_test'
marker=secrets.token_hex(8)
sent=call('/v0/messages',{'request_id':'account-test-'+marker,'recipient_ids':['actor_test'],'kind':'info','subject':'Isolated acceptance','body':{'text':'Synthetic harmless message'}},token=token)
page=call('/v0/inbox/read',{'consumer_id':'consumer_test'},token=token)
item=next(i for i in page['items'] if i['resource_id']==sent['message_id'])
content=call('/v0/messages/'+sent['message_id'],token=token)
p=Path(tempfile.mkdtemp(prefix='waypost-account-smoke-'))
(p/'saved-message.json').write_text(json.dumps(content));(p/'saved-message.json').chmod(0o600)
for stage in ['received','processed']:
 call('/v0/receipts',{'request_id':stage+'-'+marker,'consumer_id':'consumer_test','items':[{'item_id':item['item_id'],'stage':stage}]},token=token)
(p/'token').write_text(token);(p/'token').chmod(0o600)
config={'version':1,'base_url':base,'token_file':str(p/'token'),'space_id':'space_test','actor_id':'actor_test','consumer_id':'consumer_test','device_id':pair['device_id'],'token_id':cred['token_id'],'allow_loopback':True}
(p/'config.json').write_text(json.dumps(config));(p/'config.json').chmod(0o600)
request={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'waypost_describe','arguments':{}}}
r=subprocess.run(['python','plugins/waypost/client.py','serve','--config',str(p/'config.json')],input=json.dumps(request)+'\n',capture_output=True,text=True,timeout=20)
assert r.returncode==0
answer=json.loads(r.stdout);assert 'result' in answer and not answer['result'].get('isError'),answer
assert token not in r.stdout+r.stderr
call('/account/devices/revoke',{'device_id':pair['device_id']},owner=True)
try:call('/v0/describe',token=token);raise AssertionError('revoked token accepted')
except urllib.error.HTTPError as e:assert e.code==401
print(json.dumps({'result':'passed','runtime':'actual local Workerd, D1 and R2','identity':'seeded synthetic account session, not real OIDC login','checks':['account session','device inspect and approval','S256 one-time redemption','authenticated describe','message send/read','received and processed ACK','actual local plugin stdio to MCP','device revoke rejects token']}))
