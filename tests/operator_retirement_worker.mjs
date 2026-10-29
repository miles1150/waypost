// Actual compiled Worker with isolated Miniflare D1/R2 and synthetic identities.
// No external provider login, production credential or production state is used.
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {createPrivateKey,createPublicKey,createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {Miniflare,Log,LogLevel} from '../examples/mcp-client/node_modules/miniflare/dist/src/index.js';

const root=fileURLToPath(new URL('../',import.meta.url)),origin='http://127.0.0.1:8793';
const secret=()=>randomBytes(32).toString('base64url');
const oldOperator=secret(),operatorCookie=secret(),ownerCookie=secret(),accountCookie=secret(),otherCookie=secret(),ownerKey=secret();
const tokens={keep:secret(),revoke:secret(),other:secret(),foreign:secret(),oauth:secret(),oauth_other:secret()};
const digest=value=>createHash('sha256').update(value).digest();
const key=createPublicKey(createPrivateKey(await readFile(new URL('fixtures/oidc-test-private.pem',import.meta.url)))).export({format:'jwk'});
const statements=JSON.parse(execFileSync('python3',['-c',`
import json,pathlib,sqlite3,sys
out=[]
for path in sorted(pathlib.Path(sys.argv[1]).glob('*.sql')):
 pending=''
 for line in path.read_text().splitlines(True):
  pending+=line
  if sqlite3.complete_statement(pending):out.append(pending);pending=''
 if pending.strip() and not all(not l.strip() or l.lstrip().startswith('--') for l in pending.splitlines()):raise ValueError('Incomplete migration')
print(json.dumps(out))
`,root+'migrations'],{encoding:'utf8'}));
const bindings={PUBLIC_ORIGIN:origin,WAYPOST_OPERATOR_MODE:'disabled',WAYPOST_CSRF_SECRET:secret(),WAYPOST_CURSOR_SECRET:secret(),WAYPOST_ACCOUNT_SIGNUP_LIMIT:'0',WAYPOST_ONBOARDING_MODE:'accounts',
  WAYPOST_ENCRYPTION_KEYS:JSON.stringify({active:'test',keys:{test:randomBytes(32).toString('hex')}}),
  WAYPOST_OIDC_CONFIG:JSON.stringify({issuer:'https://issuer.example',client_id:'test-client',authorization_endpoint:'https://issuer.example/authorize',token_endpoint:'https://issuer.example/token',keys:[{kid:'test',n:key.n,e:key.e}]}),
  WAYPOST_OAUTH_CLIENT_DISCOVERY:JSON.stringify({dynamic_registration:true})};
let unexpectedOutbound=0,phase='setup';
const options={modules:true,scriptPath:root+'build/index.js',modulesRules:[{type:'CompiledWasm',include:['**/*.wasm'],fallthrough:true}],compatibilityDate:'2026-07-17',log:new Log(LogLevel.NONE),d1Databases:{DB:'operator-retirement-local'},r2Buckets:['OBJECTS'],bindings,outboundService:()=>{unexpectedOutbound++;throw new Error('External network forbidden');}};
const mf=new Miniflare(options);
async function response(path,{method='GET',body,headers={}}={}) {
  const r=await mf.dispatchFetch(origin+path,{method,redirect:'manual',headers:{'content-type':'application/json',...headers},...(body===undefined?{}:{body:JSON.stringify(body)})});
  const raw=await r.text();return {status:r.status,headers:r.headers,value:raw?JSON.parse(raw):null};
}
function ok(r){assert.equal(r.status,200);assert.equal(r.value.ok,true);return r.value.data;}
function denied(r){assert([401,403,404].includes(r.status));}
let csrf='';
async function account(path,body={},cookie=accountCookie){if(['/account/connections/revoke','/account/oauth/revoke','/account/identities/disable','/account/primary/set'].includes(path))body={space_id:'space_a',...body};return response(path,{method:'POST',body,headers:{origin,cookie:'waypost_account='+cookie,'x-waypost-csrf':csrf}});}
const agent=(path,body,token=tokens.keep)=>response(path,{method:body===undefined?'GET':'POST',body,headers:{authorization:'Bearer '+token}});
try {
  for(const invalid of ['missing OIDC','missing CSRF','missing cursor','reused independent keys','enabled without admin','legacy static client variable']) {
    phase='reject configuration: '+invalid;
    const invalidBindings={...bindings};
    if(invalid==='missing OIDC'){delete invalidBindings.WAYPOST_OIDC_CONFIG;delete invalidBindings.WAYPOST_OAUTH_CLIENT_DISCOVERY;delete invalidBindings.WAYPOST_ONBOARDING_MODE;}
    if(invalid==='missing CSRF')delete invalidBindings.WAYPOST_CSRF_SECRET;
    if(invalid==='missing cursor')delete invalidBindings.WAYPOST_CURSOR_SECRET;
    if(invalid==='reused independent keys')invalidBindings.WAYPOST_CURSOR_SECRET=invalidBindings.WAYPOST_CSRF_SECRET;
    if(invalid==='enabled without admin')invalidBindings.WAYPOST_OPERATOR_MODE='enabled';
    if(invalid==='legacy static client variable')invalidBindings.WAYPOST_OAUTH_CLIENTS=JSON.stringify({clients:[]});
    const rejected=new Miniflare({...options,bindings:invalidBindings});
    try {const r=await rejected.dispatchFetch(origin+'/health');assert([500,503].includes(r.status));await r.text();}
    finally {await rejected.dispose();}
  }
  phase='schema and historical fixtures';
  let db=await mf.getD1Database('DB');
  for(const sql of statements)await db.prepare(sql).run();
  await db.prepare('CREATE TABLE d1_migrations(name TEXT PRIMARY KEY)').run();
  for(const name of await readdir(root+'migrations'))if(name.endsWith('.sql'))await db.prepare('INSERT INTO d1_migrations(name) VALUES(?)').bind(name).run();
  const registration=await response('/oauth/register',{method:'POST',body:{client_name:'Operator retirement fixture',redirect_uris:['http://127.0.0.1:8765/callback'],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code'],scope:'waypost'}});
  assert.equal(registration.status,201);const dynamicClient=registration.value.client_id;
  const now=Date.now();
  await db.batch([
    db.prepare("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_a','https://issuer.example','synthetic-a',?),('account_b','https://issuer.example','synthetic-b',?)").bind(now,now),
    ...['a','other','foreign'].flatMap(label=>[
      db.prepare('INSERT INTO spaces(space_id,display_name,source_uri,default_actor_id,default_consumer_id,created_at) VALUES(?,?,?,?,?,?)').bind('space_'+label,label,'urn:test:'+label,'actor_'+label,'consumer_'+label,now),
      db.prepare("INSERT INTO actors(space_id,actor_id,display_name,kind,created_at) VALUES(?,?,?,'agent',?)").bind('space_'+label,'actor_'+label,label,now),
      db.prepare("INSERT INTO consumers(space_id,consumer_id,actor_id,view,created_at) VALUES(?,?,?,'inbox',?)").bind('space_'+label,'consumer_'+label,'actor_'+label,now),
      db.prepare('INSERT INTO account_spaces(space_id,account_id,created_at) VALUES(?,?,?)').bind('space_'+label,label==='foreign'?'account_b':'account_a',now),
    ]),
    db.prepare("INSERT INTO account_sessions(session_digest,account_id,selected_space_id,created_at,expires_at) VALUES(?,'account_a','space_a',?,?),(?,'account_b','space_foreign',?,?)").bind(digest(accountCookie),now,now+3600000,digest(otherCookie),now,now+3600000),
    db.prepare('INSERT INTO admin_sessions(session_digest,admin_fingerprint,created_at,expires_at,space_id) VALUES(?,?,?,?,NULL)').bind(digest(operatorCookie),digest(oldOperator),now,now+3600000),
    db.prepare("INSERT INTO admin_sessions(session_digest,admin_fingerprint,created_at,expires_at,space_id) VALUES(?,?,?,?,'space_a')").bind(digest(ownerCookie),digest(ownerKey),now,now+3600000),
    db.prepare("INSERT INTO space_admin_credentials(space_id,credential_digest,version,created_at) VALUES('space_a',?,1,?)").bind(digest(ownerKey),now),
    ...Object.entries(tokens).map(([name,token])=>{
      const label=name==='foreign'?'foreign':name.endsWith('other')?'other':'a';
      return db.prepare('INSERT INTO tokens(token_id,token_digest,space_id,actor_id,consumer_id,created_at,credential_kind,expires_at) VALUES(?,?,?,?,?,?,?,?)').bind('token_'+name,digest(token),'space_'+label,'actor_'+label,'consumer_'+label,now,name.startsWith('oauth')?'oauth':'legacy',now+300000);
    }),
    ...['a','other'].flatMap(label=>[
      db.prepare("INSERT INTO oauth_families(family_id,client_id,resource,scope,account_id,space_id,actor_id,consumer_id,created_at,expires_at,client_revision) VALUES(?,?,?,'waypost','account_a',?,?,?,?,?,1)").bind('family_'+label,dynamicClient,origin+'/mcp','space_'+label,'actor_'+label,'consumer_'+label,now,now+3600000),
      db.prepare('INSERT INTO oauth_access_tokens(token_id,family_id) VALUES(?,?)').bind(label==='a'?'token_oauth':'token_oauth_other','family_'+label),
    ]),
  ]);
  phase='disabled runtime without admin secret';
  ok(await response('/health'));
  const onboarding=ok(await response('/onboarding'));assert.equal(onboarding.accounts_enabled,true);assert.equal(onboarding.invitations_enabled,false);
  // Retain the old key as well: disabling must gate authority, not merely lose a key.
  await mf.setOptions({...options,bindings:{...bindings,WAYPOST_ADMIN_SECRET:oldOperator}});
  db=await mf.getD1Database('DB');
  ok(await response('/health'));
  denied(await response('/ready',{headers:{authorization:'Bearer '+oldOperator}}));
  denied(await response('/admin/session',{method:'POST',body:{admin_secret:oldOperator},headers:{origin}}));
  denied(await response('/admin/session',{headers:{cookie:'waypost_admin='+operatorCookie}}));
  denied(await response('/admin/v0/spaces',{method:'POST',body:{request_id:'forbidden',display_name:'forbidden'},headers:{authorization:'Bearer '+oldOperator}}));
  phase='legacy agent data compatibility';
  ok(await agent('/v0/describe'));ok(await agent('/v0/describe',undefined,tokens.oauth));
  const message=ok(await agent('/v0/messages',{request_id:'retired-operator-message',kind:'info',subject:'Synthetic local message',body:{text:'Legacy agent remains usable.'}}));
  ok(await agent('/v0/messages/'+message.message_id));
  const session=ok(await response('/account/session',{headers:{cookie:'waypost_account='+accountCookie}}));csrf=session.csrf_token;
  ok(await response('/ready',{headers:{cookie:'waypost_account='+accountCookie}}));
  ok(await response('/ready',{headers:{authorization:'Bearer '+ownerKey}}));
  phase='Dashboard account-cookie session bootstrap';
  const dashboardCookie={cookie:'waypost_account='+accountCookie};
  const dashboardSession=ok(await response('/admin/session',{headers:dashboardCookie}));
  assert.equal(dashboardSession.operator,false);assert.equal(dashboardSession.space_id,'space_a');
  const dashboardHeaders={...dashboardCookie,origin,'x-waypost-csrf':dashboardSession.csrf_token};
  phase='Dashboard registry spaces and actors';
  const visibleSpaces=ok(await response('/admin/v0/registry',{method:'POST',body:{kind:'spaces',limit:20,cursor:null},headers:dashboardHeaders}));
  assert.deepEqual(visibleSpaces.items.map(item=>item.space_id),['space_a']);
  const visibleActors=ok(await response('/admin/v0/registry',{method:'POST',body:{kind:'actors',space_id:'space_a',limit:20,cursor:null},headers:dashboardHeaders}));
  assert(visibleActors.items.some(item=>item.actor_id==='actor_a'));
  phase='Dashboard primary assistant and inbox';
  ok(await response('/admin/v0/spaces/space_a/primary-assistant',{headers:dashboardCookie}));
  const inbox=ok(await response('/admin/v0/spaces/space_a/inspect',{method:'POST',body:{kind:'inbox',limit:20,cursor:null},headers:dashboardHeaders}));
  assert(inbox.items.some(item=>item.message_id===message.message_id));
  phase='Dashboard memory read';
  await db.prepare("INSERT INTO memory_collections(space_id,collection_id,source_actor_id,scope,display_name,created_at) VALUES('space_a','collection_dashboard','actor_a','shared','Dashboard fixture',?)").bind(now).run();
  const collections=ok(await response('/admin/v0/spaces/space_a/inspect',{method:'POST',body:{kind:'collections',limit:20,cursor:null},headers:dashboardHeaders}));
  assert(collections.items.some(item=>item.collection_id==='collection_dashboard'));
  const memory=ok(await response('/admin/v0/spaces/space_a/memory/collection_dashboard/read',{method:'POST',body:{limit:20},headers:dashboardHeaders}));
  assert.equal(memory.collection_id,'collection_dashboard');assert.deepEqual(memory.items,[]);
  phase='Dashboard CSRF and cross-space boundaries';
  for(const path of ['/admin/v0/registry','/admin/v0/spaces/space_a/inspect','/admin/v0/spaces/space_a/memory/collection_dashboard/read']) {
    const body=path.endsWith('/registry')?{kind:'spaces'}:path.endsWith('/inspect')?{kind:'inbox'}:{};
    for(const headers of [{...dashboardCookie,origin},{...dashboardCookie,origin,'x-waypost-csrf':'incorrect'}])assert.equal((await response(path,{method:'POST',body,headers})).status,403);
  }
  for(const target of ['other','foreign']) {
    assert.equal((await response('/admin/v0/registry',{method:'POST',body:{kind:'actors',space_id:'space_'+target},headers:dashboardHeaders})).status,404);
    assert.equal((await response('/admin/v0/spaces/space_'+target+'/primary-assistant',{headers:dashboardCookie})).status,404);
    assert.equal((await response('/admin/v0/spaces/space_'+target+'/inspect',{method:'POST',body:{kind:'inbox'},headers:dashboardHeaders})).status,404);
    assert.equal((await response('/admin/v0/spaces/space_'+target+'/memory/collection_dashboard/read',{method:'POST',body:{},headers:dashboardHeaders})).status,404);
  }
  phase='Dashboard explicit account mode with legacy cookie coexistence';
  const mixedCookies='waypost_account='+accountCookie+'; waypost_admin='+operatorCookie;
  // Existing implicit mode retains legacy precedence, reproducing the old-session
  // collision that previously sent a logged-in account owner back to key login.
  assert.equal((await response('/admin/session',{headers:{cookie:mixedCookies}})).status,401);
  const legacyOwner=ok(await response('/admin/session',{headers:{cookie:'waypost_admin='+ownerCookie}}));
  assert.equal(legacyOwner.space_id,'space_a');
  const explicitAccountHeaders={cookie:mixedCookies,'x-waypost-auth':'account'};
  const explicitAccount=ok(await response('/admin/session',{headers:explicitAccountHeaders}));
  assert.equal(explicitAccount.account_id,'account_a');assert.equal(explicitAccount.space_id,'space_a');
  const explicitWrites={...explicitAccountHeaders,origin,'x-waypost-csrf':explicitAccount.csrf_token};
  const explicitSpaces=ok(await response('/admin/v0/registry',{method:'POST',body:{kind:'spaces'},headers:explicitWrites}));
  assert.deepEqual(explicitSpaces.items.map(item=>item.space_id),['space_a']);
  ok(await response('/admin/v0/registry',{method:'POST',body:{kind:'actors',space_id:'space_a'},headers:explicitWrites}));
  ok(await response('/admin/v0/spaces/space_a/primary-assistant',{headers:explicitAccountHeaders}));
  const explicitInbox=ok(await response('/admin/v0/spaces/space_a/inspect',{method:'POST',body:{kind:'inbox'},headers:explicitWrites}));
  assert(explicitInbox.items.some(item=>item.message_id===message.message_id));
  ok(await response('/admin/v0/spaces/space_a/memory/collection_dashboard/read',{method:'POST',body:{},headers:explicitWrites}));
  const invalidAccount={cookie:'waypost_account='+secret()+'; waypost_admin='+ownerCookie,'x-waypost-auth':'account'};
  assert.equal((await response('/admin/session',{headers:invalidAccount})).status,401);
  // The valid legacy session's CSRF must not authenticate an account-mode POST.
  const invalidWrites={...invalidAccount,origin,'x-waypost-csrf':legacyOwner.csrf_token};
  assert.equal((await response('/admin/v0/registry',{method:'POST',body:{kind:'spaces'},headers:invalidWrites})).status,403);
  assert.equal((await response('/admin/v0/spaces/space_a/memory/collection_dashboard/read',{method:'POST',body:{},headers:invalidWrites})).status,403);
  const conflictingBearer=await response('/admin/session',{headers:{'x-waypost-auth':'account',authorization:'Bearer '+ownerKey}});
  assert.equal(conflictingBearer.status,400);assert.equal(conflictingBearer.value.error.code,'INVALID_ARGUMENT');
  for(const headers of [{...explicitAccountHeaders,origin},{...explicitAccountHeaders,origin,'x-waypost-csrf':'wrong'}])assert.equal((await response('/admin/v0/registry',{method:'POST',body:{kind:'spaces'},headers})).status,403);
  assert.equal((await response('/admin/v0/spaces/space_other/inspect',{method:'POST',body:{kind:'inbox'},headers:explicitWrites})).status,404);
  phase='selected space connection scope';
  const connections=ok(await account('/account/connections/list'));
  assert.equal(connections.space_id,'space_a');assert(connections.items.some(item=>item.token_id==='token_keep'));
  assert(!connections.items.some(item=>['token_other','token_foreign'].includes(item.token_id)));
  denied(await account('/account/connections/revoke',{token_id:'token_other'}));
  denied(await account('/account/connections/revoke',{token_id:'token_foreign'}));
  denied(await response('/account/connections/revoke',{method:'POST',body:{token_id:'token_keep'},headers:{origin,authorization:'Bearer '+tokens.keep}}));
  ok(await account('/account/connections/revoke',{token_id:'token_revoke'}));
  denied(await agent('/v0/describe',undefined,tokens.revoke));ok(await agent('/v0/describe',undefined,tokens.other));ok(await agent('/v0/describe',undefined,tokens.keep));
  phase='expired session and stale selected-space intent';
  await db.prepare('UPDATE account_sessions SET expires_at=1 WHERE session_digest=?').bind(digest(accountCookie)).run();
  assert.equal((await account('/account/connections/list')).status,401);
  await db.prepare('UPDATE account_sessions SET expires_at=? WHERE session_digest=?').bind(now+3600000,digest(accountCookie)).run();
  ok(await account('/account/spaces/select',{space_id:'space_other'}));
  assert.equal((await account('/account/connections/revoke',{token_id:'token_other'})).status,403);
  ok(await account('/account/spaces/select',{space_id:'space_a'}));
  ok(await agent('/v0/describe',undefined,tokens.other));
  phase='selected space OAuth revocation';
  const families=ok(await account('/account/oauth/list'));assert(families.items.some(item=>item.family_id==='family_a'));assert(!families.items.some(item=>item.family_id==='family_other'));
  denied(await account('/account/oauth/revoke',{family_id:'family_other'}));
  ok(await account('/account/oauth/revoke',{family_id:'family_a'}));
  denied(await agent('/v0/describe',undefined,tokens.oauth));ok(await agent('/v0/describe',undefined,tokens.oauth_other));
  phase='self managed identity and primary assistant';
  const created=ok(await account('/account/agents/create',{request_id:'self-agent',display_name:'Self managed'}));
  const identities=ok(await account('/account/identities/list',{kind:'actors'}));
  assert(identities.items.some(item=>item.actor_id===created.actor_id));assert(!identities.items.some(item=>item.actor_id==='actor_foreign'));
  for(const identity_id of ['actor_foreign','actor_other']) {
    const r=await account('/account/identities/disable',{kind:'actors',identity_id});
    assert.equal(r.status,400);assert.equal(r.value.error.code,'INVALID_ARGUMENT');
  }
  ok(await agent('/v0/describe',undefined,tokens.foreign));ok(await agent('/v0/describe',undefined,tokens.other));
  const primary=ok(await account('/account/primary/set',{expected_revision:identities.primary_revision,actor_id:created.actor_id}));
  assert.equal((await account('/account/primary/set',{expected_revision:identities.primary_revision,actor_id:null})).status,409);
  ok(await account('/account/primary/set',{expected_revision:primary.primary_revision,actor_id:null}));
  ok(await account('/account/identities/disable',{kind:'consumers',identity_id:created.consumer_id}));
  phase='existing recovery key compatibility only';
  // Existing owner keys are compatibility data, never issued by this test's account flow.
  const ownerRegistry=ok(await response('/admin/v0/registry',{method:'POST',body:{kind:'spaces'},headers:{authorization:'Bearer '+ownerKey}}));
  assert.deepEqual(ownerRegistry.items.map(item=>item.space_id),['space_a']);
  denied(await response('/admin/v0/spaces',{method:'POST',body:{request_id:'owner-global',display_name:'Denied'},headers:{authorization:'Bearer '+ownerKey}}));
  ok(await response('/account/spaces/recover',{method:'POST',body:{space_id:'space_a',owner_credential:ownerKey},headers:{origin}}));
  denied(await account('/account/connections/list'));
  ok(await agent('/v0/messages/'+message.message_id));
  ok(await agent('/v0/describe',undefined,tokens.oauth_other));
  assert.equal(unexpectedOutbound,0);
  console.log(JSON.stringify({result:'passed',runtime:'actual compiled Worker/local Miniflare D1',identity:'synthetic seeded accounts, sessions and historical credentials',missing_admin_secret:true,invalid_configurations_rejected:6,retained_admin_secret_disabled:true,operator_bearer_and_cookie_denied:true,legacy_agent_data:true,account_cookie_dashboard_bootstrap:true,explicit_account_mode_ignores_old_admin_cookie:true,invalid_account_no_legacy_fallback:true,dashboard_memory_read:true,dashboard_csrf_and_space_boundaries:true,selected_space_management:true,expired_session_denied:true,stale_space_intent_denied:true,account_and_scoped_owner_readiness:true,scoped_connection_and_oauth_revoke:true,self_managed_identity_and_primary:true,existing_recovery_compatibility:true,new_recovery_key_issued:false,external_requests:unexpectedOutbound,production_verified:false}));
} catch(error) {
  console.error(JSON.stringify({result:'failed',phase,error_type:error.constructor.name,assertion_line:error.stack?.split('\n').find(line=>line.includes('operator_retirement_worker.mjs:'))?.trim(),actual:typeof error.actual==='number'?error.actual:undefined,expected:typeof error.expected==='number'?error.expected:undefined}));process.exitCode=1;
} finally {await mf.dispose();}
