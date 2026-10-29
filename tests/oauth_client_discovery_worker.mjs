// Isolated compiled Worker fixture and DCR regression. --serve exposes only
// literal loopback for actual client tests; no production or real IdP is used.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createPrivateKey,createPublicKey,createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {Miniflare,Log,LogLevel} from '../examples/mcp-client/node_modules/miniflare/dist/src/index.js';
import {startAuthorization} from '../examples/mcp-client/node_modules/@modelcontextprotocol/sdk/dist/esm/client/auth.js';
const root=fileURLToPath(new URL('../',import.meta.url)),origin='http://127.0.0.1:8793',resource=origin+'/mcp';
const cookie='waypost_account='+'c'.repeat(43),redirect='http://127.0.0.1:8765/callback';
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
let phase='initialization',outbound=0;
const mf=new Miniflare({modules:true,scriptPath:root+'build/index.js',modulesRules:[{type:'CompiledWasm',include:['**/*.wasm'],fallthrough:true}],compatibilityDate:'2026-07-17',log:new Log(LogLevel.NONE),host:'127.0.0.1',port:8793,d1Databases:{DB:'oauth-discovery-fixture'},r2Buckets:['OBJECTS'],bindings:{PUBLIC_ORIGIN:origin,WAYPOST_ADMIN_SECRET:randomBytes(32).toString('hex'),WAYPOST_ACCOUNT_SIGNUP_LIMIT:'0',WAYPOST_OIDC_CONFIG:JSON.stringify({issuer:'https://accounts.google.com',client_id:'synthetic-google',authorization_endpoint:'https://accounts.google.com/o/oauth2/v2/auth',token_endpoint:'https://oauth2.googleapis.com/token',keys:[{kid:'fixture',n:key.n,e:key.e}]}),WAYPOST_OAUTH_CLIENT_DISCOVERY:JSON.stringify({dynamic_registration:true}),WAYPOST_ENCRYPTION_KEYS:JSON.stringify({active:'test',keys:{test:randomBytes(32).toString('hex')}})},outboundService:()=>{outbound++;throw new Error('External requests forbidden');}});
async function request(path,{method='GET',body,headers={},form}={}) {
 const r=await mf.dispatchFetch(origin+path,{method,redirect:'manual',headers:{'content-type':form?'application/x-www-form-urlencoded':'application/json',...headers},...(body===undefined?{}:{body:form?new URLSearchParams(body):JSON.stringify(body)})});
 const raw=await r.text();return {status:r.status,headers:r.headers,value:raw?JSON.parse(raw):null};
}
const token=(body)=>request('/oauth/token',{method:'POST',form:true,body:{resource,...body}});
const revoke=(client_id,token)=>request('/oauth/revoke',{method:'POST',form:true,body:{client_id,token}});
const access=(raw)=>request('/mcp',{method:'POST',headers:{authorization:'Bearer '+raw},body:{jsonrpc:'2.0',id:1,method:'tools/list'}});
let cleanup=[];
try {
 const db=await mf.getD1Database('DB');for(const sql of statements)await db.prepare(sql).run();
 const now=Date.now();
 await db.batch([
  db.prepare("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_test','https://accounts.google.com','synthetic-google-owner',?)").bind(now),
  ...['test','foreign'].flatMap(id=>[
   db.prepare('INSERT INTO spaces(space_id,display_name,source_uri,default_actor_id,default_consumer_id,created_at) VALUES(?,?,?,?,?,?)').bind('space_'+id,id,'urn:test:'+id,'actor_'+id,'consumer_'+id,now),
   db.prepare("INSERT INTO actors(space_id,actor_id,display_name,kind,created_at) VALUES(?,?,?,'agent',?)").bind('space_'+id,'actor_'+id,id,now),
   db.prepare("INSERT INTO consumers(space_id,consumer_id,actor_id,view,created_at) VALUES(?,?,?,'inbox',?)").bind('space_'+id,'consumer_'+id,'actor_'+id,now),
  ]),
  db.prepare("INSERT INTO account_spaces(space_id,account_id,created_at) VALUES('space_test','account_test',?)").bind(now),
  db.prepare("INSERT INTO account_sessions(session_digest,account_id,selected_space_id,created_at,expires_at) VALUES(?,'account_test','space_test',?,?)").bind(createHash('sha256').update('c'.repeat(43)).digest(),now,now+3600000),
 ]);
 if(process.argv.includes('--serve')) {
  await mf.ready;
  console.log(JSON.stringify({ready:true,origin,identity:'synthetic seeded Google account, not real Google login'}));
  await new Promise(resolve=>{process.once('SIGTERM',resolve);process.once('SIGINT',resolve);});
 } else {
  phase='metadata and dynamic registration';
  const metadata=(await request('/.well-known/oauth-authorization-server')).value;
  assert.equal(metadata.registration_endpoint,origin+'/oauth/register');
  assert.equal(metadata.client_id_metadata_document_supported,false);
  const registration={client_name:'Isolated DCR test',redirect_uris:[redirect],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code'],scope:'waypost'};
  for(const bad of ['http://169.254.169.254/callback','http://example.test/callback','https://client.example/callback#fragment','https://user@client.example/callback']) {
   const rejected=await request('/oauth/register',{method:'POST',body:{...registration,redirect_uris:[bad]}});assert.equal(rejected.status,400);
  }
  const registered=await request('/oauth/register',{method:'POST',body:registration});assert.equal(registered.status,201);assert.equal(registered.headers.get('cache-control'),'no-store');
  const client_id=registered.value.client_id;assert(client_id.startsWith('dcr_'));assert.equal(registered.value.client_secret,undefined);
  const started=await startAuthorization(origin,{metadata,clientInformation:{client_id},redirectUrl:redirect,scope:'waypost',resource,state:'synthetic-state'});
  phase='explicit consent and cross-space rejection';
  const begun=await request(started.authorizationUrl.pathname+started.authorizationUrl.search);assert.equal(begun.status,303);
  const browser=begun.headers.get('set-cookie').split(';')[0],id=new URL(begun.headers.get('location'),origin).searchParams.get('oauth_request');
  const session=await request('/account/session',{headers:{cookie}});assert.equal(session.status,200);
  const headers={origin,cookie:cookie+'; '+browser,'x-waypost-csrf':session.value.data.csrf_token};
  const consent={request_id:id,decision:'approve',actor_id:'actor_test',consumer_id:'consumer_test'};
  const foreign=await request('/oauth/consent',{method:'POST',headers,body:{...consent,actor_id:'actor_foreign',consumer_id:'consumer_foreign'}});assert.equal(foreign.status,400);assert.equal(foreign.value.error,'access_denied');
  const approved=await request('/oauth/consent',{method:'POST',headers,body:consent});assert.equal(approved.status,200);
  const callback=new URL(approved.value.redirect_uri);assert.equal(callback.searchParams.get('state'),'synthetic-state');assert.equal(callback.searchParams.get('iss'),origin);
  const exchange={client_id,grant_type:'authorization_code',code:callback.searchParams.get('code'),code_verifier:started.codeVerifier,redirect_uri:redirect};
  phase='PKCE redirect and resource binding';
  assert.equal((await token({...exchange,redirect_uri:'https://other.example/callback'})).status,400);
  assert.equal((await token({...exchange,resource:'https://other.example/mcp'})).value.error,'invalid_target');
  const issued=await token(exchange);assert.equal(issued.status,200);cleanup.push([client_id,issued.value.refresh_token]);
  const tools=await access(issued.value.access_token);assert.equal(tools.status,200);assert.equal(tools.value.result.tools.length,11);
  phase='refresh rotation and revocation';
  const refreshed=await token({client_id,grant_type:'refresh_token',refresh_token:issued.value.refresh_token});assert.equal(refreshed.status,200);assert.notEqual(refreshed.value.refresh_token,issued.value.refresh_token);cleanup.push([client_id,refreshed.value.refresh_token]);
  assert.equal((await revoke(client_id,refreshed.value.refresh_token)).status,200);
  assert.equal((await access(issued.value.access_token)).status,401);assert.equal((await access(refreshed.value.access_token)).status,401);
  assert.equal((await token({client_id,grant_type:'refresh_token',refresh_token:refreshed.value.refresh_token})).value.error,'invalid_grant');
  assert.equal(outbound,0);
  console.log(JSON.stringify({result:'passed',runtime:'actual isolated local Workerd/D1',identity:'synthetic seeded Google account',dynamic_registration:true,preregistered_client:false,pkce:true,tools:11,invalid_redirect_and_resource:true,cross_space_denied:true,refresh_and_revoke:true,model_calls:0,live_google_verified:false}));
 }
} catch(error) {console.error(JSON.stringify({result:'failed',phase,error_type:error.constructor.name,assertion_line:error.stack?.split('\n').find(line=>line.includes('oauth_client_discovery_worker.mjs:'))?.trim(),actual:typeof error.actual==='number'?error.actual:undefined,expected:typeof error.expected==='number'?error.expected:undefined}));process.exitCode=1;}
finally {for(const [client,raw]of cleanup)try{await revoke(client,raw);}catch{process.exitCode=1;}await mf.dispose();}
