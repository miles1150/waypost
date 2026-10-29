// Real compiled Worker + local D1/R2. Google HTTPS transports are synthetic and
// intercepted: this does not test Google availability, credentials or deployment.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createPrivateKey,createPublicKey,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {Miniflare,Response,Log,LogLevel} from '../examples/mcp-client/node_modules/miniflare/dist/src/index.js';

const root=fileURLToPath(new URL('../',import.meta.url));
const origin='http://127.0.0.1:8793';
const tokenUrl='https://oauth2.googleapis.com/token';
const jwksUrl='https://www.googleapis.com/oauth2/v3/certs';
const keyA=createPrivateKey(await readFile(new URL('fixtures/oidc-test-private.pem',import.meta.url)));
const keyB=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey;
const jwk=(key,kid)=>({...createPublicKey(key).export({format:'jwk'}),kid,alg:'RS256',use:'sig'});
const encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
// sqlite3.complete_statement handles multi-line triggers and quoted semicolons.
const statements=JSON.parse(execFileSync('python3',['-c',`
import json,pathlib,sqlite3,sys
out=[]
for path in sorted(pathlib.Path(sys.argv[1]).glob('*.sql')):
 pending=''
 for line in path.read_text().splitlines(True):
  pending+=line
  if sqlite3.complete_statement(pending): out.append(pending);pending=''
 if pending.strip() and not all(not l.strip() or l.lstrip().startswith('--') for l in pending.splitlines()): raise ValueError('Incomplete migration')
print(json.dumps(out))
`,root+'migrations'],{encoding:'utf8'}));
let phase='initialization',unexpected=0;
async function fixture(initialMode='keys') {
  const state={jwksCalls:0,tokenCalls:0,keys:[jwk(keyA,'a')],mode:initialMode,issued:new Map()};
  const mf=new Miniflare({
    modules:true,scriptPath:root+'build/index.js',modulesRules:[{type:'CompiledWasm',include:['**/*.wasm'],fallthrough:true}],
    compatibilityDate:'2026-07-17',log:new Log(LogLevel.NONE),
    d1Databases:{DB:'google-jwks-test'},r2Buckets:['OBJECTS'],
    bindings:{PUBLIC_ORIGIN:origin,WAYPOST_ADMIN_SECRET:randomBytes(32).toString('hex'),WAYPOST_ACCOUNT_SIGNUP_LIMIT:'0',
      WAYPOST_ENCRYPTION_KEYS:JSON.stringify({active:'test',keys:{test:randomBytes(32).toString('hex')}}),
      WAYPOST_OIDC_CONFIG:JSON.stringify({issuer:'https://accounts.google.com',client_id:'jwks-worker-test',authorization_endpoint:'https://accounts.google.com/o/oauth2/v2/auth',token_endpoint:tokenUrl,google_jwks:true,keys:[]})},
    outboundService:async request=>{
      if(request.url===jwksUrl&&request.method==='GET') {
        state.jwksCalls++;
        if(state.mode==='error')return new Response('synthetic outage',{status:503});
        return new Response(JSON.stringify({keys:state.keys}),{headers:{'content-type':'application/json','cache-control':'public, max-age=3600'}});
      }
      if(request.url===tokenUrl&&request.method==='POST') {
        state.tokenCalls++;
        const fields=new URLSearchParams(await request.text());
        assert.equal(fields.get('client_id'),'jwks-worker-test');
        assert.equal(fields.get('redirect_uri'),origin+'/account/callback');
        const token=state.issued.get(fields.get('code'));assert(token);
        return new Response(JSON.stringify({id_token:token}),{headers:{'content-type':'application/json'}});
      }
      unexpected++;throw new Error('Unexpected outbound request blocked');
    },
  });
  try {
    const db=await mf.getD1Database('DB');
    for(const statement of statements)await db.prepare(statement).run();
    await db.prepare("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_google','https://accounts.google.com','synthetic-google-owner',0)").run();
  }catch(error){await mf.dispose();throw error;}
  async function login({key=keyA,kid='a',expected=303}={}) {
    const start=await mf.dispatchFetch(origin+'/account/login',{method:'POST',headers:{origin,'content-type':'application/json'},body:'{}'});
    assert.equal(start.status,200);
    const browser=start.headers.get('set-cookie').split(';')[0];
    const authorization=new URL((await start.json()).data.authorization_url);
    assert.equal(authorization.origin,'https://accounts.google.com');
    const code=randomBytes(24).toString('hex'),now=Math.floor(Date.now()/1000);
    const unsigned=encode({alg:'RS256',kid})+'.'+encode({iss:'https://accounts.google.com',aud:'jwks-worker-test',sub:'synthetic-google-owner',nonce:authorization.searchParams.get('nonce'),iat:now,exp:now+300});
    state.issued.set(code,unsigned+'.'+sign('RSA-SHA256',Buffer.from(unsigned),key).toString('base64url'));
    const query=new URLSearchParams({state:authorization.searchParams.get('state'),code});
    const callback=await mf.dispatchFetch(origin+'/account/callback?'+query,{redirect:'manual',headers:{cookie:browser}});
    state.issued.delete(code);
    assert.equal(callback.status,expected);
    assert.equal(callback.headers.get('cache-control'),'no-store');
    if(expected===303) {
      const cookie=callback.headers.get('set-cookie').split(';')[0];
      const session=await mf.dispatchFetch(origin+'/account/session',{headers:{cookie}});
      assert.equal(session.status,200);assert.equal((await session.json()).data.account_id,'account_google');
      const logout=await mf.dispatchFetch(origin+'/account/session',{method:'DELETE',body:'{}',headers:{'content-type':'application/json',cookie,origin,'x-waypost-csrf':(await (await mf.dispatchFetch(origin+'/account/session',{headers:{cookie}})).json()).data.csrf_token}});
      assert.equal(logout.status,200);
    }else assert.equal(callback.headers.get('set-cookie'),null);
  }
  return {mf,state,login};
}
try {
  const normal=await fixture();
  try {
    phase='cold fetch and cross-request reuse';
    await normal.login();assert.equal(normal.state.jwksCalls,1);
    await normal.login();assert.equal(normal.state.jwksCalls,1);
    phase='unknown kid cooldown';
    await normal.login({key:keyB,kid:'b',expected:401});assert.equal(normal.state.jwksCalls,1);
    normal.state.keys=[jwk(keyB,'b')];
    // Real time exercises the production cooldown without a test-only clock hook.
    console.error('Google JWKS local Worker: waiting 31 seconds for the real refresh cooldown.');
    await new Promise(resolve=>setTimeout(resolve,31000));
    phase='rotated key refresh across requests';
    await normal.login({key:keyB,kid:'b'});assert.equal(normal.state.jwksCalls,2);
    await normal.login({key:keyB,kid:'b'});assert.equal(normal.state.jwksCalls,2);
    await normal.login({kid:'unknown',expected:401});assert.equal(normal.state.jwksCalls,2);
    assert.equal(normal.state.tokenCalls,6);
  } finally {await normal.mf.dispose();}
  const outage=await fixture('error');
  try {
    phase='upstream failure cooldown across requests';
    await outage.login({expected:401});assert.equal(outage.state.jwksCalls,1);
    outage.state.mode='keys';
    await outage.login({expected:401});assert.equal(outage.state.jwksCalls,1);
    assert.equal(outage.state.tokenCalls,2);
  } finally {await outage.mf.dispose();}
  assert.equal(unexpected,0);
  console.log(JSON.stringify({result:'passed',runtime:'actual compiled Worker in local Miniflare/Workerd',provider:'mock fixed Google token and JWKS HTTPS endpoints',d1:'isolated synthetic account',cross_request_cache_reuse:true,rotation_after_real_cooldown:true,unknown_kid_denied:true,upstream_error_denied:true,failure_cooldown_reused:true,unexpected_outbound_requests:unexpected,live_google_verified:false}));
} catch(error) {
  // No tokens, authorization codes, cookies or upstream bodies in output.
  console.error(JSON.stringify({result:'failed',phase,error_type:error.constructor.name,assertion_line:error.stack?.split('\n').find(line=>line.includes('google_jwks_worker.mjs:'))?.trim(),actual:typeof error.actual==='number'?error.actual:undefined,expected:typeof error.expected==='number'?error.expected:undefined}));process.exitCode=1;
}
