#!/usr/bin/env node
// Serve the compiled Worker (build/index.js) on isolated local Workerd with an
// in-memory D1/R2, all migrations applied, and a SYNTHETIC account session.
// For local acceptance scripts only; never point it at real data.
//
//   node scripts/serve_local_workerd.mjs [--product waypost|keys] [--port 8793]
//        [--cimd] [--dcr] [--document URL=FILE ...]
//
// Waypost mode seeds tests/fixtures/account-preview-seed.sql (session cookie
// 'c'*43) and preregisters local-mcp-test, as scripts/verify_oauth_sdk.mjs and
// scripts/verify_oauth_preview.py expect. Keys mode seeds an account and the
// same session. Outbound network is refused; `--document URL=FILE` answers a
// metadata-document fetch for URL with a local FIXTURE file instead (clearly a
// stand-in for the real client's document, used when its host is unreachable).
import {readFile,readdir} from 'node:fs/promises';
import {createPrivateKey,createPublicKey,randomBytes,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {Miniflare,Log,LogLevel} from '../examples/mcp-client/node_modules/miniflare/dist/src/index.js';

const args=process.argv.slice(2);
const option=(name,fallback)=>{const i=args.indexOf('--'+name);return i>=0?args[i+1]:fallback;};
const product=option('product','waypost'),port=Number(option('port','8793'));
const root=fileURLToPath(new URL('../',import.meta.url)),origin=`http://127.0.0.1:${port}`;
const key=createPublicKey(createPrivateKey(await readFile(root+'tests/fixtures/oidc-test-private.pem'))).export({format:'jwk'});
const statements=sql=>JSON.parse(execFileSync('python3',['-c',`
import json,pathlib,sqlite3,sys
out=[]
for path in sys.argv[1:]:
 pending=''
 for line in pathlib.Path(path).read_text().splitlines(True):
  pending+=line
  if sqlite3.complete_statement(pending):out.append(pending);pending=''
print(json.dumps(out))
`,...sql],{encoding:'utf8'}));
const migrations=(await readdir(root+'migrations')).filter(n=>n.endsWith('.sql')).sort();
const oauth={clients:[],client_id_metadata_documents:args.includes('--cimd'),dynamic_registration:args.includes('--dcr')};
if(product==='waypost')oauth.clients.push({client_id:'local-mcp-test',name:'Local MCP test',redirect_uris:['http://127.0.0.1:8765/callback','http://localhost:8766/callback'],allow_loopback_port_variation:true});
const bindings={PUBLIC_ORIGIN:origin,WAYPOST_PRODUCT:product,WAYPOST_ACCOUNT_SIGNUP_LIMIT:'1',
  WAYPOST_OIDC_CONFIG:JSON.stringify({issuer:'https://issuer.example',client_id:'test-client',authorization_endpoint:'https://issuer.example/authorize',token_endpoint:'https://issuer.example/token',keys:[{kid:'test',n:key.n,e:key.e}]}),
  WAYPOST_OAUTH_CLIENTS:JSON.stringify(oauth)};
if(product==='keys')Object.assign(bindings,{WAYPOST_OPERATOR_MODE:'disabled',WAYPOST_CSRF_SECRET:randomBytes(32).toString('hex'),WAYPOST_CURSOR_SECRET:randomBytes(32).toString('hex'),KEYS_DATA_KEYS:JSON.stringify({active:'k1',keys:{k1:randomBytes(32).toString('hex')}})});
else Object.assign(bindings,{WAYPOST_ADMIN_SECRET:'local-only-admin-secret-32-bytes-long',WAYPOST_ENCRYPTION_KEYS:JSON.stringify({active:'w1',keys:{w1:randomBytes(32).toString('hex')}})});
const documents=new Map();
for(let i=0;i<args.length;i++)if(args[i]==='--document'){const [url,file]=args[i+1].split(/=(.*)/s);documents.set(url,await readFile(file,'utf8'));}
const mf=new Miniflare({modules:true,scriptPath:root+'build/index.js',modulesRules:[{type:'CompiledWasm',include:['**/*.wasm'],fallthrough:true}],compatibilityDate:'2026-07-17',
  log:new Log(LogLevel.WARN),host:'127.0.0.1',port,d1Databases:{DB:'local-'+product},r2Buckets:['OBJECTS'],bindings,
  outboundService:request=>{
    const body=documents.get(request.url);
    if(body!==undefined){console.log(JSON.stringify({served_fixture_document:request.url}));return new Response(body,{headers:{'content-type':'application/json','cache-control':'max-age=300'}});}
    console.log(JSON.stringify({refused_outbound:new URL(request.url).host}));
    throw new Error('External network is disabled in local acceptance.');
  }});
await mf.ready;
const db=await mf.getD1Database('DB');
for(const sql of statements(migrations.map(n=>root+'migrations/'+n)))await db.prepare(sql).run();
await db.prepare('CREATE TABLE d1_migrations(name TEXT PRIMARY KEY)').run();
for(const name of migrations)await db.prepare('INSERT INTO d1_migrations(name) VALUES(?)').bind(name).run();
// One batch is one transaction, so the seed's deferred foreign keys apply.
if(product==='waypost')await db.batch(statements([root+'tests/fixtures/account-preview-seed.sql']).map(sql=>db.prepare(sql)));
else{const now=Date.now();
  await db.prepare("INSERT INTO accounts(account_id,issuer,subject,created_at) VALUES('account_test','https://issuer.example','fixture',?)").bind(now).run();
  await db.prepare("INSERT INTO account_sessions(session_digest,account_id,created_at,expires_at) VALUES(?,'account_test',?,?)").bind(createHash('sha256').update('c'.repeat(43)).digest(),now,now+3600000).run();}
console.log(JSON.stringify({ready:true,origin,product,cimd:oauth.client_id_metadata_documents,dcr:oauth.dynamic_registration,fixture_documents:[...documents.keys()]}));
process.on('SIGTERM',async()=>{await mf.dispose();process.exit(0);});
process.on('SIGINT',async()=>{await mf.dispose();process.exit(0);});
