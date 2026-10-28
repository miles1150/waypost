#!/usr/bin/env node
// Concurrent requests to an isolated local Workerd/D1 fixture, not remote D1.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {discoverOAuthServerInfo,startAuthorization,exchangeAuthorization} from '../examples/mcp-client/node_modules/@modelcontextprotocol/sdk/dist/esm/client/auth.js';

const origin='http://127.0.0.1:8793',resource=origin+'/mcp';
const redirectUri='http://127.0.0.1:8765/callback',clientInformation={client_id:'local-mcp-test'};
const accountCookie='waypost_account='+'c'.repeat(43);
const cleanupTokens=new Set();
let phase='setup',checks=[];
async function localFetch(input,options={}) {
  assert.equal(new URL(input instanceof Request?input.url:input).origin,origin);
  return fetch(input,{...options,redirect:'manual',signal:AbortSignal.timeout(15000)});
}
async function jsonRequest(path,options={}) {
  const response=await localFetch(origin+path,options);
  assert.equal(response.status,200);
  assert.equal(response.headers.get('cache-control'),'no-store');
  return response.json();
}
async function form(path,fields) {
  const response=await localFetch(origin+path,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:clientInformation.client_id,...fields})});
  assert.equal(response.headers.get('cache-control'),'no-store');
  const raw=await response.text();
  const value=raw?JSON.parse(raw):null;
  if(response.status===200&&value?.access_token) {
    cleanupTokens.add(value.access_token);
    if(value.refresh_token)cleanupTokens.add(value.refresh_token);
  }
  return {status:response.status,value};
}
async function revoke(token) {
  assert.equal((await form('/oauth/revoke',{token})).status,200);
}
async function assertDenied(accessToken) {
  const response=await localFetch(resource,{method:'POST',headers:{authorization:'Bearer '+accessToken,'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
  assert.equal(response.status,401);
  assert.equal(response.headers.get('cache-control'),'no-store');
}
function winner(results) {
  const successes=results.filter(r=>r.status===200);
  const failures=results.filter(r=>r.status!==200);
  assert.equal(successes.length,1);
  assert.equal(failures.length,1);
  assert.equal(failures[0].status,400);
  assert.equal(failures[0].value.error,'invalid_grant');
  assert(successes[0].value.access_token);assert(successes[0].value.refresh_token);
  return successes[0].value;
}
try {
  const info=await discoverOAuthServerInfo(resource,{fetchFn:localFetch});
  assert.equal(info.authorizationServerUrl,origin);assert.equal(info.resourceMetadata.resource,resource);
  const metadata=info.authorizationServerMetadata;
  const session=await jsonRequest('/account/session',{headers:{cookie:accountCookie}});
  assert(session.data.selected_space_id);
  const browserHeaders={cookie:accountCookie,origin,'x-waypost-csrf':session.data.csrf_token,'content-type':'application/json'};
  const actor=await jsonRequest('/account/agents/create',{method:'POST',headers:browserHeaders,body:JSON.stringify({request_id:randomUUID(),display_name:'OAuth concurrent local fixture'})});
  async function authorization() {
    const state=randomUUID();
    const started=await startAuthorization(origin,{metadata,clientInformation,redirectUrl:redirectUri,scope:'waypost',state,resource});
    const response=await localFetch(started.authorizationUrl);
    assert.equal(response.status,303);
    const location=new URL(response.headers.get('location'),origin);
    assert.equal(location.origin,origin);assert.equal(location.pathname,'/account');
    const requestId=location.searchParams.get('oauth_request');assert(requestId);
    const cookie=response.headers.get('set-cookie');assert(cookie?.includes('HttpOnly'));
    const consent=await jsonRequest('/oauth/consent',{method:'POST',headers:{...browserHeaders,cookie:accountCookie+'; '+cookie.split(';')[0]},body:JSON.stringify({request_id:requestId,decision:'approve',actor_id:actor.data.actor_id,consumer_id:actor.data.consumer_id})});
    const callback=new URL(consent.redirect_uri);
    assert.equal(callback.origin+callback.pathname,redirectUri);assert.equal(callback.searchParams.get('state'),state);assert.equal(callback.searchParams.get('iss'),origin);
    const code=callback.searchParams.get('code');assert(code);
    return {grant_type:'authorization_code',resource,code,code_verifier:started.codeVerifier,redirect_uri:redirectUri};
  }
  async function issue() {
    const fields=await authorization();
    const token=await exchangeAuthorization(origin,{metadata,clientInformation,authorizationCode:fields.code,codeVerifier:fields.code_verifier,redirectUri,resource,fetchFn:localFetch});
    assert(token.refresh_token);
    cleanupTokens.add(token.access_token);cleanupTokens.add(token.refresh_token);
    return token;
  }
  phase='concurrent authorization code exchanges';
  const codeFields=await authorization();
  const codeWinner=winner(await Promise.all([form('/oauth/token',codeFields),form('/oauth/token',codeFields)]));
  await assertDenied(codeWinner.access_token);
  checks.push('same code: one issuance; replay revokes winner');

  phase='concurrent refresh rotations';
  const original=await issue();
  const refreshFields={grant_type:'refresh_token',resource,refresh_token:original.refresh_token};
  const refreshWinner=winner(await Promise.all([form('/oauth/token',refreshFields),form('/oauth/token',refreshFields)]));
  assert.notEqual(refreshWinner.refresh_token,original.refresh_token);
  await assertDenied(original.access_token);await assertDenied(refreshWinner.access_token);
  checks.push('same refresh: one rotation; replay revokes old and winner access');

  phase='concurrent revoke and refresh';
  // Reverse request launch order on a fresh family each time. This observes local
  // runtime schedules; it does not claim to enumerate every possible interleaving.
  for(const revokeFirst of [true,false]) {
    const token=await issue();
    const refresh=()=>form('/oauth/token',{grant_type:'refresh_token',resource,refresh_token:token.refresh_token});
    const cancel=()=>form('/oauth/revoke',{token:token.refresh_token});
    const results=await Promise.all(revokeFirst?[cancel(),refresh()]:[refresh(),cancel()]);
    const revoked=results[revokeFirst?0:1],rotated=results[revokeFirst?1:0];
    assert.equal(revoked.status,200);
    if(rotated.status===200) {
      assert(rotated.value.access_token);assert(rotated.value.refresh_token);
      await assertDenied(rotated.value.access_token);
      const retry=await form('/oauth/token',{grant_type:'refresh_token',resource,refresh_token:rotated.value.refresh_token});
      assert.equal(retry.status,400);assert.equal(retry.value.error,'invalid_grant');
    } else {assert.equal(rotated.status,400);assert.equal(rotated.value.error,'invalid_grant');}
    await assertDenied(token.access_token);
  }
  checks.push('revoke vs refresh: both launch orders leave no usable original or returned access');
} catch {
  // Assertions/SDK errors may carry credentials. Emit only the safe stage name.
  console.error(JSON.stringify({result:'failed',phase}));process.exitCode=1;
} finally {
  for(const token of cleanupTokens) {
    try {await revoke(token);}catch {console.error(JSON.stringify({result:'failed',phase:'revocation cleanup'}));process.exitCode=1;}
  }
}
if(!process.exitCode)console.log(JSON.stringify({result:'passed',runtime:'isolated local Workerd/D1',requests:'concurrent HTTP; local scheduling only',identity:'synthetic seeded account',remote_d1_verified:false,checks}));
