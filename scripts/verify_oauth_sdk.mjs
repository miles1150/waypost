#!/usr/bin/env node
// Local Workerd acceptance with the official MCP SDK. The account session is
// seeded by the disposable fixture; no real IdP, Codex or Claude is exercised.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {discoverOAuthServerInfo,startAuthorization,exchangeAuthorization,refreshAuthorization} from '../examples/mcp-client/node_modules/@modelcontextprotocol/sdk/dist/esm/client/auth.js';
import {InvalidGrantError} from '../examples/mcp-client/node_modules/@modelcontextprotocol/sdk/dist/esm/server/auth/errors.js';
import {Client} from '../examples/mcp-client/node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js';
import {StreamableHTTPClientTransport} from '../examples/mcp-client/node_modules/@modelcontextprotocol/sdk/dist/esm/client/streamableHttp.js';

const origin='http://127.0.0.1:8793',resource=origin+'/mcp';
const redirectUri='http://127.0.0.1:8765/callback';
const clientInformation={client_id:'local-mcp-test'};
const accountCookie='waypost_account='+'c'.repeat(43);
let phase='discovery',tokens,client,revoked=false;
// No discovery endpoint, redirect or SDK request may leave the disposable service.
async function localFetch(input,options={}) {
  const url=new URL(input instanceof Request?input.url:input);
  assert.equal(url.origin,origin);
  return fetch(input,{...options,redirect:'manual',signal:AbortSignal.timeout(15000)});
}
async function jsonRequest(path,options={}) {
  const response=await localFetch(origin+path,options);
  assert.equal(response.headers.get('cache-control'),'no-store');
  assert.equal(response.status,200);
  return response.json();
}
async function revoke() {
  if(!tokens||revoked)return;
  const body=new URLSearchParams({client_id:clientInformation.client_id,token:tokens.refresh_token||tokens.access_token});
  const response=await localFetch(origin+'/oauth/revoke',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body});
  assert.equal(response.status,200);
  assert.equal(response.headers.get('cache-control'),'no-store');
  revoked=true;
}
async function exerciseMcp(accessToken) {
  client=new Client({name:'waypost-oauth-sdk-acceptance',version:'0.1.0'},{capabilities:{}});
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(resource),{fetch:localFetch,requestInit:{headers:{authorization:'Bearer '+accessToken}}}));
    const listed=await client.listTools();assert(listed.tools.some(tool=>tool.name==='waypost_describe'));
    const description=await client.callTool({name:'waypost_describe',arguments:{}});
    assert.equal(description.isError,false);
  } finally {await client.close();client=undefined;}
}
try {
  const info=await discoverOAuthServerInfo(new URL(resource),{fetchFn:localFetch});
  assert.equal(info.authorizationServerUrl,origin);
  assert.equal(info.resourceMetadata.resource,resource);
  const metadata=info.authorizationServerMetadata;
  assert.equal(metadata.issuer,origin);
  assert.equal(metadata.revocation_endpoint,origin+'/oauth/revoke');
  const state=randomUUID();
  const started=await startAuthorization(origin,{metadata,clientInformation,redirectUrl:redirectUri,scope:'waypost',state,resource});
  phase='authorization browser binding';
  const authorization=await localFetch(started.authorizationUrl);
  assert.equal(authorization.status,303);
  assert.equal(authorization.headers.get('cache-control'),'no-store');
  const location=new URL(authorization.headers.get('location'),origin);
  assert.equal(location.origin,origin);assert.equal(location.pathname,'/account');
  const requestId=location.searchParams.get('oauth_request');assert(requestId);
  const browserCookie=authorization.headers.get('set-cookie');assert(browserCookie?.includes('HttpOnly'));
  const cookie=accountCookie+'; '+browserCookie.split(';')[0];
  const session=await jsonRequest('/account/session',{headers:{cookie:accountCookie}});
  assert(session.data.selected_space_id);
  const browserHeaders={cookie,origin,'x-waypost-csrf':session.data.csrf_token,'content-type':'application/json'};
  phase='explicit synthetic owner consent';
  const actor=await jsonRequest('/account/agents/create',{method:'POST',headers:browserHeaders,body:JSON.stringify({request_id:randomUUID(),display_name:'Official SDK local fixture'})});
  const preview=await jsonRequest('/oauth/consent?request_id='+encodeURIComponent(requestId),{headers:{cookie}});
  assert.equal(preview.selected_space_id,session.data.selected_space_id);
  assert.equal(preview.client_id,clientInformation.client_id);
  const consent=await jsonRequest('/oauth/consent',{method:'POST',headers:browserHeaders,body:JSON.stringify({request_id:requestId,decision:'approve',actor_id:actor.data.actor_id,consumer_id:actor.data.consumer_id})});
  // Validate the callback in memory: no listener or redirect to another service.
  const callback=new URL(consent.redirect_uri);
  assert.equal(callback.origin+callback.pathname,redirectUri);
  assert.equal(callback.searchParams.get('state'),state);
  assert.equal(callback.searchParams.get('iss'),origin);
  const code=callback.searchParams.get('code');assert(code);
  phase='SDK code exchange';
  tokens=await exchangeAuthorization(origin,{metadata,clientInformation,authorizationCode:code,codeVerifier:started.codeVerifier,redirectUri,resource,fetchFn:localFetch});
  assert(tokens.refresh_token);
  phase='official MCP client';
  await exerciseMcp(tokens.access_token);
  phase='SDK refresh rotation';
  const previousRefresh=tokens.refresh_token;
  tokens=await refreshAuthorization(origin,{metadata,clientInformation,refreshToken:previousRefresh,resource,fetchFn:localFetch});
  assert(tokens.refresh_token);assert.notEqual(tokens.refresh_token,previousRefresh);
  await exerciseMcp(tokens.access_token);
  phase='revocation';
  await revoke();
  const denied=await localFetch(resource,{method:'POST',headers:{authorization:'Bearer '+tokens.access_token,'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
  assert.equal(denied.status,401);
  assert.equal(denied.headers.get('cache-control'),'no-store');
  let refreshDenied=false;
  try {await refreshAuthorization(origin,{metadata,clientInformation,refreshToken:tokens.refresh_token,resource,fetchFn:localFetch});}catch(error) {assert(error instanceof InvalidGrantError);refreshDenied=true;}
  assert(refreshDenied);
  console.log(JSON.stringify({result:'passed',runtime:'local Workerd',client:'official MCP JavaScript SDK',identity:'synthetic seeded account session',discovery:true,pkce_authorization:true,explicit_consent:true,mcp_tools:true,refresh_rotation:true,revocation:true,real_idp_or_codex_or_claude:false}));
} catch {
  // SDK exceptions may contain protocol payloads. Never print tokens, cookies or bodies.
  console.error(JSON.stringify({result:'failed',phase}));process.exitCode=1;
} finally {
  try {if(client)await client.close();}catch {process.exitCode=1;}
  try {await revoke();}catch {console.error(JSON.stringify({result:'failed',phase:'revocation cleanup'}));process.exitCode=1;}
}
