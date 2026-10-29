'use strict';
const el = id => document.getElementById(id);
let csrf = '';
let inspectedCode = null;
let oauthPreview = false;
let oauthDeviceCode = null;
let oauthRevision = 0;
// This ID is only a navigation hint. The server's HttpOnly cookie binds consent.
const oauthHintKey = 'waypost.oauth.request';
let oauthRequest = null;
try {
  const incoming = new URL(location.href).searchParams.get('oauth_request');
  const hint = incoming || sessionStorage.getItem(oauthHintKey);
  if (hint && /^oauth_[A-Za-z0-9_-]{1,128}$/.test(hint)) {
    oauthRequest = hint; sessionStorage.setItem(oauthHintKey, hint);
  }
} catch (_) { /* Storage may be unavailable; direct navigation still works below. */ }
el('oauth-browser').hidden = !oauthRequest;
function resetOAuthConsent() {
  oauthRevision++; oauthPreview = false; oauthDeviceCode = null;
  for (const id of ['oauth-approve','oauth-deny','oauth-device-approve','oauth-device-deny']) el(id).disabled = true;
}
async function oauthApi(path, body, method = 'POST') {
  const response = await fetch(path, {method, credentials:'same-origin', headers:{'Content-Type':'application/json','X-Waypost-CSRF':csrf}, ...(method==='GET'?{}:{body:JSON.stringify(body)})});
  const value = await response.json();
  if (!response.ok || value.error) throw new Error('OAuth request failed. Sign in again if your session is older than 15 minutes, then review the request.');
  return value;
}
async function reviewOAuth() {
  oauthPreview = false; el('oauth-approve').disabled = true; el('oauth-deny').disabled = true;
  if (!oauthRequest) return;
  const requestId = oauthRequest, revision = ++oauthRevision;
  const info = await oauthApi('/oauth/consent?request_id='+encodeURIComponent(oauthRequest), null, 'GET');
  if (oauthRequest !== requestId || oauthRevision !== revision) return;
  el('oauth-info').textContent = JSON.stringify(info, null, 2);
  oauthPreview = true; el('oauth-approve').disabled = false; el('oauth-deny').disabled = false;
}
function clearOAuthHint() {
  oauthRequest = null; resetOAuthConsent(); el('oauth-browser').hidden = true;
  try { sessionStorage.removeItem(oauthHintKey); } catch (_) {}
  const url = new URL(location.href); url.searchParams.delete('oauth_request'); history.replaceState(null,'',url);
}
async function api(path, body, method = 'POST') {
  const response = await fetch(path, {method, credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-Waypost-CSRF': csrf}, ...(method === 'GET' ? {} : {body: JSON.stringify(body || {})})});
  const value = await response.json();
  if (!response.ok || !value.ok) throw new Error(value.error?.message || 'Request failed');
  return value.data;
}
async function refresh() {
  resetOAuthConsent();
  const data = await api('/account/session', null, 'GET');
  csrf = data.csrf_token;
  el('status').textContent = `Account: ${data.account_id}\nSelected Space: ${data.selected_space_id || 'none'}`;
  el('spaces').replaceChildren();
  for (const space of data.spaces) {
    const li = document.createElement('li');
    const button = document.createElement('button');
    button.textContent = `${space.display_name} (${space.space_id})`;
    button.onclick = () => run(async () => {resetOAuthConsent(); await api('/account/spaces/select', {space_id: space.space_id}); await refresh();});
    li.append(button); el('spaces').append(li);
  }
  if (oauthRequest) await reviewOAuth();
}
async function run(fn) { try { await fn(); } catch (error) { el('status').textContent = error.message; } }
el('login').onclick = () => run(async () => {const data = await api('/account/login'); location.assign(data.authorization_url);});
el('logout').onclick = () => run(async () => {await api('/account/session', null, 'DELETE'); csrf=''; location.reload();});
el('refresh').onclick = () => run(refresh);
el('create').onclick = () => run(async () => {await api('/account/spaces/create',{display_name:el('space-name').value}); await refresh();});
for (const action of ['claim','unlink','recover']) el(action).onclick = () => run(async () => {
  const owner = el('owner-key').value; el('owner-key').value='';
  await api(`/account/spaces/${action}`,{space_id:el('space-id').value,owner_credential:owner}); await refresh();
});
el('agent-create').onclick=()=>run(async()=>{
  const result=await api('/account/agents/create',{request_id:crypto.randomUUID(),display_name:el('agent-name').value});
  el('actor-id').value=result.actor_id;el('consumer-id').value=result.consumer_id;
  el('status').textContent='Agent identity created. Use these IDs when approving your device.';
});
el('device-code').oninput=()=>{inspectedCode=null;el('approve').disabled=true;};
el('inspect').onclick=()=>run(async()=>{
  inspectedCode=null;el('approve').disabled=true;
  const code=el('device-code').value;
  const info=await api('/account/devices/inspect',{user_code:code});
  el('device-info').textContent=JSON.stringify(info,null,2);
  inspectedCode=code;el('approve').disabled=false;
});
el('approve').onclick=()=>run(async()=>{
  if(!inspectedCode || inspectedCode!==el('device-code').value) throw new Error('Inspect the device first.');
  await api('/account/devices/approve',{user_code:inspectedCode,actor_id:el('actor-id').value,consumer_id:el('consumer-id').value});
  inspectedCode=null;el('approve').disabled=true;el('status').textContent='Approved. Return to your device to finish pairing.';
});
el('devices').onclick=()=>run(async()=>{
  el('device-list').replaceChildren();let cursor=null;
  do {
    const page=await api('/account/devices/list',cursor ? {cursor} : {});
    for (const device of page.devices) {
      const li=document.createElement('li');
      li.textContent=`${device.display_name} (${device.device_id}) ${device.state} `;
      const button=document.createElement('button');button.textContent='Revoke';
      button.onclick=()=>run(async()=>{await api('/account/devices/revoke',{device_id:device.device_id});button.disabled=true;});
      li.append(button);el('device-list').append(li);
    }
    cursor=page.has_more?page.next_cursor:null;
  } while(cursor);
});
el('oauth-inspect').onclick = () => run(reviewOAuth);
el('oauth-dismiss').onclick = clearOAuthHint;
for (const decision of ['approve','deny']) el('oauth-'+decision).onclick = () => run(async () => {
  if (!oauthPreview || !oauthRequest) throw new Error('Review the request first.');
  const requestId = oauthRequest; resetOAuthConsent();
  const result = await oauthApi('/oauth/consent', {request_id:requestId,decision, ...(decision==='approve'?{actor_id:el('actor-id').value,consumer_id:el('consumer-id').value}:{})});
  // The server returns only the exact pre-registered destination after binding checks.
  const target = new URL(result.redirect_uri);
  if (!['https:','http:'].includes(target.protocol)) throw new Error('Invalid authorization redirect.');
  clearOAuthHint(); location.assign(target.href);
});
el('oauth-device-code').oninput = () => {oauthRevision++; oauthDeviceCode=null; el('oauth-device-approve').disabled=true; el('oauth-device-deny').disabled=true;};
el('oauth-device-inspect').onclick = () => run(async () => {
  el('oauth-device-code').oninput();
  const code = el('oauth-device-code').value, revision = oauthRevision;
  const info = await oauthApi('/oauth/device_consent',{action:'inspect',user_code:code});
  if (code !== el('oauth-device-code').value || revision !== oauthRevision) return;
  el('oauth-device-info').textContent = JSON.stringify(info,null,2);
  oauthDeviceCode=code; el('oauth-device-approve').disabled=false; el('oauth-device-deny').disabled=false;
});
for (const action of ['approve','deny']) el('oauth-device-'+action).onclick = () => run(async () => {
  if (!oauthDeviceCode || oauthDeviceCode!==el('oauth-device-code').value) throw new Error('Inspect the OAuth device first.');
  const code=oauthDeviceCode; el('oauth-device-code').oninput();
  await oauthApi('/oauth/device_consent',{action,user_code:code,...(action==='approve'?{actor_id:el('actor-id').value,consumer_id:el('consumer-id').value}:{})});
  el('status').textContent=action==='approve'?'OAuth device approved. Return to your client.':'OAuth device denied.';
});
run(refresh);
