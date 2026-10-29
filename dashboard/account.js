'use strict';
const el = id => document.getElementById(id);
let csrf = '';
let inspectedCode = null;
let managementRevision = 0;
let primarySelection = null;
function resetManagement() {
  managementRevision++; primarySelection=null;
  for(const kind of ['connections','oauth','actors','consumers']) {el('management-'+kind).replaceChildren();el('more-'+kind).hidden=true;}
  el('primary-clear').disabled=true;el('primary-info').textContent='';
}
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
  resetManagement();
  resetOAuthConsent();
  el('open-dashboard').hidden = true;
  el('dashboard-selection').textContent = 'Sign in and select a Space above before opening its dashboard.';
  const data = await api('/account/session', null, 'GET');
  csrf = data.csrf_token;
  el('status').textContent = `Account: ${data.account_id}\nSelected Space: ${data.selected_space_id || 'none'}`;
  const selected = data.spaces.find(space => space.space_id === data.selected_space_id);
  el('open-dashboard').hidden = !selected;
  el('open-dashboard').textContent = selected ? `Open dashboard: ${selected.display_name} (${selected.space_id})` : 'Open selected Space dashboard';
  el('dashboard-selection').textContent = selected ? `Selected Space: ${selected.display_name} (${selected.space_id})` : 'Select a Space above before opening its dashboard.';
  el('spaces').replaceChildren();
  for (const space of data.spaces) {
    const li = document.createElement('li');
    const button = document.createElement('button');
    button.textContent = `${space.space_id === data.selected_space_id ? 'Selected' : 'Select'}: ${space.display_name} (${space.space_id})`;
    button.onclick = () => run(async () => {resetManagement(); resetOAuthConsent(); el('open-dashboard').hidden = true; el('dashboard-selection').textContent = 'Selecting Space…'; await api('/account/spaces/select', {space_id: space.space_id}); await refresh();});
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

async function managementPage(kind, cursor=null, revision=managementRevision) {
  const identities=kind==='actors'||kind==='consumers';
  const endpoint=identities?'identities':kind;
  const body={...(identities?{kind}:{}),...(cursor?{cursor}:{})};
  const data=await api('/account/'+endpoint+'/list',body);
  if(revision!==managementRevision) return;
  if(identities) {
    primarySelection={space_id:data.space_id,expected_revision:data.primary_revision};
    el('primary-info').textContent='Primary assistant: '+(data.primary_actor_id||'none');
    el('primary-clear').disabled=false;
  }
  for(const item of data.items) {
    const li=document.createElement('li');li.textContent=JSON.stringify(item)+' ';
    const button=document.createElement('button');
    const id=kind==='connections'?item.token_id:kind==='oauth'?item.family_id:kind==='actors'?item.actor_id:item.consumer_id;
    button.textContent=identities?'Disable identity':'Revoke access';
    button.disabled=Boolean(item.disabled||item.revoked_at!==null && item.revoked_at!==undefined);
    button.onclick=()=>run(async()=>{
      if(revision!==managementRevision) throw new Error('Refresh the selected Space before changing access.');
      button.disabled=true;
      try {
        await api('/account/'+endpoint+(identities?'/disable':'/revoke'),{space_id:data.space_id,...(identities?{kind,identity_id:id}:kind==='connections'?{token_id:id}:{family_id:id})});
        el('status').textContent=identities?'Identity disabled.':'Access revoked.';
      } catch(error) {button.disabled=false;throw error;}
    });
    li.append(button);
    if(identities) {
      const use=document.createElement('button');use.textContent='Use for approval';use.disabled=item.disabled;
      use.onclick=()=>{if(revision!==managementRevision)return;el('actor-id').value=item.actor_id;if(kind==='consumers')el('consumer-id').value=item.consumer_id;};li.append(use);
    }
    if(kind==='actors'&&item.kind==='agent'&&!item.disabled) {
      const choose=document.createElement('button');choose.textContent='Make primary';
      choose.onclick=()=>run(async()=>{if(revision!==managementRevision)throw new Error('Refresh Actors first.');await api('/account/primary/set',{space_id:data.space_id,expected_revision:data.primary_revision,actor_id:item.actor_id});resetManagement();await managementPage('actors');});li.append(choose);
    }
    el('management-'+kind).append(li);
  }
  const more=el('more-'+kind);more.hidden=!data.has_more;
  more.onclick=()=>run(async()=>{more.disabled=true;try{await managementPage(kind,data.next_cursor,revision);}finally{more.disabled=false;}});
}
for(const kind of ['connections','oauth','actors','consumers']) el('manage-'+kind).onclick=()=>run(async()=>{el('management-'+kind).replaceChildren();el('more-'+kind).hidden=true;await managementPage(kind);});
el('primary-clear').onclick=()=>run(async()=>{if(!primarySelection)throw new Error('List Actors first.');await api('/account/primary/set',{...primarySelection,actor_id:null});resetManagement();await managementPage('actors');});
run(refresh);
