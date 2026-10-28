'use strict';
const el = id => document.getElementById(id);
let csrf = '';
let inspectedCode = null;
async function api(path, body, method = 'POST') {
  const response = await fetch(path, {method, credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-Waypost-CSRF': csrf}, ...(method === 'GET' ? {} : {body: JSON.stringify(body || {})})});
  const value = await response.json();
  if (!response.ok || !value.ok) throw new Error(value.error?.message || 'Request failed');
  return value.data;
}
async function refresh() {
  const data = await api('/account/session', null, 'GET');
  csrf = data.csrf_token;
  el('status').textContent = `Account: ${data.account_id}\nSelected Space: ${data.selected_space_id || 'none'}`;
  el('spaces').replaceChildren();
  for (const space of data.spaces) {
    const li = document.createElement('li');
    const button = document.createElement('button');
    button.textContent = `${space.display_name} (${space.space_id})`;
    button.onclick = () => run(async () => {await api('/account/spaces/select', {space_id: space.space_id}); await refresh();});
    li.append(button); el('spaces').append(li);
  }
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
run(refresh);
