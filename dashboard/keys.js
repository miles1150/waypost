'use strict';
// keyenv-remote consent and connection management. All text is set with
// textContent; nothing from the server is parsed as HTML.
const el = (id) => document.getElementById(id);
const hintKey = 'keyenv-remote.oauth.request';
let csrf = null;
let request = null;

function status(text) { el('status').textContent = text || ''; }
function readHint() {
  const incoming = new URL(location.href).searchParams.get('oauth_request');
  let hint = incoming;
  try { hint = incoming || sessionStorage.getItem(hintKey); } catch (_) {}
  if (hint && /^oauth_[A-Za-z0-9_-]{1,128}$/.test(hint)) {
    try { sessionStorage.setItem(hintKey, hint); } catch (_) {}
    return hint;
  }
  return null;
}
function clearHint() {
  try { sessionStorage.removeItem(hintKey); } catch (_) {}
  const url = new URL(location.href); url.searchParams.delete('oauth_request'); history.replaceState(null, '', url);
}
async function api(path, body, method) {
  const headers = {};
  if (body !== undefined) { headers['content-type'] = 'application/json'; }
  if (csrf && (method || 'GET') !== 'GET') { headers['x-waypost-csrf'] = csrf; }
  const response = await fetch(path, {method: method || 'GET', headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body)});
  let data = null;
  try { data = await response.json(); } catch (_) {}
  return {status: response.status, data};
}
function cell(text) { const td = document.createElement('td'); td.textContent = text; return td; }
function box(cls) { const td = document.createElement('td'); const input = document.createElement('input'); input.type = 'checkbox'; input.className = cls; td.append(input); return td; }

async function showConsent() {
  const {status: code, data} = await api('/oauth/consent?request_id=' + encodeURIComponent(request));
  if (code !== 200) { status('This authorization request is no longer valid. Start the connection again from your app.'); clearHint(); return; }
  el('client-name').textContent = data.client_name;
  el('client-detail').textContent = data.client_kind === 'metadata_document' ? data.client_host + ' (' + data.client_id + ')' : data.client_id + ' (' + data.client_kind.replace(/_/g, ' ') + ')';
  el('redirect-host').textContent = data.redirect_host || '';
  el('scope').textContent = data.scope;
  el('warnings').replaceChildren(...data.client_warnings.concat([data.warning]).map((w) => { const li = document.createElement('li'); li.textContent = w; return li; }));
  const rows = data.vault.entries.map((entry) => {
    const tr = document.createElement('tr'); tr.dataset.name = entry.name;
    const label = entry.name + (entry.purpose ? ' — ' + entry.purpose : '') + (entry.disabled ? ' (disabled)' : '');
    tr.append(cell(label), cell(entry.fields.join(', ')), box('read'), box('write'));
    return tr;
  });
  el('entries').replaceChildren(...rows);
  const scopes = data.scope.split(' ');
  for (const input of document.querySelectorAll('#all-read, .read')) input.disabled = !scopes.includes('keys:read');
  for (const input of document.querySelectorAll('#all-write, #can-create, .write')) input.disabled = !scopes.includes('keys:write');
  el('consent').hidden = false;
}
async function decide(decision) {
  el('approve').disabled = true; el('deny').disabled = true;
  const body = {request_id: request, decision};
  if (decision === 'approve') {
    body.all_read = el('all-read').checked; body.all_write = el('all-write').checked; body.can_create = el('can-create').checked;
    body.entries = [...document.querySelectorAll('#entries tr')].map((tr) => ({name: tr.dataset.name, read: tr.querySelector('.read').checked, write: tr.querySelector('.write').checked})).filter((e) => e.read || e.write);
  }
  const {status: code, data} = await api('/oauth/consent', body, 'POST');
  if (code === 200 && data && data.redirect_uri) { clearHint(); location.assign(data.redirect_uri); return; }
  el('approve').disabled = false; el('deny').disabled = false;
  if (data && data.error === 'invalid_request' && decision === 'approve') { status('Choose at least one permission.'); return; }
  status('Approval needs a sign-in from the last 15 minutes. Sign in again; if the request has expired, start the connection again from your app.');
  el('signin').hidden = false;
}
async function showGrants() {
  const {status: code, data} = await api('/account/keys/grants');
  if (code !== 200) return;
  const items = data.data.grants.map((g) => {
    const li = document.createElement('li');
    const what = [g.all_read ? 'read all' : '', g.all_write ? 'change all' : '', g.can_create ? 'create' : '', ...g.entries.map((e) => e.name + ':' + (e.read ? 'r' : '') + (e.write ? 'w' : ''))].filter(Boolean).join(', ');
    li.textContent = g.client_id + ' — ' + g.scope + ' — ' + what + ' ';
    const revoke = document.createElement('button'); revoke.type = 'button'; revoke.textContent = 'Revoke';
    revoke.onclick = async () => { await api('/account/keys/grants/revoke', {grant_id: g.grant_id}, 'POST'); showGrants(); };
    li.append(revoke); return li;
  });
  el('grant-list').replaceChildren(...items);
  el('grants').hidden = false;
}
el('login').onclick = async () => {
  const {status: code, data} = await api('/account/login', {}, 'POST');
  if (code === 200 && data && data.data) location.assign(data.data.authorization_url); else status('Sign-in is not available.');
};
el('approve').onclick = () => decide('approve');
el('deny').onclick = () => decide('deny');
el('logout').onclick = async () => { await api('/account/session', undefined, 'DELETE'); location.reload(); };
el('all-read').onchange = el('all-write').onchange = () => {
  for (const input of document.querySelectorAll('.read')) { if (el('all-read').checked) input.checked = true; }
  for (const input of document.querySelectorAll('.write')) { if (el('all-write').checked) input.checked = true; }
};

(async () => {
  request = readHint();
  const session = await api('/account/session');
  if (session.status !== 200) { el('signin').hidden = false; return; }
  csrf = session.data.data.csrf_token;
  if (request) await showConsent(); else await showGrants();
})();
