#!/usr/bin/env python3
"""Local-only standard OAuth smoke against actual Workerd; synthetic account, not IdP/host.

Requires isolated migrations, account-preview seed, and preregistered local-mcp-test
callback http://127.0.0.1:8765/callback. Never prints credentials.
"""
import base64
import hashlib
import json
import secrets
import urllib.error
import urllib.parse
import urllib.request

BASE = 'http://127.0.0.1:8793'
RESOURCE = BASE + '/mcp'
CLIENT = 'local-mcp-test'
REDIRECT = 'http://127.0.0.1:8765/callback'
COOKIE = 'waypost_account=' + 'c' * 43

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect)

def request(path, body=None, form=False, cookie=None, csrf=None, token=None):
    headers = {}
    if cookie:
        headers.update(Cookie=cookie, Origin=BASE)
    if csrf:
        headers['X-Waypost-CSRF'] = csrf
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = None
    if body is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        data = (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
    try:
        r = opener.open(urllib.request.Request(BASE + path, data=data, headers=headers), timeout=20)
    except urllib.error.HTTPError as e:
        r = e
    raw = r.read()
    return r.status, r.headers, json.loads(raw) if raw and r.status != 302 else None

status, headers, _ = request('/mcp', {'jsonrpc':'2.0','id':1,'method':'tools/list'})
assert status == 401 and 'resource_metadata' in headers['WWW-Authenticate']
assert request('/.well-known/oauth-protected-resource/mcp')[2]['resource'] == RESOURCE
assert request('/.well-known/oauth-authorization-server')[2]['code_challenge_methods_supported'] == ['S256']
csrf = request('/account/session', cookie=COOKIE)[2]['data']['csrf_token']
verifier = secrets.token_urlsafe(32)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
state = secrets.token_urlsafe(16)
params = dict(client_id=CLIENT, redirect_uri=REDIRECT, response_type='code', resource=RESOURCE, scope='waypost', state=state, code_challenge=challenge, code_challenge_method='S256')
status, headers, _ = request('/oauth/authorize?' + urllib.parse.urlencode(params))
assert status == 303
browser = headers['Set-Cookie'].split(';')[0]
request_id = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)['oauth_request'][0]
owner = COOKIE + '; ' + browser
assert request('/oauth/consent?request_id=' + request_id, cookie=owner)[0] == 200
status, _, consent = request('/oauth/consent', dict(request_id=request_id, decision='approve', actor_id='actor_test', consumer_id='consumer_test'), cookie=owner, csrf=csrf)
assert status == 200
callback = urllib.parse.parse_qs(urllib.parse.urlparse(consent['redirect_uri']).query)
assert callback['state'] == [state] and callback['iss'] == [BASE]
params = dict(grant_type='authorization_code', client_id=CLIENT, redirect_uri=REDIRECT, resource=RESOURCE, code=callback['code'][0], code_verifier=verifier)
status, _, issued = request('/oauth/token', params, form=True)
assert status == 200
status, _, mcp = request('/mcp', {'jsonrpc':'2.0','id':2,'method':'tools/list'}, token=issued['access_token'])
assert status == 200 and 'result' in mcp
params = dict(grant_type='refresh_token', client_id=CLIENT, resource=RESOURCE, refresh_token=issued['refresh_token'])
status, _, refreshed = request('/oauth/token', params, form=True)
assert status == 200 and refreshed['refresh_token'] != issued['refresh_token']
assert request('/oauth/token', params, form=True)[2]['error'] == 'invalid_grant'
assert request('/v0/describe', token=refreshed['access_token'])[0] == 401
status, _, device = request('/oauth/device_authorization', dict(client_id=CLIENT, resource=RESOURCE), form=True)
assert status == 200
assert request('/oauth/device_consent', dict(action='approve', user_code=device['user_code'], actor_id='actor_test', consumer_id='consumer_test'), cookie=COOKIE, csrf=csrf)[0] == 200
params = dict(grant_type='urn:ietf:params:oauth:grant-type:device_code', client_id=CLIENT, resource=RESOURCE, device_code=device['device_code'])
status, _, issued = request('/oauth/token', params, form=True)
assert status == 200
assert request('/v0/describe', token=issued['access_token'])[0] == 200
assert request('/oauth/revoke', dict(client_id=CLIENT, token=issued['refresh_token']), form=True)[0] == 200
assert request('/v0/describe', token=issued['access_token'])[0] == 401
print(json.dumps({'result':'passed','runtime':'actual local Workerd/D1','identity':'synthetic seeded account, not real IdP or host','checks':['discovery','401 challenge','browser-bound consent','S256 exchange','MCP tools/list','refresh rotation and replay family revocation','RFC8628 device grant','RFC7009 revoke']}))
