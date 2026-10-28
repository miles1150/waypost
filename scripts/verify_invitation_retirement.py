#!/usr/bin/env python3
"""Fixed-loopback smoke; no production configuration/credentials or real IdP.

Run against isolated Workerd on8793; use --expected after explicitly switching
its local WAYPOST_ONBOARDING_MODE. Legacy checks are read-only.
"""
import argparse
import json
import urllib.error
import urllib.request

BASE = 'http://127.0.0.1:8793'


def request(path, body=None, method=None):
    req = urllib.request.Request(
        BASE + path, data=None if body is None else json.dumps(body).encode(),
        method=method, headers={'Content-Type': 'application/json'})
    try:
        response = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    return response.status, response.headers, response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected', choices=['accounts', 'legacy'], required=True)
    expected = parser.parse_args().expected
    status, headers, raw = request('/onboarding')
    assert status == 200 and headers['Cache-Control'] == 'no-store'
    data = json.loads(raw)['data']
    assert data['invitations_enabled'] == (expected == 'legacy')
    if expected == 'accounts':
        assert data['accounts_enabled'] and data['account_url'] == '/account'
        for method, path in [
            ('POST', '/admin/access-request'),
            ('POST', '/admin/invitation'),
            ('POST', '/admin/v0/access-requests'),
            ('POST', '/admin/v0/spaces/space_test/invitations'),
            ('POST', '/admin/v0/spaces/space_test/invitations/'),
            ('DELETE', '/admin/v0/spaces/space_test/invitations/missing'),
        ]:
            status, headers, raw = request(path, {}, method)
            assert status == 410, path
            assert headers['Cache-Control'] == 'no-store'
            assert json.loads(raw)['error']['code'] == 'INVITATIONS_RETIRED'
    else:
        assert request('/admin/invitation')[0] == 404
    status, _, html = request('/dashboard/')
    assert status == 200 and b'id="account-setup"' in html
    print(json.dumps({'result': 'passed', 'runtime': 'isolated Workerd/D1 and Static Assets',
                      'mode': expected, 'real_idp_or_production': False}))


if __name__ == '__main__':
    main()
