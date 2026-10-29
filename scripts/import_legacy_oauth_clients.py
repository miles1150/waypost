#!/usr/bin/env python3
"""Generate offline, idempotent SQL importing public pre-registered OAuth clients.

Input is the former WAYPOST_OAUTH_CLIENTS JSON (public metadata, never secrets).
Apply migration 0015 first. This command does not connect to any service. Inspect
and apply the output with the normal database migration process, then compare
registry metadata before removing the old runtime setting. Conflicting records
are never overwritten; disabling a client cannot be undone by rerunning import.
"""
import argparse
import hashlib
import json
import ipaddress
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def generate(config, timestamp):
    if not isinstance(config, dict) or set(config) != {'clients'}:
        raise ValueError('Expected only a clients array')
    clients = config['clients']
    if not isinstance(clients, list) or not 1 <= len(clients) <= 32:
        raise ValueError('Expected 1..32 legacy clients')
    if type(timestamp) is not int or not 0 <= timestamp <= 2**53-1:
        raise ValueError('Invalid timestamp')
    statements = ['-- Public metadata only. Requires migration 0015. Never overwrites existing clients.']
    seen = set()
    for client in clients:
        if not isinstance(client, dict) or set(client) - {'client_id', 'name', 'redirect_uris', 'allow_loopback_port_variation'}:
            raise ValueError('Unexpected legacy fields; do not supply credentials')
        identifier, name = client.get('client_id'), client.get('name')
        for value in (identifier, name):
            if not isinstance(value, str) or not value or len(value.encode()) > 200 or any(unicodedata.category(c) == "Cc" for c in value):
                raise ValueError('Invalid public client identifier or name')
        if identifier in seen:
            raise ValueError('Duplicate client identifier')
        seen.add(identifier)
        redirects = client.get('redirect_uris')
        variation = client.get('allow_loopback_port_variation', False)
        if type(variation) is not bool or not isinstance(redirects, list) or not 0 <= len(redirects) <= 8:
            raise ValueError('Invalid redirect policy')
        for uri in redirects:
            if not isinstance(uri, str) or not uri.isascii() or len(uri.encode()) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in uri) or any(c in uri for c in ('?', '#', chr(92))):
                raise ValueError('Invalid redirect URI')
            parsed = urlsplit(uri)
            host = parsed.hostname or ''
            if ':' in host:
                host = '[' + ipaddress.IPv6Address(host).compressed + ']'
            port = parsed.port
            canonical_netloc = host + (':' + str(port) if port is not None and port != {'https': 443, 'http': 80}.get(parsed.scheme) else '')
            if parsed.geturl() != uri or parsed.netloc != canonical_netloc or not parsed.path.startswith('/') or any(segment.lower().replace('%2e', '.') in ('.', '..') for segment in parsed.path.split('/')):
                raise ValueError('Redirect URI must already be canonical')
            if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                    or parsed.query or parsed.fragment or parsed.port == 0
                    or not (parsed.scheme == 'https' or parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', '::1', 'localhost'))):
                raise ValueError('Unsafe redirect URI')
        if len(set(redirects)) != len(redirects):
            raise ValueError('Duplicate redirect URI')
        metadata = dict(client_id=identifier, client_name=name, redirect_uris=redirects,
                        token_endpoint_auth_method='none', grant_types=['authorization_code', 'refresh_token'],
                        response_types=['code'], scope='waypost')
        raw = json.dumps(metadata, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        fingerprint = hashlib.sha256(raw.encode()).hexdigest()
        values = ','.join([literal(identifier), "'legacy'", literal(raw), literal(fingerprint),
                           '0', str(2**53-1), str(int(variation)), str(timestamp), str(timestamp)])
        statements.append('INSERT INTO oauth_dynamic_clients(client_id,source,metadata_json,security_fingerprint,revision,valid_until,allow_loopback_port_variation,created_at,updated_at) VALUES('
                          + values + ') ON CONFLICT(client_id) DO NOTHING;')
    return '\n'.join(statements) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path, help='Public legacy client JSON file')
    parser.add_argument('--created-at-ms', type=int, required=True)
    args = parser.parse_args()
    try:
        raw = args.config.read_bytes()
        if len(raw) > 65536:
            raise ValueError('Input too large')
        output = generate(json.loads(raw), args.created_at_ms)
    except (ValueError, OSError):
        parser.exit(2, 'Invalid public client configuration; no SQL generated.\n')
    print(output, end='')


if __name__ == '__main__':
    main()
