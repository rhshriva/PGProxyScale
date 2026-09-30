#!/usr/bin/env python3
"""Generate disposable TLS acceptance fixtures and a matching proxy configuration.

Usage: PGPROXY_AREA_PASSWORD=... python3 security_fixtures.py /tmp/test-tls
Requires openssl. Contains only test identities; never use these certificates in production.
"""
import argparse
import base64
import hashlib
import hmac
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('directory', type=Path)
parser.add_argument('--backend-host', default='127.0.0.1')
parser.add_argument('--backend-port', type=int, default=55439)
args = parser.parse_args()
root = args.directory.resolve()
root.mkdir(parents=True, exist_ok=True)
if any(root.iterdir()):
    raise SystemExit('Use an empty directory to avoid replacing existing certificates.')
secret = os.environ['PGPROXY_AREA_PASSWORD'].encode()

def openssl(*options):
    subprocess.run(['openssl', *options], cwd=root, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:host.docker.internal',
        '-keyout', 'server-key.pem', '-out', 'server.pem')
openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=Acceptance Client CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-keyout', 'ca-key.pem', '-out', 'ca.pem')
(root / 'client.ext').write_text('extendedKeyUsage=clientAuth\n')
for name in ['client', 'other']:
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + name,
            '-keyout', name + '-key.pem', '-out', name + '.csr')
    openssl('x509', '-req', '-in', name + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca-key.pem',
            '-CAcreateserial', '-days', '1', '-extfile', 'client.ext', '-out', name + '.pem')
openssl('x509', '-in', 'client.pem', '-outform', 'DER', '-out', 'client.der')
fingerprint = hashlib.sha256((root / 'client.der').read_bytes()).hexdigest()
salt = os.urandom(16)
key = hashlib.pbkdf2_hmac('sha256', secret, salt, 4096)
b64 = lambda value: base64.b64encode(value).decode()
verifier = ('SCRAM-SHA-256$4096:' + b64(salt) + '$' +
            b64(hashlib.sha256(hmac.digest(key, b'Client Key', 'sha256')).digest()) + ':' +
            b64(hmac.digest(key, b'Server Key', 'sha256')))
import json
q = json.dumps
config = f'''[general]
listen_addr = "0.0.0.0"
listen_port = 6440
workers = 2
[general.tls]
certificate = {q(str(root / 'server.pem'))}
private_key = {q(str(root / 'server-key.pem'))}
client_ca = {q(str(root / 'ca.pem'))}
required = true
'''
for route, mode, method, credential in [
    ('areas_scram', 'transaction', 'scram-sha256', verifier),
    ('areas_scram_session', 'session', 'scram-sha256', verifier),
    ('areas_certificate', 'transaction', 'certificate', fingerprint),
]:
    config += f'''\n[[databases]]
name = {q(route)}
host = {q(args.backend_host)}
port = {args.backend_port}
dbname = "conformance"
pool_mode = {q(mode)}
client_auth = {q(method)}
pool_size = 2
auth_users = {{ postgres = {q(credential)} }}
'''
(root / 'proxy.toml').write_text(config)
for private in root.glob('*key.pem'):
    private.chmod(0o600)
print(root / 'proxy.toml')
