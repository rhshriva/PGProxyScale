#!/usr/bin/env python3
"""Create disposable server certificate rotation fixtures and a reload test config."""
import argparse
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('directory', type=Path)
parser.add_argument('--port', type=int, default=6444)
parser.add_argument('--operations-port', type=int, default=6452)
parser.add_argument('--backend-port', type=int, default=55439)
parser.add_argument('--backend-limit', type=int, default=2)
args = parser.parse_args()
root = args.directory.resolve()
root.mkdir(parents=True, exist_ok=True)
if any(root.iterdir()):
    raise SystemExit('Use an empty directory to avoid replacing existing fixtures.')

def openssl(*options):
    subprocess.run(['openssl', *options], cwd=root, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=Reload Acceptance CA', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-keyout', 'ca-key.pem', '-out', 'ca.pem')
(root / 'server.ext').write_text('basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1\n')
for index in [1, 2]:
    name = f'server-{index}'
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
            '-keyout', name + '-key.pem', '-out', name + '.csr')
    openssl('x509', '-req', '-in', name + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca-key.pem',
            '-set_serial', str(index), '-days', '1', '-extfile', 'server.ext', '-out', name + '.pem')
q = json.dumps
(root / 'proxy.toml').write_text(f'''[general]
listen_addr = "0.0.0.0"
listen_port = {args.port}
workers = 2
max_backend_connections = {args.backend_limit}
[general.session]
startup_timeout_secs = 2
[general.tls]
certificate = {q(str(root / 'server-1.pem'))}
private_key = {q(str(root / 'server-1-key.pem'))}
required = true
[operations]
listen = "127.0.0.1:{args.operations_port}"
token = "pgproxy-reload-test-token-0000000000"
[[databases]]
name = "reload_transaction"
host = "127.0.0.1"
port = {args.backend_port}
dbname = "conformance"
pool_mode = "transaction"
client_auth = "trust"
pool_size = 2
connect_timeout_secs = 1
checkout_timeout_secs = 1
require_primary = true
[[databases]]
name = "reload_session"
host = "127.0.0.1"
port = {args.backend_port}
dbname = "conformance"
pool_mode = "session"
client_auth = "passthrough"
''')
print(root / 'proxy.toml')
