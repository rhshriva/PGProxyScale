#!/usr/bin/env python3
"""Isolated short-lived file/broker/environment credential fixture, public test secrets only."""
import argparse, base64, hashlib, hmac, json, pathlib, time
p=argparse.ArgumentParser();p.add_argument('directory',type=pathlib.Path);p.add_argument('--backend-port',type=int,default=55439);a=p.parse_args()
a.directory.mkdir(parents=True,exist_ok=True)
def verifier(password):
    salt=b'pgproxy-credential-test';key=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,4096)
    client=hmac.new(key,b'Client Key','sha256').digest();server=hmac.new(key,b'Server Key','sha256').digest()
    enc=lambda b:base64.b64encode(b).decode()
    return f'SCRAM-SHA-256$4096:{enc(salt)}${enc(hashlib.sha256(client).digest())}:{enc(server)}'
lease=a.directory/'lease.json';lease.write_text(json.dumps({'user':'pgproxy_credential_a','password':'pgproxy-credential-test-a','expires_at':int(time.time())+3600}));lease.chmod(0o600)
broker=a.directory/'broker.py';broker.write_text('import pathlib,sys\nsys.stdout.write(pathlib.Path(sys.argv[1]).read_text())\n')
quote=json.dumps
routes=[]
for name,provider in [('credential_file',f'kind = "file"\npath = {quote(str(lease))}'),('credential_command',f'kind = "command"\nprogram = "/usr/bin/python3"\nargs = [{quote(str(broker))}, {quote(str(lease))}]\ntimeout_secs = 2'),('credential_environment','kind = "environment"\npassword_variable = "PGPROXY_CREDENTIAL_TEST_PASSWORD"\nttl_secs = 2')]:
    routes.append(f'''[[databases]]
name = "{name}"
host = "127.0.0.1"
port = {a.backend_port}
dbname = "conformance"
pool_mode = "transaction"
client_auth = "scram-sha256"
auth_users = {{ postgres = "{verifier('pgproxy-client-test')}", other = "{verifier('pgproxy-client-test')}" }}
user = "pgproxy_credential_a"
pool_size = 1
connect_timeout_secs = 3
[databases.credential_provider]
{provider}
''')
(a.directory/'proxy.toml').write_text('''[general]
listen_addr = "127.0.0.1"
listen_port = 6447
workers = 2
max_backend_connections = 6
[general.session]
cost_attribution = true
[operations]
listen = "127.0.0.1:6455"
token = "pgproxy-credential-usage-test-token-123456789"
[logging]
level = "info"
format = "text"
'''+ '\n'.join(routes))
print(a.directory/'proxy.toml')
