#!/usr/bin/env python3
"""Verify MCP uses the same trusted role/RLS/timeout context as wire clients."""
import argparse
import json
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--database', default='policy_rls')
    args = parser.parse_args()
    for user, expected in [('postgres', '42'), ('other', '84')]:
        requests = []
        for index, (name, arguments) in enumerate([
            ('query', {'sql': 'SELECT id FROM public.pgproxy_rls_tenants'}),
            ('query', {'sql': 'SELECT secret FROM public.pgproxy_rls_tenants'}),
            ('describe_schema', {}),
            ('query', {'sql': 'SELECT pg_catalog.pg_sleep(2)'}),
        ], 1):
            requests.append(dict(jsonrpc='2.0', id=index, method='tools/call', params=dict(name=name, arguments=arguments)))
        started = time.monotonic()
        process = subprocess.run([args.binary, '--config', args.config, '--mcp-stdio', '--mcp-database', args.database, '--mcp-user', user],
                                 input=''.join(json.dumps(request) + '\n' for request in requests), text=True, capture_output=True, timeout=30)
        assert process.returncode == 0, process.stderr
        responses = [json.loads(line)['result'] for line in process.stdout.splitlines() if line.strip()]
        assert len(responses) == 4, process.stdout
        assert responses[0]['isError'] is False, responses[0]
        rows = json.loads(responses[0]['content'][0]['text'])
        assert [row['values'][0] for row in rows] == [expected], rows
        assert responses[1]['isError'] is True, responses[1]
        assert responses[2]['isError'] is False and 'secret' not in responses[2]['content'][0]['text'], responses[2]
        assert responses[3]['isError'] is True, responses[3]
        assert time.monotonic() - started >= 1.3, 'trusted timeout query did not execute'
        print(f'PASS {user}: isolated rows, protected columns, filtered schema, tenant timeout')
    print('8/8 MCP RLS checks passed')


if __name__ == '__main__':
    main()
