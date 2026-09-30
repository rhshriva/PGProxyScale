#!/usr/bin/env python3
"""Run authenticated MCP stdio checks against the actual PGProxyScale executable."""
import argparse
import json
import subprocess
import pathlib
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--database', default='policy_app')
    parser.add_argument('--user', default='postgres')
    parser.add_argument('--limits', action='store_true', help='derive a one-second test configuration and allow safe test functions')
    args = parser.parse_args()
    commands = [
        ('initialize', {'method': 'initialize', 'params': {'protocolVersion': '2024-11-05', 'capabilities': {}, 'clientInfo': {'name': 'acceptance', 'version': '1'}}}, True),
        ('tool discovery', {'method': 'tools/list'}, True),
        ('permitted query', {'method': 'tools/call', 'params': {'name': 'query', 'arguments': {'sql': 'SELECT id FROM public.policy_allowed'}}}, True),
        ('protected column', {'method': 'tools/call', 'params': {'name': 'query', 'arguments': {'sql': 'SELECT secret FROM public.policy_allowed'}}}, False),
        ('filtered schema', {'method': 'tools/call', 'params': {'name': 'describe_schema', 'arguments': {}}}, True),
        ('safe explain', {'method': 'tools/call', 'params': {'name': 'explain', 'arguments': {'sql': 'SELECT id FROM public.policy_allowed'}}}, True),
        ('principal override', {'method': 'tools/call', 'params': {'name': 'query', 'arguments': {'sql': 'SELECT 1', 'principal': 'admin'}}}, False),
        ('dangerous function', {'method': 'tools/call', 'params': {'name': 'query', 'arguments': {'sql': "SELECT pg_catalog.pg_read_file('/etc/passwd')"}}}, False),
        ('explain analyze refused', {'method': 'tools/call', 'params': {'name': 'explain', 'arguments': {'sql': 'EXPLAIN ANALYZE SELECT 1'}}}, False),
        ('unknown tool', {'method': 'tools/call', 'params': {'name': 'admin', 'arguments': {}}}, False),
    ]
    config_path = args.config
    fixture = None
    if args.limits:
        text = pathlib.Path(args.config).read_text()
        if '[general.session]' in text:
            raise AssertionError('limits fixture expects no existing general.session section')
        text = text.replace('[[databases]]', '[general.session]\nquery_timeout_secs = 1\n[[databases]]', 1)
        text = text.replace('functions = ["pg_catalog.pg_sleep"]', 'functions = ["pg_catalog.pg_sleep", "pg_catalog.generate_series", "pg_catalog.repeat"]')
        fixture = tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False)
        fixture.write(text)
        fixture.close()
        config_path = fixture.name
        for name, sql, allowed in [
            ('small series', 'SELECT pg_catalog.generate_series(1,2)', True),
            ('small string', "SELECT pg_catalog.repeat('x',2)", True),
            ('short sleep', 'SELECT pg_catalog.pg_sleep(0)', True),
            ('query timeout', 'SELECT pg_catalog.pg_sleep(2)', False),
            ('row ceiling', 'SELECT pg_catalog.generate_series(1,1001)', False),
            ('byte ceiling', "SELECT pg_catalog.repeat('x',1100000)", False),
        ]:
            commands.append((name, {'method': 'tools/call', 'params': {'name': 'query', 'arguments': {'sql': sql}}}, allowed))
    requests = [dict(jsonrpc='2.0', id=index, **command) for index, (_, command, _) in enumerate(commands, 1)]
    started = time.monotonic()
    result = subprocess.run([args.binary, '--config', config_path, '--mcp-stdio', '--mcp-database', args.database, '--mcp-user', args.user],
                            input=''.join(json.dumps(request) + '\n' for request in requests), text=True, capture_output=True, timeout=90)
    if fixture:
        pathlib.Path(fixture.name).unlink()
        assert time.monotonic() - started >= 0.8, 'timeout fixture did not execute the query'
    responses = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    if len(responses) != len(commands):
        raise AssertionError(f'Expected {len(commands)} responses, got {len(responses)}: {result.stderr}')
    failures = []
    for (name, _, allowed), response in zip(commands, responses):
        payload = response.get('result', {})
        okay = 'error' not in response and not payload.get('isError', False)
        if okay != allowed:
            failures.append(name)
            print(f'FAIL {name}: {response}')
            continue
        if name == 'permitted query':
            assert '42' in payload['content'][0]['text'], response
        if name == 'filtered schema':
            text = payload['content'][0]['text']
            assert 'secret' not in text and 'id' in text, response
        if name == 'tool discovery':
            assert {tool['name'] for tool in payload['tools']} == {'query', 'explain', 'describe_schema'}
        print(f'PASS {name}')
    print(f'{len(commands)-len(failures)}/{len(commands)} MCP checks passed')
    if result.returncode or failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
