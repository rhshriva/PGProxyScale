"""Source identity and authenticated external release evidence. No implicit trust anchors."""
import base64
import datetime as dt
import hashlib
import json
import math
import os
import stat
import pathlib
import re
import subprocess
import tempfile

KINDS = {
    'release_verification': 'release_builder',
    'independent_security_review': 'security_reviewer',
    'deployment_fencing': 'deployment_operator',
    'real_provider_integration': 'provider_operator',
    'bare_metal_performance_soak': 'performance_lab',
}
SURFACES = {'client-auth', 'tls', 'wire-protocol', 'sql-policy', 'session-isolation', 'provider-adapters'}
HEX = re.compile(r'^[0-9a-f]{64}$')

class EvidenceError(ValueError):
    pass

def require(condition, message):
    if not condition:
        raise EvidenceError(message)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def read_regular(path, max_bytes):
    path = pathlib.Path(path)
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= max_bytes, 'file missing, non-regular, or oversized')
            body = handle.read(max_bytes + 1)
            require(len(body) <= max_bytes, 'file oversized')
            return body
    except OSError as error:
        raise EvidenceError('evidence file unavailable') from error

def strict_json_bytes(body, max_bytes=1024 * 1024):
    require(len(body) <= max_bytes, 'JSON file oversized')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def invalid_number(value):
        raise EvidenceError('non-finite JSON number')
    return json.loads(body, object_pairs_hook=pairs, parse_constant=invalid_number)

def strict_json(path, max_bytes=1024 * 1024):
    return strict_json_bytes(read_regular(path, max_bytes), max_bytes)

def source_identity(root):
    root = pathlib.Path(root)
    entries = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root).split(b'\0')
    digest = hashlib.sha256()
    for entry in sorted(set(entries)):
        if not entry:
            continue
        path = pathlib.Path(entry.decode())
        if path.parts[0] in {'.git', 'target', 'docs', 'deliverables', 'dist', 'node_modules', '.venv'} or path.name in {'README.md', 'CHANGELOG.md', 'LICENSE', 'LICENSE-MIT', 'LICENSE-APACHE'} or '__pycache__' in path.parts:
            continue
        full = root / path
        if full.is_file():
            body = full.read_bytes()
            digest.update(len(entry).to_bytes(8, 'big'))
            digest.update(entry)
            digest.update(len(body).to_bytes(8, 'big'))
            digest.update(body)
    return digest.hexdigest()

def timestamp(value):
    require(isinstance(value, str), 'timestamp must be an explicit UTC string')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise EvidenceError('invalid timestamp') from error
    require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(), 'timestamp must be UTC')
    return parsed

def verify_signature(payload, signature, public_key):
    """RSA-PSS/SHA256 with digest-length salt; policy keys are provisioned out of band."""
    try:
        raw = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError) as error:
        raise EvidenceError('invalid signature encoding') from error
    require(384 <= len(raw) <= 1024, 'invalid RSA signature size')
    with tempfile.TemporaryDirectory(prefix='pgproxy-evidence-') as directory:
        path = pathlib.Path(directory)
        (path / 'payload').write_bytes(canonical(payload))
        (path / 'signature').write_bytes(raw)
        key_bytes = public_key if isinstance(public_key, bytes) else read_regular(public_key, 65536)
        (path / 'key.pem').write_bytes(key_bytes)
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(path / 'key.pem'), '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:digest', '-signature', str(path / 'signature'), str(path / 'payload')], capture_output=True, timeout=10)
    require(result.returncode == 0, 'signature verification failed')

def key_identity(public_key):
    key_bytes = public_key if isinstance(public_key, bytes) else read_regular(public_key, 65536)
    with tempfile.TemporaryDirectory(prefix='pgproxy-key-id-') as directory:
        path = pathlib.Path(directory) / 'key.pem'
        path.write_bytes(key_bytes)
        result = subprocess.run(['openssl', 'rsa', '-pubin', '-in', str(path), '-modulus', '-noout'], capture_output=True, timeout=10)
    match = re.fullmatch(rb'Modulus=([0-9A-F]+)\r?\n?', result.stdout)
    require(result.returncode == 0 and match is not None, 'RSA public key required')
    modulus = int(match[1], 16)
    require(3072 <= modulus.bit_length() <= 8192, 'RSA key size outside 3072–8192 bits')
    return hashlib.sha256(modulus.to_bytes((modulus.bit_length()+7)//8, 'big')).hexdigest()

def attachment(root, item):
    require(isinstance(item, dict) and set(item) == {'path', 'sha256'}, 'attachment needs path and SHA256')
    relative = pathlib.Path(item['path'])
    require(not relative.is_absolute() and '..' not in relative.parts and relative.parts, 'unsafe attachment path')
    require(HEX.fullmatch(item['sha256']) is not None, 'invalid attachment SHA256')
    root = pathlib.Path(root).resolve()
    path = root / relative
    require(not any((root / pathlib.Path(*relative.parts[:index])).is_symlink() for index in range(1, len(relative.parts) + 1)), 'symlink attachment rejected')
    # Hash the captured bytes once. All later parsing and signature verification
    # uses this immutable snapshot, never the attacker's mutable file path.
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts[:-1]:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(relative.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=descriptor)
        with os.fdopen(file_descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= 256 * 1024 * 1024, 'attachment non-regular or oversized')
            body = handle.read(256 * 1024 * 1024 + 1)
            require(len(body) <= 256 * 1024 * 1024, 'attachment oversized')
    finally:
        os.close(descriptor)
    require(hashlib.sha256(body).hexdigest() == item['sha256'], 'attachment hash mismatch')
    return body

def check_claim(kind, claim, policy, files, paths):
    require(isinstance(claim, dict), 'structured claims required')
    if kind == 'release_verification':
        require(claim.get('automated_report_sha256') in {value['sha256'] for value in files}, 'release report not bound to signed attachment')
        report = strict_json_bytes(paths[claim['automated_report_sha256']])
        require(report.get('source_sha256_start') == report.get('source_sha256_end') == report.get('source_sha256_after_all_gates') == policy['source_sha256'], 'automated source stability missing')
        require(policy['release_binary_sha256'] in report.get('binary_sha256', {}).values(), 'automated release binary identity missing')
        gates = {gate['name']: gate for gate in report.get('gates', [])}
        required = {'workspace-tests', 'strict-lint', 'release-build', 'build', 'replicated-failover', 'linux-tests-lint', 'source-stability', 'postgres-14-18-compatibility', 'postgres-14-18-tls-mtls-plus-rsa-pss'}
        require(required <= set(gates) and all(gates[name].get('status') == 'pass' for name in required), 'automated release gates incomplete')
        require(gates['workspace-tests'].get('tests_passed', 0) > 0 and gates['linux-tests-lint'].get('tests_passed', 0) > 0, 'automated tests missing')
        require(gates['replicated-failover'].get('checks_passed', 0) >= 5 and gates['postgres-14-18-compatibility'].get('checks_passed', 0) >= 260 and gates['postgres-14-18-tls-mtls-plus-rsa-pss'].get('checks_passed', 0) >= 48, 'automated acceptance coverage incomplete')
    elif kind == 'independent_security_review':
        require(SURFACES <= set(claim.get('tested_surfaces', [])), 'security surface coverage incomplete')
        findings = claim.get('findings')
        require(isinstance(findings, list), 'security findings list required')
        for finding in findings:
            require(finding.get('severity') in {'critical', 'high', 'medium', 'low', 'info'}, 'invalid severity')
            require(finding.get('id') and finding.get('disposition') in {'remediated', 'accepted', 'open'}, 'invalid finding disposition')
            if finding['severity'] == 'medium':
                require(finding['disposition'] != 'open', 'open medium security finding')
                if finding['disposition'] == 'accepted':
                    require(finding['id'] in policy.get('accepted_medium_findings', []) and finding.get('risk_acceptance_attachment_sha256') in {value['sha256'] for value in files}, 'medium risk acceptance not authorized')
            if finding['severity'] in {'critical', 'high'}:
                require(finding['disposition'] == 'remediated' and finding.get('remediation_attachment_sha256') in {value['sha256'] for value in files}, 'unremediated high/critical finding')
        require(claim.get('review_report_sha256') in {value['sha256'] for value in files}, 'independent report attachment missing')
    elif kind == 'deployment_fencing':
        transitions = claim.get('transitions', [])
        require(transitions, 'fencing transition observations missing')
        require({'primary_loss', 'network_partition', 'old_primary_rejoin'} <= set(claim.get('faults_tested', [])), 'fencing fault coverage incomplete')
        previous_epoch = -1
        for event in transitions:
            require(isinstance(event.get('epoch'), int) and event['epoch'] > previous_epoch, 'fence epochs must advance')
            previous_epoch = event['epoch']
            require(event.get('old_server') and event.get('new_server') and event['old_server'] != event['new_server'], 'distinct server identities required')
            require(timestamp(event['fence_confirmed_at']) <= timestamp(event['new_writer_enabled_at']), 'new writer enabled before fencing confirmation')
            require(event.get('authority_audit_sha256') in {value['sha256'] for value in files}, 'authoritative fencing audit missing')
            audit = strict_json_bytes(paths[event['authority_audit_sha256']])
            require(audit.get('deployment_id') == policy['deployment_id'] and audit.get('epoch') == event['epoch'] and audit.get('old_server') == event['old_server'], 'fencing authority identity mismatch')
            require(audit.get('fencing_method') in {'power_off', 'storage_isolation', 'quorum_lease'} and audit.get('operation_id') and audit.get('result') == 'confirmed' and audit.get('fence_confirmed_at') == event['fence_confirmed_at'], 'authoritative infrastructure fencing proof incomplete')
            observers = event.get('observers', [])
            require(len({observer.get('vantage_id') for observer in observers}) >= 2, 'multiple independent network vantage observations required')
            for observer in observers:
                require(observer.get('old_write_probe') in {'fenced_unreachable', 'read_only_rejected'} and observer.get('new_write_probe') == 'committed', 'fencing write probes incomplete')
                require(observer.get('trace_sha256') in {value['sha256'] for value in files}, 'vantage trace missing')
                trace = strict_json_bytes(paths[observer['trace_sha256']])
                require(trace.get('deployment_id') == policy['deployment_id'] and trace.get('epoch') == event['epoch'] and trace.get('vantage_id') == observer['vantage_id'] and trace.get('old_server') == event['old_server'] and trace.get('new_server') == event['new_server'], 'fencing observer identity mismatch')
                require(trace.get('old_write_probe') == observer['old_write_probe'] and trace.get('new_write_probe') == observer['new_write_probe'], 'fencing probe trace mismatch')
    elif kind == 'real_provider_integration':
        required = set(policy['required_providers'])
        observed = set()
        for provider in claim.get('providers', []):
            require(provider.get('kind') in {'aws_rds', 'vault'}, 'unknown real provider')
            require(provider.get('endpoint') and provider.get('identity'), 'real provider endpoint/identity missing')
            events = set(provider.get('observations', []))
            require({'authenticated', 'backend_tls_verified', 'lease_expiry_rotation', 'expired_lease_rejected', 'provider_failure_closed'} <= events, 'provider lifecycle coverage incomplete')
            require(provider.get('trace_sha256') in {value['sha256'] for value in files}, 'provider trace missing')
            trace = strict_json_bytes(paths[provider['trace_sha256']])
            require(trace.get('source_sha256') == policy['source_sha256'] and trace.get('release_binary_sha256') == policy['release_binary_sha256'] and trace.get('deployment_id') == policy['deployment_id'], 'provider trace deployment mismatch')
            require(trace.get('kind') == provider['kind'] and trace.get('endpoint') == provider['endpoint'] and trace.get('identity') == provider['identity'] and events <= set(trace.get('observations', [])), 'provider trace lifecycle mismatch')
            observed.add(provider['kind'])
        require(required <= observed, 'required provider integration missing')
    elif kind == 'bare_metal_performance_soak':
        require(claim.get('hardware_id') and claim.get('platform_class') == 'bare_metal', 'bare-metal identity required')
        require(claim.get('hardware_inventory_sha256') in {value['sha256'] for value in files}, 'hardware inventory missing')
        inventory = strict_json_bytes(paths[claim['hardware_inventory_sha256']])
        require(inventory.get('hardware_id') == claim['hardware_id'] and inventory.get('platform_class') == 'bare_metal' and inventory.get('virtualization_detected') is False and inventory.get('physical_inventory_ref'), 'independent physical hardware inventory incomplete')
        limits = policy['performance_limits']
        observed = set()
        for measurement in claim.get('workloads', []):
            name = measurement['name']
            require(name in limits, 'undeclared performance workload')
            limit = limits[name]
            require(measurement.get('duration_secs', 0) >= limit['min_duration_secs'] >= 3600, 'production soak too short')
            require(measurement.get('sample_count', 0) >= limit['min_samples'] > 0, 'insufficient samples')
            require(measurement.get('dropped_samples') == 0 and measurement.get('errors') == 0, 'performance samples lost or workload failed')
            require(0 < measurement.get('p99_ms', 0) <= limit['max_p99_ms'], 'latency SLO failed')
            require(measurement.get('throughput_ops_per_sec', 0) >= limit['min_throughput_ops_per_sec'] > 0, 'throughput SLO failed')
            require(measurement.get('measurement_sha256') in {value['sha256'] for value in files}, 'raw performance measurements missing')
            raw = strict_json_bytes(paths[measurement['measurement_sha256']], 256 * 1024 * 1024)
            require(raw.get('source_sha256') == policy['source_sha256'] and raw.get('release_binary_sha256') == policy['release_binary_sha256'] and raw.get('hardware_id') == claim['hardware_id'] and raw.get('name') == name, 'performance measurement identity mismatch')
            start, finish = raw['started_ns'], raw['finished_ns']
            require(type(start) is int and type(finish) is int, 'invalid raw measurement clock')
            duration = (finish - start) / 1e9
            require(duration > 0 and math.isclose(duration, measurement['duration_secs'], rel_tol=1e-9), 'raw measurement duration mismatch')
            if raw.get('format') == 'log_histogram_v1':
                require(raw.get('ratio') == 1.001 and raw.get('max_bins') == 40000 and raw.get('errors') == 0 and raw.get('dropped_samples') == 0, 'invalid or failed histogram')
                bins = raw.get('counts', [])
                require(1 <= len(bins) <= 40000, 'histogram empty or oversized')
                previous = -1
                total = 0
                for index, count in bins:
                    require(type(index) is int and type(count) is int and previous < index < 40000 and count > 0, 'invalid histogram count')
                    previous = index
                    total += count
                require(total == measurement['sample_count'], 'histogram sample count mismatch')
                accumulated = 0
                p99 = None
                for index, count in bins:
                    accumulated += count
                    if accumulated >= math.ceil(total*.99):
                        p99 = math.ceil(math.exp(index*math.log(1.001)))/1e6
                        break
            else:
                events = raw.get('events', [])
                require(len(events) == measurement['sample_count'] and raw.get('dropped_samples') == 0, 'raw measurement sample count mismatch')
                latencies = []
                for event in events:
                    require(len(event) == 3 and type(event[0]) is int and type(event[1]) is int and event[1] > 0 and event[2] is True and start <= event[0] < event[0] + event[1] <= finish, 'invalid raw workload event')
                    latencies.append(event[1] / 1e6)
                require(latencies, 'raw workload empty')
                total = len(events)
                p99 = sorted(latencies)[math.ceil(total*.99)-1]
            require(math.isclose(p99, measurement['p99_ms'], rel_tol=1e-9) and math.isclose(total/duration, measurement['throughput_ops_per_sec'], rel_tol=1e-9), 'raw percentile or throughput mismatch')
            observed.add(name)
        require(set(limits) <= observed and {'simple_select', 'prepared_select', 'transaction_rollback'} <= observed, 'required workload coverage missing')

def evaluate(policy_envelope, bundle, root, trust_root, source_sha256, release_sha256, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    policy = policy_envelope['payload']
    verify_signature(policy, policy_envelope['signature'], trust_root)
    require(policy.get('schema_version') == 1 and policy.get('policy_id'), 'unsupported trust policy')
    require(policy.get('source_sha256') == source_sha256 and policy.get('release_binary_sha256') == release_sha256, 'trust policy source/binary mismatch')
    require(timestamp(policy['created_at']) <= now < timestamp(policy['expires_at']), 'trust policy not current')
    require(policy.get('deployment_id') and policy.get('build_organization'), 'deployment and builder identity required')
    require(1 <= policy.get('max_evidence_age_days', 0) <= 90, 'evidence age policy invalid')
    require(set(policy.get('required_providers', [])) == {'aws_rds', 'vault'}, 'both real provider integrations required')
    require(isinstance(policy.get('performance_limits'), dict), 'explicit performance limits required')
    issuers = policy['issuers']
    keys = {}
    key_ids = {}
    root_identity = key_identity(trust_root)
    for key_id, issuer in issuers.items():
        key_file = attachment(root, issuer['public_key'])
        keys[key_id] = key_file
        key_ids[key_id] = key_identity(key_file)
        require(key_ids[key_id] != root_identity, 'trust root cannot double as evidence issuer')
        require(issuer.get('organization') and set(issuer.get('roles', [])) <= set(KINDS.values()), 'invalid trusted issuer scope')
        require(policy['deployment_id'] in issuer.get('deployments', []), 'issuer deployment not authorized')
    security_keys = {key_ids[key_id] for key_id, issuer in issuers.items() if 'security_reviewer' in issuer['roles']}
    builder_keys = {key_ids[key_id] for key_id, issuer in issuers.items() if 'release_builder' in issuer['roles']}
    require(security_keys.isdisjoint(builder_keys), 'security reviewer cannot reuse builder key')
    accepted = {}
    for envelope in bundle.get('attestations', []):
        payload = envelope['payload']
        kind = payload.get('kind')
        require(kind in KINDS and kind not in accepted, 'unknown or duplicate attestation kind')
        issuer_id = payload['issuer_id']
        require(issuer_id in issuers and KINDS[kind] in issuers[issuer_id]['roles'], 'issuer not authorized for evidence kind')
        issuer = issuers[issuer_id]
        if kind == 'independent_security_review':
            require(issuer['organization'] != policy['build_organization'], 'security review is internal, not independent')
        verify_signature(payload, envelope['signature'], keys[issuer_id])
        require(payload.get('schema_version') == 1 and payload.get('policy_id') == policy['policy_id'], 'attestation policy mismatch')
        require(payload.get('source_sha256') == source_sha256 and payload.get('release_binary_sha256') == release_sha256 and payload.get('deployment_id') == policy['deployment_id'], 'evidence source/binary/deployment mismatch')
        created, expires = timestamp(payload['created_at']), timestamp(payload['expires_at'])
        require(created <= now < expires and now - created <= dt.timedelta(days=policy['max_evidence_age_days']) and expires <= timestamp(policy['expires_at']), 'evidence stale or not current')
        files = payload.get('attachments', [])
        require(isinstance(files, list) and 1 <= len(files) <= 32, 'hashed evidence attachments required')
        paths = {item['sha256']: attachment(root, item) for item in files}
        check_claim(kind, payload.get('claims'), policy, files, paths)
        accepted[kind] = {'issuer_id': issuer_id, 'organization': issuer['organization'], 'attachments': files}
    missing = sorted(set(KINDS) - set(accepted))
    return {'production_certified': not missing, 'policy_id': policy['policy_id'], 'source_sha256': source_sha256, 'release_binary_sha256': release_sha256, 'deployment_id': policy['deployment_id'], 'evaluated_at': now.isoformat(), 'accepted': accepted, 'missing': missing, 'trust_assumption': 'Trust root and issuer identity/scopes must be verified and provisioned by the deployment authority out of band. Signatures authenticate attestations; they do not independently recreate external audits or infrastructure tests.'}
