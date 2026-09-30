#!/usr/bin/env python3
"""Authenticate source-bound external evidence using an out-of-band trust root."""
import argparse
import hashlib
import json
import pathlib
import sys
from evidence import EvidenceError, evaluate, source_identity, strict_json

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, type=pathlib.Path, help='root-signed trust policy envelope')
    parser.add_argument('--bundle', required=True, type=pathlib.Path, help='signed external attestations')
    parser.add_argument('--trust-root', required=True, type=pathlib.Path, help='RSA3072+ public key provisioned and identity-verified out of band')
    parser.add_argument('--evidence-directory', required=True, type=pathlib.Path)
    parser.add_argument('--release-binary', required=True, type=pathlib.Path)
    parser.add_argument('--checkout', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[2])
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'production_certified': False, 'decision': 'validation-pending'})+'\n')
    try:
        decision = evaluate(strict_json(args.policy), strict_json(args.bundle), args.evidence_directory, args.trust_root, source_identity(args.checkout), hashlib.sha256(args.release_binary.read_bytes()).hexdigest())
    except Exception as error:
        decision = {'production_certified': False, 'decision': 'invalid-evidence', 'reason': str(error)[:512], 'error_type': type(error).__name__}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(decision, indent=2)+'\n')
    print('Authenticated production release evidence accepted.' if decision['production_certified'] else 'Production certification incomplete or rejected; see decision report.')
    return 0 if decision['production_certified'] else 2

if __name__ == '__main__':
    sys.exit(main())
