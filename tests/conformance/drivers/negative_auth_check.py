#!/usr/bin/env python3
"""Assert that a wrong password is rejected by the endpoint under test.

Why this exists: a green passthrough run proves the *client* authenticated. It does not
prove the proxy is authenticating anyone — a proxy that relayed everything and ignored
credentials would also look green. This closes that loop by demanding that a wrong
password still fails through the same path.

Exit codes: 0 rejected (good), 1 accepted (bad), 2 unexpected error (inconclusive).
"""

from __future__ import annotations

import argparse
import sys

import psycopg


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--dbname", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    try:
        psycopg.connect(
            host=args.host,
            port=args.port,
            user=args.user,
            password=args.password,
            dbname=args.dbname,
            connect_timeout=10,
        )
    except psycopg.OperationalError as exc:
        detail = str(exc).strip().splitlines()[0][:110]
        print(f"  rejected as expected: {detail}")
        return 0
    except Exception as exc:  # noqa: BLE001 - inconclusive, not a pass
        print(f"  INCONCLUSIVE {type(exc).__name__}: {exc}")
        return 2

    print("  FAIL: the endpoint accepted a wrong password")
    return 1


if __name__ == "__main__":
    sys.exit(main())
