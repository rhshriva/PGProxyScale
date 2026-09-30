#!/usr/bin/env python3
"""Asyncpg acceptance: extended protocol, concurrent pools, prepared state and rollback."""
import argparse
import asyncio
import asyncpg


async def run(args):
    options = dict(host=args.host, port=args.port, user="postgres", database=args.database,
                   ssl=False, timeout=5, command_timeout=5)
    pool = await asyncpg.create_pool(**options, min_size=2, max_size=4)
    try:
        async def worker(index):
            async with pool.acquire() as connection:
                statement = await connection.prepare("SELECT $1::int + 1")
                for value in range(4):
                    assert await statement.fetchval(index + value) == index + value + 1
                async with connection.transaction():
                    await connection.execute("SET LOCAL application_name='asyncpg-local'")
                    assert await connection.fetchval("SHOW application_name") == "asyncpg-local"
                assert await connection.fetchval("SELECT 42") == 42
                try:
                    async with connection.transaction():
                        await connection.execute("SELECT 1/0")
                except asyncpg.DivisionByZeroError:
                    pass
                assert await connection.fetchval("SELECT 42") == 42
        await asyncio.wait_for(asyncio.gather(*(worker(index) for index in range(4))), timeout=30)
    finally:
        # Pool.close waits for checked-out connections; failed scenarios must remain bounded.
        pool.terminate()
    print("PASS asyncpg concurrent prepared statements, transactions, rollback and pool reset", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="host.docker.internal")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--database", required=True)
    asyncio.run(run(parser.parse_args()))
