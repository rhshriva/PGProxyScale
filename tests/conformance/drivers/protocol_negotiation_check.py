#!/usr/bin/env python3
"""Verify startup version downgrade, extension negotiation and GSS fallback."""
import argparse
import socket
import struct

parser = argparse.ArgumentParser()
parser.add_argument('--host', default='127.0.0.1')
parser.add_argument('--port', type=int, default=6439)
args = parser.parse_args()

def exact(stream, count):
    result = b''
    while len(result) < count:
        data = stream.recv(count - len(result))
        if not data:
            raise EOFError('closed connection')
        result += data
    return result

def startup(stream, version, extensions=False):
    body = struct.pack('!I', version) + b'user\0postgres\0database\0areas_transaction\0'
    if extensions:
        body += b'_pq_.unsupported_test\0enabled\0'
    body += b'\0'
    stream.sendall(struct.pack('!I', len(body) + 4) + body)
    frames = []
    while True:
        tag = exact(stream, 1)
        length = struct.unpack('!I', exact(stream, 4))[0]
        payload = exact(stream, length - 4)
        assert tag != b'E', payload
        frames.append((tag, payload))
        if tag == b'Z':
            return frames

def connect():
    return socket.create_connection((args.host, args.port), timeout=3)

with connect() as stream:
    frames = startup(stream, 196610, True)
    assert frames[0] == (b'v', struct.pack('!II', 0, 1) + b'_pq_.unsupported_test\0')
    stream.sendall(b'Q' + struct.pack('!I', 14) + b'SELECT 42\0')
    while True:
        tag = exact(stream, 1)
        payload = exact(stream, struct.unpack('!I', exact(stream, 4))[0] - 4)
        assert tag != b'E', payload
        if tag == b'Z':
            break
with connect() as stream:
    stream.sendall(struct.pack('!II', 8, 80877104))
    assert exact(stream, 1) == b'N'
    assert startup(stream, 196608)[-1] == (b'Z', b'I')
with connect() as stream:
    try:
        startup(stream, 4 << 16)
    except (EOFError, ConnectionResetError):
        pass
    else:
        raise AssertionError('unsupported protocol major accepted')
print('PASS 3/3 protocol downgrade/extensions, GSS fallback, unknown major rejection')
