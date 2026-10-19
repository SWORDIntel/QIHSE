#!/usr/bin/env python3
"""Upload a raw dump through QIHSE's authenticated, loopback-only RESP adapter.

Requires an explicitly enabled ARTIFACT.* server and QIHSE_UPLOAD_USER and
QIHSE_UPLOAD_PASSWORD in the process environment; never supplies a path to
QIHSE and never reads QIHSE's storage directories directly.
"""
import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import socket

CHUNK = 256 * 1024
MAX_SIZE = 4 * 1024 * 1024 * 1024


def read_line(sock):
    result = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError('QIHSE closed the connection')
        result.extend(ch)
        if len(result) > 256:
            raise ValueError('oversized RESP reply header')
        if result.endswith(b'\r\n'):
            return bytes(result[:-2])


def receive(sock):
    head = read_line(sock)
    if head[:1] == b'-':
        raise RuntimeError('QIHSE rejected request: ' + head[1:].decode('utf-8', 'replace'))
    if head[:1] in (b'+', b':'):
        return head[1:]
    if head[:1] != b'$':
        raise ValueError('unexpected RESP reply')
    length = int(head[1:])
    if length < 0 or length > CHUNK:
        raise ValueError('invalid RESP bulk length')
    body = bytearray()
    while len(body) < length + 2:
        part = sock.recv(length + 2 - len(body))
        if not part:
            raise ConnectionError('truncated RESP bulk')
        body.extend(part)
    if body[-2:] != b'\r\n':
        raise ValueError('invalid RESP bulk terminator')
    return bytes(body[:-2])


def command(sock, *args):
    sock.sendall(f'*{len(args)}\r\n'.encode())
    for arg in args:
        raw = arg if isinstance(arg, bytes) else str(arg).encode()
        sock.sendall(f'${len(raw)}\r\n'.encode())
        sock.sendall(raw)
        sock.sendall(b'\r\n')
    return receive(sock)


def digest_file(path):
    digest = hashlib.sha384()
    size = 0
    with path.open('rb') as source:
        while data := source.read(1024 * 1024):
            digest.update(data)
            size += len(data)
            if size > MAX_SIZE:
                raise ValueError('source exceeds the 4 GiB artifact limit')
    return size, digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--tenant', type=int, required=True)
    parser.add_argument('--classification', type=int, required=True)
    parser.add_argument('--sci', type=int, default=0)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=6379)
    args = parser.parse_args()
    if not 0 <= args.tenant <= 0xffffffff or not 0 <= args.classification <= 65535 or not 0 <= args.sci <= 65535:
        parser.error('tenant/classification/SCI out of range')
    try:
        if not ipaddress.ip_address(args.host).is_loopback:
            parser.error('only numeric loopback hosts are supported; remote transfers require QKP sealing')
    except ValueError:
        parser.error('provide a numeric loopback IP address')
    user = os.environ.get('QIHSE_UPLOAD_USER')
    password = os.environ.get('QIHSE_UPLOAD_PASSWORD')
    if not user or not password:
        parser.error('set QIHSE_UPLOAD_USER and QIHSE_UPLOAD_PASSWORD in the environment')
    size, digest = digest_file(args.source)
    with socket.create_connection((args.host, args.port), timeout=30) as sock:
        sock.settimeout(120)
        command(sock, 'AUTH', user, password)
        command(sock, 'ARTIFACT.BEGIN', args.tenant, args.classification, args.sci, size, digest)
        try:
            offset = 0
            transmitted = hashlib.sha384()
            with args.source.open('rb') as source:
                while data := source.read(CHUNK):
                    committed = int(command(sock, 'ARTIFACT.CHUNK', offset, data))
                    transmitted.update(data)
                    offset += len(data)
                    if committed != offset:
                        raise RuntimeError('upload offset mismatch')
            if offset != size or transmitted.hexdigest() != digest:
                raise RuntimeError('source changed during upload')
            published = command(sock, 'ARTIFACT.COMMIT').decode('ascii')
            if published != digest:
                raise RuntimeError('published digest mismatch')
        except Exception:
            try:
                command(sock, 'ARTIFACT.ABORT')
            except Exception:
                pass
            raise
        # Authentication and classification are rechecked on this range read.
        tail = min(CHUNK, size)
        with args.source.open('rb') as source:
            source.seek(size - tail)
            expected_tail = source.read(tail)
        if command(sock, 'ARTIFACT.GET', digest, size - tail, tail) != expected_tail:
            raise RuntimeError('published tail range mismatch')
    print(f'published sha384={digest} bytes={size}')


if __name__ == '__main__':
    main()
