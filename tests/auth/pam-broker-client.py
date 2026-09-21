#!/usr/bin/env python3
"""Minimal PLAP client for exercising plank-pam-broker directly (root only).

Usage: pam-broker-client.py SOCKET USER BASE64_TOKEN   (begin_gssapi)
       pam-broker-client.py SOCKET USER -              (password begin)
Prints the broker result; an authenticated session is closed immediately.
"""
import socket, struct, sys, base64
MAGIC=0x504c4150
def s(b): return struct.pack('<I', len(b)) + b
def frame(t, tid, payload): return struct.pack('<IHHQI', MAGIC, 1, t, tid, len(payload)) + payload
def main():
    path, user, token_b64 = sys.argv[1], sys.argv[2], sys.argv[3]
    tok = base64.b64decode(token_b64) if token_b64 != '-' else b''
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); sock.connect(path)
    payload = s(user.encode()) + s(b'203.0.113.9') + s(b'plank')
    if tok: payload += s(tok); t = 6
    else: t = 1
    sock.sendall(frame(t, 42, payload))
    hdr = sock.recv(20, socket.MSG_WAITALL)
    if len(hdr) < 20: print('closed'); return
    magic, ver, mtype, tid, length = struct.unpack('<IHHQI', hdr)
    body = sock.recv(length, socket.MSG_WAITALL) if length else b''
    if mtype == 4:
        phase, status = struct.unpack('<Hi', body)
        print(f'result phase={phase} pam_status={status}')
        if phase == 7:
            sock.sendall(frame(5, 42, b''))
    else:
        print(f'message type={mtype} len={length}')
main()
