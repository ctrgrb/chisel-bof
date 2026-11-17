# tests/uplapp.py - push bytes as fast as possible through the tunnel to a
# slow or wedged target (run slowtarget.py / stalltarget.py on the CLIENT
# machine first).  Run on the SERVER machine, where R:1080:socks is bound.
#
# What matters is NOT the app-side send rate (the server's socket absorbs it)
# but what the tunnel does with it: it must pace to the target, never spin the
# client's single pump thread (that thread also answers the server's 25 s ping;
# a spin there kills the session ~125 s later), and if the target is truly
# stuck it must lose only that channel.
#
# usage: python tests/uplapp.py <socks-port> <total-bytes> [streams] [target-port]
import socket
import struct
import sys
import threading
import time

SOCKS_PORT = int(sys.argv[1])
TOTAL = int(sys.argv[2])
STREAMS = int(sys.argv[3]) if len(sys.argv) > 3 else 1
TARGET_PORT = int(sys.argv[4]) if len(sys.argv) > 4 else 19102
res = {}


def socks_connect(s, port):
    s.sendall(b"\x05\x01\x00")
    h = s.recv(2)
    if len(h) != 2 or h[1] != 0:
        raise Exception("greeting %r" % (h,))
    s.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", port))
    r = s.recv(32)
    if len(r) < 10 or r[1] != 0:
        raise Exception("connect %r" % (r,))


def stream(i):
    try:
        s = socket.create_connection(("127.0.0.1", SOCKS_PORT), 15)
        s.settimeout(240)
        socks_connect(s, TARGET_PORT)
        blob = bytes((i * 7 + n) & 0xFF for n in range(65536))
        t0 = time.time()
        sent = 0
        while sent < TOTAL:
            n = s.send(blob[:TOTAL - sent])
            if n <= 0:
                break
            sent += n
        dt = time.time() - t0
        res[i] = (sent, dt)
        print("stream %d pushed %d bytes in %.1fs" % (i, sent, dt), flush=True)
    except Exception as e:
        res[i] = (0, 0)
        print("stream %d FAILED %r" % (i, e), flush=True)


ts = [threading.Thread(target=stream, args=(i,)) for i in range(STREAMS)]
for t in ts:
    t.start()
for t in ts:
    t.join()
print("UPLAPP done streams=%d" % STREAMS, flush=True)
for i in sorted(res):
    print("  s%d pushed=%d t=%.1f" % (i, res[i][0], res[i][1]))
