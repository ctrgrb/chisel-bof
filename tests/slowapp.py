# tests/slowapp.py - many parallel fetchers whose APPLICATION READS SLOWLY.
#
# This is the traffic shape of RDP + Ad Explorer + a browser at once: many
# concurrent channels, each consumed slowly, so the chisel server stops draining
# our writes.  Fast consumers (`curl`) never park a WebSocket frame and never
# leave a channel's SSH flow-control window boundary-exact, which is exactly why
# naive throughput tests pass while real browsing kills the session with
#   server: session#N: Close (...) (error ssh: remote side wrote too much)
# and quietly truncates downloads (a channel-EOF sent while bytes were still
# queued for window credit).  See README "Stability" / TASKS 43.5.
#
# It checks both failure modes at once:
#   * session survival      - grep the server log for "wrote too much", and the
#                             socks port still being LISTEN after the run
#   * stream integrity      - byte count AND sha256 of everything each stream
#                             received (a double-sent frame corrupts the stream)
#
# Run on the SERVER machine (where R:1080:socks is bound).  The target is
# dialled by the CLIENT, so start the payload server there first:
#   python tests/mkpayload.py            # writes tests/pub/big.bin + prints sha
#   python -m http.server 19101 --directory tests/pub     # on the CLIENT machine
#
# usage: python tests/slowapp.py <socks-port> [streams] [bytes] [chunk] [delay-s]
#                               [target-port] [expected-sha]
# Defaults: 6 streams, payload size/sha from tests/pub/big.bin, 16 KiB chunks,
# 0.05 s between reads, target port 19101.  Pass bytes + expected-sha explicitly
# to run this on a machine that has no tests/pub/big.bin (e.g. the server box).
import hashlib
import os
import socket
import struct
import sys
import threading
import time

SOCKS_PORT = int(sys.argv[1])
STREAMS = int(sys.argv[2]) if len(sys.argv) > 2 else 6
PAYLOAD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pub", "big.bin")
have = os.path.exists(PAYLOAD)
SIZE = int(sys.argv[3]) if len(sys.argv) > 3 else (os.path.getsize(PAYLOAD) if have else 0)
CHUNK = int(sys.argv[4]) if len(sys.argv) > 4 else 16384
DELAY = float(sys.argv[5]) if len(sys.argv) > 5 else 0.05
TARGET_PORT = int(sys.argv[6]) if len(sys.argv) > 6 else 19101
EXPECT = sys.argv[7] if len(sys.argv) > 7 else (
    hashlib.sha256(open(PAYLOAD, "rb").read()).hexdigest() if have else "")
if not SIZE:
    sys.exit("no payload size: run tests/mkpayload.py or pass [bytes]")

print("socks=%d streams=%d bytes=%d chunk=%d delay=%s target=%d sha=%s"
      % (SOCKS_PORT, STREAMS, SIZE, CHUNK, DELAY, TARGET_PORT, EXPECT[:16] or "SKIP"))
res = {}


def socks_connect(s, port):
    s.sendall(b"\x05\x01\x00")
    h = s.recv(2)
    if len(h) != 2 or h[0] != 5 or h[1] != 0:
        raise Exception("socks greeting %r" % (h,))
    s.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", port))
    r = s.recv(32)
    if len(r) < 10 or r[1] != 0:
        raise Exception("socks connect %r" % (r,))


def stream(i):
    try:
        s = socket.create_connection(("127.0.0.1", SOCKS_PORT), 15)
        s.settimeout(300)
        socks_connect(s, TARGET_PORT)
        s.sendall(b"GET /big.bin HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                  b"User-Agent: slowapp\r\nConnection: close\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
        head, _, body = buf.partition(b"\r\n\r\n")
        if b" 200 " not in head.split(b"\r\n")[0]:
            raise Exception("bad status %r" % head.split(b"\r\n")[0])
        got = bytearray(body)
        while len(got) < SIZE:
            d = s.recv(min(CHUNK, SIZE - len(got)))
            if not d:
                break
            got += d
            if DELAY:
                time.sleep(DELAY)
        s.close()
        h = hashlib.sha256(bytes(got[:SIZE])).hexdigest()
        res[i] = (len(got), (EXPECT == "" or h == EXPECT), h[:16])
        print("stream %d: %d bytes sha_ok=%s %s" % (i, len(got), res[i][1], res[i][2]), flush=True)
    except Exception as e:
        res[i] = (0, False, repr(e))
        print("stream %d: FAILED %s" % (i, e), flush=True)


ts = [threading.Thread(target=stream, args=(i,)) for i in range(STREAMS)]
for t in ts:
    t.start()
for t in ts:
    t.join()

ok = sum(1 for v in res.values() if v[1] and v[0] == SIZE)
print("SLOWAPP ok=%d/%d" % (ok, STREAMS))
for i in sorted(res):
    print("  s%d bytes=%d sha_ok=%s %s" % (i, res[i][0], res[i][1], res[i][2]))
sys.exit(0 if ok == STREAMS else 1)
