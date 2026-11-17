# tests/stalltarget.py - a target that reads a little, then STOPS reading for
# 160 s.  A wedged proxied connection must not take the whole session down:
# the client waits for writability instead of spinning, keeps answering the
# server's 25 s ping, and after its ~30 s deadline drops ONLY that channel.
# While it is wedged, run slowapp.py on another channel and require it to come
# back byte-exact.  Run on the CLIENT machine (the client dials the target).
# usage: python tests/stalltarget.py [port]      default 19102
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 19102
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(8)
print("stalltarget listening on %d" % port, flush=True)

while True:
    c, a = srv.accept()
    print("accepted", a, flush=True)
    got = 0
    c.settimeout(600)
    while got < 8192:                 # read a normal burst first
        d = c.recv(4096)
        if not d:
            break
        got += len(d)
    print("read %d, now NOT reading for 160s" % got, flush=True)
    time.sleep(160)                   # wedged peer
    print("resuming reads", flush=True)
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            got += len(d)
    except Exception as e:
        print("resume err", e, flush=True)
    print("conn done after %d" % got, flush=True)
    c.close()
