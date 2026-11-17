# tests/slowtarget.py - a target that ACCEPTS but reads very slowly (2 KiB/s).
# A chisel client must pace to the target instead of buffering ahead of it.
# Run on the CLIENT machine (the client dials the target), then push data at it
# with uplapp.py from the server machine.
# usage: python tests/slowtarget.py [port]      default 19102
import socket
import sys
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 19102
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(8)
print("slowtarget listening on %d" % port, flush=True)

tot = 0
while True:
    c, a = srv.accept()
    print("accepted", a, flush=True)
    got = 0
    c.settimeout(240)
    while True:
        try:
            d = c.recv(4096)
        except Exception as e:
            print("recv err", e, flush=True)
            break
        if not d:
            break
        got += len(d)
        tot += len(d)
        time.sleep(2.0)
        print("  got %d total %d" % (got, tot), flush=True)
    print("conn done after", got, flush=True)
    c.close()
