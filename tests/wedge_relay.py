#!/usr/bin/env python3
"""tests/wedge_relay.py <listen-port> <target-host> <target-port> <flagfile>

TCP relay used to wedge a live session: it keeps BOTH TCP connections open and simply
stops forwarding while <flagfile> exists.  Nothing is reset and no FIN is sent, so the
only way either endpoint can discover the dead path is its own keepalive - which is
exactly what --keepalive / --ping-timeout is for.

    python tests\\wedge_relay.py 8412 127.0.0.1 8411 C:\\tmp\\_hole.on

Test shape (client machine, one server with --auth so the session log is readable):

    python tests\\wedge_relay.py 8412 127.0.0.1 8411 C:\\tmp\\_hole.on
    build\\pebdrv.exe build\\chiselbof.dll https://127.0.0.1:8412 "R:1080:socks" ^
        --auth op:s3cr3t --keepalive 3s --ping-timeout 2s --ws-timeout 3s
    curl -x socks5h://127.0.0.1:1080 -o NUL -w "%%{http_code}\\n" http://127.0.0.1:9006/big.bin
    echo. > C:\\tmp\\_hole.on          # black-hole: forwards stop, sockets stay open
    ... wait 8 s ...
    del C:\\tmp\\_hole.on             # path returns; the client must redial by itself

Expected, with the flags above (the twin build shows the same thing as marks):
the client ends the wedged session 5-8 s after the hole appears - the server log shows
`session#N: Close (user=op ... duration=8.26s)` while nothing on the *network* broke -
then `retry: ...` attempts bounded by --ws-timeout while the hole is still up, a fresh
`session#M: Open` once the flag is gone, and byte-exact fetches through the same socks
port again.  Run the same test with `--keepalive 0` as the control: the client never
notices, no teardown happens, and the session survives only until the server's own
25 s pings expire it.
"""
import os, socket, sys, threading

if len(sys.argv) != 5:
    sys.exit(__doc__)
lp, th, tp, flag = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]


def hole():
    return os.path.exists(flag)


def pump(a, b):
    while True:
        try:
            d = a.recv(65536)
        except OSError:
            break
        if not d:
            break
        if hole():
            continue                      # silently dropped, connection stays open
        try:
            b.sendall(d)
        except OSError:
            break
    try:
        a.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        b.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", lp))
ls.listen(16)
print("relay %d -> %s:%d (hole flag: %s)" % (lp, th, tp, flag), flush=True)
while True:
    c, addr = ls.accept()
    r = socket.create_connection((th, tp))
    print("relay: client connection from %s (%s)" % (addr, "hole UP" if hole() else "forwarding"),
          flush=True)
    threading.Thread(target=pump, args=(c, r), daemon=True).start()
    threading.Thread(target=pump, args=(r, c), daemon=True).start()
