# Tests

Prereqs: the stock chisel server binary (any 1.12.x), python 3, and a self-signed cert
for the TLS leg (any of `openssl`, the Go `chisel` server's `--tls-cert`, or a front-end).

```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 30 -nodes -subj /CN=test
```

Two machines are useful for the stability suite, because the **target is dialled by the
client** while the **socks port is bound by the server**: the payload HTTP server and the
slow/wedged targets run where the client runs, and `slowapp.py` / `uplapp.py` run where
the server runs. For a single-machine smoke, everything is 127.0.0.1 and it all works.

## 1. UDP + socks smoke

Terminal 1 (server machine):

```
chisel server --port 8406 --reverse -v --tls-cert cert.pem --tls-key key.pem
python tests\udp_echo.py 9053
python -m http.server 9006 --bind 127.0.0.1
```

Terminal 2 (client machine):

```
build\pebdrv.exe build\chiselpe.dll https://127.0.0.1:8406 "R:9054:127.0.0.1:9053/udp" "R:1543:socks"
```

Terminal 3 — expect `UDP-TEST PASS`:

```
python tests\udp_test.py 9054
curl -x socks5h://127.0.0.1:1543 http://localhost:9006/     # 200, hostname resolved by the client
```

The server log must show `proxy#R:127.0.0.1:9054=>9053/udp: Listening` and
`acquired channel`, with no `Dropping` / `decode error` / `duplicate type` lines.

## 2. Slow-consumer soak (the test that catches flow-control bugs)

`slowapp.py` opens N parallel SOCKS5 connections that fetch `tests/pub/big.bin` and read
it slowly (16 KiB + delay per read), i.e. the RDP / Ad Explorer / browser shape. It
verifies **byte count and SHA-256 of every stream**, and afterwards the session must
still be alive (the socks port still `LISTEN`, no `Close (user=` in the server log).
Fast-consumer tests (`curl`) do **not** catch this class of bug.

```
# client machine
python tests\mkpayload.py 6291456          # writes tests\pub\big.bin, prints its sha256
python -m http.server 19101 --directory tests\pub
build\pebdrv.exe build\chiselpe.dll https://127.0.0.1:8406 "R:1080:socks"

# server machine
python tests\slowapp.py 1080 6                        # 6 streams, payload size/sha auto
python tests\slowapp.py 1080 12 20971520 8192 0.1     # heavier soak (20 MiB, ~80 KiB/s)
```

Expected: `SLOWAPP ok=N/N` with `sha_ok=True` on every stream, `wrote too much`=0 in the
server log, no `Close (user=` line. A build with the window-accounting bugs returns
`0/N` and the server aborts the session with
`(error ssh: remote side wrote too much)`; with the queue-drain bug fixed but the EOF
ordering not, streams arrive a few KiB short (`6289203` instead of `6291456` bytes).

Passing a size and a hash explicitly lets you run it on a machine without
`tests/pub/big.bin` (e.g. on the server box against a remote payload server):

```
python3 tests/slowapp.py 1080 12 20971520 8192 0.1 19101 <expected-sha256>
```

## 3. Slow and wedged targets

`slowtarget.py` accepts but reads 4 KiB every 2 s — the client must pace to ~2 KiB/s
instead of buffering ahead of the target. `stalltarget.py` reads 8 KiB and then
**stops reading for 160 s**; a wedged proxied connection must not take the session with
it (the client's single pump thread also answers the server's 25 s ping, so spinning in
a blocked `send()` would kill everything ~125 s later).

```
# client machine
python tests\slowtarget.py 19102          # or tests\stalltarget.py 19102

# server machine
python tests\uplapp.py 1080 2000000 1 19102          # push 2 MB at the wedged target
python tests\slowapp.py 1080 6                       # ... while it is wedged: must stay 6/6
```

Expected: the wedged channel alone is lost (after the client's ~30 s write deadline),
the session survives with zero `ping failed`, other streams return `sha_ok=True`, and
the client's CPU stays flat (no spin).
