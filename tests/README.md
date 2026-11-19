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
build\pebdrv.exe build\chiselbof.dll https://127.0.0.1:8406 "R:9054:127.0.0.1:9053/udp" "R:1543:socks"
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
build\pebdrv.exe build\chiselbof.dll https://127.0.0.1:8406 "R:1080:socks"

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
the client's CPU stays flat (no spin). The same holds with the client's *own* pings
enabled (the default `--keepalive 25s`): zero `ping failed`/`ping timeout` on the server
and no `ka: no pong` teardown on the client.

## 4. Authentication

The server must run with `--auth` (or `--authfile`) for this to mean anything:

```
chisel server --port 8411 --reverse -v --auth "op:s3cr3t:pass" \
              --tls-cert cert.pem --tls-key key.pem
```

| client invocation | expected client | expected server log |
|---|---|---|
| no `--auth` | twin: `auth failure: methods=[password] count=1 partial=0`, `stage auth failed user=` (empty), `ss_run rc=-2`, then the `session died at SSH userauth: …` hint and backoff | `Login failed for user ""`, no `Open` |
| `--auth op:wrong` | same, with `user=op` | `Login failed for user "op"` |
| `--auth "op:s3cr3t:pass"` | session opens; `Open (user=op …)`; fetches byte-exact | `session#N: Open (user=op addr=… remotes=…)` + `tun: Bound proxies` |
| `--auth op` (no colon) | `bad --auth op (expected <user>:<pass>)`, exit 7, no dial | nothing |
| more than 24 packed `z` records (PE image only) | `go()` returns 6; `stock_run` never starts, so there is no dial | nothing at all |

The colon-in-password row is the one to keep: `settings.ParseAuth` splits at the **first**
colon, so `s3cr3t:pass` is one password. A build that split at the last colon logs
`Login failed for user "op"` with the credentials looking correct.

`ss_run` returning `-2` means *the transport worked and the credential did not* — it is the
difference between "fix the password" and "fix the network", and it only shows up in the twin
or a `-DDIAG_MARK` build (the shipped image has `OUT()` compiled out; the server log is then
the only visible half).

## 5. Timeouts, keepalive and black-holed paths

Phase deadlines, measured against a peer that accepts TCP and then does nothing
(`gotest`-style silent listener, or any port with a listening socket behind it):

```
build\pebdrv.exe build\chiselbof.dll https://127.0.0.1:8413 "R:1080:socks" --ws-timeout 2s --max-retry-count 1
```

`--ws-timeout 1s` → exits in ~1.0 s, `--ws-timeout 2s` → ~2.0 s: the deadline is enforced, not
decorative (`--ssh-timeout` behaves the same way, 2 s → 2032 ms and 6 s → 6041 ms measured on
the twin, marking `stage handshake failed`). `--max-retry-count 1` means exactly one attempt
(the failed attempt is counted before the decision, as upstream does); `2` gives one retry.

Black-hole detection — the test that a keepalive is actually *for*. Nothing resets, nothing
times out at the TCP layer, so the only signal is the missing `pong`:

```
# client machine
python tests\wedge_relay.py 8412 127.0.0.1 8411 C:\tmp\_hole.on
build\pebdrv.exe build\chiselbof.dll https://127.0.0.1:8412 "R:1080:socks" ^
    --auth op:s3cr3t:pass --keepalive 3s --ping-timeout 2s --ws-timeout 3s
curl -x socks5h://127.0.0.1:1080 -o NUL -w "%{http_code}\n" http://127.0.0.1:9006/big.bin   # 200 first
echo. > C:\tmp\_hole.on && timeout /t 8 >nul && del C:\tmp\_hole.on
```

Expected on the **server**: `session#N: Close (user=op … duration=8.26s)` written while the
relay was still holding both sockets open — i.e. the *client* ended it — then
`session#M: Open (user=op …)` for the redial, and byte-exact fetches through the same socks
port again. Measured on this build with `--keepalive 3s --ping-timeout 2s --ws-timeout 3s
--ssh-timeout 4s --min-retry-interval 1s --max-retry-interval 3s`: teardown 5-8 s after the hole
appears, `Close (user=op … duration=11.323723s)` on the wedged session, a fresh `Open` **3 s**
later, and byte-exact 6 MiB fetches **8 s** after the flag file was deleted — the attempts in
between are bounded by `--ws-timeout`/`--ssh-timeout` + the backoff wait, so the worst case is
attempts × (deadline + wait).

**The flag list is itself a test on the PE image** (the twin takes real `argv` and never hits
this): pack 24 `z` records and the session opens; pack 26 or 44 and `go()` returns 6 — count
`Handshaking with` lines in the server log and expect zero. Older builds capped the list at 8
records and *dropped the rest silently*, so every flag past the eighth (`--ws-timeout`,
`--ssh-timeout`, the retry flags, even `--auth`) had no effect in the DLL while the same command
line worked in the twin; the symptom was a stalled handshake timing out at the 45 s default
despite `--ws-timeout 3s` on the command line.

**Control, same hole, `--keepalive 0`:** zero `ka:` marks, no teardown, one session, and the
path stays unusable until the *server's* own pings expire it (~125 s). A keepalive-free build
passes every other suite in this folder and still loses the connection silently in the field —
which is the reason this test exists.

## 6. Packed-argument contract (the C2 surface, no network needed)

```
python tests\packedargs.py build\chiselbof.dll
```

`packedargs.py` calls the DLL export `go(args, len)` through `ctypes` with hand-built argument
buffers and asserts on the return code — the only observable an offline test has, and enough to
pin the whole unpacker:

| record layout | expected |
|---|---|
| Cobalt-Strike header form (`u32` = size of remainder), `z` records, dash-free flag names | `1` in ~1 s (the dial budget ran out, so the flags were applied) |
| Outflank header form (`u32` = total incl. header) | `1` |
| `b` records for the flag tokens (length-prefixed, **no** NUL inside) | `1` — a NUL-driven copy would mis-parse and hang on unlimited retries |
| 24 records (at the cap) | runs: `1` |
| 26 records (over the cap) | `6` immediately, and **no** connection to the port at all |
| `keepalive 99zz` | `7` — the dash-free name reached the duration parser |

Every flag in sections 4 and 5 can be spelled **without its leading dashes** (`auth u:p`,
`keepalive 3s`, `max-retry-count 1`): positional C2 argument parsers (`exec_bof <types><args>`)
claim any token that starts with `-`, so the dashed spelling cannot always be delivered. Run the
dashed and dash-free forms once each — a build whose parser strips dashes on the argument side
only would accept neither.
