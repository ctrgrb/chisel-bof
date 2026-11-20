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
--ssh-timeout 4s --min-retry-interval 1s --max-retry-interval 3s`: the hole opened ~7 s after the
session opened, the client tore the wedged session down **~4 s** later (`Close (user=op …
duration=11.6042139s)`), exactly **2** redial attempts reached the server during the 14 s the hole
was up (each attempt costs its phase deadline plus a backoff wait — that count *is* the backoff
working; a build whose sleep is fake redials continuously), and the first byte-exact 6 MiB fetch
succeeded **5 s** after the flag file was removed.

Give-up windows, measured with the twin (exit code propagates there; `pebdrv` does not) against a
closed port, a TLS peer that answers `502` (`gotest/fake502.py 8416 <cert> <key> 502`) and a peer
that accepts TCP and says nothing (`gotest/fakepeer.exe 8417 silent`):

| flags | wall |
|---|---|
| `max-retry-count 5 min-retry-interval 2s max-retry-interval 2s connect-timeout 1s`, closed port | 13 s |
| same without `connect-timeout` (8 s default), closed port | 49 s |
| `max-retry-count 3 min/max 2s connect-timeout 3s ws-timeout 3s ssh-timeout 3s`, `502` front end | 4 s |
| `max-retry-count 4 min/max 1s` and every timeout `1s`, TLS never answers | 7 s |
| `max-retry-count 0` | never: unlimited retries, the redial rate bounded by the backoff |

Timing these needs `$SECONDS` (or the twin's own phase marks): the *printed* `waiting N ms` is not
proof, and a build that slept through the Winsock NULL-set `select` idiom redialled instantly while
printing exactly the same lines.

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
| **one** record holding `url remote max-retry-count 1 connect-timeout 1s` | `1` — the payload tokenized it |
| one record holding the same line **with dashes** (`--max-retry-count 1 --connect-timeout 1s`) | `1` — dashes are legal in this form |
| one record, `keepalive "99 zz"` (quoted, one value with a space) | `7`; unquoted `keepalive 99 zz` (two tokens) → `1` |
| one record, unterminated quote | `6` |
| one record, 25 tokens | `6` (the same cap, counted in tokens) |
| one `Z` record (UTF-16LE) holding the command line, **no** bounds | still running when the 15 s watchdog fires = unlimited retries, i.e. it decoded the wide record |
| `Z` record holding a flag **name**, `z` records for the values | `1` — the wide/narrow test is per record |
| a second `go()` in the same process, with no flags at all | still running (unbounded): run #2 did not inherit run #1's `max-retry-count` |
| 3 attempts with `connect-timeout 1s` and `min == max == 1s` | `1` **and ≥ 1.8 s of wall** — the backoff has to consume time, not just print |

Every flag in sections 4 and 5 can be spelled **without its leading dashes** (`auth u:p`,
`keepalive 3s`, `max-retry-count 1`): positional C2 argument parsers (`exec_bof <types><args>`)
claim any token that starts with `-`, so the dashed spelling cannot always be delivered. The other
way to deliver a dashed line is **one record holding the whole command line** (row above): the
payload splits it, so the C2 never sees a token starting with `-`. Run the dashed and dash-free
forms once each — a build whose parser strips dashes on the argument side only would accept
neither, and a build whose tokenizer writes its terminator before stepping over the separator would
stop after the first token. Each case runs under a watchdog: `hang` is a legitimate expected
outcome (an unbounded retry loop), never a stuck test suite.
