# Internals: how the payload actually works

```
go(args,len)                       BOF entry, arg unpacking, session loop
  arena (20 MiB, .data)            every allocation
  ws2_32 by ordinal                socket/connect/send/recv/select/…
  Mbed TLS 3.6.7 (trimmed)         TLS 1.2 only, SNI, chain parsed, not verified
  WebSocket client                 masked frames, single non-blocking outbox
  SSH client (src/sshtun.c)        curve25519-sha256, chacha20-poly1305, channels
  chisel control                   SSH global "config" JSON, ping/pong, remotes
  remotes                          socks5 (client-side name resolution), TCP, UDP(gob)
```

One thread drives everything: TLS record I/O, WebSocket framing, the SSH pump, the server's
25 s pings, and every proxied channel. Nothing blocks it; nothing else exists (no threads, no
fibre scheduling — unlike the Go client).

## Image and loading

- Entry `DllMainCRTStartup` returns immediately; the only export is `go @1`
  (`deps/chiselbof.def`).
- Built `-nostdlib -shared -Wl,--dynamicbase -Wl,--strip-all -Wl,--no-undefined`, compile side
  `-fno-pic -fno-pie`.
- 587 absolute relocation slots (581 on a GCC 16 build), **all of them pointing inside the
  image** — that is the property Beacon-style loaders care about. Check and optionally rewrite
  them to `IMAGE_REL_BASED_DIR64`:

  ```
  python tools\pehl2dir.py build\chiselbof.dll out.dll --audit
  ```

- Size ~21.4 MB, almost entirely Mbed TLS code; stripped.

## Memory

One 20 MiB static arena (`ARENA_N`) plus a live-block bitmap (one bit per 8-byte quantum at
header starts), used by `arena_calloc`/`arena_free`, which are wired into Mbed TLS as
`MBEDTLS_PLATFORM_CALLOC_MACRO`/`_FREE_MACRO`. There is no heap API call anywhere in the image —
the only `KERNEL32` import is `GetTickCount64`. The arena lives in `.data`, not `.bss`, and is
pre-filled with `0xAA`: a loader that commits only `SizeOfRawData` would otherwise map no arena
at all. The bitmap and offset are reset on every new session.

## The libc it does not have

`src/crypto.c` defines `memcpy`, `memset`, `memmove`, `memcmp`, `strlen`, `strcmp`, `strstr`,
`strchr`; `src/mbedfmt.c` provides `mbed_snprintf_impl`/`mbed_vsnprintf_impl`/
`mbed_printf_impl`/`mbed_fprintf_impl`, which `deps/mbedinc/…/mbedtls_config.h` binds to the
`MBEDTLS_PLATFORM_{SN,VSN,PRINTF,FPRINTF}_MACRO` hooks. So Mbed TLS never emits a libc call and
we never define a libc-named symbol that the CRT would also want — with the exception of the
byte-loop helpers above, which is exactly why
[the loop-idiom flag](build.md#the-flag-table) is mandatory.

Winsock is imported **by ordinal** from `deps/WS2_32nat.def` (generated with `dlltool`), and every
call site uses a hand-written `extern` declaration — no `<winsock2.h>`, no SDK headers, so nothing
can drag in a CRT dependency. Note the `select()` extern: the payload includes no headers, so the
prototype has to be explicit or a modern compiler will refuse the build.

## Randomness

`rng_dummy` is Mbed TLS's RNG hook and is also used directly (X25519 ephemerals, the SSH
transport cookies, and the per-frame WebSocket mask key). It is xorshift64 over one 64-bit state,
reseeded once per session by mixing `GetTickCount64()` with a stack address.

Two consequences of that design are worth knowing:

- **Operationally, the seed must not be constant.** With a fixed seed, every ECDHE ephemeral
  share *and* every WebSocket mask key is identical, the server's TLS 1.2 GCM write nonce
  (`salt || sequence number`) then repeats across sessions, and Go's TLS stack kills the
  connection. That is why `rng_reseed()` runs per TLS session rather than once at load.
- **Security-wise, it is a non-cryptographic PRNG seeded from coarse values** — a deliberate
  trade-off, because a real entropy source would mean extra imports
  (`BCryptGenRandom`/`RtlGenRandom`) and a dependency on that DLL surface. The client's
  contribution to the session keys (its TLS and SSH ephemeral shares, its nonces, its mask keys)
  therefore has limited entropy. The server's keys, and the tunnel's confidentiality against an
  off-path observer, still rest on the server's side of the exchange, but forward secrecy of a
  recorded session is weaker than it would be with an OS CSPRNG. If that matters for your
  deployment, adding `BCryptGenRandom` is one import plus one extern.

## SSH layer (`src/sshtun.c`)

- Client version string: `SSH-chisel-v3-client`.
- KEX: `curve25519-sha256` (and `…@libssh.org`) only, **non-strict** KEX with
  `CONTINUING`/`NEWKEYS` handled inline; the client deliberately never advertises
  `mlkem768x25519-sha256` or `ext-info-negotiation` (a modern Go server would then expect a
  KEM share and a second KEX payload it does not send us).
- Host key algorithms accepted: `ecdsa-sha2-nistp256/384/521`, `ssh-ed25519`, `rsa-sha2-512`,
  `rsa-sha2-256`, `ssh-rsa` — verified, not pinned (the server is unauthenticated by design:
  there is no fingerprint UI in a BOF).
- Cipher: `chacha20-poly1305@openssh.com` for records; MAC list offered for the negotiation
  fallback (`*-etm@openssh.com`, `hmac-sha2-256/512`, `hmac-sha1`), and the KDF labels use the
  `'C'`/`'S'`/`'A'`/`'D'`/`'E'`/`'I'` tags of the chacha20-poly1305 profile.
- Channel parameters `CH_W = 2097152`, `CH_MAX = 32768` match x/crypto's
  `channelWindowSize`/`channelMaxPacket` exactly; the server's credit accounting assumes them.
- The stock server rekeys the transport at `1 << 30` bytes of traffic — minutes of normal
  browsing — and `do_rekey` survives it in place.

## Chisel control plane

After SSH user-auth succeeds the client sends **one SSH global request named `config`** whose
body is chisel's own JSON config (upstream's `settings.EncodeConfig` shape), e.g.:

```json
{"Version":"1.12.1","Remotes":[{"LocalHost":"","LocalPort":"1080","LocalProto":"tcp",
 "RemoteHost":"","RemotePort":"","RemoteProto":"tcp","Socks":true,"Reverse":true,"Stdio":false}]}
```

`Socks:true` is what makes the server bind a SOCKS5 listener; `Reverse:true` marks `R:` remotes;
UDP remotes arrive as `LocalProto:"udp"`. This is the request whose contents show up in the
server log line `Open (user=- addr=… remotes=R:1080:socks)`.

- Keepalive: the server sends SSH **global** requests named `ping` (every 25 s by default); the
  client answers `pong` in the same message type (`80` → `81`). Missing pings are how the server
  kills a wedged client ~125 s later, so the pump must never block.
- Each proxied stream is its own SSH channel: `90` open, `94` data, `93` window adjust, `96` EOF,
  `97` close, `92` open-refused. A `R:<port>:socks` remote is one channel whose open carries the
  extra data string `socks`; the client then speaks SOCKS5 on that channel and resolves CONNECT
  target names locally (`socks5h`).
- The stock server closes tunnels with channel-EOF (`96`) only — never `97` — and the client must
  not treat a missing `97` as a protocol error.

## Wire facts learned the hard way

- chisel's gob integers are **not** uvarint: values `< 128` are one byte, otherwise
  `-bytelen || big-endian` (1000 → `fe 03 e8`). The UDP codec additionally hardcodes the server's
  exact 43-byte type-def message and counts field deltas from `-1`.
- UDP needs winsock1-style `socket(2 /*AF_INET*/, SO_ANY, 17 /*IPPROTO_UDP*/)` — the only form that
  puts real UDP datagrams on the wire here; and `WSAStartup` must be handed a real 512-byte
  `WSADATA` buffer, not a pointer to nothing.
- `Host:` must be `host[:port]` with the port omitted for the scheme default — a front-end that
  correlates SNI with `Host` rejects anything else with `421`/`SSLMismatchedSNI`.
- The WebSocket client masks every frame (RFC 6455 client rule); an unmasked frame is answered
  with a close and, behind a front-end, with a `400` from the proxy layer instead.

## Diagnostic build switches

The payload is silent by default — there is no console and no file output. To see what it is
doing, compile one of these variants instead (both are the same sources, different entry):

| switch | effect |
|---|---|
| `-DTWIN_MAIN` | console twin: `main()` taking `argv` (`stock_run(argc, argv)`), `OUT(...)` lines on stderr, linked against a normal CRT. Mbed TLS debug threshold 4 (full handshake traces, incl. hex dumps of the ClientHello) via `mbedtls_ssl_conf_dbg`. |
| `-DDIAG_MARK` | the same `OUT(...)` lines go into an in-memory ring (`slogw`) instead of stderr, so the payload stays a PE image and you can read the marks afterwards. Mbed TLS threshold 1 by default; add `-DTLS_DBG4` for threshold 4 (the full extension/SNI dump — that is how the missing-SNI bug behind the front-end was proven). |

Mbed TLS's debug output is routed through our own `mbed_printf_impl` family, so enabling it pulls
in no stdio (see [build.md](build.md)).
