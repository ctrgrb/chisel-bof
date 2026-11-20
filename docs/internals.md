# Internals: how the payload actually works

```
go(args,len)                       BOF entry, arg unpacking, session loop
  arena (20 MiB, .data)            every allocation
  ws2_32 (13 names, hand def)      socket/connect/send/recv/select/setsockopt/…
  Mbed TLS 3.6.7 (trimmed)         TLS 1.2 only, SNI, chain parsed, not verified
  WebSocket client                 masked frames, single non-blocking outbox
  SSH client (src/sshtun.c)        curve25519-sha256, chacha20-poly1305, channels
  chisel control                   SSH global "config" JSON, ping/pong, remotes
  remotes                          socks5 (client-side name resolution), TCP, UDP(gob)
```

One thread drives everything: TLS record I/O, WebSocket framing, the SSH pump, the keepalive
pings in both directions, and every proxied channel. Nothing blocks it; nothing else exists (no
threads, no fibre scheduling — unlike the Go client).

## Image and loading

- Entry `DllMainCRTStartup` returns immediately; the only export is `go @1`
  (`deps/chiselbof.def`).
- `go(const char *args, int len)` unpacks the beacon's records itself (`pe_args` in
  `src/stock.c`): it accepts the Cobalt-Strike form (leading `u32` = size of the remainder) and
  the Outflank form (leading `u32` = total including the header), falling back to the other if the
  first does not match. At most `PE_MAXARG` = **24** records, each up to `PE_ARGMAX` = **1024**
  characters. Records are copied **by length, never by NUL**: a `z` record carries its own
  terminator inside `l` but a `b` record does not, and a record without one would otherwise read
  into the next. A record whose shape is UTF-16LE (printable first byte, every odd byte zero —
  `pe_iswide`) is collapsed to 8-bit on the way in, because a `Z` (wide) argument would otherwise
  stop at its first NUL byte; the test is per record, so a command line may mix `z` and `Z`.
  Any leftover byte after 24 records means the list was longer than the cap: it returns 6 (then
  `stock_run` never runs) instead of using the prefix. Silently dropping the tail is not an
  option — the tail is where `auth`, the timeouts and the retry flags land.
- **One record may be the whole command line.** When the buffer yields exactly one record, `go()`
  hands it to `pe_tokenize`: split on ASCII blanks, `"` toggles grouping and the quote characters
  are dropped (so a value may contain spaces), tokens written back over the source (never to the
  right of it). This is the form that makes chisel's dashed spellings reachable from a positional
  C2 parser — `exec_bof z "https://host R:1080:socks --auth u:p --max-retry-count 5"` — because the
  payload, not the C2, does the splitting. One record can never be a valid record-form list (chisel
  needs URL + remote), so the two forms cannot collide. Over 24 tokens or an unterminated quote is
  a refusal (6), same rule as the record walk.
- Flag matching (`flagis`) ignores **leading dashes on both sides**, so `--auth`, `-auth` and
  `auth` are one flag and `authx` is none of them. That exists for CLIs that pack arguments
  positionally (`exec_bof <types><args>`): their own option parser claims any token starting with
  `-`, so a dashed flag can never arrive — in the record form. `tests/packedargs.py` drives `go()`
  with hand-built buffers (both header forms, `z`, `b` and wide records, the single-record form,
  the cap boundary) and asserts on the return code and, for the retry flags, on the **elapsed
  wall**: a `waiting 2000 ms` line proves nothing on its own.
- Per-run state is reset at the top of `stock_run` (credentials, `--tgt`/udp remote, `--hv`, the
  retry counters and intervals, the dial deadline). Those buffers are process-lifetime storage and
  a beacon may call `go()` several times in one injected process; without the reset, run #2 would
  authenticate with run #1's username and start with run #1's attempt count already spent.
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

Winsock comes from a hand-written import def, `deps/WS2_32nat.def` (`dlltool` generates the
`.a`; `gethostbyname`/`getsockopt` carry explicit ordinals), and every call site uses a
hand-written `extern` declaration — no `<winsock2.h>`, no SDK headers, so nothing can drag in a
CRT dependency. The list is 13 names: the 12 transport calls plus `setsockopt`, which the
timeout options (`SO_RCVTIMEO`/`SO_SNDTIMEO`) need. Note the `select()` extern: the payload
includes no headers, so the prototype has to be explicit or a modern compiler will refuse the
build. `KERNEL32` contributes exactly one import, `GetTickCount64`, which is the clock for every
deadline here — connect, handshake, pong and backoff.

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
- User-auth: a `none` probe (to read the server's allowed methods) and then `password` — that is
  chisel's only credential path, see [Authentication](#authentication).
- The stock server rekeys the transport at `1 << 30` bytes of traffic — minutes of normal
  browsing — and `do_rekey` survives it in place.

## Authentication

A chisel server started with `--auth`/`--authfile` does **not** authenticate the WebSocket
upgrade: there is no `Authorization` header anywhere in chisel's protocol. It authenticates the
SSH layer. `server/server.go` installs `authUser` as the `ssh.ServerConfig`
`PasswordCallback`:

```go
func (s *Server) authUser(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	// check if user authentication is enabled and if not, allow all
	if s.users.Len() == 0 {
		return nil, nil
	}
	// check the user exists and has matching password
	n := c.User()
	user, found := s.users.Get(n)
	if !found || subtle.ConstantTimeCompare([]byte(user.Pass), password) != 1 {
		s.Infof("Login failed for user %q (%s)", n, c.RemoteAddr())
		return nil, fmt.Errorf("invalid authentication for username: %s", n)
	}
	return &ssh.Permissions{Extensions: map[string]string{"user": n}}, nil
}
```

so the client's job is to send a `USERAUTH_REQUEST` with method `password`, the username and the
password. `ss_run(…, user, pass, …)` does exactly that, and the username is what later shows up
in the server log (`Open (user=ops addr=… remotes=…)`), which is also how `--authfile`'s
per-user `addr` allow-list is keyed. `--auth <user>:<pass>` is split at the **first** colon —
the same rule as `settings.ParseAuth` upstream — so a password may contain colons; with no colon
the payload reports `bad --auth <value> (expected <user>:<pass>)` and returns 7.

A rejected credential is distinguishable from a transport failure: `ss_run` returns `-2` after
logging `auth failure: methods=[…] count=N partial=0` and `stage auth failed user=…`, and the
operator sees the server write `Login failed for user "<name>"`. Everything else returns `-1`.

**Wire quirk worth knowing:** the `USERAUTH_FAILURE` reply is produced by x/crypto's
`userAuthFailureMsg{ Methods []string; PartialSuccess bool }`, i.e. marshalled **name-list
first, boolean second** — the reverse of RFC 4252 §5.1. Against chisel 1.12.1 the measured body
is `51 | 00 00 00 08 "password" | 00` (one method, `partial=false`, one trailing pad byte). A
parser written from the RFC reads that as garbage; `auth_read` parses x/crypto's order.

## Timeouts and keepalive

Three separate deadlines, all set with `setsockopt(SO_RCVTIMEO/SO_SNDTIMEO)` — the 13th winsock
name this image imports — and all cleared again before the data pump starts:

| phase | flag | default | what a timeout looks like |
|---|---|---|---|
| TCP connect | `--connect-timeout` | 8 s | non-blocking `connect` + `select`, confirmed with `SO_ERROR`; `retry: connect` |
| TLS handshake + upgrade read | `--ws-timeout` | 45 s | `handshake ret=-0x1`, `retry: tls handshake`; measured 1 s and 4 s flags produce 1030 ms and 4020 ms exits |
| SSH handshake, userauth, `config` | `--ssh-timeout` | 30 s | `stage handshake failed` / `stage auth failed`, `ss_run rc=-2`; measured 2 s and 6 s flags produce 2032 ms and 6041 ms exits |

They are cleared (`sock_timeo(fd, 0)`) before `ws_set_nb()` because the pump below is
`select`-driven: with a receive timeout installed, `recv` inside the pump would return
`WSAETIMEDOUT` on any idle second and look like a broken tunnel.

Keepalive is what notices a path that is *alive at the TCP layer and dead underneath* — a
front-end that dropped an idle stream, a NAT expiry, a laptop that slept. Without it the pump
sits in its 1 s `select` forever, because nothing ever arrives to wake it. The client sends the
SSH global request `ping` (`wantReply`) every `--keepalive`, and if no `81`/`82` comes back
within `--ping-timeout` (default: the keepalive interval) it declares the tunnel dead. Measured
with `tests/wedge_relay.py` (a relay that keeps both sockets open and silently stops forwarding):
a 3 s keepalive + 2 s ping-timeout ends the session 5-8 s after the path black-holes, the server
logs `session#N: Close (user=ops … duration=8.26s)` **because the client closed it**, and a fresh
session was declared and serving 6 MiB byte-exactly ~15 s after the path returned (console twin).
The shipped PE image, same rig, flags `--keepalive 3s --ping-timeout 2s --ws-timeout 3s
--ssh-timeout 4s --min-retry-interval 1s --max-retry-interval 3s`: the wedged session is closed by
the client (`Close … duration=11.323723s`), a fresh `Open` lands **3 s later**, and byte-exact
6 MiB fetches work **~8 s after the path returned**. Worst case is
attempts × (`--ws-timeout` + backoff wait). That PE number was ~45 s in an earlier build for the
same command line, and it was not the network: the flags sat past the 8-record packed-argument
cap and were dropped, so the image was dialing with 45 s defaults (see `PE_MAXARG` above). With
`--keepalive 0` the same hole was never noticed at all: zero marks, no teardown, one session
until the server's own pings expired it.

Pings are interval-driven, never per-spin: the earlier implementation answered every spin with a
ping, which saturated the server's mux and closed the session every ~27 s.

Reconnect: after any session death the client redials and re-declares its remotes, waiting
chisel's backoff (`jpillora/backoff`, jitter on, factor 2): uniform in `[min, min·2ⁿ]` capped at
`--max-retry-interval`. Measured: `1000, 1615, 3421, 6191, 9125, 19609, 28835 ms`. `attempts`
counts failed connections and is **reset once a session has stayed up for more than 5 s** —
upstream's `connected = time.Since(t0) > 5*time.Second` rule — so a long-lived proxy never burns
a budget. `--max-retry-count` behaves as it does upstream: the failed attempt is counted before
the decision, so `1` means exactly one attempt, and a negative value (the default) is unlimited.
At most `SESSION_MAX` (512) sessions are attempted per `go()` call, so a permanently unreachable
server cannot spin forever inside one beacon task.

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

- Keepalive runs in **both** directions (upstream's `BindSSH` starts `keepAliveLoop` on both
  ends): the server sends SSH **global** requests named `ping` (type `80`, `wantReply` set) every
  25 s and the client answers `pong` in type `81`; and the client sends its own `ping` every
  `--keepalive` (default 25 s) and requires the reply within `--ping-timeout`. A reply body of
  zero length or exactly `pong` is accepted — anything else is chisel's "strange ping response"
  and ends the session, as does a `81` carrying failure or a type `82` (peer refused the ping).
  Missing pings are how the *server* kills a wedged client ~125 s later; missing pongs are how the
  client notices a path that is silently black-holed (see
  [Timeouts and keepalive](#timeouts-and-keepalive)). The pump must never block, so pings are
  interval-driven, never per-spin.
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
- `ioctlsocket`'s command is an **encoded winsock ioctl**, not the BSD integer: `FIONBIO =
  _IOW('f',126,u_long) = 0x8004667E` (and `FIONREAD = 0x4004667F`). Passing BSD-style `0` makes
  the call fail with `WSAEINVAL`, which is what this payload used to do — so for a long time no
  socket was ever actually switched to non-blocking mode: the pump's "non-blocking" behaviour came
  from `MSG_DONTWAIT` on the TLS write path, and the bounded dial was decorative (a black-holed
  SYN stalled the single thread for the OS SYN-retry period, ~21 s, not the intended 8 s).
- Related, and the reason the mode is left alone: **the pump runs on blocking sockets, and that is
  the tested contract.** Turning the server socket non-blocking for real truncates proxied streams
  (`tls_read` maps a mid-record `WSA_E_WOULDBLOCK` to a transport error rather than "nothing yet":
  measured `0/6` in `tests/slowapp.py`, streams dying after 0.4-2.2 MB with zero server-side
  errors). The only intentionally non-blocking phase is the dial inside `sock_raw_connect`, which
  is restored to blocking before the fd is handed out — that is what makes `--connect-timeout`
  real, and `SO_RCVTIMEO`/`SO_SNDTIMEO` (ignored on a non-blocking socket) then bound every
  handshake phase.
- The WebSocket outbox (`obuf`) and the outbox-mode flag must be **reset per session**: a frame
  left half-flushed by a dead connection makes the next session's first write return "refused",
  and since nothing ever drains it there, the reconnect loop spins without ever reaching the pump.

## Diagnostic build switches

The payload is silent by default — there is no console and no file output. To see what it is
doing, compile one of these variants instead (both are the same sources, different entry):

| switch | effect |
|---|---|
| `-DTWIN_MAIN` | console twin: `main()` taking `argv` (`stock_run(argc, argv)`), `OUT(...)` lines on stderr, linked against a normal CRT. Mbed TLS debug threshold 4 (full handshake traces, incl. hex dumps of the ClientHello) via `mbedtls_ssl_conf_dbg`. |
| `-DDIAG_MARK` | the same `OUT(...)` lines go into an in-memory ring (`slogw`) instead of stderr, so the payload stays a PE image and you can read the marks afterwards. Mbed TLS threshold 1 by default; add `-DTLS_DBG4` for threshold 4 (the full extension/SNI dump — that is how the missing-SNI bug behind the front-end was proven). |

Mbed TLS's debug output is routed through our own `mbed_printf_impl` family, so enabling it pulls
in no stdio (see [build.md](build.md)).
