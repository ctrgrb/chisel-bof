# Stability: what to test, and why `curl` is not enough

Throughput tests with a fast consumer (`curl` a 100 MB file, browse 1.5 GB) pass even when the
client has flow-control bugs, because the SSH channel window never goes boundary-exact and a
WebSocket write never parks half-written. The shape that exposes the bugs is **many concurrent
channels whose application reads slowly** — RDP, Ad Explorer, a browser — which is exactly what
breaks in real use, as
`server: session#N: Close (…) (error ssh: remote side wrote too much)` plus quietly truncated
downloads.

## The suites in `tests/`

| test | what it does | pass condition |
|---|---|---|
| `tests/slowapp.py` | N parallel SOCKS5 fetches of `tests/pub/big.bin` (make it with `tests/mkpayload.py`), each read in 16 KiB chunks with a delay — ~320 KiB/s per stream | byte count **and SHA-256** of every stream; and the session is still alive (socks port still `LISTEN`) |
| `tests/slowtarget.py` | a target that accepts but reads 4 KiB every 2 s | the client paces to 2 KiB/s instead of buffering ahead |
| `tests/stalltarget.py` + `tests/uplapp.py` | a target that reads 8 KiB then **stops reading for 160 s**, while 2 MB is pushed at it | no spin (client CPU flat), no missed pings, only that channel is lost — other channels keep working byte-exact |
| `tests/udp_test.py` + `tests/udp_echo.py` | chisel's gob UDP codec: multi-socket, source-port fidelity, same-socket reuse, 1000 B datagrams | `UDP-TEST PASS`, and no decode complaints in the server log |
| `tests/wedge_relay.py` | a relay that keeps both TCP sockets open and silently stops forwarding (touch a flag file, delete it to restore) — the only way to test a black-holed path | the client ends the session within `--keepalive + --ping-timeout`, redials with backoff, and byte-exact fetches resume; with `--keepalive 0` it must *not* notice |

`tests/README.md` has the exact commands and which side of the tunnel each harness runs on (the
target is dialled by the **client**, so the payload HTTP server belongs on the client machine;
`slowapp.py` runs where the socks port is bound).

## Reference results

- Local chain (client and server on one machine): the flow-control build returned `0/6` streams
  intact and killed the session; the fixed build returns `6/6` with matching hashes,
  `wrote too much` count 0, and the socks port still bound afterwards.
- Real Front Door → caddy → chisel chain, 12 slow streams × 20 MB: `0/12` intact and the session
  aborted 66 s in (`ssh: remote side wrote too much`) before the fix; `12/12` with matching
  hashes and the session still bound 270 s later after it.

## The invariants, in `src/sshtun.c`

Worth knowing before patching anything in the pump:

- **`flush_pend` is the only place that emits a channel-data (`t=94`) frame**, and every payload
  byte it emits is charged against the channel window exactly once. The server aborts the *whole
  session* (`vendored/ssh/channel.go:336`, `if ch.myWindow < length`) if we overrun the credit it
  granted; a helper that emitted channel data "just for the SOCKS handshake reply" desynced it by
  12 bytes per channel.
- The WebSocket writer has **three distinct outcomes** and the caller must distinguish them: frame
  fully written / frame **committed** to the non-blocking outbox (partially written,
  `ws_outbox_flush` finishes it) / **refused** (the outbox still holds the previous frame, nothing
  went out). Reading the second as the third re-sent the same payload — duplicated stream bytes
  *and* phantom window credit.
- Channel EOF (`96`) is **deferred** until the queue has drained: sending it while bytes are parked
  tells the server the stream ended, and those bytes are silently lost (measured: every
  window-stalled download 1.2–9.4 KiB short).
- Target writes never spin: they wait for writability with a bounded `select()` and give up on that
  channel after ~30 s. One thread services TLS, the WebSocket, the server's 25 s ping and every
  channel, so a tight loop in one target's write path stops us answering pings and the server
  tears the session down ~125 s later.
- Window-stalled channels are excluded from the `select()` set (their target stays readable, which
  would spin the pump at ~66k syscalls/s); `rx93` (channel window adjust) / `pump_round` resume
  them.
- Channel table is 256 slots (`CH_N`), and `CH_W = 2097152` / `CH_MAX = 32768` deliberately match
  x/crypto's `channelWindowSize` / `channelMaxPacket` exactly — the server's accounting assumes
  those numbers.

- Keepalive pings are **interval-driven, never per-spin**. `ka_ms`/`ka_deadline` decide when the
  next global `ping` goes out, and at most one is outstanding at a time (`ka_wait`). Pinging every
  pump spin saturated the server's mux and closed the session every ~27 s; the interval form is
  also what upstream does. Conversely, the pong deadline is the *only* signal that a path which
  is still connected at the TCP layer has gone silent — with `--keepalive 0` a black-holed
  front-end is never noticed by the client at all.
- The `ping` reply body is accepted **raw**: zero length or exactly `pong`, anything else ends the
  session (chisel's "strange ping response"). A `81` with the failure flag, or a `82` (peer
  refused), also ends it. Never assume the reply is an SSH boolean + string: `keepAlivePing`
  upstream checks the same two shapes.
- **`SO_RCVTIMEO`/`SO_SNDTIMEO` are installed per phase and cleared before the pump**
  (`sock_timeo(fd, 0)` right before `ws_set_nb()`). Left in place, every idle second in the
  `select`-driven pump would surface as `WSAETIMEDOUT` and look like a dead tunnel.
- **The packed argument list is never truncated.** `pe_args` must consume every record; more
  than `PE_MAXARG` (24) records returns 6 and `stock_run` never starts. Each flag is two records,
  so a dropped tail means the image runs on defaults while the operator believes otherwise: this
  happened with a cap of 8 and showed up as `SO_RCVTIMEO` measured installed at 45000 ms — the
  default — on a stalled handshake whose command line said `--ws-timeout 3s`. Check the boundary
  (24 records → the server logs `Open`; 26 and 44 → no connection at all). Records are copied **by
  length, never by NUL** (a `b`-type record has no terminator, and a `z` record missing one must
  not eat the next record), and `flagis` matches flag names **with or without leading dashes** —
  positional C2 parsers (`exec_bof <types><args>`) claim any dashed token for their own options, so
  the dash-free spelling is the only one that can arrive. `tests/packedargs.py` asserts all of this
  against `go()`'s return code with no network involved.
- The reconnect attempt counter is **reset once a session has stayed up more than 5 s** (the same
  rule as upstream's `connected = time.Since(t0) > 5*time.Second`), so `--max-retry-count` bounds
  a *failed dial burst*, not the lifetime of a working proxy. Backoff waits must sleep in bounded
  `select` slices (`sleep_ms`), never one long `Sleep`, so a kill request stays responsive.

## Session lifetime

Sessions are cheap to rebuild and the client does it: on any session death — a failed dial, a
handshake that exceeded `--ws-timeout`/`--ssh-timeout`, a rejected credential (`rc=-2`, then
backoff), a wedged path caught by `--ping-timeout`, or a server-side teardown — it reconnects,
re-does TLS + SSH and re-declares its remotes, and the server logs a new `Open`. The wait between
attempts is chisel's jittered exponential backoff (`--min-retry-interval` …
`--max-retry-interval`), and the attempts spent are counted against `--max-retry-count`
(unlimited by default) with the counter reset after any session that lasted more than 5 s. That
is what keeps a session alive through a front-end `502` or a backend restart, and what makes a
wrong URL return control to the beacon instead of hanging forever. The rebuild path is capped
(`SESSION_MAX 512`) and the 20 MiB arena bitmap and offset are reset per session, so a long-lived
resident client does not leak.
