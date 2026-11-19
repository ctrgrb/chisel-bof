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

## Session lifetime

Sessions are cheap to rebuild and the client does it: on any session death it reconnects, re-does
TLS + SSH and re-declares its remotes (the server then logs a new `Open`). Connect failures are
bounded (16 tries) so a wrong URL returns control to the beacon; everything else backs off 2 s
forever, which is what keeps a session alive through a front-end `502` or a backend restart. The
rebuild path is capped (`SESSION_MAX 512`) and the 20 MiB arena bitmap and offset are reset per
session, so a long-lived resident client does not leak.
