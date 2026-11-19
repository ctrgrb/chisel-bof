# Running behind a public TLS front-end (Azure Front Door + caddy)

Topology this client is proven on, with example names substituted:

```
chiselbof.dll
  -> https://chisel.example.com:443        Azure Front Door terminates TLS
  -> www1.example.com:443                  caddy, site block proxying to the backend
  -> 127.0.0.1:8000                        plain: chisel_1.12.0 server --port 8000 --reverse
```

An AFD front-end answers on `https://<frontend-name>-<instance-hash>.z02.azurefd.net`; a custom
domain in front of it (`chisel.example.com` above) behaves identically, and it is the domain
that ends up in the SNI/`Host` of the client, so use that one in the payload URL.

The chisel server runs **plain HTTP** (`--reverse`, no `--tls`): the TLS terminus is the
front-end. The client must therefore speak TLS to the front-end, and the front-end must forward
the WebSocket upgrade.

## Probe the front-end before touching the client

From any machine:

```
curl -s -o /dev/null -D - --http1.1 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Protocol: chisel-v3' \
  https://chisel.example.com/
```

Expected: `HTTP/1.1 101 Switching Protocols` (with `Sec-WebSocket-Protocol: chisel-v3`). A plain
`GET /` returning `404` is **normal** — chisel only answers the upgrade.

## The traps, all of them measured here

Each row was an actual failure of an earlier build against exactly this chain. Every one of them
passes locally, because a plain chisel server ignores SNI, certificate chains and the `Host`
header — which is why local testing alone never caught them.

| symptom on the wire | cause | status |
|---|---|---|
| TLS handshake dies at `-0x3A00` (`MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE`) | config lacked P-384/P-521; AFD's chain is ECDSA with P-384 intermediates/roots and is parsed before `VERIFY_NONE` applies | fixed (config, see [build.md](build.md)) |
| `404` from the front-end after a clean TLS handshake | no SNI extension (compiled out) → the connection was routed to the default frontend | fixed (config) |
| `421 Misdirected Request`, error info `SSLMismatchedSNI` | `Host:` was written as `host` + port digits with **no colon** (`…example.com8443`); AFD correlates SNI with `Host` | fixed (`Host: host[:port]`, port omitted for the scheme default, exactly like Go's `net/http`) |
| client exits ~2 s after the backend restarts | the "no 101" path shared the 16-try hard-connect budget: caddy/AFD still complete TLS and answer `502` while chisel is down | fixed (back off and redial forever; only genuine connect failures are bounded, so a wrong URL still returns control to the beacon) |
| fatal alert 40 (`-0x7780 handshake_failure`) offered on TLS 1.3 | this trimmed Mbed TLS build's TLS 1.3 ClientHello is rejected by AFD | fixed (client pins min = max = TLS 1.2; AFD happily negotiates `ECDHE-ECDSA-AES256-GCM-SHA384` on 1.2) |
| `session#N: Close (…) (error ssh: remote side wrote too much)` after ~10 min of browsing | client-side SSH flow-control accounting | fixed — see [stability-invariants.md](stability-invariants.md) |

## Useful checks while it runs

- URL must be `https://` (or `wss://`), never `ws://`. The port may be omitted (`443` default);
  the `Host` header then reads `host` with no port, like a Go client's.
- Front-ends hand out one anycast address; different `x-azure-ref` values mean different POPs,
  not flakiness.
- **Reconnect through the front end**: stop the chisel backend, leave it down ~20 s
  (caddy/AFD keep answering, now with `502`), start it again — the untouched running client
  re-dials and the socks port is `LISTEN` again within ~6 s. Measured.
- Server-side verification while the payload runs:

  ```
  ss -tlnp | grep :1080
  curl -x socks5h://127.0.0.1:1080 -o /dev/null -w '%{http_code}\n' https://example.com
  ```

  with the server `-v`: `Open (… remotes=R:1080:socks)`, `Bound proxies`, and — for a healthy
  long session — **no** `wrote too much` lines at all.

## Throughput and shape

Behind the front-end the payload behaves like the Go client: one TLS session carrying one SSH
multiplexer carrying every channel. Reference soak on this chain (12 slow streams × 20 MB) is in
[stability-invariants.md](stability-invariants.md); the same session sustained normal browsing
and RDP without a reconnect.
