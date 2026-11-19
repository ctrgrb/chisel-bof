# Build problems: symptom → cause → fix

Each row is a failure that actually happened on some box, with the fix now in the tree.

| symptom | cause, and the fix that is in the tree |
|---|---|
| wall of `implicit declaration of function 'mbed_vsnprintf_impl'` / `mbed_snprintf_impl` / `printf` / `vsnprintf_s` | older copy of this folder. `MBEDTLS_PLATFORM_NO_STD_FUNCTIONS` suppresses `platform.h`'s `#include <stdio.h>`, so the `snprintf`/`printf` replacements the payload needs arrived **undeclared** — warnings on GCC 8, hard errors on GCC 14. `deps/mbedinc/mbedtls/mbedtls_config.h` now declares *and* overrides all four entry points (`MBEDTLS_PLATFORM_{SN,VSN,}PRINTF_MACRO` + `FPRINTF`), and `src/mbedfmt.c` provides them, so the library never references a libc symbol and no libc name is defined by us either. |
| `undefined reference to __stack_chk_fail` / `__chk_fail` at link | distro spec re-injects fortify/protector after our flags → pass them through `EXTRA_CFLAGS` (see [build.md](build.md)). |
| DLL loads with `1114` | `-no-pie` added to the link line → remove it (compile-side pin only). |
| `OUTPUT LOCKED: build\chiselbof.dll is still loaded by a running process` | a test client still holds the DLL mapped; stop it. Without this guard the delete fails silently and a stale DLL gets relinked with a fresh timestamp. |
| `MBED.a ARCHIVE FAILED` with an empty `build/mbedlog.txt` | one `ar` invocation carrying ~110 quoted absolute paths exceeded cmd's 8191-character command line; archiving is batched (24 objects per call). |
| stray directories named `..deps` / `..build` next to `build.bat` | `%~dp0..` was being resolved by string concatenation; the root is now canonicalised (`for %%I in ("%~dp0..") do set ROOT=%%~fI\`). |
| `SHA256 MISMATCH: got … expected …` | the file in `deps/` is not the v3.6.7 release tarball. Delete it and re-fetch, or download the pinned URL by hand, verify the hash, unpack so that `deps/mbedtls-3.6.7/library/` exists, then re-run. |
| `undefined reference to __imp_inet_pton` at link (UCRT toolchains only; the same sources link fine on the old msvcrt box) | `library/x509_crt.c` chooses the platform `inet_pton` or its own software copy on `_WIN32_WINNT >= 0x0600`. Old mingw defaults below that, UCRT defaults to Win10 — so the *same* sources ask for a libc symbol on one toolchain and not the other. Pinned to the software path with upstream's own bypass, `#define MBEDTLS_TEST_SW_INET_PTON`, in our config: same symbol set on every toolchain. |
| `warning: "PSA_WANT_ECC_SECP_R1_256" redefined` (×14 per library TU) | bare `#define PSA_WANT_…` colliding with upstream's `config_adjust_psa_{from,superset}_legacy.h`, which defines the same macros to `1`. Every `PSA_WANT_*` in our config is now `#define PSA_WANT_X 1`. No behaviour change — it just stops the warnings from burying real ones. Confirmed with `-Wp,-w` that nothing else was being silenced. |
| the `-Werror=` pins seem to do nothing; bad code compiles | the compile lines used to carry `-w`. `-w` suppresses diagnostics **before** `-Werror=` can promote them, so on a pre-GCC-14 toolchain the pins were decorative — and it was hiding two genuine bugs in `src/stock.c`: `select()` used with no declaration anywhere (now declared with the other winsock externs) and `mbedtls_ssl_session_free(&ctx)` called on an `mbedtls_ssl_context *` where an `mbedtls_ssl_session *` was expected (deleted — this client has no session object; `mbedtls_ssl_free()` already releases `ssl->session` and `ssl->session_negotiate`). On a modern toolchain both were hard errors. |
| builds clean, then **never reaches the server**: no server-side log line, socks port never bound, client prints nothing and never exits | `-fno-tree-loop-distribute-patterns` stripped ([build.md](build.md)): the compiler rewrote the byte loops inside our own `memcpy`/`memset`/`strlen` into calls to those same functions, so the client self-recurses before the first `connect()`. |
| the server logs `Login failed for user ""` (or `Login failed for user "<name>"`) and no `session#N: Open` ever appears | the server has `--auth`/`--authfile` and the payload was started without `--auth` (the empty username is the giveaway: chisel's auth is SSH password userauth, and an unset `--auth` sends no credentials). Pass `--auth <user>:<pass>`; remember the split is at the **first** colon, so quoting `"user:pa:ss"` is correct, `user:` means an empty password, and `--auth op` (no colon at all) is a client-side argument error (`bad --auth op (expected <user>:<pass>)`, return 7). |
| the payload appears to hang with no session and no exit, forever | older builds had no deadline for the TLS/upgrade/SSH phases. Every phase is bounded now (`--connect-timeout`, `--ws-timeout`, `--ssh-timeout`); if the process still looks stuck, one of them was set enormous, or a `--max-retry-count` of `-1` (unlimited) is redialing a dead endpoint with backoff capped at `--max-retry-interval`. Build the twin below and read which phase is failing. |
| `bad --keepalive xyz`, `bad --auth …` in the twin and an immediate exit 7 | duration flags use chisel's syntax — `500ms`, `30s`, `5m`, `1h`; a bare number means seconds and anything unparseable is a hard argument error, not a silent default. |
| a flag does something in the twin and nothing in the DLL: `--ws-timeout 3s` yet the handshake still dies at 45 s, or `--auth` behaves as if absent | the packed `z` list exceeded the argument cap. It used to be 8 records with the surplus dropped **silently**, which is why this is easy to miss: only the flags past the eighth vanished, and the proxy otherwise worked. The cap is 24 now and an over-long list returns 6 without starting, so it cannot fail quietly again. To confirm the diagnosis on a running process: `gdb -p <pid>` and read the installed `SO_RCVTIMEO` (`getsockopt(fd, 0xffff, 0x1005, …)`) — if it says 45000 while the command line said `3s`, the flag never arrived. |

## Diagnosing a payload that builds but does nothing

Two cheap moves, in this order.

**1. Attach a debugger to the running process.** In PE mode the payload prints nothing by
design, so a hang looks like silence:

```
gdb -p <pid> -batch -ex "thread apply all bt"
```

The failure modes have distinct shapes: a main thread parked in `memset`/`memcpy` inside the
image with one frame is the loop-idiom self-recursion above; a thread inside `connect`/`recv`
means the network path (URL, port, front-end upgrade) is the problem; `ssl_get_next_record()
returned -0x7200` (`MBEDTLS_ERR_SSL_INVALID_RECORD`) in the mbed debug trace usually means the
peer is **not** speaking TLS to you — e.g. you pointed `https://` at a plain-HTTP chisel server,
which answers `400 Bad Request` and logs nothing at the chisel layer.

**2. Build a console twin of the same sources** and watch it on stderr — every progress line,
plus Mbed TLS's own debug trace. Same sources, same flags, normal CRT, `-DTWIN_MAIN` instead of
`-DPE_MAIN`:

```
gcc -O2 -std=c11 -DTWIN_MAIN -fno-stack-protector -fno-pic -fno-pie -U_FORTIFY_SOURCE \
    -fno-tree-loop-distribute-patterns -I src -I deps/mbedinc -I deps/mbedtls-3.6.7/include \
    src/stock.c src/crypto.c src/x25519.c deps/MBED.a deps/WS2_32nat.a -lkernel32 -o twin.exe
twin.exe https://127.0.0.1:8406 "R:1080:socks"
twin.exe https://127.0.0.1:8406 "R:1080:socks" --auth op:s3cr3t --keepalive 5s --ws-timeout 10s
```

Lines worth recognising, in order of appearance:

```
auth=op keepalive=5000 ms ping-timeout=5000 ms dial=8000 ms ws=10000 ms ssh=30000 ms retry=-1 x 1000-300000 ms
                                        <- the parsed flag summary (retry=-1 means unlimited)
handshake ret=-0x1                      <- --ws-timeout fired during the TLS handshake/upgrade
stage handshake failed / ss_run rc=-1   <- --ssh-timeout fired
auth failure: methods=[password] count=1 partial=0
stage auth failed user=op  /  ss_run rc=-2   <- the server accepted the transport and rejected
                                             the credential: it is a credential problem, not a
                                             network one (rc=-2 is only ever userauth)
session died at SSH userauth: the server has --auth/--authfile set, …
ka: ping sent, reply due in 2000 ms     <- our own keepalive, and its deadline
ka: pong
ka: no pong within 2000 ms: ending session   <- black-holed path detected
retry: session (attempt 1/unlimited) waiting 1000 ms
retry: tls handshake (attempt 2/unlimited) waiting 1721 ms
give up after 3 failed attempts (last: tls handshake)
```

`ss_run`'s return code is the diagnostic: `-2` userauth rejected, `-1` everything else. The
process exit code mirrors `stock_run`'s: `7` bad arguments (bad duration, `--auth` with no
colon), `1` connect budget spent, `2` TLS-layer failure, `3` session/SSH failure. `-Wall
-Wextra` on this twin build is how the `%llu` format bug was caught (MinGW's default stdio
rejects it), which is why every duration in this code is printed as `%u` after a cast.

If the twin works and the DLL does not, the difference is the image (exports, relocations,
how it is loaded) rather than the logic.
