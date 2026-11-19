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
    src/stock.c src/crypto.c src/x25519.c deps/MBED.a deps/WS2_32nat.a -o twin.exe
twin.exe https://127.0.0.1:8406 "R:1080:socks"
```

If the twin works and the DLL does not, the difference is the image (exports, relocations,
how it is loaded) rather than the logic.
