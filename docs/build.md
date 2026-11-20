# Build: toolchain, pinned flags, and the crypto dependency

## Toolchains

Tested: mingw-w64 **x86_64 8.1.0** (msvcrt runtime, the toolchain this client was developed
on) and, from a clean folder with nothing pre-staged, **winlibs GCC 16.2.0 posix-seh / UCRT
(mingw-w64 14.0.0 r3)**. Both produce 0 warnings and 0 errors, link with `--no-undefined`,
import exactly `ws2_32.dll` + `KERNEL32.dll`, pass the relocation audit (587/587 in-image on
8.1, 581/581 on 16.2), and pass the whole `tests/` suite.

Nothing else here is toolchain-specific — but the build **pins compiler behaviour**, because
distro gcc specs (MSYS2 in particular) differ, and a `-nostdlib` payload has no way to survive
a wrong default quietly.

| flag group | why it is pinned |
|---|---|
| `-Werror=implicit-function-declaration -Werror=implicit-int -Werror=int-conversion -Werror=incompatible-pointer-types -Werror=discarded-qualifiers` | these diagnostics are **errors by default in GCC ≥ 14** and only warnings on older gcc. Pinning them makes "it compiled on my box" mean "it compiles on a modern box". An earlier revision of this client relied on implicit declarations for its `snprintf` replacements and failed on a modern box with a wall of `implicit declaration of …`. |
| no `-w` anywhere | `-w` suppresses diagnostics **before** `-Werror=` can promote them, so with `-w` the pin above is decorative on a pre-14 toolchain. It was hiding two genuine bugs (an undeclared winsock `select()`, and a wrong-pointer call) that a modern toolchain rejected immediately. |
| `-fno-stack-protector -U_FORTIFY_SOURCE` | a stack protector and fortified libc calls reference `__stack_chk_fail` / `__stack_chk_guard` / `__chk_fail`, which exist only in a C runtime we deliberately do not link. |
| `-fno-pic -fno-pie` — **compile side only** | codegen must stay absolute/non-PIE: that is the image shape `tools/pehl2dir.py --audit` checks. **Never pass `-no-pie` to the link**: for this `-shared -nostdlib` image it produces a DLL the Windows loader refuses to initialise — `LoadLibrary` fails with `1114` (`ERROR_DLL_INIT_FAILED`) and gives no other clue. Verified both ways on this tree. |
| `-Wl,--no-undefined` | the payload must import nothing but `ws2_32` + `kernel32`. With `-nostdlib`, a stray libc reference (a `memcpy`/`printf` the compiler decided to call out-of-line, a library file that suddenly matters) would otherwise link into a DLL whose calls jump into garbage at run time. It has to be a link error. |
| `-fno-tree-loop-distribute-patterns` | `src/crypto.c` **defines** `memcpy`, `memset`, `memmove`, `memcmp`, `strlen`, `strcmp`, `strchr` (there is no CRT to borrow them from) and their bodies are byte loops. GCC ≥ 12 runs the loop-idiom pass at **-O2**, so it rewrites those bodies into calls to the very functions being defined: infinite self-recursion. Strip this flag and the payload *builds clean*, then hangs before the first `connect()` — silently, because the self-call is a tail call, so the stack never overflows. 8.1.0 only ran that pass at `-O3`, which is why it never showed on the reference box. |

If your gcc **specs** re-inject options after the command line (some MSYS2 builds re-add
`-D_FORTIFY_SOURCE` or a stack protector, which the `-nostdlib` link then rejects with
`undefined reference to __stack_chk_fail`), append your own flags without editing the scripts:

```
set EXTRA_CFLAGS=-D_FORTIFY_SOURCE=0 && build.bat
```

## The crypto dependency (`deps/MBED.a`)

`MBED.a` is simply Mbed TLS 3.6.7 compiled with **our** trimmed configuration — it is not a
mysterious blob, and it is not published. `tools/build-deps.bat` (called automatically by
`build.bat`) does this:

1. Fetches the GitHub source archive for tag **`v3.6.7`**
   (`https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.6.7.tar.gz`) and verifies its
   SHA-256 against the pin in that script
   (`7312b70b067b6a271961c8d36c3b8f9ba3e86fe6b26f18af13cd70430ee52ed1`). The build refuses to
   link against a crypto tree that is not exactly that one. `library/`, `include/` and
   `3rdparty/` of that archive were verified byte-identical to the tree this client was
   developed and tested against — there are **no local Mbed TLS patches**.
2. Compiles `deps/mbedtls-3.6.7/library/*.c` (109 files, minus `platform.c` — see below) plus
   our own `src/mbedfmt.c` (the `snprintf`/`vsnprintf`/`printf` Mbed TLS is told to use), with
   **`deps/mbedinc` first on the include path**, so
   `deps/mbedinc/mbedtls/mbedtls_config.h` wins over upstream's config.
3. Archives the objects into `deps/MBED.a` in batches (~110 quoted absolute paths exceed
   `cmd`'s 8191-character command-line limit) and generates `deps/WS2_32nat.a` from
   `deps/WS2_32nat.def` with `dlltool`. The def is the payload's entire winsock surface —
   13 names (`WSAStartup WSAGetLastError socket connect bind? no: send recv select getsockopt
   setsockopt ioctlsocket gethostbyname shutdown closesocket`) — `setsockopt` being there
   because `SO_RCVTIMEO`/`SO_SNDTIMEO` implement the handshake deadlines. If you add a winsock
   call to the payload, add it here first: `-Wl,--no-undefined` turns the omission into a link
   error rather than a crash, and deleting `deps/WS2_32nat.a` forces `dlltool` to regenerate it.

`library/platform.c` is **skipped on purpose**: `platform.h` force-defines
`MBEDTLS_PLATFORM_HAS_NON_CONFORMING_{SN,VSN}PRINTF` for every `__MINGW32__` build, so that
file would compile win32 `snprintf` shims that reference UCRT `vsnprintf_s`. Nothing in this
client references those shims — `nm` over the whole object set shows
`mbedtls_platform_setup/teardown` and the win32 `snprintf` helpers unreferenced, because
`calloc`/`free`/`printf`/`snprintf` are all overridden by config macros — so the file is left
out rather than declaring a prototype for a function we never implement.
`build.bat` links with `-Wl,--no-undefined`, which turns any future accidental dependency into
a hard error.

Offline build: download the archive yourself, verify the hash, unpack so that
`deps/mbedtls-3.6.7/library/` exists, then run `build.bat`.

## The configuration is load-bearing

`deps/mbedinc/mbedtls/mbedtls_config.h` decides which `.c` files contribute code, so a
different config means a different `MBED.a` — and a client that cannot talk to public
infrastructure. These groups must not be dropped:

- `MBEDTLS_ECP_DP_SECP256R1_ENABLED`, `SECP384R1_ENABLED`, `SECP521R1_ENABLED` **and the
  matching** `PSA_WANT_ECC_SECP_R1_256/_384/_521`, `PSA_WANT_ALG_ECDH`,
  `KEY_TYPE_ECC_KEY_PAIR_BASIC/IMPORT/EXPORT`, `ECC_PUBLIC`. Public CA chains (Let's Encrypt,
  Azure Front Door, caddy's internal CA) carry NIST **P-384** intermediates/roots, and the
  chain is **parsed before** `VERIFY_NONE` can apply — without the curve support the handshake
  dies at `MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE (-0x3A00)` and no amount of
  certificate-verification skipping helps. Both `MBEDTLS_ECP_DP_*` and `PSA_WANT_ECC_*` must
  list a curve: the PSA layer only registers curves it is explicitly told to want.
- `MBEDTLS_SSL_SERVER_NAME_INDICATION`: without it `mbedtls_ssl_set_hostname()` sets only the
  verification hostname and puts **no SNI extension on the wire, silently** — every
  multi-tenant front-end then routes the (perfectly valid) TLS connection to its default site,
  and you get `404`.
- `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` + `MBEDTLS_PEM_PARSE_C` (the client walks the chain),
  `ECDHE_RSA`/`ECDHE_ECDSA` key exchange, `TLS1_2` and `TLS1_3` protocol objects. The client
  itself **pins min = max = TLS 1.2**: this trimmed Mbed TLS build gets `handshake_failure`
  (fatal alert 40, `-0x7780`) from Azure Front Door when it offers TLS 1.3, so 1.2 is the
  verified working level, not an oversight.
- Every `PSA_WANT_*` is written `#define PSA_WANT_X 1` — the value upstream's
  `config_adjust_psa_{from,superset}_legacy.h` uses. Bare `#define PSA_WANT_X` collides with
  those headers and produces 14 redefinition warnings per library TU, which bury the warnings
  that matter.
- `#define MBEDTLS_TEST_SW_INET_PTON` pins upstream's own bypass so that `x509_crt.c` always
  uses its software `inet_pton`. Without it the choice depends on `_WIN32_WINNT >= 0x0600`,
  which old mingw defaults below and UCRT defaults above — so the *same* sources ask for
  `__imp_inet_pton` on one toolchain and not the other. Affects only X.509 name-constraint
  IP-prefix checks, never the handshake.

## The reference build, and how to compare your own

Nothing is published here — no releases, no tags, no binary assets — so there is no download to
match. The build every measurement in these docs came from (mingw-w64 8.1.0, msvcrt runtime,
2026-11-20) is 21,402,624 bytes,
`sha256 d71f4a1a4e5aaa2dda83c127024e438f7a25f9ac214ca4f123b72dcf21d427d7`, and a local rebuild will
not hash-match it: the PE timestamp differs, and Mbed TLS's debug build embeds the absolute
`__FILE__` paths of wherever the dependency was unpacked (that is a tens-of-kilobytes difference on
its own). Compare behaviour instead — `pehl2dir.py --audit` slot counts, the import list, and the
suites in `tests/`. A different toolchain is expected to produce a different size: winlibs GCC
16.2.0 (posix-seh, UCRT) gives 21,433,856 bytes with the same 13+1 imports, 581/581 slots and the
same suite results.
