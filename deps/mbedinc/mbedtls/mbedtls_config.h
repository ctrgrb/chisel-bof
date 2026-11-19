/* mbedtls_config.h shim for chisel-go BOF build.
 * Resolved via -I <mbedinc> ahead of the stock include/ tree: every
 * mbedtls header that does #include MBEDTLS_CONFIG_FILE (default
 * "mbedtls/mbedtls_config.h") lands here. Trimmed TLS 1.2 + 1.3 client:
 * ECDHE (secp256r1 + x25519), AES-GCM, ChaCha20-Poly1305, PSA with an
 * EXTERNAL rng (we feed it from crypto.c rnd()), no libc platform layer.
 */
#ifndef BOF_MBMBED_CONFIG_SHIM
#define BOF_MBMBED_CONFIG_SHIM
/* The CALLOC/FREE macros below expand to plain calls to arena_calloc/arena_free
 * in every mbedtls TU. Without a prototype those calls infer an int return, and
 * gcc then SIGN-EXTENDS the 32-bit return into the 64-bit pointer (movslq %eax,%rdx)
 * - which corrupts every arena pointer once the image is mapped above 2 GiB.
 * Declare them with the real signature so the full 64-bit return survives. */
#include <stddef.h>
void *arena_calloc( size_t num, size_t size );
void arena_free( void *p );

/* core bignum / ecdsa / ecdh */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_MD_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDH_GENP_SUPPORTED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
/* P-384 / P-521 are REQUIRED, not optional: public TLS front-ends serve ECDSA
   chains whose intermediates/roots sit on NIST P-384 (Azure Front Door / Caddy:
   leaf P-256 -> "Microsoft TLS G2 ECC CA OCSP" P-384 -> "Microsoft TLS ECC Root
   G2" P-384 -> cross-signed "DigiCert Global Root G3" P-384).  With only P-256
   the chain parse dies at the second certificate with
   MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE (-0x3A00) and the TLS handshake aborts -
   VERIFY_NONE cannot help, the parse happens before the verify callback.
   Caddy's own issuer defaults to ECDSA P-521, so enable that too. */
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED

/* hashes (SHA-NI paths auto-gated) */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_SHA384_C

/* ciphers used by TLS suites */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_POLY1305_C

/* asn.1 for ECDSA signature blobs in TLS1.2 */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C

/* PSA (required for TLS 1.3) with application-provided RNG */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG

/* keep peer cert (TLS 1.3 requirement) */
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

/* platform: no std functions, custom calloc/free (glue provides
 * mbedtls_calloc/mbedtls_free; printf stubbed by NO_STD_FUNCTIONS) */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO( n, size ) arena_calloc( n, size )
#define MBEDTLS_PLATFORM_FREE_MACRO( p ) arena_free( p )

#define MBEDTLS_ERROR_C


#define MBEDTLS_SSL_CLI_C

#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE

#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
#define MBEDTLS_DEBUG_C

/* ---- stdio replacement: there is no CRT, so every standard stdio entry point
 * that Mbed TLS *references* has to be both declared and provided by us.  This
 * is a build-portability requirement, not tidiness:
 *   - MBEDTLS_PLATFORM_NO_STD_FUNCTIONS above suppresses platform.h's
 *     `#include <stdio.h>`, so `mbedtls_printf` (which expands to a bare
 *     `printf` unless overridden) reaches every library TU undeclared;
 *   - platform.h force-defines MBEDTLS_PLATFORM_HAS_NON_CONFORMING_{SN,VSN}PRINTF
 *     for EVERY __MINGW32__ build, so library/platform.c compiles
 *     mbedtls_platform_win32_{snprintf,vsnprintf}, which call `vsnprintf_s`;
 *   - GCC >= 14 (any current mingw-w64 / MSYS2 toolchain) promotes
 *     -Wimplicit-function-declaration / -Wint-conversion /
 *     -Wincompatible-pointer-types from warnings to ERRORS, so those calls now
 *     stop the build.  (gcc 8.1.0, used to develop this client, only warned and
 *     the linker then dropped the never-referenced win32 shim - which is why the
 *     old build looked fine.)
 * We therefore override all four macros with our own implementations from
 * src/mbedfmt.c and declare them HERE, in the config header, because that is
 * the one file build_info.h includes before anything that uses them.  <stdio.h>
 * is deliberately NOT included: it would pull mingw's declarations plus the
 * `__USE_MINGW_ANSI_STDIO` redirections of printf/snprintf/puts into every
 * library TU, i.e. libc symbols the payload must never import. */
#include <stdarg.h>
#include <stddef.h>

int mbed_snprintf_impl(char *s, size_t n, const char *format, ...);
int mbed_vsnprintf_impl(char *s, size_t n, const char *format, va_list ap);
/* debug output has no sink inside a payload DLL: these discard the format,
   exactly as the previous `printf` stub in src/crypto.c did. */
int mbed_printf_impl(const char *format, ...);
int mbed_fprintf_impl(void *stream, const char *format, ...);

#define MBEDTLS_PLATFORM_SNPRINTF_MACRO    mbed_snprintf_impl
#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO   mbed_vsnprintf_impl
#define MBEDTLS_PLATFORM_PRINTF_MACRO      mbed_printf_impl
#define MBEDTLS_PLATFORM_FPRINTF_MACRO     mbed_fprintf_impl

/* ---- toolchain determinism: pin the header-driven code paths too ----
 * library/x509_crt.c chooses between the PLATFORM inet_pton() and its own
 * software implementation on `_WIN32_WINNT >= 0x0600` (x509_crt.c:2698).  Older
 * mingw-w64 (the msvcrt 8.1.0 toolchain this client was developed on) defaults
 * _WIN32_WINNT below that, so it compiled the software version; a current
 * UCRT-based mingw-w64 defaults it to Windows 10 and instead emits a reference to
 * ws2_32's inet_pton - which our -nostdlib, ordinal-only winsock import library
 * cannot satisfy (undefined reference to `__imp_inet_pton`).  Upstream's documented
 * bypass forces the software implementation (it exists so that code path gets
 * tested); using it makes MBED.a reference the same symbols on every toolchain.
 * Affects only X.509 name-constraint IP-prefix checks, never the TLS handshake. */
#define MBEDTLS_TEST_SW_INET_PTON

#define MBEDTLS_OID_C

/* RSA: TLS 1.2 RSA-OAEP session-key unwrap + TLS 1.3 RSA suites (self-signed RSA test cert) */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21


#define MBEDTLS_PK_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_CIPHER_AES_ENABLED
/* PSA_WANT_* must be written `#define PSA_WANT_X 1`, not the bare `#define
 * PSA_WANT_X`: build_info.h includes mbedtls/config_adjust_psa_{from,superset}_legacy.h
 * right after the config, and those headers define the SAME macros to `1` from the
 * legacy MBEDTLS_* options.  With a valueless define every library TU gets 14
 * "PSA_WANT_... redefined" preprocessor warnings, and any upstream check that reads
 * the VALUE (`#if PSA_WANT_ALG_X`) only works because their define lands first.  Keep
 * the `1` on all of them, including the ones upstream does not mirror. */
#define PSA_WANT_KEY_TYPE_AES 1
#define PSA_WANT_ALG_CBC_NO_PADDING 1
#define PSA_WANT_ALG_CTR 1
#define PSA_WANT_ALG_GCM 1
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED

#define MBEDTLS_USE_PSA_CRYPTO

#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR

#define MBEDTLS_PEM_WRITE_C
/* PSA wants (TLS 1.3 HKDF + ECDHE + hashes) - see the note above about the `1` */
#define PSA_WANT_ALG_SHA_256 1
#define PSA_WANT_ALG_SHA_384 1
#define PSA_WANT_ALG_SHA_512 1
#define PSA_WANT_ALG_HKDF 1
#define PSA_WANT_ALG_HKDF_EXTRACT 1
#define PSA_WANT_ALG_HKDF_EXPAND 1
#define PSA_WANT_ALG_ECDH 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT 1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC 1
#define PSA_WANT_ECC_SECP_R1_256 1
/* must mirror MBEDTLS_ECP_DP_SECP384R1/521R1_ENABLED above: PSA only registers
   curves it is told to want, and TLS parses/uses peer keys through PSA. */
#define PSA_WANT_ECC_SECP_R1_384 1
#define PSA_WANT_ECC_SECP_R1_521 1
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_SSL_ALPN
/* SNI is MANDATORY on the public internet: without it AFD/CDN/multi-tenant hosts
   route the TLS connection to their DEFAULT frontend and answer HTTP 404 (with a
   valid handshake!) instead of reaching the intended site.  mbedtls_ssl_set_hostname
   only sends the extension when this is compiled in - silently. */
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#endif
