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

#define MBEDTLS_PLATFORM_SNPRINTF_MACRO mbed_snprintf_impl
#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO mbed_vsnprintf_impl

#define MBEDTLS_OID_C

/* RSA: TLS 1.2 RSA-OAEP session-key unwrap + TLS 1.3 RSA suites (self-signed RSA test cert) */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21


#define MBEDTLS_PK_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_CIPHER_AES_ENABLED
#define PSA_WANT_KEY_TYPE_AES
#define PSA_WANT_ALG_CBC_NO_PADDING
#define PSA_WANT_ALG_CTR
#define PSA_WANT_ALG_GCM
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED

#define MBEDTLS_USE_PSA_CRYPTO

#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR

/* PSA wants (TLS 1.3 HKDF + ECDHE + hashes) */
#define MBEDTLS_PEM_WRITE_C
/* PSA wants (TLS 1.3 HKDF + ECDHE + hashes) */
#define PSA_WANT_ALG_SHA_256
#define PSA_WANT_ALG_SHA_384
#define PSA_WANT_ALG_SHA_512
#define PSA_WANT_ALG_HKDF
#define PSA_WANT_ALG_HKDF_EXTRACT
#define PSA_WANT_ALG_HKDF_EXPAND
#define PSA_WANT_ALG_ECDH
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC
#define PSA_WANT_ECC_SECP_R1_256
/* must mirror MBEDTLS_ECP_DP_SECP384R1/521R1_ENABLED above: PSA only registers
   curves it is told to want, and TLS parses/uses peer keys through PSA. */
#define PSA_WANT_ECC_SECP_R1_384
#define PSA_WANT_ECC_SECP_R1_521
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
