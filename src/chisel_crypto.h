/* chisel_crypto.h - prototypes + sha256 state type for crypto.c */
#ifndef CHISEL_CRYPTO_H
#define CHISEL_CRYPTO_H
#include <stdint.h>
#include <stddef.h>

typedef struct {
	 uint32_t state[8];
	 uint64_t len;
	 size_t off;
	 uint8_t buf[64];
} sha256;

void sha256_copy(sha256 *src, sha256 *dst);
void sha256_init(sha256 *h);
void sha256_update(sha256 *h, const void *p, size_t n);
void sha256_final(sha256 *h, uint8_t out[32]);
void sha256_hash(const void *p, size_t n, uint8_t out[32]);
void ssh_kdf(uint8_t *out, size_t n, const uint8_t *K, size_t Klen,
	 const uint8_t *H32, const uint8_t *sessionId, size_t sidlen, uint8_t tag);
size_t mpint_payload(const uint8_t *sec,size_t n,uint8_t *out);
void chacha20_keystream(const uint8_t key[32], const uint8_t nonce[12],
	 uint32_t ctr, uint8_t *out, size_t n);
void poly1305_sum(uint8_t out[16], const uint8_t *msg, size_t n,
	 const uint8_t key[32]);
int b64_encode(const uint8_t *in, int n, char *out);

/* x25519.c */
void x25519_scalarmul(const uint8_t scalar[32], const uint8_t u[32],
	 uint8_t out[32]);
void x25519_base(const uint8_t scalar[32], uint8_t out[32]);
void x25519_clamp(uint8_t k[32]);
#endif
