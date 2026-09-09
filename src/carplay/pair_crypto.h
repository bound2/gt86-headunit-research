/* SPDX-License-Identifier: GPL-3.0-only
 * Explicit, memory-only Monocypher 4.0.3 adapter. No default RNG or key store.
 */
#ifndef GT86_PAIR_CRYPTO_H
#define GT86_PAIR_CRYPTO_H
#include "iap2_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PAIR_CRYPTO_MAX_DATA 65536u
#define PAIR_CRYPTO_MAX_KDF_INPUT 8192u
#define PAIR_CRYPTO_MAX_KDF_OUTPUT 16320u
#define PAIR_ID_MAX 64u
/* Synchronous CSPRNG callback: fill exactly n bytes, return 0 on success.
 * No reentry, pointer retention, default entropy or silent retry. Production
 * callers must supply a real platform CSPRNG; deterministic tests are not one.
 */
typedef int (*pair_random_fn)(void *,uint8_t *,size_t);
typedef struct pair_identity {
    uint8_t secret[64], public_key[32], identifier[PAIR_ID_MAX];
    size_t identifier_size;
    uint8_t ready;
} pair_identity;
/* Caller initializes a fresh noncopyable identity once. Internals read-only,
 * immutable while borrowed by a session. Import DER-independent raw seed and
 * optional expected public key; always derive the bundled signing secret,
 * never accept an independently supplied public half of a signing key.
 * Identifier is explicit 1..64 printable non-space ASCII bytes (not a UUID
 * generator). No file read/write, automatic replacement or persistence.
 * Invalid input/RNG/mismatched public key leaves destination unchanged.
 */
int pair_identity_import(pair_identity *,const uint8_t seed[32],const uint8_t *expected_public_key,
                         const uint8_t *identifier,size_t identifier_size);
int pair_identity_generate(pair_identity *,pair_random_fn,void *,const uint8_t *,size_t);
void pair_identity_clear(pair_identity *);
int pair_identity_sign(const pair_identity *,const uint8_t *,size_t,uint8_t signature[64]);
/* Canonical encodings and non-low-order public key/R required in addition to
 * the backend's curve/scalar/cofactored signature checks. No custom signing
 * algorithm, Ed25519ph, BLAKE2b EdDSA or unchecked success provider is used.
 */
int pair_ed25519_verify(const uint8_t public_key[32],const uint8_t *,size_t,const uint8_t signature[64]);
int pair_x25519_generate(pair_random_fn,void *,uint8_t secret[32],uint8_t public_key[32]);
int pair_x25519_shared(const uint8_t secret[32],const uint8_t peer[32],uint8_t shared[32]);
/* Fixed-width outputs require their full documented space. Other lengths are
 * bounded above; invalid arguments leave output unchanged. Failed ECDH/RNG or
 * AEAD authentication zeroes the applicable output. All arguments disjoint.
 * AEAD uses a fresh IETF context per call; caller owns unique 12-byte nonces
 * per key, not the backend's incremental rekeying scheme. Output is ciphertext
 * followed by its 16-byte tag. No plaintext exposed before tag verification.
 */
int pair_hkdf_sha512(const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t,uint8_t *,size_t);
int pair_aead_seal(const uint8_t key[32],const uint8_t nonce[12],const uint8_t *aad,size_t aad_size,
                    const uint8_t *,size_t,uint8_t *,size_t capacity,size_t *written);
int pair_aead_open(const uint8_t key[32],const uint8_t nonce[12],const uint8_t *aad,size_t aad_size,
                    const uint8_t *,size_t,uint8_t *,size_t capacity,size_t *written);
void pair_crypto_wipe(void *,size_t);
#ifdef __cplusplus
}
#endif
#endif
