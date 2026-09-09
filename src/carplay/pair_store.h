/* SPDX-License-Identifier: GPL-3.0-only
 * Portable bounded identity/trust snapshots. No filesystem or default identity.
 */
#ifndef GT86_PAIR_STORE_H
#define GT86_PAIR_STORE_H
#include "pair_crypto.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PAIR_STORE_MAX_CONTROLLERS 16u
#define PAIR_STORE_IMAGE_SIZE 1888u
#define PAIR_STORE_HASH_OFFSET 1824u
#define PAIR_STORE_MAX_FILE_SIZE (PAIR_STORE_IMAGE_SIZE*(PAIR_STORE_MAX_CONTROLLERS+1u))
#define PAIR_STORE_CLOSED (-7)
#define PAIR_STORE_CORRUPT (-8)
#define PAIR_STORE_CONFLICT (-9)
/* Some/all bytes may have reached storage. No success, retry or rollback is
 * implied. A file owner must stop serving trust until close/reopen validates it.
 */
#define PAIR_STORE_UNCERTAIN (-10)
typedef struct pair_store_entry {
    uint8_t identifier[PAIR_ID_MAX],public_key[32],identifier_size;
} pair_store_entry;
typedef struct pair_store_data {
    pair_identity identity;
    uint8_t seed[32];
    pair_store_entry controllers[PAIR_STORE_MAX_CONTROLLERS];
    uint64_t revision;
    uint32_t count;
    uint8_t ready;
} pair_store_data;
/* Read-only internals; all inputs/outputs disjoint. Explicit import/generation,
 * never a missing-file fallback. Invalid input/RNG leaves destination unchanged.
 * Snapshots contain secrets: caller must clear them, including copies/images.
 */
int pair_store_init(pair_store_data *,const uint8_t seed[32],const uint8_t *expected_public,
                    const uint8_t *identifier,size_t);
int pair_store_generate(pair_store_data *,pair_random_fn,void *,const uint8_t *,size_t);
void pair_store_clear(pair_store_data *);
/* Memory only, NOT a commit provider. OK adds; END is exact existing match;
 * CONFLICT refuses an existing ID with another key. Never replace/remove trust.
 * Public keys are opaque 32 bytes here; enrollment must verify possession first.
 * Lookup returns END for unknown ID and clears output on every failure.
 */
int pair_store_add(pair_store_data *,const uint8_t *,size_t,const uint8_t public_key[32]);
int pair_store_lookup(const pair_store_data *,const uint8_t *,size_t,uint8_t public_key[32]);
/* Fixed, canonical, little-endian versioned image, SHA512 corruption checksum.
 * Not encryption, authentication or rollback protection. Decode validates every
 * reserved byte, ID, duplicate, count/revision and seed-derived public key.
 * Failed encode/decode leaves destination unchanged. Capacity >= IMAGE_SIZE.
 */
int pair_store_encode(const pair_store_data *,uint8_t *,size_t capacity);
int pair_store_decode(pair_store_data *,const uint8_t *,size_t);
/* Journal must start at count0/revision1 and append exactly one new controller
 * per image, preserving identity and the complete previous prefix. Individual
 * decode alone does NOT validate this history. OK only for that next snapshot.
 */
int pair_store_successor(const pair_store_data *previous,const pair_store_data *next);
#ifdef __cplusplus
}
#endif
#endif
