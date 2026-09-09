/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_CONTROL_CIPHER_H
#define GT86_CONTROL_CIPHER_H
#include "pair_crypto.h"
#include "rtsp_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define CONTROL_CIPHER_FRAME 13
#define CONTROL_CIPHER_OUTPUT 14
#define CONTROL_CIPHER_CLOSED (-7)
#define CONTROL_CIPHER_BUSY 3
#define CONTROL_CIPHER_MAX_PAYLOAD 16384u
#define CONTROL_CIPHER_OVERHEAD 18u
typedef struct control_cipher_config { uint32_t payload_limit,receive_ms,hold_ms,output_ms; } control_cipher_config;
typedef struct control_cipher_key { uint64_t generation,counter; } control_cipher_key;
enum control_cipher_state { CONTROL_CIPHER_DORMANT,CONTROL_CIPHER_ACTIVE,CONTROL_CIPHER_DEAD };
enum control_cipher_reason { CONTROL_CIPHER_REASON_NONE,CONTROL_CIPHER_REASON_LOCAL,
    CONTROL_CIPHER_REASON_PROTOCOL,CONTROL_CIPHER_REASON_AUTH,CONTROL_CIPHER_REASON_DEADLINE,
    CONTROL_CIPHER_REASON_EXHAUSTED,CONTROL_CIPHER_REASON_EOF };
typedef struct control_cipher {
    uint8_t *rx,*plain,*tx;
    size_t rx_used,rx_expected,plain_size,plain_offset,tx_size,tx_offset;
    control_cipher_config config;
    uint8_t read_key[32],write_key[32];
    uint64_t generation,now,read_counter,write_counter,held_counter,output_counter;
    uint64_t rx_at,held_at,tx_at;
    uint8_t held,read_exhausted,write_exhausted;
    enum control_cipher_state state;
    enum control_cipher_reason reason;
    int last_error;
} control_cipher;
/* Memory-only duplex record codec, NOT a pairing/authentication owner. Fresh,
 * noncopyable, read-only internals; all storage/arguments disjoint. Buffers stay
 * borrowed until close: rx/tx >= limit+18, plain >= limit; only that prefix is
 * owned/cleared. Defaults limit16384, receive10s/hold5s/output5s, times1..60000.
 * init is dormant; start copies explicit directional keys once. Caller must
 * prove their origin and lifetime (projection_control owns this integration).
 * No automatic key generation, transport, idle timer, rekey or restart.
 */
void control_cipher_default_config(control_cipher_config *);
int control_cipher_init(control_cipher *,const control_cipher_config *,uint8_t *rx,size_t,
                         uint8_t *plain,size_t,uint8_t *tx,size_t,uint64_t generation,uint64_t now_ms);
int control_cipher_start(control_cipher *,uint64_t generation,const uint8_t read_key[32],
                          const uint8_t write_key[32],uint64_t now_ms);
int control_cipher_check(control_cipher *,uint64_t generation,uint64_t now_ms);
/* LE16 length is authenticated AAD, nonce = zero32 || LE64 directional counter.
 * Feed consumes at most one record, never exposes unauthenticated plaintext,
 * retains a complete (even empty) frame until consume, and leaves tail outside.
 * Partial receive/hold/output do not renew absolute budgets. Bad tag/oversize/
 * deadline/exhaustion closes both directions, zeroes all owned buffers/keys.
 * Counter UINT64_MAX is usable once; the next record closes, never wraps.
 */
int control_cipher_feed(control_cipher *,uint64_t generation,const uint8_t *,size_t,size_t *consumed,uint64_t now_ms);
int control_cipher_plain(const control_cipher *,rtsp_slice *,control_cipher_key *);
/* Key validation precedes clock; empty frame requires count0, nonempty >0.
 * Prefix retirement wipes plaintext; complete retirement enables next frame.
 */
int control_cipher_consume_plain(control_cipher *,control_cipher_key,size_t count,uint64_t now_ms);
/* Queue exactly one record <=limit (including empty). Encrypt once, advance
 * nonce once. Partial output retirement cannot reencrypt or reuse a nonce.
 * Complete retirement only means accepted by an exclusive downstream owner,
 * NOT physically sent. Higher-level owner must enforce its drain barrier.
 */
int control_cipher_queue(control_cipher *,uint64_t generation,const uint8_t *,size_t,uint64_t now_ms);
int control_cipher_output(const control_cipher *,rtsp_slice *,control_cipher_key *);
int control_cipher_consume_output(control_cipher *,control_cipher_key,size_t count,uint64_t now_ms);
int control_cipher_eof(control_cipher *,uint64_t generation,uint64_t now_ms);
void control_cipher_close(control_cipher *);
uint32_t control_cipher_next_delay(const control_cipher *);
#ifdef __cplusplus
}
#endif
#endif
