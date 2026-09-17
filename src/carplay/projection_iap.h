/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_IAP_H
#define GT86_PROJECTION_IAP_H
#include "control_cipher.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PROJECTION_IAP_HEADER 32u
#define PROJECTION_IAP_MAX_PACKAGE (4u * 1024u * 1024u)
#define PROJECTION_IAP_COMM UINT32_C(0x636f6d6d)
#define PROJECTION_IAP_PACKAGE 40
#define PROJECTION_IAP_IGNORED 41
#define PROJECTION_IAP_BUSY 3
#define PROJECTION_IAP_CLOSED (-7)

typedef struct projection_iap_config {
    control_cipher_config records;
    uint32_t package_limit,package_ms,hold_ms;
} projection_iap_config;
typedef struct projection_iap_storage {
    uint8_t *cipher_rx,*plain,*unused_tx,*package;
    size_t cipher_rx_size,plain_size,unused_tx_size,package_size;
} projection_iap_storage;
typedef struct projection_iap_key { uint64_t generation,token; } projection_iap_key;
typedef struct projection_iap_view { rtsp_slice header,body; } projection_iap_view;
enum projection_iap_reason { PROJECTION_IAP_REASON_NONE,PROJECTION_IAP_REASON_LOCAL,
    PROJECTION_IAP_REASON_CIPHER,PROJECTION_IAP_REASON_SIZE,PROJECTION_IAP_REASON_DEADLINE,
    PROJECTION_IAP_REASON_EXHAUSTED,PROJECTION_IAP_REASON_EOF };
typedef struct projection_iap {
    projection_iap_config config; projection_iap_storage storage; control_cipher cipher;
    uint64_t generation,now,package_at,held_at,next_token,held_token;
    size_t used,expected,offset;
    uint8_t held,dead;
    enum projection_iap_reason reason;
    int last_error;
} projection_iap;
/* Receive-only encrypted iAP DataStream input (session type130), not a socket,
 * USB/link/authentication engine or application dispatcher. Fresh noncopyable
 * serial owner; all arguments/storage/context disjoint. Treat fields as read-only;
 * only this owner calls its child cipher. Bindings immutable and
 * exclusively borrowed until close. No allocation, I/O, callback or background
 * work. Only caller-supplied, session-derived READ key is installed. No rekey,
 * reconnect, restart, write-record API or fabricated upstream ACK.
 *
 * records follows control_cipher (LE16 authenticated length, zero32||LE64 nonce,
 * payload<=16384). rx/unused_tx each >= payload_limit+18, plain >= payload_limit.
 * unused_tx is required storage of the shared duplex codec, never used to send;
 * its all-zero internal write key is NOT an available output credential.
 * package storage >= explicit package_limit (32..4MiB, including header).
 * Defaults: 64KiB package, 10s assembly, 5s hold; budgets1..60000ms. Larger valid
 * packages need explicit caller capacity. Only owned prefixes are wiped.
 *
 * Plaintext packages: BE32 total size at0, exact32-byte opaque header, BE32
 * message type at16. Only 'comm' bodies are delivered. Other message types are
 * bounded/assembled then ignored, never interpreted or automatically replied to.
 * Header/body views are authenticated, but unknown header fields have NO validated
 * semantic meaning. Bodies stay opaque; may contain split/coalesced iAP bytes.
 * Never assume a package is one iAP message or reset an existing iAP connection.
 * Caller must bind a live session/relay before routing, independently of RECORD.
 */
void projection_iap_default_config(projection_iap_config *);
int projection_iap_init(projection_iap *,const projection_iap_config *,const projection_iap_storage *,
                        const uint8_t read_key[32],uint64_t generation,uint64_t now_ms);
int projection_iap_check(projection_iap *,uint64_t,uint64_t now_ms);
/* At most one new cipher record and one complete package per call. Input tails
 * remain with caller. Retained authenticated tails may progress with used0;
 * feed(NULL,0) drains them. PACKAGE blocks further input until fully consumed.
 * IGNORED is progress, not a callback or success reply. Empty cipher records
 * advance the nonce, never package readiness/deadlines. Partial package/record
 * and held-body deadlines are absolute, unchanged by progress/empty traffic.
 * Wrong generation/backward time are transactional. EOF or any wire/deadline
 * failure closes/wipes all owned buffers and key, including held views.
 */
int projection_iap_feed(projection_iap *,uint64_t,const uint8_t *,size_t,size_t *consumed,uint64_t now_ms);
/* Read-only view; caller must check/feed with fresh time before using it. */
int projection_iap_peek(const projection_iap *,uint64_t,projection_iap_view *,projection_iap_key *);
/* Same token for partial prefix consumption. Nonempty body requires count>0;
 * empty body requires count0. Token/generation/count checked BEFORE clock mutation.
 * Only accepted body bytes may be consumed. Final consume retires the header.
 */
int projection_iap_consume(projection_iap *,projection_iap_key,size_t,uint64_t now_ms);
int projection_iap_eof(projection_iap *,uint64_t,uint64_t now_ms);
void projection_iap_close(projection_iap *);
uint32_t projection_iap_next_delay(const projection_iap *);
#ifdef __cplusplus
}
#endif
#endif
