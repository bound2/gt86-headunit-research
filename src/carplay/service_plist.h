/* SPDX-License-Identifier: GPL-3.0-only
 * Independent bounded XML/binary plist subset for phone-service messages.
 * No allocation, I/O, external entities, trust operations or TLS.
 */
#ifndef GT86_SERVICE_PLIST_H
#define GT86_SERVICE_PLIST_H
#include "iap2_wire.h"
#ifdef __cplusplus
extern "C" {
#endif
#define SERVICE_PLIST_LIMIT 65536u
#define SERVICE_PLIST_NODES 256u
#define SERVICE_PLIST_PROJECTION_NODES 640u
#define SERVICE_PLIST_DEPTH 16u
#define SERVICE_PLIST_NONE UINT16_MAX
enum service_plist_type { SERVICE_PLIST_NULL, SERVICE_PLIST_BOOL, SERVICE_PLIST_INTEGER,
    SERVICE_PLIST_STRING, SERVICE_PLIST_DATA, SERVICE_PLIST_ARRAY, SERVICE_PLIST_DICT, SERVICE_PLIST_KEY,
    SERVICE_PLIST_REAL };
typedef struct service_plist_node {
    const uint8_t *data; size_t size;
    uint64_t magnitude; /* Integers: -2^63..2^64-1, separate sign. BOOL: 0/1.
                         * Projection REAL: raw finite IEEE bits; size=4/8,
                         * data=NULL, negative=0 (sign remains inside bits).
                         * Never interpret a REAL as an integer/boolean. */
    uint16_t first, next, children;
    uint8_t type, negative;
} service_plist_node;
typedef struct service_plist_storage {
    service_plist_node *nodes; size_t node_capacity; /* 1..256; explicit projection profile <=640. */
    uint8_t *bytes; size_t byte_capacity; /* 1..65536 */
} service_plist_storage;
typedef struct service_plist_document {
    const service_plist_node *nodes; size_t count, bytes_used;
} service_plist_document;
/* Parse ONE complete body, not its length prefix. XML UTF-8 and bplist00.
 * Root is node 0. Containers link children with first/next; dictionaries have
 * alternating KEY/value children and reject duplicate decoded keys. Strings
 * are UTF-8 byte views, not NUL-terminated. Data is decoded bytes. Supported:
 * string/key, data, integer, bool, array/dict, plus binary null. Real/date/UID,
 * sets and other extensions return UNSUPPORTED. XML declarations and the known
 * Apple public plist DTD are optional; no DTD is fetched or entity declared.
 * Numeric/predefined entities supported; no CDATA or processing instructions.
 *
 * <=65536 input bytes, <=16 levels INCLUDING the root, <=256 EXPANDED nodes.
 * Shared binary references are expanded; cycles, overlapping object spans and
 * invalid offsets/lengths are rejected. Limits are local, not Apple guarantees.
 * All strings/data are copied into caller storage; body may be released after
 * success. No overlapping arguments/storage, concurrency or reentry. Document
 * and storage stay read-only/alive until no views remain. Reusing storage
 * invalidates prior views. On ANY failure document is zeroed; scratch storage
 * may be partially overwritten, never a usable partial document.
 */
int service_plist_decode(const uint8_t *, size_t, const service_plist_storage *, service_plist_document *);
/* Explicit projection-only bplist00 profile: <=640 objects/expanded nodes,
 * caller storage <=640 nodes, plus finite 32/64-bit IEEE real numbers preserved
 * as bits (no floating-point execution or lossy integer conversion). Rejects
 * NaN/infinity, other real widths, XML and the other unsupported extensions.
 * Existing service_plist_decode remains <=256 and rejects ALL real values.
 * Same depth, byte, ownership, failure-publication and no-I/O guarantees.
 */
int service_plist_decode_projection(const uint8_t *, size_t, const service_plist_storage *, service_plist_document *);
/* Valid decoded documents only. Missing key -> END; wrong container -> INVALID.
 * Exact length-aware UTF-8 key bytes; output zero on failure. No clock or I/O.
 */
int service_plist_find(const service_plist_document *, const service_plist_node *dict,
                       const uint8_t *key, size_t, const service_plist_node **);
#ifdef __cplusplus
}
#endif
#endif
