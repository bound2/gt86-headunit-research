/* SPDX-License-Identifier: GPL-3.0-only
 * MFiSAP v1 responder, informed by pinned LIVI authSetup.ts. No chip driver,
 * credential, default signer, pairing bypass or claim of handset acceptance.
 */
#ifndef GT86_MFI_SAP_H
#define GT86_MFI_SAP_H
#include "pair_crypto.h"
#ifdef __cplusplus
extern "C" {
#endif
#define MFI_SAP_CERT_MAX 4096u
#define MFI_SAP_SIGNATURE_MAX 512u
#define MFI_SAP_REPLY_MAX (40u+MFI_SAP_CERT_MAX+MFI_SAP_SIGNATURE_MAX)
#define MFI_SAP_RESPONSE 19
#define MFI_SAP_DRAINED 20
#define MFI_SAP_CLOSED (-7)
/* Trusted synchronous actual-chip provider. Identity returns COMPLETE opaque
 * certificate bytes and protocol major from the SAME pinned provider identity;
 * sign uses that same identity's nonexportable private key. Only majors2/3 are
 * supported (SHA1/SHA256 digests). No fallback for unknown versions. Provider
 * owns complete certificate validation, chip/bus locking, identity stability,
 * time bounds and I/O; must not reenter or retain pointers. All outputs bounded,
 * written=0 on failure. These callbacks do not attest phone acceptance. */
typedef struct mfi_sap_provider {
    void *context;
    int (*identity)(void *,uint64_t generation,uint8_t *,size_t,size_t *,uint8_t *protocol_major);
    int (*sign)(void *,uint64_t generation,const uint8_t *digest,size_t,uint8_t *,size_t,size_t *);
} mfi_sap_provider;
enum mfi_sap_state { MFI_SAP_WAIT,MFI_SAP_HELD,MFI_SAP_DONE,MFI_SAP_DEAD };
enum mfi_sap_reason { MFI_SAP_REASON_NONE,MFI_SAP_REASON_LOCAL,MFI_SAP_REASON_PROTOCOL,
    MFI_SAP_REASON_CRYPTO,MFI_SAP_REASON_PROVIDER,MFI_SAP_REASON_DEADLINE };
typedef struct mfi_sap {
    pair_random_fn random;void *random_context;
    mfi_sap_provider provider;
    uint8_t output[MFI_SAP_REPLY_MAX];size_t output_size;
    uint64_t generation,now,held_at;
    uint32_t hold_ms;
    enum mfi_sap_state state;enum mfi_sap_reason reason;int last_error;
    uint8_t protocol_major;
} mfi_sap;
/* Fresh noncopyable owner; read-only internals, disjoint arguments, no reentry or
 * concurrency. Init calls no provider. No default RNG/identity, no transport or
 * controller authentication here: use only on authenticated encrypted control.
 * hold_ms1..60000 (recommended5000) is absolute response/drain budget; outer owner
 * must bound idle/receive. Refresh monotonic time after synchronous provider work.
 */
int mfi_sap_init(mfi_sap *,pair_random_fn,void *,const mfi_sap_provider *,uint32_t hold_ms,uint64_t generation,uint64_t now_ms);
int mfi_sap_check(mfi_sap *,uint64_t generation,uint64_t now_ms);
/* Exactly version1 byte plus peer X25519 public32. Fresh ephemeral; reject zero
 * ECDH, derive AES-KEY/AES-IV with SHA1, sign ownPublic||peerPublic digest through
 * provider, encrypt signature with AES128-CTR. Reply = ownPublic32, BE32 certlen,
 * cert, BE32 encrypted-signature length, encrypted signature. ONE attempt, no
 * retry. All ephemeral/private/shared/AES/plain-signature temporaries wiped.
 */
int mfi_sap_request(mfi_sap *,uint64_t generation,const uint8_t *,size_t,uint64_t now_ms);
int mfi_sap_response(const mfi_sap *,const uint8_t **,size_t *);
/* Attests complete enclosing encrypted reply drained; does NOT mean accepted by
 * Apple/phone or authenticated media. Wipes output/providers, cannot reuse. */
int mfi_sap_release(mfi_sap *,uint64_t generation,uint64_t now_ms);
void mfi_sap_close(mfi_sap *);
uint32_t mfi_sap_next_delay(const mfi_sap *);
#ifdef __cplusplus
}
#endif
#endif
