/* SPDX-License-Identifier: GPL-3.0-only
 * Hosted Windows backend, not a QNX port. Explicit paths only, no default files.
 */
#ifndef GT86_PAIR_STORE_FILE_H
#define GT86_PAIR_STORE_FILE_H
#include "pair_store.h"
#ifdef __cplusplus
extern "C" {
#endif
#define PAIR_STORE_PATH_MAX 260u
#define PAIR_STORE_ANCESTORS_MAX 32u
enum pair_store_file_state { PAIR_STORE_FILE_EMPTY,PAIR_STORE_FILE_ACTIVE,PAIR_STORE_FILE_POISONED,PAIR_STORE_FILE_CLOSED };
typedef struct pair_store_file {
    pair_store_data data;
    uintptr_t handle,ancestors[PAIR_STORE_ANCESTORS_MAX];
    size_t ancestor_count;
    uint64_t generation;
    uint32_t system_error;
    enum pair_store_file_state state;
#ifdef PAIR_STORE_TESTING
    unsigned test_fault; /* Only in separately compiled test backend. */
#endif
} pair_store_file;
typedef struct pair_store_file_view { pair_store_file *store;uint64_t generation; } pair_store_file_view;
typedef struct pair_store_file_binding {
    pair_store_file_view view;
    uint64_t enrollment_generation,authorization;
    uint8_t used;
} pair_store_file_binding;
/* Only absolute ASCII local fixed-drive paths <260 bytes. Reject device/UNC,
 * ADS, dot components, reserved names, reparse points and hardlinked files.
 * Parent/file must be current-process-user-owned with protected user-only DACLs.
 * Use a non-impersonating process. All argument/output storage must be disjoint,
 * including system_error (do not point it into the file owner's fields).
 * Holds ancestor handles against rename; holds file exclusive for its lifetime.
 * Explicit provisioning creates ONE NEW private directory, never changes an
 * existing directory's permissions and never recursively creates parents.
 * A failure after creating the new directory may leave it present, not removed.
 */
int pair_store_directory_create(const char *absolute_path,uint32_t *system_error);
/* Caller ZERO-initializes a noncopyable file owner. Fresh generation must be
 * nonzero and greater than its previous one; never reuse it. Create accepts
 * ONLY explicit count0/revision1 data and CREATE_NEW; open never creates.
 * Failure leaves owner unchanged, reports Win32 error where applicable. A
 * failed create can leave the newly created file: never delete/retry/repair it
 * automatically. Reopen scans ALL bounded journal images, then flushes before
 * publishing the last state. Partial/corrupt history fails closed, not truncated.
 * OS flush acknowledgement is not a tested power-loss/directory-durability claim.
 */
int pair_store_file_create(pair_store_file *,const char *,const pair_store_data *initial,uint64_t generation,uint32_t *system_error);
int pair_store_file_open(pair_store_file *,const char *,uint64_t generation,uint32_t *system_error);
int pair_store_file_view_init(pair_store_file_view *,pair_store_file *,uint64_t generation);
/* Borrowed immutable identity: owner/view must outlive every session. No reentry,
 * concurrency or close/reuse while borrowers exist. Poison prevents NEW use but
 * does not wipe underneath existing borrowers; frontend must quiesce them before
 * close, which wipes all owned secrets and closes handles. Stale close is inert.
 */
const pair_identity *pair_store_file_identity(const pair_store_file_view *);
int pair_store_file_lookup(void *view,const uint8_t *,size_t,uint8_t public_key[32]);
int pair_store_file_close(pair_store_file_view);
/* Explicit local-authority binding, not an approval UI or bearer authorization
 * protocol. Lifetime-bound and ONE attempt; matching validated invocation burns
 * binding even on conflict/failure. Wrong generation/authority does not burn it.
 * Commit is suitable for pair_setup_commit_fn, and only setup after verified M5
 * plus real local candidate approval may invoke it. Do not expose it to the wire.
 * Exact mapping is idempotent. New mapping appends a full snapshot and flushes
 * before cache publication/OK. Any attempted I/O failure poisons owner and returns
 * UNCERTAIN; no lookup/retry until explicit close/reopen validates the journal.
 * Synchronous local disk I/O has no hard time bound; isolate from real-time work.
 */
int pair_store_file_bind(pair_store_file_binding *,pair_store_file_view,uint64_t enrollment_generation,uint64_t authorization);
int pair_store_file_commit(void *binding,uint64_t enrollment_generation,uint64_t authorization,const uint8_t *,size_t,const uint8_t public_key[32]);
#ifdef PAIR_STORE_TESTING
/* Real file I/O with deterministic interruption points; NEVER in production lib.
 * 1 before write, 2 after a real 23-byte prefix, 3 before flush, 4 after flush.
 */
int pair_store_file_test_fault(pair_store_file_view,unsigned point);
int pair_store_file_test_initial_fault(pair_store_file *fresh_or_closed,unsigned point);
#endif
#ifdef __cplusplus
}
#endif
#endif
