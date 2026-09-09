# Persistent receiver identity and controller trust

Date: 2026-09-09. Progress Step 58; continues [pair-setup.md](pair-setup.md).

## Result and scope

Receiver identity and approved controller mappings now survive an actual file
close/reopen and process restart on the Windows development PC. The real
enrollment owner uses the file provider in tests; a newly enrolled controller
then completes pair verification and exchanges encrypted RTSP using the
reopened identity/store. These are public synthetic identities, not a connected
iPhone or the car's credentials.

The snapshot codec is portable C99. The filesystem backend is explicitly
Windows-only, not a QNX implementation or proof of head-unit durability. No
installable CarPlay update, target execution or hardware access is established.

Implementation:

- [pair_store.h](../src/carplay/pair_store.h) and
  [pair_store.c](../src/carplay/pair_store.c): explicit identity creation,
  bounded mappings, canonical snapshot codec and history validation.
- [pair_store_file.h](../src/carplay/pair_store_file.h) and
  [pair_store_file.c](../src/carplay/pair_store_file.c): private explicit paths,
  exclusive file ownership, append/flush, lookup and enrollment commit binding.
- [pair_store_tests.cpp](../tests/pair_store_tests.cpp): portable format tests.
- [pair_store_file_tests.cpp](../tests/pair_store_file_tests.cpp): actual file,
  process, security, corruption and enrollment/control tests. Built separately
  against both production and fault-instrumented libraries.

## Step 1 - Correct the physical commit contract

Step 57's statement that *every* storage failure must leave the file unchanged
was too strong. A write can partly complete, and an error after writing or
flushing does not prove that the data is absent. The setup provider contract
now distinguishes acknowledged success from an indeterminate outcome.

| Outcome | Storage behavior | Pair-setup behavior |
| --- | --- | --- |
| Invalid input, stale binding, conflicting key or full store | No file data write | No M6 success |
| Exact ID/key already present | No append; already validated/flushed mapping | May acknowledge success |
| New approved mapping, write and flush acknowledged | Publish new cached mapping | M6 becomes available |
| Write/flush outcome uncertain | Poison owner; suppress trust lookup until explicit reopen/validation | Close without M6; preserve provider error |

`PAIR_STORE_UNCERTAIN` is distinct from ordinary validation errors. There is no
automatic retry, rollback, deletion or "saved despite error" success. Setup's
`committed` flag means **acknowledged** commit: false does not establish that no
bytes reached disk; true does not establish that the peer received M6.

The backend uses write-through file handles and requires `FlushFileBuffers`
before reporting success. Microsoft documents the flush operation and the
cache/hardware qualifications separately. This is an OS-acknowledged persistence
boundary, not an atomic-sector-write, directory-flush, actual power-cut or
hardware-cache guarantee. No privileged whole-volume flush is performed.
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers),
[CreateFileW caching behavior](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

## Step 2 - Specify a bounded, canonical snapshot

One image is exactly 1,888 bytes. Integer fields are little-endian. No native
struct, pointer, `size_t`, compiler padding or private signing-key layout is
serialized.

| Byte offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `GT86PS01` format magic/version |
| 8 | 8 | Revision, exactly controller count + 1 |
| 16 | 1 | Receiver identifier length, 1..64 |
| 17 | 7 | Reserved zero |
| 24 | 32 | Explicit receiver Ed25519 seed |
| 56 | 32 | Seed-derived public key |
| 88 | 64 | Printable non-space ASCII identifier, zero padded |
| 152 | 4 | Controller count, 0..16 |
| 156 | 4 | Reserved zero |
| 160 | 1,664 | Sixteen 104-byte controller slots |
| 1,824 | 64 | SHA512 of bytes 0..1,823 |

Each used slot contains length1, reserved-zero7, identifier64 (zero padded),
public-key32. Unused slots are entirely zero. Duplicate identifiers, invalid
lengths/characters, nonzero padding/reserved fields, count/revision mismatches,
wrong checksums and inconsistent seed/public keys are rejected. Import derives
the signing secret from the seed; it never trusts an independent secret/public
pair. Encode also rejects inconsistent in-memory signing-key halves.

`pair_store_init` imports an explicit seed/identifier; `pair_store_generate`
requires an explicit caller-supplied CSPRNG. Neither is an open-file fallback.
No fixed/default identity, implicit path, automatic regeneration or production
use of fixture keys is provided. Failed init/generation/encode/decode leaves
the destination unchanged. Callers must wipe their seed, image and snapshot
copies; the owning backend wipes its secret-bearing temporaries and closed data.

`pair_store_add` is memory-only and is **not** a durable-commit callback. Exact
ID/key repeats are idempotent; a different key under an existing ID is a conflict.
There are at most sixteen entries, in insertion order. Public keys are opaque
32-byte values at this layer: enrollment must establish proof of possession and
real local approval before requesting insertion. Loading a file is not a new
cryptographic proof from each controller.

## Step 3 - Validate the entire append-only history

A file begins with count0/revision1. Every subsequent full snapshot adds exactly
one controller and preserves the receiver seed/identity and every previous
ID/key mapping. Open validates every image and every transition, not merely the
last checksum. The maximum is seventeen images, 32,096 bytes. Reads, record
sizes, controller capacity and path/handle counts are bounded.

The owner holds the file exclusively while open. Commit validates the candidate
on a temporary snapshot, confirms the expected current file length, appends one
image, flushes, then publishes only the appended entry/count/revision in memory.
It does not move the borrowed receiver identity or expose an unacknowledged
mapping. Exact existing mappings do not grow the journal, even at capacity.

This avoids an overwrite/rename protocol and its separate replacement and
directory-persistence questions. It does **not** make physical writes atomic.
A partial/corrupt tail, invalid earlier image or changed prefix makes open fail
closed. It never silently truncates to the last good record, deletes the file,
re-enrolls unknown identities or generates a replacement receiver identity.

Explicit reopening can reconcile an uncertain but complete authorized append:
the entire history must validate, then a flush must succeed before publication.
If the append is incomplete, no store is returned. Initial creation has the same
honest failure boundary: a failed create can leave a new empty, partial or complete
file, but never replaces an existing file. There is no automatic repair tool.

Important limitations:

- SHA512 detects corruption; it is not a MAC, encryption or defense against a
  malicious authorized file owner. Seeds are plaintext in the file and memory.
- Truncation at an exact earlier valid image boundary is indistinguishable from
  an older legitimate journal without an external trusted counter. This lack of
  rollback protection is explicitly tested, not presented as a rejected attack.
- Compaction, controller revocation/removal, identity rotation, backup restoration
  and migration are not implemented. Reaching capacity fails instead of replacing
  a mapping. Those operations need separate explicit authorization and recovery
  semantics before this can serve as a complete production trust-management UI.
- Actual power interruption may damage more than the last image. Filesystem,
  flash, storage-controller and QNX power-loss behavior remain untested.

## Step 4 - Make filesystem authority explicit

The host adapter accepts only absolute ASCII drive-letter paths shorter than
260 bytes on local fixed drives with persistent ACL support. It rejects UNC,
device/extended namespaces, alternate streams, dot/empty components, forbidden
characters, trailing dots/spaces, reserved device names and non-ASCII paths.
Forward slashes normalize to backslashes. This is a deliberately restricted
path contract, not a general Windows Unicode filename implementation.
[Microsoft filename and namespace rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).

Every ancestor is opened without following its reparse point, checked as a
normal directory and held without delete sharing for the owner's lifetime.
The immediate parent must have the current process user's ownership and a
protected DACL containing exactly its full-access allow entry. The file must
have the corresponding private file ACL, be a normal disk file, not be a reparse
point and have exactly one hard link. No elevation or privilege changes occur.

`pair_store_directory_create` provisions one **new** private directory at the
explicit path. It never recursively creates parents or modifies an existing
directory's permissions. File creation uses `CREATE_NEW`, opening uses
`OPEN_EXISTING`; actual ownership/ACLs are checked on handles, not inferred from
the security descriptor passed to open. File share mode zero excludes concurrent
read/write/delete opens across processes; metadata-only access is not covered
by that sharing rule. Upper ancestors need not themselves be private.
[CreateFileW creation/sharing/security behavior](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[security descriptor control](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptorcontrol).

The threat boundary is other unprivileged accounts, not malicious code running
as the same user, administrators, kernel/backup privileges, offline disk access
or process-memory compromise. Use a dedicated non-impersonating process/account
and an explicitly provisioned private production path outside this checkout and
unintended sync/backup locations. A plain SHA512 file checksum does not replace
that boundary. No actual production path or credential has been provisioned.

## Step 5 - Bind storage to enrollment and session lifetimes

The file owner is caller-zero-initialized, noncopyable and used serially, without
reentry. Successful create/open requires a nonzero generation greater than the
owner's previous generation. Generation-bound views provide a borrowed immutable
identity and a read-only cached lookup callback; lookup failures clear key output.
An old view/binding cannot read, write or close a reused newer owner.

`pair_store_file_bind` correlates one local authorization and enrollment generation
with the store lifetime. It is not an approval UI or an authority token accepted
from network input. Only the setup owner after verified M5 and explicit candidate
approval may invoke its commit callback. A matching valid invocation consumes
the binding even on conflict/capacity/I/O failure; stale or malformed calls do not
consume it. Setup already rejects stale request tokens and deadlines before
calling the provider.

Integration sequence:

1. Explicitly create a new identity/store, or open and validate an existing one.
2. Keep the store/view alive while any setup or verification session borrows it.
3. Obtain genuine local enrollment permission; bind that one authorized lifetime.
4. Run the owned SRP/setup route; approve the verified candidate deliberately.
5. Commit/flush before allowing M6; drain M6 before the existing transfer to fresh
   pair verification. A lost M6 does not automatically remove committed trust.
6. Use the store view for known-controller verification and encrypted control.
7. On storage uncertainty, stop new trust use and quiesce all borrowers before
   closing/wiping the owner. Explicit reopen validates/reconciles the journal;
   a corrupt result requires a separate authorized recovery decision.

Poisoning intentionally does not wipe an identity underneath an existing session.
It blocks new API access; the frontend must also close/quiesce existing sessions
before store teardown. A synchronous Win32 disk call has no hard latency bound:
isolate it from real-time audio/control work and refresh/check protocol time before
later output. No thread worker, approval UI, global rate limiter or listener is
implemented by this storage module.

## Step 6 - Exercise real files and failure boundaries

The portable tests cover round trips, stable signatures, all 1,888 single-byte
image mutations and every shorter image length, recomputed-hash malformed fields,
duplicate mappings, mismatched identity halves, capacity, conflicts, idempotence,
invalid identifiers, explicit RNG failure and non-prefix history.

The Windows suites use newly created private directories beneath the explicit
ignored build directory. They test actual exclusive access in a second process,
process restart, file/ancestor rename rejection, existing-file refusal, missing
file refusal, private ACLs, permissive/null DACL rejection, inherited-parent ACL
rejection, hard links, path policy, corrupted/partial/reordered history, full
capacity and stale ownership. Normal/security/enrollment paths run against the
production library as well as the instrumented test library.

An actual directory junction exercises reparse traversal refusal using the
documented mount-point buffer format. The separate symbolic-link test reports
**SKIP** because this PC lacks the necessary symlink creation privilege; no
privilege was enabled. Junction coverage is not claimed as execution of every
reparse tag. Both the junction and its target are new test-owned directories.
[REPARSE_DATA_BUFFER](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer),
[FSCTL_SET_REPARSE_POINT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point).

Test-only interruption hooks are compiled into a separate library, not declared
or exported in production. They interrupt before writing, after an actual 23-byte
write, before flushing a complete image and after a real successful flush but
before acknowledgement. Both first-file creation and enrollment append are
covered. These are real files with deterministic simulated interruption points,
not a power-cut test or an OS-reported disk-full simulation.

Enrollment integration performs real SRP/Ed25519/AEAD with the existing independent
public fixture. Approval denial writes nothing. Uncertain commits suppress M6,
leave the cache unpublished and block new trust access. Complete authorized records
can be recovered on explicit reopen; partial records remain rejected and unchanged.
Successful/reconciled enrollments and deliberately lost M6 replies are followed by
real pair verification and a bidirectional encrypted RTSP exchange from the reopened
store. The application response is explicit 501, not a fabricated working media route.

An initial sanitizer run exposed a test-oracle problem: C++ aggregate padding was
unspecified, yet a transactionality assertion compared whole object bytes. Tests
now initialize the complete owner representation and capture byte snapshots.
The failed assertion was initially obscured by a Windows Clang C++ exception
alignment diagnostic; local checks now print and abort directly. Storage rejection
was correct. No sanitizer check was disabled in the store or crypto code.

Commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
python -B -m unittest discover -s tests -p test_*.py -v
```

All 29 combined CTest, 19 standard and 22 TLS-only suites pass, as do 25 Python
regressions. Five pairing/control/store suites pass ASan/UBSan with Monocypher.
The real file/enrollment suite and the existing setup plus three TLS/carkit suites
pass ASan/UBSan with both crypto dependencies and composed modules instrumented.
New C99 modules pass strict Clang warnings in production and test configurations.
Production library symbol inspection confirms no `pair_store_file_test_*` API.

All ten optional portable pairing/control/store/Monocypher translation units
compile and relocatable-link for Cortex-A8 ARM with the same four permitted runtime
helpers as Step 55. This does not include the Windows backend, hosted SRP/MPI or
TLS. The separate twenty-unit import-free protocol core is unchanged. No linked
or executed QNX storage/receiver process is claimed.

Successful tests remove only their exact new synthetic files/directories. Four
known failed-run directories remain under ignored `build/enrollment-sanitized/`
because the execution environment rejected the subsequent cleanup command. They
contain only public test records, not user credentials. No pre-existing research
data was removed.

## Step 7 - Continue implementation without claiming installation readiness

Step 59 adds [encrypted MFiSAP and enrollment handoff](mfi-sap.md); authentication
runs after pair verification, not on an unauthenticated plaintext route. Next
connect explicit enrollment policy/first-request selection, capability declarations,
typed session handlers and real network/media endpoints. Storage still needs a
reviewed QNX backend, explicit revocation/
recovery policy and a genuine approval/provisioning frontend before production use.

Actual Go-module identity, native USB-network ownership, usable Apple authentication
chip access, installed-version execution/recovery and video/audio/input integration
remain unresolved. No real trust file, phone, head unit, firmware image or update
USB was read or modified. Windows persistence tests do not establish software-only
CarPlay on the factory hardware.
