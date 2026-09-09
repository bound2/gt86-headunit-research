# Bounded plist decoding and typed Lockdown responses

Date: 2026-09-09. Continues [service framing](lockdown-service.md) and
[CarPlay progress, Step 49](carplay-progress.md#step-49---decode-and-validate-lockdown-responses).

Result: XML and binary plist bodies can now be decoded into caller-owned
storage and validated as GetValue, StartSession, StartService or Pair replies.
An explicit helper connects validation to held dispatcher-channel responses.
This is response handling, not phone pairing, TLS establishment, carkit startup
or an installable CarPlay receiver.

## Step 1 - Verify the response and serialization references

The existing checksum-pinned idevice 0.1.65 sources remain the Lockdown reference.
Its reader interprets string/integer Error fields separately from values;
StartSession checks EnableSessionSSL, and StartService obtains Port and optional
EnableServiceSSL. Local validation adds stricter type/range/correlation checks.
See the [pinned source records](lockdown-service.md#step-1---pin-the-service-dependency-before-implementing-its-framing).

The [Apple property-list DTD](https://www.apple.com/DTDs/PropertyList-1.0.dtd) and
[CPython plistlib at v3.14.7](https://github.com/python/cpython/blob/v3.14.7/Lib/plistlib.py)
were also inspected. Binary plists use an object table, offset table and
32-byte trailer; arrays/dictionaries refer to objects. Strings use ASCII or
UTF-16BE, and large lengths have an extended integer encoding.

The installed Python reports 3.14.7. Its plistlib.py matches the fetched v3.14.7
file after LF normalization. The installed file's raw SHA256 is
`a2507c4c70e0c29eca3332917334d36f525b506ca3d61ee846626eec0804587d`.
Python remains a host test/reference tool, not a receiver dependency. No upstream
function bodies or XML library were copied; see [provenance](../third_party/README.md).

## Step 2 - Define the bounded service-data profile

[`service_plist.h`](../src/carplay/service_plist.h) accepts one complete XML UTF-8
or bplist00 body, without its length prefix. Supported types are strings, keys,
data, integers, booleans, arrays and dictionaries; binary null is distinct from
false. Real numbers, dates, UIDs, sets and other extensions are explicitly
unsupported. This is a service-message subset, not a general plist replacement.

Local limits are 65,536 input bytes, 256 expanded output nodes, 16 nesting levels
including the root, and up to 65,536 caller-owned decoded bytes. Binary object
count is also capped at 256. No heap, file/network access, external entity lookup,
runtime I/O or mutable global state is used.

Containers link direct children with bounded indices. Dictionaries alternate
key/value nodes and reject duplicate decoded keys, including different XML
spellings. Shared binary references expand within the same limits; cycles are
rejected. Offset/reference widths of 1..8 bytes are checked before use.
Referenced objects cannot cross the next declared object boundary or offset
table. Unused object contents are not interpreted, but all offsets are checked.

All string/data values are copied into caller storage and use explicit lengths.
They survive release of the input body. Reusing storage invalidates prior views.
Decode failure clears the output document; scratch storage may be partially
overwritten and is not a valid partial result. Arguments/storage cannot overlap.

## Step 3 - Handle text and numeric boundaries

XML permits optional UTF-8 declarations, comments between elements and the known
public Apple plist DOCTYPE. That DOCTYPE is syntax only: nothing is fetched,
loaded or expanded. Internal entity declarations, other DTD identifiers,
processing instructions and CDATA are rejected.

Predefined/numeric character references are decoded with Unicode bounds.
Raw XML CR/CRLF becomes LF; character references retain their decoded character.
Overlong/truncated UTF-8, invalid UTF-16 surrogate pairs and non-XML character
values are rejected. Binary strings use the same character restriction as a
local consistency policy, not a universal binary-plist requirement.

Base64 supports whitespace but requires complete quartets, exact padding and
zero unused pad bits. Integer sign/magnitude preserves -2^63 through 2^64-1;
binary signed-eight-byte and extended-sixteen-byte encodings do not narrow or
overflow. XML accepts bounded decimal/hexadecimal integers. Boolean and integer
types remain distinct even when their numeric values are zero or one.

## Step 4 - Validate the expected reply before using fields

[`lockdown_reply.h`](../src/carplay/lockdown_reply.h) requires a dictionary with
an exact Request string matching the caller's outstanding operation. The channel
serializes requests; the application supplies the corresponding command/type.

| Response | Local validation |
| --- | --- |
| GetValue | Value exists and has the explicitly selected supported type |
| StartSession | SessionID is 1..256 printable-ASCII bytes; EnableSessionSSL is boolean true |
| StartService | Port is an integer in 1..65535 before conversion; a present EnableServiceSSL must be boolean |
| Pair | Optional EscrowBag is opaque data; no record is created or stored |

StartSession's false SSL flag returns AUTH_FAILED; there is no plaintext
downgrade. Absent service SSL metadata follows the pinned false default while
preserving flag presence. A malformed present flag is rejected, not converted
to false. Validated metadata does not mean TLS ran or the phone is trusted.

Any Error field prevents success even alongside apparent success fields.
Bounded nonempty string/integer errors return LOCKDOWN_REPLY_REMOTE_ERROR,
exposing only error fields and optional bounded ErrorString/ErrorDescription.
Malformed/oversized error metadata and orphan error-description fields are
rejected. Other failures clear the result. Nothing logs a whole response,
displays a trust prompt, retries or changes phone/vehicle state.

## Step 5 - Connect validation without implicit channel actions

lockdown_reply_read obtains a held response, decodes into supplied storage and
validates the expected command/type. Success or a well-formed remote error
returns the current release token. Other outcomes clear document/result/token;
malformed input does not silently release or advance the channel.

The helper is untimed and performs no callbacks, release, retry or closure.
The application polls first and keeps servicing deadlines. It explicitly
releases a handled response or aborts invalid input. SSL metadata never begins
a TLS handoff or bypasses the request physical-completion/ACK barrier.

An integrated test sends the encoded GetValue request through the actual
dispatcher with a fake raw backend, handles XML and binary synthetic ProductType
replies, distinguishes Error, and verifies owned decoded data survives release
and overwriting of the raw response buffer. Invalid input is explicitly aborted.
No actual phone participates.

## Step 6 - Verify malformed inputs, bounds and portability

Thirteen new groups cover grammar, entities, Unicode, duplicate keys,
integer/base64 boundaries, depth/node/arena caps, binary offsets/reference
widths, cycles/shared references, all fixture truncations, unsupported types,
typed errors, service-port bounds and TLS downgrade/type checks. A deterministic
24,000-case XML/binary mutation exercise checks output/storage bounds under
sanitizers; it is not exhaustive fuzzing or conformance proof.

Seven committed [binary fixtures](../tests/fixtures/lockdown/plist-binary-vectors.txt)
are synthetic dictionaries serialized by Python, not output from the C decoder.
Python tests parse their semantics and reproduce the bytes. Earlier XML fixtures
are unchanged. The channel suite now contains 18 groups.

Verification:

1. Build.ps1: 16/16 CTest suites.
2. Check-CarPlaySanitizers.ps1: twelve protocol suites under ASan/UBSan.
3. Check-CarPlayArm.ps1: sixteen C99 units, relocatable ARM link without imports.
4. `python -B -m unittest discover -s tests -p test_*.py -v`: 24 tests.
5. Whitespace and changed-document local-link checks.

A node is 32 bytes on the tested x64 host; 256 nodes occupy 8,192 bytes, plus
the chosen arena and document. An optional compiler -fstack-usage inspection
reports 2,176 bytes for the ARM decoder entry and 80 per recursive XML/binary
node call. These per-function static figures are not a demonstrated QNX runtime
stack budget or total native memory measurement.

The first ARM check found a division-helper import in a reference-length bound.
An overflow-safe product of already-bounded factors removed the import without
relaxing validation.

## Step 7 - Continue toward authenticated carkit startup

Next add explicit session/service request construction and an application state
machine that cannot use returned ports or hand off to TLS before validation.
Separate credential provision, user-authorized pairing/record storage and the
TLS adapter. Pairing must not be an automatic fallback; reference private-key
handling needs its own audit before implementation.

TLS, trust establishment, carkit startup, real QNX USB/network transport and
media/display/audio integration remain missing. Go-module identity, installed-
version compatibility, authentication-chip access and execution/recovery are
still unverified. No installable CarPlay image, modified ISO, update USB or
vehicle change was produced.
