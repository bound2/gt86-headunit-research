# PCM device output and observed playback

Date: 2026-09-10. CarPlay progress Step 67, continuing
[encrypted audio reception](projection-audio.md).

The Windows backend now implements the existing audio sink interface using
WASAPI. It prepares an explicitly selected rendering endpoint, queues PCM16,
starts after RECORD authorization and prefill, and reads the device clock for
feedback. Automated playback-device tests remain synthetic. Read-only enumeration
found three active Windows outputs; no physical output stream has been started
by this step. This is not a QNX driver or an installable factory CarPlay update.

## Step 1 - Establish the platform contract

`IMMDeviceEnumerator::GetDevice` resolves an explicit endpoint ID. The backend
also checks active state and rendering direction; it never asks for the default
device or falls back after an error.
[Microsoft endpoint lookup](https://learn.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nf-mmdeviceapi-immdeviceenumerator-getdevice).

The backend initializes shared-mode S16LE at the negotiated PCM rate/channel
count. Requested buffer duration is local policy, while actual capacity and
device period are queried from the initialized client. COM is scoped to the
creating STA thread; the owner, callbacks and final destruction stay on that
thread. An existing incompatible MTA is rejected.
[Initialization and threading](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclient-initialize).

`AUTOCONVERTPCM` and `SRC_DEFAULT_QUALITY` request Windows' PCM channel/sample-rate
conversion to the engine mix format. `NOPERSIST` and a fresh session GUID avoid
creating a persistent volume preference. No volume, mute, default-device,
microphone or loopback-capture API is used. This OS conversion is not an AAC or
Opus decoder and does not implement synchronization to the phone's clock.
[Stream flags](https://learn.microsoft.com/en-us/windows/win32/coreaudio/audclnt-streamflags-xxx-constants).

## Step 2 - Own a bounded PCM queue per resource

`projection_wasapi.h` exposes an opaque C owner and the existing
`projection_audio_sink`. Its C++ implementation uses an internal device seam so
the same output engine can be tested without starting a speaker. The public C
factory always binds the actual WASAPI implementation, never the test device.

Each audio type (100, 101, 102) has one independently owned device and a 65,536-byte
PCM queue. Open validates an exact canonical PCM16 format and actually prepares
the specified endpoint. Unknown formats, AAC/Opus, microphone and non-audio
resources are unsupported. Explicit capability availability remains the caller's
responsibility; this sink does not advertise a complete CarPlay profile.

Submission requires an armed resource, an aligned payload of at most 8,192 bytes
and a matching frame count. It converts S16BE to S16LE while atomically copying
the whole packet into the ring. `MORE` consumes nothing. Empty packets are
no-ops; no borrowed packet pointer survives the callback. Consumed queue bytes
are wiped immediately. Close wipes remaining PCM and resets resource metadata.
Leases increase across replacements; stale generation/lease operations cannot
close a replacement stream.

This first renderer requires contiguous authenticated sample timestamps modulo
2^32 within a run. A gap or overlap closes the output owner as unsupported. It
does not silently relabel samples or infer their time from unauthenticated RTP
sequence fields. A new origin is allowed only after the old device epoch drains
and the software queue is empty. These are local supported-profile restrictions,
not claims about every iPhone audio stream.

## Step 3 - Gate startup and handle starvation without inventing continuity

The sink's start callback arms playback after the existing RECORD/SETUP reply
drain. It does not start an empty device. Poll preloads actual queued media once
the queue can fill the endpoint buffer or the configured first-packet wait has
elapsed. Example settings are a 100 ms buffer capacity and a 20 ms prefill wait;
capacity is not a promise of exact playback latency.

Each poll makes at most one buffer acquisition/release, copying at most two
contiguous spans from the ring. Available space is actual capacity minus padding.
Acquisition and release occur on the same thread, with no intervening external
callback, allocation or sleep.
[Buffer ownership](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudiorenderclient-getbuffer),
[queued padding](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclient-getcurrentpadding).

Appending requires more than two device periods of queued headroom. With less,
the engine enters a drain state and appends nothing. Once the device clock has
reached the last released frame, it stops/resets that device and begins a new
prefilled epoch if media remains. Known tail samples can still be observed while
draining. A transfer taking a full device period or longer during an active run
fails closed because continuity is no longer sufficiently established.

This conservative policy can introduce audible gaps on starvation; it is not
loss concealment or seamless recovery. No synthetic silence is inserted into an
unaccounted device timeline. Device errors close all this output owner's streams
and wipe their queues. The enclosing audio service then closes its ports/keys;
the root receiver still owns cleanup of other session resources.

The backend does no hidden polling or waiting. Integrators must call the existing
receiver poll promptly, typically every 2..5 ms, using its deadline ordering.
OS/COM calls are synchronous and finite in number, not a hard execution-time
guarantee. The startup wait must also fit the surrounding held-output budgets.

## Step 4 - Report only observed media positions

WASAPI supplies a correlated stream position and QPC time. Position units are
interpreted using the stream's reported frequency, not assumed to be frames.
The QPC result is already expressed in 100 ns units; the adapter multiplies it
by 100, rather than applying the raw QPC frequency a second time. Delayed
`S_FALSE` observations report no position.
[Device position and correlated time](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclock-getposition).

For a contiguous epoch, the engine computes
`frame = floor(device_position * negotiated_rate / device_frequency)` with
checked integer arithmetic. It reports `epoch_origin + frame` modulo 2^32 only
for an accurate positive device position within released media. Initial zero
and the end/beyond-end position have no anchor. Device frequency and position
form the compatible unit pair.
[Frequency units](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclock-getfrequency).

Raw time must not precede the device start or exceed a fresh local clock sample.
Position/time reversal and overflow fail closed. Reset clears old observations;
no old epoch is mapped onto new data. No position is extrapolated to now, and
queued byte counts or padding are never returned as played samples.

`projection_wasapi_clock_ns` returns absolute QPC-derived nanoseconds. Both the
enclosing audio service and root timing service must use this exact domain and
an origin sampled from it. Mixing GetTickCount, Unix time or time-since-start
with these observations is invalid. Existing timing synchronization and feedback
freshness gates still decide whether to publish an NTP anchor.

## Step 5 - Wire the backend into the existing owner chain

1. Select an explicit rendering endpoint and create the WASAPI owner with the
   receiver generation. Check every return value; creation itself opens no
   audio stream.
2. Before audio-service initialization, set `audio_config.sink` to
   `projection_wasapi_sink(owner)` and `audio_config.clock_ns` to
   `projection_wasapi_clock_ns`. Keep explicit local/peer IPs and packet storage.
3. Before root-service initialization, set `root_config.media` to the audio
   provider and its clock to the same QPC ns helper. Anchor `mono_origin_ns` in
   that domain alongside the explicitly configured NTP origin.
4. Supply the root provider to the receiver's session configuration. Advertise
   only capabilities actually implemented and available; there is no default
   screen, microphone, authentication-chip provider or codec fallback.
5. Run all receiver/service/sink work serially on the creating STA thread.
   Receiver failures/teardown close downstream resources. Finally close the
   audio provider, then destroy the WASAPI owner on that thread. Destroying it
   while a provider still borrows its callbacks is invalid.

The new `carplay_wasapi` target is built in the combined Windows crypto/TLS
configuration. It uses the Windows SDK/COM libraries and existing PCM/crypto
helpers; no third-party codec package was added. SDK interface GUIDs are defined
from their MIDL type metadata because this SDK's `uuid.lib` does not provide
those six declarations. Only those definitions use the deliberate Windows
`__uuidof` extension. Nothing is added to the existing ARM portability claims.

## Step 6 - Verify software paths and preserve the physical-test distinction

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayTls.ps1
python -B -m unittest discover -s tests -p test_*.py
./build/pair-reference/Scripts/python.exe -B scripts/check_projection_audio.py build/crypto/Release/projection_audio_tests.exe tests/fixtures/projection-audio-vectors.txt
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
```

Seven output-engine groups cover all twelve PCM selections, endian conversion,
prefill, timestamp/ring wrap, atomic full queues, exact end positions, starvation
and restart, partial preparation, device-operation failures, stale leases,
thread checks, clock reversal/future timestamps and integer overflow. Device
clock positions deliberately use non-frame units. Separate actual Windows tests
cover invalid configuration, a nonexistent explicit endpoint without fallback,
COM apartment balancing, wrong-thread destruction and the real QPC clock. These
tests never start a physical endpoint.

The audio-service suite now has six groups. Its added real-loopback test sends
an encrypted UDP packet through authentication, reorder/start gates and the
actual PCM output engine. It checks the copied device bytes, a separately
supplied device-clock observation, outer playback validation, fatal cleanup and
port reuse. Only the final device interface is synthetic. Existing full paired
receiver/MFi/timing integration remains in that suite.

The new integration fixture initially expected never-opened stream buffers to
be wiped on an individual runtime failure. The existing contract wipes used
streams then; final close also wipes unused extents. The test now checks both
phases and the untouched caller tail. The large PCM fixture lives on the heap,
matching production, and explicitly tests exception cleanup. No production wipe
guarantee was weakened.

The installed Clang 19.1.5 sanitizer also corrupts a named catch-parameter binding.
A separate local five-line throw/catch program with no audio code reproduces the
misaligned `std::runtime_error` reference. LLVM documents this Windows ASan issue.
The fixture's intentional unwind uses a distinct exception type and an unnamed
typed catch, retaining the cleanup test and all ASan/UBSan instrumentation.
This is not evidence that heap allocation fixes the compiler issue. Failed-test
diagnostics using named catch parameters elsewhere can still encounter that
toolchain limitation.
[LLVM's catch-parameter investigation](https://lists.llvm.org/pipermail/llvm-commits/Week-of-Mon-20250915/1734547.html).

The reproducible physical-test tool is deliberately separate from CTest:

```powershell
./build/crypto/Release/projection_wasapi_probe.exe --list
# Substitute an explicitly selected ID from --list; neither command uses a default.
./build/crypto/Release/projection_wasapi_probe.exe --prepare 'ENDPOINT_ID'
# Optional: starts the selected endpoint for two seconds with zero-valued PCM only.
./build/crypto/Release/projection_wasapi_probe.exe --silent-smoke 'ENDPOINT_ID'
```

`--prepare` opens/closes 48 kHz stereo PCM without starting or submitting audio.
`--silent-smoke` additionally requires actual device-clock media observations to
pass. It sends no tone and performs no capture or volume changes. Only `--list`
has been run against physical endpoints in this step; it found FiiO K11, Jabra
Speak2 40 UC and Mi Monitor outputs. No output has been selected for a physical
stream test. Endpoint IDs are intentionally not committed as a default profile.

Final verification passes 40 combined, 22 ordinary and 25 TLS-only CTest suites,
25 Python regressions and the independent audio fixture checker. Thirteen
hosted suites pass ASan/UBSan with both crypto dependencies instrumented,
including the intentional exception-cleanup test. Strict Clang C++20 warnings
and static analysis pass for the new production modules; the sole documented
SDK-extension diagnostic exception is confined to the GUID definitions. Existing
dependency deprecation warnings and the privileged-symlink skip remain; actual
junction rejection passes.

The x64 output engine occupies 197,016 bytes, including its three 65,536-byte
queues. The outer endpoint-ID/COM owner, per-device allocations, OS buffers and
stack are additional. These host sizes are not a QNX memory/scheduling claim.

## Step 7 - Continue toward usable CarPlay

Alongside optional explicit-device validation, next implement compressed
AAC-LC/Opus decoding and a timestamp-aware playout policy for packet gaps,
overlaps, negotiated latency, flush and synchronized pacing. The current strict
PCM continuity profile is not sufficient for arbitrary phone media traffic.
Step 68 now supplies the optional codecs and owning PCM bridge in
[projection-decode.md](projection-decode.md); the full playout policy remains next.
Physical video/display/input, microphone and control mode/resource/audio-focus
semantics remain necessary.

Factory Go-module identity, installed-version execution/recovery, native USB
network ownership, compatible existing Apple-chip access and real iPhone
acceptance are still unresolved. No phone, vehicle, firmware image, real pairing
credential, speaker preference or microphone setting was changed by this step.
