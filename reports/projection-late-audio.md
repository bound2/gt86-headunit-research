# Late PCM discard and local playback recovery

Date: 2026-09-10. Continues [relative playout](projection-playout.md) and
[CarPlay progress, Step 71](carplay-progress.md#step-71---discard-late-pcm-and-recover-on-the-original-timeline).

## Step 1 - Define what is being recovered

The optional PCM output can now discard overdue audio and restart its device
epoch on the original relative presentation timeline. Delayed authenticated AAC
and Opus bursts are decoded normally, but stale decoded samples need not play.
This is output recovery, not an authenticated RTSP FLUSH, codec reset, sender
clock adjustment, resampling or proof of CarPlay interoperability.

The new policy is explicit: `projection_wasapi_config.late_ms=0` preserves the
previous behavior; 1..1000 enables a lateness budget for timed PCM only. Untimed
PCM is unchanged. Invalid budgets are refused before opening an output device.
Existing input sample/time continuity validation remains in force.

The [GStreamer jitter-buffer reference](https://gstreamer.freedesktop.org/documentation/rtpmanager/rtpjitterbuffer.html)
already treats excessively delayed packets as loss. This implementation chooses
a different local boundary: decode authenticated, ordered input, then discard
PCM at the output. This preserves compressed-decoder history. No GStreamer body
or dependency is used, and no reference-equivalence claim is made.

## Step 2 - Trim queued PCM with exact timing and hysteresis

The PCM owner retains the first emitted sample's presentation time and a 64-bit
count of all accepted frames, including frames subsequently discarded. Its
schedule remains:

```text
due(frame_index) = first_PCM_presentation_ns
                  + floor(frame_index * 1,000,000,000 / sample_rate)
overdue         = now > due && now - due > late_ms * 1,000,000
```

Arithmetic uses checked quotient/remainder scaling. The strict comparison keeps
the exact lateness boundary; timestamp wrapping is independent of this 64-bit
frame count. The codec bridge's rational schedule and PCM's first-emitted-sample
origin can differ by the existing one-nanosecond rounding allowance.

If the queue's oldest frame exceeds the budget, discard the prefix up to the
first frame due **now or later**, not merely up to the lateness boundary. This
hysteresis avoids repeatedly restarting on the same boundary due to rounding.
Consequently some frames within the tolerance are deliberately discarded too.
The search is bounded by the 65,536-byte queue: at most 16 comparisons, followed
by bounded byte/provenance wiping. Elapsed silence does not create an unbounded
per-frame loop. A completely stale queue produces no new device Start.

`submit` still copies a complete chunk or consumes nothing on MORE. Acceptance
never means playback. Decoder work, gap concealment and replay checks happen
normally; dropping PCM does not skip codec validation or substitute compressed
history. Decoder/transport absolute ownership deadlines still fail closed. This
policy does not rescue an unpolled or already-expired session.

## Step 3 - Retire an overdue device epoch without inventing feedback

An unstarted prefilled buffer is reset if its first presentation time is too
late when activation is attempted. Start is rechecked after the transfer, so a
slow initial write cannot start stale prefill.

For a running device, an accurate device position/QPC pair is mapped back to its
original scheduled frame. If that observation is overdue, Stop/Reset retires the
epoch. An overdue software queue also forces reset before skipping frames: the
remaining queue cannot be spliced into a supposedly contiguous old device epoch.
An inaccurate clock observation alone does not establish a played position or
an observed lateness measurement.

Reset discards the **whole pending device buffer**, potentially including fresh
samples. The existing device API cannot recover or selectively trim those bytes.
This can cause an audible gap. Software-queued samples are separately trimmed,
then prefilling/start proceed with their original sample times. Device position
zero, dropped/pre-start media, concealment and retired provenance do not become
source playback anchors. Previously played audio cannot be recalled.

Microsoft documents that [IAudioClient::Reset](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclient-reset)
requires a stopped stream, discards pending data, and resets the stream clock.
The existing adapter calls Stop before Reset. It now also accepts the documented
`S_FALSE` success result for an already-reset stream. The OS implementation of
that edge was checked against documentation, not induced on a physical endpoint.

Only device-epoch counters/observations and device provenance are retired. Input
continuity, the PCM timeline, codec history, outer generation/leases, keys, peer
pinning and nonce replay history remain. In late-enabled timed mode even an
empty/drained output retains input continuity; ordinary authenticated two-phase
FLUSH is still required to authorize a different timeline. Reset failures close
all PCM resources and propagate through the decoder/audio owners as before.

## Step 4 - Configure without silently choosing hardware

For an explicitly selected WASAPI endpoint, rebuild callers with the new field:

```cpp
projection_wasapi_config output_config{explicit_endpoint_id, 100, 0, 30};
// Requested buffer 100 ms, startup wait 0 ms, late budget 30 ms.
// The separate decoder configuration must enable paced=1 for timed PCM.
```

This is an example matching the synthetic integration policy, not validated
car tuning or a request to start a speaker. The internal `projection_pcm::Output`
device seam takes the same optional final `late_ms` constructor argument. Existing
zero/default callers remain unchanged; old C binary-layout compatibility is not
asserted. No new wire flag, advertised capability, packet field or library is
introduced. The measured x64 PCM owner is 227,400 bytes, 24 bytes more than Step 70;
codec/device heaps and caller storage are additional, not QNX ARM measurements.

## Step 5 - Verify the integrated recovery

Eleven PCM-output groups and six decoder-service groups now cover:

- Strict before/at/after lateness thresholds, partial prefix trimming at all
  twelve PCM rate/channel mappings, sample wrap, full-ring discard, disabled and
  untimed policies, and retained continuity after complete stale discard/drain.
- Overdue prefill, accurate running-device delay, unavailable observations with
  an independently stale queue, delayed initial transfer, reset failure, and
  authenticated FLUSH after a local recovery. Genuine feedback after discarded
  concealment checks provenance retirement.
- Four additional 100-packet AAC/Opus timelines over actual encrypted IPv4/IPv6
  UDP. Packets 20..39 are withheld until packet 40's send time, then released in
  a 25-packet burst. This is approximately 400/464 ms of network delay while the
  receiver continues polling on its 1 ms synthetic clock.
- The delayed streams discard output and restart in a bounded number of device
  epochs, resume feedback near the original schedule, and match the final 20
  packets of an uninterrupted decode byte-for-byte. Keys/peer port/highest nonce
  remain intact, a late replay is still rejected, and ports close/reopen.

The device and time progression remain synthetic. Released bytes are not proof
of acoustic output; tail equality validates history continuity through the same
codec, not independent decoder fidelity. The earlier hybrid-Opus comparison
discrepancy and AAC recovery quality limits are unchanged.

All 42 media-enabled and 40 combined CTest suites pass, plus 25 Python regressions.
Both codec-enabled ASan/UBSan suites and all 13 hosted sanitizer checks pass,
including the eleven PCM groups and Windows argument/COM checks. Strict Clang
19 C++20 warnings and static analysis pass for both changed production units.
No instrumentation was disabled; the previously documented privileged-Windows-
symlink skip and Clang named-catch limitation remain unchanged.

Reproduce with the existing commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayMedia.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build-CarPlayCrypto.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayMediaSanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayTlsSanitizers.ps1 -IncludeEnrollment
python -B -m unittest discover -s tests -p test_*.py
```

No physical endpoint is selected or started by these checks.

## Step 6 - Remaining work

Next implement clock-drift estimation/correction with explicit clock evidence,
then sender timing/A-V mapping. This policy can remove accumulated late output
by discontinuity, but does not estimate rate mismatch, stretch/resample audio,
adapt latency, or guarantee smooth/perceptually acceptable recovery. Trailing
loss, DTX/FEC/retransmission and selective buffered FLUSH remain unfinished.

Actual CarPlay still requires video/display/input/microphone and control/focus
integration, a usable native transport, compatible existing Apple-chip access,
physical playback and phone acceptance. Factory module identity, installed-
version execution and recovery remain unresolved. No installable update for the
owner's head unit, modified firmware, update USB or vehicle operation was made.
