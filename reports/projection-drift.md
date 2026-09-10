# Bounded output-clock drift correction

Date: 2026-09-10. Continues [late-audio recovery](projection-late-audio.md) and
[CarPlay progress, Step 72](carplay-progress.md#step-72---correct-local-output-clock-drift-with-bounded-rate-adjustment).

## Step 1 - Separate device drift from phone synchronization

The optional Windows PCM backend now adjusts its per-stream consumption rate
using actual device-clock observations. This tracks the existing local relative
PCM schedule without repeatedly discarding samples to remove small rate errors.
It does **not** establish a sender-NTP/RTP mapping, correct the phone's clock,
provide A/V synchronization, or make the receiver installable on the factory unit.

`projection_wasapi_config.drift_ppm=0` disables the feature. Values 1..1000 set
the maximum absolute rate correction in parts per million (1000 ppm = 0.1%).
Only timed PCM drives the controller. No received RTP field, codec format,
source sample timestamp or advertised sample rate changes. The existing decoder
still owns/decodes input, and the PCM owner still transfers the original bytes.

Microsoft's [clock frequency documentation](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclock-getfrequency)
distinguishes nominal frequency from device drift relative to QPC. Its
[position documentation](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclock-getposition)
describes correlated stream-position/QPC observations, initial zero positions,
inaccurate readings and stream reset. These are the evidence inputs, not packet
arrival counts or estimates of how much audio ought to have played.

## Step 2 - Measure and bound the correction

An internal `projection_pcm::Drift` owner consumes contiguous, accurate device
frame/time observations. It does no I/O and does not publish playback feedback.
The PCM owner invokes it only during normal polling, never from feedback queries.

Measurements span at least two seconds and no more than four. The controller
removes the previously applied correction from the observed rate ratio:

```text
observed_ratio = delta_frames / (nominal_rate * delta_QPC_seconds)
measured_ppm   = (observed_ratio / (1 + applied_ppm / 1e6) - 1) * 1e6
estimate      = first_measurement, otherwise 0.75 * old + 0.25 * measurement

phase_ns      = observed_QPC_ns - original_due_time(observed_frame)
phase_ppm     = clamp(phase_ns / 8000, -configured_cap, +configured_cap)
wanted_ppm    = ((1 + phase_ppm / 1e6) / (1 + estimate / 1e6) - 1) * 1e6
```

The eight-second phase horizon removes accumulated phase error gradually. The
command is rounded to integer ppm, capped by configuration, and slewed by at
most 100 ppm per measurement window. Repeated/small-interval observations cannot
accelerate the adjustment cadence. A positive phase means playback is behind
the original schedule; a positive command requests faster consumption.
Nominal-rate restoration on invalid evidence or epoch retirement is immediate,
not subject to the normal measurement-update slew limit.

Finite bounded floating-point arithmetic is local to this hosted controller.
It does not replace the checked integer sample/time mapping. Measured oscillator
error beyond +/-5000 ppm, invalid arguments, reversed observations, a window
over four seconds or phase beyond +/-100 ms invalidates the estimate and returns
to nominal. These are explicit local tuning/validity limits, not Apple limits.
Actual device errors still fail closed through the enclosing owner.

The control law is a local implementation, not copied upstream code or a
perceptually certified algorithm. The simulated response assumes a rate command
affects subsequent consumption. OS processing latency, hardware clock granularity
and resampler quality require separate measurement.

## Step 3 - Apply through the real Windows stream API

When enabled, the explicit render stream requests
[`AUDCLNT_STREAMFLAGS_RATEADJUST`](https://learn.microsoft.com/en-us/windows/win32/coreaudio/audclnt-streamflags-xxx-constants)
and obtains `IAudioClockAdjustment` through `IAudioClient::GetService`. There is
no fallback if the requested service is unavailable. Interface IDs come from
the installed Windows SDK type metadata, as with the existing interfaces.

The adapter calls
[`IAudioClockAdjustment::SetSampleRate`](https://learn.microsoft.com/en-us/windows/win32/api/audioclient/nf-audioclient-iaudioclockadjustment-setsamplerate)
with `original_rate * (1 + ppm / 1e6)`. Microsoft requires shared mode and says
not to call it from a real-time processing thread. This remains the serial,
non-real-time owner/polling thread: no hidden worker or real-time callback is
introduced. The change belongs to this stream, not the endpoint's default format
or volume settings. The existing Windows conversion path performs resampling.

After each rate command, the adapter checks that reported clock frequency units
and buffer capacity still match the opened stream. A change is unsupported and
closes the resource; the code never silently substitutes a new feedback scale.
Constant reported values alone do not prove a physical device's source-frame
mapping under rate adjustment. The existing original-frame clock mapping remains
a required backend contract, still needing physical validation.

## Step 4 - Retire stale control evidence and preserve feedback ownership

Only accurate, nonzero observations inside released, still-mapped device frames
can control the rate. Samples may be marked concealment: device clock progress
remains real, but the existing provenance rules still suppress source feedback
inside replacement audio. Control calculations never create a played position.

Readings older than 100 ms are unusable for correction. With no usable
observation for one second, the owner restores nominal rate and clears the
estimate. Fresh but implausible slopes/phase are rejected by the measurement
gates. Tests isolate inaccurate/stale observations with an empty software queue,
so late-drop/reset cannot conceal a missing nominal-rate restoration.

Completed drain, late-device reset and authenticated FLUSH restore nominal rate
and clear clock-control history. FLUSH still waits for encrypted-reply drain
before media resumption. Rate-command failure closes all PCM children; enclosing
codec/audio owners retain their existing fatal-cleanup rules. Close destroys the
private stream. No session key, replay window, peer port, lease or codec history
is reset merely because the rate changes.

## Step 5 - Configure and prepare physical verification explicitly

Rebuild callers with the new configuration field. For an already selected
endpoint, the test policy is:

```cpp
projection_wasapi_config output_config{explicit_endpoint_id, 100, 0, 30, 1000};
// Requested buffer 100 ms; startup wait 0; late budget 30 ms; drift cap 1000 ppm.
// Decoder bridge separately uses paced=1, ahead_ms=40, max_gap_ms=120.
```

These are laboratory values, not established settings for the head unit. A
zero-initialized new field preserves prior behavior; binary compatibility with
old headers is not claimed. The internal device seam attests `rate_adjustable`
and implements `adjust(ppm)`; existing providers default to unsupported. Enabling
correction requires capability and an initial successful nominal-rate command.

The compiled probe adds `--prepare-drift ENDPOINT_ID` (prepare/close without
Start) and `--silent-drift ENDPOINT_ID` (12-second zero-PCM smoke with timed input
and a 500 ppm cap). Both require an explicit endpoint. **Neither was run.** The
ordinary automated `--arguments` test still names only a nonexistent endpoint.
The smoke probe is not a known-drift calibration or acoustic-quality test and
does not establish that a nonzero correction was necessary.

Measured x64 PCM owner size is 227,528 bytes, 128 more than Step 71. The controller
adds no heap allocation or library. Existing codec/device/OS storage remains
additional; this is not a QNX ARM memory/CPU measurement.

## Step 6 - Verify constant and changing drift through the receiver pipeline

The existing executables now have thirteen PCM-output and seven decoder-service
groups. New tests cover:

- 180-second simulated constant +/-300 ppm and zero drift at 8/44.1/48 kHz.
  After settling, phase stays below 0.6 ms, with bounded command slew/cap.
- Dense noisy observations and an oscillator changing from +500 to -500 ppm;
  the controller re-converges. Exact window boundaries, repeated observations,
  frozen/reversed/implausible clocks, bad phase/configuration and large inputs
  reject unusable estimates without overflow or unlimited correction.
- Actual output integration with synthetic rate commands: missing capability,
  stale/inaccurate clocks, read-only feedback queries, late reset, two-phase
  FLUSH, rate failure and sibling cleanup.
- Eight 2000-packet encrypted UDP streams: AAC/Opus, IPv4/IPv6 and +/-300 ppm
  device drift. Each spans approximately 46.4/40 seconds of accelerated media,
  includes an intentional packet loss, and preserves one device Start and the
  expected complete PCM frame count. After 30 seconds, observed phase is below
  1 ms. Normal final drain restores nominal rate, and ports/leases close cleanly.

The final devices and their rate response are synthetic, not Windows acoustic
measurements or a physical-duration soak. These tests do not establish fidelity
of the OS resampler. Existing AAC/Opus reference limitations are unchanged.

All 42 media-enabled and 40 combined CTest suites pass, along with 25 Python
regressions. Both codec-enabled ASan/UBSan suites and all 13 hosted sanitizer
checks pass, including the final noisy-clock and isolated-outage tests. Strict
Clang 19 C++20 warnings/static analysis pass for both changed production units.
No instrumentation was disabled. The previously documented Windows privileged-
symlink skip and Clang named-catch limitation remain unchanged.

Use the existing [build and sanitizer commands](projection-late-audio.md#step-5---verify-the-integrated-recovery).
No physical endpoint, phone, microphone, car or firmware is accessed by them.

## Step 7 - Remaining work toward CarPlay

Next establish the sender's timestamp/timing mapping and integrate it with media
scheduling and A/V synchronization. Local device drift correction cannot prevent
queue growth caused by an independently drifting sender clock. It also does not
replace adaptive network jitter, large-discontinuity policy, trailing-loss/DTX/
FEC handling, selective buffered FLUSH, or perceptual recovery validation.

Native transport, actual Apple-chip access, video/display/input/microphone and
control/focus integration remain incomplete. Factory module identity, executable
installation/recovery on the installed version, physical playback and real-phone
acceptance remain required. No installable CarPlay firmware or update USB exists.
