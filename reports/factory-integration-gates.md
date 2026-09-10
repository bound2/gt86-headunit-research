# Factory integration: evidence and remaining gates

Date: 2026-09-10. Continues [installation-path.md](installation-path.md) and
[CarPlay progress, Step 74](carplay-progress.md#step-74---return-to-factory-readiness-and-trace-the-remaining-media-reader).
Starting implementation checkpoint: `f6b981b`, verified on local `master` and
the configured GitHub remote. This step does not install or run software on a car.
Updated with [Step 75 diagnostic photo evidence](headunit-debug-photos.md),
supplied after the original Step 74 audit.

## Step 1 - Recheck the actual requested outcome

The requested outcome is CarPlay on the owner's existing GT86 audio/navigation
hardware, by software only. A Windows receiver library, synthetic phone exchange
or passing ARM object check is not that outcome. Bluetooth and wired Apple USB
are useful existing features, but neither supplies the missing execution,
transport, authentication and display interfaces by itself.

The current implementation includes real host cryptography, session handling,
audio decoding and Windows output support. It does not include a working factory
receiver executable or an installation/recovery procedure. The original goal
remains unachieved; no narrower host-only definition of completion is used.

## Step 2 - Revalidate local evidence rather than asking for duplicate photos

The owner-specified `C:/Users/donjulio/Pictures/headunit` folder still contains
the same seven files, `IMG_5867.jpeg` through `IMG_5873.jpeg`. Their earlier
direct inspection is recorded in [Step 11](carplay-progress.md#step-11---inspect-the-owners-existing-head-unit-photographs).
No added module-label photograph was present at this check. No photos, device-ID
strings, request codes or personal identifiers were uploaded or committed.

Known from the photos:

- Display/audio ID `13TFDAEU-DA05`, audio software `0101B0`.
- Navigation software `6.9.0WL`, maps `2017 v1`.
- License entries consistent with the later researched software family.

Still missing: the separate Go navigation module's model/part number and hardware
revision. The audio-unit ID and navigation activation identifiers are not
substitutes. The local firmware artifacts still contain the later `6.17.0WL`
research corpus, not an exact installed-version image or a unit backup.

The subsequently supplied four `Pictures/headunitdebug` photos add the audio
product code `PW600-18001`, Panasonic DA manufacturer/component versions, and
Harman International NAVI BOX manufacturer with `6.9.0WL`. Toyota documentation
maps the product code to TAS400 without DAB, not the Go module. See the
[new photo report](headunit-debug-photos.md) for direct readings and primary
sources. Exact navigation part/revision, Apple-chip identity and native access
are still not shown. The original Step 74 photo check above is historical, not
a claim that the newer folder contains no additional evidence.

## Step 3 - Audit readiness at the scope of the car

| Requirement | Current authoritative evidence | What remains necessary |
| --- | --- | --- |
| Match the physical target | Steps 11/75 identify Panasonic TAS400 audio and Harman NAVI BOX with `6.9.0WL` | Exact Go-module part/revision and matching firmware/variant evidence |
| Start and recover native code | [Installation analysis](installation-path.md) demonstrates selected later-loader behavior only in mocks/emulation | An established route on this installed version, plus recovery before any deployment experiment |
| Build a factory process | `Check-CarPlayArm.ps1` uses `armv7-none-eabi` and a relocatable link; it explicitly is not a QNX executable | Matching QNX ABI/runtime/toolchain and an actual target executable |
| Own the phone transport | [USB trace](usb-transport.md) identifies stock HID/media/audio service ownership | Native interface access and a coordinated ownership/restore plan, verified on the unit |
| Authenticate with existing hardware | Pinned driver/cached-export traces; synthetic MFi providers in tests | Usable compatible factory-chip API, complete real certificate/signature handling and phone acceptance |
| Render and control CarPlay | Windows-specific socket/WASAPI backends and synthetic final devices; no target display/video/input integration | Factory video decode, display switching, touch/buttons, audio focus/output and microphone support |
| Verify the finished system | Host tests exercise specified protocol/codec/lifetime behavior | Actual phone pairing, CarPlay UI, audio/input and safe recovery on the intended factory hardware |

No row is promoted to complete by a different row's passing tests. In particular,
`projection_services_win.c` includes Winsock/Windows interfaces and
`projection_wasapi_win.cpp` uses Windows COM/audio APIs; those are not native QNX
backends. No modified Toyota image or update USB is an output of the build.

## Step 4 - Check the official-update alternative without installing anything

Toyota Estonia's published smartphone-integration update page names RAV4 and
Corolla. It does not establish eligibility for this GT86. That is a limit of
the available evidence, not proof that every custom software route is impossible.
[Toyota Estonia multimedia update](https://www.toyota.ee/owners/connected-services/multimedia-updates).

Toyota's Touch 2 with Go dealer guide describes selecting the appropriate device
and a map/software package, with activation where applicable. It is not a custom
application loader or recovery procedure and does not establish a CarPlay upgrade
for this unit. No activation, account access, license purchase or vehicle update
was attempted. [Toyota dealer guide](https://mapupdatecontent.toyota-europe.com/Documents/Dealer%20Guide/MapUpdate_16MM_DealerGuide_English.pdf).

The bounded public-source check did not produce a verified exact `6.9.0WL`
download. Step 10's older HTTP 403 results were for guessed URLs, not proof of
global unavailability. No unrelated newer package was substituted or downloaded.

## Step 5 - Trace the outstanding native MediaService reader

Step 21 left the native `MediaService` information-file consumer unaudited.
This step follows that specific lead statically in the later corpus. It does
not execute the vendor process, invoke a parser, open a target file or query I2C.

Pinned input:

```text
extracted/qnx-system-v3/image-380000/usr/bin/MediaService
bytes: 1118933
CRC32: 5c94e242 (matches the recorded imagefs extraction inventory)
SHA256: 882e55fae0958f2a3d04d20ed9140d3777c8e798f1f7c9db710cfa6783f89796
```

Addresses below are unrelocated ELF virtual addresses, not raw file offsets.
The code-bearing PT_LOAD begins at `0x100000`, corresponding to file offset zero.

| Selected boundary | Static evidence |
| --- | --- |
| Information-file path | Function `0x17bc00` appends `/.FS_info./info.xml` through literal `0x17bda0`; the string is at VA `0x1e84d4` |
| Reader invocation | ARM BL at `0x17bd20` targets `0x178238`; nearby trace strings identify iPod storage-type handling |
| File operations | Calls at `0x1782ac`, `0x1782c0`, `0x1782dc`, `0x178348` resolve to `open`, `fstat`, `read`, `close`; selected open flags are zero |
| Parser setup | Uses Expat creation, element/text/processing-instruction handlers, then `XML_Parse` at `0x17830c` |
| Handlers | Start `0x1780a0`, text `0x177f8c`, end `0x177c3c`, processing instruction `0x177c40`; the last two return immediately |
| Selected tags | Start-handler comparisons refer to `model`, `id`, `productid`, `product`; text handling saves selected values in process-local buffers |
| Reader result | The reader inspects characters of the saved model ID and builds `flash` or `harddrive`; no XML buffer is returned by this result path |

`/etc/ipodModels.cfg` appears as an argument string at the caller, but the
selected reader does not use that incoming argument to load the file in the
examined routine. Its presence alone is not evidence of a configuration import
or user-supplied mapping facility.

The selected flow supports a storage-classification interpretation, not an
`authcoproc` export. The executable also has no contiguous ASCII `authcoproc`
literal, but that absence alone would not prove a lack of generic forwarding.
The conclusion rests on the selected reader/callback/result trace, and remains
limited to this consumer. It is not an exhaustive audit of all service APIs or
proof of the owner's running version. The whole media service has side effects;
do not launch it as a supposedly read-only collection tool.

## Step 6 - Preserve reproducibility and verify the analysis tool

`scripts/inspect_ipod_auth.py --module service` now checks the complete input hash
and emits the selected path, callbacks, tag literals, imported callsites and
result strings. Its new ARM BL decoder validates the selected instruction form;
it is not a general call graph or proof of dataflow.

```powershell
python -B scripts/inspect_ipod_auth.py --module service
python -B scripts/inspect_ipod_auth.py --module service --disassemble
python -B -m unittest discover -s tests -p test_*.py
```

Disassembly uses the existing LLVM path and existing bounded, in-memory ELF-header
adaptation. The default selected range is `0x17bc00..0x17bdac`; optional ranges
retain the existing 64 KiB/20-second limits. Original firmware is never rewritten.
The existing optional `--output NEW_PATH` still refuses overwrites. No saved
vendor binary or disassembly body is added to Git.

All **29 Python regression tests pass**, including four new static-trace tests
and changed-input refusal extended to this executable. They verify the selected
call/path/tag/result facts, reject non-call/unmapped addresses, and ensure default
inspection launches no subprocess or changes the input. They do **not** emulate
XML callbacks, query a chip, prove remote accessibility or validate CarPlay.
Production receiver code is unchanged by this step; its prior test results are
not relabeled as new factory validation.

## Step 7 - Separate offline work from deployment requirements

The Go module's exact part number and hardware revision remain unknown. They
would narrow target matching, but the owner has now confirmed that no further
identification information is available. Do not continue requesting the same
label or paperwork. This missing evidence limits deployment validation; it is
not an absolute blocker to offline analysis of the existing firmware corpus.
Step 75 now supplies its manufacturer, Harman International, and documentation
leads for navigation part-number families; the Panasonic audio product need not
be identified again. The generic chip-serial field is not an Apple-chip model.
Step 76's [navigation identification trace](navigation-identification-route.md)
finds a persisted part-number path with default/truncation limitations and a
stateful NaviSync export. Neither establishes passive PC access to complete
hardware identity or Apple-chip metadata; no on-car operation was performed.

The next offline investigation follows the native display request/release and
ownership-notification path. A method name or immediate success response is not
proof of granted display ownership or actual rendering. Keep later-corpus findings
separate from verified behavior on the installed `6.9.0WL` unit.

No VIN, device activation code, private key, dashboard disassembly, changed
service-menu flag or logging marker is requested. The MEDIA/lights sequence
explains the supplied service-menu photos; it does not establish privileged
OS access. If matching firmware or an existing diagnostic record becomes
available later, inspect it offline rather than trying it on the car.

Further host-only features cannot settle the missing physical identity,
installed-version execution/recovery and transport/chip access. The software-only
goal stays intact, but a deployable implementation cannot honestly be supplied
from the current evidence. No hardware add-on is substituted for the requested
approach, and no speculative installation instructions are supplied.
