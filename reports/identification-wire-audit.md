# Identification payload audit: packed language list

Updated: 2026-09-09. Continues [startup-order.md](startup-order.md).

## Step 1 - Publish startup-order support

Committed and pushed `5fb094d`, `Support explicit identification-first iAP2
startup`. The following correction is a separate implementation step.

## Step 2 - Reproduce the payload mismatch

At pinned LIVI commit `a76553fc941dcf378dd55c04da56aaf3d6911e08`,
IdentificationInformation defines SupportedLanguage as `[list str]`, field 13.
The CSM encoder writes a list as one parameter containing the concatenated
element payloads; each string carries its terminating NUL.
[Identification schema](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/src/messages/identification.rs),
[list encoding macro](https://github.com/f-io/LIVI/blob/a76553fc941dcf378dd55c04da56aaf3d6911e08/native/livi-helperd/crates/iap2-csm/src/lib.rs).

For the example languages `en` and `de`, the complete parameter is:

```text
00 0a 00 0d 65 6e 00 64 65 00
length 10 | field 13 | en NUL | de NUL
```

Our encoder instead emitted two seven-byte parameters. The committed golden
identity only has `en`, so the original common-field comparison still passed.
The previous four-language test even required four parameters: it reproduced
our incorrect implementation rather than checking the reference rule.

A new independent expected-byte test for one through four languages was added
first. It failed against the old encoder with `languages share one NUL-packed
parameter 13`, proving the regression exercised the defect before the fix.

## Step 3 - Correct the encoder and bounds

[iap2_identification.c](../src/carplay/iap2_identification.c) now preflights one
list header plus all string payloads, emits field 13 once, then copies each
language followed by NUL. CurrentLanguage remains the separate field 12.
The single-language bytes are unchanged. The four-language maximum decreases
from 942 to **930 bytes**, removing three unnecessary four-byte headers.

Metadata validation is unchanged: one to four unique printable-ASCII language
spans of 1..16 bytes, containing the selected current language. Empty lists,
duplicates and malformed spans are still rejected before writing. No language
defaults, hardware identity or new capabilities are introduced.

## Step 4 - Verify the correction

The identification suite now has eight groups. New/extended assertions cover
exact packed payloads, one field occurrence, independent current-language bytes,
all undersized capacities 0..929 with untouched output, exact-capacity canaries,
maximum-size arithmetic and ownership after caller language strings change.
The original pinned single-language comparison is retained unchanged.

Control and transport identity fixtures now supply `en` and `de`, exercising
the corrected payload through both startup orders, loss/retransmission,
fragmented writes and the explicit wired-start reply. All ten CTest suites,
six host-sanitized protocol executables and the seven-unit ARM portability
check pass after the change. The 19 Python checks passed earlier in this turn;
the correction changes no Python tooling or firmware inputs.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlaySanitizers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Check-CarPlayArm.ps1
```

## Step 5 - Continue toward receiver capability declaration

Next implement explicit, bounded supported-message and USB-host component
metadata from the pinned schema, without copying the reference's fallback
interface number or claiming an operational receiver by default. The wired
reference also advertises/sends PowerSourceUpdate (`0xae03`); it has an existing
pinned fixture and needs typed handling before this implementation declares it.
Only implemented, explicitly enabled behavior should appear in message lists.

The remaining receiver work still includes real USBmux/pairing/network/media
handling, authentication compatibility, QNX display/audio/input and verified
execution/recovery access. A correct identification payload is necessary
protocol work, not proof that CarPlay runs on the car. No device was contacted
and no firmware, service setting or update USB was changed.
