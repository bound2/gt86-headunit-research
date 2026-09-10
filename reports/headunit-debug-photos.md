# Diagnostic photos: audio and navigation identification

Date: 2026-09-10. Continues [factory-integration-gates.md](factory-integration-gates.md)
and [CarPlay progress, Step 75](carplay-progress.md#step-75---identify-the-audio-product-and-navigation-manufacturer-from-new-diagnostic-photos).
Starting checkpoint: `bee0b39`. This is evidence collection, not a vehicle update.

## Step 1 - Inspect the newly supplied folder

Directly viewed all four JPEGs in the owner's `Pictures/headunitdebug` folder.
These are new evidence, separate from the seven photos previously inspected in
`Pictures/headunit`. No original image was copied into the repository or sent to
a web search. The main-unit serial value is intentionally not transcribed here.
Only the non-unique product code and product names were used for public searches.

## Step 2 - Transcribe the visible identification fields

| Photo | Screen | Non-private evidence |
| --- | --- | --- |
| `IMG_5877.jpeg` | Product Information | Product information `PW600-18001`; main-unit chip-serial field populated, value omitted; EXT Box chip-serial field displays dashes |
| `IMG_5878.jpeg` | Unit Version Information - DA | Manufacturer `Panasonic`; MAIN, SYS, CAN, AUDIO DSP and Main Data versions below |
| `IMG_5879.jpeg` | Unit Version Information - DA, scrolled | Same manufacturer; overlapping version rows and SYS Data version below; glare obscures the Main Data row in this photo |
| `IMG_5880.jpeg` | Unit Version Information - NAVI BOX | Manufacturer `Harman International`; MAIN `6.9.0WL` |

The two DA photos together show:

| DA field | Displayed value | Read from |
| --- | --- | --- |
| MAIN | `770101b0` | `IMG_5878.jpeg` |
| SYS | `08000088` | Both DA photos |
| CAN | `130209` | Both DA photos |
| AUDIO DSP | `30710101` | Both DA photos |
| Main Data | `S56E1C00` | `IMG_5878.jpeg` |
| SYS Data | `S56E1C00` | `IMG_5879.jpeg` |

These are screen-reported identifiers and versions, not inspected silicon
markings or a hardware revision. The DA MAIN suffix is consistent, ignoring
letter case, with the earlier ordinary-settings audio version `0101B0`; no
undocumented decoding of its `77` prefix is assumed. The separate NAVI BOX
screen reconfirms the previously photographed navigation software version.

## Step 3 - Resolve the product code against Toyota documentation

Toyota's GT86 LHD TAS400 installation manual, reference **AIM 003 923 - 1**,
lists `PW600-18001` as TAS400 without DAB and `PW600-18002` as the DAB variant.
Its stated applicability begins at model year 2016/08. This identifies the
photographed product code as the audio product, not a Go-module part number.
Combined with the DA manufacturer screen, the evidence identifies this audio
unit as a Panasonic TAS400, with the displayed non-DAB product code.
[Toyota TAS400 manual, page 1](https://www.techdoc-toyota.com/api/assets/td4-assets/td1-publications/b9c954a7-d2d5-4235-9f24-3114356b9fe4/GT86_TAS400_PW600_18001_AIM_003_923_1.pdf?contentType=pdf&disposition=inline%3B).

Toyota's separate GT86 LHD Touch 2 with Go manual, **AIM 003 925 - 0**, lists
navigation accessory families `PZ490-00334-*0` for West-EU and
`PZ490-00335-*0` for East-EU; its component list also uses the module part-number
pattern `86840-*****`. These are identification leads from the manual, not
readings of the owner's module. The wildcard suffix and hardware revision must
not be invented, nor selected merely from the owner's current location.
[Toyota Touch 2 with Go manual, pages 1 and 3](https://www.toyota-tech.eu/aimuploads/3ec5e026-3981-47c4-8695-e908a0dff55c/GT86_Touch2withgo_PZ490_00334_G0_AIM_003_925_0.pdf).

The manuals were consulted for identification only. Their installation steps
were not performed, and they do not establish a CarPlay retrofit, firmware
compatibility, code-execution route or recovery procedure.

## Step 4 - Update what this establishes for software-only CarPlay

- **Audio identity is substantially clearer:** product `PW600-18001`, TAS400,
  manufacturer Panasonic, plus the component software versions above.
- **Navigation manufacturer is now directly observed:** Harman International,
  running `6.9.0WL`. The exact module part number and hardware revision remain
  absent from these four screens.
- **The chip-serial label is not chip-compatibility evidence.** The photo does
  not say that this is the Apple authentication coprocessor, identify its
  generation/protocol, expose its certificate or demonstrate a signing API.
  Its serial value is neither needed nor useful for the public report.
- **Dashes under EXT Box do not prove that navigation hardware is absent.**
  The separate NAVI BOX page reports its manufacturer and software. The
  meaning of that serial field is not established by these photos.
- **Diagnostic menu access is not native program execution.** No shell,
  file export, authentication-chip access or safe recovery method is shown.
  The researched `6.17.0WL` binaries are still not the installed `6.9.0WL` image.

The new evidence narrows the physical-target investigation but does not make
CarPlay installable. The remaining execution, USB ownership, authentication,
QNX runtime, display/input/audio and real-phone tests in the
[factory integration audit](factory-integration-gates.md#step-3---audit-readiness-at-the-scope-of-the-car)
are unchanged. No host-only implementation claim is promoted to factory support.

## Step 5 - Make the next identification check specific

Use existing navigation installation/service paperwork or an already accessible
label to look for the **complete Harman Go-module part number and hardware
revision**. The Toyota accessory families and `86840-` pattern above can help
distinguish navigation identifiers from the now-known `PW600-18001` audio code.
No new photo of the same audio/version pages is necessary.

Follow-up [navigation identification analysis](navigation-identification-route.md)
finds an internal persisted part-number path in the later firmware, but its
reply can be truncated or based on a default. It is not a substitute for the
owner-specific identity or a proven read-only collection route.

If an already available read-only information page supplies those fields, it
is useful evidence; these photos do not establish that such a page exists.
Do not change service-menu settings, enable logging, enter update/reprogramming
modes, clear data or dismantle the dashboard for this check. No serial, VIN or
activation code is requested. An existing original `6.9.0WL` package or backup
would also be useful for offline comparison, not for attempting an update.

## Step 6 - Verification and repository scope

All four photos were visually inspected; the product-code mapping was checked
against Toyota-hosted documentation. Only Markdown reports/indexes are changed.
Local report links and whitespace are checked before committing. No receiver
code, firmware, build output or original photograph is added or changed; no
hardware tests or vehicle operations were performed.

## Step 7 - Owner clarification: service-menu entry, no further identification

On 2026-09-10 the owner explained that these screens came from the service menu,
entered by holding the MEDIA button and flashing the lights three times. This is
the owner's report of how the existing photographs were obtained, not an
independently tested procedure or a request to repeat it. No ignition, vehicle
movement, update or configuration instructions are inferred from that description.

The owner has no further identification information available. The earlier
paperwork/label request is therefore no longer the immediate next action; do not
keep requesting the same unavailable evidence. Record the exact navigation
part/revision as unknown and continue eligible offline analysis using the confirmed
Panasonic TAS400 / Harman NAVI BOX / `6.9.0WL` observations.

Service-menu access does not establish a shell, enabled internal service flags,
arbitrary application installation or CarPlay capability. Exact target matching
and recovery remain deployment requirements, not prerequisites to reading the
later firmware. The next offline investigation is the navigation module's display
request/release and ownership-notification path, with touch and audio integration
remaining separate requirements. No on-car service call is requested.
