# Owner reports of upgrades from 6.9.0WL

Checked: 2026-09-10. Starting checkpoint: `8665ca3`.
Continues [CarPlay progress, Step 79](carplay-progress.md#step-79---check-owner-reports-of-upgrades-from-690wl)
and the [original-version download attempt](6.9.0-download-attempt.md).

## Step 1 - Separate owner outcomes from suggested upgrades

Searched Toyota Owners Club and other Toyota-owner discussions for the exact
installed version, then checked follow-up posts by the original owners.
These are firsthand accounts, not independently verified installations or
Toyota compatibility approvals for this GT86.

### Yaris: 6.9.0WL followed by a reported 6.17 upgrade

On 10 May 2021, `parker78` identified an October-2017 Yaris with `6.9.0WL`
and 2017 v1 maps (#649). `richard1` supplied the official `6.17.0L_EU`
archive (#650). The same owner reported completion the following day (#651).
No intermediate release is described, but the completion post does not include
a final version screen or detailed functional tests.
[HybridLife, page 33, posts 649-651](https://hybridlife.org/threads/tutoriel-de-mise-%C3%A0-jour-de-toyota-touch-go-2.3945/page-33).

### Auris: 6.9.0WL to the 6.13.0L package, after USB trouble

On 3 August 2019, `vajomax` reported a 2017 Auris on `6.9.0WL`, downloading
`6.13.0L` through Toyota's customer portal. Initial extraction attempts failed;
a subsequent Windows attempt accepted activation but looped after the radio
reset. These posts establish the starting version and intended package, not
the cause of failure.
[HybridLife, page 10, posts 186-192](https://hybridlife.org/threads/tutoriel-de-mise-%C3%A0-jour-de-toyota-touch-go-2.3945/page-10).

On 9 August, the same owner reported success after replacing the USB stick,
formatting with Guiformat, downloading again and changing extraction software.
The unit displayed successful completion; the owner had not yet road-tested it.
Several variables changed, so this does not prove that a particular formatter,
operating system or USB fault was responsible.
[HybridLife, page 11, post 203](https://hybridlife.org/threads/tutoriel-de-mise-%C3%A0-jour-de-toyota-touch-go-2.3945/post-116765).

### Prius: later successful update, final numeric version unstated

On 26 September 2024, `ninanina` described a 2017 Prius on `6.9.0WL` and
2017 v1 maps. Replies discussed autumn-2024 maps; on 4 October the owner said
the update worked. The final software number is not given in the reviewed
posts. The discussion disputes the activation source, so it is not a verified
official purchasing route. Historical prices and release advice are not current
offers.
[Toyota Owners Club, Latest Touch 2 Go Software?](https://www.toyotaownersclub.com/forums/topic/224024-latest-touch-2-go-software/).

## Step 2 - Check the archive links without downloading or installing

Rechecked the two forum-linked Toyota archives over HTTPS with `curl.exe
--head --fail --max-time 20`. Both returned **200**, ZIP content type and byte
range support on 2026-09-10:

| Official archive | Content-Length (bytes) |
| --- | ---: |
| [6.13.0L.zip](https://mapupdatecontent.toyota-europe.com/Updates/Toyota/6.13.0L/6.13.0L.zip) | 4,868,319,432 |
| [6.17.0L_EU.zip](https://mapupdatecontent.toyota-europe.com/Updates/Toyota/6.17.0L_EU/6.17.0L_EU.zip) | 5,224,629,268 |

HEAD verifies current server metadata, not complete archive integrity, entitlement
or target compatibility. No archive body was downloaded this step. The existing
`downloads/6.17.0L/` research files remain unchanged and are only the previously
collected subset, not a complete map-update USB image. An archive's `L` filename
and an owner's installed `WL` string must be recorded separately; a filename
alone is not a compatibility check.

## Step 3 - Cross-check how the normal update works

Toyota's dealer guide describes this sequence (its customer instructions are
provided separately through the customer portal):

1. Select the correct device and obtain its offered map/software package.
2. Extract the package contents to an empty FAT32 USB stick of at least 8 GB.
   The root contains `nav`, both SWDL ISO files and their MD5 files, not an
   enclosing download folder.
3. Use the official activation workflow; a paid update needs a license, while
   applicable included entitlements are handled separately.
4. Select countries and complete the update with the power conditions specified
   by Toyota. The guide also documents a possible second detection after the
   initial radio reset; this does not explain every repeated loop.

This summarizes a vendor workflow, **not a checked installation procedure for
this car**. No USB preparation, formatting, activation request or vehicle action
was performed. Follow the applicable customer instructions before any actual
installation; if an engine must run, never do so in an enclosed space.
[Toyota Touch 2 with Go update guide, sections 3.1-3.2](https://mapupdatecontent.toyota-europe.com/Documents/Dealer%20Guide/MapUpdate_16MM_DealerGuide_English.pdf).

## Step 4 - Apply the findings to this project's next decision

The reports support a useful distinction: acquiring the original `6.9.0WL`
image for offline loader comparison is a different task from obtaining an
official newer update. Neither the reviewed successful accounts nor the
official upgrade workflow establish a requirement to download the old image
first. This is an inference from the evidence, not a guarantee of a direct
upgrade path for every unit.

For a stock update, the next check is the package and entitlement offered for
the existing unit through Toyota's customer/dealer route. This investigation
did not access the owner's signed-in catalogue or establish the latest eligible
release. Do not buy an old license merely because a public archive responds.
No additional hardware-label photographs are requested.

The reviewed successful cases are Yaris, Auris and Prius, not a verified GT86
match. None reports obtaining CarPlay from these updates. They therefore help
the stock-update investigation but do not complete the software-only CarPlay
goal. Offline native display-ownership research can continue with the existing
later corpus; differences from the installed loader remain unresolved until
original-version evidence is obtained.

## Step 5 - Verification and repository scope

Only this report, its progress entry and a follow-up link in the original
download report changed. Checked local Markdown file links and Git whitespace.
No receiver code, firmware files, activation data or owner identifiers changed;
no new receiver or on-car test result is claimed.
