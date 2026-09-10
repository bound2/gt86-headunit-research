# Navigation identification: persisted value, default and access limits

Date: 2026-09-10. Continues [diagnostic photo findings](headunit-debug-photos.md)
and [CarPlay progress, Step 76](carplay-progress.md#step-76---trace-navigation-part-number-and-version-reporting).
Starting checkpoint: `e9dc7ab`. This is static analysis of the later `6.17.0WL`
corpus, not a read of the owner's running `6.9.0WL` system.

## Step 1 - Follow the newly identified navigation target

The new photos name Harman International for NAVI BOX and Panasonic for DA.
The audio code `PW600-18001` is already resolved; it must not be substituted for
navigation identity. Bounded public searches using that code, `13TFDAEU-DA05`
and `6.9.0WL` on Toyota documentation/update domains did not produce a verified
matching original firmware download. This is not proof that one is unavailable.

The local investigation therefore followed the later navigation software's own
version and part-number handling. It found a persisted part-number read, but
also a built-in default and a truncated reply that limit identification value.

## Step 2 - Pin the inspected inputs

All six files are under
`extracted/qnx-system-v3/image-380000/usr/share/lua/service/toyotamanager/`.
Sizes and CRC32 values are checked against `qnx-system-inventory.tsv`.

| File | Bytes | CRC32 | SHA256 |
| --- | ---: | --- | --- |
| `versioninfo.lua` | 2810 | `2a43e1d5` | `1ff343eb103c6eacba7321a3f1062b7eb91c994406e5f4c61350b1aa80ad13e9` |
| `properties.lua` | 2131 | `23c4038b` | `34aeacac5faae28cacbdafb1b7a2f28272fd4ff7fc66e7694bdc832060cc9b7b` |
| `framClient.lua` | 6891 | `91b6c566` | `032d52619f6735ea54d1ebf9d1f87612194107d04baec529e9ac01e4f2e0ed9c` |
| `avclan.lua` | 67589 | `03d5a627` | `2a0fa72645758ebcac0f92544a2408a3c41567c42794349138f22ff3e27ae1e6` |
| `toyotamanager.lua` | 30380 | `1504764f` | `af611ebdbbff9e5bfb4dfcb2464a1a2b514bb30688d90b5912af4d9d5e4232d2` |
| `deviceStatus.lua` | 7459 | `a852963e` | `2493b73cb8bcbc9f35175463beb88930adbffe11c205984e7074ec23aed742ac` |

Used the existing Win32 Lua 5.1 host's **`luac.exe -l -p`** to list bytecode.
The `-p` flag prevents creation of `luac.out`; no vendor module was executed.
Source-line references below are retained debug metadata in those pinned chunks,
not line numbers in an available original Lua source file. Host allocation
addresses printed by `luac` are irrelevant and are not treated as target addresses.

## Step 3 - Separate software version from hardware identification

`versioninfo.lua` at source lines 50-70 opens `/etc/version.txt` in mode `r`,
parses its `ifs` and `packages` sections and caches the result. Lines 72-74
register `getOmapVersion` with the AVCLAN module. The registered callback calls
`getVersions()` without a caller-supplied file path.

`avclan.lua` lines 1912-1919 select `getVersions().ifs.version`, prefix it with
an internal message identifier and byte length, and pass it to `ipcWrite`.
`toyotamanager.lua` lines 921-923 also delegate `getVersionInfo` to
`versioninfo.getVersions()`. These paths report software metadata, not a chip
probe or a read of a hardware-revision register. This is a plausible related
version-reporting path, not proof of which exact code rendered the owner's photo.

## Step 4 - Trace the part-number value and its limitations

The selected path is:

```text
properties.lua default "86100-YY050"
  -> truthy persisted "PartNumber" may replace it in framClient
  -> properties.toyotaPartnumber
  -> AVCLAN part-number handler keeps only the last five characters
  -> internal IPC device write, not a PC file export
```

1. `properties.lua` source line 45 initializes `toyotaPartnumber` to the literal
   `86100-YY050`. This is a corpus default, **not the owner's observed part number**.
2. `framClient.lua` lines 163-164 call `readPersistence("PartNumber")` and replace
   the property only if the result is truthy. An absent/failed read therefore
   need not clear the pre-existing default through this selected path.
3. The helper at lines 182-192 invokes method `read` on
   `com.harman.service.PersistentKeyValue`, with a `key` field. It returns the
   reply's `res` only when the reply is non-nil and the error result is nil.
   This is an internal service call, not a remotely accessible endpoint proved
   by this trace. The service's physical storage/provisioning is not audited here.
4. `avclan.lua` lines 1956-1965 read that property, apply `string.sub(value,-5,-1)`,
   add an internal identifier/length prefix, and call `ipcWrite`. A five-character
   reply loses the original prefix and cannot recover the complete part number.
   With the default still present, this logic would select `YY050`; that is a
   static consequence of the code, not an observed response or a hardware ID.
5. `ipcWrite` at lines 186-196 ultimately calls the held device's `write` method.
   `startipc` at lines 2060-2081 opens `/dev/avclan/tm` in `rw` mode, installs
   notification handling and subscribes to services. Do not run this initializer
   or inject bus requests as if they were passive identification checks.

No documented UI label or supported PC retrieval route for this value has been
established. A future observed value needs provenance: persisted or default,
complete or truncated, plus an independent hardware-revision source. Neither
this default nor `/etc/product_type` from an update image identifies the owner's
physical module or Apple authentication chip.

## Step 5 - Inspect the nearby device-information export without invoking it

`toyotamanager.lua` lines 936-938 forward `copyDeviceInfo` to `deviceStatus.lua`.
The latter's selected function, lines 145-225, checks the fixed USB root
`/fs/usb0`, creates its `NaviSync` directory if necessary, changes activity state,
stops existing navigation-update tools and starts `Synctool` and
`NavUpdateController` from the navigation directory. Its helper at lines 116-123
requests `UPD_RequestDeviceStatus` through `com.harman.service.NavigationUpdate`,
with a destination-path parameter and asynchronous timeout.

That is a stateful navigation export workflow, not a demonstrated copy of the
Apple `authcoproc` cache or a passive hardware-identity read. The exported
contents and its actual UI availability on `6.9.0WL` remain unverified. No
export was triggered and no tools were stopped. If the owner already has such
an export, offline inspection may be useful; generating one is not requested
on the basis of this static trace alone.

## Step 6 - Verification and next decision

Verified all six sizes/CRC32 values against the extraction inventory, recorded
their SHA256 values and inspected the selected bytecode functions. Only Markdown
files changed; no runtime implementation or test harness was altered. Checked
local report links and Git whitespace. These are static evidence checks, not
hardware, recovery or phone-interoperability tests.

This closes the specific part-number/version/export lead at the Lua boundary.
It is not an exhaustive audit of every diagnostic API or the native export tools.
The next decision still requires owner-specific evidence: complete navigation
part/revision from existing paperwork or an accessible label, an existing
diagnostic export, or an exact original `6.9.0WL` image for offline comparison.
No dashboard disassembly, serial/activation identifier, service-flag change,
firmware update or added hardware is requested. A matching identity would narrow
the investigation; execution/recovery and native CarPlay interfaces would still
need to be established before deployment.
