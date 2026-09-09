# Installation-path findings

Research continued after commit `8737ffa`. This document records the latest
results relevant to repairing the unit and eventually adding a custom display
application. All experiments were performed against the downloaded Toyota
6.17.0WL corpus on Windows. No modified ISO was written, no USB update was
prepared, and no connection to the car was made.

Continued in [the step-by-step CarPlay progress record](carplay-progress.md),
which includes complete stock-manifest evaluation, resident-dispatch tests and
the current receiver integration requirements.

## What the normal update path does

The resident Lua loader is in:

`image-380000/usr/share/lua/service/swdlMediaDetect/loader.lua`

When media detection sees `swdl.iso`, it:

1. Extracts the first 64 bytes as a signature and runs `isodigest`.
2. Verifies that digest with a public key in `/etc/keys` using OpenSSL SHA-256.
3. Mounts the ISO and loads `etc/manifest.lua` as Lua code.
4. Uses the manifest to select update components.
5. For application updates, calls a second signature service and then launches
   the manifest-selected external shell script.

The manifest is therefore executable Lua supplied by the update image. This is
the most relevant code-loading boundary found so far.

The same loader also calls `/usr/bin/verifyISO sha256 /fs/usb0/swdl.iso` before
mounting. In the observed code, the return value of that command is not checked
before loading the manifest. This is a real control-flow weakness in the script,
but it does not bypass the first public-key check.

## Local integrity experiment

The ARM `isodigest` executable was run in an emulator with all QNX filesystem,
process and hardware calls replaced by bounded mocks. This reproduced the
official public-key result for both shipped ISO files.

The checker’s per-file record is Adler-32, not a cryptographic signature. The
following experiment changed only the 268-byte `etc/manifest.lua` extent in an
in-memory copy of `swdl.iso`:

- Original and replacement manifest had the same Adler-32: `7402509d`.
- The existing RSA signature verified both digest outputs with `apps.pub`.
- An uncompensated one-byte mutation changed the digest and was rejected.
- The replacement manifest was harmless and returned only the marker
  `GT86_LOCAL_ONLY`.
- A mocked resident loader reached and executed that replacement manifest even
  when the separate `verifyISO` mock returned failure.
- The modified full ISO payload no longer matched the embedded SHA-256:
  original `aeb79c7e...4da64`; modified
  `a699b40b...b46ce0`.

The complete machine-readable result is in the ignored development artifact
`extracted/loader-integrity-probe/result.json`. The harness writes no modified
ISO and its loader test uses only mocks. The result proves a weakness in the
fast digest construction and the unchecked `verifyISO` return path; it does not
prove that a physical head unit will accept the image. The actual update flow
may include additional checks in the HMI, SAM service, boot mode, installer,
variant handling or hardware security chip.

## Other code-loading paths

The signed updater manifest supports external scripts, but the shipped manifest
selects Toyota update scripts (`nav-activation-install.sh`, IFS/MMC/ETFS
installers). The application installer is also signed and uses a separate
`apps.pub` key. The USB configuration recognizes `.jar` application packages,
but that path is an application update mechanism, not evidence that arbitrary
native binaries can be installed.

Diagnostic access is conditional:

- `inetd`/telnetd starts only when `/fs/etfs/ENABLE_TELNET` exists.
- DBus gateway access defaults to `--localonly`; an internal
  `/fs/etfs/ALLOW_SVC_ACCESS` flag changes that.
- USB serial and `pgetty` support are present, but a compatible adapter and an
  enabled console configuration are not established.
- `ACPClientON` triggers an internal logging client; it is not a general shell
  or native-code loader.

These flags are on the unit’s writable internal filesystem. A debug menu or
photographed information screen does not establish that any flag exists or can
be changed.

## Practical repair conclusion

There is now a credible static candidate for an update-loader weakness, but no
safe installation procedure for the car. The missing facts are the exact
6.9.0WL image, the module’s hardware/variant identity, the bootloader’s handling
of the full-image hash, and whether the SAM chip performs an independent check
before writing. Attempting an image on the car before those are resolved could
leave the navigation unit unbootable.

The next safe milestone is a read-only identification of the unit’s exact Go
module and firmware, followed by a hardware-free emulator test of the complete
installer manifest. If a legitimate execution route is found, the first target
should be a tiny native QNX ARM diagnostic program that reports display, touch
and audio availability. CarPlay would come only after that program can be
started and recovered reliably.

## Reproduction files

- `scripts/emulate_isodigest.py`: bounded ARM emulation of the observed
  `isodigest` computation.
- `scripts/probe_loader_integrity.py`: in-memory same-Adler manifest experiment.
- `tests/resident_loader_probe.lua`: mocked resident-loader execution test.
- `scripts/Verify-IsoPayload.ps1`: independent SHA-256 payload verification.
- [QNX extraction report](qnx-analysis.md): image layout, native interfaces and
  SAM signature call trace.
