# Native build blocked on usable QNX development inputs

Date: 2026-09-17. Step 102, a prerequisite revalidation, not an implementation
milestone. Starting checkpoint: `8bac246fbff6e7d3a78fba50569f696bc062fe7b`.

The software-only CarPlay goal remains unachieved. The immediate native build
cannot proceed with the development inputs currently configured or supplied.
Work is blocked pending SDK access, not complete based on the host tests.

## 1. Revalidate the current state

The worktree started clean; local HEAD and remote `master` both identified the
Step 101 commit above. No new SDK path or package had been supplied.

```powershell
python -B scripts/build_qnx_network_diagnostic.py --check-sdk
$LASTEXITCODE
Get-Command qcc,QCC,qconfig,ntoarmv7-gcc,ntoarm-gcc -ErrorAction SilentlyContinue
docker image ls --filter 'reference=*qnx*' --format '{{.Repository}}:{{.Tag}} {{.ID}}'
docker image ls --filter 'reference=*/*qnx*' --format '{{.Repository}}:{{.Tag}} {{.ID}}'
```

Observed:

- Native preflight exit code **2**, requesting QNX host/target paths. No compiler
  invocation or native output directory creation occurred.
- None of the selected compiler/configuration commands was found on PATH.
- Rechecked SDK roots `C:/QNX650`, `C:/QNX660`, `C:/qnx700`, `C:/qnx710`,
  `C:/qnx800`, `C:/Users/donjulio/qnx650` and `C:/Users/donjulio/qnx660` do not exist.
- Both Docker image queries completed successfully and returned no matching
  QNX-named image. No image was pulled and no container was started.

These are scoped checks, not a claim that no SDK could exist under an arbitrary
directory or unrelated container name. Such an installation needs its actual
path/identity before it can be used.

## 2. Distinguish the repeated blocker from completed work

| Checkpoint | Evidence |
| --- | --- |
| [Step 100](factory-native-build-route.md) | No usable local SDK identified; public candidate depends on supplied QNX components; SDK access requested |
| [Step 101](qnx-network-diagnostic.md) | Diagnostic source implemented and host-tested; actual native preflight stops on missing SDK paths |
| Step 102 | Same preflight result after rechecking local compiler paths, standard SDK roots and QNX-named Docker images |

Step 101 made source/test progress. This revalidation does not claim additional
implementation progress. The existing host API-model executable bypasses the SDK
include branch, so it cannot answer whether that branch compiles or runs on QNX.
The old public IPv6 stack also lacks two factory NCM exports; substituting it
does not resolve this build/compatibility dependency.

No code changed and no new test result is claimed here. The last implementation
checkpoint passed 178 Python tests, 51 CTest suites and the diagnostic's host
sanitizer checks, with their limits recorded in Step 101.

## 3. Input needed to resume the native build

Provide either:

1. The `QNX_HOST` and `QNX_TARGET` directory paths for usable QNX 6.5/SP1
   ARMle-v7 development inputs; or
2. The location/source of a QNX development package you are authorized to use,
   so its target support and compatibility can be checked first.

Do not send account passwords or license keys in chat. A local SDK may require
setup/activation through the owner's normal vendor workflow; none was inferred
or performed by this research.

With those inputs, the next action is SDK preflight, then the diagnostic's real
compile/link and ELF/import/relocation review. Even a successful build will not
establish installed-version execution/recovery, an IPv6 transport, MFi, factory
media/input or actual phone acceptance. Those remain in
[the factory integration gates](factory-integration-gates.md).

No modified firmware, installation USB or car-side command is produced by this
checkpoint. The original CarPlay objective is preserved while blocked.
