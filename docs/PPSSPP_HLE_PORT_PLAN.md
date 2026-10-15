# PPSSPP HLE port: licensing and implementation plan

Status: audit in progress. No PPSSPP implementation source is copied by this document.

## Scope

The goal is to close the HLE gaps exercised by God Eater 2 (NPJH50832) in DyausPita, then expand PortableKit's reusable HLE coverage. PPSSPP is the behavioral and source reference. Work proceeds by PSP library/NID, with tests and game-log evidence for each group; it is not a promise to copy every PPSSPP subsystem regardless of whether PortableKit needs it.

## Preliminary license findings

- PortableKit's root `LICENSE` identifies the framework as MIT.
- PortableKit's `docs/SOURCE_PROVENANCE.md` currently says not to paste or adapt source from a project whose license is incompatible with the destination file.
- PPSSPP's project README and official development documentation identify PPSSPP as GPL-2.0-or-later. Its `LICENSE.TXT` contains the GPL text plus separate PSPSDK BSD-compatible notices; individual files and bundled dependencies still need their own notices checked.
- DyausPita's active branch has no root `LICENSE` file. This is not a license grant and should be resolved before distributing a combined port.

## Consequence for direct source adaptation

Adapting PPSSPP implementation code into PortableKit and linking it into the same program is not compatible with treating the resulting combined program as MIT-only. The intended route is to license the combined distribution under GPL-2.0-or-later, retain all upstream copyright and license notices, mark modified files, include the GPL text, and meet source-availability requirements for distributed binaries. MIT-origin code can retain its existing notices; this plan does not erase or replace third-party notices.

Before changing the repository-wide license metadata, confirm the project's authority to publish the combined work under GPL-2.0-or-later and audit the actual files being copied. This document records the proposed route; it does not itself relicense any code.

## Required audit before each port

1. Record the PPSSPP source path, upstream revision, original copyright header and license for each source file or copied excerpt.
2. Check whether the implementation depends on additional PPSSPP helpers or third-party code, and record those separately.
3. Port only the required semantics into PortableKit's runtime/HLE extension API; do not import PPSSPP's unrelated emulator architecture wholesale.
4. Preserve notices and mark adaptations with the upstream path, revision, and date.
5. Add focused tests for register arguments, guest memory access, return/error codes, blocking/thread behavior, and side effects where applicable.
6. Update `docs/HLE_COVERAGE.md` with status: implemented, verified on God Eater 2, or still unverified.
7. Build PortableKit and the DyausPita Android target; attach logs and report failures honestly. A passing compile is not proof that the game behavior is correct.

## Initial priority order

Prioritize by God Eater 2's unresolved imports and runtime log evidence, not by module name alone:

1. Kernel/ThreadMan: alarms, callbacks, thread scheduling and synchronization used by the title.
2. ModuleMgr/LoadExec and module loading/return behavior.
3. SysMem and memory-block APIs used by the title.
4. IoFileMgr and memory-stick paths for DATA.RDP / PACKAGE.RDP and save data.
5. Audio (including SAS) and movie playback.
6. Utility, power, RTC, display/GU and remaining imports as evidence requires.

Each batch should be small enough to test and revert independently. Existing PortableKit handlers should be reused when correct; overrides should be added only when evidence shows a behavior mismatch.
