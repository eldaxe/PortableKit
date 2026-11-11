# God Eater Burst HLE integration notes

Target title: God Eater Burst, US release `ULUS10563`, `APP_VER 01.00`.
Game-specific profile and title-only behavior belong in Sekhmet; generic PSP
kernel and system-library behavior belongs here.

## Shared HLE already present

The `sceMd5` library is implemented in `host/hle/hle_system.cpp` by
`register_md5()`. It registers:

| NID | Function |
|---|---|
| `0x19884A15` | `sceMd5BlockInit` |
| `0xA30206C2` | `sceMd5BlockUpdate` |
| `0x4876AFFF` | `sceMd5BlockResult` |
| `0x98E31A9E` | `sceMd5Digest` |

Do not add a second MD5 implementation in a title extension. Sekhmet's
`geburst_crypto` extension duplicated these registrations and has been removed
from the Sekhmet `god-eater-burst` build. The built-in implementation remains
the single owner of these NIDs.

ThreadMan source already contains implementations for thread lifecycle and
priority, waits and wakeups, semaphores, event flags, mutexes, callbacks,
virtual timers, mailboxes, VPL/FPL, message pipes, and interrupt control.
That source inventory is not a claim that every import in ULUS10563 is
implemented or behaviorally verified.

## Verification requirements

Sekhmet's current executable audit records 320 function imports in 32 library
records, but the exact ULUS10563 `library,NID,name` list is not yet committed.
Until that list is available, do not infer title coverage from library names,
NID-name tables, or the presence of a handler with a similar name.

For each imported NID:

1. Check the exact `(library, NID)` binding after all built-in HLE groups are
   registered.
2. Record whether it is implemented, partial, missing, or only needs runtime
   testing. A logging stub is not an implementation.
3. Capture the first runtime call, argument registers, guest-memory inputs and
   outputs, return value, and caller PC.
4. Compare observable behavior with PPSSPP and PSP SDK documentation, including
   error paths and blocking/timing semantics.
5. Add generic behavior here. Put only genuinely game-specific compatibility
   behavior in Sekhmet's profile extension.

For the initial discovery run, use Sekhmet's documented
`GEBURST_LIST_STUBS=1` and interpreter-only boot. Follow with
`GEBURST_STRICT_HLE=1` after missing imports have been triaged so logging
stubs cannot silently masquerade as successful calls.

Do not use the God Eater 2 / NPJH50832 import inventory for this target.
