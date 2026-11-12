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


## Runtime evidence from Android log (2026-11-12)

The first Android run reaches UMD READY/READABLE and opens
`disc0:/PSP_GAME/USRDIR/package.rdp`. Vulkan and audio initialize on Adreno
650. The decrypted ELF SHA-256 matches the Sekhmet profile.

The first logged stub is `UtilsForUser::sceKernelGetGPI`. The next unknown
import is `ThreadManForUser::0x6652B8CA` with:

- `a0=0x00000BB8`
- `a1=0x08830998`
- `a2=0x08A89A5C`
- `a3=0x08A89B44`
- `ra=0x08831F84`

PSP NID status maps `0x6652B8CA` to `sceKernelSetAlarm`. This import is
not currently registered by PortableKit's ThreadMan HLE. Do not implement it
as an unconditional success return: verify the clock units, callback ABI,
common argument, cancellation/replacement behavior and timer scheduling first.

The game then reports `src/fw/frame.c:826` assertion. The interpreter later
stops at `0x088102CC` on instruction word `0x0000000D` (`break`). Given
the preceding guest assertion, this may be an intentional assertion trap.
Implement the Allegrex exception path rather than skipping the instruction.

The log also reports 61 distinct ignored GE opcodes, but every recorded
`first` parameter is zero. This is not enough evidence to implement those
commands. Audit whether the logger is preserving the raw 32-bit GE command
word and parameter bits.

The no-font warning explains blank game text; it is separate from the
assertion/stop. The MD5 extension's four functions being skipped is expected,
because the built-in MD5 handlers are already registered.

### Required follow-up

- Implement and test `sceKernelSetAlarm` with PSP-compatible timing and callback semantics.
- Capture the guest call stack and instruction context at the assertion and break.
- Preserve raw GE command words and decode command parameters before adding handlers.
- Keep assertion traps visible; never turn `break` into a no-op.


## Follow-up implementation: kernel alarms and GE trace capture (2026-11-12)

PortableKit's `god-eater-burst` branch now contains an initial implementation
of the PPSSPP-referenced alarm API:

- `sceKernelSetAlarm` (NID `0x6652B8CA`)
- `sceKernelSetSysClockAlarm` (NID `0xB2C25152`)
- `sceKernelCancelAlarm` (NID `0x7E65B999`)
- `sceKernelReferAlarmStatus` (NID `0xDAA3F564`)

Alarm deadlines use the kernel's virtual microsecond clock. Handlers are queued
through the existing guest interrupt-call path and receive `common` in a0.
A positive handler return schedules another firing; zero or a negative return
ends the alarm. The first firing applies PPSSPP's documented 215 us minimum.
Cancellation also invalidates an alarm already queued but not yet entered.

The implementation is committed but has **not yet been built or run on-device**.
The next validation must check the CI build, alarm timing/cancel/repeat behavior,
and the exact guest call path from God Eater Burst.

The ignored-GE-command report now retains up to the first four data words per
opcode instead of only the first. This is diagnostic capture, not GE command
implementation; do not implement the 61 opcodes until the new trace shows
their real parameter values and usage.

Allegrex BREAK remains a deliberate runtime stop. The interpreter now reports
its encoded exception code explicitly. PortableKit does not yet implement the
PSP CP0 exception vector, so this change is diagnostic and does not claim to
recover from the guest assertion.


## Follow-up implementation: thread lifecycle event callbacks

PortableKit now dispatches guest thread-event callbacks for the four PSP lifecycle events:

- CREATE (`1`) after a user thread object is created.
- START (`2`) after the thread is made ready.
- EXIT (`4`) when a thread exits normally or is forcibly terminated.
- DELETE (`8`) immediately before a dormant/terminated thread object is removed.

Callbacks receive the PSP ABI arguments `(eventMask, threadId, commonArg)`. Multiple matching handlers are called in UID/registration order, and the original HLE operation completes after the callback chain returns. The CURRENT selector is bound to the registering thread and remains EXIT-only. ALL_USER and ALL match the user threads represented by this runtime. ALL_KERNEL is accepted but currently has no matching kernel-thread objects.

The implementation is source-reviewed only. It has not been built or tested against PSP hardware or a God Eater Burst runtime log. Callback reentrancy, callback release during an in-flight event, and exact firmware error semantics still need validation.
