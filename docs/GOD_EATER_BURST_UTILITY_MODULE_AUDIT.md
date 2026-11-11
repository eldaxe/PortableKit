# God Eater Burst (ULUS10563) — sceUtility Module Audit

## Scope and method

Source: the decrypted retail EBOOT.BIN for God Eater Burst, ULUS10563.

- The EBOOT import table contains **15** `sceUtility` imports (not 16).
- All 15 imported functions have at least one direct `JAL` reference in `.text`.
- The scan found **42** direct calls to those imports.
- This is static analysis, not a runtime trace. It does not prove which branches execute during a normal boot or during every game mode.
- Provisional runtime address display uses load base `0x08804000`; the call-site offsets below are the raw `.text` offsets.

## Module IDs requested by the EBOOT

The EBOOT calls `sceUtilityLoadModule` with seven distinct module IDs and later calls `sceUtilityUnloadModule` for those modules.

| Module ID | Module | Static evidence |
|---:|---|---|
| `0x0100` | `net_common` | Read from a two-entry module-ID table in `.data`; direct call at `.text+0x173D4` |
| `0x0101` | `net_adhoc` | Second table entry; direct call at `.text+0x173F8` |
| `0x0300` | `av_avcodec` | Immediate argument at `.text+0x17328` |
| `0x0301` | `av_sascore` | Immediate argument at `.text+0x17340` |
| `0x0302` | `av_atrac3plus` | Immediate argument at `.text+0x17358` |
| `0x0303` | `av_mpegbase` | Immediate argument at `.text+0x17370` |
| `0x0500` | `np_drm` | Immediate argument at `.text+0x5FE60`, `.text+0x600F0`, and `.text+0x60444` |

The two network IDs are stored at offsets `0x53C0` and `0x53C4` within the EBOOT's `.data` segment. Their values are `0x100` and `0x101`. PPSSPP's module table identifies these as `net_common` and `net_adhoc`; its AV table identifies `0x300`–`0x303` as AVCodec, SAS Core, ATRAC3plus and MPEGBASE. PSPSDK defines the AV module IDs and documents the module-loading API.

## Direct-call counts

| Import | NID | Calls |
|---|---:|---:|
| `sceUtilityLoadModule` | `0x2A2B3DE0` | 9 |
| `sceUtilityUnloadModule` | `0xE49BFE92` | 11 |
| `sceUtilityGetSystemParamInt` | `0xA5DA2406` | 8 |
| `sceUtilityMsgDialogGetStatus` | `0x9A1C91D7` | 2 |
| `sceUtilityMsgDialogInitStart` | `0x2AD8E239` | 1 |
| `sceUtilityMsgDialogUpdate` | `0x95FC253B` | 1 |
| `sceUtilityMsgDialogShutdownStart` | `0x67AF3428` | 1 |
| `sceUtilityOskInitStart` | `0xF6269B82` | 2 |
| `sceUtilityOskUpdate` | `0x4B85C861` | 1 |
| `sceUtilityOskGetStatus` | `0xF3F76017` | 1 |
| `sceUtilityOskShutdownStart` | `0x3DFAEBA9` | 1 |
| `sceUtilitySavedataInitStart` | `0x50C4CD57` | 1 |
| `sceUtilitySavedataUpdate` | `0xD4B95FFB` | 1 |
| `sceUtilitySavedataGetStatus` | `0x8874DBE0` | 1 |
| `sceUtilitySavedataShutdownStart` | `0x9790B33C` | 1 |
| **Total** | | **42** |

## PortableKit handler coverage on `feature/geburst-sas-atrac3`

The current source has a handler path for every one of the 15 imports:

| Area | Current implementation |
|---|---|
| `sceUtilityLoadModule`, `sceUtilityUnloadModule` | Registered in `host/hle/hle_system.cpp` as success handlers. They do **not** map or execute Sony PRX modules. |
| System parameters | `sceUtilityGetSystemParamInt` is implemented in `host/hle/hle_system.cpp`. |
| Message dialog | Init/update/status/shutdown handlers in `host/hle/hle_utility.cpp`. |
| On-screen keyboard | Init/update/status/shutdown handlers in `host/hle/hle_utility.cpp`. |
| Savedata dialog | Init/update/status/shutdown handlers in `host/hle/hle_savedata.cpp`. |

The APIs behind the requested modules are also provided as HLE registrations:

- SAS Core: `register_media` in `host/hle/hle_media.cpp`.
- ATRAC3plus: `register_atrac` in `host/hle/hle_atrac.cpp`.
- MPEG/JPEG: `register_mpeg` in `host/hle/hle_mpeg.cpp`.
- Ad hoc/network: `register_adhoc` in `host/hle/hle_adhoc.cpp`, plus offline network handlers in `host/hle/hle_net_offline.cpp`.
- NPDRM: handlers in `host/hle/hle_system.cpp`.

This means a real PRX loader is **not currently justified by the EBOOT's utility-module requests**. PortableKit already binds the guest APIs directly to HLE handlers. The present gap is that the utility module load/unload calls are unconditional success stubs, not module-state-aware implementations. Whether games require module-state tracking or exact firmware error/timing behavior must be established from runtime traces before changing semantics.

## Unload order

Static code iterates the network-module table in reverse order (`0x101`, then `0x100`), then unloads the AV modules in reverse order (`0x303`, `0x302`, `0x301`, `0x300`). Separate NPDRM paths unload `0x500`.

## Recommended next action

Do not implement a general PRX loader yet. Add optional tracing around the two existing utility module handlers (module ID, load/unload, return value), then run the game and compare actual requests with this static list. If the game fails at one of these calls, implement only the missing module-state/dependency behavior. Keep the current HLE API implementations as the execution backend unless a concrete guest PRX is proven necessary.

## References

- PSPSDK module IDs and `sceUtilityLoadModule` / `sceUtilityUnloadModule`: https://pspdev.github.io/pspsdk/psputility__modules_8h_source.html
- PSPSDK AV module IDs and `sceUtilityLoadAvModule`: https://pspdev.github.io/pspsdk/psputility__avmodules_8h_source.html
- PPSSPP utility module table and module-load implementation: https://github.com/hrydgard/ppsspp/blob/master/Core/HLE/sceUtility.cpp
- PPSSPP ATRAC notes on utility-loaded firmware modules: https://www.ppsspp.org/docs/development/ppsspp-internals/atrac/
