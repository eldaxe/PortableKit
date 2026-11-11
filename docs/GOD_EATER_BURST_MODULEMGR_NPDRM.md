# ModuleMgr and NPDRM work for God Eater Burst

This is a first compatibility layer for the imports found in the ULUS10563 EBOOT. It is deliberately explicit about what it does not implement.

## Added NIDs

- `ModuleMgrForUser 0xF2D8D1B4` — `sceKernelLoadModuleNpDrm`
- `ModuleMgrForUser 0x644395E2` — `sceKernelGetModuleIdList`
- `ModuleMgrForUser 0x748CBED9` — `sceKernelQueryModuleInfo`
- `scePspNpDrm_user 0x275987D1` — `sceNpDrmRenameCheck`
- `scePspNpDrm_user 0x219EF5CC` — `sceNpDrmEdataGetDataSize`

## Current behavior

### ModuleMgr

- The existing `sceKernelLoadModule` path now records HLE-served stock modules with stable UIDs and names.
- `sceKernelLoadModuleNpDrm` forwards through the same path, matching the public PPSSPP behavior of forwarding the same arguments to the ordinary module loader.
- `sceKernelLoadModuleByID` now validates the file descriptor before reading its header.
- `sceKernelGetModuleIdList` returns the main image and recorded HLE module UIDs.
- `sceKernelQueryModuleInfo` fills the 0x40-byte base or 0x60-byte extended PSPSDK structure. It reports no segments for HLE-only modules because their PRX code is not mapped.
- Start/stop/unload operations validate the module UID and update output status where supported.

### NPDRM

- `sceNpDrmSetLicenseeKey` copies the 16-byte guest key into host state instead of silently discarding it.
- `sceNpDrmRenameCheck` validates the key state and file existence. Plain files pass; encrypted EDAT filename/hash verification is not implemented and returns an explicit unsupported/internal error.
- `sceNpDrmEdataGetDataSize` reports the current guest file size, including an active file filter.
- `sceNpDrmEdataSetupKey` accepts plain files, checks key and descriptor state, and explicitly rejects encrypted EDAT because the EDAT/PGD decryptor is not yet wired into this HLE path.

## Important limitations

This is **not a full PRX loader**. Stock modules are represented as HLE metadata records; their encrypted PRX bytes are not decrypted, mapped, relocated, or executed. The start handler therefore does not run a real `module_start` entry point. The main image's real segment metadata is not yet populated in this registry.

This is also **not full NPDRM/EDAT support**. No encrypted EDAT payload is decrypted by these new handlers. Returning a specific error for an encrypted file is intentional: pretending success would expose ciphertext to the game and hide the missing implementation.

## Verification

- Source changes committed to `feature/geburst-sas-atrac3`.
- No build or runtime test has been performed for these changes.
- Next validation should cover module-list/query structure sizes and invalid UIDs, valid/invalid file descriptors, plain and EDAT magic files, and then God Eater Burst's actual call sequence with `TRACE_IO` / kernel tracing.
