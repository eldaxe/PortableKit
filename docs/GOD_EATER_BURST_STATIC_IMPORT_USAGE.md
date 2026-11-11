# God Eater Burst (ULUS10563) — Static Import Call-Site Audit

This report supplements the HLE registration audit. It is derived from the decrypted EBOOT.BIN supplied for this port.

## Method and limits

- Executable: decrypted PSP PRX ELF32/MIPS, `.text` section (file offset `0xC0`, size `0x20AFA0`).
- Import stubs: reconstructed from `.lib.stub` and its NID table.
- Load-base assumption for call-site display: `0x08804000`.
- Scanned aligned MIPS instructions in `.text` for direct `JAL` targets matching an imported stub.

This is **static direct-call evidence**, not a dynamic trace or full call graph. It does not detect indirect calls, function pointers, runtime-loaded modules, or code outside `.text`. A zero count must not be interpreted as proof that an import is unused.

## Overall

- 320 imports in the EBOOT.
- 264 distinct imports have at least one direct `JAL` reference from `.text`.
- 1,073 direct call instructions target imported stubs.
- 56 imports have no direct `JAL` reference in this scan.
- The baseline HLE audit identified 58 imports without a matching registration; 68 direct `JAL` call sites target those 58 imports.
- The four MD5 imports alone account for 12 direct calls, so MD5 is a concrete dependency, not just an unused import.

## Previously missing imports with direct call references

Call-site addresses below use the provisional load base above.

| Library | Import | Direct calls | Call-site addresses |
|---|---|---:|---|
| scePower | unresolved NID `0x469989AD` | 5 | `0x08814B38`, `0x08814B88`, `0x08814BBC`, `0x08814BFC`, `0x08814D38` |
| sceSasCore | `__sceSasSetVoiceATRAC3` | 1 | `0x0899FEFC` |
| sceSasCore | `__sceSasConcatenateATRAC3` | 1 | `0x089A0078` |
| sceSasCore | `__sceSasUnsetATRAC3` | 1 | `0x0899FFBC` |
| sceAtrac3plus | `_sceAtracGetContextAddress` | 2 | `0x0899FE70`, `0x0899FF78` |
| sceJpeg | `sceJpegMJpegCsc` | 1 | `0x0880454C` |
| sceJpeg | `sceJpegDeleteMJpeg` | 1 | `0x08804368` |
| sceJpeg | `sceJpegFinishMJpeg` | 1 | `0x088041C8` |
| sceJpeg | `sceJpegGetOutputInfo` | 1 | `0x08804180` |
| sceJpeg | `sceJpegDecodeMJpegYCbCr` | 1 | `0x08804360` |
| sceJpeg | `sceJpegCreateMJpeg` | 1 | `0x08804338` |
| sceJpeg | `sceJpegInitMJpeg` | 1 | `0x0880415C` |
| sceMd5 | `sceMd5BlockInit` | 2 | `0x08896400`, `0x0889A8C0` |
| sceMd5 | `sceMd5BlockResult` | 2 | `0x088964E8`, `0x0889A8F4` |
| sceMd5 | `sceMd5Digest` | 1 | `0x088A07C4` |
| sceMd5 | `sceMd5BlockUpdate` | 7 | `0x08896410`, `0x08896450`, `0x08896478`, `0x088964A4`, `0x088964DC`, `0x0889A8D8`, `0x0889A8E8` |
| sceLibFont | `sceFontFlush` | 1 | `0x0883D778` |
| sceLibFont | `sceFontOpenUserMemory` | 1 | `0x0883D820` |
| sceLibFont | `sceFontSetAltCharacterCode` | 1 | `0x0883D884` |
| sceMpeg | `sceMpegRingbufferQueryPackNum` | 1 | `0x088633DC` |
| sceRtc | `sceRtcFormatRFC3339LocalTime` | 1 | `0x08891384` |
| sceRtc | `sceRtcConvertUtcToLocalTime` | 1 | `0x0889B670` |
| scePspNpDrm_user | `sceNpDrmEdataGetDataSize` | 1 | `0x0886422C` |
| scePspNpDrm_user | `sceNpDrmRenameCheck` | 3 | `0x08863F38`, `0x088641D0`, `0x088644E8` |
| Kernel_Library | `sceKernelTryLockLwMutex_600` | 1 | `0x0880A524` |
| ModuleMgrForUser | `sceKernelLoadModuleNpDrm` | 1 | `0x08863F50` |
| SysMemUserForUser | unresolved NID `0xDB83A952` | 7 | `0x08818BBC`, `0x08819000`, `0x08819234`, `0x0881927C`, `0x0881933C`, `0x088193BC`, `0x088194CC` |
| SysMemUserForUser | unresolved NID `0xFE707FDF` | 8 | `0x08818BA8`, `0x08818FE4`, `0x08819220`, `0x08819268`, `0x08819328`, `0x088193A8`, `0x08819430`, `0x088194B8` |
| SysMemUserForUser | unresolved NID `0x50F61D8A` | 6 | `0x08818AD0`, `0x08818F18`, `0x08818F5C`, `0x088192B4`, `0x08819364`, `0x08819400` |
| ThreadManForUser | `sceKernelSetAlarm` | 1 | `0x08831F7C` |
| ThreadManForUser | `sceKernelCancelAlarm` | 1 | `0x08831FB0` |
| ThreadManForUser | `sceKernelReferSemaStatus` | 1 | `0x0880AD6C` |
| UtilsForUser | `sceKernelGetGPI` | 3 | `0x08818588`, `0x0881868C`, `0x08818758` |

## Implementation priority from this evidence

1. **MD5** — all four imports have direct call sites (12 calls). A first HLE implementation has now been added to `host/hle/hle_system.cpp` on `feature/geburst-sas-atrac3`; build and runtime validation are still pending.
2. **SysMem unresolved NIDs** — three unknown imports account for 21 direct calls. Resolve their names and argument semantics before implementing them.
3. **Font and JPEG** — all three missing font imports and seven missing JPEG imports listed above have direct references.
4. **NPDRM / ModuleMgr** — the listed NPDRM and module-loader imports are directly referenced and need correct disc-game semantics.
5. **ThreadMan / Kernel_Library** — alarm, semaphore status, and lightweight-mutex calls are directly referenced.

The SAS ATRAC3 bridge and ATRAC guest-context import were also directly referenced; corresponding handlers were added on this feature branch, but have not yet been validated by a successful build or in-game run.
