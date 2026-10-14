// UtilsForUser, LoadExecForUser, StdioForUser, ModuleMgrForUser,
// InterruptManager, scePower, sceRtc, sceImpose, sceOpenPSID and the parameter
// part of sceUtility. sceWlanDrv is with the ad hoc calls in hle_adhoc.cpp.
#include "../profile.hpp"
#include "hle_common.hpp"

#include "kernel/rtc_time.hpp"
#include "overlays.hpp"
#include "save_data/aes128.hpp"

#include "psprecomp/common.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <set>
#include <string>

namespace portablekit {
void register_rtc_calendar(HleRegistrar &hle);
namespace {

// Epoch the virtual PSP clock starts at, so guest wall time advances with it.
std::uint64_t boot_unix_us() {
    static const std::uint64_t value = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    return value;
}

std::uint64_t guest_unix_us() { return boot_unix_us() + kernel().now_us(); }

void success(Runtime &, AllegrexContext &ctx) { kernel().finish(ctx, 0u); }

// sceNpDrmSetLicenseeKey stores a 16-byte key for subsequent EDAT/NPDRM operations.
// Keep the state private to the emulated process and never print the key itself.
std::array<std::uint8_t, 16> npdrm_licensee_key{};
bool npdrm_licensee_key_set = false;

using NpDrmBlock = std::array<std::uint8_t, 16>;

NpDrmBlock npdrm_xor(const NpDrmBlock &a, const NpDrmBlock &b) {
    NpDrmBlock out{};
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = a[i] ^ b[i];
    return out;
}

NpDrmBlock npdrm_double(const NpDrmBlock &in) {
    NpDrmBlock out{};
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = static_cast<std::uint8_t>((in[i] << 1u) | (i + 1u < out.size() ? in[i + 1u] >> 7u : 0u));
    if ((in[0] & 0x80u) != 0u) out[15] ^= 0x87u;
    return out;
}

// sceNpDrmGetFixedKey's BB-MAC derivation for the NPDRM module path.
// Kept separate from PGD's standard CMAC because BB-MAC applies its own
// final masks and fixed-key transform.
bool npdrm_get_fixed_key(const std::uint8_t *content_id, std::uint8_t key_mode, NpDrmBlock &out) {
    if (key_mode > 3u) return false;
    constexpr NpDrmBlock kirk38{
        0x12,0x46,0x8D,0x7E,0x1C,0x42,0x20,0x9B,0xBA,0x54,0x26,0x83,0x5E,0xB0,0x33,0x03
    };
    constexpr NpDrmBlock mac_mask{
        0xE3,0x50,0xED,0x1D,0x91,0x0A,0x1F,0xD0,0x29,0xBB,0x1C,0x3E,0xF3,0x40,0x77,0xFB
    };
    constexpr NpDrmBlock final_key{
        0x38,0x20,0xD0,0x11,0x07,0xA3,0xFF,0x3E,0x0A,0x4C,0x20,0x85,0x39,0x10,0xB5,0x54
    };
    constexpr std::array<NpDrmBlock, 3> mode_keys{{
        {0x07,0x3D,0x9E,0x9D,0xA8,0xFD,0x3B,0x2F,0x63,0x18,0x93,0x2E,0xF8,0x57,0xA6,0x64},
        {0x37,0x49,0xB7,0x01,0xCA,0xE2,0xE0,0xC5,0x44,0x2E,0x06,0xB6,0x1E,0xFF,0x84,0xF2},
        {0x9D,0x31,0xB8,0x5A,0xC8,0xFA,0x16,0x80,0x73,0x60,0x18,0x82,0x18,0x77,0x91,0x9D}
    }};
    const portablekit::savedata::Aes128 cipher(kirk38);
    NpDrmBlock chain{};
    for (std::size_t offset = 0; offset < 0x20u; offset += 16u) {
        NpDrmBlock block{};
        std::copy_n(content_id + offset, block.size(), block.begin());
        chain = cipher.encrypt(npdrm_xor(block, chain));
    }
    // sceDrmBBMacUpdate keeps the final complete 16-byte block in pad
    // (pad_size == 16); BBMacFinal therefore uses K1, without 0x80 padding.
    const NpDrmBlock subkey = npdrm_double(cipher.encrypt(NpDrmBlock{}));
    NpDrmBlock last{};
    std::copy_n(content_id + 0x20u, last.size(), last.begin());
    NpDrmBlock mac = cipher.encrypt(npdrm_xor(npdrm_xor(last, subkey), chain));
    mac = npdrm_xor(mac, mac_mask);
    mac = cipher.encrypt(npdrm_xor(mac, final_key));
    if (key_mode != 0u) mac = portablekit::savedata::Aes128(mode_keys[key_mode - 1u]).encrypt(mac);
    out = mac;
    return true;
}

bool npdrm_derive_module_key(const std::uint8_t *edat, NpDrmBlock &out) {
    NpDrmBlock key{};
    if (!npdrm_get_fixed_key(edat + 0x10u, edat[0x08u], key)) return false;
    if ((edat[0x0Fu] & 1u) != 0u) {
        if (!npdrm_licensee_key_set) return false;
        for (std::size_t i = 0; i < key.size(); ++i) key[i] ^= npdrm_licensee_key[i];
    }
    if ((edat[0x0Fu] & 2u) != 0u)
        for (std::size_t i = 0; i < key.size(); ++i) key[i] ^= edat[0x40u + i];
    constexpr NpDrmBlock drm_module_key{
        0xBA,0x87,0xE4,0xAB,0x2C,0x60,0x5F,0x59,0xB8,0x3B,0xDB,0xA6,0x82,0xFD,0xAE,0x14
    };
    out = portablekit::savedata::Aes128(drm_module_key).decrypt(key);
    return true;
}

// The console settings a game asks for and tells the system, under
// TRACE_KERNEL: which language and which confirm button it ends up using.
bool trace_system_params() {
    static const bool enabled = portablekit::env("TRACE_KERNEL") != nullptr;
    return enabled;
}

void register_utils(HleRegistrar &hle) {
    // The host has no data cache to keep coherent. Phantasy Star Portable 2
    // Infinity (NPJH50332) uses WritebackInvalidateRange.
    for (const char *name : {"sceKernelDcacheWritebackAll", "sceKernelDcacheWritebackInvalidateAll",
                             "sceKernelDcacheInvalidateRange", "sceKernelDcacheWritebackRange",
                             "sceKernelDcacheWritebackInvalidateRange", "sceKernelSetGPO"})
        hle.add("UtilsForUser", name, success);
    // The guest flushes the instruction cache after copying code into an overlay
    // slot, which is the profile's cue to re-check which overlay is loaded.
    const auto flush_icache = [](Runtime &rt, AllegrexContext &ctx) {
        forget_unmatched_overlays();
        revalidate_overlays(rt);
        kernel().finish(ctx, 0u);
    };
    hle.add("UtilsForUser", "sceKernelIcacheInvalidateAll", flush_icache);
    hle.add("UtilsForUser", "sceKernelIcacheInvalidateRange", flush_icache);
    hle.add("UtilsForUser", "sceKernelLibcTime", [](Runtime &rt, AllegrexContext &ctx) {
        const auto seconds = static_cast<std::uint32_t>(guest_unix_us() / 1'000'000u);
        if (arg(ctx, 0) != 0u) rt.memory().store32(arg(ctx, 0), seconds);
        kernel().finish(ctx, seconds);
    });
    hle.add("UtilsForUser", "sceKernelLibcGettimeofday", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint64_t now = guest_unix_us();
        if (arg(ctx, 0) != 0u) {
            rt.memory().store32(arg(ctx, 0), static_cast<std::uint32_t>(now / 1'000'000u));
            rt.memory().store32(arg(ctx, 0) + 4u, static_cast<std::uint32_t>(now % 1'000'000u));
        }
        if (arg(ctx, 1) != 0u) {
            rt.memory().store32(arg(ctx, 1), 0u);
            rt.memory().store32(arg(ctx, 1) + 4u, 0u);
        }
        kernel().finish(ctx, 0u);
    });
    hle.add("UtilsForUser", "sceKernelLibcClock", [](Runtime &, AllegrexContext &ctx) {
        kernel().finish(ctx, static_cast<std::uint32_t>(kernel().now_us()));
    });
}

void register_process(HleRegistrar &hle) {
    hle.add("LoadExecForUser", "sceKernelRegisterExitCallback", success);
    hle.add("LoadExecForUser", "sceKernelExitGame", [](Runtime &rt, AllegrexContext &ctx) {
        (void)ctx;
        rt.stop("guest called sceKernelExitGame");
    });
    hle.add("StdioForUser", "sceKernelStdin", [](Runtime &, AllegrexContext &ctx) { kernel().finish(ctx, 0u); });
    hle.add("StdioForUser", "sceKernelStdout", [](Runtime &, AllegrexContext &ctx) { kernel().finish(ctx, 1u); });
    hle.add("StdioForUser", "sceKernelStderr", [](Runtime &, AllegrexContext &ctx) { kernel().finish(ctx, 2u); });

    // The main executable is the only module; overlays are loaded by game code.
    constexpr std::uint32_t kMainModuleId = 0x01000001u;
    hle.add("ModuleMgrForUser", "sceKernelGetModuleId", [](Runtime &, AllegrexContext &ctx) {
        kernel().finish(ctx, kMainModuleId);
    });
    hle.add("ModuleMgrForUser", "sceKernelGetModuleIdByAddress", [](Runtime &, AllegrexContext &ctx) {
        kernel().finish(ctx, kMainModuleId);
    });
    // Games load Sony's stock modules (font, codecs) as encrypted PRX blobs from
    // the disc. Their exports are served by this profile's HLE, so the load is
    // acknowledged with a module id and the image itself is never touched.
    // The name logged is the one in the module's "~PSP" header.
    const auto load_stock_module = [](AllegrexContext &ctx, const std::uint8_t *header, std::size_t count,
                                      const std::string &where) {
        constexpr std::array<std::uint8_t, 8> edat_magic{0u, 'P', 'S', 'P', 'E', 'D', 'A', 'T'};
        if (count >= 0x94u && std::equal(edat_magic.begin(), edat_magic.end(), header)) {
            const std::uint8_t kind = header[0x0E];
            std::cerr << "[npdrm-module] refusing to report encrypted wrapper as loaded" << where
                      << " kind=" << static_cast<unsigned>(kind)
                      << (kind == 1u ? " (PRX decryption/loader not implemented)" :
                          kind == 3u ? " (PGD data container, not a module)" : " (unknown PSPEDAT kind)")
                      << "\n";
            kernel().finish(ctx, error::kIllegalArgument);
            return;
        }
        std::string name;
        bool recognized = false;
        for (std::size_t i = 0; i + 0x2Au < count; ++i) {
            if (std::memcmp(header + i, "~PSP", 4u) != 0) continue;
            const char *text = reinterpret_cast<const char *>(header + i + 0x0Au);
            name.assign(text, strnlen(text, 28u));
            recognized = true;
            break;
        }
        // An already-decrypted module may be a plain ELF rather than a ~PSP
        // wrapper. Never return a synthetic UID for an empty or unrecognised
        // file: that hides path/NPDRM failures from the caller and the log.
        if (!recognized && count >= 4u && std::memcmp(header, "\x7f" "ELF", 4u) == 0) {
            name = "ELF";
            recognized = true;
        }
        if (!recognized) {
            std::cerr << "[module] cannot process module" << where << ": no PSP PRX/ELF header"
                      << " (bytes=" << count << ")\n";
            kernel().finish(ctx, error::kIllegalArgument);
            return;
        }
        const auto uid = static_cast<std::uint32_t>(kernel().allocate_uid());
        log_once("module:" + name, "[module] loaded stock module " + name + where + " (HLE)");
        kernel().finish(ctx, uid);
    };
    hle.add("ModuleMgrForUser", "sceKernelLoadModuleByID", [load_stock_module](Runtime &, AllegrexContext &ctx) {
        std::array<std::uint8_t, 0x100> header{};
        const std::size_t count = read_open_file(arg(ctx, 0), 0u, header.data(), header.size());
        if (count == 0u) {
            kernel().finish(ctx, 0x80010009u); // SCE_KERNEL_ERROR_BADF
            return;
        }
        load_stock_module(ctx, header.data(), count, " from fd=" + std::to_string(arg(ctx, 0)));
    });
    // NPDRM and ordinary loads share the same file-opening and header-checking
    // path. This is not a success-only stub: the requested file must exist and
    // contain a PRX/ELF signature before stock-module HLE is acknowledged.
    const auto load_module_by_path = [load_stock_module](Runtime &rt, AllegrexContext &ctx) {
        const std::string path = read_cstring(rt.memory(), arg(ctx, 0), 256u);
        if (path.empty()) {
            kernel().finish(ctx, error::kIllegalArgument);
            return;
        }
        std::array<std::uint8_t, 0x100> header{};
        const std::int64_t count = read_guest_file(path, 0u, header.data(), header.size());
        if (count < 0) {
            std::cerr << "[module] cannot open " << path << ": "
                      << psprecomp::hex32(static_cast<std::uint32_t>(count)) << "\n";
            kernel().finish(ctx, static_cast<std::uint32_t>(count));
            return;
        }
        constexpr std::array<std::uint8_t, 8> edat_magic{0u, 'P', 'S', 'P', 'E', 'D', 'A', 'T'};
        if (count >= 0x90 && std::equal(edat_magic.begin(), edat_magic.end(), header.begin())) {
            // PPSSPP's pkg_notes documents byte 0x0E as the discriminator:
            // 3 is a PGD/data container; 1 is the encrypted-PRX path.
            const std::uint8_t kind = header[0x0E];
            std::cerr << "[npdrm-module] path=" << path << " outer=PSPEDAT kind="
                      << static_cast<unsigned>(kind)
                      << (kind == 1u ? " (PRX)" : kind == 3u ? " (PGD/data)" : " (unknown)")
                      << " licensee_key_set=" << (npdrm_licensee_key_set ? "yes" : "no");
            const std::uint32_t payload_offset =
                static_cast<std::uint32_t>(header[0x0Cu]) |
                (static_cast<std::uint32_t>(header[0x0Du]) << 8u);
            std::cerr << " payload_offset=0x" << std::hex << payload_offset << std::dec;
            if (kind == 1u) {
                NpDrmBlock module_key{};
                const bool key_ok = npdrm_derive_module_key(header.data(), module_key);
                std::cerr << " module_key_derived=" << (key_ok ? "yes" : "no");
                std::array<std::uint8_t, 0x150> inner{};
                const std::int64_t inner_count = payload_offset >= 0x90u
                    ? read_guest_file(path, payload_offset, inner.data(), inner.size()) : -1;
                if (inner_count >= static_cast<std::int64_t>(inner.size()) &&
                    std::memcmp(inner.data(), "~PSP", 4u) == 0) {
                    const std::uint32_t tag =
                        static_cast<std::uint32_t>(inner[0xD0u]) |
                        (static_cast<std::uint32_t>(inner[0xD1u]) << 8u) |
                        (static_cast<std::uint32_t>(inner[0xD2u]) << 16u) |
                        (static_cast<std::uint32_t>(inner[0xD3u]) << 24u);
                    const std::uint32_t psp_size =
                        static_cast<std::uint32_t>(inner[0x2Cu]) |
                        (static_cast<std::uint32_t>(inner[0x2Du]) << 8u) |
                        (static_cast<std::uint32_t>(inner[0x2Eu]) << 16u) |
                        (static_cast<std::uint32_t>(inner[0x2Fu]) << 24u);
                    std::cerr << " inner=~PSP tag=0x" << std::hex << tag
                              << " decrypt_mode=0x" << static_cast<unsigned>(inner[0x7Cu])
                              << " psp_size=0x" << psp_size << std::dec;
                } else {
                    std::cerr << " inner_prx_header=unavailable_or_invalid";
                }
            } else if (kind == 3u) {
                std::cerr << " payload_kind=PGD-data";
            }
            std::cerr << "\n";
        }
        load_stock_module(ctx, header.data(), static_cast<std::size_t>(count), " from " + path);
    };
    hle.add("ModuleMgrForUser", "sceKernelLoadModule", load_module_by_path);
    hle.add("ModuleMgrForUser", "sceKernelLoadModuleNpDrm", load_module_by_path);
    for (const char *name : {"sceKernelStartModule", "sceKernelStopModule", "sceKernelUnloadModule"}) {
        hle.add("ModuleMgrForUser", name, [name](Runtime &, AllegrexContext &ctx) {
            log_once(std::string("module-op:") + name, std::string("[module] ") + name);
            // sceKernelStartModule returns the module id it was given.
            kernel().finish(ctx, arg(ctx, 0));
        });
    }
    hle.add("ModuleMgrForUser", "sceKernelStopUnloadSelfModuleWithStatus", [](Runtime &, AllegrexContext &ctx) {
        kernel().exit_current_thread(ctx, static_cast<std::int32_t>(arg(ctx, 1)), true);
    });
}

void register_interrupts(HleRegistrar &hle) {
    hle.add("InterruptManager", "sceKernelRegisterSubIntrHandler", [](Runtime &, AllegrexContext &ctx) {
        auto &handler = kernel().sub_interrupts[arg(ctx, 0)][arg(ctx, 1)];
        handler.handler = arg(ctx, 2);
        handler.argument = arg(ctx, 3);
        kernel().finish(ctx, 0u);
    });
    hle.add("InterruptManager", "sceKernelReleaseSubIntrHandler", [](Runtime &, AllegrexContext &ctx) {
        kernel().finish(ctx, kernel().sub_interrupts[arg(ctx, 0)].erase(arg(ctx, 1)) != 0u ? 0u : error::kIllegalArgument);
    });
    hle.add("InterruptManager", "sceKernelEnableSubIntr", [](Runtime &, AllegrexContext &ctx) {
        auto &handlers = kernel().sub_interrupts[arg(ctx, 0)];
        const auto found = handlers.find(arg(ctx, 1));
        if (found != handlers.end()) found->second.enabled = true;
        kernel().finish(ctx, found != handlers.end() ? 0u : error::kIllegalArgument);
    });
}

void register_platform(HleRegistrar &hle) {
    hle.add("scePower", "scePowerRegisterCallback", [](Runtime &, AllegrexContext &ctx) {
        // Report mains power with a healthy battery so the game stops waiting for
        // the first power notification.
        constexpr std::uint32_t kAcPower = 0x00001000u;
        constexpr std::uint32_t kBatteryExists = 0x00000080u;
        constexpr std::uint32_t kBatteryPower = 0x00000004u;
        kernel().notify_callback(static_cast<SceUID>(arg(ctx, 1)), kAcPower | kBatteryExists | kBatteryPower);
        kernel().finish(ctx, 0u);
    });
    // Nothing here ever changes the power state, so there is nothing to stop
    // reporting; the slot is simply forgotten.
    hle.add("scePower", "scePowerUnregisterCallback", success);
    // The clocks the game asked for, reported back when it asks: a PSP
    // starts at 222/111 MHz. Setting them changes nothing here.
    struct Clocks {
        std::uint32_t pll{222u}, cpu{222u}, bus{111u};
    };
    static Clocks clocks;
    // scePowerSetClockFrequency(pll, cpu, bus) and its aliases: 0xEBD177D6
    // (its name in public NID lists is scePower_EBD177D6), which God of War,
    // Patapon and Chinatown Wars call with 333, 333, 166.
    const auto set_clocks = [](Runtime &, AllegrexContext &ctx) {
        clocks.pll = arg(ctx, 0);
        clocks.cpu = arg(ctx, 1);
        clocks.bus = arg(ctx, 2);
        kernel().finish(ctx, 0u);
    };
    hle.add("scePower", "scePowerSetClockFrequency630", set_clocks);
    hle.add("scePower", "scePowerSetClockFrequency", set_clocks);
    hle.add("scePower", "scePower_EBD177D6", set_clocks);
    hle.add("scePower", "scePowerGetCpuClockFrequencyInt", [](Runtime &, AllegrexContext &ctx) {
        kernel().finish(ctx, clocks.cpu);
    });
    hle.add("scePower", "scePowerGetBusClockFrequencyInt", [](Runtime &, AllegrexContext &ctx) {
        kernel().finish(ctx, clocks.bus);
    });
    hle.add("scePower", "scePowerGetPllClockFrequencyInt", [](Runtime &, AllegrexContext &ctx) {
        kernel().finish(ctx, clocks.pll);
    });
    // The float forms answer in $f0.
    hle.add("scePower", "scePowerGetPllClockFrequencyFloat", [](Runtime &, AllegrexContext &ctx) {
        ctx.fpr[0] = static_cast<float>(clocks.pll);
        kernel().finish(ctx, 0u);
    });
    hle.add("scePower", "scePowerCheckWlanCoexistenceClock", success);

    hle.add("sceRtc", "sceRtcGetCurrentClockLocalTime", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint64_t now = guest_unix_us();
        const auto seconds = static_cast<std::time_t>(now / 1'000'000u);
        std::tm tm{};
#if defined(_WIN32)
        localtime_s(&tm, &seconds);
#else
        localtime_r(&seconds, &tm);
#endif
        auto &memory = rt.memory();
        const std::uint32_t out = arg(ctx, 0);
        memory.store16(out, static_cast<std::uint16_t>(tm.tm_year + 1900));
        memory.store16(out + 2u, static_cast<std::uint16_t>(tm.tm_mon + 1));
        memory.store16(out + 4u, static_cast<std::uint16_t>(tm.tm_mday));
        memory.store16(out + 6u, static_cast<std::uint16_t>(tm.tm_hour));
        memory.store16(out + 8u, static_cast<std::uint16_t>(tm.tm_min));
        memory.store16(out + 10u, static_cast<std::uint16_t>(tm.tm_sec));
        memory.store32(out + 12u, static_cast<std::uint32_t>(now % 1'000'000u));
        kernel().finish(ctx, 0u);
    });
    // The RTC's tick: microseconds since 0001-01-01 00:00:00 UTC, which is
    // 719162 days before the Unix epoch.
    hle.add("sceRtc", "sceRtcGetCurrentTick", [](Runtime &rt, AllegrexContext &ctx) {
        constexpr std::uint64_t kUnixEpochTick = 719'162ull * 86'400ull * 1'000'000ull;
        if (arg(ctx, 0) != 0u) store64(rt.memory(), arg(ctx, 0), kUnixEpochTick + guest_unix_us());
        kernel().finish(ctx, 0u);
    });
    register_rtc_calendar(hle);
    // The power switch is never used here, so holding it off changes nothing.
    hle.add("sceSuspendForUser", "sceKernelPowerLock", success);
    hle.add("sceSuspendForUser", "sceKernelPowerUnlock", success);
    // NPDRM licensee-key state and module-key derivation for encrypted SPRX diagnostics.
    // The inner PRX decryption and dynamic module loader remain unimplemented.
    hle.add("scePspNpDrm_user", "sceNpDrmSetLicenseeKey", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t address = arg(ctx, 0);
        if (address == 0u) {
            kernel().finish(ctx, error::kIllegalArgument);
            return;
        }
        for (std::uint32_t i = 0; i < npdrm_licensee_key.size(); ++i)
            npdrm_licensee_key[i] = rt.memory().load8(address + i);
        npdrm_licensee_key_set = true;
        log_once("npdrm-licensee", "[npdrm] sceNpDrmSetLicenseeKey: stored 16-byte key (value redacted)");
        kernel().finish(ctx, 0u);
    });
    hle.add("scePspNpDrm_user", "sceNpDrmClearLicenseeKey", [](Runtime &, AllegrexContext &ctx) {
        npdrm_licensee_key.fill(0u);
        npdrm_licensee_key_set = false;
        log_once("npdrm-licensee-clear", "[npdrm] sceNpDrmClearLicenseeKey");
        kernel().finish(ctx, 0u);
    });
    hle.add("scePspNpDrm_user", "sceNpDrmEdataSetupKey", [](Runtime &, AllegrexContext &ctx) {
        const std::uint32_t fd = arg(ctx, 0);
        const std::uint32_t result = setup_edata_file(fd);
        kernel().finish(ctx, result);
    });
    hle.add("scePspNpDrm_user", "sceNpDrmEdataGetDataSize", [](Runtime &, AllegrexContext &ctx) {
        const std::uint32_t fd = arg(ctx, 0);
        const std::uint32_t setup_result = setup_edata_file(fd);
        if (setup_result != 0u) {
            kernel().finish(ctx, setup_result);
            return;
        }
        kernel().finish(ctx, edata_file_data_size(fd));
    });
    hle.add("sceImpose", "sceImposeSetLanguageMode", [](Runtime &, AllegrexContext &ctx) {
        if (trace_system_params())
            std::cout << "[sysparam] sceImposeSetLanguageMode language=" << arg(ctx, 0) << " button=" << arg(ctx, 1)
                      << "\n";
        kernel().finish(ctx, 0u);
    });
    // (int *language, int *button): the console's, as GetSystemParamInt says.
    hle.add("sceImpose", "sceImposeGetLanguageMode", [](Runtime &rt, AllegrexContext &ctx) {
        if (arg(ctx, 0) != 0u) rt.memory().store32(arg(ctx, 0), portablekit::game().system_language);
        if (arg(ctx, 1) != 0u) rt.memory().store32(arg(ctx, 1), portablekit::game().confirm_button);
        kernel().finish(ctx, 0u);
    });
    // Microseconds the console has been on, as the RTC counts them.
    hle.add("sceRtc", "sceRtcGetAccumulativeTime", [](Runtime &, AllegrexContext &ctx) {
        kernel().finish64(ctx, kernel().now_us());
    });
    // The shell's "the disc has been ejected" popup. There is no shell and no
    // disc to eject, so whether the game wants it makes no difference.
    hle.add("sceImpose", "sceImposeSetUMDPopup", success);
    hle.add("sceOpenPSID", "sceOpenPSIDGetOpenPSID", [](Runtime &rt, AllegrexContext &ctx) {
        for (std::uint32_t i = 0; i < 16u; ++i) rt.memory().store8(arg(ctx, 0) + i, static_cast<std::uint8_t>(0x10u + i));
        kernel().finish(ctx, 0u);
    });
    // sceUtilityGetSystemParamString(id, char *buffer, int length): id 1 is
    // the console's nickname. Vice City Stories and Chinatown Wars import it.
    hle.add("sceUtility", "sceUtilityGetSystemParamString", [](Runtime &rt, AllegrexContext &ctx) {
        constexpr std::uint32_t kInvalidId = 0x80110103u;  // not traced
        log_once("utility-param-string", "[utility] sceUtilityGetSystemParamString (UNVERIFIED: no game traced yet)");
        if (arg(ctx, 0) != 1u || arg(ctx, 1) == 0u || arg(ctx, 2) == 0u) {
            kernel().finish(ctx, kInvalidId);
            return;
        }
        write_cstring(rt.memory(), arg(ctx, 1), "PortableKit", arg(ctx, 2));
        kernel().finish(ctx, 0u);
    });
    hle.add("sceUtility", "sceUtilityGetSystemParamInt", [](Runtime &rt, AllegrexContext &ctx) {
        std::uint32_t value = 0u;
        switch (arg(ctx, 0)) {
        case 2u: value = 1u; break;  // ad hoc channel: automatic
        case 4u: value = 0u; break;  // date format YYYYMMDD
        case 5u: value = 0u; break;  // 24-hour clock
        case 8u: value = portablekit::game().system_language; break;
        case 9u: value = portablekit::game().confirm_button; break;
        default: break;
        }
        if (trace_system_params())
            std::cout << "[sysparam] sceUtilityGetSystemParamInt id=" << arg(ctx, 0) << " -> " << value << "\n";
        rt.memory().store32(arg(ctx, 1), value);
        kernel().finish(ctx, 0u);
    });
    hle.add("sceUtility", "sceUtilityLoadModule", success);
    // The dialogs themselves live in hle_utility.cpp.
    hle.add("sceUtility", "sceUtilityUnloadModule", success);
    // The audio and video modules (sceUtilityLoadAvModule(id)): the codecs
    // are the host's, always there.
    hle.add("sceUtility", "sceUtilityLoadAvModule", success);
    hle.add("sceUtility", "sceUtilityUnloadAvModule", success);
}

} // namespace

// ScePspDateTime: year, month, day, hour, minute, second (16-bit each), then
// the microsecond (32-bit).
rtc::DateTime read_date(const psprecomp::GuestMemory &memory, std::uint32_t address) {
    rtc::DateTime date;
    date.year = memory.load16(address);
    date.month = memory.load16(address + 2u);
    date.day = memory.load16(address + 4u);
    date.hour = memory.load16(address + 6u);
    date.minute = memory.load16(address + 8u);
    date.second = memory.load16(address + 10u);
    date.microsecond = memory.load32(address + 12u);
    return date;
}

void write_date(psprecomp::GuestMemory &memory, std::uint32_t address, const rtc::DateTime &date) {
    memory.store16(address, static_cast<std::uint16_t>(date.year));
    memory.store16(address + 2u, static_cast<std::uint16_t>(date.month));
    memory.store16(address + 4u, static_cast<std::uint16_t>(date.day));
    memory.store16(address + 6u, static_cast<std::uint16_t>(date.hour));
    memory.store16(address + 8u, static_cast<std::uint16_t>(date.minute));
    memory.store16(address + 10u, static_cast<std::uint16_t>(date.second));
    memory.store32(address + 12u, date.microsecond);
}

std::uint64_t load_tick(const psprecomp::GuestMemory &memory, std::uint32_t address) {
    return static_cast<std::uint64_t>(memory.load32(address)) | static_cast<std::uint64_t>(memory.load32(address + 4u)) << 32u;
}

void rtc_unverified(const char *name) {
    static std::set<std::string> said;
    if (said.insert(name).second) std::cerr << "[rtc] " << name << " (UNVERIFIED: no game traced yet)\n";
}

// A date that does not exist: what the library answers has not been traced.
constexpr std::uint32_t kRtcInvalidDate = 0xFFFFFFFFu;

void register_rtc_calendar(HleRegistrar &hle) {
    // sceRtcGetTick(const ScePspDateTime *, u64 *tick). Vice City Stories and
    // Chinatown Wars import it and CompareTick, Chinatown Wars GetCurrentClock;
    // none has been seen calling them yet. The calendar is rtc_time.hpp's,
    // unit-tested.
    hle.add("sceRtc", "sceRtcGetTick", [](Runtime &rt, AllegrexContext &ctx) {
        rtc_unverified("sceRtcGetTick");
        const auto tick = rtc::to_tick(read_date(rt.memory(), arg(ctx, 0)));
        if (!tick) {
            kernel().finish(ctx, kRtcInvalidDate);
            return;
        }
        if (arg(ctx, 1) != 0u) store64(rt.memory(), arg(ctx, 1), *tick);
        kernel().finish(ctx, 0u);
    });
    // sceRtcSetTick(ScePspDateTime *, const u64 *tick)
    hle.add("sceRtc", "sceRtcSetTick", [](Runtime &rt, AllegrexContext &ctx) {
        rtc_unverified("sceRtcSetTick");
        write_date(rt.memory(), arg(ctx, 0), rtc::from_tick(load_tick(rt.memory(), arg(ctx, 1))));
        kernel().finish(ctx, 0u);
    });
    // sceRtcCompareTick(const u64 *a, const u64 *b): 1, 0 or -1.
    hle.add("sceRtc", "sceRtcCompareTick", [](Runtime &rt, AllegrexContext &ctx) {
        rtc_unverified("sceRtcCompareTick");
        const std::uint64_t a = load_tick(rt.memory(), arg(ctx, 0));
        const std::uint64_t b = load_tick(rt.memory(), arg(ctx, 1));
        kernel().finish(ctx, a > b ? 1u : a < b ? 0xFFFFFFFFu : 0u);
    });
    // sceRtcGetCurrentClock(ScePspDateTime *, int minutes east of UTC).
    hle.add("sceRtc", "sceRtcGetCurrentClock", [](Runtime &rt, AllegrexContext &ctx) {
        rtc_unverified("sceRtcGetCurrentClock");
        const auto offset = static_cast<std::int64_t>(static_cast<std::int32_t>(arg(ctx, 1))) * 60 *
                            static_cast<std::int64_t>(rtc::kTicksPerSecond);
        const auto tick = static_cast<std::uint64_t>(static_cast<std::int64_t>(rtc::kUnixEpochTick + guest_unix_us()) + offset);
        write_date(rt.memory(), arg(ctx, 0), rtc::from_tick(tick));
        kernel().finish(ctx, 0u);
    });
    hle.add("sceRtc", "sceRtcGetDayOfWeek", [](Runtime &, AllegrexContext &ctx) {
        rtc_unverified("sceRtcGetDayOfWeek");
        kernel().finish(ctx, static_cast<std::uint32_t>(rtc::day_of_week(static_cast<int>(arg(ctx, 0)),
                                                                          static_cast<int>(arg(ctx, 1)),
                                                                          static_cast<int>(arg(ctx, 2)))));
    });
    hle.add("sceRtc", "sceRtcGetDaysInMonth", [](Runtime &, AllegrexContext &ctx) {
        rtc_unverified("sceRtcGetDaysInMonth");
        kernel().finish(ctx, static_cast<std::uint32_t>(rtc::days_in_month(static_cast<int>(arg(ctx, 0)),
                                                                            static_cast<int>(arg(ctx, 1)))));
    });
    hle.add("sceRtc", "sceRtcIsLeapYear", [](Runtime &, AllegrexContext &ctx) {
        rtc_unverified("sceRtcIsLeapYear");
        kernel().finish(ctx, rtc::is_leap_year(static_cast<int>(arg(ctx, 0))) ? 1u : 0u);
    });
    hle.add("sceRtc", "sceRtcCheckValid", [](Runtime &rt, AllegrexContext &ctx) {
        rtc_unverified("sceRtcCheckValid");
        kernel().finish(ctx, rtc::to_tick(read_date(rt.memory(), arg(ctx, 0))) ? 0u : kRtcInvalidDate);
    });
    // sceRtcGetTime64_t(const ScePspDateTime *, u64 *time): seconds since
    // 1970-01-01. Phantasy Star Portable 2 Infinity (NPJH50332) calls it.
    hle.add("sceRtc", "sceRtcGetTime64_t", [](Runtime &rt, AllegrexContext &ctx) {
        const auto tick = rtc::to_tick(read_date(rt.memory(), arg(ctx, 0)));
        if (!tick || *tick < rtc::kUnixEpochTick) {
            kernel().finish(ctx, kRtcInvalidDate);
            return;
        }
        if (arg(ctx, 1) != 0u) store64(rt.memory(), arg(ctx, 1), (*tick - rtc::kUnixEpochTick) / rtc::kTicksPerSecond);
        kernel().finish(ctx, 0u);
    });
    hle.add("sceRtc", "sceRtcGetTickResolution", [](Runtime &, AllegrexContext &ctx) {
        rtc_unverified("sceRtcGetTickResolution");
        kernel().finish(ctx, static_cast<std::uint32_t>(rtc::kTicksPerSecond));
    });
    // sceRtcTickAdd*(u64 *dst, const u64 *src, amount): the 64-bit amounts
    // come in a2:a3, the 32-bit ones in a2.
    const auto add_ticks = [](const char *name, std::uint64_t unit, bool wide) {
        return [name, unit, wide](Runtime &rt, AllegrexContext &ctx) {
            rtc_unverified(name);
            const std::int64_t amount =
                wide ? static_cast<std::int64_t>(static_cast<std::uint64_t>(arg(ctx, 2)) |
                                                 static_cast<std::uint64_t>(arg(ctx, 3)) << 32u)
                     : static_cast<std::int64_t>(static_cast<std::int32_t>(arg(ctx, 2)));
            const std::uint64_t source = load_tick(rt.memory(), arg(ctx, 1));
            store64(rt.memory(), arg(ctx, 0), source + static_cast<std::uint64_t>(amount * static_cast<std::int64_t>(unit)));
            kernel().finish(ctx, 0u);
        };
    };
    hle.add("sceRtc", "sceRtcTickAddTicks", add_ticks("sceRtcTickAddTicks", 1u, true));
    hle.add("sceRtc", "sceRtcTickAddMicroseconds", add_ticks("sceRtcTickAddMicroseconds", 1u, true));
    hle.add("sceRtc", "sceRtcTickAddSeconds", add_ticks("sceRtcTickAddSeconds", rtc::kTicksPerSecond, true));
    hle.add("sceRtc", "sceRtcTickAddMinutes", add_ticks("sceRtcTickAddMinutes", 60u * rtc::kTicksPerSecond, true));
    hle.add("sceRtc", "sceRtcTickAddHours", add_ticks("sceRtcTickAddHours", 3600u * rtc::kTicksPerSecond, false));
    hle.add("sceRtc", "sceRtcTickAddDays", add_ticks("sceRtcTickAddDays", rtc::kTicksPerDay, false));
    hle.add("sceRtc", "sceRtcTickAddWeeks", add_ticks("sceRtcTickAddWeeks", 7u * rtc::kTicksPerDay, false));
}

void register_system(HleRegistrar &hle) {
    register_utils(hle);
    register_process(hle);
    register_interrupts(hle);
    register_platform(hle);
}

} // namespace portablekit
