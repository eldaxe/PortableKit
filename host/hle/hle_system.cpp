// UtilsForUser, LoadExecForUser, StdioForUser, ModuleMgrForUser,
// InterruptManager, scePower, sceRtc, sceImpose, sceOpenPSID and the parameter
// part of sceUtility. sceWlanDrv is with the ad hoc calls in hle_adhoc.cpp.
#include "../profile.hpp"
#include "hle_common.hpp"

#include "kernel/rtc_time.hpp"
#include "overlays.hpp"

#include "psprecomp/common.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <vector>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
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

struct LoadedModule {
    std::string name;
    std::string path;
};
constexpr std::uint32_t kMainModuleId = 0x01000001u;
std::map<std::uint32_t, LoadedModule> &loaded_modules() {
    static std::map<std::uint32_t, LoadedModule> modules{
        {kMainModuleId, {"GOD EATER BURST", "disc0:/PSP_GAME/SYSDIR/EBOOT.BIN"}}
    };
    return modules;
}
struct NpDrmState {
    std::array<std::uint8_t, 16> licensee_key{};
    bool licensee_key_set{};
};
NpDrmState &npdrm_state() {
    static NpDrmState state;
    return state;
}
constexpr std::uint32_t kNpDrmNoKey = 0x80550916u;
constexpr std::uint32_t kNpDrmInvalidFile = 0x80550901u;
constexpr std::uint32_t kNpDrmInternalError = 0x80550902u;

// sceMd5's guest context is the PSPSDK SceKernelUtilsMd5Context layout:
// h[4], pad, remains, computed, total length, then a 64-byte block buffer.
// Keep all state in guest memory so multiple independent contexts work.
namespace md5 {
constexpr std::uint32_t kBadAddress = 0x800200D3u;
constexpr std::uint32_t kContextSize = 96u;
constexpr std::uint32_t kBufferOffset = 32u;
constexpr std::array<std::uint32_t, 64> kConstants = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};
constexpr std::array<unsigned, 64> kShifts = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};
struct State {
    std::array<std::uint32_t, 4> h{0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
    std::uint64_t total{};
    std::uint16_t remains{};
    std::array<std::uint8_t, 64> buffer{};
};
std::uint32_t load32(const psprecomp::GuestMemory &memory, std::uint32_t address) {
    return memory.load32(address);
}
void transform(State &state, const std::uint8_t *block) {
    std::array<std::uint32_t, 16> words{};
    for (unsigned i = 0; i < 16; ++i) {
        const unsigned p = i * 4;
        words[i] = static_cast<std::uint32_t>(block[p]) |
                   (static_cast<std::uint32_t>(block[p + 1]) << 8u) |
                   (static_cast<std::uint32_t>(block[p + 2]) << 16u) |
                   (static_cast<std::uint32_t>(block[p + 3]) << 24u);
    }
    std::uint32_t a = state.h[0], b = state.h[1], c = state.h[2], d = state.h[3];
    for (unsigned i = 0; i < 64; ++i) {
        std::uint32_t f{};
        unsigned g{};
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5u * i + 1u) & 15u; }
        else if (i < 48) { f = b ^ c ^ d; g = (3u * i + 5u) & 15u; }
        else { f = c ^ (b | ~d); g = (7u * i) & 15u; }
        const std::uint32_t next = b + std::rotl(a + f + kConstants[i] + words[g],
                                                  static_cast<int>(kShifts[i]));
        a = d; d = c; c = b; b = next;
    }
    state.h[0] += a; state.h[1] += b; state.h[2] += c; state.h[3] += d;
}
void update(State &state, const std::uint8_t *data, std::size_t size) {
    if (size == 0u) return;
    state.total += size;
    std::size_t offset = 0;
    if (state.remains != 0) {
        const std::size_t take = std::min<std::size_t>(64u - state.remains, size);
        std::copy_n(data, take, state.buffer.begin() + state.remains);
        state.remains = static_cast<std::uint16_t>(state.remains + take);
        offset += take;
        if (state.remains == 64u) {
            transform(state, state.buffer.data());
            state.remains = 0;
        }
    }
    while (offset + 64u <= size) {
        transform(state, data + offset);
        offset += 64u;
    }
    if (offset < size) {
        const std::size_t left = size - offset;
        std::copy_n(data + offset, left, state.buffer.begin());
        state.remains = static_cast<std::uint16_t>(left);
    }
}
std::array<std::uint8_t, 16> finish(State state) {
    const std::uint64_t bits = state.total * 8u;
    state.buffer[state.remains++] = 0x80u;
    if (state.remains > 56u) {
        std::fill(state.buffer.begin() + state.remains, state.buffer.end(), 0u);
        transform(state, state.buffer.data());
        state.remains = 0;
    }
    std::fill(state.buffer.begin() + state.remains, state.buffer.begin() + 56, 0u);
    for (unsigned i = 0; i < 8; ++i)
        state.buffer[56u + i] = static_cast<std::uint8_t>(bits >> (i * 8u));
    transform(state, state.buffer.data());
    std::array<std::uint8_t, 16> digest{};
    for (unsigned i = 0; i < 4; ++i)
        for (unsigned j = 0; j < 4; ++j)
            digest[i * 4u + j] = static_cast<std::uint8_t>(state.h[i] >> (j * 8u));
    return digest;
}
bool read_context(const psprecomp::GuestMemory &memory, std::uint32_t address, State &state) {
    if (address == 0u || !memory.contains(address, kContextSize)) return false;
    for (unsigned i = 0; i < 4; ++i) state.h[i] = load32(memory, address + i * 4u);
    state.remains = memory.load16(address + 20u);
    state.total = static_cast<std::uint64_t>(load32(memory, address + 24u)) |
                  (static_cast<std::uint64_t>(load32(memory, address + 28u)) << 32u);
    if (state.remains > 63u) return false;
    memory.copy_out(address + kBufferOffset, state.buffer);
    return true;
}
void write_context(psprecomp::GuestMemory &memory, std::uint32_t address, const State &state) {
    for (unsigned i = 0; i < 4; ++i) memory.store32(address + i * 4u, state.h[i]);
    memory.store32(address + 16u, 0u);
    memory.store16(address + 20u, state.remains);
    memory.store16(address + 22u, 0u);
    memory.store32(address + 24u, static_cast<std::uint32_t>(state.total));
    memory.store32(address + 28u, static_cast<std::uint32_t>(state.total >> 32u));
    memory.copy_in(address + kBufferOffset, state.buffer);
}
bool read_data(const psprecomp::GuestMemory &memory, std::uint32_t address, std::uint32_t size,
               std::vector<std::uint8_t> &data) {
    if (size == 0u) { data.clear(); return true; }
    if (address == 0u || !memory.contains(address, size)) return false;
    data.resize(size);
    memory.copy_out(address, data);
    return true;
}
void write_digest(psprecomp::GuestMemory &memory, std::uint32_t address,
                  const std::array<std::uint8_t, 16> &digest) {
    memory.copy_in(address, digest);
}
} // namespace md5

void register_md5(HleRegistrar &hle) {
    hle.add("sceMd5", "sceMd5BlockInit", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t address = arg(ctx, 0);
        if (address == 0u || !rt.memory().contains(address, md5::kContextSize)) {
            kernel().finish(ctx, md5::kBadAddress); return;
        }
        md5::State state{};
        md5::write_context(rt.memory(), address, state);
        kernel().finish(ctx, 0u);
    });
    hle.add("sceMd5", "sceMd5BlockUpdate", [](Runtime &rt, AllegrexContext &ctx) {
        md5::State state{};
        const std::uint32_t context = arg(ctx, 0), source = arg(ctx, 1), size = arg(ctx, 2);
        std::vector<std::uint8_t> data;
        if (!md5::read_context(rt.memory(), context, state) ||
            !md5::read_data(rt.memory(), source, size, data)) {
            kernel().finish(ctx, md5::kBadAddress); return;
        }
        md5::update(state, data.data(), data.size());
        md5::write_context(rt.memory(), context, state);
        kernel().finish(ctx, 0u);
    });
    hle.add("sceMd5", "sceMd5BlockResult", [](Runtime &rt, AllegrexContext &ctx) {
        md5::State state{};
        const std::uint32_t context = arg(ctx, 0), output = arg(ctx, 1);
        if (!md5::read_context(rt.memory(), context, state) || output == 0u ||
            !rt.memory().contains(output, 16u)) {
            kernel().finish(ctx, md5::kBadAddress); return;
        }
        md5::write_digest(rt.memory(), output, md5::finish(state));
        kernel().finish(ctx, 0u);
    });
    hle.add("sceMd5", "sceMd5Digest", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t source = arg(ctx, 0), size = arg(ctx, 1), output = arg(ctx, 2);
        std::vector<std::uint8_t> data;
        if (output == 0u || !rt.memory().contains(output, 16u) ||
            !md5::read_data(rt.memory(), source, size, data)) {
            kernel().finish(ctx, md5::kBadAddress); return;
        }
        md5::State state{};
        md5::update(state, data.data(), data.size());
        md5::write_digest(rt.memory(), output, md5::finish(state));
        kernel().finish(ctx, 0u);
    });
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

    // The main executable and stock PRX modules exposed through this HLE.
    hle.add("ModuleMgrForUser", "sceKernelGetModuleId", [](Runtime &, AllegrexContext &ctx) {
        kernel().finish(ctx, kMainModuleId);
    });
    hle.add("ModuleMgrForUser", "sceKernelGetModuleIdByAddress", [](Runtime &, AllegrexContext &ctx) {
        // Until separately loaded PRX images are mapped, only the main image has
        // a meaningful address range in this runtime.
        (void)arg(ctx, 0);
        kernel().finish(ctx, kMainModuleId);
    });
    const auto load_stock_module = [](AllegrexContext &ctx, const std::uint8_t *header,
                                      std::size_t count, const std::string &path) {
        if (count == 0u) {
            kernel().finish(ctx, 0x80020148u); // invalid module image
            return;
        }
        std::string name;
        for (std::size_t i = 0; i + 0x2Au < count; ++i) {
            if (std::memcmp(header + i, "~PSP", 4u) != 0) continue;
            const char *module_name = reinterpret_cast<const char *>(header + i + 0x0Au);
            name.assign(module_name, strnlen(module_name, 28u));
            break;
        }
        if (name.empty()) name = path;
        const auto uid = static_cast<std::uint32_t>(kernel().allocate_uid());
        loaded_modules()[uid] = LoadedModule{name, path};
        log_once("module:" + name, "[module] registered stock module " + name + " from " + path +
                                      " (HLE metadata only; PRX code is not mapped)");
        kernel().finish(ctx, uid);
    };
    const auto load_module_path = [load_stock_module](Runtime &rt, AllegrexContext &ctx) {
        const std::string path = read_cstring(rt.memory(), arg(ctx, 0), 256u);
        std::array<std::uint8_t, 0x100> header{};
        const std::int64_t count = read_guest_file(path, 0u, header.data(), header.size());
        if (count < 0) {
            kernel().finish(ctx, static_cast<std::uint32_t>(count));
            return;
        }
        load_stock_module(ctx, header.data(), static_cast<std::size_t>(count), path);
    };
    hle.add("ModuleMgrForUser", "sceKernelLoadModule", load_module_path);
    hle.add("ModuleMgrForUser", "sceKernelLoadModuleNpDrm", load_module_path);
    hle.add("ModuleMgrForUser", "sceKernelLoadModuleByID", [load_stock_module](Runtime &, AllegrexContext &ctx) {
        const auto size = open_file_size(arg(ctx, 0));
        if (!size) {
            kernel().finish(ctx, 0x80010009u); // bad file descriptor
            return;
        }
        std::array<std::uint8_t, 0x100> header{};
        const std::size_t count = read_open_file(arg(ctx, 0), 0u, header.data(), header.size());
        load_stock_module(ctx, header.data(), count, "fd:" + std::to_string(arg(ctx, 0)));
    });
    hle.add("ModuleMgrForUser", "sceKernelGetModuleIdList", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t buffer = arg(ctx, 0), buffer_size = arg(ctx, 1), count_out = arg(ctx, 2);
        if (buffer == 0u || count_out == 0u || !rt.memory().contains(count_out, 4u) ||
            (buffer_size != 0u && !rt.memory().contains(buffer, buffer_size))) {
            kernel().finish(ctx, error::kIllegalArgument);
            return;
        }
        std::uint32_t count = 0u, written = 0u;
        for (const auto &[uid, module] : loaded_modules()) {
            (void)module;
            if (written + 4u <= buffer_size) {
                rt.memory().store32(buffer + written, uid);
                written += 4u;
            }
            ++count;
        }
        rt.memory().store32(count_out, count);
        kernel().finish(ctx, 0u);
    });
    hle.add("ModuleMgrForUser", "sceKernelQueryModuleInfo", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t uid = arg(ctx, 0), info = arg(ctx, 1);
        if (info == 0u || !rt.memory().contains(info, 4u)) {
            kernel().finish(ctx, error::kIllegalArgument);
            return;
        }
        const auto found = loaded_modules().find(uid);
        if (found == loaded_modules().end()) {
            kernel().finish(ctx, error::kUnknownUid);
            return;
        }
        const std::uint32_t size = rt.memory().load32(info);
        if ((size != 0x40u && size != 0x60u) || !rt.memory().contains(info, size)) {
            kernel().finish(ctx, error::kIllegalArgument);
            return;
        }
        // Segment and entry information is deliberately zero: the HLE module
        // is registered for imports, but its encrypted PRX image is not mapped.
        for (std::uint32_t offset = 4u; offset < std::min(size, 0x60u); offset += 4u)
            rt.memory().store32(info + offset, 0u);
        rt.memory().store32(info, size);
        rt.memory().store8(info + 4u, 0u); // nsegment
        if (size == 0x60u) {
            const std::string &name = found->second.name;
            for (std::uint32_t i = 0; i < 28u; ++i)
                rt.memory().store8(info + 0x44u + i,
                    i < name.size() ? static_cast<std::uint8_t>(name[i]) : 0u);
        }
        kernel().finish(ctx, 0u);
    });
    hle.add("ModuleMgrForUser", "sceKernelStartModule", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t uid = arg(ctx, 0), status = arg(ctx, 3);
        if (!loaded_modules().contains(uid)) {
            kernel().finish(ctx, error::kUnknownUid);
            return;
        }
        if (status != 0u && rt.memory().contains(status, 4u)) rt.memory().store32(status, 0u);
        log_once("module-start:" + std::to_string(uid),
                 "[module] start requested for HLE metadata module " + loaded_modules().at(uid).name +
                 "; no module_start code is mapped");
        kernel().finish(ctx, uid);
    });
    hle.add("ModuleMgrForUser", "sceKernelStopModule", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t uid = arg(ctx, 0), status = arg(ctx, 3);
        if (!loaded_modules().contains(uid)) {
            kernel().finish(ctx, error::kUnknownUid);
            return;
        }
        if (status != 0u && rt.memory().contains(status, 4u)) rt.memory().store32(status, 0u);
        kernel().finish(ctx, 0u);
    });
    hle.add("ModuleMgrForUser", "sceKernelUnloadModule", [](Runtime &, AllegrexContext &ctx) {
        const std::uint32_t uid = arg(ctx, 0);
        if (uid == kMainModuleId || loaded_modules().erase(uid) == 0u) {
            kernel().finish(ctx, error::kUnknownUid);
            return;
        }
        kernel().finish(ctx, 0u);
    });
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
    // A disc game's licensee key and a PSN title's data key: nothing here
    // decrypts with them yet. Chinatown Wars imports both.
    hle.add("scePspNpDrm_user", "sceNpDrmSetLicenseeKey", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t address = arg(ctx, 0);
        if (address == 0u || !rt.memory().contains(address, 16u)) {
            kernel().finish(ctx, error::kIllegalArgument);
            return;
        }
        auto &state = npdrm_state();
        for (std::uint32_t i = 0; i < 16u; ++i) state.licensee_key[i] = rt.memory().load8(address + i);
        state.licensee_key_set = true;
        kernel().finish(ctx, 0u);
    });
    hle.add("scePspNpDrm_user", "sceNpDrmRenameCheck", [](Runtime &rt, AllegrexContext &ctx) {
        if (!npdrm_state().licensee_key_set) {
            kernel().finish(ctx, kNpDrmNoKey);
            return;
        }
        const std::string path = read_cstring(rt.memory(), arg(ctx, 0), 512u);
        std::array<std::uint8_t, 8> magic{};
        const std::int64_t count = read_guest_file(path, 0u, magic.data(), magic.size());
        if (count < 0) {
            kernel().finish(ctx, kNpDrmInvalidFile);
            return;
        }
        // The full EDAT filename/hash verification is not implemented yet.
        // Plain files are accepted; encrypted EDATs must not be reported as
        // cryptographically verified by this compatibility handler.
        const bool edat = count == 8 && magic[0] == 0u && magic[1] == 'P' &&
                          magic[2] == 'S' && magic[3] == 'P' &&
                          magic[4] == 'E' && magic[5] == 'D' && magic[6] == 'A' && magic[7] == 'T';
        kernel().finish(ctx, edat ? kNpDrmInternalError : 0u);
    });
    hle.add("scePspNpDrm_user", "sceNpDrmEdataSetupKey", [](Runtime &rt, AllegrexContext &ctx) {
        if (!npdrm_state().licensee_key_set) {
            kernel().finish(ctx, kNpDrmNoKey);
            return;
        }
        const auto size = open_file_size(arg(ctx, 0));
        if (!size) {
            kernel().finish(ctx, kNpDrmInvalidFile);
            return;
        }
        std::array<std::uint8_t, 8> magic{};
        const std::size_t count = read_open_file(arg(ctx, 0), 0u, magic.data(), magic.size());
        const bool edat = count == 8 && magic[0] == 0u && magic[1] == 'P' &&
                          magic[2] == 'S' && magic[3] == 'P' &&
                          magic[4] == 'E' && magic[5] == 'D' && magic[6] == 'A' && magic[7] == 'T';
        // Plain file descriptors need no EDAT filter. Encrypted content needs
        // the EDAT/PGD crypto path, so fail explicitly instead of returning a
        // false success and handing encrypted bytes to the game.
        kernel().finish(ctx, edat ? kNpDrmInternalError : 0u);
    });
    hle.add("scePspNpDrm_user", "sceNpDrmEdataGetDataSize", [](Runtime &, AllegrexContext &ctx) {
        const auto size = open_file_size(arg(ctx, 0));
        if (!size || *size > 0x7FFFFFFFu) {
            kernel().finish(ctx, size ? error::kIllegalArgument : kNpDrmInvalidFile);
            return;
        }
        kernel().finish(ctx, static_cast<std::uint32_t>(*size));
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
    // Firmware modules requested by the game are backed by PortableKit HLE
    // implementations (network, SAS, ATRAC, MPEG and NPDRM). They are not
    // Sony PRXs mapped into guest memory. Keep the compatibility return value,
    // but make the requested IDs observable when TRACE_UTILITY_MODULES is set.
    const auto trace_module = [](const char *operation, AllegrexContext &ctx) {
        if (portablekit::env("TRACE_UTILITY_MODULES") != nullptr) {
            std::cout << "[utility-module] " << operation
                      << " id=" << psprecomp::hex32(arg(ctx, 0))
                      << " -> 0x00000000 (HLE-backed; no PRX mapped)\\n";
        }
        kernel().finish(ctx, 0u);
    };
    hle.add("sceUtility", "sceUtilityLoadModule",
            [trace_module](Runtime &, AllegrexContext &ctx) { trace_module("load", ctx); });
    // The dialogs themselves live in hle_utility.cpp.
    hle.add("sceUtility", "sceUtilityUnloadModule",
            [trace_module](Runtime &, AllegrexContext &ctx) { trace_module("unload", ctx); });
    // The audio and video modules (sceUtilityLoadAvModule(id)): the codecs
    // are the host's, always there.
    hle.add("sceUtility", "sceUtilityLoadAvModule",
            [trace_module](Runtime &, AllegrexContext &ctx) { trace_module("load-av", ctx); });
    hle.add("sceUtility", "sceUtilityUnloadAvModule",
            [trace_module](Runtime &, AllegrexContext &ctx) { trace_module("unload-av", ctx); });
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
    register_md5(hle);
    register_utils(hle);
    register_process(hle);
    register_interrupts(hle);
    register_platform(hle);
}

} // namespace portablekit
