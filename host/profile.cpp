#include "profile.hpp"

#include <cstdlib>
#include <string>

namespace portablekit {

const char *env(const char *name) {
    // God Eater Burst builds collect GE draw and audio diagnostics by default:
    // a black screen or silent mix should leave evidence without requiring
    // the user to configure Android environment variables. Set
    // GEBURST_DIAGNOSTICS=0 to disable these defaults; an explicit per-trace
    // variable still takes precedence.
    if (game().env_prefix == "GEBURST" &&
        (std::string_view(name) == "TRACE_GE" || std::string_view(name) == "TRACE_AUDIO" ||
         std::string_view(name) == "TRACE_MPEG" || std::string_view(name) == "TRACE_SAS" ||
         std::string_view(name) == "TRACE_FB_TEXTURES" || std::string_view(name) == "TRACE_SYNC" ||
         std::string_view(name) == "TRACE_KERNEL")) {
        std::string full = game().env_prefix;
        full += '_';
        full += name;
        if (const char *value = std::getenv(full.c_str()); value != nullptr) return value;
        if (const char *diagnostics = std::getenv("GEBURST_DIAGNOSTICS");
            diagnostics == nullptr || std::string_view(diagnostics) != "0")
            return "1";
        return nullptr;
    }

    // The prefix is fixed for the life of the process, so the name is built
    // once per call and never kept: getenv's result points into the
    // environment, not into this string.
    std::string full = game().env_prefix;
    full += '_';
    full += name;
    return std::getenv(full.c_str());
}

bool env_set(const char *name) { return env(name) != nullptr; }

std::string env_name(const char *name) { return std::string(game().env_prefix) + '_' + name; }

namespace {
const ProfileVariant *g_active_variant = nullptr;
}

const ProfileVariant *find_variant(std::string_view executable_sha256) {
    for (const ProfileVariant &variant : game().variants)
        if (variant.executable_sha256 != nullptr && executable_sha256 == variant.executable_sha256) return &variant;
    return nullptr;
}

const ProfileVariant *find_variant_by_encrypted(std::string_view eboot_sha256) {
    for (const ProfileVariant &variant : game().variants)
        if (variant.encrypted_executable_sha256 != nullptr && eboot_sha256 == variant.encrypted_executable_sha256)
            return &variant;
    return nullptr;
}

bool is_known_executable(std::string_view executable_sha256) {
    return (game().executable_sha256 != nullptr && executable_sha256 == game().executable_sha256) ||
           find_variant(executable_sha256) != nullptr;
}

void set_active_variant(const ProfileVariant *variant) { g_active_variant = variant; }
const ProfileVariant *active_variant() { return g_active_variant; }

ExtraHleHook active_register_extra_hle() {
    if (g_active_variant != nullptr && g_active_variant->register_extra_hle != nullptr)
        return g_active_variant->register_extra_hle;
    return game().register_extra_hle;
}

PatchImageHook active_patch_loaded_image() {
    if (g_active_variant != nullptr && g_active_variant->patch_loaded_image != nullptr)
        return g_active_variant->patch_loaded_image;
    return game().patch_loaded_image;
}

std::span<const std::uint32_t> active_overlay_slots() {
    if (g_active_variant != nullptr && !g_active_variant->overlay_slots.empty()) return g_active_variant->overlay_slots;
    return game().overlay_slots;
}

} // namespace portablekit
