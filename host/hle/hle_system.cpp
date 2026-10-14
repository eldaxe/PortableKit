// UtilsForUser, LoadExecForUser, StdioForUser, ModuleMgrForUser,
// InterruptManager, scePower, sceRtc, sceImpose, sceOpenPSID and the parameter
// part of sceUtility. sceWlanDrv is with the ad hoc calls in hle_adhoc.cpp.
#include "../profile.hpp"
#include "../crypto_keys.hpp"
#include "hle_common.hpp"

#include "kernel/rtc_time.hpp"
#include "overlays.hpp"
#include "save_data/aes128.hpp"

#include "psprecomp/common.hpp"
#include "psprecomp/elf32.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <limits>
#include <set>
#include <span>
#include <string>
#include <vector>

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

using NpDrmSha1 = std::array<std::uint8_t, 20>;

NpDrmSha1 npdrm_sha1(std::span<const std::uint8_t> input) {
    std::vector<std::uint8_t> bytes(input.begin(), input.end());
    const std::uint64_t bit_length = static_cast<std::uint64_t>(bytes.size()) * 8u;
    bytes.push_back(0x80u);
    while ((bytes.size() & 63u) != 56u) bytes.push_back(0u);
    for (int shift = 56; shift >= 0; shift -= 8)
        bytes.push_back(static_cast<std::uint8_t>(bit_length >> shift));
    std::uint32_t h0 = 0x67452301u, h1 = 0xEFCDAB89u, h2 = 0x98BADCFEu;
    std::uint32_t h3 = 0x10325476u, h4 = 0xC3D2E1F0u;
    for (std::size_t offset = 0; offset < bytes.size(); offset += 64u) {
        std::array<std::uint32_t, 80> w{};
        for (std::size_t i = 0; i < 16u; ++i) {
            const std::size_t p = offset + i * 4u;
            w[i] = (static_cast<std::uint32_t>(bytes[p]) << 24u) |
                   (static_cast<std::uint32_t>(bytes[p + 1u]) << 16u) |
                   (static_cast<std::uint32_t>(bytes[p + 2u]) << 8u) | bytes[p + 3u];
        }
        for (std::size_t i = 16u; i < 80u; ++i) {
            const std::uint32_t v = w[i - 3u] ^ w[i - 8u] ^ w[i - 14u] ^ w[i - 16u];
            w[i] = (v << 1u) | (v >> 31u);
        }
        std::uint32_t a = h0, b = h1, d = h3, e = h4, cc = h2;
        for (std::size_t i = 0; i < 80u; ++i) {
            std::uint32_t f{}, k{};
            if (i < 20u) { f = (b & cc) | (~b & d); k = 0x5A827999u; }
            else if (i < 40u) { f = b ^ cc ^ d; k = 0x6ED9EBA1u; }
            else if (i < 60u) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDCu; }
            else { f = b ^ cc ^ d; k = 0xCA62C1D6u; }
            const std::uint32_t rotated = (a << 5u) | (a >> 27u);
            const std::uint32_t temp = rotated + f + e + k + w[i];
            e = d; d = cc; cc = (b << 30u) | (b >> 2u); b = a; a = temp;
        }
        h0 += a; h1 += b; h2 += cc; h3 += d; h4 += e;
    }
    NpDrmSha1 out{};
    const std::array<std::uint32_t, 5> words{h0, h1, h2, h3, h4};
    for (std::size_t i = 0; i < words.size(); ++i)
        for (std::size_t j = 0; j < 4u; ++j)
            out[i * 4u + j] = static_cast<std::uint8_t>(words[i] >> (24u - j * 8u));
    return out;
}

void npdrm_kirk7(std::span<std::uint8_t> data, const NpDrmBlock &key) {
    const portablekit::savedata::Aes128 cipher(key);
    NpDrmBlock previous{};
    for (std::size_t offset = 0; offset < data.size(); offset += 16u) {
        NpDrmBlock encrypted{};
        std::copy_n(data.data() + offset, encrypted.size(), encrypted.begin());
        NpDrmBlock plain = cipher.decrypt(encrypted);
        for (std::size_t i = 0; i < plain.size(); ++i) data[offset + i] = plain[i] ^ previous[i];
        previous = encrypted;
    }
}

// Validates the decrypted PRX type-5 header used by NPDRM SPRX modules.

bool npdrm_validate_sprx_header(std::span<const std::uint8_t> prx, const NpDrmBlock &module_key);

NpDrmBlock npdrm_cmac(std::span<const std::uint8_t> message, const NpDrmBlock &key) {
    const portablekit::savedata::Aes128 aes(key);
    const NpDrmBlock zero{};
    const NpDrmBlock l = aes.encrypt(zero);
    auto dbl = [](const NpDrmBlock &in) {
        NpDrmBlock out{};
        for (std::size_t i = 0; i < 16u; ++i)
            out[i] = static_cast<std::uint8_t>((in[i] << 1u) | (i + 1u < 16u ? in[i + 1u] >> 7u : 0u));
        if ((in[0] & 0x80u) != 0u) out[15] ^= 0x87u;
        return out;
    };
    const NpDrmBlock k1 = dbl(l);
    const NpDrmBlock k2 = dbl(k1);
    const std::size_t blocks = message.empty() ? 1u : (message.size() + 15u) / 16u;
    const bool complete = !message.empty() && (message.size() % 16u == 0u);
    NpDrmBlock previous{};
    for (std::size_t block = 0; block + 1u < blocks; ++block) {
        NpDrmBlock current{};
        std::copy_n(message.data() + block * 16u, 16u, current.begin());
        previous = aes.encrypt(npdrm_xor(previous, current));
    }
    NpDrmBlock last{};
    const std::size_t last_offset = (blocks - 1u) * 16u;
    const std::size_t remaining = message.size() > last_offset ? message.size() - last_offset : 0u;
    if (remaining != 0u) std::copy_n(message.data() + last_offset, remaining, last.begin());
    if (complete) last = npdrm_xor(last, k1);
    else {
        last[remaining] = 0x80u;
        last = npdrm_xor(last, k2);
    }
    return aes.encrypt(npdrm_xor(previous, last));
}

bool npdrm_cbc_decrypt(std::span<std::uint8_t> data, const NpDrmBlock &key) {
    if (data.empty() || (data.size() % 16u) != 0u) return false;
    const portablekit::savedata::Aes128 aes(key);
    NpDrmBlock previous{};
    for (std::size_t offset = 0; offset < data.size(); offset += 16u) {
        NpDrmBlock ciphertext{};
        std::copy_n(data.data() + offset, 16u, ciphertext.begin());
        NpDrmBlock plain = aes.decrypt(ciphertext);
        for (std::size_t i = 0; i < 16u; ++i) data[offset + i] = plain[i] ^ previous[i];
        previous = ciphertext;
    }
    return true;
}

// Reconstruct and decrypt the KIRK CMD1 block from a type-5 NPDRM SPRX.
// The result is the decrypted PRX payload; ELF/module mapping is a separate step.
bool npdrm_decrypt_type5_payload(std::span<const std::uint8_t> prx,
                                 const NpDrmBlock &module_key,
                                 std::vector<std::uint8_t> &payload,
                                 std::string &reason) {
    if (!npdrm_validate_sprx_header(prx, module_key)) {
        reason = "type5-header-validation-failed";
        return false;
    }
    const CryptoKeys *keys = crypto_keys();
    if (keys == nullptr || !keys->kirk_cmd1.has_value()) {
        reason = "missing-kirk-cmd1-key";
        return false;
    }
    if (prx.size() < 0x150u) {
        reason = "prx-too-small";
        return false;
    }

    constexpr NpDrmBlock sprx_xor{
        0x84,0x7B,0xF5,0xFE,0xE8,0x4D,0xAD,0x7A,0xB5,0x06,0x28,0x0E,0x09,0xFA,0x81,0xE1
    };
    constexpr NpDrmBlock tag_key{
        0xAF,0xAD,0xCA,0xF1,0x95,0x59,0x91,0xEC,0x1B,0x27,0xD0,0x4E,0x8A,0xF3,0x3D,0xE7
    };
    const Key16 *kirk7_key = keys->kirk(0x6Au);
    if (kirk7_key == nullptr) {
        reason = "missing-kirk-slot-0x6a";
        return false;
    }
    std::array<std::uint8_t, 0x90> expanded{};
    for (std::size_t offset = 0; offset < expanded.size(); offset += 16u) {
        std::copy(tag_key.begin(), tag_key.end(), expanded.begin() + static_cast<std::ptrdiff_t>(offset));
        expanded[offset] = static_cast<std::uint8_t>(offset / 16u);
    }
    npdrm_kirk7(expanded, *kirk7_key);
    for (std::size_t i = 0; i < expanded.size(); ++i) expanded[i] ^= module_key[i % 16u];

    std::array<std::uint8_t, 0x40> encrypted_kirk_header{};
    std::copy_n(prx.data() + 0x80u, 0x30u, encrypted_kirk_header.begin());
    std::copy_n(prx.data() + 0xC0u, 0x10u, encrypted_kirk_header.begin() + 0x30);
    std::array<std::uint8_t, 0x50> first{};
    std::copy(encrypted_kirk_header.begin(), encrypted_kirk_header.end(), first.begin());
    std::copy_n(prx.data() + 0x12Cu, 0x10u, first.begin() + 0x40);
    for (std::size_t i = 0; i < first.size(); ++i)
        first[i] ^= sprx_xor[i % 16u] ^ module_key[i % 16u];
    npdrm_kirk7(first, *kirk7_key);
    std::copy_n(first.begin(), encrypted_kirk_header.size(), encrypted_kirk_header.begin());

    NpDrmBlock kirk_header{};
    for (std::size_t i = 0; i < kirk_header.size(); ++i)
        kirk_header[i] = encrypted_kirk_header[i] ^ expanded[0x10u + i];
    npdrm_kirk7(kirk_header, *kirk7_key);
    for (std::size_t i = 0; i < kirk_header.size(); ++i)
        kirk_header[i] ^= expanded[0x50u + i];

    std::vector<std::uint8_t> work(prx.begin(), prx.end());
    constexpr std::size_t header_offset = 0x40u;
    std::fill_n(work.begin() + header_offset, 0x90u, 0u);
    std::copy(kirk_header.begin(), kirk_header.end(), work.begin() + header_offset);
    std::copy_n(prx.data() + 0xB0u, 0x10u, work.begin() + header_offset + 0x70u);
    std::copy_n(prx.data(), 0x80u, work.begin() + header_offset + 0x90u);
    work[header_offset + 0x60u] = 1u; // KIRK_MODE_CMD1

    auto read_le32 = [](const std::uint8_t *p) {
        return static_cast<std::uint32_t>(p[0]) |
               (static_cast<std::uint32_t>(p[1]) << 8u) |
               (static_cast<std::uint32_t>(p[2]) << 16u) |
               (static_cast<std::uint32_t>(p[3]) << 24u);
    };
    const std::uint32_t data_size = read_le32(work.data() + header_offset + 0x70u);
    const std::uint32_t data_offset = read_le32(work.data() + header_offset + 0x74u);
    const std::uint64_t aligned_size = (static_cast<std::uint64_t>(data_size) + 15u) & ~std::uint64_t(15u);
    const std::uint64_t needed = header_offset + 0x90u + data_offset + aligned_size;
    if (data_size == 0u || (data_size % 16u) != 0u || needed > work.size() ||
        data_size > 64u * 1024u * 1024u) {
        reason = "kirk-output-range-invalid";
        return false;
    }

    NpDrmBlock encrypted_keys{};
    std::copy_n(work.data() + header_offset, encrypted_keys.size(), encrypted_keys.begin());
    if (!npdrm_cbc_decrypt(encrypted_keys, *keys->kirk_cmd1)) {
        reason = "kirk-cmd1-key-decrypt-failed";
        return false;
    }
    NpDrmBlock aes_key{}, cmac_key{};
    std::copy_n(encrypted_keys.begin(), 16u, aes_key.begin());
    std::copy_n(encrypted_keys.begin() + 16u, 16u, cmac_key.begin());

    const std::span<const std::uint8_t> header_auth(
        work.data() + header_offset + 0x60u, 0x30u);
    const NpDrmBlock header_mac = npdrm_cmac(header_auth, cmac_key);
    if (!std::equal(header_mac.begin(), header_mac.end(),
                    work.begin() + header_offset + 0x20u)) {
        reason = "kirk-header-cmac-failed";
        return false;
    }
    const std::size_t data_auth_size = 0x30u + static_cast<std::size_t>(data_offset) +
                                       static_cast<std::size_t>(aligned_size);
    const std::span<const std::uint8_t> data_auth(
        work.data() + header_offset + 0x60u, data_auth_size);
    const NpDrmBlock data_mac = npdrm_cmac(data_auth, cmac_key);
    if (!std::equal(data_mac.begin(), data_mac.end(),
                    work.begin() + header_offset + 0x30u)) {
        reason = "kirk-data-cmac-failed";
        return false;
    }

    const std::size_t cipher_offset = header_offset + 0x90u + data_offset;
    payload.assign(work.begin() + static_cast<std::ptrdiff_t>(cipher_offset),
                   work.begin() + static_cast<std::ptrdiff_t>(cipher_offset + data_size));
    if (!npdrm_cbc_decrypt(payload, aes_key)) {
        payload.clear();
        reason = "kirk-payload-decrypt-failed";
        return false;
    }
    reason = "ok";
    return true;
}

bool npdrm_validate_sprx_header(std::span<const std::uint8_t> prx, const NpDrmBlock &module_key) {
    if (prx.size() < 0x150u || std::memcmp(prx.data(), "~PSP", 4u) != 0) return false;
    const std::uint32_t tag = static_cast<std::uint32_t>(prx[0xD0u]) |
        (static_cast<std::uint32_t>(prx[0xD1u]) << 8u) |
        (static_cast<std::uint32_t>(prx[0xD2u]) << 16u) |
        (static_cast<std::uint32_t>(prx[0xD3u]) << 24u);
    if (tag != 0x407810F0u || prx[0x7Cu] != 23u) return false;
    for (std::size_t i = 0xD5u; i < 0x12Cu; ++i)
        if (prx[i] != 0u) return false;
    const CryptoKeys *keys = crypto_keys();
    const Key16 *kirk_key = keys != nullptr ? keys->kirk(0x6Au) : nullptr;
    if (kirk_key == nullptr) return false;
    constexpr NpDrmBlock tag_key{
        0xAF,0xAD,0xCA,0xF1,0x95,0x59,0x91,0xEC,0x1B,0x27,0xD0,0x4E,0x8A,0xF3,0x3D,0xE7
    };
    constexpr NpDrmBlock sprx_xor{
        0x84,0x7B,0xF5,0xFE,0xE8,0x4D,0xAD,0x7A,0xB5,0x06,0x28,0x0E,0x09,0xFA,0x81,0xE1
    };
    // expandSeed(tag_key, 0x6A, module_key): nine AES-CBC blocks, then xor2.
    std::array<std::uint8_t, 0x90> expanded{};
    for (std::size_t offset = 0; offset < expanded.size(); offset += 16u) {
        std::copy(tag_key.begin(), tag_key.end(), expanded.begin() + static_cast<std::ptrdiff_t>(offset));
        expanded[offset] = static_cast<std::uint8_t>(offset / 16u);
    }
    npdrm_kirk7(expanded, *kirk_key);
    for (std::size_t i = 0; i < expanded.size(); ++i) expanded[i] ^= module_key[i % 16u];

    std::array<std::uint8_t, 4> tag_bytes{};
    std::copy_n(prx.data() + 0xD0u, 4u, tag_bytes.begin());
    std::array<std::uint8_t, 0x58> empty{};
    std::array<std::uint8_t, 0x10> id{};
    std::array<std::uint8_t, 0x14> sha{};
    std::array<std::uint8_t, 0x40> kirk_header{};
    std::array<std::uint8_t, 0x10> metadata{};
    std::array<std::uint8_t, 0x80> prx_header{};
    std::copy_n(prx.data() + 0x140u, id.size(), id.begin());
    std::copy_n(prx.data() + 0x12Cu, sha.size(), sha.begin());
    std::copy_n(prx.data() + 0x80u, 0x30u, kirk_header.begin());
    std::copy_n(prx.data() + 0xC0u, 0x10u, kirk_header.begin() + 0x30);
    std::copy_n(prx.data() + 0xB0u, metadata.size(), metadata.begin());
    std::copy_n(prx.data(), prx_header.size(), prx_header.begin());

    std::array<std::uint8_t, 0x50> first{};
    std::copy(kirk_header.begin(), kirk_header.end(), first.begin());
    std::copy_n(sha.begin(), 0x10u, first.begin() + 0x40);
    for (std::size_t i = 0; i < first.size(); ++i)
        first[i] ^= sprx_xor[i % 16u] ^ module_key[i % 16u];
    npdrm_kirk7(first, *kirk_key);
    std::copy_n(first.begin(), kirk_header.size(), kirk_header.begin());
    std::copy_n(first.begin() + 0x40, 0x10u, sha.begin());

    // PRXType5::decrypt() applies xor1 to the contiguous id + SHA1 +
    // kirkHeader region, then runs KIRK7 over all 0x60 bytes. The struct
    // layout matters here: id is followed immediately by sha1 and kirkHeader.
    std::array<std::uint8_t, 0x60> id_region{};
    std::copy(id.begin(), id.end(), id_region.begin());
    std::copy(sha.begin(), sha.end(), id_region.begin() + 0x10);
    std::copy_n(kirk_header.begin(), 0x3Cu, id_region.begin() + 0x24);
    for (std::size_t i = 0; i < id_region.size(); ++i) id_region[i] ^= sprx_xor[i % 16u];
    npdrm_kirk7(id_region, *kirk_key);
    std::copy_n(id_region.begin(), id.size(), id.begin());
    std::copy_n(id_region.begin() + 0x10, sha.size(), sha.begin());
    std::copy_n(id_region.begin() + 0x24, 0x3Cu, kirk_header.begin());

    std::vector<std::uint8_t> hash_data;
    hash_data.insert(hash_data.end(), tag_bytes.begin(), tag_bytes.end());
    hash_data.insert(hash_data.end(), expanded.begin(), expanded.begin() + 0x10);
    hash_data.insert(hash_data.end(), empty.begin(), empty.end());
    hash_data.insert(hash_data.end(), id.begin(), id.end());
    hash_data.insert(hash_data.end(), kirk_header.begin(), kirk_header.end());
    hash_data.insert(hash_data.end(), metadata.begin(), metadata.end());
    hash_data.insert(hash_data.end(), prx_header.begin(), prx_header.end());
    const NpDrmSha1 digest = npdrm_sha1(hash_data);
    return std::equal(digest.begin(), digest.end(), sha.begin());
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


struct LoadedPrxModule {
    std::uint32_t uid{};
    std::int32_t memory_block{};
    std::uint32_t load_base{};
    std::uint32_t start_function{};
    std::uint32_t stop_function{};
    std::uint32_t gp{};
    std::string name;
    bool started{};
};

std::map<std::uint32_t, LoadedPrxModule> loaded_prx_modules;

std::uint32_t load_decrypted_prx(Runtime &rt, std::span<const std::uint8_t> image,
                                 const std::string &source, std::string &reason) {
    if (image.size() < 4u || image[0] != 0x7Fu || image[1] != 'E' ||
        image[2] != 'L' || image[3] != 'F') {
        reason = "decrypted-payload-is-not-elf";
        return 0u;
    }

    std::int32_t block_uid = 0;
    try {
        auto elf = psprecomp::Elf32Image::from_bytes(
            std::vector<std::uint8_t>(image.begin(), image.end()), source);
        if (!elf.is_psp_prx()) {
            reason = "elf-is-not-a-relocatable-psp-prx";
            return 0u;
        }

        std::uint64_t image_end = 0u;
        for (const auto &segment : elf.segments()) {
            if (segment.type != 1u) continue; // PT_LOAD
            if (segment.memory_size < segment.file_size) {
                reason = "pt-load-memsz-smaller-than-filesz";
                return 0u;
            }
            image_end = std::max(image_end,
                static_cast<std::uint64_t>(segment.vaddr) + segment.memory_size);
        }
        if (image_end == 0u || image_end > 64u * 1024u * 1024u) {
            reason = "prx-load-size-out-of-range";
            return 0u;
        }
        const std::uint64_t allocation_size64 = (image_end + 0xFFFu) & ~std::uint64_t(0xFFFu);
        if (allocation_size64 == 0u || allocation_size64 > std::numeric_limits<std::uint32_t>::max()) {
            reason = "prx-allocation-size-overflow";
            return 0u;
        }

        const std::string module_name = source.empty() ? "npdrm-prx" : source.substr(source.find_last_of('/') == std::string::npos ? 0u : source.find_last_of('/') + 1u);
        block_uid = kernel().allocate_block(module_name, 0u,
            static_cast<std::uint32_t>(allocation_size64), 0u);
        const auto *block = kernel().find_block(block_uid);
        if (block == nullptr) {
            reason = "prx-memory-allocation-failed";
            return 0u;
        }
        const std::uint32_t load_base = block->address;
        auto &memory = rt.memory();
        const auto relocations = elf.load_and_relocate(memory, load_base);
        if (relocations.invalid != 0u || relocations.unsupported != 0u) {
            std::cerr << "[npdrm-module] " << module_name
                      << " relocation warnings: invalid=" << relocations.invalid
                      << " unsupported=" << relocations.unsupported << "\n";
        }

        const auto module = elf.find_module_info(memory, load_base);
        if (!module.has_value()) {
            (void)kernel().free_block(block_uid);
            reason = "module-info-not-found";
            return 0u;
        }
        const auto imports = elf.scan_imports(memory, *module);
        for (const auto &import : imports) {
            if (!memory.contains(import.stub_address, 8u)) {
                (void)kernel().free_block(block_uid);
                reason = "import-stub-outside-guest-memory";
                return 0u;
            }
        }

        std::uint32_t module_start = 0u;
        std::uint32_t module_stop = 0u;
        std::uint32_t cursor = module->ent_top;
        std::uint32_t export_count = 0u;
        while (cursor < module->ent_end) {
            if (++export_count > 4096u || !memory.contains(cursor, 16u)) {
                (void)kernel().free_block(block_uid);
                reason = "invalid-export-table";
                return 0u;
            }
            const std::uint32_t entry_name = memory.load32(cursor);
            const std::uint8_t words = memory.load8(cursor + 8u);
            const std::uint8_t old_var_count = memory.load8(cursor + 9u);
            const std::uint16_t function_count = memory.load16(cursor + 10u);
            const std::uint32_t resident = memory.load32(cursor + 12u);
            if (words < 4u) {
                (void)kernel().free_block(block_uid);
                reason = "invalid-export-entry-size";
                return 0u;
            }
            const std::uint32_t entry_bytes = static_cast<std::uint32_t>(words) * 4u;
            if (entry_bytes > module->ent_end - cursor) {
                (void)kernel().free_block(block_uid);
                reason = "export-entry-outside-table";
                return 0u;
            }
            std::uint32_t variable_count = old_var_count;
            if (words > 4u) {
                if (words < 5u) {
                    (void)kernel().free_block(block_uid);
                    reason = "truncated-export-entry";
                    return 0u;
                }
                variable_count = std::max<std::uint32_t>(variable_count, memory.load16(cursor + 16u));
            }
            const std::uint64_t symbol_count = static_cast<std::uint64_t>(function_count) + variable_count;
            const std::uint64_t symbol_bytes = symbol_count * 8u;
            if (symbol_count != 0u && (resident == 0u || symbol_bytes > 1024u * 1024u ||
                !memory.contains(resident, static_cast<std::size_t>(symbol_count * 4u)) ||
                !memory.contains(resident + static_cast<std::uint32_t>(symbol_count * 4u),
                                 static_cast<std::size_t>(symbol_count * 4u)))) {
                (void)kernel().free_block(block_uid);
                reason = "invalid-export-resident-table";
                return 0u;
            }
            if (symbol_count != 0u) {
                const std::uint32_t export_addresses =
                    resident + static_cast<std::uint32_t>(symbol_count * 4u);
                for (std::uint32_t i = 0; i < function_count; ++i) {
                    const std::uint32_t nid = memory.load32(resident + i * 4u);
                    const std::uint32_t address = memory.load32(export_addresses + i * 4u);
                    if (nid == 0xD632ACDBu) module_start = address;
                    else if (nid == 0xCEE8593Cu) module_stop = address;
                }
            }
            (void)entry_name;
            cursor += entry_bytes;
        }
        if (cursor != module->ent_end) {
            (void)kernel().free_block(block_uid);
            reason = "export-table-end-misaligned";
            return 0u;
        }

        for (const auto &import : imports)
            (void)rt.register_import_stub(import.stub_address, import.library, import.nid);

        const std::uint32_t uid = static_cast<std::uint32_t>(kernel().allocate_uid());
        LoadedPrxModule state{};
        state.uid = uid;
        state.memory_block = block_uid;
        state.load_base = load_base;
        state.start_function = module_start;
        state.stop_function = module_stop;
        state.gp = module->gp;
        state.name = module->name.empty() ? module_name : module->name;
        loaded_prx_modules[uid] = state;
        std::cerr << "[npdrm-module] loaded " << state.name
                  << " uid=0x" << std::hex << uid
                  << " base=0x" << load_base
                  << " entry=0x" << elf.runtime_entry(load_base)
                  << " module_start=0x" << module_start
                  << " imports=" << std::dec << imports.size()
                  << " rel2-invalid=" << relocations.invalid
                  << " rel2-unsupported=" << relocations.unsupported << "\n";
        reason = "ok";
        return uid;
    } catch (const std::exception &error) {
        if (block_uid != 0) (void)kernel().free_block(block_uid);
        reason = std::string("elf-loader-exception:") + error.what();
        return 0u;
    }
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
                    if (key_ok) {
                        std::vector<std::uint8_t> decrypted_payload;
                        std::string decrypt_reason;
                        const bool header_valid = npdrm_validate_sprx_header(inner, module_key);
                        std::cerr << " type5_header_sha1="
                                  << (header_valid ? "valid" : "invalid_or_unsupported");
                        if (header_valid) {
                            // Read the full wrapped PRX separately; the small header probe above
                            // intentionally does not allocate according to untrusted file metadata.
                            constexpr std::size_t kMaxPrxProbe = 64u * 1024u * 1024u;
                            if (psp_size < 0x150u || psp_size > kMaxPrxProbe) {
                                std::cerr << " payload_decrypt=failed payload_reason=declared-prx-size-out-of-range";
                            } else {
                                std::vector<std::uint8_t> full_prx(psp_size);
                                const std::int64_t full_count = read_guest_file(
                                    path, payload_offset, full_prx.data(), full_prx.size());
                                if (full_count >= 0x150) {
                                    full_prx.resize(static_cast<std::size_t>(full_count));
                                    const bool decrypted = npdrm_decrypt_type5_payload(
                                        full_prx, module_key, decrypted_payload, decrypt_reason);
                                    std::cerr << " payload_decrypt=" << (decrypted ? "success" : "failed")
                                              << " payload_reason=" << decrypt_reason;
                                    if (decrypted) {
                                        std::cerr << " payload_bytes=" << decrypted_payload.size();
                                        const std::string payload_magic = decrypted_payload.size() >= 4u
                                            ? std::string(reinterpret_cast<const char *>(decrypted_payload.data()), 4u)
                                            : std::string("<short>");
                                        std::cerr << " payload_magic=" << payload_magic;
                                        std::string load_reason;
                                        const std::uint32_t module_uid = load_decrypted_prx(
                                            rt, decrypted_payload, path, load_reason);
                                        if (module_uid != 0u) {
                                            std::cerr << " module_load=success module_uid=0x"
                                                      << std::hex << module_uid << std::dec << "\n";
                                            kernel().finish(ctx, module_uid);
                                            return;
                                        }
                                        std::cerr << " module_load=failed module_reason=" << load_reason;
                                    }
                                } else {
                                    std::cerr << " payload_decrypt=failed payload_reason=prx-read-failed";
                                }
                            }
                        }
                    }
                } else {
                    std::cerr << " inner_prx_header=unavailable_or_invalid";
                }
            } else if (kind == 3u) {
                std::cerr << " payload_kind=PGD-data";
            }
            std::cerr << "\n";
            if (kind == 1u) {
                // Never return a synthetic UID for a PRX that failed decryption or loading.
                kernel().finish(ctx, error::kIllegalArgument);
                return;
            }
        }
        load_stock_module(ctx, header.data(), static_cast<std::size_t>(count), " from " + path);
    };
    hle.add("ModuleMgrForUser", "sceKernelLoadModule", load_module_by_path);
    hle.add("ModuleMgrForUser", "sceKernelLoadModuleNpDrm", load_module_by_path);
    hle.add("ModuleMgrForUser", "sceKernelStartModule", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t uid = arg(ctx, 0);
        auto found = loaded_prx_modules.find(uid);
        if (found == loaded_prx_modules.end()) {
            // Stock Sony modules whose exports are supplied by HLE retain the
            // existing synthetic-module behavior.
            kernel().finish(ctx, uid);
            return;
        }
        LoadedPrxModule &module = found->second;
        if (module.started) {
            kernel().finish(ctx, 0u);
            return;
        }
        if (module.start_function == 0u) {
            module.started = true;
            kernel().finish(ctx, 0u);
            return;
        }
        const std::uint32_t status_address = arg(ctx, 3);
        const portablekit::GuestCallArguments arguments{
            arg(ctx, 1), arg(ctx, 2), 0u, 0u, 0u, 0u, 0u, 0u
        };
        const std::uint32_t entry = module.start_function;
        kernel().call_guest(ctx, entry, arguments,
            [uid, status_address, &memory = rt.memory()](AllegrexContext &return_ctx, std::uint32_t result) {
                auto state = loaded_prx_modules.find(uid);
                if (state != loaded_prx_modules.end()) state->second.started = (result == 0u);
                if (status_address != 0u && memory.contains(status_address, 4u))
                    memory.store32(status_address, result);
                kernel().finish(return_ctx, result);
            }, 2u);
    });
    hle.add("ModuleMgrForUser", "sceKernelStopModule", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t uid = arg(ctx, 0);
        auto found = loaded_prx_modules.find(uid);
        if (found == loaded_prx_modules.end()) {
            kernel().finish(ctx, uid);
            return;
        }
        LoadedPrxModule &module = found->second;
        if (!module.started || module.stop_function == 0u) {
            module.started = false;
            kernel().finish(ctx, 0u);
            return;
        }
        const std::uint32_t status_address = arg(ctx, 3);
        const portablekit::GuestCallArguments arguments{
            arg(ctx, 1), arg(ctx, 2), 0u, 0u, 0u, 0u, 0u, 0u
        };
        kernel().call_guest(ctx, module.stop_function, arguments,
            [uid, status_address, &memory = rt.memory()](AllegrexContext &return_ctx, std::uint32_t result) {
                auto state = loaded_prx_modules.find(uid);
                if (state != loaded_prx_modules.end()) state->second.started = false;
                if (status_address != 0u && memory.contains(status_address, 4u))
                    memory.store32(status_address, result);
                kernel().finish(return_ctx, result);
            }, 2u);
    });
    hle.add("ModuleMgrForUser", "sceKernelUnloadModule", [](Runtime &rt, AllegrexContext &ctx) {
        const std::uint32_t uid = arg(ctx, 0);
        auto found = loaded_prx_modules.find(uid);
        if (found == loaded_prx_modules.end()) {
            kernel().finish(ctx, uid);
            return;
        }
        const LoadedPrxModule module = found->second;
        const auto *block = kernel().find_block(module.memory_block);
        if (block != nullptr) {
            const std::uint32_t begin = block->address;
            const std::uint64_t end = static_cast<std::uint64_t>(begin) + block->size;
            if (end <= 0x100000000ull)
                rt.unregister_functions(begin, static_cast<std::uint32_t>(end));
        }
        (void)kernel().free_block(module.memory_block);
        loaded_prx_modules.erase(found);
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
    // NPDRM licensee-key state, type-5 header validation and KIRK CMD1 payload decryption.
    // Mapping the decrypted ELF, relocations/imports and module_start still needs a loader.
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
