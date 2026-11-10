#include "psprecomp/elf32.hpp"
#include "psprecomp/guest_memory.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const char *message) {
    if (!condition) throw std::runtime_error(message);
}

void put16(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::uint8_t>(value);
    bytes.at(offset + 1u) = static_cast<std::uint8_t>(value >> 8u);
}

void put32(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned i = 0; i < 4u; ++i)
        bytes.at(offset + i) = static_cast<std::uint8_t>(value >> (i * 8u));
}

std::vector<std::uint8_t> make_rel1_prx() {
    // Three program headers: two loadable segments and one PT_PSPREL1 table.
    // There are deliberately no section headers: this covers stripped PRXs.
    std::vector<std::uint8_t> bytes(0x160u, 0u);
    bytes[0] = 0x7Fu; bytes[1] = 'E'; bytes[2] = 'L'; bytes[3] = 'F';
    bytes[4] = 1u; bytes[5] = 1u; bytes[6] = 1u;
    put16(bytes, 16u, psprecomp::kElfTypePspPrx);
    put16(bytes, 18u, 8u);
    put32(bytes, 20u, 1u);
    put32(bytes, 28u, 52u);
    put16(bytes, 40u, 52u);
    put16(bytes, 42u, 32u);
    put16(bytes, 44u, 3u);
    put16(bytes, 46u, 40u);

    const auto ph = [&](std::size_t index, std::uint32_t type, std::uint32_t offset,
                        std::uint32_t vaddr, std::uint32_t filesz, std::uint32_t memsz) {
        const std::size_t at = 52u + index * 32u;
        put32(bytes, at, type);
        put32(bytes, at + 4u, offset);
        put32(bytes, at + 8u, vaddr);
        put32(bytes, at + 12u, vaddr);
        put32(bytes, at + 16u, filesz);
        put32(bytes, at + 20u, memsz);
        put32(bytes, at + 24u, 5u);
        put32(bytes, at + 28u, 4u);
    };

    ph(0u, 1u, 0x100u, 0x0000u, 16u, 16u);
    ph(1u, 1u, 0x120u, 0x1000u, 4u, 4u);
    ph(2u, 0x700000A0u, 0x140u, 0u, 32u, 32u);

    put32(bytes, 0x100u, 0x00000020u); // R_MIPS_32
    put32(bytes, 0x104u, 0x0C000000u); // R_MIPS_26 (JAL)
    put32(bytes, 0x108u, 0x3C020000u); // R_MIPS_HI16
    put32(bytes, 0x10Cu, 0x24421234u); // R_MIPS_LO16

    // Rel32.info: type in bits 0..3, patch segment in 8..15,
    // target segment in 16..23.
    const std::uint32_t offsets[4] = {0u, 4u, 8u, 12u};
    const std::uint32_t types[4] = {2u, 4u, 5u, 6u};
    for (std::uint32_t i = 0u; i < 4u; ++i) {
        put32(bytes, 0x140u + i * 8u, offsets[i]);
        put32(bytes, 0x144u + i * 8u, (1u << 16u) | types[i]);
    }
    return bytes;
}

void test_pt_psprel1_without_sections() {
    const auto image = psprecomp::Elf32Image::from_bytes(make_rel1_prx(), "synthetic_pt_psprel1.prx");
    require(image.sections().empty(), "REL1 fixture unexpectedly contains section headers");

    psprecomp::GuestMemory memory;
    const auto stats = image.load_and_relocate(memory, 0x08804000u);
    require(stats.total == 4u && stats.invalid == 0u && stats.unsupported == 0u,
            "PT_PSPREL1 relocation statistics are incorrect");
    require(stats.r_mips_32 == 1u && stats.r_mips_26 == 1u &&
                stats.r_mips_hi16 == 1u && stats.r_mips_lo16 == 1u,
            "PT_PSPREL1 did not apply all expected relocation types");
    require(memory.load32(0x08804000u) == 0x08805020u, "PT_PSPREL1 R_MIPS_32 failed");
    require(memory.load32(0x08804004u) == 0x0E201400u, "PT_PSPREL1 R_MIPS_26 failed");
    require(memory.load32(0x08804008u) == 0x3C020881u, "PT_PSPREL1 R_MIPS_HI16 failed");
    require(memory.load32(0x0880400Cu) == 0x24426234u, "PT_PSPREL1 R_MIPS_LO16 failed");
}

} // namespace

int main() {
    try {
        test_pt_psprel1_without_sections();
        std::cout << "PortableKit ELF relocation regression tests passed.\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "ELF relocation regression test failed: " << error.what() << '\n';
        return 1;
    }
}
