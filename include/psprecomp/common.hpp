#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace psprecomp {

class Error final : public std::runtime_error {
public:
    explicit Error(const std::string &message) : std::runtime_error(message) {}
};

[[nodiscard]] inline std::string hex32(std::uint32_t value) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string out = "0x00000000";
    for (std::size_t i = 0; i < 8; ++i) {
        out[9u - i] = digits[value & 0xFu];
        value >>= 4u;
    }
    return out;
}

} // namespace psprecomp
