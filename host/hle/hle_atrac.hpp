#pragma once

#include "psprecomp/guest_memory.hpp"

#include <cstdint>

namespace portablekit::audio {

int atrac_sas_read(psprecomp::GuestMemory &memory, std::uint32_t guest_context,
                   std::int16_t &left, std::int16_t &right);
bool atrac_sas_enqueue(psprecomp::GuestMemory &memory, std::uint32_t guest_context,
                       std::uint32_t address, std::uint32_t size);

} // namespace portablekit::audio
