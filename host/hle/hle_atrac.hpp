#pragma once

#include "psprecomp/guest_memory.hpp"

#include <cstdint>

namespace portablekit::audio {

// Return 1 for one stereo sample, 0 at end of stream, -1 when a streamed
// context needs more data. The context address is returned by
// _sceAtracGetContextAddress.
int atrac_sas_read(psprecomp::GuestMemory &memory, std::uint32_t guest_context,
                   std::int16_t &left, std::int16_t &right);

// Append data supplied by __sceSasConcatenateATRAC3 to a streamed context.
bool atrac_sas_enqueue(psprecomp::GuestMemory &memory, std::uint32_t guest_context,
                       std::uint32_t address, std::uint32_t size);

} // namespace portablekit::audio
