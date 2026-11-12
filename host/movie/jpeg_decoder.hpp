#pragma once

#include "movie/avc_decoder.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace portablekit::movie {

class JpegDecoder {
public:
    JpegDecoder();
    ~JpegDecoder();
    JpegDecoder(const JpegDecoder &) = delete;
    JpegDecoder &operator=(const JpegDecoder &) = delete;

    [[nodiscard]] static bool available() noexcept;
    bool decode(std::span<const std::uint8_t> bytes, Picture &picture);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace portablekit::movie
