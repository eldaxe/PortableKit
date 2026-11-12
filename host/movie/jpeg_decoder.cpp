#include "movie/jpeg_decoder.hpp"

#include <algorithm>
#include <climits>
#include <cstring>

#if defined(PORTABLEKIT_HAS_FFMPEG)
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/pixdesc.h>
}
#endif

namespace portablekit::movie {

#if defined(PORTABLEKIT_HAS_FFMPEG)
struct JpegDecoder::Impl {
    AVCodecContext *context{};
    AVPacket *packet{};
    AVFrame *frame{};

    ~Impl() {
        avcodec_free_context(&context);
        av_packet_free(&packet);
        av_frame_free(&frame);
    }

    bool open() {
        const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_MJPEG);
        if (!codec) return false;
        context = avcodec_alloc_context3(codec);
        packet = av_packet_alloc();
        frame = av_frame_alloc();
        if (!context || !packet || !frame) return false;
        context->thread_count = 1;
        return avcodec_open2(context, codec, nullptr) >= 0;
    }

    bool take(Picture &out) {
        if (avcodec_receive_frame(context, frame) < 0) return false;
        const auto format = static_cast<AVPixelFormat>(frame->format);
        const AVPixFmtDescriptor *desc = av_pix_fmt_desc_get(format);
        if (!desc || frame->width <= 0 || frame->height <= 0 ||
            !(desc->flags & AV_PIX_FMT_FLAG_PLANAR) || desc->nb_components < 1 ||
            frame->data[0] == nullptr) {
            av_frame_unref(frame);
            return false;
        }
        const bool gray = format == AV_PIX_FMT_GRAY8;
        if (!gray && (desc->nb_components < 3 || frame->data[1] == nullptr || frame->data[2] == nullptr)) {
            av_frame_unref(frame);
            return false;
        }
        out.width = static_cast<std::uint32_t>(frame->width);
        out.height = static_cast<std::uint32_t>(frame->height);
        out.full_range = (desc->flags & AV_PIX_FMT_FLAG_RGB) != 0 ||
                         format == AV_PIX_FMT_YUVJ420P || format == AV_PIX_FMT_YUVJ422P ||
                         format == AV_PIX_FMT_YUVJ444P || frame->color_range == AVCOL_RANGE_JPEG;
        const std::uint32_t cw = (out.width + 1u) / 2u;
        const std::uint32_t ch = (out.height + 1u) / 2u;
        out.y.resize(static_cast<std::size_t>(out.width) * out.height);
        out.cb.resize(static_cast<std::size_t>(cw) * ch);
        out.cr.resize(static_cast<std::size_t>(cw) * ch);
        for (std::uint32_t y = 0; y < out.height; ++y)
            std::memcpy(out.y.data() + static_cast<std::size_t>(y) * out.width,
                        frame->data[0] + static_cast<std::ptrdiff_t>(y) * frame->linesize[0], out.width);
        const unsigned shiftX = desc->log2_chroma_w;
        const unsigned shiftY = desc->log2_chroma_h;
        for (std::uint32_t y = 0; y < ch; ++y) {
            for (std::uint32_t x = 0; x < cw; ++x) {
                const std::uint32_t sx = std::min((x * 2u) >> shiftX,
                                                  (out.width - 1u) >> shiftX);
                const std::uint32_t sy = std::min((y * 2u) >> shiftY,
                                                  (out.height - 1u) >> shiftY);
                const std::size_t at = static_cast<std::size_t>(y) * cw + x;
                if (gray) {
                    out.cb[at] = 128u;
                    out.cr[at] = 128u;
                } else {
                    out.cb[at] = frame->data[1][static_cast<std::ptrdiff_t>(sy) * frame->linesize[1] + sx];
                    out.cr[at] = frame->data[2][static_cast<std::ptrdiff_t>(sy) * frame->linesize[2] + sx];
                }
            }
        }
        av_frame_unref(frame);
        return true;
    }
};

JpegDecoder::JpegDecoder() : impl_(std::make_unique<Impl>()) {}
JpegDecoder::~JpegDecoder() = default;
bool JpegDecoder::available() noexcept { return avcodec_find_decoder(AV_CODEC_ID_MJPEG) != nullptr; }
bool JpegDecoder::decode(std::span<const std::uint8_t> bytes, Picture &picture) {
    if (bytes.size() < 4 || bytes.size() > static_cast<std::size_t>(INT_MAX) ||
        bytes[0] != 0xFFu || bytes[1] != 0xD8u) return false;
    if (!impl_->context && !impl_->open()) return false;
    avcodec_flush_buffers(impl_->context);
    av_packet_unref(impl_->packet);
    if (av_new_packet(impl_->packet, static_cast<int>(bytes.size())) < 0) return false;
    std::memcpy(impl_->packet->data, bytes.data(), bytes.size());
    if (avcodec_send_packet(impl_->context, impl_->packet) < 0) return false;
    return impl_->take(picture);
}
#else
struct JpegDecoder::Impl {};
JpegDecoder::JpegDecoder() : impl_(std::make_unique<Impl>()) {}
JpegDecoder::~JpegDecoder() = default;
bool JpegDecoder::available() noexcept { return false; }
bool JpegDecoder::decode(std::span<const std::uint8_t>, Picture &) { return false; }
#endif

} // namespace portablekit::movie
