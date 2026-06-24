/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "base64/Base64Encoder.h"

Base64Encoder::Base64Encoder(size_t maxEncodedSize)
    : std::ostream(nullptr),
      maxEncodedSize_(maxEncodedSize),
      streamBuffer_(*this)
{
    base64_encode_init(&ctx_);
    rdbuf(&streamBuffer_);
    clear();
}

Base64Encoder::Base64Encoder(const SBuf &input, size_t maxEncodedSize)
    : Base64Encoder(maxEncodedSize)
{
    // Encode the input immediately - will throw if too large
    *this << input;
}

Base64Encoder::~Base64Encoder()
{
    // Ensure encoding is finalized; log but don't propagate exceptions to avoid terminate during unwinding
    try {
        streamBuffer_.pubsync();
    } catch (const std::exception &e) {
        debugs(0, DBG_CRITICAL, "Base64Encoder dtor error: " << e.what());
    } catch (...) {
        debugs(0, DBG_CRITICAL, "Base64Encoder dtor unknown error");
    }
}

SBuf
Base64Encoder::buf()
{
    flush();
    return sink_;
}

Base64Encoder&
Base64Encoder::clearBuf()
{
    flush();
    sink_.clear();
    base64_encode_init(&ctx_);
    finalized_ = false;
    clear(); // Clear stream error state (badbit, failbit, etc.)
    return *this;
}

std::ostream&
operator<<(std::ostream& os, Base64Encoder& encoder)
{
    encoder.flush();
    return encoder.sink_.print(os);
}

// --- Base64Encoder encoding implementation ---

void
Base64Encoder::checkSizeLimit(size_t newInputBytes)
{
    // Since we sync after every append, sink_.length() is always up to date
    // The additional encoded size for newInputBytes raw bytes is BASE64_ENCODE_RAW_LENGTH
    const size_t additionalEncoded = BASE64_ENCODE_RAW_LENGTH(newInputBytes);
    if (sink_.length() + additionalEncoded > maxEncodedSize_)
        throw TextException("Base64Encoder output size limit exceeded", Here());
}

void
Base64Encoder::encodePending()
{
    if (streamBuffer_.inputBufferPos_ == 0)
        return;

    checkSizeLimit(0); // No additional new input, just check pending

    const size_t maxEncoded = BASE64_ENCODE_LENGTH(streamBuffer_.inputBufferPos_) + BASE64_ENCODE_FINAL_LENGTH;
    sink_.reserveSpace(maxEncoded);
    char *dst = sink_.rawAppendStart(maxEncoded);
    size_t encoded = base64_encode_update(&ctx_, dst, streamBuffer_.inputBufferPos_,
                                          reinterpret_cast<const uint8_t*>(streamBuffer_.inputBuffer_));
    sink_.rawAppendFinish(dst, encoded);
    streamBuffer_.inputBufferPos_ = 0;
    streamBuffer_.setp(streamBuffer_.inputBuffer_, streamBuffer_.inputBuffer_ + 4096);
}

void
Base64Encoder::finalize()
{
    if (finalized_)
        return;

    encodePending();

    const size_t maxFinal = BASE64_ENCODE_FINAL_LENGTH;
    sink_.reserveSpace(maxFinal);
    char *dst = sink_.rawAppendStart(maxFinal);
    size_t encoded = base64_encode_final(&ctx_, dst);
    sink_.rawAppendFinish(dst, encoded);

    finalized_ = true;
}

// --- Base64StreamBuf implementation ---

Base64Encoder::Base64StreamBuf::Base64StreamBuf(Base64Encoder &encoder)
    : encoder_(encoder)
{
    inputBuffer_ = static_cast<char*>(memAllocate(MEM_4K_BUF));
    setp(inputBuffer_, inputBuffer_ + 4096);
}

Base64Encoder::Base64StreamBuf::~Base64StreamBuf()
{
    memFree(inputBuffer_, MEM_4K_BUF);
    inputBuffer_ = nullptr;

    if (!encoder_.finalized_) {
        try {
            encoder_.finalize();
        } catch (const std::exception &e) {
            debugs(0, DBG_CRITICAL, "Base64StreamBuf dtor error: " << e.what());
        } catch (...) {
            debugs(0, DBG_CRITICAL, "Base64StreamBuf dtor unknown error");
        }
    }
}

int
Base64Encoder::Base64StreamBuf::overflow(int_type ch)
{
    if (ch != traits_type::eof()) {
        encoder_.checkSizeLimit(1);
        inputBuffer_[inputBufferPos_++] = static_cast<char>(ch);
        if (inputBufferPos_ >= 4096)
            encoder_.encodePending();
    }
    encoder_.encodePending(); // Sync after every append
    return ch;
}

int
Base64Encoder::Base64StreamBuf::sync()
{
    encoder_.encodePending();
    encoder_.finalize();
    return 0;
}

std::streamsize
Base64Encoder::Base64StreamBuf::xsputn(const char *s, std::streamsize n)
{
    std::streamsize written = 0;

    while (n > 0) {
        const size_t space = 4096 - inputBufferPos_;
        const size_t toCopy = std::min<size_t>(static_cast<size_t>(n), space);

        encoder_.checkSizeLimit(toCopy);

        std::memcpy(inputBuffer_ + inputBufferPos_, s, toCopy);
        inputBufferPos_ += toCopy;
        s += toCopy;
        n -= toCopy;
        written += toCopy;

        if (inputBufferPos_ >= 4096)
            encoder_.encodePending();
    }

    encoder_.encodePending(); // Sync after every append
    return written;
}