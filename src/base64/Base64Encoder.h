/*
 * Copyright (C) 1996-2026 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE64_BASE64ENCODER_H
#define SQUID_SRC_BASE64_BASE64ENCODER_H

#include "base/PackableStream.h"
#include "base64.h"
#include "mem/forward.h"
#include "sbuf/SBuf.h"

#include <ostream>
#include <limits>

/** Stream interface to write to a Base64-encoded SBuf.
 *
 * Data is appended using standard operator << semantics. The data is
 * base64-encoded on the fly as it is written. The encoded result can be
 * retrieved using the buf() method.
 *
 * This class inherits from std::ostream to provide a familiar streaming
 * interface, similar to SBufStream.
 */
class Base64Encoder : public std::ostream
{
public:
    /// Special value indicating no size limit
    static constexpr size_t noLimit = std::numeric_limits<size_t>::max();

    /// Create a Base64Encoder with optional maximum encoded output size limit
    /// \param maxEncodedSize maximum encoded output size (default: noLimit)
    explicit Base64Encoder(size_t maxEncodedSize = noLimit);

    /// Create a Base64Encoder and immediately encode the contents of a SBuf
    /// \param input SBuf to encode immediately
    /// \param maxEncodedSize maximum encoded output size (default: noLimit)
    explicit Base64Encoder(const SBuf &input, size_t maxEncodedSize = noLimit);

    /// Destructor finalizes the encoding
    ~Base64Encoder() override;

    /// Non-copyable (std::ostream is non-copyable)
    Base64Encoder(const Base64Encoder&) = delete;
    Base64Encoder& operator=(const Base64Encoder&) = delete;

    /// Non-movable (std::ostream is non-movable)
    Base64Encoder(Base64Encoder&&) = delete;
    Base64Encoder& operator=(Base64Encoder&&) = delete;

    /// Get the encoded result (finalizes encoding if not already done)
    SBuf buf();

    /// Clear the stream's backing store and reset encoder state
    Base64Encoder& clearBuf();

    /// Stream output operator for printing the encoded contents (finalizes encoding)
    friend std::ostream& operator<<(std::ostream& os, Base64Encoder& encoder);

private:
    /** Custom streambuf that buffers input data and delegates encoding to Base64Encoder.
     *
     * Only manages the input buffer. All encoding logic, size checking,
     * and state management lives in Base64Encoder.
     */
    class Base64StreamBuf : public std::streambuf
    {
    public:
        Base64StreamBuf(Base64Encoder &encoder);
        ~Base64StreamBuf() override;

    protected:
        int_type overflow(int_type ch = traits_type::eof()) override;
        int sync() override;
        std::streamsize xsputn(const char *s, std::streamsize n) override;

    private:
        Base64Encoder &encoder_;
        char *inputBuffer_ = nullptr;
        size_t inputBufferPos_ = 0;

        // Base64Encoder needs access to these
        friend class Base64Encoder;
    };

    // Encoding state (moved from Base64StreamBuf)
    const size_t maxEncodedSize_ = noLimit;
    SBuf sink_;
    base64_encode_ctx ctx_;
    bool finalized_ = false;

    // Encoding implementation (moved from Base64StreamBuf)
    void checkSizeLimit(size_t newInputBytes);
    void encodePending();
    void finalize();

    Base64StreamBuf streamBuffer_;
};

/// Helper to encode multiple arguments and return the Base64-encoded result
/// Usage: SBuf result = ToBase64(arg1, arg2, ...);
template <typename... Args>
inline
SBuf ToBase64(Args&&... args)
{
    Base64Encoder encoder;
    (encoder << ... << args);
    return encoder.buf();
}

#endif /* SQUID_SRC_BASE64_BASE64ENCODER_H */
