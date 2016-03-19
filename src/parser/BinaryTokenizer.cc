/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 24    SBuf */

#include "squid.h"
#include "BinaryTokenizer.h"

BinaryTokenizer::BinaryTokenizer(): BinaryTokenizer(SBuf())
{
}

BinaryTokenizer::BinaryTokenizer(const SBuf &data):
    context(""),
    data_(data),
    parsed_(0),
    syncPoint_(0)
{
}

/// debugging helper that prints a "standard" debugs() trailer
#define BinaryTokenizer_tail(size, start) \
    " occupying " << (size) << " bytes @" << (start) << " in " << this;

/// logs and throws if fewer than size octets remain; no other side effects
void
BinaryTokenizer::want(uint64_t size, const char *description) const
{
    if (parsed_ + size > data_.length()) {
        debugs(24, 5, (parsed_ + size - data_.length()) << " more bytes for " <<
               context << description << BinaryTokenizer_tail(size, parsed_));
        throw InsufficientInput();
    }
}

/// debugging helper for parsed number fields
void
BinaryTokenizer::got(uint32_t value, uint64_t size, const char *description) const
{
    debugs(24, 7, context << description << '=' << value <<
           BinaryTokenizer_tail(size, parsed_ - size));
}

/// debugging helper for parsed areas/blobs
void
BinaryTokenizer::got(const SBuf &value, uint64_t size, const char *description) const
{
    debugs(24, 7, context << description << '=' <<
           Raw(nullptr, value.rawContent(), value.length()).hex() <<
           BinaryTokenizer_tail(size, parsed_ - size));

}

/// debugging helper for skipped fields
void
BinaryTokenizer::skipped(uint64_t size, const char *description) const
{
    debugs(24, 7, context << description << BinaryTokenizer_tail(size, parsed_ - size));

}

/// Returns the next ready-for-shift byte, adjusting the number of parsed bytes.
/// The larger 32-bit return type helps callers shift/merge octets into numbers.
/// This internal method does not perform out-of-bounds checks.
uint32_t
BinaryTokenizer::octet()
{
    // While char may be signed, we view data characters as unsigned,
    // which helps to arrive at the right 32-bit return value.
    return static_cast<uint8_t>(data_[parsed_++]);
}

void
BinaryTokenizer::reset(const SBuf &data)
{
    *this = BinaryTokenizer(data);
}

void
BinaryTokenizer::rollback()
{
    parsed_ = syncPoint_;
}

void
BinaryTokenizer::commit()
{
    if (context && *context)
        debugs(24, 6, context << BinaryTokenizer_tail(parsed_ - syncPoint_, syncPoint_));
    syncPoint_ = parsed_;
}

bool
BinaryTokenizer::atEnd() const
{
    return parsed_ >= data_.length();
}

uint8_t
BinaryTokenizer::uint8(const char *description)
{
    want(1, description);
    const uint8_t result = octet();
    got(result, 1, description);
    return result;
}

uint16_t
BinaryTokenizer::uint16(const char *description)
{
    want(2, description);
    const uint16_t result = (octet() << 8) | octet();
    got(result, 2, description);
    return result;
}

uint32_t
BinaryTokenizer::uint24(const char *description)
{
    want(3, description);
    const uint32_t result = (octet() << 16) | (octet() << 8) | octet();
    got(result, 3, description);
    return result;
}

uint32_t
BinaryTokenizer::uint32(const char *description)
{
    want(4, description);
    const uint32_t result = (octet() << 24) | (octet() << 16) | (octet() << 8) | octet();
    got(result, 4, description);
    return result;
}

SBuf
BinaryTokenizer::area(uint64_t size, const char *description)
{
    want(size, description);
    const SBuf result = data_.substr(parsed_, size);
    parsed_ += size;
    got(result, size, description);
    return result;
}

void
BinaryTokenizer::skip(uint64_t size, const char *description)
{
    want(size, description);
    parsed_ += size;
    skipped(size, description);
}

