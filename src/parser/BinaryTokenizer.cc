/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 24    SBuf */

#include "squid.h"
#include "parser/BinaryTokenizer.h"

Parser::BinaryTokenizer::BinaryTokenizer(): BinaryTokenizer(SBuf())
{
}

Parser::BinaryTokenizer::BinaryTokenizer(const SBuf &data, const bool expectMore):
    context(nullptr),
    data_(data),
    parsed_(0),
    syncPoint_(0),
    expectMore_(expectMore)
{
}

static inline
std::ostream &
operator <<(std::ostream &os, const Parser::BinaryTokenizerContext *context)
{
    if (context)
        os << context->parent << context->name;
    return os;
}

/// debugging helper that prints a "standard" debugs() trailer
#define BinaryTokenizer_tail(size, start) \
    " occupying " << (size) << " bytes @" << (start) << " in " << this << \
    (expectMore_ ? ';' : '.');

/// logs and throws if fewer than size octets remain; no other side effects
void
Parser::BinaryTokenizer::want(uint64_t size, const char *description) const
{
    if (parsed_ + size > data_.length()) {
        debugs(24, 5, (parsed_ + size - data_.length()) << " more bytes for " <<
               context << description << BinaryTokenizer_tail(size, parsed_));
        Must(expectMore_); // throw an error on premature input termination
        throw InsufficientInput();
    }
}

void
Parser::BinaryTokenizer::got(uint64_t size, const char *description) const
{
    debugs(24, 7, context << description <<
           BinaryTokenizer_tail(size, parsed_ - size));
}

/// debugging helper for parsed number fields
void
Parser::BinaryTokenizer::got(uint32_t value, uint64_t size, const char *description) const
{
    debugs(24, 7, context << description << '=' << value <<
           BinaryTokenizer_tail(size, parsed_ - size));
}

/// debugging helper for parsed areas/blobs
void
Parser::BinaryTokenizer::got(const SBuf &value, uint64_t size, const char *description) const
{
    debugs(24, 7, context << description << '=' <<
           Raw(nullptr, value.rawContent(), value.length()).hex() <<
           BinaryTokenizer_tail(size, parsed_ - size));

}

/// debugging helper for skipped fields
void
Parser::BinaryTokenizer::skipped(uint64_t size, const char *description) const
{
    debugs(24, 7, context << description << BinaryTokenizer_tail(size, parsed_ - size));

}

/// Returns the next ready-for-shift byte, adjusting the number of parsed bytes.
/// The larger 32-bit return type helps callers shift/merge octets into numbers.
/// This internal method does not perform out-of-bounds checks.
uint32_t
Parser::BinaryTokenizer::octet()
{
    // While char may be signed, we view data characters as unsigned,
    // which helps to arrive at the right 32-bit return value.
    return static_cast<uint8_t>(data_[parsed_++]);
}

void
Parser::BinaryTokenizer::reset(const SBuf &data, const bool expectMore)
{
    *this = BinaryTokenizer(data, expectMore);
}

void
Parser::BinaryTokenizer::rollback()
{
    parsed_ = syncPoint_;
}

void
Parser::BinaryTokenizer::commit()
{
    syncPoint_ = parsed_;
}

bool
Parser::BinaryTokenizer::atEnd() const
{
    return parsed_ >= data_.length();
}

uint8_t
Parser::BinaryTokenizer::uint8(const char *description)
{
    want(1, description);
    const uint8_t result = octet();
    got(result, 1, description);
    return result;
}

uint16_t
Parser::BinaryTokenizer::uint16(const char *description)
{
    want(2, description);
    const uint16_t result = (octet() << 8) | octet();
    got(result, 2, description);
    return result;
}

uint32_t
Parser::BinaryTokenizer::uint24(const char *description)
{
    want(3, description);
    const uint32_t result = (octet() << 16) | (octet() << 8) | octet();
    got(result, 3, description);
    return result;
}

uint32_t
Parser::BinaryTokenizer::uint32(const char *description)
{
    want(4, description);
    const uint32_t result = (octet() << 24) | (octet() << 16) | (octet() << 8) | octet();
    got(result, 4, description);
    return result;
}

SBuf
Parser::BinaryTokenizer::area(uint64_t size, const char *description)
{
    want(size, description);
    const SBuf result = data_.substr(parsed_, size);
    parsed_ += size;
    got(result, size, description);
    return result;
}

void
Parser::BinaryTokenizer::skip(uint64_t size, const char *description)
{
    want(size, description);
    parsed_ += size;
    skipped(size, description);
}

/*
 * BinaryTokenizer::pstringN() implementations below reduce debugging noise by
 * not parsing empty areas and not summarizing parsing context.success().
 */

SBuf
Parser::BinaryTokenizer::pstring8(const char *description)
{
    BinaryTokenizerContext pstring(*this, description);
    if (const uint8_t length = uint8(".length"))
        return area(length, ".octets");
    return SBuf();
}

SBuf
Parser::BinaryTokenizer::pstring16(const char *description)
{
    BinaryTokenizerContext pstring(*this, description);
    if (const uint16_t length = uint16(".length"))
        return area(length, ".octets");
    return SBuf();
}

SBuf
Parser::BinaryTokenizer::pstring24(const char *description)
{
    BinaryTokenizerContext pstring(*this, description);
    if (const uint32_t length = uint24(".length"))
        return area(length, ".octets");
    return SBuf();
}

