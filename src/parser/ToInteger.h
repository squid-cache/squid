/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PARSER_TOINTEGER_H
#define SQUID_SRC_PARSER_TOINTEGER_H

#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"

#include <limits>

namespace Parser
{

namespace Detail_
{

/// for simplicity sake, we manipulate all integers using this single large type
using RawInteger = int64_t;

/// parses the entire rawInput as a decimal integer value in the given range
RawInteger DecimalInteger(const char *description, const SBuf &rawInput, RawInteger minValue, RawInteger maxValue);

template <typename Integer>
Integer
DecimalInteger(const char *description, const SBuf &rawInput)
{
    /* make sure our RawInteger can represent caller-requested Integer */

    const auto callerMin = std::numeric_limits<Integer>::min();
    const auto callerMax = std::numeric_limits<Integer>::max();

    const auto rawMin = std::numeric_limits<RawInteger>::min();
    const auto rawMax = std::numeric_limits<RawInteger>::max();

    static_assert(callerMin >= rawMin);
    static_assert(callerMax <= rawMax);

    // with the checks above, casting between RawInteger and Integer is safe (as
    // long as DecimalInteger() implementations obeys passed caller limits)
    return DecimalInteger(description, rawInput, callerMin, callerMax);
}

} // namespace Detail_

/// parses a decimal integer that fits the specified Integer type
template <typename Integer>
Integer
SignedDecimalInteger(const char *description, const SBuf &rawInput)
{
    return Detail_::DecimalInteger<Integer>(description, rawInput);
}

/// parses a decimal non-negative integer that fits the specified Integer type
template <typename Integer>
Integer
UnsignedDecimalInteger(const char *description, const SBuf &rawInput)
{
    const auto result = Detail_::DecimalInteger<Integer>(description, rawInput);
    if (result < 0) {
        throw TextException(ToSBuf("Malformed ", description,
                                   ": Expected a non-negative integer value but got ", rawInput), Here());
    }
    return result;
}

} // namespace Parser

#endif /* SQUID_SRC_PARSER_TOINTEGER_H */

