/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PARSER_TOINTEGER_H
#define SQUID_PARSER_TOINTEGER_H

#include "sbuf/SBuf.h"
#include "sbuf/Stream.h"

#include <limits>

namespace Parser
{

/// parses the entire rawInput as a decimal integer value fitting the [min..max] range
int64_t DecimalInteger_(const char *description, const SBuf &rawInput, const int64_t min, const int64_t max);
    
template <typename Integer>
static Integer
DecimalInteger_(const char *description, const SBuf &rawInput)
{
    const auto lowerLimit = std::numeric_limits<Integer>::min();
    const auto upperLimit = std::numeric_limits<Integer>::max();

    using ParsedInteger = int64_t;
    const auto parsedMin = std::numeric_limits<ParsedInteger>::min(); 
    const auto parsedMax = std::numeric_limits<ParsedInteger>::max(); 

    static_assert(lowerLimit >= parsedMin);
    static_assert(upperLimit <= parsedMax);

    return DecimalInteger_(description, rawInput, lowerLimit, upperLimit);
}

/// parses a decimal integer that fits the specified Integer type
template <typename Integer>
static Integer
SignedDecimalInteger(const char *description, const SBuf &rawInput) 
{
    return DecimalInteger_<Integer>(description, rawInput);
}

/// parses a decimal non-negative integer that fits the specified Integer type
template <typename Integer>
static Integer
UnsignedDecimalInteger(const char *description, const SBuf &rawInput)
{
    const auto result = DecimalInteger_<Integer>(description, rawInput);
    if (result < 0) {
        throw TextException(ToSBuf("Malformed ", description,
                            ": Expected a non-negative integer value but got ", rawInput), Here());
    }
    return result;
}

} /* namespace Parser */

#endif /* SQUID_PARSER_TOINTEGER_H */

