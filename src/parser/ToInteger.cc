/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "parser/ToInteger.h"
#include "parser/Tokenizer.h"

/// Parser::Detail_::DecimalInteger() helper that disregards value range limits
static Parser::Detail_::RawInteger
ParseDecimalInteger(const char * const description, const SBuf &rawInput)
{
    Parser::Tokenizer tok(rawInput);

    // prohibit leading zeros
    if (tok.skip('0')) {
        if (!tok.atEnd()) {
            // e.g., 077, 0xFF, 0b101, or 0.1
            throw TextException(ToSBuf("Malformed ", description,
                                       ": Expected a decimal integer without leading zeros but got '",
                                       rawInput, "'"), Here());
        }
        return 0;
    }
    // else the value might still be zero (e.g., -0)

    Parser::Detail_::RawInteger rawInteger = 0;
    if (!tok.int64(rawInteger, 10, true)) {
        // e.g., FF
        throw TextException(ToSBuf("Malformed ", description,
                                   ": Expected an int64_t value but got '",
                                   rawInput, "'"), Here());
    }

    if (!tok.atEnd()) {
        // e.g., 1,000, 1.0, or 1e6
        throw TextException(ToSBuf("Malformed ", description,
                                   ": Trailing garbage after ", rawInteger, " in '",
                                   rawInput, "'"), Here());
    }

    return rawInteger;
}

Parser::Detail_::RawInteger
Parser::Detail_::DecimalInteger(const char *description, const SBuf &rawInput, const RawInteger minValue, const RawInteger maxValue)
{
    const auto rawInteger = ParseDecimalInteger(description, rawInput);

    if (rawInteger < minValue) {
        throw TextException(ToSBuf("Malformed ", description,
                                   ": Expected an integer value not below ", minValue,
                                   " but got ", rawInteger), Here());
    }

    if (rawInteger > maxValue) {
        throw TextException(ToSBuf("Malformed ", description,
                                   ": Expected an integer value not exceeding ", maxValue,
                                   " but got ", rawInteger), Here());
    }

    return rawInteger;
}

