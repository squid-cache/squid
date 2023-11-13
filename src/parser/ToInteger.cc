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

int64_t
Parser::DecimalInteger_(const char *description, const SBuf &rawInput, const int64_t min, const int64_t max)
{
    Parser::Tokenizer tok(rawInput);
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

    int64_t rawInteger = 0;
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

    if (rawInteger > max) {
        throw TextException(ToSBuf("Malformed ", description,
                            ": Expected an integer value not exceeding ", max,
                            " but got ", rawInteger), Here());
    }

    if (rawInteger < min) {
        throw TextException(ToSBuf("Malformed ", description,
                            ": Expected an integer value not below ", min,
                            " but got ", rawInteger), Here());
    }

    return rawInteger;
}

