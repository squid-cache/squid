/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 55    HTTP Header */

#include "squid.h"
#include "base/CharacterSet.h"
#include "Debug.h"
#include "http/ContentLengthInterpreter.h"
#include "http/one/Parser.h"
#include "HttpHeaderTools.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "StrList.h"

Http::ContentLengthInterpreter::ContentLengthInterpreter():
    value(-1),
    headerWideProblem(nullptr),
    debugLevel(Config.onoff.relaxed_header_parser <= 0 ? DBG_IMPORTANT : 2),
    sawBad(false),
    needsSanitizing(false),
    sawGood(false),
    prohibitedAndIgnored_(nullptr)
{
}

/// checks whether all characters before the Content-Length number are allowed
/// \returns the start of the digit sequence (or nil on errors)
const char *
Http::ContentLengthInterpreter::findDigits(const char *prefix, const char * const valueEnd) const
{
    // skip leading OWS in RFC 7230's `OWS field-value OWS`
    const CharacterSet &whitespace = Http::One::Parser::WhitespaceCharacters();
    while (prefix < valueEnd) {
        const auto ch = *prefix;
        if (CharacterSet::DIGIT[ch])
            return prefix; // common case: a pre-trimmed field value
        if (!whitespace[ch])
            return nullptr; // (trimmed) length does not start with a digit
        ++prefix;
    }
    return nullptr; // empty or whitespace-only value
}

/// checks whether all characters after the Content-Length are allowed
bool
Http::ContentLengthInterpreter::goodSuffix(const char *suffix, const char * const end) const
{
    // optimize for the common case that does not need delimiters
    if (suffix == end)
        return true;

    for (const CharacterSet &delimiters = Http::One::Parser::DelimiterCharacters();
            suffix < end; ++suffix) {
        if (!delimiters[*suffix])
            return false;
    }
    // needsSanitizing = true; // TODO: Always remove trailing whitespace?
    return true; // including empty suffix
}

/// handles a single-token Content-Length value
/// rawValue null-termination requirements are those of httpHeaderParseOffset()
bool
Http::ContentLengthInterpreter::checkValue(const char *rawValue, const int valueSize)
{
    Must(!sawBad);

    const auto valueEnd = rawValue + valueSize;

    const auto digits = findDigits(rawValue, valueEnd);
    if (!digits) {
        debugs(55, debugLevel, "WARNING: Leading garbage or empty value in" << Raw("Content-Length", rawValue, valueSize));
        sawBad = true;
        return false;
    }

    int64_t latestValue = -1;
    char *suffix = nullptr;

    if (!httpHeaderParseOffset(digits, &latestValue, &suffix)) {
        debugs(55, DBG_IMPORTANT, "WARNING: Malformed" << Raw("Content-Length", rawValue, valueSize));
        sawBad = true;
        return false;
    }

    if (latestValue < 0) {
        debugs(55, debugLevel, "WARNING: Negative" << Raw("Content-Length", rawValue, valueSize));
        sawBad = true;
        return false;
    }

    // check for garbage after the number
    if (!goodSuffix(suffix, valueEnd)) {
        debugs(55, debugLevel, "WARNING: Trailing garbage in" << Raw("Content-Length", rawValue, valueSize));
        sawBad = true;
        return false;
    }

    if (sawGood) {
        /* we have found at least two, possibly identical values */

        needsSanitizing = true; // replace identical values with a single value

        const bool conflicting = value != latestValue;
        if (conflicting)
            headerWideProblem = "Conflicting"; // overwrite any lesser problem
        else if (!headerWideProblem) // preserve a possibly worse problem
            headerWideProblem = "Duplicate";

        // with relaxed_header_parser, identical values are permitted
        sawBad = !Config.onoff.relaxed_header_parser || conflicting;
        return false; // conflicting or duplicate
    }

    sawGood = true;
    value = latestValue;
    return true;
}

/// handles Content-Length: a, b, c
bool
Http::ContentLengthInterpreter::checkList(const String &list)
{
    Must(!sawBad);

    if (!Config.onoff.relaxed_header_parser) {
        debugs(55, debugLevel, "WARNING: List-like" << Raw("Content-Length", list.rawBuf(), list.size()));
        sawBad = true;
        return false;
    }

    needsSanitizing = true; // remove extra commas (at least)

    const char *pos = nullptr;
    const char *item = nullptr;;
    int ilen = -1;
    while (strListGetItem(&list, ',', &item, &ilen, &pos)) {
        if (!checkValue(item, ilen) && sawBad)
            break;
        // keep going after a duplicate value to find conflicting ones
    }
    return false; // no need to keep this list field; it will be sanitized away
}

bool
Http::ContentLengthInterpreter::checkField(const String &rawValue)
{
    if (sawBad)
        return false; // one rotten apple is enough to spoil all of them

    // TODO: Optimize by always parsing the first integer first.
    return rawValue.pos(',') ?
           checkList(rawValue) :
           checkValue(rawValue.rawBuf(), rawValue.size());
}

