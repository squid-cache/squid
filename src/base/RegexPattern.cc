/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/RegexPattern.h"
#include "base/TextException.h"
#include "debug/Stream.h"
#include "sbuf/Stream.h"

#include <iostream>
#include <utility>

RegexPattern::RegexPattern(const SBuf &aPattern, const int aFlags):
    pattern(aPattern),
    flags(aFlags)
{
    memset(&regex, 0, sizeof(regex)); // paranoid; POSIX does not require this
    if (const auto errCode = regcomp(&regex, pattern.c_str(), flags)) {
        char errBuf[256];
        // for simplicity, ignore any error message truncation
        (void)regerror(errCode, &regex, errBuf, sizeof(errBuf));
        // POSIX examples show no regfree(&regex) after a regcomp() error;
        // presumably, regcom() frees any allocated memory on failures
        throw TextException(ToSBuf("POSIX regcomp(3) failure: (", errCode, ") ", errBuf,
                                   Debug::Extra, "regular expression: ", pattern), Here());
    }

    debugs(28, 2, *this);
}

RegexPattern::~RegexPattern()
{
    regfree(&regex);
}

void
RegexPattern::print(std::ostream &os, const RegexPattern * const previous) const
{
    // report context-dependent explicit options and delimiters
    if (!previous) {
        // do not report default settings
        if (!caseSensitive())
            os << "-i ";
    } else {
        os << ' '; // separate us from the previous value

        // do not report same-as-previous (i.e. inherited) settings
        if (previous->flags != flags)
            os << (caseSensitive() ? "+i " : "-i ");
    }

    os << pattern;
}

