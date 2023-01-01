/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_REGEXPATTERN_H
#define SQUID_SRC_BASE_REGEXPATTERN_H

#include "mem/forward.h"
#include "sbuf/SBuf.h"

#if HAVE_REGEX_H
#include <regex.h>
#endif

/**
 * A regular expression,
 * plain text and compiled representations
 */
class RegexPattern
{
    MEMPROXY_CLASS(RegexPattern);

public:
    RegexPattern() = delete;
    RegexPattern(const SBuf &aPattern, int aFlags);
    ~RegexPattern();

    RegexPattern(RegexPattern &&) = delete; // no copying of any kind

    /// whether the regex differentiates letter case
    bool caseSensitive() const { return !(flags & REG_ICASE); }

    /// whether this is an "any single character" regex (".")
    bool isDot() const { return pattern.length() == 1 && pattern[0] == '.'; }

    bool match(const char *str) const {return regexec(&regex,str,0,nullptr,0)==0;}

    /// Attempts to reproduce this regex (context-sensitive) configuration.
    /// If the previous regex is nil, may not report default flags.
    /// Otherwise, may not report same-as-previous flags (and prepends a space).
    void print(std::ostream &os, const RegexPattern *previous = nullptr) const;

private:
    /// a regular expression in the text form, suitable for regcomp(3)
    SBuf pattern;

    /// bitmask of REG_* flags for regcomp(3)
    const int flags;

    /// a "compiled pattern buffer" filled by regcomp(3) for regexec(3)
    regex_t regex;
};

inline std::ostream &
operator <<(std::ostream &os, const RegexPattern &rp)
{
    rp.print(os);
    return os;
}

#endif /* SQUID_SRC_BASE_REGEXPATTERN_H */

