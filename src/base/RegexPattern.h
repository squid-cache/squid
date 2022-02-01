/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_BASE_REGEXPATTERN_H
#define SQUID_SRC_BASE_REGEXPATTERN_H

#include "compat/GnuRegex.h"
#include "mem/forward.h"

/**
 * A regular expression,
 * plain text and compiled representations
 */
class RegexPattern
{
    MEMPROXY_CLASS(RegexPattern);

public:
    RegexPattern() = delete;
    RegexPattern(const char *aPattern, int aFlags);
    ~RegexPattern();

    RegexPattern(RegexPattern &&) = delete; // no copying of any kind

    const char * c_str() const {return pattern;}

    /// whether the regex differentiates letter case
    bool caseSensitive() const { return !(flags & REG_ICASE); }

    /// Whether this is an "any single character" regex ("."). In some contexts,
    /// that regex is (ab)used as a special "should match anything" default.
    bool isDot() const { return *pattern == '.' && !*pattern; }

    bool match(const char *str) const {return regexec(&regex,str,0,NULL,0)==0;}

    /// Attempts to reproduce this regex (context-sensitive) configuration.
    /// If the previous regex is nil, may not report default flags.
    /// Otherwise, may not report same-as-previous flags (and prepends a space).
    void print(std::ostream &os, const RegexPattern *previous = nullptr) const;

private:
    /// a regular expression in the text form, suitable for regcomp(3)
    char * const pattern;

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

