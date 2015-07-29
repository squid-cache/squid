/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
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
    RegexPattern(int aFlags, const char *aPattern);
    RegexPattern(const RegexPattern &) = delete;
    RegexPattern(RegexPattern &&) = default;
    ~RegexPattern();

    const char * c_str() const {return pattern;}
    bool match(const char *str) const {return regexec(&regex,str,0,NULL,0)==0;}

public:
    int flags;
    regex_t regex;

private:
    char *pattern;
};

#endif /* SQUID_SRC_BASE_REGEXPATTERN_H */

