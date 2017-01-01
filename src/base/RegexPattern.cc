/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/RegexPattern.h"
#include <utility>

RegexPattern::RegexPattern(int aFlags, const char *aPattern) :
    flags(aFlags),
    pattern(xstrdup(aPattern))
{
    memset(&regex, 0, sizeof(regex));
}

RegexPattern::RegexPattern(RegexPattern &&o) :
    flags(std::move(o.flags)),
    regex(std::move(o.regex)),
    pattern(std::move(o.pattern))
{
    memset(&o.regex, 0, sizeof(o.regex));
    o.pattern = nullptr;
}

RegexPattern::~RegexPattern()
{
    xfree(pattern);
    regfree(&regex);
}

RegexPattern &
RegexPattern::operator =(RegexPattern &&o)
{
    flags = std::move(o.flags);
    regex = std::move(o.regex);
    memset(&o.regex, 0, sizeof(o.regex));
    pattern = std::move(o.pattern);
    o.pattern = nullptr;
    return *this;
}

