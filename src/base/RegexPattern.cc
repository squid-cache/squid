/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/RegexPattern.h"

RegexPattern::RegexPattern(int aFlags, const char *aPattern) :
        flags(aFlags),
        pattern(xstrdup(aPattern))
{
    memset(&regex, 0, sizeof(regex));
}

RegexPattern::~RegexPattern()
{
    xfree(pattern);
    regfree(&regex);
}
