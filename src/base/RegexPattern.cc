/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/RegexPattern.h"

RegexPattern::~RegexPattern()
{
    xfree(pattern);
    regfree(&regex);
}

RegexList::~RegexList()
{
    // lists could be very long
    // iterate instead of recursing
    for (auto p = next; p; p = next) {
        next = p->next;
        p->next = nullptr;
        delete p;
    }
}

