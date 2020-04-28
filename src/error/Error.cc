/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 04    error management */

#include "squid.h"
#include "Debug.h"
#include "error/Error.h"

void
Error::update(const Error &recent)
{
    if (*this)
        debugs(4, 5, "old: " << *this);
    debugs(4, 3, "current: " << recent);
    // checking category and detail separately may cause inconsistency, but
    // may result in more details available if they only become available later
    if (category == ERR_NONE)
        category = recent.category; // may still be ERR_NONE
    if (!detail)
        detail = recent.detail; // may still be nil
}

std::ostream &
operator <<(std::ostream &os, const Error &error)
{
    os << errorTypeName(error.category);
    if (error.detail)
        os << '/' << *error.detail;
    return os;
}
