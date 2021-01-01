/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AnyOf.h"

char const *
Acl::AnyOf::typeString() const
{
    return "any-of";
}

ACL *
Acl::AnyOf::clone() const
{
    return new AnyOf;
}

// called once per "acl name any-of name1 name2 ...." line
// but since multiple lines are ORed, the line boundary does not matter,
// so we flatten the tree into one line/level here to minimize overheads
void
Acl::AnyOf::parse()
{
    lineParse();
}

