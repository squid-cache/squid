/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/HierCodeData.h"
#include "cache_cf.h"
#include "hier_code.h"

ACLHierCodeData::ACLHierCodeData()
{
    // initialize mask to NULL
    memset(values, 0, sizeof(values));
}

ACLHierCodeData::ACLHierCodeData(ACLHierCodeData const &old)
{
    memcpy(values, old.values, sizeof(values) );
}

ACLHierCodeData::~ACLHierCodeData()
{ }

bool
ACLHierCodeData::match(hier_code toFind)
{
    return values[toFind];
}

SBufList
ACLHierCodeData::dump() const
{
    SBufList sl;

    for (hier_code iter=HIER_NONE; iter<HIER_MAX; ++iter) {
        if (!values[iter]) continue;
        sl.push_back(SBuf(hier_code_str[iter]));
    }

    return sl;
}

void
ACLHierCodeData::parse()
{
    char *t = NULL;

    while ((t = strtokFile())) {
        for (hier_code iter = HIER_NONE; iter <= HIER_MAX; ++iter) {
            if (iter == HIER_MAX) {
                fatalf("ERROR: No such hier_code '%s'",t);
                return;
            }
            if (strcmp(hier_code_str[iter],t) == 0) {
                values[iter] = true;
                break; // back to while-loop
            }
        }
    }
}

bool
ACLHierCodeData::empty() const
{
    for (hier_code iter = HIER_NONE; iter <= HIER_MAX; ++iter) {
        if (values[iter]) return false; // not empty.
    }
    return true;
}

ACLData<hier_code> *
ACLHierCodeData::clone() const
{
    return new ACLHierCodeData(*this);
}

