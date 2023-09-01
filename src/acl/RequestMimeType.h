/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREQUESTMIMETYPE_H
#define SQUID_ACLREQUESTMIMETYPE_H

#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/RequestHeaderStrategy.h"

/* partial specialisation */

template <>
inline int
Acl::RequestHeaderCheck<Http::HdrType::CONTENT_TYPE>::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    char const *theHeader = checklist->request->header.getStr(Http::HdrType::CONTENT_TYPE);

    if (nullptr == theHeader)
        theHeader = "";

    return data->match(theHeader);
}

#endif /* SQUID_ACLREQUESTMIMETYPE_H */

