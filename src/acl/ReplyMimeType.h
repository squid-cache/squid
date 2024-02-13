/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_REPLYMIMETYPE_H
#define SQUID_SRC_ACL_REPLYMIMETYPE_H

#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/ReplyHeaderStrategy.h"

/* partial specialisation */

template <>
inline int
Acl::ReplyHeaderCheck<Http::HdrType::CONTENT_TYPE>::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    char const *theHeader = checklist->reply->header.getStr(Http::HdrType::CONTENT_TYPE);

    if (nullptr == theHeader)
        theHeader = "";

    return data->match(theHeader);
}

#endif /* SQUID_SRC_ACL_REPLYMIMETYPE_H */

