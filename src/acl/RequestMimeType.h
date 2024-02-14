/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_REQUESTMIMETYPE_H
#define SQUID_SRC_ACL_REQUESTMIMETYPE_H

#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/RequestHeaderStrategy.h"

/* partial specialisation */

template <>
inline int
ACLRequestHeaderStrategy<Http::HdrType::CONTENT_TYPE>::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist)
{
    char const *theHeader = checklist->request->header.getStr(Http::HdrType::CONTENT_TYPE);

    if (nullptr == theHeader)
        theHeader = "";

    return data->match(theHeader);
}

#endif /* SQUID_SRC_ACL_REQUESTMIMETYPE_H */

