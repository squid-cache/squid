/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREPLYMIMETYPE_H
#define SQUID_ACLREPLYMIMETYPE_H

#include "acl/Data.h"
#include "acl/FilledChecklist.h"
#include "acl/ReplyHeaderStrategy.h"

/* partial specialisation */

template <>
inline int
ACLReplyHeaderStrategy<Http::HdrType::CONTENT_TYPE>::match(ACLData<char const *> * &data, ACLFilledChecklist *checklist)
{
    char const *theHeader = checklist->reply->header.getStr(Http::HdrType::CONTENT_TYPE);

    if (NULL == theHeader)
        theHeader = "";

    return data->match(theHeader);
}

#endif /* SQUID_ACLREPLYMIMETYPE_H */

