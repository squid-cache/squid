/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREPLYMIMETYPE_H
#define SQUID_ACLREPLYMIMETYPE_H

#include "acl/Acl.h"
#include "acl/Strategised.h"

class ACLReplyMIMEType
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<char const *> RegistryEntry_;
};

/* partial specialisation */

#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/ReplyHeaderStrategy.h"

template <>
inline int
ACLReplyHeaderStrategy<HDR_CONTENT_TYPE>::match(ACLData<char const *> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    char const *theHeader = checklist->reply->header.getStr(HDR_CONTENT_TYPE);

    if (NULL == theHeader)
        theHeader = "";

    return data->match(theHeader);
}

#endif /* SQUID_ACLREPLYMIMETYPE_H */

