/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLREQUESTMIMETYPE_H
#define SQUID_ACLREQUESTMIMETYPE_H

#include "acl/Acl.h"
#include "acl/Strategised.h"

class ACLRequestMIMEType
{

private:
    static ACL::Prototype RegistryProtoype;
    static ACLStrategised<char const *> RegistryEntry_;
};

/* partial specialisation */

#include "acl/Checklist.h"
#include "acl/Data.h"
#include "acl/RequestHeaderStrategy.h"

template <>
inline int
ACLRequestHeaderStrategy<Http::HdrType::CONTENT_TYPE>::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    char const *theHeader = checklist->request->header.getStr(Http::HdrType::CONTENT_TYPE);

    if (NULL == theHeader)
        theHeader = "";

    return data->match(theHeader);
}

#endif /* SQUID_ACLREQUESTMIMETYPE_H */

