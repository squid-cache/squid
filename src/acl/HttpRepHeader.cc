/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/HttpHeaderData.h"
#include "acl/HttpRepHeader.h"
#include "HttpReply.h"

int
ACLHTTPRepHeaderStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    return data->match (&checklist->reply->header);
}

ACLHTTPRepHeaderStrategy *
ACLHTTPRepHeaderStrategy::Instance()
{
    return &Instance_;
}

ACLHTTPRepHeaderStrategy ACLHTTPRepHeaderStrategy::Instance_;

