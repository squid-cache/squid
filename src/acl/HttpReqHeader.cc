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
#include "acl/HttpReqHeader.h"
#include "HttpRequest.h"

int
ACLHTTPReqHeaderStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    return data->match (&checklist->request->header);
}

ACLHTTPReqHeaderStrategy *
ACLHTTPReqHeaderStrategy::Instance()
{
    return &Instance_;
}

ACLHTTPReqHeaderStrategy ACLHTTPReqHeaderStrategy::Instance_;

