/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/IntRange.h"
#include "acl/UrlPort.h"
#include "HttpRequest.h"

int
ACLUrlPortStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    return data->match (checklist->request->port);
}

ACLUrlPortStrategy *
ACLUrlPortStrategy::Instance()
{
    return &Instance_;
}

ACLUrlPortStrategy ACLUrlPortStrategy::Instance_;

