/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/SquidError.h"
#include "HttpRequest.h"

int
ACLSquidErrorStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    if (checklist->requestErrorType != ERR_MAX)
        return data->match(checklist->requestErrorType);
    else if (checklist->request)
        return data->match(checklist->request->errType);
    return 0;
}

ACLSquidErrorStrategy *
ACLSquidErrorStrategy::Instance()
{
    return &Instance_;
}

ACLSquidErrorStrategy ACLSquidErrorStrategy::Instance_;

