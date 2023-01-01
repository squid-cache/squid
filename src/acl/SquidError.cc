/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/SquidError.h"
#include "HttpRequest.h"

int
ACLSquidErrorStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    if (checklist->requestErrorType != ERR_MAX)
        return data->match(checklist->requestErrorType);
    else if (checklist->request)
        return data->match(checklist->request->error.category);
    return 0;
}

