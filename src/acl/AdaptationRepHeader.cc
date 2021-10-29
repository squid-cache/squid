/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AdaptationRepHeader.h"
#include "acl/FilledChecklist.h"
#include "acl/HttpHeaderData.h"
#include "HttpRequest.h"
#include "log/Config.h"

ACLAdaptationRepHeaderStrategy::ACLAdaptationRepHeaderStrategy()
{
    Log::TheConfig.needsAdaptationHistory = true;
}

int
ACLAdaptationRepHeaderStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    const auto &request = checklist->request;
    if (!request)
        return 0; // bug or misconfiguration; ACL::matches() warned the admin

    if (const auto &ah = request->adaptHistory())
        return data->match(&ah->allMeta);

    return 0;
}

