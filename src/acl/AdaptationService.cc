/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AdaptationService.h"
#include "acl/Checklist.h"
#include "acl/IntRange.h"
#include "adaptation/Config.h"
#include "adaptation/History.h"
#include "HttpRequest.h"

int
ACLAdaptationServiceStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    HttpRequest::Pointer request = checklist->request;
    if (request == NULL)
        return 0;
    Adaptation::History::Pointer ah = request->adaptHistory();
    if (ah == NULL)
        return 0;

    Adaptation::History::AdaptationServices::iterator it;
    for (it = ah->theAdaptationServices.begin(); it != ah->theAdaptationServices.end(); ++it) {
        if (data->match(it->c_str()))
            return 1;
    }

    return 0;
}

ACLAdaptationServiceStrategy *
ACLAdaptationServiceStrategy::Instance()
{
    return &Instance_;
}

ACLAdaptationServiceStrategy ACLAdaptationServiceStrategy::Instance_;

