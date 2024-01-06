/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AdaptationService.h"
#include "acl/FilledChecklist.h"
#include "adaptation/History.h"
#include "HttpRequest.h"

int
Acl::AdaptationServiceCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    HttpRequest::Pointer request = checklist->request;
    if (request == nullptr)
        return 0;
    Adaptation::History::Pointer ah = request->adaptHistory();
    if (ah == nullptr)
        return 0;

    Adaptation::History::AdaptationServices::iterator it;
    for (it = ah->theAdaptationServices.begin(); it != ah->theAdaptationServices.end(); ++it) {
        if (data->match(it->c_str()))
            return 1;
    }

    return 0;
}

