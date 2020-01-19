/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AnnotateTransaction.h"
#include "acl/AnnotationData.h"
#include "acl/FilledChecklist.h"
#include "HttpRequest.h"
#include "Notes.h"

int
ACLAnnotateTransactionStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    if (const auto request = checklist->request) {
        ACLAnnotationData *tdata = dynamic_cast<ACLAnnotationData*>(data);
        assert(tdata);
        tdata->annotate(request->notes(), &delimiters.value, checklist->al);
        return 1;
    }
    return 0;
}

