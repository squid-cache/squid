/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AnnotateTransaction.h"
#include "acl/AnnotationData.h"
#include "acl/Checklist.h"
#include "HttpRequest.h"
#include "Notes.h"

int
ACLAnnotateTransactionStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &flags)
{
    if (const auto request = checklist->request) {
        ACLAnnotationData *tdata = dynamic_cast<ACLAnnotationData*>(data);
        assert(tdata);
        tdata->annotate(request->notes(), flags.delimiters(), checklist->al);
        return 1;
    }
    return 0;
}

ACLAnnotateTransactionStrategy *
ACLAnnotateTransactionStrategy::Instance()
{
    return &Instance_;
}

ACLAnnotateTransactionStrategy ACLAnnotateTransactionStrategy::Instance_;

