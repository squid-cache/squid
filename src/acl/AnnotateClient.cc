/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/AnnotateClient.h"
#include "acl/AnnotationData.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "http/Stream.h"
#include "Notes.h"

int
ACLAnnotateClientStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    if (const auto conn = checklist->conn()) {
        ACLAnnotationData *tdata = dynamic_cast<ACLAnnotationData*>(data);
        assert(tdata);
        tdata->annotate(conn->notes(), &delimiters.value, checklist->al);
        if (const auto request = checklist->request)
            tdata->annotate(request->notes(), &delimiters.value, checklist->al);
        return 1;
    }
    return 0;
}

