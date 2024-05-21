/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

int
Acl::AnnotateTransactionCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    if (const auto request = checklist->request) {
        const auto tdata = dynamic_cast<ACLAnnotationData*>(data.get());
        assert(tdata);
        tdata->annotate(request->notes(), &delimiters.value, checklist->al);
    } else {
        debugs(28, DBG_IMPORTANT, "WARNING: " << name << " ACL cannot be used for annotation " <<
               "because the HTTP request is missing.");
        // this is an 'always matching' ACL
    }
    return 1;
}

