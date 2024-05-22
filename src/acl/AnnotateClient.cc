/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
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

int
Acl::AnnotateClientCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);
    auto annotated = false;
    const auto tdata = dynamic_cast<ACLAnnotationData*>(data.get());
    assert(tdata);
    const auto conn = checklist->conn();

    if (conn) {
        tdata->annotate(conn->notes(), &delimiters.value, checklist->al);
        annotated = true;
    }

    if (const auto &request = checklist->request) {
        tdata->annotate(request->notes(), &delimiters.value, checklist->al);
        annotated = true;
    } else if (conn && !conn->pipeline.empty()) {
        debugs(28, DBG_IMPORTANT, "ERROR: Squid BUG: " << name << " ACL is used in context with " <<
               "an unexpectedly nil ACLFilledChecklist::request. Did not annotate the current transaction.");
    }

    if (!annotated) {
        debugs(28, DBG_IMPORTANT, "WARNING: " << name << " ACL is used in context without " <<
               "active client-to-Squid connection and current transaction information. Did not annotate.");
    }

    return 1; // this is an "always matching" ACL
}

