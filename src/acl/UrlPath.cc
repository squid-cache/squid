/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/UrlPath.h"
#include "HttpRequest.h"

int
Acl::UrlPathCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);
    auto urlPath = checklist->request->url.path();

    if (urlPath.isEmpty())
        return -1;

    return data->match(urlPath.c_str());
}
