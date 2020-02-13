/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/UrlPath.h"
#include "HttpRequest.h"
#include "rfc1738.h"

int
ACLUrlPathStrategy::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist)
{
    if (checklist->request->url.path().isEmpty())
        return -1;

    char *esc_buf = SBufToCstring(checklist->request->url.path());
    rfc1738_unescape(esc_buf);
    int result = data->match(esc_buf);
    xfree(esc_buf);
    return result;
}

