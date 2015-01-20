/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/RegexData.h"
#include "acl/UrlPath.h"
#include "HttpRequest.h"
#include "rfc1738.h"

int
ACLUrlPathStrategy::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    if (!checklist->request->urlpath.size())
        return -1;

    char *esc_buf = xstrdup(checklist->request->urlpath.termedBuf());
    rfc1738_unescape(esc_buf);
    int result = data->match(esc_buf);
    safe_free(esc_buf);
    return result;
}

ACLUrlPathStrategy *
ACLUrlPathStrategy::Instance()
{
    return &Instance_;
}

ACLUrlPathStrategy ACLUrlPathStrategy::Instance_;

