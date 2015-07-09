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
    if (checklist->request->url.path().isEmpty())
        return -1;

    SBuf tmp = checklist->request->url.path();
    char *esc_buf = xstrndup(tmp.rawContent(), tmp.length());
    rfc1738_unescape(esc_buf);
    int result = data->match(esc_buf);
    xfree(esc_buf);
    return result;
}

ACLUrlPathStrategy *
ACLUrlPathStrategy::Instance()
{
    return &Instance_;
}

ACLUrlPathStrategy ACLUrlPathStrategy::Instance_;

