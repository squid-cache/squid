/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/RegexData.h"
#include "acl/UrlLogin.h"
#include "HttpRequest.h"
#include "rfc1738.h"

int
ACLUrlLoginStrategy::match(ACLData<char const *> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    if (checklist->request->url.userInfo().isEmpty()) {
        debugs(28, 5, "URL has no user-info details. cannot match");
        return 0; // nothing can match
    }

    static char str[MAX_URL]; // should be big enough for a single URI segment

    const SBuf::size_type len = checklist->request->url.userInfo().copy(str, sizeof(str)-1);
    str[len] = '\0';
    rfc1738_unescape(str);
    return data->match(str);
}

ACLUrlLoginStrategy *
ACLUrlLoginStrategy::Instance()
{
    return &Instance_;
}

ACLUrlLoginStrategy ACLUrlLoginStrategy::Instance_;

