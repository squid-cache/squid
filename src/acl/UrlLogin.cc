/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
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
ACLUrlLoginStrategy::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    char *esc_buf = xstrdup(checklist->request->login);
    rfc1738_unescape(esc_buf);
    int result = data->match(esc_buf);
    safe_free(esc_buf);
    return result;
}

ACLUrlLoginStrategy *
ACLUrlLoginStrategy::Instance()
{
    return &Instance_;
}

ACLUrlLoginStrategy ACLUrlLoginStrategy::Instance_;

