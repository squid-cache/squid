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
#include "acl/Url.h"
#include "HttpRequest.h"
#include "rfc1738.h"
#include "src/URL.h"

int
ACLUrlStrategy::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    const SBuf &tmp = checklist->request->effectiveRequestUri();
    char *esc_buf = xstrndup(tmp.rawContent(), tmp.length()+1);
    rfc1738_unescape(esc_buf);
    int result = data->match(esc_buf);
    xfree(esc_buf);
    return result;
}

ACLUrlStrategy *
ACLUrlStrategy::Instance()
{
    return &Instance_;
}

ACLUrlStrategy ACLUrlStrategy::Instance_;

