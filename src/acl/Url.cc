/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
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
#include "rfc1738.h"
#include "src/URL.h"

int
ACLUrlStrategy::match (ACLData<char const *> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    char *esc_buf = xstrdup(urlCanonical(checklist->request));
    rfc1738_unescape(esc_buf);
    int result = data->match(esc_buf);
    safe_free(esc_buf);
    return result;
}

ACLUrlStrategy *
ACLUrlStrategy::Instance()
{
    return &Instance_;
}

ACLUrlStrategy ACLUrlStrategy::Instance_;

