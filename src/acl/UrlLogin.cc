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
#include "acl/UrlLogin.h"
#include "anyp/Uri.h"
#include "HttpRequest.h"

int
Acl::UrlLoginCheck::match(ACLChecklist * const ch)
{
    const auto checklist = Filled(ch);

    if (checklist->request->url.userInfo().isEmpty()) {
        debugs(28, 5, "URL has no user-info details. cannot match");
        return 0; // nothing can match
    }

    auto decodedUserInfo = AnyP::Uri::Decode(checklist->request->url.userInfo());
    return data->match(decodedUserInfo.c_str());
}

