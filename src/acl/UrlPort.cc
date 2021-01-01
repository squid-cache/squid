/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/UrlPort.h"
#include "HttpRequest.h"

int
ACLUrlPortStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    return data->match(checklist->request->url.port());
}

