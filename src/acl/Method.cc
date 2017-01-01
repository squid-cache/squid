/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/Method.h"
#include "acl/MethodData.h"
#include "HttpRequest.h"

/* explicit template instantiation required for some systems */

template class ACLStrategised<HttpRequestMethod>;

int
ACLMethodStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    return data->match (checklist->request->method);
}

ACLMethodStrategy *
ACLMethodStrategy::Instance()
{
    return &Instance_;
}

ACLMethodStrategy ACLMethodStrategy::Instance_;

