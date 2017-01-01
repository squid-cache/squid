/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/Protocol.h"
#include "acl/ProtocolData.h"
#include "HttpRequest.h"

/* explicit template instantiation required for some systems */

template class ACLStrategised<AnyP::ProtocolType>;

int
ACLProtocolStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist, ACLFlags &)
{
    return data->match(checklist->request->url.getScheme());
}

ACLProtocolStrategy *
ACLProtocolStrategy::Instance()
{
    return &Instance_;
}

ACLProtocolStrategy ACLProtocolStrategy::Instance_;

