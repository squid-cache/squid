/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "acl/Protocol.h"
#include "acl/ProtocolData.h"
#include "acl/Strategised.h"
#include "HttpRequest.h"

/* explicit template instantiation required for some systems */

template class ACLStrategised<AnyP::ProtocolType>;

int
ACLProtocolStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    return data->match(checklist->request->url.getScheme());
}

