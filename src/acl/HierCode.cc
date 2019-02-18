/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/Checklist.h"
#include "acl/HierCode.h"
#include "acl/HierCodeData.h"
#include "acl/Strategised.h"
#include "HttpRequest.h"

/* explicit template instantiation required for some systems */

template class ACLStrategised<hier_code>;

int
ACLHierCodeStrategy::match (ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    return data->match (checklist->request->hier.code);
}

