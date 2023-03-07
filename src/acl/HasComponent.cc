/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/HasComponent.h"
#include "acl/HasComponentData.h"

int
ACLHasComponentStrategy::match(ACLData<MatchType> * &data, ACLFilledChecklist *checklist)
{
    ACLHasComponentData *cdata = dynamic_cast<ACLHasComponentData*>(data);
    assert(cdata);
    return cdata->match(checklist);
}

