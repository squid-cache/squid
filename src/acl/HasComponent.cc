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
Acl::HasComponentCheck::match(ACLChecklist * const checklist)
{
    const auto cdata = dynamic_cast<ACLHasComponentData*>(data.get());
    assert(cdata);
    return cdata->match(checklist);
}

