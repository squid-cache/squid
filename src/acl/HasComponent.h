/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLHASCOMPONENT_H
#define SQUID_ACLHASCOMPONENT_H

#include "acl/Strategised.h"
#include "acl/Strategy.h"

/// \ingroup ACLAPI
class ACLHasComponentStrategy : public ACLStrategy<ACLChecklist *>
{
public:
    virtual int match(ACLData<MatchType> * &, ACLFilledChecklist *);
};

#endif

