/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_SOURCEASN_H
#define SQUID_ACL_SOURCEASN_H

#include "acl/Strategy.h"
#include "ip/Address.h"

class ACLChecklist;

class ACLSourceASNStrategy : public ACLStrategy<Ip::Address>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
};

#endif /* SQUID_ACL_SOURCEASN_H */

