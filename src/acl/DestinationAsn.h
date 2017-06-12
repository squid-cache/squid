/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLDESTINATIONASN_H
#define SQUID_ACLDESTINATIONASN_H

#include "acl/Asn.h"
#include "acl/Strategy.h"
#include "ip/Address.h"

/// \ingroup ACLAPI
class ACLDestinationASNStrategy : public ACLStrategy<Ip::Address>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    virtual bool requiresRequest() const {return true;}
};

#endif /* SQUID_ACLDESTINATIONASN_H */

