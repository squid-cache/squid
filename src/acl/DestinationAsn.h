/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_DESTINATIONASN_H
#define SQUID_SRC_ACL_DESTINATIONASN_H

#include "acl/Asn.h"
#include "acl/Strategy.h"
#include "ip/Address.h"

/// \ingroup ACLAPI
class ACLDestinationASNStrategy : public ACLStrategy<Ip::Address>
{

public:
    int match (ACLData<MatchType> * &, ACLFilledChecklist *) override;
    bool requiresRequest() const override {return true;}
};

#endif /* SQUID_SRC_ACL_DESTINATIONASN_H */

