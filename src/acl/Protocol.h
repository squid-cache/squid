/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLPROTOCOL_H
#define SQUID_ACLPROTOCOL_H

#include "acl/Strategy.h"
#include "anyp/ProtocolType.h"

class ACLProtocolStrategy : public ACLStrategy<AnyP::ProtocolType>
{

public:
    virtual int match (ACLData<MatchType> * &, ACLFilledChecklist *);
    virtual bool requiresRequest() const {return true;}
};

#endif /* SQUID_ACLPROTOCOL_H */

